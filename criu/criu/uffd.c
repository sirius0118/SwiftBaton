#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>

#include "linux/userfaultfd.h"
#include "common/compiler.h"

#include "int.h"
#include "page.h"
#include "criu-log.h"
#include "criu-plugin.h"
#include "pagemap.h"
#include "files-reg.h"
#include "kerndat.h"
#include "mem.h"
#include "uffd.h"
#include "util-pie.h"
#include "protobuf.h"
#include "pstree.h"
#include "crtools.h"
#include "cr_options.h"
#include "xmalloc.h"
#include <compel/plugins/std/syscall-codes.h>
#include "restorer.h"
#include "page-xfer.h"
#include "common/lock.h"
#include "rst-malloc.h"
#include "tls.h"
#include "fdstore.h"
#include "util.h"
#include "namespaces.h"

#ifdef RDMA_CODESIGN
#include "RDMA.h"
#include <pthread.h>
#include "pre-transfer.h"
#include "transfer.h"

extern int item_num;
extern uint64_t pidset[MAX_PROCESS];
extern int uffdset[MAX_PROCESS];

volatile extern int TS_server_stop, TS_client_stop, FT_server_stop, PF_server_stop, PF_client_stop, write_stop;
extern int page_server_sk;
extern struct pid_vmas *PidVma[MAX_PROCESS];
#endif
extern mutex_t clientmutex;
#ifdef DOCKER
#include "cr-sync.h"
#endif

#ifdef MEM_PREDICT
#include "pf-cache.h"
#endif

#ifdef EPOLL_PLUS

#endif

#undef LOG_PREFIX
#define LOG_PREFIX "uffd: "

#define lp_debug(lpi, fmt, arg...)  pr_debug("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_info(lpi, fmt, arg...)   pr_info("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_warn(lpi, fmt, arg...)   pr_warn("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_err(lpi, fmt, arg...)    pr_err("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)
#define lp_perror(lpi, fmt, arg...) pr_perror("%d-%d: " fmt, lpi->pid, lpi->lpfd.fd, ##arg)

#define NEED_UFFD_API_FEATURES \
	(UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP | UFFD_FEATURE_EVENT_UNMAP | UFFD_FEATURE_EVENT_REMOVE)

#define LAZY_PAGES_SOCK_NAME "lazy-pages.socket"

#define LAZY_PAGES_RESTORE_FINISHED 0x52535446 /* ReSTore Finished */

/*
 * Background transfer parameters.
 * The default xfer length is arbitrary set to 64Kbytes
 * The limit of 4Mbytes matches the maximal chunk size we can have in
 * a pipe in the page-server
 */
#define DEFAULT_XFER_LEN (64 << 10)
#define MAX_XFER_LEN	 (4 << 20)

static mutex_t *lazy_sock_mutex;

struct lazy_iov {
	struct list_head l;
	unsigned long start;	 /* run-time start address, tracks remaps */
	unsigned long end;	 /* run-time end address, tracks remaps */
	unsigned long img_start; /* start address at the dump time */
};

struct lazy_pages_info {
	int pid;
	bool exited;

	struct list_head iovs;
	struct list_head reqs;

	struct lazy_pages_info *parent;
	unsigned ref_cnt;

	struct page_read pr;

	unsigned long xfer_len; /* in pages */
	unsigned long total_pages;
	unsigned long copied_pages;

	struct epoll_rfd lpfd;

	struct list_head l;

	unsigned long buf_size;
	void *buf;
};

/* global lazy-pages daemon state */
static LIST_HEAD(lpis);
static LIST_HEAD(exiting_lpis);
static LIST_HEAD(pending_lpis);
static int epollfd;
static bool restore_finished;
static struct epoll_rfd lazy_sk_rfd;
/* socket for communication with lazy-pages daemon */
static int lazy_pages_sk_id = -1;

static int handle_uffd_event(struct epoll_rfd *lpfd);

static struct lazy_pages_info *lpi_init(void)
{
	struct lazy_pages_info *lpi = NULL;

	lpi = xmalloc(sizeof(*lpi));
	if (!lpi)
		return NULL;

	memset(lpi, 0, sizeof(*lpi));
	INIT_LIST_HEAD(&lpi->iovs);
	INIT_LIST_HEAD(&lpi->reqs);
	INIT_LIST_HEAD(&lpi->l);
	
	lpi->lpfd.read_event = handle_uffd_event;
	lpi->xfer_len = DEFAULT_XFER_LEN;
	lpi->ref_cnt = 1;

	return lpi;
}

static void free_iovs(struct lazy_pages_info *lpi)
{
	struct lazy_iov *p, *n;

	list_for_each_entry_safe(p, n, &lpi->iovs, l) {
		list_del(&p->l);
		xfree(p);
	}

	list_for_each_entry_safe(p, n, &lpi->reqs, l) {
		list_del(&p->l);
		xfree(p);
	}
}

static void lpi_fini(struct lazy_pages_info *lpi);

static inline void lpi_put(struct lazy_pages_info *lpi)
{
	lpi->ref_cnt--;
	if (!lpi->ref_cnt)
		lpi_fini(lpi);
}

static inline void lpi_get(struct lazy_pages_info *lpi)
{
	lpi->ref_cnt++;
}

static void lpi_fini(struct lazy_pages_info *lpi)
{
	if (!lpi)
		return;
	xfree(lpi->buf);
	free_iovs(lpi);
	if (lpi->lpfd.fd > 0)
		close(lpi->lpfd.fd);
	if (lpi->parent)
		lpi_put(lpi->parent);
	if (!lpi->parent && lpi->pr.close)
		lpi->pr.close(&lpi->pr);
	xfree(lpi);
}

static int prepare_sock_addr(struct sockaddr_un *saddr)
{
	int len;

	memset(saddr, 0, sizeof(struct sockaddr_un));

	saddr->sun_family = AF_UNIX;
	len = snprintf(saddr->sun_path, sizeof(saddr->sun_path), "%s", LAZY_PAGES_SOCK_NAME);
	if (len >= sizeof(saddr->sun_path)) {
		pr_err("Wrong UNIX socket name: %s\n", LAZY_PAGES_SOCK_NAME);
		return -1;
	}

	return 0;
}

static int send_uffd(int sendfd, int pid)
{
	int fd;
	int ret = -1;

	if (sendfd < 0)
		return -1;

	fd = fdstore_get(lazy_pages_sk_id);
	if (fd < 0) {
		pr_err("%s: get_service_fd\n", __func__);
		return -1;
	}
	
	mutex_lock(lazy_sock_mutex);

	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	pr_debug("Sending PID %d\n", pid);
	if (send(fd, &pid, sizeof(pid), 0) < 0) {
		pr_perror("PID sending error");
		goto out;
	}

	/* for a zombie process pid will be negative */
	if (pid < 0) {
		ret = 0;
		goto out;
	}

	if (send_fd(fd, NULL, 0, sendfd) < 0) {
		pr_err("send_fd error\n");
		goto out;
	}

	ret = 0;
out:
	mutex_unlock(lazy_sock_mutex);
	close(fd);
	return ret;
}

int lazy_pages_setup_zombie(int pid)
{
	if (!opts.lazy_pages)
		return 0;

	if (send_uffd(0, -pid))
		return -1;

	return 0;
}

int uffd_noncooperative(void)
{
	unsigned long features = NEED_UFFD_API_FEATURES;

	return (kdat.uffd_features & features) == features;
}

static int uffd_api_ioctl(void *arg, int fd, pid_t pid)
{
	struct uffdio_api *uffdio_api = arg;

	return ioctl(fd, UFFDIO_API, uffdio_api);
}

int uffd_open(int flags, unsigned long *features, int *err)
{
	struct uffdio_api uffdio_api = { 0 };
	int uffd;

	uffd = syscall(SYS_userfaultfd, flags);
	if (uffd == -1) {
		pr_info("Lazy pages are not available: %s\n", strerror(errno));
		if (err)
			*err = errno;
		return -1;
	}

	uffdio_api.api = UFFD_API;
	if (features)
		uffdio_api.features = *features;

	if (userns_call(uffd_api_ioctl, 0, &uffdio_api, sizeof(uffdio_api), uffd)) {
		pr_perror("Failed to get uffd API");
		goto close;
	}

	if (uffdio_api.api != UFFD_API) {
		pr_err("Incompatible uffd API: expected %llu, got %llu\n", UFFD_API, uffdio_api.api);
		goto close;
	}

	if (features)
		*features = uffdio_api.features;

	return uffd;

close:
	close(uffd);
	return -1;
}

#ifndef MUL_UFFD
/* This function is used by 'criu restore --lazy-pages' */
int setup_uffd(int pid, struct task_restore_args *task_args)
{
	unsigned long features = kdat.uffd_features & NEED_UFFD_API_FEATURES;

	if (!opts.lazy_pages) {
		task_args->uffd = -1;
		return 0;
	}

	/*
	 * Open userfaulfd FD which is passed to the restorer blob and
	 * to a second process handling the userfaultfd page faults.
	 */
	task_args->uffd = uffd_open(O_CLOEXEC | O_NONBLOCK, &features, NULL);
	if (task_args->uffd < 0) {
		pr_perror("Unable to open an userfaultfd descriptor");
		return -1;
	}

	if (send_uffd(task_args->uffd, pid) < 0)
		goto err;

	return 0;
err:
	close(task_args->uffd);
	return -1;
}

#else

int setup_uffdset(int pid, struct task_restore_args *task_args)
{
	int *tmp_uffdset;
	int page_server_sk;

	page_server_sk = fdstore_get(lazy_pages_sk_id);

	pr_warn("set uffdset\n");
	PidUffdSet_fullfill(pid, page_server_sk);
	pr_warn("run to here\n");
	PidUffdSet_sendfd(page_server_sk, pid);
	pr_warn("run to here\n");
	PidUffdSet_send_region(page_server_sk, pid);
	pr_warn("run to here\n");
	PidUffdSet_taskargs(task_args, pid);
	pr_warn("run to here\n");

	return 0;
}

int setup_uffd(int pid, struct task_restore_args *task_args)
{
	return setup_uffdset(pid, task_args);
}

#endif

int prepare_lazy_pages_socket(void)
{
	int fd, len, ret = -1;
	struct sockaddr_un sun;
	char *buffer;

	if (!opts.lazy_pages)
		return 0;

	if (prepare_sock_addr(&sun))
		return -1;

	lazy_sock_mutex = shmalloc(sizeof(*lazy_sock_mutex));
	if (!lazy_sock_mutex)
		return -1;

	mutex_init(lazy_sock_mutex);

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	buffer = (char *)malloc(1024);
	if (getcwd(buffer, 1024) != NULL)
		pr_warn("work_dir:%s\n", buffer);
	pr_warn("restorer连接到:%s\n", sun.sun_path);
	pr_warn("opts.work_dir=%s\n", opts.work_dir);

	while (true) {
		if (access(sun.sun_path, F_OK) != -1)
			break;
		else
			usleep(1);
	}

	if (connect(fd, (struct sockaddr *)&sun, len) < 0) {
		pr_perror("connect to %s failed", sun.sun_path);
		goto out;
	}

	lazy_pages_sk_id = fdstore_add(fd);
	if (lazy_pages_sk_id < 0) {
		pr_perror("Can't add fd to fdstore");
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int server_listen(struct sockaddr_un *saddr)
{
	int fd;
	int len;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	unlink(saddr->sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(saddr->sun_path);

	if (bind(fd, (struct sockaddr *)saddr, len) < 0) {
		goto out;
	}

	if (listen(fd, 10) < 0) {
		goto out;
	}

	return fd;

out:
	close(fd);
	return -1;
}

static MmEntry *init_mm_entry(struct lazy_pages_info *lpi)
{
	struct cr_img *img;
	MmEntry *mm;
	int ret;

	img = open_image(CR_FD_MM, O_RSTR, lpi->pid);
	if (!img)
		return NULL;

	ret = pb_read_one_eof(img, &mm, PB_MM);
	close_image(img);
	if (ret == -1)
		return NULL;
	lp_debug(lpi, "Found %zd VMAs in image\n", mm->n_vmas);

	return mm;
}

static struct lazy_iov *find_iov(struct lazy_pages_info *lpi, unsigned long addr)
{
	struct lazy_iov *iov;

	list_for_each_entry(iov, &lpi->iovs, l)
		if (addr >= iov->start && addr < iov->end)
			return iov;

	return NULL;
}

static int split_iov(struct lazy_iov *iov, unsigned long addr)
{
	struct lazy_iov *new;

	new = xzalloc(sizeof(*new));
	if (!new)
		return -1;

	new->start = addr;
	new->img_start = iov->img_start + addr - iov->start;
	new->end = iov->end;
	iov->end = addr;
	list_add(&new->l, &iov->l);

	return 0;
}

static void iov_list_insert(struct lazy_iov *new, struct list_head *dst)
{
	struct lazy_iov *iov;

	if (list_empty(dst)) {
		list_move(&new->l, dst);
		return;
	}

	list_for_each_entry(iov, dst, l) {
		if (new->start < iov->start) {
			list_move_tail(&new->l, &iov->l);
			break;
		}
		if (list_is_last(&iov->l, dst) && new->start > iov->start) {
			list_move(&new->l, &iov->l);
			break;
		}
	}
}

static void merge_iov_lists(struct list_head *src, struct list_head *dst)
{
	struct lazy_iov *iov, *n;

	if (list_empty(src))
		return;

	list_for_each_entry_safe(iov, n, src, l)
		iov_list_insert(iov, dst);
}

static int __copy_iov_list(struct list_head *src, struct list_head *dst)
{
	struct lazy_iov *iov, *new;

	list_for_each_entry(iov, src, l) {
		new = xzalloc(sizeof(*new));
		if (!new)
			return -1;

		new->start = iov->start;
		new->img_start = iov->img_start;
		new->end = iov->end;

		list_add_tail(&new->l, dst);
	}

	return 0;
}

static int copy_iovs(struct lazy_pages_info *src, struct lazy_pages_info *dst)
{
	if (__copy_iov_list(&src->iovs, &dst->iovs))
		goto free_iovs;

	if (__copy_iov_list(&src->reqs, &dst->reqs))
		goto free_iovs;

	/*
	 * The IOVs already in flight for the parent process need to be
	 * transferred again for the child process
	 */
	merge_iov_lists(&dst->reqs, &dst->iovs);

	dst->buf_size = src->buf_size;
	if (posix_memalign(&dst->buf, PAGE_SIZE, dst->buf_size))
		goto free_iovs;

	return 0;

free_iovs:
	free_iovs(dst);
	return -1;
}

/*
 * Purge range (addr, addr + len) from lazy_iovs. The range may
 * cover several continuous IOVs.
 */
static int __drop_iovs(struct list_head *iovs, unsigned long addr, int len)
{
	struct lazy_iov *iov, *n;

	list_for_each_entry_safe(iov, n, iovs, l) {
		unsigned long start = iov->start;
		unsigned long end = iov->end;

		if (len <= 0 || addr + len < start)
			break;

		if (addr >= end)
			continue;

		if (addr < start) {
			len -= (start - addr);
			addr = start;
		}

		/*
		 * The range completely fits into the current IOV.
		 * If addr equals iov_start we just "drop" the
		 * beginning of the IOV. Otherwise, we make the IOV to
		 * end at addr, and add a new IOV start starts at
		 * addr + len.
		 */
		if (addr + len < end) {
			if (addr == start) {
				iov->start += len;
				iov->img_start += len;
			} else {
				if (split_iov(iov, addr + len))
					return -1;
				iov->end = addr;
			}
			break;
		}

		/*
		 * The range spawns beyond the end of the current IOV.
		 * If addr equals iov_start we just "drop" the entire
		 * IOV.  Otherwise, we cut the beginning of the IOV
		 * and continue to the next one with the updated range
		 */
		if (addr == start) {
			list_del(&iov->l);
			xfree(iov);
		} else {
			iov->end = addr;
		}

		len -= (end - addr);
		addr = end;
	}

	return 0;
}

static int drop_iovs(struct lazy_pages_info *lpi, unsigned long addr, int len)
{
	if (__drop_iovs(&lpi->iovs, addr, len))
		return -1;

	if (__drop_iovs(&lpi->reqs, addr, len))
		return -1;

	return 0;
}

static struct lazy_iov *extract_range(struct lazy_iov *iov, unsigned long start, unsigned long end)
{
	/* move the IOV tail into a new IOV */
	if (end < iov->end)
		if (split_iov(iov, end))
			return NULL;

	if (start == iov->start)
		return iov;

	/* after splitting the IOV head we'll need the ->next IOV */
	if (split_iov(iov, start))
		return NULL;

	return list_entry(iov->l.next, struct lazy_iov, l);
}

static int __remap_iovs(struct list_head *iovs, unsigned long from, unsigned long to, unsigned long len)
{
	LIST_HEAD(remaps);

	unsigned long off = to - from;
	struct lazy_iov *iov, *n;

	list_for_each_entry_safe(iov, n, iovs, l) {
		if (from >= iov->end)
			continue;

		if (len <= 0 || from + len <= iov->start)
			break;

		if (from < iov->start) {
			len -= (iov->start - from);
			from = iov->start;
		}

		if (from > iov->start) {
			if (split_iov(iov, from))
				return -1;
			list_safe_reset_next(iov, n, l);
			continue;
		}

		if (from + len < iov->end) {
			if (split_iov(iov, from + len))
				return -1;
			list_safe_reset_next(iov, n, l);
		}

		/* here we have iov->start = from, iov->end <= from + len */
		from = iov->end;
		len -= iov->end - iov->start;
		iov->start += off;
		iov->end += off;
		list_move_tail(&iov->l, &remaps);
	}

	merge_iov_lists(&remaps, iovs);

	return 0;
}

static int remap_iovs(struct lazy_pages_info *lpi, unsigned long from, unsigned long to, unsigned long len)
{
	if (__remap_iovs(&lpi->iovs, from, to, len))
		return -1;

	if (__remap_iovs(&lpi->reqs, from, to, len))
		return -1;

	return 0;
}

/*
 * Create a list of IOVs that can be handled using userfaultfd. The
 * IOVs generally correspond to lazy pagemap entries, except the cases
 * when a single pagemap entry covers several VMAs. In those cases
 * IOVs are split at VMA boundaries because UFFDIO_COPY may be done
 * only inside a single VMA.
 * We assume here that pagemaps and VMAs are sorted.
 */
static int collect_iovs(struct lazy_pages_info *lpi)
{
	struct page_read *pr = &lpi->pr;
	struct lazy_iov *iov;
	MmEntry *mm;
	uint64_t nr_pages = 0, n_vma = 0, max_iov_len = 0;
	int ret = -1;
	unsigned long start, end, len;

	mm = init_mm_entry(lpi);
	if (!mm)
		return -1;

	while (pr->advance(pr)) {
		if (!pagemap_lazy(pr->pe))
			continue;

		start = pr->pe->vaddr;
		end = start + pr->pe->nr_pages * page_size();
		nr_pages += pr->pe->nr_pages;

		for (; n_vma < mm->n_vmas; n_vma++) {
			VmaEntry *vma = mm->vmas[n_vma];

			if (start >= vma->end)
				continue;

			iov = xzalloc(sizeof(*iov));
			if (!iov)
				goto free_iovs;

			len = min_t(uint64_t, end, vma->end) - start;
			iov->start = start;
			iov->img_start = start;
			iov->end = iov->start + len;
			list_add_tail(&iov->l, &lpi->iovs);

			if (len > max_iov_len)
				max_iov_len = len;

			if (end <= vma->end)
				break;

			start = vma->end;
		}
	}
	
	lpi->buf_size = max_iov_len;
	pr_warn("done！ bufsize=:%ld\n", max_iov_len);
	if (posix_memalign(&lpi->buf, PAGE_SIZE, lpi->buf_size))
		goto free_iovs;

	ret = nr_pages;
	goto free_mm;

free_iovs:
	free_iovs(lpi);
free_mm:
	mm_entry__free_unpacked(mm, NULL);
	pr_warn("run to here ret:%d\n", ret);
	return ret;
}

static int uffd_io_complete(struct page_read *pr, unsigned long vaddr, int nr);

static int ud_open(int client, struct lazy_pages_info **_lpi)
{
	struct lazy_pages_info *lpi;
	int ret = -1;
	int pr_flags = PR_TASK;
	int *tmp_uffdset;
	int tmp_nr_uffd, pid;

	lpi = lpi_init();
	if (!lpi)
		goto out;

#ifdef MUL_UFFD

	PidUffdSet_recvfd(client, &pid, &tmp_uffdset, &tmp_nr_uffd);
	pr_warn("receive uffd done, pid: %d, nr_uffd:%d, uffd:%d\n", pid, tmp_nr_uffd, tmp_uffdset[0]);
	PidUffdSet_recv_region(client, pid, tmp_uffdset);

	update_PidUffdSet(pid, tmp_nr_uffd, tmp_uffdset);
	pr_warn("receive uffd region done\n");
	lpi->pid = pid;
#else
	/* The "transfer protocol" is first the pid as int and then
	 * the FD for UFFD */
	ret = recv(client, &lpi->pid, sizeof(lpi->pid), 0);
	if (ret != sizeof(lpi->pid)) {
		if (ret < 0)
			pr_perror("PID recv error");
		else
			pr_err("PID recv: short read\n");
		goto out;
	}

	if (lpi->pid < 0) {
		pr_debug("Zombie PID: %d\n", lpi->pid);
		lpi_fini(lpi);
		return 0;
	}

	lpi->lpfd.fd = recv_fd(client);
	if (lpi->lpfd.fd < 0) {
		pr_err("recv_fd error\n");
		goto out;
	}
	pr_debug("Received PID: %d, uffd: %d\n", lpi->pid, lpi->lpfd.fd);
#endif

#ifndef MUL_UFFD
#ifdef RDMA_CODESIGN
	for (int i = 0; i < item_num; i++) {
		if (lpi->pid == pidset[i]) {
			uffdset[i] = lpi->lpfd.fd;
			break;
		}
	}
#endif
#endif

	if (opts.use_page_server)
		pr_flags |= PR_REMOTE;
	ret = open_page_read(lpi->pid, &lpi->pr, pr_flags);
	if (ret <= 0) {
		lp_err(lpi, "Failed to open pagemap\n");
		goto out;
	}

	lpi->pr.io_complete = uffd_io_complete;

	/*
	 * Find the memory pages belonging to the restored process
	 * so that it is trackable when all pages have been transferred.
	 */
	ret = collect_iovs(lpi);
	pr_warn("collect_iovs done ret:%d\n", ret);
	if (ret < 0)
		goto out;
	lpi->total_pages = ret;

	lp_debug(lpi, "Found %ld pages to be handled by UFFD\n", lpi->total_pages);

	list_add_tail(&lpi->l, &lpis);
	*_lpi = lpi;

	return 0;

out:
	lpi_fini(lpi);
	return -1;
}

static int handle_exit(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "EXIT\n");
	if (epoll_del_rfd(epollfd, &lpi->lpfd))
		return -1;
	free_iovs(lpi);
	close(lpi->lpfd.fd);
	lpi->lpfd.fd = -lpi->lpfd.fd;
	lpi->exited = true;

	/* keep it for tracking in-flight requests and for the summary */
	list_move_tail(&lpi->l, &lpis);

	return 0;
}

static bool uffd_recoverable_error(int mcopy_rc)
{
	if (errno == EAGAIN || errno == ENOENT || errno == EEXIST)
		return true;

	if (mcopy_rc == -ENOENT || mcopy_rc == -EEXIST)
		return true;

	return false;
}

static int uffd_check_op_error(struct lazy_pages_info *lpi, const char *op, int *nr_pages, long mcopy_rc)
{
	if (errno == ENOSPC || errno == ESRCH) {
		handle_exit(lpi);
		return 0;
	}

	if (!uffd_recoverable_error(mcopy_rc)) {
		lp_perror(lpi, "%s: mcopy_rc:%ld", op, mcopy_rc);
		return -1;
	}

	lp_debug(lpi, "%s: mcopy_rc:%ld, errno:%d\n", op, mcopy_rc, errno);

	if (mcopy_rc <= 0)
		*nr_pages = 0;
	else
		*nr_pages = mcopy_rc / PAGE_SIZE;

	return 0;
}


static int uffd_copy(struct lazy_pages_info *lpi, __u64 address, int *nr_pages)
{
	struct uffdio_copy uffdio_copy;
	unsigned long len = *nr_pages * page_size();

	uffdio_copy.dst = address;
	uffdio_copy.src = (unsigned long)lpi->buf;
	uffdio_copy.len = len;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;
	// sleep(1);
	lp_debug(lpi, "uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);
	if (ioctl(lpi->lpfd.fd, UFFDIO_COPY, &uffdio_copy) &&
	    uffd_check_op_error(lpi, "copy", nr_pages, uffdio_copy.copy))
		return -1;
	pr_debug("done! uffd_copy: 0x%llx/%ld\n", uffdio_copy.dst, len);
	lpi->copied_pages += *nr_pages;

	return 0;
}

static int uffd_io_complete(struct page_read *pr, unsigned long img_addr, int nr)
{
	struct lazy_pages_info *lpi;
	unsigned long addr = 0;
	int req_pages, ret;
	struct lazy_iov *req;

	lpi = container_of(pr, struct lazy_pages_info, pr);

	/*
	 * The process may exit while we still have requests in
	 * flight. We just drop the request and the received data in
	 * this case to avoid making uffd unhappy
	 */
	if (lpi->exited)
		return 0;

	list_for_each_entry(req, &lpi->reqs, l) {
		if (req->img_start == img_addr) {
			addr = req->start;
			break;
		}
	}

	/* the request may be already gone because if unmap/remove */
	if (!addr)
		return 0;

	/*
	 * By the time we get the pages from the remote source, parts
	 * of the request may already be gone because of unmap/remove
	 * OTOH, the remote side may send less pages than we requested.
	 * Make sure we are not trying to uffd_copy more memory than
	 * we should.
	 */
	req_pages = (req->end - req->start) / PAGE_SIZE;
	nr = min(nr, req_pages);

	ret = uffd_copy(lpi, addr, &nr);
	if (ret < 0)
		return ret;

	/* recheck if the process exited, it may be detected in uffd_copy */
	if (lpi->exited)
		return 0;

	/*
	 * Since the completed request length may differ from the
	 * actual data we've received we re-insert the request to IOVs
	 * list and let drop_iovs do the range math, free memory etc.
	 */
	iov_list_insert(req, &lpi->iovs);
	return drop_iovs(lpi, addr, nr * PAGE_SIZE);
}

static int uffd_zero(struct lazy_pages_info *lpi, __u64 address, int nr_pages)
{
	struct uffdio_zeropage uffdio_zeropage;
	unsigned long len = page_size() * nr_pages;

	uffdio_zeropage.range.start = address;
	uffdio_zeropage.range.len = len;
	uffdio_zeropage.mode = 0;

	lp_debug(lpi, "zero page at 0x%llx\n", address);
	if (ioctl(lpi->lpfd.fd, UFFDIO_ZEROPAGE, &uffdio_zeropage) &&
	    uffd_check_op_error(lpi, "zero", &nr_pages, uffdio_zeropage.zeropage))
		return -1;

	return 0;
}

/*
 * Seek for the requested address in the pagemap. If it is found, the
 * subsequent call to pr->page_read will bring us the data. If the
 * address is not found in the pagemap, but no error occurred, the
 * address should be mapped to zero pfn.
 *
 * Returns 0 for zero pages, 1 for "real" pages and negative value on
 * error
 */
static int uffd_seek_pages(struct lazy_pages_info *lpi, __u64 address, int nr)
{
	int ret;

	lpi->pr.reset(&lpi->pr);
	
	ret = lpi->pr.seek_pagemap(&lpi->pr, address);
	if (!ret) {
		lp_err(lpi, "no pagemap covers %llx\n", address);
		return -1;
	}

	return 0;
}

static int uffd_handle_pages(struct lazy_pages_info *lpi, __u64 address, int nr, unsigned flags)
{
	int ret;
	
	ret = uffd_seek_pages(lpi, address, nr);
	if (ret)
		return ret;
	
	
	ret = lpi->pr.read_pages(&lpi->pr, address, nr, lpi->buf, flags);
	if (ret <= 0) {
		lp_err(lpi, "failed reading pages at %llx\n", address);
		return ret;
	}

	return 0;
}

static struct lazy_iov *pick_next_range(struct lazy_pages_info *lpi)
{
	return list_first_entry(&lpi->iovs, struct lazy_iov, l);
}

/*
 * This is very simple heurstics for background transfer control.
 * The idea is to transfer larger chunks when there is no page faults
 * and drop the background transfer size each time #PF occurs to some
 * default value. The default is empirically set to 64Kbytes
 */
static void update_xfer_len(struct lazy_pages_info *lpi, bool pf)
{
	if (pf)
		lpi->xfer_len = DEFAULT_XFER_LEN;
	else
		lpi->xfer_len += DEFAULT_XFER_LEN;

	if (lpi->xfer_len > MAX_XFER_LEN)
		lpi->xfer_len = MAX_XFER_LEN;
}

static int xfer_pages(struct lazy_pages_info *lpi)
{
	struct lazy_iov *iov;
	unsigned int nr_pages;
	unsigned long len;
	int err;

	iov = pick_next_range(lpi);
	if (!iov)
		return 0;

	len = min(iov->end - iov->start, lpi->xfer_len);

	iov = extract_range(iov, iov->start, iov->start + len);
	if (!iov)
		return -1;
	list_move(&iov->l, &lpi->reqs);

	nr_pages = (iov->end - iov->start) / PAGE_SIZE;

	update_xfer_len(lpi, false);

	err = uffd_handle_pages(lpi, iov->img_start, nr_pages, PR_ASYNC | PR_ASAP);
	if (err < 0) {
		lp_err(lpi, "Error during UFFD copy\n");
		return -1;
	}

	return 0;
}

static int handle_remove(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct uffdio_range unreg;

	unreg.start = msg->arg.remove.start;
	unreg.len = msg->arg.remove.end - msg->arg.remove.start;

	lp_debug(lpi, "%s: %llx(%llx)\n", msg->event == UFFD_EVENT_REMOVE ? "REMOVE" : "UNMAP", unreg.start, unreg.len);

	/*
	 * The REMOVE event does not change the VMA, so we need to
	 * make sure that we won't handle #PFs in the removed
	 * range. With UNMAP, there's no VMA to worry about
	 */
	if (msg->event == UFFD_EVENT_REMOVE && ioctl(lpi->lpfd.fd, UFFDIO_UNREGISTER, &unreg)) {
		/*
		 * The kernel returns -ENOMEM when unregister is
		 * called after the process has gone
		 */
		if (errno == ENOMEM) {
			handle_exit(lpi);
			return 0;
		}

		pr_perror("Failed to unregister (%llx - %llx)", unreg.start, unreg.start + unreg.len);
		return -1;
	}

	return drop_iovs(lpi, unreg.start, unreg.len);
}

static int handle_remap(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	unsigned long from = msg->arg.remap.from;
	unsigned long to = msg->arg.remap.to;
	unsigned long len = msg->arg.remap.len;

	lp_debug(lpi, "REMAP: %lx -> %lx (%ld)\n", from, to, len);

	return remap_iovs(lpi, from, to, len);
}

static int handle_fork(struct lazy_pages_info *parent_lpi, struct uffd_msg *msg)
{
	struct lazy_pages_info *lpi;
	int uffd = msg->arg.fork.ufd;

	lp_debug(parent_lpi, "FORK: child with ufd=%d\n", uffd);

	lpi = lpi_init();
	if (!lpi)
		return -1;

	if (copy_iovs(parent_lpi, lpi))
		goto out;

	lpi->pid = parent_lpi->pid;
	lpi->lpfd.fd = uffd;
	lpi->parent = parent_lpi->parent ? parent_lpi->parent : parent_lpi;
	lpi->copied_pages = lpi->parent->copied_pages;
	lpi->total_pages = lpi->parent->total_pages;
	list_add_tail(&lpi->l, &pending_lpis);

	dup_page_read(&lpi->parent->pr, &lpi->pr);

	lpi_get(lpi->parent);

	return 1;

out:
	lpi_fini(lpi);
	return -1;
}

/*
 * We may exit epoll_run_rfds() loop because of non-fork() event. In
 * such case we return 1 rather than 0 to let the caller know that no
 * fork() events were pending
 */
int complete_forks(int epollfd, struct epoll_event **events, int *nr_fds)
{
	struct lazy_pages_info *lpi, *n;
	struct epoll_event *tmp;

	if (list_empty(&pending_lpis))
		return 1;

	list_for_each_entry(lpi, &pending_lpis, l)
		(*nr_fds)++;

	tmp = xrealloc(*events, sizeof(struct epoll_event) * (*nr_fds));
	if (!tmp)
		return -1;
	*events = tmp;

	list_for_each_entry_safe(lpi, n, &pending_lpis, l) {
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			return -1;

		list_del_init(&lpi->l);
		list_add_tail(&lpi->l, &lpis);
	}

	return 0;
}

static bool is_page_queued(struct lazy_pages_info *lpi, unsigned long addr)
{
	struct lazy_iov *req;

	list_for_each_entry(req, &lpi->reqs, l)
		if (addr >= req->start && addr < req->end)
			return true;

	return false;
}

#ifdef RDMA_CODESIGN

static int RDMA_handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	int ret = -1, pid;
	__u64 address;
	int uffd = 0, head;
	struct PF_PageRequest req;
	struct PF_PageResponse *resp;
	struct uffdio_copy uffdio_copy;
	struct page_data_set_t *buf = (struct page_data_set_t *)PF_res.buf;
	
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	req.pid = lpi->pid;
	req.addr = address;

#ifdef MEM_PREDICT
	pr_warn("PF的地址为: pid:%ld, addr:%lx\n", req.pid, req.addr);
	pf_cache_insert(req.pid, req.addr);
#endif
	ret = send_page_request(&PF_res, &req);
	if (ret)
		pr_err("send page request failed\n");

	
	post_receive(&PF_res, item_num, (uintptr_t)PF_res.buf, sizeof(struct PF_PageResponse));
	ret = poll_completion(&PF_res);
	resp = (struct PF_PageResponse *)PF_res.buf;
	uffd = lpi->lpfd.fd;
	if ((address != resp->addr) || (resp->pid != req.pid)) {
		pr_err("page fault address not match\n");
		return -1;
	}

	uffdio_copy.dst = (uint64_t)resp->addr;
	uffdio_copy.src = (uint64_t)resp->page;
	uffdio_copy.len = 4096;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;
	pid = lpi->pid;
	if (ioctl_mul(&uffdio_copy, pid) < 0) {
		if (errno != EEXIST)
			pr_err("ioctl(UFFDIO_COPY) failed\n");
	}
	return ret;
}

#endif

static int handle_page_fault(struct lazy_pages_info *lpi, struct uffd_msg *msg)
{
	struct lazy_iov *iov;
	__u64 address;
	int ret;

	/* Align requested address to the next page boundary */
	
	address = msg->arg.pagefault.address & ~(page_size() - 1);
	lp_debug(lpi, "#PF at 0x%llx\n", address);

	if (is_page_queued(lpi, address))
		return 0;

	iov = find_iov(lpi, address);
	if (!iov)
		return uffd_zero(lpi, address, 1);

	iov = extract_range(iov, address, address + PAGE_SIZE);
	if (!iov)
		return -1;

	list_move(&iov->l, &lpi->reqs);

	update_xfer_len(lpi, true);

	ret = uffd_handle_pages(lpi, iov->img_start, 1, PR_ASYNC | PR_ASAP);
	if (ret < 0) {
		lp_err(lpi, "Error during regular page copy\n");
		return -1;
	}

	return 0;
}


static int handle_uffd_event(struct epoll_rfd *lpfd)
{
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;
	int ret;

	lpi = container_of(lpfd, struct lazy_pages_info, lpfd);

	ret = read(lpfd->fd, &msg, sizeof(msg));
	if (ret < 0) {
		/* we've already handled the page fault for another thread */
		if (errno == EAGAIN)
			return 0;
		if (errno == EBADF && lpi->exited) {
			lp_debug(lpi, "excess message in queue: %d", msg.event);
			return 0;
		}
		lp_perror(lpi, "Can't read uffd message");
		return -1;
	} else if (ret == 0) {
		return 1;
	} else if (ret != sizeof(msg)) {
		lp_err(lpi, "Can't read uffd message: short read");
		return -1;
	}

	switch (msg.event) {
#ifdef RDMA_CODESIGN
	case UFFD_EVENT_PAGEFAULT:
		return RDMA_handle_page_fault(lpi, &msg);
#else
	case UFFD_EVENT_PAGEFAULT:
		return handle_page_fault(lpi, &msg);
#endif
	case UFFD_EVENT_REMOVE:
	case UFFD_EVENT_UNMAP:
		return handle_remove(lpi, &msg);
	case UFFD_EVENT_REMAP:
		return handle_remap(lpi, &msg);
	case UFFD_EVENT_FORK:
		return handle_fork(lpi, &msg);
	default:
		lp_err(lpi, "unexpected uffd event %u\n", msg.event);
		return -1;
	}

	return 0;
}

static void lazy_pages_summary(struct lazy_pages_info *lpi)
{
	lp_debug(lpi, "UFFD transferred pages: (%ld/%ld)\n", lpi->copied_pages, lpi->total_pages);

#if 0
	if ((lpi->copied_pages != lpi->total_pages) && (lpi->total_pages > 0)) {
		lp_warn(lpi, "Only %ld of %ld pages transferred via UFFD\n"
			"Something probably went wrong.\n",
			lpi->copied_pages, lpi->total_pages);
		return 1;
	}
#endif
}

#ifdef RDMA_CODESIGN
struct RDMA_PF_handle_request_arg {
	int epollfd;
	struct epoll_event **events;
	int nr_fds;
	bool stop;
};

struct RDMA_TS_arg {
	int index;
};

#ifdef EPOLL_PLUS

struct index_node {
	int index;
	struct list_head list;
};

struct event_set_t {
	futex_t nr_events;
	int *events;
	mutex_t mutex;
	mutex_t rdma;
	struct list_head *index_pipe;
};

static struct event_set_t *event_sets;

static void event_set_init(void)
{
	event_sets = (struct event_set_t *)malloc(sizeof(struct event_set_t));
	futex_init(&event_sets->nr_events);
	mutex_init(&event_sets->mutex);
	event_sets->events = (int *)malloc(sizeof(int) * item_num);
	event_sets->index_pipe = (struct list_head *)malloc(sizeof(struct list_head) * item_num);
	for (int i = 0; i < item_num; i++) {
		event_sets->events[i] = 0;
		INIT_LIST_HEAD(&event_sets->index_pipe[i]);
	}
}

struct tpe_args {
	int index;
	int epollfd;
	struct epoll_event **events;
};

void *thread_process_event(void *arg)
{
	struct tpe_args *temp_args;
	// struct list_head *index_pipe;
	struct epoll_rfd *rfd;
	struct index_node *node;
	int index;
	struct epoll_event *evs;
	uint32_t events;
	int ret, evs_i;
	struct page_data_set_t *buf;
	struct uffdio_copy uffdio_copy;
	int uffd, head, pid;
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;

	temp_args = (struct tpe_args *)arg;
	// index_pipe = event_sets->index_pipe;s
	epollfd = temp_args->epollfd;
	evs = *temp_args->events;
	index = temp_args->index;

	buf = (struct page_data_set_t *)PF_res.buf;
	uffd = uffdset[index];
	pid = pidset[index];

	while (1) {
		// struct lazy_pages_info *lpi;

		
		if (event_sets->events[index] > 0) {
			int i = 0;
			
			// update index_pipe & events
			mutex_lock(&event_sets->mutex);
			// list_for_each_entry(node, &event_sets->index_pipe[index], list){
			// 	pr_warn("22node->index:%d, i:%d\n", node->index, i++);
			// }
			node = list_first_entry(&event_sets->index_pipe[index], struct index_node, list);
			list_del(&node->list);
			event_sets->events[index]--;
			mutex_unlock(&event_sets->mutex);

			evs_i = node->index;
			
			rfd = (struct epoll_rfd *)evs[evs_i].data.ptr;
			ret = read(rfd->fd, &msg, sizeof(msg));
			futex_inc_and_wake(&event_sets->nr_events);
			events = evs[evs_i].events;
			head = buf->local_head[index];
			buf->imm_data = msg.arg.pagefault.address & ~(4096 - 1);
			if (buf->imm_data == 0)
				continue;
			
			if (events & EPOLLIN) {
				mutex_lock(&event_sets->rdma);
				
				// 		+ (sizeof(uint64_t) * head), (uint64_t)&buf->imm_data);
				ret = rdma_write(&PF_res, (sizeof(int) * MAX_PROCESS * 2) + (sizeof(uint64_t) * MAX_THREADS * index) + (sizeof(uint64_t) * head), (uint64_t)&buf->imm_data, 8, item_num);
				buf->local_head[index] = (head + 1) % MAX_THREADS;
				ret = rdma_write(&PF_res, sizeof(int) * index, (uint64_t)&buf->local_head[index], sizeof(int), item_num);
				pf_cache_insert(pidset[index], buf->imm_data);
				mutex_unlock(&event_sets->rdma);
				
				if (ret)
					pr_err("rdma write\n");
				// ret = rfd->read_event(rfd);
			}
			
			if (events & (EPOLLHUP | EPOLLRDHUP)) {
				ret = epoll_hangup_event(epollfd, rfd);
			}

			
			// rfd = (struct epoll_rfd *)evs[node->index].data.ptr;
			// events = evs[node->index].events;
			// lpi = container_of(rfd, struct lazy_pages_info, lpfd);
			// mutex_lock(&event_sets->mutex);
			
			// mutex_unlock(&event_sets->mutex);
			

			// lpi = container_of(rfd, struct lazy_pages_info, lpfd);
			// ret = read(rfd->fd, &msg, sizeof(msg));
			
			// buf->imm_data = node->addr;

			// head = buf->local_head[index] % MAX_THREADS;
			
			// 		+ sizeof(uint64_t) * head, (uint64_t)&buf->imm_data, node->addr);

			// ret = rdma_write(&PF_res, sizeof(int) * MAX_PROCESS * 2 + sizeof(uint64_t) * MAX_THREADS * index
			// 		+ sizeof(uint64_t) * head, (uint64_t)&buf->imm_data, 8, item_num);
			// buf->local_head[index] = head + 1;
			// ret = rdma_write(&PF_res, sizeof(int) * index, (uint64_t)&buf->local_head[index], sizeof(int), item_num);
			// mutex_unlock(&event_sets->rdma);
			
			// if (ret)
			// 	pr_err("rdma write\n");
		}

		
		if (buf->head[index] != buf->tail[index]) {
			
			uffdio_copy.dst = *(uint64_t *)buf->data[index][buf->tail[index]];
			uffdio_copy.src = (uint64_t)&buf->data[index][buf->tail[index]][8];
			uffdio_copy.len = 4096;
			uffdio_copy.mode = 0;
			uffdio_copy.copy = 0;

			
			if (ioctl_mul(&uffdio_copy, pid) < 0) {
				if (errno != EEXIST)
					pr_err("ioctl(UFFDIO_COPY) failed\n");
			}
			
			buf->tail[index] = (buf->tail[index] + 1) % MAX_THREADS;
		}
	}
	return NULL;
}

int epoll_run_rfds_pthread(int epollfd, struct epoll_event *evs, int nr_fds, int timeout)
{
	int ret, i, nr_events;
	bool have_a_break = false;
	// struct uffd_msg msg;
	uint32_t events;

	while (1) {
		
		ret = epoll_wait(epollfd, evs, nr_fds, timeout);
		if (ret <= 0) {
			if (ret < 0)
				pr_perror("polling failed");
			break;
		}
		
		// TODO: process the epoll event by multiple threads
		
		nr_events = ret;
		futex_init(&event_sets->nr_events);
		for (int i = 0; i < nr_events; i++) {
			int index = -1;
			struct epoll_rfd *rfd;
			struct lazy_pages_info *lpi;
			struct index_node *node;
			// struct index_node *nodei;

			rfd = (struct epoll_rfd *)evs[i].data.ptr;
			lpi = container_of(rfd, struct lazy_pages_info, lpfd);
			events = evs[i].events;
			if (lpi->pid > 0) {
				
				for (int j = 0; j < item_num; j++) {
					if (lpi->pid == pidset[j]) {
						index = j;
						break;
					}
				}
				// if (events & EPOLLIN) {
				
				// 	rfd = (struct epoll_rfd *)evs[i].data.ptr;
				// 	events = evs[i].events;
				// 	ret = read(rfd->fd, &msg, sizeof(msg));
				// }
				// if (events & (EPOLLHUP | EPOLLRDHUP)) {
				// 	ret = epoll_hangup_event(epollfd, rfd);
				// 	if (ret < 0)
				// 		return 0;
				// 	if (ret > 0)
				// 		continue;
				// }
				node = (struct index_node *)malloc(sizeof(struct index_node));
				node->index = i;
				mutex_lock(&event_sets->mutex);
				list_add_tail(&node->list, &event_sets->index_pipe[index]);

				// list_for_each_entry(nodei, &event_sets->index_pipe[index], list){
				// 	pr_warn("111node->index:%d\n", nodei->index);
				// }
				event_sets->events[index]++;
				mutex_unlock(&event_sets->mutex);

			} else {
				
				futex_inc_and_wake(&event_sets->nr_events);
				
				if (events & EPOLLIN) {
					ret = rfd->read_event(rfd);
				}
				
				if (events & (EPOLLHUP | EPOLLRDHUP)) {
					ret = epoll_hangup_event(epollfd, rfd);
				}
				continue;
			}

			
			
			// futex_inc_and_wake(&event_sets->events[index]);
			
		}
		
		futex_wait_until(&event_sets->nr_events, nr_events);
	}

	return 0;
}
#endif

#ifndef NO_EPOLL
static void *RDMA_PF_handle_request(void *arg)
{
	int epollfd, ret;
	struct epoll_event **events;
	int nr_fds;
	int poll_timeout = -1;
#ifdef EPOLL_PLUS
	pthread_t *pthread_set;
	struct tpe_args *th_args;
#endif
	struct RDMA_PF_handle_request_arg *temp_arg = (struct RDMA_PF_handle_request_arg *)arg;
	epollfd = temp_arg->epollfd;
	events = temp_arg->events;
	nr_fds = temp_arg->nr_fds;
	
#ifdef EPOLL_PLUS
	event_set_init();

	pthread_set = (pthread_t *)malloc(sizeof(pthread_t) * item_num);
	th_args = (struct tpe_args *)malloc(sizeof(struct tpe_args) * item_num);
	for (int i = 0; i < item_num; i++) {
		th_args[i].epollfd = epollfd;
		th_args[i].events = events;
		th_args[i].index = i;
		pthread_create(&pthread_set[i], NULL, thread_process_event, &th_args[i]);
	}

#endif
	
	while (true) {
#ifdef EPOLL_PLUS
		ret = epoll_run_rfds_pthread(epollfd, *events, nr_fds, poll_timeout);
#else
		ret = epoll_run_rfds(epollfd, *events, nr_fds, poll_timeout);
#endif
		if (ret < 0) {
			pr_err("can not get epoll event\n");
			break;
		}
		if (ret > 0) {
			ret = complete_forks(epollfd, events, &nr_fds);
			if (ret < 0) {
				pr_err("can not complete forks\n");
				break;
			}
			if (restore_finished)
				poll_timeout = 0;
			if (!restore_finished || !ret)
				continue;
		}
	}

#ifdef EPOLL_PLUS
	for (int i = 0; i < item_num; i++)
		pthread_cancel(pthread_set[i]);
#endif
	return NULL;
}

#else //NO_EPOLL

struct tpe_args {
	int index; 
};

void *thread_process_event(void *args)
{
	// struct tpe_args *temp_args;
	// int index;
	// int ret, uffd, head = 0, pid;
	// struct page_data_set_t *buf;
	// struct uffdio_copy uffdio_copy;
	// struct lazy_pages_info *lpi;
	// struct uffd_msg msg;
	// int nread;

	// temp_args = (struct tpe_args *)args;
	// index = temp_args->index;
	// buf = (struct page_data_set_t *)PF_res.buf;
	// uffd = uffdset[index];
	// pid = pidset[index];

	// while (true) {
	// 	// wait for a message
	// 	ret = (nread = read(uffd, &msg, sizeof(msg)));
	// 	if (ret != -1) {
	// 		head = buf->local_head[index];
	// 		buf->imm_data = msg.arg.pagefault.address & ~(4096 - 1);
	// 		if (buf->imm_data == 0)
	// 			continue;

	// 		// write address to the page server
	// 		ret = rdma_write(&PF_res, (sizeof(int) * MAX_PROCESS * 2) + (sizeof(uint64_t) * MAX_THREADS * index) + (sizeof(uint64_t) * head), (uint64_t)&buf->imm_data, 8, item_num);
	// 		buf->local_head[index] = (head + 1) % MAX_THREADS;
	// 		ret = rdma_write(&PF_res, sizeof(int) * index, (uint64_t)&buf->local_head[index], sizeof(int), item_num);
	// 		pf_cache_insert(pidset[index], buf->imm_data);
	// 	} else {
	// 		if (buf->head[index] != buf->tail[index]) {
	
	// 			uffdio_copy.dst = *(uint64_t *)buf->data[index][buf->tail[index]];
	// 			uffdio_copy.src = (uint64_t)&buf->data[index][buf->tail[index]][8];
	// 			uffdio_copy.len = 4096;
	// 			uffdio_copy.mode = 0;
	// 			uffdio_copy.copy = 0;

	
	// 			if (ioctl_mul(&uffdio_copy, pid) < 0) {
	// 				if (errno != EEXIST)
	// 					pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
	// 			}
	// 			buf->tail[index] = (buf->tail[index] + 1) % MAX_THREADS;
	// 		}
	// 	}
	// }
	return NULL;
}

pthread_t *pthread_set;

static void inline clear_PF_resource(void)
{
	for (int i = 0; i < item_num; i++)
		pthread_cancel(pthread_set[i]);
}

static void *RDMA_PF_handle_request(void *arg)
{
	int ret, nr_fds;
	struct epoll_event **events;
	int poll_timeout = -1;
	struct tpe_args *th_args;

	struct RDMA_PF_handle_request_arg *temp_arg = (struct RDMA_PF_handle_request_arg *)arg;
	epollfd = temp_arg->epollfd;
	events = temp_arg->events;
	nr_fds = temp_arg->nr_fds;

	pthread_set = (pthread_t *)malloc(sizeof(pthread_t) * item_num);
	th_args = (struct tpe_args *)malloc(sizeof(struct tpe_args) * item_num);
	for (int i = 0; i < item_num; i++) {
		th_args[i].index = i;
		pthread_create(&pthread_set[i], NULL, thread_process_event, &th_args[i]);
	}

	while (true) {
		ret = epoll_run_rfds(epollfd, *events, nr_fds, poll_timeout);
		if (ret < 0) {
			pr_err("epoll_wait failed\n");
			break;
		}
		if (ret > 0) {
			ret = complete_forks(epollfd, events, &nr_fds);
			if (ret < 0) {
				pr_err("complete_forks failed\n");
				break;
			}
			if (restore_finished)
				poll_timeout = 0;
			if (!restore_finished || !ret)
				continue;
		}
	}

	return NULL;
}
#endif

static void *RDMA_TS_handle_request(void *arg)
{
	// int epollfd;
	// struct epoll_event **events;
	int ret, pid = -1;
	struct transfer_t *mem;
	struct uffdio_copy uffdio_copy;
	struct RDMA_PF_handle_request_arg *temp_arg = (struct RDMA_PF_handle_request_arg *)arg;
	// epollfd = temp_arg->epollfd;
	// events = temp_arg->events;
	// nr_fds = temp_arg->nr_fds;
	post_receive(&TS_res, item_num, (uintptr_t)TS_res.buf, TRANSFER_REGION_SIZE);
	// post_receive(&TS_res, item_num, (uintptr_t)TS_res.buf, TRANSFER_REGION_SIZE);
	
	
	while (true) {
		uint64_t off = 0;
		/* make sure we return success if there is nothing to xfer */
		poll_completion(&TS_res);
		

		mem = (struct transfer_t *)TS_res.buf;
		// pr_warn("mem->is_fulled:%d, mem->is_ready:%d\n", mem->is_fulled, mem->is_ready);
		if (mem->is_fulled == -1) {
			// pr_warn("no page needed to xfer\n");
			break;
		}

		for (int i = 0; i < mem->nr_pi; i++) {
			int uffd = -1;
#ifdef MEM_PREDICT
			struct skipnode *node[1024];
			int length;
			uint64_t start, end;
			int try_times = 0;
#endif

			
			for (int j = 0; j < item_num; j++) {
				if (pidset[j] == mem->page_info[i].pid) {
					uffd = uffdset[j];
					pid = pidset[j];
					break;
				}
			}

#ifdef MEM_PREDICT
			
			
			
			

try_uffd:
			if (try_times++ < 5) {
				ret = pf_cache_range_search(mem->page_info[i].pid, mem->page_info[i].addr,
							    mem->page_info[i].addr + mem->page_info[i].leng * PAGE_SIZE, node, &length);

				if (ret != 0)
					pr_err("page not in PF\n");
				start = mem->page_info[i].addr;

				for (int j = 0; j <= length; j++) {
					if (j == length)
						end = mem->page_info[i].addr + mem->page_info[i].leng * PAGE_SIZE;
					else
						end = node[j]->key;

					if (end > start) {
						uffdio_copy.dst = start;
						uffdio_copy.src = (uint64_t)((uint64_t)get_mem(mem) + off * PAGE_SIZE + start - mem->page_info[i].addr);
						uffdio_copy.len = end - start;
						uffdio_copy.mode = 0;
						uffdio_copy.copy = 0;
						if (ioctl_mul(&uffdio_copy, pid) == -1) {
							// pr_err("ioctl failed\n");
							goto try_uffd;
						}
					}
					start = end + PAGE_SIZE;
				}
			} else {
				for (int j = 0; j < mem->page_info[i].leng; j++) {
					int done;
					done = pf_cache_get(mem->page_info[i].pid, mem->page_info[i].addr);
					if (done)
						continue;

					uffdio_copy.dst = mem->page_info[i].addr + j * PAGE_SIZE;
					uffdio_copy.src = (uint64_t)((uint64_t)get_mem(mem) + off * PAGE_SIZE + j * PAGE_SIZE);
					uffdio_copy.len = PAGE_SIZE;
					uffdio_copy.mode = 0;
					uffdio_copy.copy = 0;
					if (ioctl_mul(&uffdio_copy, pid) == -1) {
						pr_err("ioctl failed\n");
					}
				}
			}

#endif

			
			// pr_warn("uffd:%d, src:%lx, mem:%lx\n, off:%ld, leng:%ld", uffd, (uint64_t)((uint64_t)get_mem(mem) + off * 4096), (uint64_t)mem, off, mem->page_info[i].leng * 4096);
			// uffdio_copy.dst = mem->page_info[i].addr;
			// uffdio_copy.src = (uint64_t)((uint64_t)get_mem(mem) + off * 4096);
			// uffdio_copy.len = mem->page_info[i].leng * 4096;
			// uffdio_copy.mode = 0;
			// uffdio_copy.copy = 0;
			// if(ioctl_mul(&uffdio_copy, pid))
			// 	return NULL;
			
			off += mem->page_info[i].leng;
		}

		post_receive(&TS_res, item_num, (uintptr_t)TS_res.buf, TRANSFER_REGION_SIZE);
		// send ack

		*(uint32_t *)TS_res.buf = 1;
		// send_ack(&TS_res);
		post_send(&TS_res, IBV_WR_SEND, item_num, (uint64_t)TS_res.buf, 4);
		poll_completion(&TS_res);

		// sleep(10);
	}

	return NULL;
}

#endif

static int handle_requests(int epollfd, struct epoll_event **events, int nr_fds)
{
	struct lazy_pages_info *lpi, *n;
	int poll_timeout = -1;
	int ret;

	for (;;) {
		ret = epoll_run_rfds(epollfd, *events, nr_fds, poll_timeout);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			ret = complete_forks(epollfd, events, &nr_fds);
			if (ret < 0)
				goto out;
			if (restore_finished)
				poll_timeout = 0;
			if (!restore_finished || !ret)
				continue;
		}

		/* make sure we return success if there is nothing to xfer */
		ret = 0;

		list_for_each_entry_safe(lpi, n, &lpis, l) {
			if (!list_empty(&lpi->iovs) && list_empty(&lpi->reqs)) {
				ret = xfer_pages(lpi);
				if (ret < 0)
					goto out;
				break;
			}

			if (list_empty(&lpi->reqs)) {
				lazy_pages_summary(lpi);
				list_del(&lpi->l);
				lpi_put(lpi);
			}
		}
		
		if (list_empty(&lpis))
			break;
	}

out:
	return ret;
}

int lazy_pages_finish_restore(void)
{
	uint32_t fin = LAZY_PAGES_RESTORE_FINISHED;
	int fd, ret;

	if (!opts.lazy_pages)
		return 0;

	fd = fdstore_get(lazy_pages_sk_id);
	if (fd < 0) {
		pr_err("No lazy-pages socket\n");
		return -1;
	}

	ret = send(fd, &fin, sizeof(fin), 0);
	if (ret != sizeof(fin))
		pr_perror("Failed sending restore finished indication");

	close(fd);

	return ret < 0 ? ret : 0;
}

static int prepare_lazy_socket(void)
{
	int listen;
	char *buffer;
	struct sockaddr_un saddr;

	if (prepare_sock_addr(&saddr))
		return -1;

	buffer = (char *)malloc(1024);
	if (getcwd(buffer, 1024) != NULL)
		pr_warn("work_dir:%s\n", buffer);
	pr_warn("work_dir:%s\n", buffer);
	pr_debug("Waiting for incoming connections on %s\n", saddr.sun_path);
	if ((listen = server_listen(&saddr)) < 0) {
		pr_perror("server_listen error");
		return -1;
	}

	return listen;
}

static int lazy_sk_read_event(struct epoll_rfd *rfd)
{
	uint32_t fin;
	int ret;

	
	ret = recv(rfd->fd, &fin, sizeof(fin), 0);
	/*
	 * epoll sets POLLIN | POLLHUP for the EOF case, so we get short
	 * read just before hangup_event
	 */
	if (!ret)
		return 0;

	if (ret != sizeof(fin)) {
		pr_perror("Failed getting restore finished indication");
		return -1;
	}

	if (fin != LAZY_PAGES_RESTORE_FINISHED) {
		pr_err("Unexpected response: %x\n", fin);
		return -1;
	}

	restore_finished = true;

	return 1;
}

static int lazy_sk_hangup_event(struct epoll_rfd *rfd)
{
	if (!restore_finished) {
		pr_err("Restorer unexpectedly closed the connection\n");
		return -1;
	}

	return 0;
}

static int prepare_uffds(int listen, int epollfd)
{
	int i;
	int client;
	socklen_t len;
	struct sockaddr_un saddr;
	pr_warn("run to here\n");
	/* accept new client request */
	len = sizeof(struct sockaddr_un);
	if ((client = accept(listen, (struct sockaddr *)&saddr, &len)) < 0) {
		pr_perror("server_accept error");
		close(listen);
		return -1;
	}
	pr_warn("run to here\n");
	InitPidUffdSet();
	pr_warn("run to here\n");
	for (i = 0; i < task_entries->nr_tasks; i++) {
		struct lazy_pages_info *lpi = NULL;
		
		if (ud_open(client, &lpi))
			goto close_uffd;
		if (lpi == NULL)
			continue;
#ifndef NO_EPOLL
		
		
		if (epoll_add_rfd(epollfd, &lpi->lpfd))
			goto close_uffd;
#endif
	}
	
	
	lazy_sk_rfd.fd = client;
	lazy_sk_rfd.read_event = lazy_sk_read_event;
	lazy_sk_rfd.hangup_event = lazy_sk_hangup_event;
	if (epoll_add_rfd(epollfd, &lazy_sk_rfd))
		goto close_uffd;

	
	close(listen);
	return 0;

close_uffd:
	close_safe(&client);
	close(listen);
	return -1;
}

pid_t get_container_pid(const char *container_name)
{
	char command[256];
	char buffer[128];

	
	snprintf(command, sizeof(command), "docker top %s", container_name);

	
	FILE *fp = popen(command, "r");
	if (fp == NULL) {
		perror("popen failed");
		return -1;
	}

	
	if (fgets(buffer, sizeof(buffer), fp) == NULL) {
		perror("fgets failed");
		fclose(fp);
		return -1;
	}

	
	if (fgets(buffer, sizeof(buffer), fp) != NULL) {
		
		char *token = strtok(buffer, " "); 
		token = strtok(NULL, " ");	   

		if (token != NULL) {
			pid_t pid = atoi(token); 
			fclose(fp);
			return pid;
		} else {
			printf("PID not found\n");
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return -1;
}

// target machine create a page client of lazy_page
int cr_lazy_pages(bool daemon)
{
	struct epoll_event *events = NULL;
	int nr_fds;
	int lazy_sk;
	int ret = 0;
	int index;
	struct epoch_area *PidEpochArea;
	struct access_area *access_area;
	struct __vma_area *vma;
	int i;
#ifdef RDMA_CODESIGN
	struct pstree_item *item;
	pthread_t PF_thread, TS_thread, FT_thread, load_thread;
	struct RDMA_PF_handle_request_arg PF_arg;
	struct RDMA_TS_arg TS_arg;
	char dev_name[10] = "mlx5_1";
	struct data_buffer *pre_mr;
#endif
#ifdef DOCKER
	char unix_addr[200];
	int page_sync, root_pid;
	int sync_fd_PC, sync_pretransfer;
#endif
	struct timespec start, end;
	long long elapsed_ns;
	log_set_loglevel(5);
	if (log_init("/var/lib/criu/pageclient.log") == -1) {
		pr_perror("Can't initiate log");
	}
	if (!kdat.has_uffd)
		return -1;
	pr_warn("cr_lazy_pages: create page client\n ");
#ifdef DOCKER
	resources_init(&PF_res);
	PF_res.config.dev_name = dev_name;
	PF_res.config.server_name = opts.addr;
	PF_res.config.ib_port = 1;
	resources_create(&PF_res);

	resources_init(&PT_res);
	PT_res.config.dev_name = dev_name;
	PT_res.config.server_name = opts.addr;
	PT_res.config.ib_port = 1;
	resources_create(&PT_res);

	resources_init(&TS_res);
	TS_res.config.dev_name = dev_name;
	TS_res.config.server_name = opts.addr;
	TS_res.config.ib_port = 1;
	resources_create_ts(&TS_res);

	resources_init(&FT_res);
	FT_res.config.dev_name = dev_name;
	FT_res.config.server_name = opts.addr;
	FT_res.config.ib_port = 1;
	resources_create_ts(&FT_res);

	
	strcpy(unix_addr, opts.work_dir);
	if (unix_addr[strlen(unix_addr) - 1] == '/')
		strcat(unix_addr, "sync.sock");
	else
		strcat(unix_addr, "/sync.sock");
	page_sync = syncClientInit_unix("sync.sock");
	if (page_sync <= 0)
		pr_err("Can not create Page-Client\n");

	sync_fd_PC = syncClientInit(opts.addr, opts.port);
	pr_warn("Try connect to %s:%d\n", opts.addr, opts.port + 1);
	// sync_pretransfer = syncClientInit(opts.addr, opts.port + 1);
	sync_pretransfer = sync_fd_PC;
	if (sync_fd_PC <= 0 || sync_pretransfer <= 0)
		pr_err("Create page-client failed.\n");
	// DOCKERTODO: prepare RDMA resource & connect_qp
	PF_res.buf = malloc(sizeof(struct page_data_set_t));
	memset(PF_res.buf, 0, sizeof(struct page_data_set_t));
	PF_res.mr_buf = ibv_reg_mr(PF_res.pd, PF_res.buf, sizeof(struct page_data_set_t),
				   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	PT_res.buf = malloc(sizeof(struct page_data_set_t));
	memset(PT_res.buf, 0, sizeof(struct page_data_set_t));
	PT_res.mr_buf = ibv_reg_mr(PT_res.pd, PT_res.buf, sizeof(struct page_data_set_t),
				   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	TS_res.buf = malloc(2 * sizeof(int) + TRANSFER_REGION_SIZE * TRANSFER_BUFFER_SIZE);
	memset(TS_res.buf, 0, 2 * sizeof(int) + TRANSFER_REGION_SIZE * TRANSFER_BUFFER_SIZE);
	TS_res.mr_buf = ibv_reg_mr(TS_res.pd, TS_res.buf, 2 * sizeof(int) + TRANSFER_REGION_SIZE * TRANSFER_BUFFER_SIZE,
				   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	FT_res.buf = malloc(sizeof(struct prefetch_t_buffer));
	memset(FT_res.buf, 0, sizeof(struct prefetch_t_buffer));
	FT_res.mr_buf = ibv_reg_mr(FT_res.pd, FT_res.buf, sizeof(struct prefetch_t_buffer),
				   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	connect_qp(&PF_res, sync_fd_PC, 0);
	connect_qp(&PT_res, sync_fd_PC, 0);
	connect_qp(&TS_res, sync_fd_PC, 0);
	connect_qp(&FT_res, sync_fd_PC, 0);
	pr_warn("run to here\n");
	while(1){
		ret = read(sync_pretransfer, &item_num, 4);
		if (item_num == 1){
			pr_warn("读取到pre_mr的item_num:%d\n", item_num);
			break;
		}
	}
	pr_warn("开始读取pre_mr, item_num:%d\n", item_num);
	
	pre_mr = (struct data_buffer *)malloc(sizeof(struct data_buffer) * item_num);
	ret = read(sync_pretransfer, pre_mr, sizeof(struct data_buffer) * item_num);
	item_num = 0;

	pr_warn("run to here, pre_mr->raddr:%lx\n", pre_mr->r_addr);

	
	pre_mr->length1 = pre_mr->mr.length;
	// pre_mr->length1 = 4 * 1024 * 1024;
	pr_warn("run to here length1:%ld\n",pre_mr->length1);
	wait_state(sync_pretransfer, END_PAGE_PRTRANSFER);
	rdma_read_pretransfer(&PT_res, pre_mr, 1);
	pr_warn("读取请求发送\n");
	// ret = poll_completion(&PT_res);
	pr_warn("RDMA读取数据成功, vma_num:%d off:%lx, pid:%ld\n", *(int *)(pre_mr->l_addr1 + 16), *(u_int64_t *)(pre_mr->l_addr1 + 8), *(u_int64_t *)(pre_mr->l_addr1));
	// close(sync_fd_PC);
	wait_state(sync_pretransfer, END_PROCESS_DUMP);
	pr_warn("pstreee恢复开始\n");
#endif
	pr_warn("睡眠1s等待pstree.img ready\n");
	sleep(1);
	
	if (prepare_dummy_pstree())
		return -1;

#ifdef RDMA_CODESIGN

#ifndef DOCKER
	
	resources_init(&PF_res);
	PF_res.config.dev_name = dev_name;
	PF_res.config.server_name = opts.addr;
	PF_res.config.ib_port = 1;
	if (resources_create(&PF_res))
		pr_err("RDMA resource create failed\n");

	resources_init(&PT_res);
	PT_res.config.dev_name = dev_name;
	PT_res.config.server_name = opts.addr;
	PT_res.config.ib_port = 1;
	if (resources_create(&PT_res))
		pr_err("RDMA resource create failed\n");

	resources_init(&TS_res);
	TS_res.config.dev_name = dev_name;
	TS_res.config.server_name = opts.addr;
	TS_res.config.ib_port = 1;
	if (resources_create_ts(&TS_res))
		pr_err("RDMA resource create failed\n");

	pr_info("start create the FT RDMA resources.\n");
	resources_init(&FT_res);
	FT_res.config.dev_name = dev_name;
	FT_res.config.server_name = opts.addr;
	FT_res.config.ib_port = 1;
	resources_create(&FT_res);
	pr_info("all RDMA resources is created.\n");

	for_each_pstree_item(item) {
		pidset[item_num] = item->pid->ns[0].virt;
		item_num++;
	}
	buble_sort(pidset, item_num);
	PF_res.mr = (struct ibv_mr **)calloc(item_num + 1, sizeof(struct ibv_mr *));
	PF_res.buf = malloc(sizeof(struct page_data_set_t));
	memset(PF_res.buf, 0, sizeof(struct page_data_set_t));
	PF_res.mr[item_num] = ibv_reg_mr(PF_res.pd, PF_res.buf, sizeof(struct page_data_set_t),
					 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (PF_res.mr[item_num] == NULL)
		pr_err("RDMA memory registry\n");

	PT_res.mr = (struct ibv_mr **)calloc(item_num + 1, sizeof(struct ibv_mr *));
	PT_res.buf = malloc(sizeof(struct page_data_set_t));
	memset(PT_res.buf, 0, sizeof(struct page_data_set_t));
	PT_res.mr[item_num] = ibv_reg_mr(PT_res.pd, PT_res.buf, sizeof(struct page_data_set_t),
					 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (PT_res.mr[item_num] == NULL)
		pr_err("RDMA memory registry\n");

	TS_res.buf = malloc(TRANSFER_REGION_SIZE);
	TS_res.mr[item_num] = ibv_reg_mr(TS_res.pd, TS_res.buf, TRANSFER_REGION_SIZE,
					 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);

	FT_res.buf = malloc(sizeof(struct prefetch_t_buffer));
	memset(FT_res.buf, 0, sizeof(struct prefetch_t_buffer));
	FT_res.mr[item_num] = ibv_reg_mr(FT_res.pd, FT_res.buf, sizeof(struct prefetch_t_buffer),
					 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (FT_res.mr_buf == NULL)
		pr_err("RDMA memory registry: FT\n");
#else
	for_each_pstree_item(item) {
		pidset[item_num] = item->pid->ns[0].virt;
		item_num++;
	}
	buble_sort(pidset, item_num);
	PF_res.mr = (struct ibv_mr **)calloc(item_num + 1, sizeof(struct ibv_mr *));
	PF_res.mr[item_num] = PF_res.mr_buf;
	PT_res.mr = (struct ibv_mr **)calloc(item_num + 1, sizeof(struct ibv_mr *));
	PT_res.mr[item_num] = PT_res.mr_buf;
	TS_res.mr[item_num] = TS_res.mr_buf;
	FT_res.mr[item_num] = FT_res.mr_buf;
#endif

#endif

#ifdef MEM_PREDICT
	// init phrase
	ret = pf_cache_init(pidset, item_num);
#endif
	
	lazy_sk = prepare_lazy_socket();
	if (lazy_sk < 0)
		return -1;

	if (daemon) {
		
		ret = cr_daemon(1, 0, -1);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			return -1;
		}
		if (ret > 0) { /* parent task, daemon started */
			if (opts.pidfile) {
				if (write_pidfile(ret) == -1) {
					pr_perror("Can't write pidfile");
					kill(ret, SIGKILL);
					waitpid(ret, NULL, 0);
					return -1;
				}
			}

			return 0;
		}
	}
	
	if (status_ready())
		return -1;

	/*
	 * we poll nr_tasks userfault fds, UNIX socket between lazy-pages
	 * daemon and the cr-restore, and, optionally TCP socket for
	 * remote pages
	 */
	pr_warn("run to here\n");
	
	nr_fds = task_entries->nr_tasks + (opts.use_page_server ? 2 : 1);
	epollfd = epoll_prepare(nr_fds, &events);
	if (epollfd < 0)
		return -1;
	pr_warn("run to here\n");
	
	if (prepare_uffds(lazy_sk, epollfd)) {
		xfree(events);
		return -1;
	}

	
	
	if (opts.use_page_server) {
		if (connect_to_page_server_to_recv(epollfd)) {
			xfree(events);
			return -1;
		}
	}

#ifdef RDMA_CODESIGN
	
	
	

	
	// connect_qp(&PF_res, page_server_sk, 0);
	// connect_qp(&TS_res, page_server_sk, 0);
	
	// memset(PF_res.buf, 's', 10);
	// post_send(&PF_res, IBV_WR_SEND, item_num, (uint64_t)PF_res.buf, 5);
	// poll_completion(&PF_res);
	

	pr_warn("run to here!\n");
	// while(1);

	
	wait_state(sync_pretransfer, END_PAGE_DIRTY);

	// read dirty flag from page server
	pre_mr->length2 = ONE_AREA_SIZE * item_num;
	// memset((void *)*(uint64_t *)(pre_mr->l_addr2), 1, pre_mr->length2);
	
	// usleep(300000);
	rdma_read_pretransfer(&PT_res, pre_mr, 2);
	// ret = poll_completion(&PT_res);
	pr_warn("root_item pid: %d\n", root_item->pid->real);
	// #define PIPE_NAME "/tmp/my_pipe"
	// ret = open(PIPE_NAME, O_RDONLY);
	// ret = read(ret, &root_pid, sizeof(root_pid));
	
	// if (ptrace(PTRACE_SEIZE, root_pid, 0, 0) == -1) {
	// 	pr_err("Child process ptrace seize pid:%d!\n", root_pid);
	// }
	// if (ptrace(PTRACE_INTERRUPT, root_pid, 0, 0) == -1) {
	// 	pr_err("Child process ptrace interrupt pid:%d!\n",root_pid);
	// }

	//=========================== Pidvma update start ====================================
	
	index = 0;
	PidVma[index] = (struct pid_vmas *)malloc(sizeof(struct pid_vmas));
	memset(PidVma[index], 0, sizeof(struct pid_vmas));
	
	PidEpochArea = (struct epoch_area *)(pre_mr->l_addr2 + ACCESS_VMA_SIZE);
	pr_warn("here\n");
	*(uint64_t *)((uint64_t)PidEpochArea + index * ONE_AREA_SIZE + 8) = ((uint64_t)PidEpochArea + index * ONE_AREA_SIZE + 4096);
	pr_warn("here\n");
	access_area = (struct access_area *)((struct epoch_area *)((uint64_t)PidEpochArea + index * ONE_AREA_SIZE))->areas[0];
	pr_warn("here\n");
	PidVma[index]->vmas = (struct vmas_t *)malloc((access_area->num_vma) * sizeof(struct vmas_t));
	// PidVma[index]->can_lazy = (int *)malloc(i * sizeof(int));
	// memset(PidVma[index]->can_lazy, 0, i * sizeof(int));
	pr_warn("创建%ld个vma\n", access_area->num_vma);
	for (i = 0; i < access_area->num_vma; i++) {
		vma = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * i);
		PidVma[index]->vmas[i].start = vma->start;
		PidVma[index]->vmas[i].end = vma->end;
		PidVma[index]->vmas[i].bitmap = (unsigned long *)malloc(round_up((vma->end - vma->start) / PAGE_SIZE, 64) / 8);
		memset(PidVma[index]->vmas[i].bitmap, 0, round_up((vma->end - vma->start) / PAGE_SIZE, 64) / 8);
	}
	PidVma[index]->num_vma = access_area->num_vma;
	PidVma[index]->pid = pidset[index];

	//=========================== Pidvma update end ====================================

	update_pid_array(pidset, item_num);
	clock_gettime(CLOCK_MONOTONIC, &start);
	pthread_create(&load_thread, NULL, page_client_load_page_V2, (void *)pre_mr);
	pthread_join(load_thread, NULL);
	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
	pr_warn("耗时：%lld ns\n", elapsed_ns);

	// if (ptrace(PTRACE_DETACH, root_pid, NULL, NULL))
	// 			pr_err("Unable to detach from %d", root_pid);

	PF_arg.epollfd = epollfd;
	PF_arg.events = &events;
	PF_arg.nr_fds = nr_fds;
	
	TS_arg.index = 0;
	mutex_init(&clientmutex);
	pr_warn("create three client thread\n");
	
	// pthread_create(&TS_thread, NULL, ioctl_write_thread, &TS_arg);
	// sleep(1000);
	// PF_client_stop=1;
	pthread_create(&PF_thread, NULL, RDMA_PF_handler_client, &PF_arg);
	// pthread_create(&FT_thread, NULL, RDMA_FT_handler_client, NULL);
	// usleep(10000);
	TS_client_stop = 1;
	pthread_create(&TS_thread, NULL, RDMA_TS_handler_client, &TS_arg);

	// usleep(200000);
	// update_state(PF_res.sock, START_TS_PAGE);
	

	// PF_client_stop = 1;
	// clock_gettime(CLOCK_MONOTONIC, &start);
	// pthread_create(&load_thread, NULL, page_client_load_page_V2, (void *)pre_mr);
	// pthread_join(load_thread, NULL);
	// clock_gettime(CLOCK_MONOTONIC, &end);
	// elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9
	//                + (end.tv_nsec - start.tv_nsec);
	
	// PF_client_stop = 0;

	pthread_join(PF_thread, NULL);
	// pthread_join(FT_thread, NULL);
	pthread_join(TS_thread, NULL);

#ifdef NO_EPOLL
	clear_PF_resource();
#endif
	//TODO:znashi gaunbi
	pthread_cancel(PF_thread);
	// sleep(10000);
	
	exit(0);
	// resources_destroy(&PF_res);
	// resources_destroy(&TS_res);
	// close(PF_res.sock);
	// disconnect_from_page_server();
#else
	ret = handle_requests(epollfd, &events, nr_fds);
	disconnect_from_page_server();
#endif
	// xfree(events);
	return ret;
}
