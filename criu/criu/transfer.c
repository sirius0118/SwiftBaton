/**
 * transfer.c contains three functions:
 * 1. page-fault        :   RDMA_PF_handler_server(), RDMA_PF_handler_client()
 * 2. page prefetch     :   RDMA_FT_handler_server(), RDMA_FT_handler_client()
 * 3. page transfer     :   RDMA_TS_handler_server(), RDMA_TS_handler_client()
 * 
 */



#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <time.h>
#include <string.h>

#include "linux/userfaultfd.h"

#include "uffd.h"
#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "RDMA.h"
#include "transfer.h"
#include "pf-cache.h"
#include "util.h"
#include "analyze-access.h"
#include "pre-transfer.h"
#include "mul-uffd.h"
// #include "shregion.h"
#define PF_DEBUG
#define TS_DEBUG
#define FT_DEBUG
#define DELAY
// #include "cr-dump.h"

// #define PAGE_SIZE 4096
#ifdef PARALLEL_DUMP
#define MAX_PID 32768
extern int item_num;
extern uint64_t pidset[MAX_PROCESS];
extern uint64_t vpidset[MAX_PROCESS];
extern int socketset[MAX_PROCESS];
extern int uffdset[MAX_PROCESS];
// extern uint64_t pid2index[MAX_PID];
#endif

extern int list_length;
extern struct pid_data_list *pid_data_list;

#ifdef RDMA_CODESIGN
// #include "RDMA.h"
// #include "common/shregion.h"
// #include "transfer.h"
// #include "pre-transfer.h"

//client RDMA resources
extern struct resources PF_res;
extern struct resources TS_res;
extern struct resources FT_res;
extern struct resources PT_res;

//server and pie client
extern volatile struct mul_shregion_t *SharedRegions;
extern volatile struct transfer_t *TransferRegions;
extern volatile struct prefetch_t *PrefetchRegions;

//pagefault server and prefetch server
extern struct pid_FT_area *pid_area;

extern volatile struct pid_vmas *PidVma[MAX_PROCESS];
extern mutex_t tsmutex;

//3 client
extern volatile struct PF_address_set PFaddrset[MAX_PROCESS];
extern mutex_t clientmutex;
#endif

volatile int TS_server_stop = 0, TS_client_stop = 0, FT_server_stop = 0, PF_server_stop = 0, PF_client_stop = 0, write_stop = 0;

bool stop = false;

int prefetch_size = 2;

static int TS_id = 0;

void delay_1us(int n) {
	for (int i = 0; i < n; i++) {
		asm volatile (
			"mov $900, %%ecx\n"  // Assume 100 iterations for ~1us delay (adjust as needed)
			"1:\n"
			"dec %%ecx\n"
			"jnz 1b\n"
			:
			:
			: "ecx", "memory"
		);
	}
}

uint64_t inline pid2index(uint64_t pid)
{
	
	for (int i = 0; i < item_num; i++) {
		// pr_warn("pid:%d\n",(int)pidset[i]);
		if (pidset[i] == pid)
			return i;
	}
	pr_warn("index not found\n");

	return -1;
}

int get_vmas_index(int index, uint64_t addr)
{
	// pr_warn("get_vmas_index  pid:%d, addr:%lx\n", pid, addr);
	for (int i = 0; i < PidVma[index]->num_vma; i++) {
		if (PidVma[index]->vmas[i].start <= addr && PidVma[index]->vmas[i].end >= addr) {
			return i;
		}
	}
	return -1;
}

// --------------  page-fault  --------------

void *RDMA_PF_handler_server(void *arg)
{
	struct resources *res = (struct resources *)arg;
	volatile struct page_request_set_t *buf = (struct page_request_set_t *)res->buf;
	struct PF_PageResponse *resp;
	struct shregion_t *sh;
	int ret;
	volatile int head, *hhead;
	int PF_exist = 0;
	volatile int *vhead, *vtail;
	volatile int64_t *shead, *stail;

	for (int i = 0; i < 101; i++) {
		buf->num[i] = i;
	}

	pr_warn("PF开始\n");
	while (true) {
		// pr_warn("PF loop\n");
		// sleep(0.01);
		while (PF_server_stop)
			;
		for (int i = 0; i < item_num; i++) {
			
			// if (*(int *)buf == -1) {
			// 	stop = true;
			// 	break;
			// }
			__asm__ __volatile__("" ::: "memory");
			vhead = &buf->head[i];
			vtail = &buf->tail[i];
			if (*vhead != *vtail) {
				// pr_debug("dumpe1 :%lx\n", buf->addr[i][buf->tail[i]]);
				sh = SharedRegions->shregions[i];

#ifdef PF_DEBUG
				pr_debug("dump1.5:%lx  tail:%d\n", buf->addr[i][*vtail], *vtail);
#endif
				WQenqueue(&sh->address_queue, buf->addr[i][*vtail]);
				// pr_debug("dumpe2 :%lx\n", buf->addr[i][buf->tail[i]]);
				enqueueFT(&(pid_area[i].area), buf->addr[i][*vtail]);
				// sh->isPageFault++;
				buf->tail[i] = (*vtail + 1) % MAX_THREADS;
				// pr_debug("dumpe3 :%lx\n", buf->addr[i][buf->tail[i]]);
			}
		}

		// serve response: send pages to page-client
		PF_exist = 0;
		for (int i = 0; i < item_num; i++) {
			
			__asm__ __volatile__("" ::: "memory");
			sh = SharedRegions->shregions[i];
			shead = &sh->data_queue.head;
			stail = &sh->data_queue.tail;
			// if (SharedRegions->shregions[i]->isPageReady > 0) {
			// shead =& sh->data_queue.head;
			// stail =& sh->data_queue.tail;
			if (*shead != *stail) {
				uint64_t addr = (uint64_t)(sh->data_queue.data[*shead].address);
				// pr_warn("1: %lx\n", addr);
				hhead = &buf->local_head[i];
				head = *hhead;

				// if (sh->isPageReady > 0 || sh->isPageFault > 0) {
				// 	PF_exist = 1;
				// }
				// sh->isPageReady--;
				resp = (struct PF_PageResponse *)CQdequeue(&sh->data_queue);
				// pr_warn("3: %lx\n", addr);

				// ret = rdma_write(res, (uint64_t)(4 * MAX_PROCESS * 2) + (uint64_t)(PF_DATA_SIZE * MAX_THREADS * i) + (uint64_t)(PF_DATA_SIZE * head),
				//  (uint64_t)&resp->addr, PF_DATA_SIZE, i);
				// pr_warn("3: %lx\n", addr);
				// buf->local_head[i]++;
				buf->local_head[i] = (head + 1) % MAX_THREADS;
				hhead = &(buf->num[(head + 1) % MAX_THREADS]);
				__asm__ __volatile__("" ::: "memory");
				ret = rdma_write_2(res, (uint64_t)(4 * MAX_PROCESS * 2) + (uint64_t)(PF_DATA_SIZE * MAX_THREADS * i) + (uint64_t)(PF_DATA_SIZE * head),
						   (uint64_t)&resp->addr, PF_DATA_SIZE, i,
						   sizeof(int) * i, (uint64_t)hhead, sizeof(int), item_num);
				
				// 	 (uint64_t)(4 * MAX_PROCESS * 2) + (uint64_t)(PF_DATA_SIZE * MAX_THREADS * i) + (uint64_t)(PF_DATA_SIZE * head), (uint64_t)hhead);
				// ret = rdma_write(res, sizeof(int) * i, (uint64_t)&buf->local_head[i], sizeof(int), item_num);
				if (ret)
					pr_err("rdma_write error");
				// pr_warn("4: %lx\n", addr);
				pr_debug("rdma发送结束: lhead:%d head:%d tail:%d\n", buf->local_head[i], buf->head[i], buf->tail[i]);
			}
		}
		// if (stop && PF_exist == 0)
		// 	break;
	}
	pr_debug("PF数据结束\n");

	return NULL;
}

struct the_args {
	int index;
};
extern int item_num;
extern uint64_t pidset[MAX_PROCESS];
extern int uffdset[MAX_PROCESS];

int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl(F_GETFL)");
		return -1;
	}
	if (flags & O_NONBLOCK)
		return 0;
	flags |= O_NONBLOCK; 
	if (fcntl(fd, F_SETFL, flags) == -1) {
		perror("fcntl(F_SETFL)");
		return -1;
	}

	return 0;
}
int page_fault_num = 0;
void *thread_handle_event(void *args)
{
	struct the_args *temp_args;
	volatile int index;
	int ret = 0, nr_uffd, uffd;
	volatile int head = 0, *lhead;
	// int *head,*tail,*loacl_head;
	volatile struct page_data_set_t *buf;
	volatile uint64_t temp_addr;
	volatile struct uffdio_copy uffdio_copy;
	struct lazy_pages_info *lpi;
	struct uffd_msg msg;
	int nread;
	int pid;
	unsigned long label = 0;
	static volatile int page_fault_num = 0;
	volatile int *PF_head, *PF_tail;
	// struct pid_uffd_region_set *mul_uffdset;
	temp_args = (struct the_args *)args;
	index = temp_args->index;
	buf = (struct page_data_set_t *)PF_res.buf;
	// uffd = uffdset[index];
	pid = pidset[index];
	nr_uffd = PidUffdSet[index].nr_uffd_region;
	// mul_uffdset=&PidUffdSet[index];
	// loacl_head=&(buf->local_head[index]);
	// tail=&(buf->tail[index]);
	// head=&(buf->head[index]);
	PF_head = &buf->head[index];
	PF_tail = &buf->tail[index];
	if (pid != PidUffdSet[index].pid) {
		pr_err("pid 不对应, %d. %ld\n", pid, PidUffdSet[index].pid);
		return NULL;
	}
#ifdef PF_DEBUG
	pr_warn("添加O_NONBLOCK标志, nr_uffd:%d\n", nr_uffd);
#endif
	
	for (int i = 0; i < nr_uffd; i++) {
		if (set_nonblocking(PidUffdSet[index].uffd_region[i].uffd) != 0) {
			pr_err("Error: add no-block flags.\n");
		}
	}

	pr_warn("客户端PF线程启动\n");
	for (int i = 0; i < 101; i++)
		buf->num[i] = i;
	while (PF_client_stop);

	while (true) {
		// wait for a message
		// pr_warn("uffd:%d\n",uffd);
		// ret = (nread = read(uffd, &msg, sizeof(msg)));
		// sleep(0.01);
		// pr_warn("prepeare read uffd\n");
		label++;
		for (int i = 0; i < nr_uffd; i++) {
			ret = (nread = read(PidUffdSet[index].uffd_region[i].uffd, &msg, sizeof(msg)));
			if (nread > 0) {
				__asm__ __volatile__("" ::: "memory");
				lhead = &buf->local_head[index];
				head = *lhead;
				buf->imm_data[(head % 2)] = msg.arg.pagefault.address & ~(4096 - 1);

				__asm__ __volatile__("" ::: "memory");
				// pr_warn("%d read msg: %lx head:%d\n", label, buf->imm_data[(head % 2)], head);
				// usleep(30);
				if(page_fault_num >= 30)
					TS_client_stop = 0;
				else
					page_fault_num++;

				if (buf->imm_data[(head % 2)] == 0)
					continue;
#ifdef PF_DEBUG
				// pr_warn("%d cPF: %lx\n",label, buf->imm_data);
				// page_fault_num++;
				// pr_warn("page_fault_num:%d\n", page_fault_num);
				// if(page_fault_num==50){
				// 	while(TS_id<3){
				// 		sleep(0.00000001);
				// 	}
				// }
#endif
				// pr_warn("%d 0: %lx\n",label, buf->imm_data);
				// write address to the page server
				// ret = rdma_write(&PF_res, (sizeof(int) * MAX_PROCESS * 2) + (sizeof(uint64_t) * MAX_THREADS * index) + (sizeof(uint64_t) * head), (uint64_t)&buf->imm_data, 8, item_num);
				// pr_warn("%d 1: %lx\n",label, buf->imm_data);
				// buf->local_head[index] = (head + 1) % MAX_THREADS;

				buf->local_head[index] = (head + 1) % MAX_THREADS;
				lhead = &(buf->num[(head + 1) % MAX_THREADS]);
#ifdef DELAY
				// delay_1us(2);
#endif
				// ret = rdma_write(&PF_res, sizeof(int) * index, (uint64_t)&buf->local_head[index], sizeof(int), item_num);
				__asm__ __volatile__("" ::: "memory");
				ret = rdma_write_2(&PF_res, (sizeof(int) * MAX_PROCESS * 2) + (sizeof(uint64_t) * MAX_THREADS * index) + (sizeof(uint64_t) * head), (uint64_t)&buf->imm_data[(head % 2)], 8, item_num,
						   sizeof(int) * index, (uint64_t)lhead, sizeof(int), item_num);
// pr_warn("%d 2 : %lx\n", label,buf->imm_data);
#ifdef PF_DEBUG
				// pr_warn("PF rdma write\n");
				pr_warn("%ld send msg: %lx head:%d\n", label, buf->imm_data[(head % 2)], buf->local_head[index]);
#endif
				// pf_cache_insert(pidset[index], buf->imm_data);
				// pr_warn("read msg\n");
				break;
			}
			// else{
			// 	pr_warn("no pf\n");
			// }
		}

		if (*PF_head != *PF_tail) {
			volatile uint64_t src, dst;
#ifdef PF_DEBUG
			pr_warn("PF准备写页面\n");
#endif
			
			// pfcheck = 0;
			__asm__ __volatile__("" ::: "memory");
			// dst = *(uint64_t *)PF_buf->data[index][*PF_tail];
			// src = (uint64_t)&PF_buf->data[index][*PF_tail][8];
			dst = *(uint64_t *)buf->data[index][*PF_tail];
			src = (uint64_t)&buf->data[index][*PF_tail][8];
			__asm__ __volatile__("" ::: "memory");
			uffdio_copy.dst = dst;
			uffdio_copy.src = src;
			uffdio_copy.len = 4096;
			uffdio_copy.mode = 0;
			uffdio_copy.copy = 0;
#ifdef PF_DEBUG
			pr_warn("准备ioctl页面, addr:%lx, index:%d, head:%d, tail:%d\n",(uint64_t)uffdio_copy.dst, index, buf->head[index], buf->tail[index]);
#endif

			
			for(int i=0;i<PidVma[index]->num_vma;i++){
				if((uffdio_copy.dst>=PidVma[index]->vmas[i].start) && (uffdio_copy.dst<PidVma[index]->vmas[i].end)){
					if(test_bit( (uffdio_copy.dst - PidVma[index]->vmas[i].start) / PAGE_SIZE,PidVma[index]->vmas[i].bitmap)){
						// goto skip_pf;
					}
					set_bit((uffdio_copy.dst - PidVma[index]->vmas[i].start) / PAGE_SIZE,PidVma[index]->vmas[i].bitmap);
					break;
				}
			}
			
			// pr_warn("%d 3: %lx\n",label, (uint64_t)uffdio_copy.dst);
			if ((ret = ioctl_mul(&uffdio_copy, pid)) < 0) {
				pr_err("PF ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
			} else {
				// PF_address_set_insert(&PFaddrset[index], uffdio_copy.dst);
			}
			// skip_pf:
#ifdef PF_DEBUG
			pr_warn(" done, addr:%lx tail:%d head:%d\n", (uint64_t)uffdio_copy.dst, *PF_tail, *PF_head);
			// pr_warn(" done, addr:%lx tail:%d head:%d\n", (uint64_t)uffdio_copy.dst, PFR_tail, PFR_head);
			//pr_warn("pfcheck: done, addr:%lx tail:%d head:%d\n", (uint64_t)uffdio_copy.dst, *PF_tail, *PF_head);

#endif
			
			// pfcheck = 0;
			// buf->tail[index] = (buf->tail[index] + 1) % MAX_THREADS;
			buf->tail[index] = (*PF_tail + 1) % MAX_THREADS;
		}
		// pr_warn("read uffd over\n");
		// if (ret != -1) {
		// 	// pr_warn("get PF\n");
		// }
	}
	pr_warn("PF线程退出\n");
	return NULL;
}

pthread_t *thread_set;
static void inline clear_PF_resource(void)
{
	for (int i = 0; i < item_num; i++) {
		pthread_cancel(thread_set[i]);
	}
	free(thread_set);
}

void *RDMA_PF_handler_client(void *arg)
{
	int ret, nr_fds;
	struct epoll_event *events;
	int poll_timeout = -1;
	struct the_args *th_args;
	int epollfd;
	int restore_finished = 0;

	struct RDMA_PF_handle_client_arg *temp_arg = (struct RDMA_PF_handle_client_arg *)arg;
	
	epollfd = temp_arg->epollfd;
	events = *temp_arg->events;
	nr_fds = temp_arg->nr_fds;

	thread_set = (pthread_t *)malloc(sizeof(pthread_t) * item_num);
	th_args = (struct the_args *)malloc(sizeof(struct the_args) * item_num);
	pr_warn("PF client start\n");
	for (int i = 0; i < item_num; i++) {
		th_args[i].index = i;
		pthread_create(&thread_set[i], NULL, thread_handle_event, &th_args[i]);
	}
	while (1)
		;
	while (true) {
		ret = epoll_run_rfds(epollfd, events, nr_fds, poll_timeout);
		if (ret < 0) {
			pr_err("epoll_wait failed\n");
			break;
		}
		if (ret > 0) {
			ret = complete_forks(epollfd, &events, &nr_fds);
			if (ret < 0) {
				pr_err("complete_forks failed\n");
				break;
			}
			
			if (restore_finished)
				poll_timeout = 0;
			if (!restore_finished || !ret)
				continue;
		}
		// if (stop) {
		// 	for (int i = 0; i < item_num; i++) {
		// 		if (pthread_join(thread_set[i], NULL) != 0) {
		// 			perror("pthread_join failed");
		// 			return NULL;
		// 		}
		// 	}
		// 	break;
		// }
	}
	pr_warn("PF client exit!\n");
	return NULL;
}

// --------------  page prefetch  --------------

void *RDMA_FT_handler_server(void *arg)
{
	int test_num = 0;
	int ret, i, num;
	volatile int *head, *tail;
	volatile int ahead, atail;
	volatile int *pie_ready;
	int exist_PF = 0;
	struct resources *res = (struct resources *)arg;
	int index;
	head = (int *)((void *)(res->buf));
	tail = (int *)((void *)(res->buf) + sizeof(int));
	pie_ready = &(PrefetchRegions->is_ready);
	pr_debug("FT开始\n");

	while (true) {
		
		exist_PF = 0;
		while (FT_server_stop)
			;
		for (i = 0; i < item_num; i++) {
			ahead = pid_area[i].area.head;
			atail = pid_area[i].area.tail;
			if (ahead != atail) {
				int vmas_index;
				unsigned long addr;
				test_num++;
				exist_PF = 1;

				addr = dequeueFT(&(pid_area[i].area));
#ifdef FT_DEBUG
				pr_warn("FT检测到页错误，页错误地址: %lx\n", addr);
#endif
				index = pid2index(pid_area[i].pid);
				vmas_index = get_vmas_index(index, addr);
				if (vmas_index == -1) {
					pr_err("Can't find the vmas index\n");
					return NULL;
				}
				// pr_warn("find the vmas index success!\n");
				num = 0;
				if (test_bit((addr - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, PidVma[i]->vmas[vmas_index].bitmap)) {
					continue;
				}
				mutex_lock(&tsmutex);
				
				// ca_bitmap_set(PidVma[i]->vmas[vmas_index].bitmap, (addr - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, 1);
				set_bit((addr - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, PidVma[i]->vmas[vmas_index].bitmap);
				mutex_unlock(&tsmutex);
				// continue;
				// send prefetch request to dumpee
				
				
				if (addr > PidVma[i]->vmas[vmas_index].start && !test_bit((addr - prefetch_size / 2 * 4096 - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, PidVma[i]->vmas[vmas_index].bitmap)) {
					mutex_lock(&tsmutex);
					
					// ca_bitmap_set(PidVma[i]->vmas[vmas_index].bitmap, (addr - prefetch_size / 2 * 4096 - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, 1);
					set_bit((addr - prefetch_size / 2 * 4096 - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, PidVma[i]->vmas[vmas_index].bitmap);
					mutex_unlock(&tsmutex);
// sleep(0.001);
//
#ifdef FT_DEBUG
					pr_warn("FT第一次预取地址：%lx\n", addr - prefetch_size / 2 * 4096);
#endif
					send_prefetch((struct prefetch_t *)PrefetchRegions, 1, vpidset[index], addr - prefetch_size / 2 * 4096, prefetch_size / 2 * 4096);
					num++;
				} else {
					send_prefetch((struct prefetch_t *)PrefetchRegions, 1, vpidset[index], 0, 0);
				}
				if (addr + 4096 < PidVma[i]->vmas[vmas_index].end && !test_bit((addr + 4096 - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, PidVma[i]->vmas[vmas_index].bitmap)) {
					mutex_lock(&tsmutex);
					
					// ca_bitmap_set(PidVma[i]->vmas[vmas_index].bitmap, (addr + 4096 - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, 1);
					set_bit((addr + 4096 - PidVma[i]->vmas[vmas_index].start) / PAGE_SIZE, PidVma[i]->vmas[vmas_index].bitmap);
					mutex_unlock(&tsmutex);
// sleep(0.001);
//
#ifdef FT_DEBUG
					pr_warn("FT第二次预取地址：%lx\n", addr + 4096);
#endif
					send_prefetch((struct prefetch_t *)PrefetchRegions, 2, vpidset[index], addr + 4096, prefetch_size / 2 * 4096);
				} else if (num) {
					send_prefetch((struct prefetch_t *)PrefetchRegions, 2, vpidset[index], 0, 0);

				} else {
					continue;
				}
#ifdef FT_DEBUG
				pr_warn("FT等待pie返回数据\n");
#endif
				while (*pie_ready != 1)
					;
// sleep(0.00000001);

// sleep(2);
// head=tail=0;
// rdma_read(res, 0, (uint64_t)(head), sizeof(int),0);
// rdma_read(res, sizeof(int), (uint64_t)(tail), sizeof(int),0);
#ifdef FT_DEBUG

#endif
				while ((*head + 1) % PREFETCH_BUFFER_SIZE == *tail) {
					// sleep(0.00000001);
					// rdma_read(res, 0, (uint64_t)(head), sizeof(int),0);
					// rdma_read(res, sizeof(int), (uint64_t)(tail), sizeof(int),0);
				}
// pr_warn("head:%d tail:%d\n",*head,*tail);
#ifdef FT_DEBUG
				pr_warn("prepare to send %lx, head: %d\n", PrefetchRegions->address1, *head);
				pr_warn("prepare to send %lx, head: %d\n", PrefetchRegions->address2, *head);
#endif
				rdma_write_ft(res, 2 * sizeof(int) + *head * sizeof(struct prefetch_t), (uint64_t)PrefetchRegions, sizeof(struct prefetch_t), 0);
				*head = (*head + 1) % PREFETCH_BUFFER_SIZE;
				
				rdma_write_ft(res, 0, (uint64_t)(head), sizeof(int), -1);
				
			}
		}
		// if(test_num>4){
		// 	while(1){
		// 		pr_warn("head:%d tail:%d\n",*head,*tail);
		// 		sleep(1);
		// 	}
		// }
		// if (exist_PF && stop) {
		// 	break;
		// }
	}
	return NULL;
}

void *RDMA_FT_handler_client(void *arg)
{
	volatile struct uffdio_copy uffdio_copy;
	volatile struct prefetch_t_buffer *buf;
	volatile struct prefetch_t *pst;
	int uffd, i, pid;
	int test_flag = -1;
	int index=0;
	int err;
	volatile int *head, *tail;

	buf = (struct prefetch_t_buffer *)FT_res.buf;
	pr_warn("FT client start!\n");

	head = &buf->head;
	tail = &buf->tail;
	while (1) {
		// pr_warn("head:%d tail:%d\n",buf->head,buf->tail);
		
		// sleep(0.0000001);
		if (*head != *tail) {
			

			
			pst = &(buf->data[*tail]);
			// uffd = uffdset[pid2index(pst->pid)];
			pid = pst->pid;
			index =pid2index(pid);
			
			if (pst->length1 != 0) {
				
				uffdio_copy.dst = (uint64_t)pst->address1;
				uffdio_copy.src = (uint64_t)&pst->data1;
				uffdio_copy.len = pst->length1;
				uffdio_copy.mode = 0;
				uffdio_copy.copy = 0;
				for(int i=0;i<PidVma[index]->num_vma;i++){
					if((uffdio_copy.dst>=PidVma[index]->vmas[i].start) && (uffdio_copy.dst<PidVma[index]->vmas[i].end)){
						if(test_bit( (uffdio_copy.dst - PidVma[index]->vmas[i].start) / PAGE_SIZE,PidVma[index]->vmas[i].bitmap)){
							
							goto skip1;
						}
						set_bit( (uffdio_copy.dst - PidVma[index]->vmas[i].start) / PAGE_SIZE,PidVma[index]->vmas[i].bitmap);
						break;
					}
				}
// sleep(0.01);
#ifdef FT_DEBUG
				pr_warn("client FT准备1写ioctl页面,dst:%lx, src:%lx, off:%lx\n", (uint64_t)uffdio_copy.dst, (uint64_t)uffdio_copy.src, (uint64_t)uffdio_copy.dst - (uint64_t)buf->data);
#endif
				if ((err = ioctl_mul(&uffdio_copy, pid)) < 0) {
					if (err != EEXIST)
						pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
				}
			}
			skip1:
			if (pst->length2 != 0) {
				
				uffdio_copy.dst = (uint64_t)pst->address2;
				uffdio_copy.src = (uint64_t)&pst->data2;
				uffdio_copy.len = pst->length2;
				uffdio_copy.mode = 0;
				uffdio_copy.copy = 0;
				for(int i=0;i<PidVma[index]->num_vma;i++){
					if((uffdio_copy.dst>=PidVma[index]->vmas[i].start) && (uffdio_copy.dst<PidVma[index]->vmas[i].end)){
						if(test_bit( (uffdio_copy.dst - PidVma[index]->vmas[i].start) / PAGE_SIZE,PidVma[index]->vmas[i].bitmap)){
							
							goto skip2;
						}
						set_bit( (uffdio_copy.dst - PidVma[index]->vmas[i].start) / PAGE_SIZE,PidVma[index]->vmas[i].bitmap);
						break;
					}
				}
// sleep(0.01);
#ifdef FT_DEBUG
				pr_warn("client FT准备2写ioctl页面,dst:%lx, src:%lx, off:%lx\n", (uint64_t)uffdio_copy.dst, (uint64_t)uffdio_copy.src, (uint64_t)uffdio_copy.dst - (uint64_t)buf->data);
#endif
				if ((err = ioctl_mul(&uffdio_copy, pid)) < 0) {
					if (err != EEXIST)
						pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
					else
						pr_err("other error\n");
				}
			}
			skip2:

			*tail = (*tail + 1) % PREFETCH_BUFFER_SIZE;
			
			rdma_write_ft_remote(&FT_res, sizeof(int), (uint64_t)tail, sizeof(int), -1);
			// test_flag--;
			
		}
		// else if (stop) {
		// 	break;
		// }
		
	}
	return NULL;
}

// --------------  page transfer  server --------------

extern volatile struct pid_vmas *PidVma[100];

static void try_to_send_request(struct resources *res, struct transfer_t *ts, int pid, uint64_t addr, uint64_t leng, int is_last)
{
	int ret;
	volatile int *head, *tail, *is_ready;
	int i = 0;
	head = (int *)TS_res.buf;
	tail = (int *)((void *)TS_res.buf + sizeof(int));
	is_ready = &ts->is_ready;
	if (unlikely(is_last == 1)) {
		ts->is_fulled = 1;
		while (*is_ready != 1) {
		};
#ifdef TS_DEBUG
		pr_warn("发送信息汇总:nr_pi:%d\n", TransferRegions->nr_pi);
		TransferRegions->id = rand();
		pr_warn("发送信息汇总:id:%d\n", TransferRegions->id);
#endif
		while ((*head + 1) % TRANSFER_BUFFER_SIZE == *tail) {
			// sleep(0.00000001);
		}
#ifdef DELAY
		
		// usleep(200);
#endif
		rdma_write_ts(res, 2 * sizeof(int) + *head * TRANSFER_REGION_SIZE, (uint64_t)TransferRegions, TRANSFER_REGION_SIZE, 0);
		*head = (*head + 1) % TRANSFER_BUFFER_SIZE;
		
		rdma_write_ts(res, 0, (uint64_t)(head), sizeof(int), -1);
		pr_warn("============================发送一轮\n");
		// pr_warn("busy wait success!\n");
		clean_transfer_t((struct transfer_t *)TransferRegions, item_num);
		return;
	}
	if (leng == 0)
		return;
	ret = send_request(ts, pid2vpid(pid, pidset, vpidset), addr, leng);

	
	if (ret == 0) {
		
		pr_warn("wait is ready!\n");
		while (*is_ready != 1) {
			// sleep(0.00000001);
		};
#ifdef TS_DEBUG
		pr_warn("发送信息汇总:nr_pi:%d\n", TransferRegions->nr_pi);
		TransferRegions->id = rand();
		pr_warn("发送信息汇总:id:%d\n", TransferRegions->id);
#endif
		while ((*head + 1) % TRANSFER_BUFFER_SIZE == *tail) {
			// sleep(0.00000001);
		}
		
		// for(i=0;i<TransferRegions->nr_pi;i++){
		// 	pr_warn("page info:addr:%lx, leng:%lx\n",  TransferRegions->page_info[i].addr, TransferRegions->page_info[i].leng);

		// }
		rdma_write_ts(res, 2 * sizeof(int) + *head * TRANSFER_REGION_SIZE, (uint64_t)TransferRegions, TRANSFER_REGION_SIZE, 0);
		*head = (*head + 1) % TRANSFER_BUFFER_SIZE;
		
		rdma_write_ts(res, 0, (uint64_t)(head), sizeof(int), -1);
		// pr_warn("busy wait success!\n");
		clean_transfer_t((struct transfer_t *)TransferRegions, item_num);
		ret = send_request(ts, pid2vpid(pid, pidset, vpidset), addr, leng);
		pr_warn("============================发送一轮\n");
#ifdef TS_DEBUG
		TS_id++;
		pr_warn("==================================第%d轮=====================================\n", TS_id);
		
#endif

	} else {
#ifdef TS_DEBUG
		
#endif
	}
}

void *RDMA_TS_handler_server(void *arg)
{
	int ret, i, j, index, k, m;
	int last_k;
	
	struct resources *res = (struct resources *)arg;
	

	struct score_list *temp_dirtylist;
#ifdef TS_DEBUG
	pr_warn("TS开始\n");
	srand((unsigned int)time(NULL));
#endif

// sleep(2);


#ifdef TS_DEBUG
	pr_warn("TS dirty list length: %d\n", list_length);
	for (i = 0; i < item_num; i++) {
		for (j = 0; j < PidVma[i]->num_vma; j++) {
			// if (PidVma[i]->can_lazy[j] == 0) {
			// 	// pr_warn("TS can not be lazyed\n");
			// 	pr_warn("txtxtxtxtxtxtxtxtx cggvma %lx~%lx can not be lazyed\n", PidVma[i]->vmas[j].start, PidVma[i]->vmas[j].end);

			// } else {
			// 	pr_warn("txtxtxtxtxtxtxtxtx cggvma %lx~%lx can be lazyed\n", PidVma[i]->vmas[j].start, PidVma[i]->vmas[j].end);
			// }
			// memset(PidVma[i]->vmas[j].bitmap, 0, round_up((PidVma[i]->vmas[j].end - PidVma[i]->vmas[j].start) / PAGE_SIZE, 64) / 8);
			// pr_warn("\n");
			// for(k=0;k<(PidVma[i]->vmas[j].end-PidVma[i]->vmas[j].start)/4096/64;k++){
			// 	pr_info("vma bitmap:%lx\n",*(PidVma[i]->vmas[j].bitmap+k));
			// }
		}
	}
	pr_warn("==================================第%d轮=====================================\n", TS_id);
#endif



// 	for (m = 0; m < list_length; m++) {
// 		// pr_warn("TS loop\n");
// 		for (k = PRIORITY_QUEUE_LEVEL - 1; k >= 0; k--) {
// 			while (TS_server_stop)
// 				;
// 			temp_dirtylist = pid_data_list[m].dirtylist[k];
// 			if (temp_dirtylist == NULL) {
// 				continue;
// 			}
// 			index = pid2index(pid_data_list[m].pid);
// 			// pr_warn("get index success: %d\n", index);
// 			while (temp_dirtylist != NULL) {
// 				// pr_warn("TS inner loop vmanum:%d\n", PidVma[index]->num_vma);

// 				for (i = 0; i < PidVma[index]->num_vma; i++) {
// 					// pr_warn("TS vma find loop\n");
// 					if (PidVma[index]->vmas[i].start <= temp_dirtylist->addr && PidVma[index]->vmas[i].end >= temp_dirtylist->addr) {
// 						// pr_warn("TS find vma success\n");
// 						break;
// 					}
// 				}
// 				if (PidVma[index]->can_lazy[i] == 0) {
// 					// pr_warn("txtxtxtxtxtxtxtxtx %lx can not be lazyed\n", temp_dirtylist->addr);
// 					temp_dirtylist = temp_dirtylist->next;
// 					continue;
// 				}
// 				// pr_warn("TS find exit\n");

// 				j = (temp_dirtylist->addr - PidVma[index]->vmas[i].start) / PAGE_SIZE;
// 				// try_to_send_request(res, TransferRegions, pid_data_list[m].pid, temp_dirtylist->addr, 1, 0);
// 				if (!test_bit(j, PidVma[index]->vmas[i].bitmap)) {
// 					// pr_warn("TS to send\n");
// 					mutex_lock(&tsmutex);
// 					// pr_warn("set bit bitmap:0x%lx, bit index:%d\n", *(PidVma[index]->vmas[i].bitmap), j);

// 					set_bit(j, PidVma[index]->vmas[i].bitmap);
// 					// pr_warn("set bit success\n");
// 					mutex_unlock(&tsmutex);
// 					// pr_warn("try to send %lx\n", temp_dirtylist->addr);
// 					try_to_send_request(res, (struct transfer_t *)TransferRegions, pid_data_list[m].pid, temp_dirtylist->addr, 1, 0);
// 				}
// #ifdef TS_DEBUG
// 				else {

// 				}
// #endif
// 				// pr_warn("send over\n");
// 				temp_dirtylist = temp_dirtylist->next;
// 			}
// 		}
// 	}
#ifdef TS_DEBUG
	pr_warn("all priority send over\n");
#endif

	// sleep(100000);
	
	for (i = 0; i < item_num; i++) {
#ifdef TS_DEBUG
		pr_warn("总共%d个进程, 现在传输第%d个进程\n", item_num, i + 1);
#endif
		for (j = 0; j < PidVma[i]->num_vma; j++) {
			int nr_bit;
			while (TS_server_stop)
				;
			if (PidVma[i]->can_lazy[j] == 0) {
				// pr_warn("TS can not be lazyed\n");
				// pr_warn("txtxtxtxtxtxtxtxtx %lx~%lx can not be lazyed\n", PidVma[i]->vmas[j].start, PidVma[i]->vmas[j].end);
				continue;
			}
			// if(!(PidVma[i]->vmas[j].flags&0x00000001)){
			// 	continue;
			// }
			nr_bit = (PidVma[i]->vmas[j].end - PidVma[i]->vmas[j].start) / PAGE_SIZE;
			
			last_k = 0;
			for (k = 0; k < nr_bit; k++) {
				// if (ca_bitmap_get(PidVma[i]->vmas[j].bitmap, k)){
				
				// }
				// try_to_send_request(res, TransferRegions, PidVma[i]->pid, PidVma[i]->vmas[j].start + k * PAGE_SIZE, 1, 0);



				if (!test_bit(k, PidVma[i]->vmas[j].bitmap)) {
					mutex_lock(&tsmutex);
					
					set_bit(k, PidVma[i]->vmas[j].bitmap);
					mutex_unlock(&tsmutex);
					try_to_send_request(res, (struct transfer_t *)TransferRegions, PidVma[i]->pid, PidVma[i]->vmas[j].start + k * PAGE_SIZE, 1, 0);
				} else {
#ifdef TS_DEBUG
					
#endif
				}
					// try_to_send_request(res, (struct transfer_t *)TransferRegions, PidVma[i]->pid, PidVma[i]->vmas[j].start + k * PAGE_SIZE, 1, 0);
// 				} else {
// #ifdef TS_DEBUG

// #endif
// 				}



				// else if (k > last_k) {
				// 	pr_warn("prepare to send\n");
				
				// 	try_to_send_request(res, TransferRegions, PidVma[i]->pid, PidVma[i]->vmas[j].start + last_k * PAGE_SIZE, k - last_k, 0);
				// 	pr_warn("single send over\n");
				// 	last_k = k + 1;
				// } else {
				// 	last_k = k + 1;
				// }
			}
			// if (k > last_k) {
			// 	pr_warn("prepare to send\n");
			
			// 	try_to_send_request(res, TransferRegions, PidVma[i]->pid, PidVma[i]->vmas[j].start + last_k * PAGE_SIZE, k - last_k, 0);
			// 	pr_warn("single send over\n");
			// 	last_k = k + 1;
			// }
		}
	}

	try_to_send_request(res, (struct transfer_t *)TransferRegions, 0, 0, 0, 1);
	pr_warn("结束\n");
	while (1)
		;
	// page_server_done = 1;
	TransferRegions->is_fulled = -1;
	post_send(res, IBV_WR_SEND, 0, (uint64_t)TransferRegions, TRANSFER_REGION_SIZE);
	poll_completion(res);
	stop = true;

	sleep(0.1);

	pr_warn("TS完毕\n");
	while (1)
		;
	return NULL;
}

#define MUL_TS
#ifndef MUL_TS

pthread_t *TS_thread_set;
void *RDMA_TS_handler_client(void *arg)
{
	struct the_args *temp_args;
	struct transfer_t_buffer *buf;
	struct the_args *th_args;
	struct transfer_t *curbuf;
	volatile int *head, *tail;
	volatile struct uffdio_copy uffdio_copy;
	int sum = 0, i, off = 0, index, pid, ret = 0;
	time_t currentTime;
	pr_warn("TS client start!\n");
	temp_args = (struct the_args *)arg;
	index = temp_args->index;
	buf = (struct transfer_t_buffer *)TS_res.buf;
	head = &buf->head;
	tail = &buf->tail;
	pid = pidset[index];
	// post_receive(&TS_res, item_num, (uintptr_t)TS_res.buf, TRANSFER_REGION_SIZE);
	// post_receive(&TS_res, item_num, (uintptr_t)TS_res.buf, TRANSFER_REGION_SIZE);
	// pr_warn("receive 2!\n");
	// TS_thread_set = (pthread_t *)malloc(sizeof(pthread_t) * item_num);
	// th_args = (struct the_args *)malloc(sizeof(struct the_args) * item_num);
	// for (int i = 0; i < item_num; i++) {
	// 	is_ready[i] = 1;
	// 	th_args[i].index = i;
	// 	pthread_create(&TS_thread_set[i], NULL, TS_thread_handle_event, &th_args[i]);
	// }

	

	while (1) {
		if (*head != *tail) {
			off = 0;
			curbuf = (struct transfer_t *)(TS_res.buf + sizeof(int) * 2 + *tail * TRANSFER_REGION_SIZE);
#ifdef TS_DEBUG
			pr_warn("TS线程%d发现数据\n", pid);
			
			// mutex_lock(&ready_mutex[index]);
			pr_warn("==================================第%d轮=====================================\n", TS_id);
			TS_id++;

			pr_warn("接收信息汇总:nr_pi:%d\n", curbuf->nr_pi);
			pr_warn("发送信息汇总:id:%d\n", curbuf->id);
#endif
			for (i = 0; i < curbuf->nr_pi; i++) {
				
				
				if (curbuf->page_info[i].pid == pid) {
					

					
					for (uint64_t k = 0; k < curbuf->page_info[i].leng * 4096; k += 4096) {
						
						
						
						uffdio_copy.dst = (uint64_t)((void *)(curbuf->page_info[i].addr) + k);
						uffdio_copy.src = (uint64_t)((void *)get_mem(curbuf) + off * 4096);
						uffdio_copy.len = 4096;
						uffdio_copy.mode = 0;
						uffdio_copy.copy = 0;

						for(int j=0;j<PidVma[index]->num_vma;j++){
							if((uffdio_copy.dst>=PidVma[index]->vmas[j].start) && (uffdio_copy.dst<PidVma[index]->vmas[j].end)){
								if(test_bit( (uffdio_copy.dst - PidVma[index]->vmas[j].start) / PAGE_SIZE,PidVma[index]->vmas[j].bitmap)){
#ifdef TS_DEBUG
									pr_warn("TSbitmap为1，跳过addr: %lx\n", (uint64_t)uffdio_copy.dst);
#endif
									goto skip_ts_client;
								}
								set_bit( (uffdio_copy.dst - PidVma[index]->vmas[j].start) / PAGE_SIZE,PidVma[index]->vmas[j].bitmap);
								break;
							}
						}

#ifdef TS_DEBUG
						pr_warn("stststsststststststsstststts写ioctl页面,dst:%lx, src:%lx, len:%lx\n", (uint64_t)uffdio_copy.dst, (uint64_t)uffdio_copy.src, (uint64_t)uffdio_copy.len);
#endif
						

						if ((ret = ioctl_mul(&uffdio_copy, pid)) < 0) {
							if (ret != EEXIST)
								pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
							else {
								pr_err("TS other error!\n");
							}
						}
						skip_ts_client:
						off++;
					}
				} else {
#ifdef TS_DEBUG
					pr_warn("不是我的数据\n");
#endif
					off += curbuf->page_info[i].leng;
				}
			}
			*tail = (*tail + 1) % TRANSFER_BUFFER_SIZE;
			rdma_write_ts(&TS_res, sizeof(int), (uint64_t)&(buf->tail), sizeof(int), -1);
		}
	}

	while (1)
		;
	stop = true;
	return NULL;
}

#else

#define MUL_THREAD_NUM 2

struct TS_write_thread_arg{
	int all_threads;
	int write_index;
	struct the_args * args;
};

volatile int thread_state[TRANSFER_BUFFER_SIZE][MUL_THREAD_NUM];
pthread_mutex_t write_lock;

void * RDMA_TS_write_thread(void *arg)
{
	struct TS_write_thread_arg * temp_arg;
	int write_index, all_threads;
	volatile struct transfer_t_buffer *buf;
	volatile struct the_args *th_args;
	volatile struct transfer_t *curbuf;
	volatile int *head, *tail;
	volatile struct uffdio_copy uffdio_copy;
	int sum = 0, i, off = 0, index, pid, ret = 0, block_i;

	pr_warn("TS client start!\n");

	temp_arg = (struct TS_write_thread_arg *)arg;
	th_args = temp_arg->args;
	index = th_args->index;
	write_index = temp_arg->write_index;
	all_threads = temp_arg->all_threads;
	buf = (struct transfer_t_buffer *)TS_res.buf;
	head = &buf->head;
	tail = &buf->tail;
	pid = pidset[index];

	while (1)
	{
		int keep_runnging = -1;
		int start, end;
		if (*head == *tail)
			continue;
		
		if(*tail > *head)
			end = *head + TRANSFER_BUFFER_SIZE;
		else
			end = *head;

		for (int i = *tail; i < end; i++){
			if (thread_state[i % TRANSFER_BUFFER_SIZE][write_index] == 0){
				keep_runnging = i % TRANSFER_BUFFER_SIZE;
				break;
			}
		}
		// usleep(10000);
		__asm__ __volatile__("" ::: "memory");
		// pr_warn("head:%d, tail:%d, keep_running:%d\n",*head, *tail, keep_runnging);
		// pr_warn("%d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n", thread_state[0][0], thread_state[1][0], thread_state[2][0], thread_state[3][0], thread_state[4][0], thread_state[5][0], thread_state[6][0], thread_state[7][0], thread_state[8][0], thread_state[9][0]);
		if (keep_runnging == -1)
			continue;
		// pr_warn("head:%d, tail:%d, keep_running:%d\n",*head, *tail, keep_runnging);

		off = write_index;
		curbuf = (struct transfer_t *)(TS_res.buf + sizeof(int) * 2 + keep_runnging * TRANSFER_REGION_SIZE);
		for (i = write_index; i < curbuf->nr_pi; i += all_threads) {
			
			
			if (curbuf->page_info[i].pid == pid) {
				

				
				for (uint64_t k = 0; k < curbuf->page_info[i].leng * 4096; k += 4096) {
					
					
					
					uffdio_copy.dst = (uint64_t)((void *)(curbuf->page_info[i].addr) + k);
					uffdio_copy.src = (uint64_t)((void *)get_mem(curbuf) + off * 4096);
					uffdio_copy.len = 4096;
					uffdio_copy.mode = 0;
					uffdio_copy.copy = 0;

					for(int j=0;j<PidVma[index]->num_vma;j++){
						if((uffdio_copy.dst>=PidVma[index]->vmas[j].start) && (uffdio_copy.dst<PidVma[index]->vmas[j].end)){
							if(test_bit( (uffdio_copy.dst - PidVma[index]->vmas[j].start) / PAGE_SIZE,PidVma[index]->vmas[j].bitmap)){
								goto skip_ts_write;
							}
							set_bit( (uffdio_copy.dst - PidVma[index]->vmas[j].start) / PAGE_SIZE,PidVma[index]->vmas[j].bitmap);
							break;
						}
					}
						

					if ((ret = ioctl_mul(&uffdio_copy, pid)) < 0) {
						if (ret != EEXIST)
							pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
						else {
							pr_err("TS other error!\n");
						}
					}
					skip_ts_write:
					off += all_threads;
				}
			} else {
				pr_warn("不是我的页面\n");
				off += curbuf->page_info[i].leng;
			}
		}
		thread_state[keep_runnging][write_index] = 1;
		
		// *tail = (*tail + 1) % TRANSFER_BUFFER_SIZE;
		// rdma_write_ts(&TS_res, sizeof(int), (uint64_t)&(buf->tail), sizeof(int), -1);
	}
}



void *RDMA_TS_handler_client(void *arg)
{
	struct transfer_t_buffer *buf;
	volatile int *head, *tail;
	pthread_t *TS_thread_set;
	struct TS_write_thread_arg * write_arg_set;
	int write_threads = MUL_THREAD_NUM;
	buf = (struct transfer_t_buffer *)TS_res.buf;
	head = &buf->head;
	tail = &buf->tail;

	pr_warn("TS client start!\n");

	write_arg_set = (struct TS_write_thread_arg *)malloc(sizeof(struct TS_write_thread_arg) * MUL_THREAD_NUM);
	TS_thread_set = (pthread_t *)malloc(sizeof(pthread_t) * MUL_THREAD_NUM);

	for (int i = 0; i < TRANSFER_BUFFER_SIZE; i++)
		for (int j = 0; j < MUL_THREAD_NUM;j++)
			thread_state[i][j] = 0;

	while (TS_client_stop);

	for (int i = 0; i < MUL_THREAD_NUM; i++){
		write_arg_set[i].write_index = i;
		write_arg_set[i].args = arg;
		write_arg_set[i].all_threads = MUL_THREAD_NUM;
		
		pthread_create(&TS_thread_set[i], NULL, RDMA_TS_write_thread, &write_arg_set[i]);
	}
	while (1)
	{
		int start, end;
		// int start, end;
		if (*head == *tail)
			continue;

		if(*tail > *head)
			end = *head + TRANSFER_BUFFER_SIZE;
		else
			end = *head;
		
		for (int i = *tail; i < end; i++){
			int done = 1;
			for (int j = 0; j < MUL_THREAD_NUM; j++){
				if (thread_state[i % TRANSFER_BUFFER_SIZE][j] != 1)
					done = 0;
			}
			if (done == 1){
				
				*tail = (*tail + 1) % TRANSFER_BUFFER_SIZE;
				rdma_write_ts(&TS_res, sizeof(int), (uint64_t)&(buf->tail), sizeof(int), -1);
				for (int j = 0; j < MUL_THREAD_NUM; j++)
					thread_state[i % TRANSFER_BUFFER_SIZE][j] = 0;
				pr_warn("RDMA更新Tail:%d\n", *tail);
			}
		}
	}
	

	for (int i = 0; i < MUL_THREAD_NUM; i++){
		pthread_join(TS_thread_set[i], NULL);
	}
}



#endif




// --------------  page write  --------------

#define TS_WRITE_GRANULARITY 1

__attribute__((optimize("O0"))) void *ioctl_write_thread(void *arg)
{
	struct the_args *temp_args;
	int index;
	int ret = 0, uffd, head = 0, err, i = 0, off = 0, count = 0;

	// int *head,*tail,*loacl_head;
	volatile struct uffdio_copy uffdio_copy;

	volatile struct prefetch_t *pst;
	volatile struct transfer_t *curbuf;

	volatile struct page_data_set_t *PF_buf;
	volatile struct prefetch_t_buffer *FT_buf;
	volatile struct transfer_t_buffer *TS_buf;

	volatile int PFR_head, PFR_tail;
	volatile int FTR_head, FTR_tail;
	volatile int TSR_head, TSR_tail;

	volatile int *PF_head, *PF_tail;
	volatile int *FT_head, *FT_tail;
	volatile int *TS_head, *TS_tail;
	volatile int pid;
	int pfcheck = 0;
	// struct pid_uffd_region_set *mul_uffdset;
	temp_args = (struct the_args *)arg;
	index = temp_args->index;

	// uffd = uffdset[index];
	pid = pidset[index];

	PF_buf = (struct page_data_set_t *)PF_res.buf;
	FT_buf = (struct prefetch_t_buffer *)FT_res.buf;
	TS_buf = (struct transfer_t_buffer *)TS_res.buf;

	FT_head = &FT_buf->head;
	FT_tail = &FT_buf->tail;
	TS_head = &TS_buf->head;
	TS_tail = &TS_buf->tail;
	PF_head = &PF_buf->head[index];
	PF_tail = &PF_buf->tail[index];
	if (pid != PidUffdSet[index].pid) {
		pr_err("pid 不对应\n");
		return NULL;
	}
	curbuf = (struct transfer_t *)(TS_res.buf + sizeof(int) * 2 + *TS_tail * TRANSFER_REGION_SIZE);
	pr_warn("客户端write线程启动\n");

	while (true) {
		FTR_head = *FT_head;
		FTR_tail = *FT_tail;
		TSR_head = *TS_head;
		TSR_tail = *TS_tail;
		__asm__ __volatile__("" ::: "memory");
		__asm__ volatile(
			"movl (%[in]), %[out]"
			: [out] "=r"(PFR_head)
			: [in] "r"(PF_head)
			: "memory");

		__asm__ volatile(
			"movl (%[in]), %[out]"
			: [out] "=r"(PFR_tail)
			: [in] "r"(PF_tail)
			: "memory");
		__asm__ __volatile__("" ::: "memory");
		// if (*PF_head != *PF_tail) {
		
		if (PFR_head == PFR_tail)
			pfcheck++;

		while (write_stop)
			;
		if (PFR_head != PFR_tail) {
			volatile uint64_t src, dst;
#ifdef PF_DEBUG
			
#endif
			
			// pfcheck = 0;
			__asm__ __volatile__("" ::: "memory");
			// dst = *(uint64_t *)PF_buf->data[index][*PF_tail];
			// src = (uint64_t)&PF_buf->data[index][*PF_tail][8];
			dst = *(uint64_t *)PF_buf->data[index][PFR_tail];
			src = (uint64_t)&PF_buf->data[index][PFR_tail][8];
			__asm__ __volatile__("" ::: "memory");
			uffdio_copy.dst = dst;
			uffdio_copy.src = src;
			uffdio_copy.len = 4096;
			uffdio_copy.mode = 0;
			uffdio_copy.copy = 0;
#ifdef PF_DEBUG
			
#endif
			
			// pr_warn("%d 3: %lx\n",label, (uint64_t)uffdio_copy.dst);
			if ((ret = ioctl_mul(&uffdio_copy, pid)) < 0) {
				pr_err("PF ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
			} else {
				// PF_address_set_insert(&PFaddrset[index], uffdio_copy.dst);
			}
#ifdef PF_DEBUG
			// pr_warn(" done, addr:%lx tail:%d head:%d\n", (uint64_t)uffdio_copy.dst, *PF_tail, *PF_head);
			pr_warn(" done, addr:%lx tail:%d head:%d\n", (uint64_t)uffdio_copy.dst, PFR_tail, PFR_head);

#endif
			pr_warn("pfcheck:%d done, addr:%lx tail:%d head:%d\n", pfcheck, (uint64_t)uffdio_copy.dst, PFR_tail, PFR_head);
			pfcheck = 0;
			// buf->tail[index] = (buf->tail[index] + 1) % MAX_THREADS;
			PF_buf->tail[index] = (*PF_tail + 1) % MAX_THREADS;

		} else if (FTR_head != FTR_tail) {
			

			
			__asm__ __volatile__("" ::: "memory");
			pst = (struct prefetch_t *)&(FT_buf->data[*FT_tail]);
			__asm__ __volatile__("" ::: "memory");
			// uffd = uffdset[pid2index(pst->pid)];
			// pid = pst->pid;
			
			if (pst->length1 != 0) {
				
				__asm__ __volatile__("" ::: "memory");
				uffdio_copy.dst = (uint64_t)pst->address1;
				uffdio_copy.src = (uint64_t)&pst->data1;
				uffdio_copy.len = pst->length1;
				uffdio_copy.mode = 0;
				uffdio_copy.copy = 0;
// sleep(0.01);
#ifdef FT_DEBUG
				pr_warn("client FT1,dst:%lx, src:%lx, off:%lx, tail:%d\n", (uint64_t)uffdio_copy.dst, (uint64_t)uffdio_copy.src, (uint64_t)uffdio_copy.dst - (uint64_t)FT_buf->data, *FT_tail);
#endif
				if ((err = ioctl_mul(&uffdio_copy, pid)) < 0) {
					if (err != EEXIST)
						pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
				}
			}
			if (pst->length2 != 0) {
				
				__asm__ __volatile__("" ::: "memory");
				uffdio_copy.dst = (uint64_t)pst->address2;
				uffdio_copy.src = (uint64_t)&pst->data2;
				uffdio_copy.len = pst->length2;
				uffdio_copy.mode = 0;
				uffdio_copy.copy = 0;
// sleep(0.01);
#ifdef FT_DEBUG
				pr_warn("client FT2,dst:%lx, src:%lx, off:%lx tail:%d\n", (uint64_t)uffdio_copy.dst, (uint64_t)uffdio_copy.src, (uint64_t)uffdio_copy.dst - (uint64_t)FT_buf->data, *FT_tail);
#endif
				if ((err = ioctl_mul(&uffdio_copy, pid)) < 0) {
					if (err != EEXIST)
						pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
					else
						pr_err("other error\n");
				}
			}

			*FT_tail = (*FT_tail + 1) % PREFETCH_BUFFER_SIZE;
			
			__asm__ __volatile__("" ::: "memory");
			rdma_write_ft_remote(&FT_res, sizeof(int), (uint64_t)FT_tail, sizeof(int), -1);
			// test_flag--;
			
		} else if (TSR_head != TSR_tail) {
			count = 0;
			for (; i < curbuf->nr_pi; i++) {
				if (curbuf->page_info[i].pid == pid) {
					
					__asm__ __volatile__("" ::: "memory");
					uffdio_copy.dst = (uint64_t)((void *)(curbuf->page_info[i].addr));
					uffdio_copy.src = (uint64_t)((void *)get_mem(curbuf) + off * 4096);
					__asm__ __volatile__("" ::: "memory");
					uffdio_copy.len = 4096;
					uffdio_copy.mode = 0;
					uffdio_copy.copy = 0;
#ifdef TS_DEBUG
					
#endif
					
					if ((ret = ioctl_mul(&uffdio_copy, pid)) < 0) {
						if (ret != EEXIST)
							pr_err("ioctl(UFFDIO_COPY) failed. Address:%lx\n", (uint64_t)uffdio_copy.dst);
						else {
							pr_err("TS other error!\n");
						}
					}
					off++;
					count++;
					if (count >= TS_WRITE_GRANULARITY) {
						i++;
						// pr_warn("break!\n");
						break;
					}

				} else {
					pr_warn("no data!\n");
					off += curbuf->page_info[i].leng;
				}
			}
			if (i == curbuf->nr_pi) {
				pr_warn("stststsststststststsstststts写完一轮\n");

				*TS_tail = (*TS_tail + 1) % TRANSFER_BUFFER_SIZE;
				__asm__ __volatile__("" ::: "memory");
				rdma_write_ts(&TS_res, sizeof(int), (uint64_t)TS_tail, sizeof(int), -1);
				curbuf = (struct transfer_t *)(TS_res.buf + sizeof(int) * 2 + *TS_tail * TRANSFER_REGION_SIZE);
				off = 0;
				i = 0;
				count = 0;
			}
		}
	}
	pr_warn("write线程退出\n");
	return NULL;
}
