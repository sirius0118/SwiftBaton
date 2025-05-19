#include <compel/plugins/std.h>

#include "common/scm.h"
#include "common/compiler.h"
#include "common/lock.h"
#include "common/page.h"
#define COMPEL_LOG_H__
#define pr_err(fmt, ...)   print_on_level(1, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)  print_on_level(3, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) print_on_level(4, fmt, ##__VA_ARGS__)

#include "common/bug.h"

#include "uapi/compel/asm/sigframe.h"
#include "uapi/compel/infect-rpc.h"

#include "rpc-pie-priv.h"

#ifdef RDMA_CODESIGN

#define delay_ns(ns)                       \
	{                                  \
		struct timespec req, rem;  \
		req.tv_sec = 0;            \
		req.tv_nsec = ns;          \
		sys_nanosleep(&req, &rem); \
	}
#define delay_us(us) delay_ns(us * 1000)

static inline void delay1us(void){
    int i, j = 0;
    for (i = 0; i < 500; i++)
        j+=i;
}

#include <compel/plugins/std/syscall.h>
#include "common/shregion.h"

static noinline __used unsigned long RDMApagefault(void *args);
static noinline __used unsigned long RDMAtranspage(void *args);
static noinline __used unsigned long RDMAprefetch(void *args);
int create_over = 0;
int page_server_done = 0;
static inline void *sharemem_create(void *args, unsigned long size)
{
	int ret;
	void *mem;
	// struct shmem_plugin_msg *spi;
	// spi = (struct shmem_plugin_msg *)args;
	// struct msghdr msg;
	// struct iovec iov[1];
	pr_debug("PF内存11111\n");
	mem = (void *)sys_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	pr_debug("mem地址:%lx, size:%ld\n", (uint64_t)mem, size);
	if (mem == MAP_FAILED){
		pr_debug("PF内存创建33333\n");
		return NULL;
	}
	pr_debug("arg地址:%lx\n", (uint64_t)args);
	
	*(unsigned long *)args = (unsigned long)mem;
	pr_debug("run to here62\n");
	*(unsigned long *)(args + 8) = size;
	pr_debug("run to here64\n");
	// msg.msg_name = NULL;
	// msg.msg_namelen = 0;
	// iov[0].iov_base = &spi;
	// iov[0].iov_len = sizeof(spi);
	// msg.msg_iov = iov;
	// msg.msg_iovlen = 1;
	
	
	// ret = sys_sendto(tsock, &spi, sizeof(spi), 0, NULL, 0);
	// if (ret < 0) {
	// 	sys_munmap(mem, size);
	// 	return NULL;
	// }

	return mem;
}

static inline void int2str_noglibc(uint64_t value, char *str, int buffer_size)
{
	int start_index = 0;
	int index;

	if (buffer_size == 0) {
		return; // Buffer is too small to store even the null terminator
	}

	// Start from the end of the buffer
	index = buffer_size - 1;
	str[index] = '\0'; // Null terminator

	// Convert the number to string in reverse order
	do {
		if (index == 0) {
			// No more space left in the buffer
			str[0] = '\0'; // Indicate an error with empty string
			return;
		}
		str[--index] = '0' + (value % 10);
		value /= 10;
	} while (value > 0);

	// Shift the result to the beginning of the buffer
	while (str[index] != '\0') {
		str[start_index++] = str[index++];
	}
	str[start_index] = '\0';
}

static inline void hex2str_noglibc(uint64_t num, char *buf)
{
	int i;
	int j = 0;
	uint64_t temp;

	for (i = 0; i < 16; i++) {
		temp = num << 4 * i;
		temp = temp >> 4 * (15 - i);
		if (temp == 0)
			continue;
		else if (temp < 10)
			buf[j++] = '0' + temp;
		else
			buf[j++] = 'a' + temp - 10;
	}
}

static inline void strconcat(char *dest, const char *src)
{
	char *dest_ptr = dest;

	// Move dest_ptr to the end of the dest string
	while (*dest_ptr != '\0') {
		dest_ptr++;
	}

	// Append src to dest
	while (*src != '\0') {
		*dest_ptr = *src;
		dest_ptr++;
		src++;
	}

	// Null-terminate the resulting string
	*dest_ptr = '\0';
}

static inline void *sharemem_receive(uint64_t pid, uint64_t start, uint64_t size)
{
	int fd = -1;
	int ret;
	void *mem;
	char path[100] = "/proc/";
	char temp[100];

	int2str_noglibc(pid, temp, 100);
	strconcat(path, temp);
	strconcat(path, "/map_files/");
	hex2str_noglibc(start, temp);
	strconcat(path, temp);
	strconcat(path, "-");
	hex2str_noglibc(start + size, temp);
	strconcat(path, temp);

	fd = sys_open(path, O_RDWR, 0);
	if (fd < 0) {
		pr_err("open %s failed\n", path);
		return NULL;
	}

	mem = (void *)sys_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_err("mmap %s failed\n", path);
		return NULL;
	}

	return mem;
}
#endif

#ifndef ARCH_RT_SIGRETURN_DUMP
#define ARCH_RT_SIGRETURN_DUMP ARCH_RT_SIGRETURN
#endif

static int tsock = -1;

static struct rt_sigframe *sigframe;

#ifdef ARCH_HAS_LONG_PAGES
/*
 * XXX: Make it compel's std plugin global variable. Drop parasite_size().
 * Hint: compel on aarch64 shall learn relocs for that.
 */
static unsigned __page_size;

unsigned long __attribute((weak)) page_size(void)
{
	return __page_size;
}
#endif

int parasite_get_rpc_sock(void)
{
	return tsock;
}

/* RPC helpers */
static int __parasite_daemon_reply_ack(unsigned int cmd, int err)
{
	struct ctl_msg m;
	int ret;

	m = ctl_msg_ack(cmd, err);
	ret = sys_sendto(tsock, &m, sizeof(m), 0, NULL, 0);
	if (ret != sizeof(m)) {
		pr_err("Sent only %d bytes while %zu expected\n", ret, sizeof(m));
		return -1;
	}

	pr_debug("__sent ack msg: %d %d %d\n", m.cmd, m.ack, m.err);

	return 0;
}

static int __parasite_daemon_wait_msg(struct ctl_msg *m)
{
	int ret;

	pr_debug("Daemon waits for command\n");

	while (1) {
		*m = (struct ctl_msg){};
		ret = sys_recvfrom(tsock, m, sizeof(*m), MSG_WAITALL, NULL, 0);
		if (ret != sizeof(*m)) {
			pr_err("Trimmed message received (%d/%d)\n", (int)sizeof(*m), ret);
			return -1;
		}

		pr_debug("__fetched msg: %d %d %d\n", m->cmd, m->ack, m->err);
		return 0;
	}

	return -1;
}

/* Core infect code */

static noinline unsigned long fini_sigreturn(unsigned long new_sp)
{
	ARCH_RT_SIGRETURN_DUMP(new_sp, sigframe);
	return new_sp;
}

static unsigned long fini(void)
{
	unsigned long new_sp;

	parasite_cleanup();

	new_sp = (long)sigframe + RT_SIGFRAME_OFFSET(sigframe);
	pr_debug("%ld: new_sp=%lx ip %lx\n", sys_gettid(), new_sp, RT_SIGFRAME_REGIP(sigframe));

	sys_close(tsock);
	std_log_set_fd(-1);

	return fini_sigreturn(new_sp);

	BUG();

	return -1;
}

static noinline __used unsigned long parasite_daemon(void *args)
{
	struct ctl_msg m;
	int ret = -1;
	// void *pargs = args;

	pr_debug("Running daemon thread leader\n");

	/* Reply we're alive */
	if (__parasite_daemon_reply_ack(PARASITE_CMD_INIT_DAEMON, 0))
		goto out;

	ret = 0;

	while (1) {
		if (__parasite_daemon_wait_msg(&m))
			break;
		pr_err("当前命令：%d, arg地址:%lx\n", m.cmd, (uint64_t)args);
		if (ret && m.cmd != PARASITE_CMD_FINI) {
			pr_err("Command rejected\n");
			continue;
		}

		if (m.cmd == PARASITE_CMD_FINI) {
			pr_err("daemon 退出\n");
			goto out;
		}
#ifdef RDMA_CODESIGN
		if (m.cmd == 77) {
			uint64_t tid;
			uint64_t clone_flags;
			void *stack_top, *child_stack;
			pr_debug("pie执行指令pagefault\n");

			create_over = 0;
			clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_IO;
			child_stack = (void *)sys_mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
			stack_top = child_stack + 0x100000;
			// tid = sys_clone(CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS | CLONE_FILES | CLONE_IO, stack_top, 0, 0, 0);
			asm volatile(
				"movq %1, %%rdi        \n\t" 
				"movq %2, %%rsi        \n\t" 
				"xorq %%rdx, %%rdx     \n\t" //
				"xorq %%r10, %%r10     \n\t" 
				"xorq %%r8, %%r8       \n\t" 
				"xorq %%r9, %%r9       \n\t" 
				"movq $56, %%rax       \n\t" 
				"syscall               \n\t" 
				"movq %%rax, %0        \n\t" 
				: "=r"(tid)
				: "r"(clone_flags), "r"((uint64_t)stack_top)
				: "rdi", "rsi", "rcx", "rdx", "r10", "r8", "r9", "rax", "memory");
			if (tid == -1) {
				pr_err("clone failed\n");
			} else if (tid == 0) {
				// *(unsigned long*)args = 100;
				// *(unsigned long*)(args+8) = 100;
				tid = RDMApagefault(args);
				
				
				sys_exit(0);
			} else {
				
				while (1) {
					delay_us(10);
					if (create_over == 1)
						break;
				}
			}
		} else if (m.cmd == 78) {
			uint64_t tid;
			uint64_t clone_flags;
			void *stack_top, *child_stack;
			pr_debug("pie执行指令ts\n");
			create_over = 0;
			clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_IO;
			child_stack = (void *)sys_mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, 0, 0);
			stack_top = child_stack + 0x100000;

			asm volatile(
				"movq %1, %%rdi        \n\t" 
				"movq %2, %%rsi        \n\t" 
				"xorq %%rdx, %%rdx     \n\t" //
				"xorq %%r10, %%r10     \n\t" 
				"xorq %%r8, %%r8       \n\t" 
				"xorq %%r9, %%r9       \n\t" 
				"movq $56, %%rax       \n\t" 
				"syscall               \n\t" 
				"movq %%rax, %0        \n\t" 
				: "=r"(tid)
				: "r"(clone_flags), "r"((uint64_t)stack_top)
				: "rdi", "rsi", "rcx", "rdx", "r10", "r8", "r9", "rax", "memory");

			if (tid == -1) {
				pr_err("clone failed\n");
			} else if (tid == 0) {
				tid = RDMAtranspage(args);
				sys_exit(0);
			} else {
				
				while (1) {
					delay_us(100);
					if (create_over == 1)
						break;
				}
			}
		}else if (m.cmd == 79){
			uint64_t tid;
			uint64_t clone_flags;
			void *stack_top, *child_stack;
			pr_debug("pie执行指令prefetch\n");
			create_over = 0;
			clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_IO;
			child_stack = (void *)sys_mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, 0, 0);
			stack_top = child_stack + 0x100000;

			asm volatile(
				"movq %1, %%rdi        \n\t" 
				"movq %2, %%rsi        \n\t" 
				"xorq %%rdx, %%rdx     \n\t" //
				"xorq %%r10, %%r10     \n\t" 
				"xorq %%r8, %%r8       \n\t" 
				"xorq %%r9, %%r9       \n\t" 
				"movq $56, %%rax       \n\t" 
				"syscall               \n\t" 
				"movq %%rax, %0        \n\t" 
				: "=r"(tid)
				: "r"(clone_flags), "r"((uint64_t)stack_top)
				: "rdi", "rsi", "rcx", "rdx", "r10", "r8", "r9", "rax", "memory");

			if (tid == -1) {
				pr_err("clone failed\n");
			} else if (tid == 0) {
				tid = RDMAprefetch(args);
				sys_exit(0);
			} else {
				
				while (1) {
					delay_us(100);
					if (create_over == 1)
						break;
				}
			}
		} else {
			ret = parasite_daemon_cmd(m.cmd, args);
		}
#else
		ret = parasite_daemon_cmd(m.cmd, args);
#endif

		if (__parasite_daemon_reply_ack(m.cmd, ret))
			break;

		if (ret) {
			pr_err("Close the control socket for writing\n");
			sys_shutdown(tsock, SHUT_WR);
		}
	}

out:
	return fini();
}

static noinline __used unsigned long parasite_init_daemon(void *data)
{
	struct parasite_init_args *args = data;
	int ret;
	// int fd;

	args->sigreturn_addr = (uint64_t)(uintptr_t)fini_sigreturn;
	sigframe = (void *)(uintptr_t)args->sigframe;
#ifdef ARCH_HAS_LONG_PAGES
	__page_size = args->page_size;
#endif

	ret = tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (tsock < 0) {
		pr_err("Can't create socket: %d\n", tsock);
		goto err;
	}

	
	// fd = sys_open("/tmp/redis1.log", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	// if (args->h_addr.sun_path[0] == 0)
	// 	sys_write(fd, args->h_addr.sun_path, args->h_addr_len - 1);
	// sys_write(fd, args->h_addr.sun_path + 1, args->h_addr_len - 1);

	ret = sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len);
	if (ret < 0) {
		pr_err("Can't connect the control socket\n");
		
		goto err;
	}
	// sys_close(fd);

	futex_set_and_wake(&args->daemon_connected, 1);

	ret = recv_fd(tsock);
	if (ret >= 0) {
		std_log_set_fd(ret);
		std_log_set_loglevel(args->log_level);
		ret = 0;
	} else
		goto err;

	return parasite_daemon(data);

err:
	futex_set_and_wake(&args->daemon_connected, ret);
	return fini();
}

#ifdef RDMA_CODESIGN
// extern void * shmem_region;
static noinline __used unsigned long RDMApagefault(void *args)
{
	void *mem_temp;
	uint64_t address;
	volatile struct  shregion_t *mem;
	volatile int64_t *head, *tail;
	
	
pr_debug("PF内存创建start\n");
	mem_temp = sharemem_create(args, SHMEM_REGION_SIZE);
	pr_debug("PF内存创建start1\n");
	
	// *(unsigned long*)args = 100;
	// *(unsigned long*)(args+8) = 100;
	
	shregion_t_init(mem_temp);
	mem = (volatile struct shregion_t *)mem_temp;
	create_over = 1;
	pr_debug("PF内存创建");
	
	// pr_err("mem:%lx, len:%ld\n", *(unsigned long*)args, *(unsigned long*)(args+8));

	
	// while(1){
	// 	struct timespec req, rem;
	// 	req.tv_sec = 100000;
	// 	req.tv_nsec = 1000;
	// 	sys_nanosleep(&req, &rem);
	// 	// if (create_over == 1)
	// 	// 	break;
	// }
	// while (1)
	// {
	// 	delay_us(10000);
	// }
	head = &(mem->address_queue.head);
	tail = &(mem->address_queue.tail);
	while (1) {
		
		// if (page_server_done == 1)
		// 	break;
		// if (mem->isPageFault == 0) {
		// 	delay_us(1);
		// 	continue;
		// }
		
		// else if (mem->isPageFault > 0) {
		if (*head != *tail) {
			// delay_us(1000000);
			
			// pr_err("pie get pf\n");
			address = WQdequeue(&mem->address_queue);
			// pr_err("pie Address%lx\n",address);
			
			// memcpy((void *)mem->data + mem->data_queue.tail * 4096, (void *)address, 4096);
			
			CQenqueue(&mem->data_queue, sys_getpid(), address);
			// pr_err("pie data write\n");
			// memcpy(&queue->data[queue->tail], (void *)data, 4096);
			// queue->tail = (queue->tail + 1) % MAX_THREAD_SIZE;
			
			// mem->isPageFault--;
			// mem->isPageReady++;

		} 
		// else {
		// 	pr_err("wrong\n");
		// }

		// delay_us(1);
		// delay1us();
	}
	pr_err("PF退出\n");
	sys_munmap(mem_temp, SHMEM_REGION_SIZE);
	return 0;
}

static noinline __used unsigned long RDMAprefetch(void *args)
{
	int ret;
	volatile void *mem_temp;
	volatile struct prefetch_t *mem;
	uint64_t address, pid, pid_real;
	volatile int *is_request,*target_pid;

	pid = *(uint64_t *)args;
	address = *(uint64_t *)(args + 8);
	pid_real = *(uint64_t *)(args + 24);
	
	// mem_temp = para_sharemem_open("ts_mem", TRANSFER_REGION_SIZE);
	// mem_temp = sharemem_create(args, TRANSFER_REGION_SIZE);
	if (pid == 0)
		mem_temp = sharemem_create(args, PREFETCH_REGION_SIZE);
	else
		mem_temp = sharemem_receive(pid, address, PREFETCH_REGION_SIZE);
	pr_err("mem_temp:%lx, len:%ld\n", *(unsigned long *)args, *(unsigned long *)(args + 8));
	create_over = 1;
	

	mem = (struct prefetch_t *)mem_temp;
	is_request = &mem->is_request;
	target_pid=&mem->pid;
	// init_transfer_t(mem);
	
	pr_err("FT realpid:%lx\n",pid_real);
	while(1){
		while(*is_request==0||*target_pid!=pid_real){

		}
		serve_prefetch(mem,pid_real);
		// delay_us(1);
	}
	pr_err("FT退出\n");
	sys_munmap((void *)mem_temp, PREFETCH_REGION_SIZE);
	return 0;
}
// #define PIE_DEBUG
static noinline __used unsigned long RDMAtranspage(void *args)
{
	int ret;
	void *mem_temp;
	struct transfer_t *mem;
	uint64_t addr, size, pid, pid_real;
	volatile int *is_fulled;
	
	
	pid = *(uint64_t *)args;
	addr = *(uint64_t *)(args + 8);
	size = *(uint64_t *)(args + 16);
	pid_real = *(uint64_t *)(args + 24);
	
	
	// mem_temp = para_sharemem_open("ts_mem", TRANSFER_REGION_SIZE);
	// mem_temp = sharemem_create(args, TRANSFER_REGION_SIZE);
	if (pid == 0)
		mem_temp = sharemem_create(args, TRANSFER_REGION_SIZE);
	else
		mem_temp = sharemem_receive(pid, addr, size);
	pr_err("mem_temp:%lx, len:%ld\n", *(unsigned long *)args, *(unsigned long *)(args + 8));
	
	
	
	mem = (struct transfer_t *)mem_temp;
	create_over = 1;
	pr_debug("TS内存创建\n");
	// init_transfer_t(mem);
	// while (1)
	// {
	// 	delay_us(10000);
	// }
	pr_err("TS realpid:%lx\n",pid_real);
	is_fulled=&mem->is_fulled;
	while (1) {
		// continue;
		// struct timespec req, rem;
		// req.tv_sec = 1;
		// req.tv_nsec = 0;
		// sys_nanosleep(&req, &rem);
		#ifdef PIE_DEBUG
		pr_err("开始一轮server\n");
		#endif
		while(*is_fulled == 0){
			

		}
		ret = serve_request(mem, pid_real);
		#ifdef PIE_DEBUG
		if (mem->is_ready == 1)
			pr_err("server一轮\n");
		pr_err("结束一次TS\n");
		#endif
		if (ret == -1) {
			page_server_done = 1;
			break;
		}
		// delay_us(1);
		
		// if (ret == 0)
		// 	sleep(1);
	}
	pr_err("TS退出\n");
	sys_munmap(mem_temp, TRANSFER_REGION_SIZE);
	return 0;
}

#endif

#ifndef __parasite_entry
#define __parasite_entry
#endif

/*
 * __export_parasite_service_{cmd,args} serve as arguments to the
 * parasite_service() function. We use these global variables to make it
 * easier to pass arguments when invoking from ptrace.
 *
 * We need the linker to allocate these variables. Hence the dummy
 * initialization. Otherwise, we end up with COMMON symbols.
 */
unsigned int __export_parasite_service_cmd = 0;
void *__export_parasite_service_args_ptr = NULL;

unsigned long __used __parasite_entry parasite_service(void)
{
	unsigned int cmd = __export_parasite_service_cmd;
	void *args = __export_parasite_service_args_ptr;

	pr_info("Parasite cmd %d/%x process\n", cmd, cmd);

	if (cmd == PARASITE_CMD_INIT_DAEMON)
		return parasite_init_daemon(args);

	return parasite_trap_cmd(cmd, args);
}
