#include <sys/mman.h>

#include <compel/plugins.h>
#include <compel/plugins/shmem.h>
#include <compel/plugins/std/syscall.h>
#include "shmem.h"
#include "std-priv.h"

// void *shmem_create(unsigned long size)
// {
// 	int ret;
// 	void *mem;
// 	struct shmem_plugin_msg spi;

// 	mem = (void *)sys_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
// 	if (mem == MAP_FAILED)
// 		return NULL;

// 	spi.start = (unsigned long)mem;
// 	spi.len = size;

// 	ret = sys_write(std_ctl_sock(), &spi, sizeof(spi));
// 	if (ret != sizeof(spi)) {
// 		sys_munmap(mem, size);
// 		return NULL;
// 	}

// 	return mem;
// }

// static int mem_open_proc(int pid, int mode, const char *fmt, ...)
// {
// 	int l, i, j = 0;
// 	char path[128];
// 	va_list args;

// 	std_vdprintf(path, "/proc/%d/", pid);
// 	for(i = 0; i < 128; i++){
// 		if(path[i] == '/'){
// 			if ( j++ == 2){
// 				l = i + 1;
// 				break;
// 			}
// 		}
// 	}

// 	std_vdprintf(path + l, sizeof(path) - l, fmt, args);

// 	return open(path, mode);
// }

// void *shmem_receive(unsigned long *size, long pid)
// {
// 	/* master -> parasite not implemented yet */
// 	// Let me to implement it
// 	int ret, fd;
// 	void *mem;
// 	struct shmem_plugin_msg spi;

// 	ret = sys_read(std_ctl_sock(), spi, sizeof(spi));

// 	fd = mem_open_proc(pid, O_RDWR, "map_files/%lx-%lx", (long)spi.start,
// 	 (long)spi.start + spi.length);
	
// 	mem = sys_mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
// 	if ( mem == MAP_FAILED){
// 		mem = NULL;
// 		pr_err("Can't map remote parasite map!\n");
// 		return -1;
// 	}

// 	return mem;
// }

PLUGIN_REGISTER_DUMMY(shmem)
