#ifndef __CR_TRANSFER_H__
#define __CR_TRANSFER_H__

#include <stdint.h>

struct vmas_t{
    uint64_t start;
    uint64_t end;
    unsigned long flags;
    unsigned long *bitmap;
};

struct pid_vmas{
    uint64_t pid;
    int num_vma;
    int *can_lazy;
    volatile struct vmas_t * volatile vmas;
};

extern uint64_t pid2index(uint64_t pid);


struct RDMA_PF_handle_client_arg {
	int epollfd;
	struct epoll_event **events;
	int nr_fds;
	bool stop;
};

// server: be used in page server
void *RDMA_PF_handler_server(void *arg);
void *RDMA_TS_handler_server(void *arg);
void *RDMA_TS_preload_handler_server(void *arg);
void *RDMA_FT_handler_server(void *arg);

// client: be used in page client 
void *RDMA_PF_handler_client(void *arg);
void *RDMA_FT_handler_client(void *arg);
void *RDMA_TS_handler_client(void *arg);

void *ioctl_write_thread(void *arg);

// part3: othrers functions implementation in dumper
#endif