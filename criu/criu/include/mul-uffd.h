#ifndef __CR_MUL_UFFD_H__
#define __CR_MUL_UFFD_H__

#include "linux/userfaultfd.h"
#include "pstree.h"

#define REGION_SIZE (unsigned long)(1UL * 1024 * 1024 * 1024 * 50)
#define MAX_VMA_NUM 2000
#define MAX_UFFD_NUM 20

#ifdef MUL_UFFD
// #define ioctl_mul(&uffdio_copy, pid) ioctl_mul(&uffdio_copy, pid)
#endif
struct vma
{
    unsigned long start;
    unsigned long end;
};


struct uffd_region
{
    int uffd;
    
    unsigned long start;
    unsigned long end;
    struct vma vma[MAX_VMA_NUM];
    int nr_vma;
};

struct pid_uffd_region_set
{
    unsigned long pid;
    struct uffd_region uffd_region[MAX_UFFD_NUM];
    int nr_uffd_region;
};

extern volatile struct pid_uffd_region_set *PidUffdSet;
extern int item_num;
extern uint64_t pidset[MAX_PROCESS];


extern void InitPidUffdSet(void);

extern void PidUffdSet_taskargs(void *args, int pid);

extern void PidUffdSet_sendfd(int sockfd, int pid);
extern void PidUffdSet_recvfd(int sockfd, int *pid, int **uffdset, int *nr_uffd);

extern void PidUffdSet_send_region(int sockfd, int pid);
extern void PidUffdSet_recv_region(int sockfd, int pid, int *uffdset);

extern void PidUffdSet_fullfill(int pid, int sockfd);

extern int ioctl_mul(volatile struct uffdio_copy *data, int pid);

extern void * shmmap(uint64_t size);

void update_PidUffdSet(int pid, int nr_uffd, int *uffdset);

#endif