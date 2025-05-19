#ifndef __CR_PRE_TRANSFER_H__
#define __CR_PRE_TRANSFER_H__

#include "analyze-access.h"
#include "RDMA.h"
#include "mul-uffd.h"

#define ONE_AREA_SIZE 1024 * 4096
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern uint64_t pidset[MAX_PROCESS];
extern int uffdset[MAX_PROCESS];


struct pid_data_list
{
    int pid;
    struct score_list *ScoreList;
    struct score_list **dirtylist;
    volatile unsigned long * volatile ReadList;
    int read_hot_num;
};

struct data_buffer{
    int pid;
    struct ibv_mr mr, l_mr1, l_mr2;
    uint64_t r_addr;
    uint64_t l_addr1, l_addr2;
    uint64_t length1, length2;
};

// remote_iov
struct iov_list
{
    struct iovec iov;
    struct iov_list *next;
};

struct local_iov{
    int pid;
    struct iovec iov;
};

struct p_read_pages_args
{
    int pid;
    struct local_iov *local_iov;
    struct iov_list *remote_iov;
};

struct p_read_pages_args_V2
{
    int pid;
    int num_pages;
    unsigned long *addr_set;
};

struct true_readiov
{
    struct iovec iov;
    unsigned long addr;
    struct true_readiov *prev;
    struct true_readiov *next;
};

struct p_load_page_args
{
    int pid;
    struct true_readiov *PidReadIov;
};


// extern struct p_read_pages_args *pid_local_remote_iov;
// extern struct pid_data_list *pid_data_list;
// extern int list_length;

struct get_vma_dirtylist_arg
{
    int sock;
    void *mem;
};

extern void *get_vma_dirtylist(void *arg);
extern int create_pid_score_list(pid_t pid);
extern void read_pages(void **mem, uint64_t *mem_size);
extern void read_pages_V2(volatile void **mem, uint64_t *mem_size);
extern void *page_client_load_page(void *args);
extern void *page_client_load_page_V2(void *args);
extern void rdma_read_pretransfer(struct resources *res, struct data_buffer *pre_mr, int type);

extern void update_pid_array(uint64_t *pids, int size);



#endif