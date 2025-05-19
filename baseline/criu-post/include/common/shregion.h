#ifndef __CR_SHREGION_H__
#define __CR_SHREGION_H__

// TYPE of transmission
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include "log.h"
#include <common/lock.h>
#include <compel/plugins/std/syscall.h>
#include <compel/plugins/std/string.h>


#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y)	   ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y)   ((x) & ~__round_mask(x, y))

/**
 * shregion: communication between dumpee & page server
*/

#define PAGE_FAULT   1
#define PAGE_TRANSFER   2

// VALUE recore

#define MAX_THREAD_SIZE 100
#define MAX_PROCESS_SIZE 100

// OFFSETS in shregion
#define ISPAGEFAULT 0
#define ISPAGEREADY 8

#define DATA_OFFSET 4096

#define MAX_PROCESS 100
#define MAX_THREADS 100
#define MAX_PREFETCH_CACHE 1000
#define PF_DATA_SIZE (4096 + 8)
#define SHMEM_REGION_SIZE 4096 * 256

#define TRANSFER_REGION_SIZE 4096 * 2048
#define PREFETCH_REGION_SIZE 4096 * 33
#define PREFETCH_BUFFER_SIZE 10
extern int item_num;
extern uint64_t pidset[MAX_PROCESS];
extern int socketset[MAX_PROCESS];

// extern void *sharemem_create(unsigned long size);
// extern void *sharemem_receive(unsigned long *size, long pid);

struct request_t {
    uint64_t pid;
    uint64_t address;
};

struct pagedata_t {
    uint64_t pid;
    uint64_t address;
    char page[4096];
};

struct work_queue {
    // int64_t length;
    int64_t head;
    int64_t tail;
    uint64_t data[MAX_THREAD_SIZE];
};

struct address_data {
    uint64_t address;
    void * page;
};

struct completion_queue {
    // int64_t length;
    int64_t head;
    int64_t tail;
    struct pagedata_t data[MAX_THREAD_SIZE];
    // uint64_t address[MAX_THREAD_SIZE];
    // char data[MAX_THREAD_SIZE][4096];
};

struct shregion_t {
    uint64_t isPageFault;
    uint64_t isPageReady;
    struct work_queue address_queue;
    struct completion_queue data_queue;
};


struct mul_shregion_t {
    int num_process;
    uint64_t * PIDs;
    
    struct shregion_t ** shregions;
    struct request_t * request;
};

struct page_request_set_t{
    int head[MAX_PROCESS];
    int tail[MAX_PROCESS];
    uint64_t addr[MAX_PROCESS][MAX_THREADS];
    int local_head[MAX_PROCESS];
};

struct page_data_set_t{
    int head[MAX_PROCESS];
    int tail[MAX_PROCESS];
    char data[MAX_PROCESS][MAX_THREADS][PF_DATA_SIZE];
    int local_head[MAX_PROCESS];
    uint64_t imm_data;
};

struct shmem_plugin_msg {
	unsigned long start;
	unsigned long len;
};

/**
 * shared memory for page server
*/

struct page_server_shregion_t {
    uint64_t head;
    uint64_t tail;
    struct request_t * request;
};

/**
 * shared memory for page client
*/

struct page_client_shregion_t {
    uint64_t head;
    uint64_t tail;
    struct pagedata_t * pagedata;
};

/**
 * page fault client
 */
struct PF_address {
    uint64_t address;
    int to_delete;
    struct PF_address *next;
};

struct PF_address_set {
    uint64_t pid;
    struct PF_address *head,*tail;
};

/**
 * action of PF_address_set
 * 
 */

static inline int PF_address_set_init(struct PF_address_set *set, uint64_t pid){
    set->pid = pid;
    set->head=NULL;
    set->tail=NULL;
    return 0;
}

static inline int PF_address_set_insert(struct PF_address_set *set, uint64_t address){
    struct PF_address *node = (struct PF_address *)malloc(sizeof(struct PF_address));
    node->address = address;
    node->to_delete = 0;
    node->next=NULL;
    if(set->head==NULL){
        set->head=node;
        set->tail=node;
    }else{
        set->tail->next=node;
        set->tail=node;
    }
    return 0;
}

static inline int PF_address_set_delete(struct PF_address_set *set,struct PF_address *prenode, struct PF_address *node){
    
    if(node->next==NULL){
        node->to_delete=1;
        return 1;
    }
    if(prenode==NULL){
        set->head=node->next;
    }else{
        prenode->next=node->next;
    }
    
    free(node);
    return 0;
}

/**
 * action of shregion between dumpee & page server
*/

static inline void shregion_t_init(void * mem){
    struct shregion_t * shregion = (struct shregion_t *)mem;
    shregion->isPageFault = 0;
    shregion->isPageReady = 0;
    shregion->address_queue.head = 0;
    shregion->address_queue.tail = 0;
    shregion->data_queue.head = 0;
    shregion->data_queue.tail = 0;
    
    // shregion->data = (void *)(round_up((uint64_t)(&shregion->data), 4096));
}

static inline void mul_shregion_t_init(void * mem, uint64_t num_process, uint64_t * pids){
    struct mul_shregion_t * mul_shregion = (struct mul_shregion_t *)mem;
    mul_shregion->num_process = num_process;
    mul_shregion->PIDs = (uint64_t *)mmap(NULL, sizeof(uint64_t) * num_process, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // mul_shregion->PIDs = (uint64_t *)malloc(sizeof(uint64_t) * num_process);
    for(int i = 0; i < num_process; i++){
        mul_shregion->PIDs[i] = pids[i];
    }
    mul_shregion->shregions = (struct shregion_t **)mmap(NULL, sizeof(struct shregion_t *) * num_process, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // mul_shregion->shregions = (struct shregion_t *)malloc(sizeof(struct shregion_t) * num_process);
}

static inline void WQenqueue(struct work_queue *queue, long address){
    queue->data[queue->tail] = address;
    queue->tail = (queue->tail + 1) % MAX_THREAD_SIZE;
}

static inline uint64_t WQdequeue(struct work_queue *queue){
    uint64_t address = queue->data[queue->head];
    queue->head = (queue->head + 1) % MAX_THREAD_SIZE;
    return address;
}

static inline void CQenqueue(struct completion_queue *queue, uint64_t pid, uint64_t data){
    // queue->address[queue->tail] = address;
    memcpy(queue->data[queue->tail].page, (void *)data, 4096);
    queue->data[queue->tail].address = data;
    queue->data[queue->tail].pid = pid;
    // queue->data[queue->tail] = data;
    queue->tail = (queue->tail + 1) % MAX_THREAD_SIZE;
}

static inline struct pagedata_t * CQdequeue(struct completion_queue *queue){
    struct pagedata_t *result;
    result = &queue->data[queue->head];
    queue->head = (queue->head + 1) % MAX_THREAD_SIZE;
    return result;
}

// extern void GetRequest(struct shregion_t * shregion, uint64_t address){
//     shregion -> isPageFault += 1;
//     WQenqueue(&shregion->address_queue, address);
// }


// extern void HandleRequest(struct shregion_t * shregion){
//     uint64_t address;
//     address = WQdequeue(&shregion->address_queue);
//     // memcpy data of address to completion queue
//     // 
// }

// ############## For Tansfer Page ################
#define MAX_PI 1024
#define MAX_BUFFER_SIZE 1024

struct mem_iov{
    // int nr_before;
    int pid;
    uint64_t addr;
    uint64_t leng;
};



extern mutex_t tsmutex;

struct transfer_t{
    int is_fulled;
    int is_ready;
    int nr_pi;
    int nr_page;
    struct{
        uint64_t pid;
        int done;
    }pid_info[MAX_PROCESS];
    struct mem_iov page_info[MAX_PI];
};


#define get_mem(p) (struct transfer_t*)((uint64_t)((uint64_t)(p) + sizeof(struct transfer_t) + (p)->nr_pi * sizeof(struct mem_iov)))

static inline void init_transfer_t(struct transfer_t *transfer, int item_num, uint64_t *pidset)
{
    // struct transfer_t * transfer = (struct transfer_t *)mem;
    transfer->is_ready = 0;
    transfer->nr_pi = 0;
    
    transfer->is_fulled = 0;
    transfer->nr_page = 0;
    for (int i = 0; i < MAX_PROCESS; i++){
        if ( i < item_num)
            transfer->pid_info[i].pid = pidset[i];
        else
            transfer->pid_info[i].pid = 0;
        transfer->pid_info[i].done = 0;
    }

}

static inline void clean_transfer_t(struct transfer_t *ts, int item_num)
{
    if(ts->is_fulled != -1)
    {
        ts->is_fulled = 0;
        ts->nr_pi = 0;
        ts->nr_page = 0;
        ts->is_ready = 0;

        for(int i = 0; i < item_num; i++){
            ts->pid_info[i].done = 0;
        }
    }
}

static inline int send_request(struct transfer_t *ts, int pid, uint64_t addr, uint64_t leng)
{
    if(ts->nr_page + leng > MAX_BUFFER_SIZE)
    {
        ts->is_fulled = 1;
        return 0;
    }
    ts->page_info[ts->nr_pi].pid = pid;
    ts->page_info[ts->nr_pi].addr = addr;
    ts->page_info[ts->nr_pi].leng = leng;
    // if (likely(ts->nr_pi > 0))
    //     ts->page_info[ts->nr_pi].nr_before = ts->page_info[ts->nr_pi - 1].nr_before + ts->page_info[ts->nr_pi - 1].leng;
    // else
    //     ts->page_info[ts->nr_pi].nr_before = 0;
    ts->nr_pi += 1;
    ts->nr_page += leng;
    // if(ts->nr_page == MAX_BUFFER_SIZE)
    // {
    //     ts->is_fulled = 1;
    // }
    // mutex_unlock(&tsmutex);    
    return 1;
}

static inline int serve_request(struct transfer_t *ts, uint64_t pid)
{
    int i;
    uint64_t off = 0;
    // uint64_t pid, vpid;

    if(ts->is_fulled != 1)
        return ts->is_fulled;
    
    
    for(int i = 0; i < MAX_PROCESS; i++){
        if (ts->pid_info[i].pid == 0)
            break;
        // pr_err("pid:%ld, pid_info[i]:%ld\n", pid, ts->pid_info[i].pid);
        if (ts->pid_info[i].pid == pid)
            if (ts->pid_info[i].done){
                return 0;
            }
    }

    for( i = 0; i < ts->nr_pi; i++) {
        // TODO: send request to parasite
        if ( ts->page_info[i].pid == pid ){
            memcpy((void *)((uint64_t)get_mem(ts) + off * 4096), (void *)ts->page_info[i].addr, ts->page_info[i].leng * 4096);
            ts->nr_page += ts->page_info[i].leng;
            
        }
        if ( i == ts->nr_pi - 1){
            int done = 1;
            
            for(int j = 0; j < MAX_PROCESS; j++){
                if (ts->pid_info[j].pid == 0)
                    break;
                if (ts->pid_info[j].pid == pid)
                    ts->pid_info[j].done = 1;
                if (ts->pid_info[j].done == 0)
                    done = 0;
            }
            if (done){
                pr_err("done\n");
                ts->is_ready = 1;
                ts->is_fulled = 0;
            }
        }
        off += ts->page_info[i].leng;
    }
    
    // for(int i = 0; i < MAX_PROCESS; i++){
    //     if (ts->pid_info[i].pid == 0)
    //         break;
    //     if (ts->pid_info[i].pid == pid){
    //         ts->pid_info[i].done = 1;
    
    //     }
    // }
    return 1;
}


// ############# for TS shared memory  ################

#define SHM_SIZE 4096

static inline void * para_sharemem_open(char *path, int size)
{
    int dirfd, shm_fd;
    void *shm_ptr;
    
    
    dirfd = sys_open("/dev/shm", O_RDONLY | O_DIRECTORY, 0);
    
    
    shm_fd = sys_openat(dirfd, path, O_RDWR | O_CREAT, 0666);
    sys_close(dirfd);
    
    // sys_ftruncate(shm_fd, size);

    
    shm_ptr = (void *)sys_mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    sys_close(shm_fd);
    return shm_ptr;
}

static inline int para_sharemem_close(char *path)
{
    sys_unlink(path);
    return 0;
}

static inline void * sharemem_open(char *path, int size)
{
    int dirfd, shm_fd;
    void *shm_ptr;
    dirfd = open("/dev/shm", O_RDONLY | O_DIRECTORY);
    if (dirfd == -1) {
        pr_err("open /dev/shm");
        return NULL;
    }

    
    shm_fd = syscall(SYS_openat, dirfd, path, O_CREAT | O_RDWR, 0666);
    close(dirfd);
    if (shm_fd == -1) {
        pr_err("syscall openat");
        return NULL;
    }

    
    if (ftruncate(shm_fd, size) == -1) {
        pr_err("syscall ftruncate");
        close(shm_fd);
        return NULL;
    }

    
    shm_ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        pr_err("mmap");
        close(shm_fd);
        return NULL;
    }
    close(shm_fd);
    return shm_ptr;
}

static inline int sharemem_close(char *path){
    int result = syscall(SYS_unlink, path);
    return result;
}

static inline int pid2vpid(uint64_t pid, uint64_t *pidset, uint64_t *vpidset){
    int i;
    for(i = 0; i < MAX_PROCESS; i++){
        if (pidset[i] == 0)
            break;
        if (pidset[i] == pid)
            return vpidset[i];
    }
    return -1;
}

// ############# For Page Prefetching ################

#define MAX_CACHE_SIZE 1000

struct PF_FT_area {
	unsigned long addr[MAX_CACHE_SIZE];
	int head, tail;
};

struct pid_FT_area {
	unsigned long pid;
	struct PF_FT_area area;
};

static inline void enqueueFT(struct PF_FT_area *area, unsigned long addr)
{
	area->addr[area->tail] = addr;
	area->tail = (area->tail + 1) % MAX_CACHE_SIZE;
}

static inline unsigned long dequeueFT(struct PF_FT_area *area)
{
	unsigned long addr = area->addr[area->head];
	area->head = (area->head + 1) % MAX_CACHE_SIZE;
	return addr;
}




struct prefetch_t{
    int is_request;
    int is_ready;
    pid_t pid;
    uint64_t address1;
    uint64_t length1;
    uint64_t address2;
    uint64_t length2;
    char data1[4096 * 16];
    char data2[4096 * 16];
};

struct prefetch_t_buffer{
    int head;
    int tail;
    struct prefetch_t data[PREFETCH_BUFFER_SIZE];
};

static inline void send_prefetch(struct prefetch_t * pst, int type, pid_t pid, uint64_t address, uint64_t length)
{
    int ret, i;

    if (type == 1){
        pst->pid = pid;
        pst->address1 = address;
        pst->length1 = length;
    }else{
        pst->address2 = address;
        pst->length2 = length;
        pst->is_request = 1;
        pst->is_ready = 0;
    }
}

static inline void serve_prefetch(struct prefetch_t * pst)
{
    while (true)
    {
        if (pst->is_request == 1){
            // send prefetch request to dumpee
            // pr_err("send prefetch request to dumpee\n");
            memcpy(pst->data1, (void *)pst->address1, pst->length1);
            memcpy(pst->data2, (void *)pst->address2, pst->length2);
            pst->is_ready = 1;
            pst->is_request = 0;
            
        }
    }
}

#endif