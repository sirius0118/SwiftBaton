#ifndef __CR_HOT_MEM_H_
#define __CR_HOT_MEM_H_
// struct: vma, vmaset, priority page(shared with PageTrans)
// function: collection softdity, hotMemory predict, print proority page

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include "bitmap.h"
#include "common/list.h"
#include "vma.h"

#define PAGEMAP_LENGTH 8
// ########### Just last record ##########
#define MAX_LAST_RECORD_SIZE (16 * 1024 *1024)
#define MAX_TRANSFER_SIZE (1 << 22)    // 4MB = 1024 pages
struct last_record{
    uint64_t pid;
    uint64_t addr;
};
struct share_LR
{
    int stop;
    int can_be_write;
    int nr_dirty;
    int max_items;
};
// #define get_mem(p) (struct transfer_t*)round_up((uint64_t)(p + sizeof(struct transfer_t) + p->nr_pi * sizeof(struct mem_iov)), 4096)
#define get_LR(p) (struct last_record *)(p + sizeof(struct share_LR))
extern uint64_t nr_dirty;

struct last_record * LR_init(long size);
int LR_add(struct last_record *LR, uint64_t pid, uint64_t addr);
struct share_LR *share_LR_init(void *mem, int size);
int SLR_add(struct share_LR *SLR, uint64_t pid, uint64_t addr);

// ########## For LRU alogrithm ##########

struct LRU_page{
    uint64_t addr;
    uint64_t times;
    struct LRU_page *next;
    struct LRU_page *prev;
};

struct LRU_list{
    struct LRU_page *head;
    struct LRU_page *tail;
};

struct LRU_list *LRU_init(void);
void LRU_add(struct LRU_list *list, uint64_t addr);
void LRU_del(struct LRU_list *list, uint64_t addr);
// void LRU_out(struct LRU_list *list);
// void LRU_free(struct LRU_list *list);



// ########## For hot memory ##########

#define get_hotmem_start(addr) ((addr) & ~(MAX_TRANSFER_SIZE - 1))

struct hmvma{
    uint64_t start;
    uint64_t end;
    // int lazy_page;
    unsigned long *page_transed;
    struct list_head list;
};

struct hmvma_set{
    /* data */
    int pid;
    struct list_head h;
    struct list_head list;
};

struct pid_vma{
    struct list_head h;
};

extern struct pid_vma *PidVma;

static inline void hmvma_init(struct hmvma* hi){
    memset(hi, 0, sizeof(struct hmvma));
    INIT_LIST_HEAD(&hi->list);
}

static inline void hmvma_set_init(struct hmvma_set* hsi){
    memset(hsi, 0, sizeof(struct hmvma_set));
    INIT_LIST_HEAD(&hsi->list);
}

static inline void hmvma_add(struct hmvma_set* hs, struct hmvma* h){
    list_add_tail(&h->list, &hs->h);
}

static inline void pid_vma_init(struct pid_vma* pv){
    memset(pv, 0, sizeof(struct pid_vma));
    INIT_LIST_HEAD(&pv->h);
}

static inline void pid_vma_add(struct pid_vma* pv, struct hmvma_set* hs){
    list_add_tail(&hs->h, &pv->h);
}

extern void hot_mem_init(struct pid_vma* pv, struct vm_area_list *vma_list, int pid);

// ########## Collection softdirty ##########

void CleanSoftdirty(uint64_t pid);
void CollectSoftdirty(struct share_LR *SLR, uint64_t pid);



#endif