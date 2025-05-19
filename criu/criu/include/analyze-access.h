#ifndef __CR__ANALYZE_ACCESS_H__
#define __CR__ANALYZE_ACCESS_H__

#include "access-area.h"



#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define MAX_PAGES_NUM 10 * 1024 * 1024
#define INIT_READ_NUM 30 * 1024 * 1024
#define SHARED_MEM_SIZE 20 * 1024 * 1024 *100
#define IOCTL_MODIFY_PTE _IOW('m', 1, struct ioctl_data)
#define IOCTL_ALLOC_MEMORY _IOW('m', 2, int)
#define IOCTL_FREE_MEMORY _IOW('m', 3, int)
#define SAMPLE_TIMES 10
#define SAMPLE_INTERVAL_MICROSECOND 100000
#define PRIORITY_QUEUE_LEVEL 20
struct ioctl_data
{
    int pid;
    unsigned long addr;
    // char *addr;
    // char *path;
};



struct score_list{
    unsigned long addr;
    int times;
    int dirty_times;
    float score;
    int pid;

    volatile struct score_list *next;
    volatile struct score_list *prev;
};

// extern struct score_list * Scorelist;

extern int init_score_list(struct score_list * Scorelist, int size);
extern struct score_list * analyze_access(struct epoch_area *epoch_area, int access_hot, int dirty_hot, volatile unsigned long *read_hot_list, volatile int *read_hot_num);
// extern int score_list_sort(struct score_list *list); 
extern void *analyze(void *analyze_arg);
extern void address_translation(struct access_area *access);

#endif