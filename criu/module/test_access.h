#ifndef __CR__ANALYZE_ACCESS_H__
#define __CR__ANALYZE_ACCESS_H__

#include "access-area.h"

struct score_list{
    unsigned long addr;
    int times;
    int dirty_times;
    float score;

    struct score_list *next;
    struct score_list *prev;
};

// extern struct score_list * Scorelist;

extern int init_score_list(struct score_list * Scorelist, int size);
extern struct score_list * analyze_access(struct epoch_area *area);
// extern int score_list_sort(struct score_list *list); 


#endif