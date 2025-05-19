#include "pf-cache.h"

#define MAX_NODE 1024

extern int item_num;

struct cache{
    uint64_t pid;
    struct skiplist *list;
};


static struct cache *pf_cache;

int pf_cache_init(uint64_t *pidset, int item_num){
    pf_cache = (struct cache *)malloc(sizeof(struct cache) * item_num);
    for(int i = 0; i < item_num; i++){
        pf_cache[i].pid = pidset[i];
        pf_cache[i].list = skiplist_new();
        skiplist_insert(pf_cache[i].list, 0, 0);
    }
    return 0;
}

int pf_cache_insert(uint64_t pid, uint64_t addr){
    int i = 0;
    for(i = 0; i < item_num; i++){
        if(pf_cache[i].pid == pid){
            break;
        }
    }
    if(i == item_num){
        return -1;
    }
    skiplist_insert(pf_cache[i].list, addr, 0);
    return 0;
}

int pf_cache_get(uint64_t pid, uint64_t addr){
    int ret, i;
    struct skipnode *node;

    for(i = 0; i < item_num; i++){
        if(pf_cache[i].pid == pid){
            break;
        }
    }
    node = skiplist_search(pf_cache[i].list, addr);
    if(node == NULL){
        return -1;
    }
    return node->value;
}

int pf_cache_set(uint64_t pid, uint64_t addr){
    int ret, i;
    struct skipnode *node;

    for(i = 0; i < item_num; i++){
        if(pf_cache[i].pid == pid){
            break;
        }
    }
    node = skiplist_search(pf_cache[i].list, addr);
    if(node == NULL){
        return -1;
    }
    node->value = 1;
    return 0;
}

void pf_cache_del(uint64_t pid, uint64_t addr){
    int ret, i;
    struct skipnode *node;

    for(i = 0; i < item_num; i++){
        if(pf_cache[i].pid == pid){
            break;
        }
    }

    skiplist_remove(pf_cache[i].list, addr);
}

int pf_cache_range_search(uint64_t pid, uint64_t start, uint64_t end, struct skipnode **result, int *length){
    int ret, i;
    struct skipnode *node;
    // struct skipnode * result[1024];
    // int length;

    for(i = 0; i < item_num; i++){
        if(pf_cache[i].pid == pid){
            break;
        }
    }

    skiplist_range_search(pf_cache[i].list, start, end, result, length);

    return 0;
}

void  pf_cache_dump(){
    int ret, i;
    struct skipnode *node;
    for(i = 0; i < item_num; i++){
        printf("\npid = %lu\n", pf_cache[i].pid);
        skiplist_dump(pf_cache[i].list);
    }
    
}