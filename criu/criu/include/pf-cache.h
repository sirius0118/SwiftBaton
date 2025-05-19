#ifndef __PF_CACHE_H__
#define __PF_CACHE_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



struct sk_link {
        struct sk_link *prev, *next;
};

static inline void pflist_init(struct sk_link *link)
{
        link->prev = link;
        link->next = link;
}

static inline void __pflist_add(struct sk_link *link, struct sk_link *prev, struct sk_link *next)
{
        link->next = next;
        link->prev = prev;
        next->prev = link;
        prev->next = link;
}

static inline void __pflist_del(struct sk_link *prev, struct sk_link *next)
{
        prev->next = next;
        next->prev = prev;
}

static inline void pflist_add(struct sk_link *link, struct sk_link *prev)
{
        __pflist_add(link, prev, prev->next);
}

static inline void pflist_del(struct sk_link *link)
{
        __pflist_del(link->prev, link->next);
        pflist_init(link);
}

static inline int pflist_empty(struct sk_link *link)
{
        return link->next == link;
}

#define pflist_entry(ptr, type, member) \
        ((type *)((char *)(ptr) - (size_t)(&((type *)0)->member)))

#define skiplist_foreach(pos, end) \
        for (; pos != end; pos = pos->next)

#define skiplist_foreach_x(pos, end) \
        for (; pos != end->next; pos = pos->next)

#define skiplist_foreach_safe(pos, n, end) \
        for (n = pos->next; pos != end; pos = n, n = pos->next)

#define MAX_LEVEL 32  /* Should be enough for 2^32 elements */

struct skiplist {
        int level;
        int count;
        struct sk_link head[MAX_LEVEL];
};

struct skipnode {
        uint64_t key;
        int value;
        struct sk_link link[0];
};

static struct skipnode *skipnode_new(int level, uint64_t key, int value)
{
        struct skipnode *node;
        node = (struct skipnode *)malloc(sizeof(*node) + level * sizeof(struct sk_link));
        if (node != NULL) {
                node->key = key;
                node->value = value;
        }
        return node;
}

static void skipnode_delete(struct skipnode *node)
{
        free(node);
}

static struct skiplist *skiplist_new(void)
{
        int i;
        struct skiplist *list = (struct skiplist *)malloc(sizeof(*list));
        if (list != NULL) {
                list->level = 1;
                list->count = 0;
                for (i = 0; i < sizeof(list->head) / sizeof(list->head[0]); i++) {
                        pflist_init(&list->head[i]);
                }
        }
        return list;
}

static void skiplist_delete(struct skiplist *list)
{
        struct sk_link *n;
        struct sk_link *pos = list->head[0].next;
        skiplist_foreach_safe(pos, n, &list->head[0]) {
                struct skipnode *node = pflist_entry(pos, struct skipnode, link[0]);
                skipnode_delete(node);
        }
        free(list);
}

static int random_level(void)
{
        int level = 1;
        const double p = 0.25;
        while ((random() & 0xffff) < 0xffff * p) {
                level++;
        }
        return level > MAX_LEVEL ? MAX_LEVEL : level;
}

static struct skipnode *skiplist_search(struct skiplist *list, uint64_t key)
{
        struct skipnode *node = NULL;
        int i = list->level - 1;
        struct sk_link *pos = &list->head[i];
        struct sk_link *end = &list->head[i];
        
        for (; i >= 0; i--) {
                pos = pos->next;
                skiplist_foreach(pos, end) {
                        node = pflist_entry(pos, struct skipnode, link[i]);
                        if (node->key >= key) {
                                end = &node->link[i];
                                break;
                        }
                }
                if (node->key == key) {
                        return node;
                }
                pos = end->prev;
                pos--;
                end--;
        }

        return NULL;
}

static void skiplist_range_search(struct skiplist *list, 
        uint64_t key1, uint64_t key2, struct skipnode ** result, int *length)
{
        struct skipnode *node = NULL;
        struct sk_link *start_pos = NULL, *end_pos = NULL;
        int i = list->level - 1;
        struct sk_link *pos = &list->head[i];
        struct sk_link *end = &list->head[i];

        // struct skipnode * result[1024];

        for (; i >= 0; i--) {
                // printf("i: %d\n", i);
                pos = pos->next;
                while(1){
                        node = pflist_entry(pos, struct skipnode, link[i]);
                        if( node->key == key1){
                                start_pos = pos - i;
                                goto out;
                        }
                        if (node->key > key1) {
                                end = &node->link[i];
                                break;
                        }
                        if(pos == end)
                                break;
                        pos = pos->next;
                }
                if( node->key == key1){
                        start_pos = pos - i;
                        break;
                }
                if (i == 0) {
                        if (node->key < key1)
                            pos = pos->next;
                            // node = pflist_entry(pos++, struct skipnode, link[i]);
                        start_pos = pos;
                        break;
                }
                pos = end->prev;
                pos--;
                end--;
        }
out:
        pos = start_pos;
        end = &list->head[0];
        end_pos = start_pos;
        skiplist_foreach(pos, end) {
                node = pflist_entry(pos, struct skipnode, link[0]);
                if (node->key >= key2) 
                        break;
                else
                        end_pos = pos->next;
        }

        // i = list->level - 1;
        // pos = &list->head[i];
        // end = &list->head[i];
        // for (; i >= 0; i--) {
        //         pos = pos->next;
        //         skiplist_foreach(pos, end) {
        //                 node = pflist_entry(pos, struct skipnode, link[i]);
        //                 if (node->key >= key2) {
        //                         end = &node->link[i];
        //                         have_end = 1;
        //                         break;
        //                 }
        //         }
        //         if (i == 0) {
        //                 if (node->key >= key2 && have_end == 0)
        //                     pos = pos->prev;
        //                 // node = pflist_entry(pos++, struct skipnode, link[i]);
        //                 end_pos = pos;
        //                 break;
        //         }
        //         pos = end->prev;
        //         pos--;
        //         end--;
        // }
        // printf("start_pos: %p, end_pos: %p\n", start_pos, end_pos);
        *length = 0;
        skiplist_foreach(start_pos, end_pos){
            node = pflist_entry(start_pos, struct skipnode, link[0]);
            result[*length] = node;
            *length += 1;
            // printf("start_pos: %p, value:%d\n", start_pos, node->key);
        }
}

static struct skipnode * skiplist_insert(struct skiplist *list, uint64_t key, int value)
{
        struct skipnode *node;
        int level = random_level();
        if (level > list->level) {
                list->level = level;
        }

        node = skipnode_new(level, key, value);
        if (node != NULL) {
                int i = list->level - 1;
                struct sk_link *pos = &list->head[i];
                struct sk_link *end = &list->head[i];

                for (; i >= 0; i--) {
                        pos = pos->next;
                        skiplist_foreach(pos, end) {
                                struct skipnode *nd = pflist_entry(pos, struct skipnode, link[i]);
                                if (nd->key >= key) {
                                        end = &nd->link[i];
                                        break;
                                }
                        }
                        pos = end->prev;
                        if (i < level) {
                                __pflist_add(&node->link[i], pos, end);
                        }
                        pos--;
                        end--;
                }

                list->count++;
        }
        return node;
}

static void __remove(struct skiplist *list, struct skipnode *node, int level)
{
        int i;
        for (i = 0; i < level; i++) {
                pflist_del(&node->link[i]);
                if (pflist_empty(&list->head[i])) {
                        list->level--;
                }
        }
        skipnode_delete(node);
        list->count--;
}

static void skiplist_remove(struct skiplist *list, uint64_t key)
{
        struct sk_link *n;
        struct skipnode *node;
        int i = list->level - 1;
        struct sk_link *pos = &list->head[i];
        struct sk_link *end = &list->head[i];

        for (; i >= 0; i--) {
                pos = pos->next;
                skiplist_foreach_safe(pos, n, end) {
                        node = pflist_entry(pos, struct skipnode, link[i]);
                        if (node->key > key) {
                                end = &node->link[i];
                                break;
                        } else if (node->key == key) {
                                /* we allow nodes with same key. */
                                __remove(list, node, i + 1);
                        }
                }
                pos = end->prev;
                pos--;
                end--;
        }
}

static void skiplist_dump(struct skiplist *list)
{
        struct skipnode *node;
        int i = list->level - 1;
        struct sk_link *pos = &list->head[i];
        struct sk_link *end = &list->head[i];

        printf("\nTotal %d nodes: \n", list->count);
        for (; i >= 0; i--) {
                pos = pos->next;
                printf("level %d:\n", i + 1);
                skiplist_foreach(pos, end) {
                        node = pflist_entry(pos, struct skipnode, link[i]);
                        printf("key:%ld value:%d\n", node->key, node->value);
                }
                pos = &list->head[i];
                pos--;
                end--;
        }
}

extern int pf_cache_init(uint64_t *pidset, int item_num);
extern int pf_cache_insert(uint64_t pid, uint64_t addr);
extern int pf_cache_get(uint64_t pid, uint64_t addr);
extern int pf_cache_set(uint64_t pid, uint64_t addr);
extern void pf_cache_del(uint64_t pid, uint64_t addr);
extern int pf_cache_range_search(uint64_t pid, uint64_t start, uint64_t end, struct skipnode **result, int *length);
extern void  pf_cache_dump(void);
#endif