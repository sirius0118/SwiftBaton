#ifndef __CR_PSTREE_H__
#define __CR_PSTREE_H__

#include "common/list.h"
#include "common/lock.h"
#include "pid.h"
#include "xmalloc.h"
#include "images/core.pb-c.h"

/*
 * That's the init process which usually inherit
 * all orphaned children in the system.
 */
#define INIT_PID (1)
struct pstree_item {
	struct pstree_item *parent;
	struct list_head children; /* list of my children */
	struct list_head sibling;  /* linkage in my parent's children list */

	struct pid *pid;
	pid_t pgid;
	pid_t sid;
	pid_t born_sid;

	int nr_threads;	     /* number of threads */
	struct pid *threads; /* array of threads */
	CoreEntry **core;
	TaskKobjIdsEntry *ids;
	union {
		futex_t task_st;
		unsigned long task_st_le_bits;
	};
};

#ifdef PARALLEL_DUMP
#define MAX_PROCESS 100
struct futex_barriers{
	mutex_t mutex1, mutex2;
	mutex_t new_sock, proc_parse;
	mutex_t TS;
	futex_t cg_root_item, num_process, process_done;
	futex_t processes[MAX_PROCESS];
	futex_t num_misc;
};

extern struct futex_barriers * barriers;
extern struct list_head cg_sets;
extern int enter_multi_process;

static inline void buble_sort(uint64_t *a, int n) {
    int i, j;
	uint64_t tmp;
    for (i = 0; i < n - 1; i++) {
        for (j = 0; j < n - i - 1; j++) {
            if (a[j] > a[j + 1]) {
                tmp = a[j]; // swap a[j] and a[j+1]
                a[j] = a[j + 1];
                a[j + 1] = tmp;
            }
        }
    }
}
static inline void buble2_sort(uint64_t *a, uint64_t *b, int n) {
    int i, j;
	uint64_t tmp;
    for (i = 0; i < n - 1; i++) {
        for (j = 0; j < n - i - 1; j++) {
            if (a[j] > a[j + 1]) {
                tmp = a[j]; // swap a[j] and a[j+1]
                a[j] = a[j + 1];
                a[j + 1] = tmp;
				
				tmp = b[j]; // swap b[j] and b[j+1]
				b[j] = b[j + 1];
				b[j + 1] = tmp;
            }
        }
    }
}
#endif

#ifdef RDMA_CODESIGN
extern volatile struct mul_shregion_t *SharedRegions;
extern volatile struct transfer_t *TransferRegions;
extern volatile struct prefetch_t *PrefetchRegions;
extern volatile uint64_t tsmem_addr, tsmem_size;
extern volatile uint64_t ftmem_addr, ftmem_size;
#endif

static inline pid_t vpid(const struct pstree_item *i)
{
	return i->pid->ns[0].virt;
}

enum {
	FDS_EVENT_BIT = 0,
};
#define FDS_EVENT (1 << FDS_EVENT_BIT)

extern struct pstree_item *current;

struct rst_info;
/* See alloc_pstree_item() for details */
static inline struct rst_info *rsti(struct pstree_item *i)
{
	return (struct rst_info *)(i + 1);
}

struct thread_lsm {
	char *profile;
	char *sockcreate;
};

struct ns_id;
struct dmp_info {
	struct ns_id *netns;
	struct page_pipe *mem_pp;
	struct parasite_ctl *parasite_ctl;
	struct parasite_thread_ctl **thread_ctls;
	uint64_t *thread_sp;
	struct criu_rseq_cs *thread_rseq_cs;

	/*
	 * Although we don't support dumping different struct creds in general,
	 * we do for threads. Let's keep track of their profiles here; a NULL
	 * entry means there was no LSM profile for this thread.
	 */
	struct thread_lsm **thread_lsms;
};

static inline struct dmp_info *dmpi(const struct pstree_item *i)
{
	return (struct dmp_info *)(i + 1);
}

/* ids is allocated and initialized for all alive tasks */
static inline int shared_fdtable(struct pstree_item *item)
{
	return (item->parent && item->ids->files_id == item->parent->ids->files_id);
}

static inline bool is_alive_state(int state)
{
	return (state == TASK_ALIVE) || (state == TASK_STOPPED);
}

static inline bool task_alive(struct pstree_item *i)
{
	return is_alive_state(i->pid->state);
}

extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst);
#define alloc_pstree_item() __alloc_pstree_item(false)
extern int init_pstree_helper(struct pstree_item *ret);

extern struct pstree_item *lookup_create_item(pid_t pid);
extern void pstree_insert_pid(struct pid *pid_node);
extern struct pid *pstree_pid_by_virt(pid_t pid);

extern struct pstree_item *root_item;
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree(void);
extern int prepare_dummy_pstree(void);
#ifdef DOCKER
extern int prepare_pstree_root(void);
extern int prepare_pstree_noroot(void);
#endif

extern int dump_pstree(struct pstree_item *root_item);

struct pstree_item *pstree_item_by_real(pid_t virt);
struct pstree_item *pstree_item_by_virt(pid_t virt);

extern int pid_to_virt(pid_t pid);

struct task_entries;
extern struct task_entries *task_entries;
extern int prepare_task_entries(void);
extern int prepare_dummy_task_state(struct pstree_item *pi);

extern int get_task_ids(struct pstree_item *);
extern TaskKobjIdsEntry *root_ids;

extern void core_entry_free(CoreEntry *core);
extern CoreEntry *core_entry_alloc(int alloc_thread_info, int alloc_tc);
extern int pstree_alloc_cores(struct pstree_item *item);
extern void pstree_free_cores(struct pstree_item *item);

extern int collect_pstree_ids(void);

extern int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *));

extern int prepare_pstree_kobj_ids(void);
extern int read_pstree_ids(struct pstree_item *pi);
#endif /* __CR_PSTREE_H__ */
