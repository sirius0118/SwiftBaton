#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include "uthash.h"

#include "linux/userfaultfd.h"
// #include "uffd.h"

#include "types.h"
#include "log.h"
#include "common/list.h"
#include "pstree.h"
#include "rst_info.h"
#include "pre-transfer.h"
#include "transfer.h"
#include "analyze-access.h"

#include "cr-sync.h"

#define PROC_PATH "/proc/"

extern struct pid_vmas *PidVma[MAX_PROCESS];

static pid_t *pid_array;
static int pid_array_size = 0;
volatile struct pid_data_list *pid_data_list;

static int pre_wr_id = 1;

int list_length;

typedef struct {
	int parent_pid;	 
	int *children;	 
	size_t count;	 
	size_t capacity; 
	UT_hash_handle hh;
} parent_map;

struct pid_ppid {
	int pid;
	int ppid;
};


int is_number(const char *s)
{
	for (; *s; s++) {
		if (!isdigit(*s)) {
			return 0;
		}
	}
	return 1;
}


int get_ppid(int pid)
{
	char path[256];
	int ppid = -1;
	char line[256];
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	fp = fopen(path, "r");
	if (!fp) {
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "PPid:", 5) == 0) {
			sscanf(line + 5, "%d", &ppid);
			break;
		}
	}
	fclose(fp);
	return ppid;
}

int collect_process_tree(pid_t root_pid)
{
	
	struct pid_ppid *processes = NULL;
	size_t num_processes = 0;
	size_t capacity = 0;
	struct dirent *entry;
	int root_exists = 0;
	parent_map *pmap = NULL;
	DIR *proc_dir = opendir("/proc");
	
	int *result = NULL;
	size_t result_size = 0, result_capacity = 0;
	int *queue = NULL;
	size_t queue_front = 0, queue_rear = 0, queue_capacity = 0;
	parent_map *current, *tmp;

	if (!proc_dir) {
		perror("opendir");
		return 1;
	}

	while ((entry = readdir(proc_dir)) != NULL) {
		int pid = atoi(entry->d_name);
		int ppid = get_ppid(pid);
		if (!is_number(entry->d_name)) {
			continue;
		}

		if (ppid == -1) {
			continue; 
		}

		
		if (num_processes >= capacity) {
			capacity = capacity == 0 ? 128 : capacity * 2;
			processes = realloc(processes, sizeof(struct pid_ppid) * capacity);
			if (!processes) {
				perror("realloc");
				closedir(proc_dir);
				return 1;
			}
		}
		processes[num_processes].pid = pid;
		processes[num_processes].ppid = ppid;
		num_processes++;
	}
	closedir(proc_dir);

	

	for (size_t i = 0; i < num_processes; i++) {
		if (processes[i].pid == root_pid) {
			root_exists = 1;
			break;
		}
	}
	if (!root_exists) {
		fprintf(stderr, "Error: PID %d does not exist.\n", root_pid);
		free(processes);
		return 1;
	}

	
	for (size_t i = 0; i < num_processes; i++) {
		int ppid = processes[i].ppid;
		int pid = processes[i].pid;
		parent_map *entry = NULL;

		HASH_FIND_INT(pmap, &ppid, entry);
		if (!entry) {
			entry = malloc(sizeof(parent_map));
			entry->parent_pid = ppid;
			entry->capacity = 4;
			entry->children = malloc(sizeof(int) * entry->capacity);
			entry->count = 0;
			HASH_ADD_INT(pmap, parent_pid, entry);
		}

		if (entry->count >= entry->capacity) {
			entry->capacity *= 2;
			entry->children = realloc(entry->children, sizeof(int) * entry->capacity);
		}
		entry->children[entry->count++] = pid;
	}

	queue_capacity = 16;
	queue = malloc(sizeof(int) * queue_capacity);
	queue[queue_rear++] = root_pid;

	while (queue_front < queue_rear) {
		int current_pid = queue[queue_front++];
		parent_map *entry = NULL;
		
		if (result_size >= result_capacity) {
			result_capacity = result_capacity ? result_capacity * 2 : 16;
			result = realloc(result, sizeof(int) * result_capacity);
		}
		result[result_size++] = current_pid;

		
		HASH_FIND_INT(pmap, &current_pid, entry);
		if (entry) {
			for (size_t i = 0; i < entry->count; i++) {
				if (queue_rear >= queue_capacity) {
					queue_capacity *= 2;
					queue = realloc(queue, sizeof(int) * queue_capacity);
				}
				queue[queue_rear++] = entry->children[i];
			}
		}
	}

	
	pid_array = (pid_t *)malloc(sizeof(pid_t) * result_size);
	for (size_t i = 0; i < result_size; i++) {
		pid_array[i] = result[i];
	}
	pid_array_size = result_size;

	
	free(queue);
	free(result);

	HASH_ITER(hh, pmap, current, tmp)
	{
		HASH_DEL(pmap, current);
		free(current->children);
		free(current);
	}

	free(processes);
	list_length = pid_array_size;
	return pid_array_size;
}

int create_pid_score_list(pid_t pid)
{
	int ret, i;
	// struct pid_data_list *pid_data_list;
	pthread_t *threads;
	pr_warn("Create process tree\n");
	ret = collect_process_tree(pid);
	pr_warn("Create process done\n");
	pid_data_list = (struct pid_data_list *)malloc(sizeof(struct pid_data_list) * pid_array_size);
	threads = (pthread_t *)malloc(sizeof(pthread_t) * pid_array_size);

	for (i = 0; i < pid_array_size; i++) {
		volatile struct pid_data_list *args = &pid_data_list[i];
		// struct pid_data_list *args = (struct pid_data_list *)malloc(sizeof(struct pid_data_list));
		args->pid = pid_array[i];
		args->ScoreList = NULL;
		args->dirtylist = NULL;
		
		args->ReadList = (unsigned long *)malloc(INIT_READ_NUM);
		args->read_hot_num = 0;

		pthread_create(&threads[i], NULL, analyze, (void*)args);
	}
	pr_warn("pid_data_list size:%d\n", pid_array_size);
	if (pid_data_list[0].dirtylist == NULL) {
		pr_warn("here is NULL\n");
	}
	pr_warn("Start analyze\n");
	for (i = 0; i < pid_array_size; i++) {
		pthread_join(threads[i], NULL);
	}
	return ret;
}

// ssize_t nread = process_vm_readv(target_pid,




static struct iov_list *merge_ReadList_iov(volatile unsigned long *Readlist, int read_hot_num)
{
	int i, j;
	struct iov_list *head = NULL, *current = NULL;

	if (read_hot_num == 0)
		return NULL;

	for (i = 0; i < read_hot_num; i++) {
		if (head == NULL) {
			head = (struct iov_list *)malloc(sizeof(struct iov_list));
			head->iov.iov_base = (void *)Readlist[i];
			head->iov.iov_len = PAGE_SIZE;
			head->next = NULL;
			current = head;
		}
		if (Readlist[i] == (unsigned long)current->iov.iov_base + current->iov.iov_len) {
			current->iov.iov_len += PAGE_SIZE;
		} else {
			current->next = (struct iov_list *)malloc(sizeof(struct iov_list));
			current->next->iov.iov_base = (void *)Readlist[i];
			current->next->iov.iov_len = PAGE_SIZE;
			current->next->next = NULL;
			current = current->next;
		}
	}
	return head;
}

void *p_read_pages(void *args)
{
	struct p_read_pages_args *arg = (struct p_read_pages_args *)args;
	struct iov_list *remote_iov = (struct iov_list *)arg->remote_iov, *current;
	struct local_iov *local_iov = (struct local_iov *)arg->local_iov;

	struct iovec *iov;
	int lens = 0;
	ssize_t nread;
	pr_warn("run to herevm\n");
	current = remote_iov;
	while (current != NULL) {
		lens++;
		current = current->next;
	}
	pr_warn("run to herevm\n");
	iov = (struct iovec *)malloc(sizeof(struct iovec) * lens);
	current = remote_iov;
	for (int i = 0; i < lens; i++) {
		iov[i].iov_base = current->iov.iov_base;
		iov[i].iov_len = current->iov.iov_len;
		current = current->next;
	}
	pr_warn("run to herevm\n");
	nread = process_vm_readv(local_iov->pid,
				 &local_iov->iov, 1, 
				 iov, lens,	     
				 0);		     
	if (nread == -1) {
		perror("process_vm_readv");
	}
	pr_warn("run to here\n");
	return NULL;
}

struct p_read_pages_args *pid_local_remote_iov;
// Read all the 'read hot pages' of all the processes saved in local_iov
void read_pages(void **mem, uint64_t *mem_size) // page server
{
	int i, j, k, lens = 0;
	struct iov_list *current;
	struct p_read_pages_args *args;
	struct local_iov *local_iov;
	pthread_t *threads;
	void *a;
	int pid_iovs[MAX_PROCESS];
	struct iovec *iov;
	// int mem_size = 0;
	// void *mem;
	pr_warn("run to here pid_array_size:%d hot_num:%d\n", pid_array_size, pid_data_list[0].read_hot_num);
	args = (struct p_read_pages_args *)malloc(sizeof(struct p_read_pages_args) * pid_array_size);

	for (i = 0; i < pid_array_size; i++) {
		args[i].remote_iov = merge_ReadList_iov(pid_data_list[i].ReadList, pid_data_list[i].read_hot_num);
		current = args[i].remote_iov;
		while (current != NULL) {
			lens++;
			current = current->next;
		}
		pid_iovs[i] = lens;
		
		*mem_size += 8 + 8 + 8 + sizeof(struct iovec) * lens + pid_data_list[i].read_hot_num * PAGE_SIZE;
	}
	pr_warn("执行到,mem地址:0x%lx, lens:%d, mem_size:%ld\n", (uint64_t)mem, lens, *mem_size);

	local_iov = (struct local_iov *)malloc(sizeof(struct local_iov) * pid_array_size);
	threads = (pthread_t *)malloc(sizeof(pthread_t) * pid_array_size);
	a = *mem = (void *)malloc(*mem_size);
	pr_warn("memory位置:0x%lx, a的地址:0x%lx, 大小为:%ld\n", (uint64_t)(*mem), (uint64_t)a, *mem_size);
	*mem_size = 0;

	
	for (i = 0; i < pid_array_size; i++) {
		for (j = 0; j < pid_array_size; j++) {
			pr_warn("判断pid_array[%d]:%d, pid_data_list[%d].pid:%d\n", i, pid_array[i], j, pid_data_list[j].pid);
			if (pid_data_list[j].pid != pid_array[i])
				continue;

			*(unsigned long *)(*mem + *mem_size + i * 16) = pid_array[i];
			*(unsigned long *)(*mem + *mem_size + i * 16 + 8) = (unsigned long)(16 + *mem_size);
			*(unsigned long *)(*mem + *mem_size + i * 16 + 16) = pid_iovs[i];

			local_iov[i].pid = pid_array[i];

			local_iov[i].iov.iov_base = (void *)((unsigned long)(*mem) + 16 + *mem_size + sizeof(struct iovec) * pid_iovs[i]);
			local_iov[i].iov.iov_len = pid_data_list[j].read_hot_num * PAGE_SIZE;

			
			current = args[i].remote_iov;
			for (k = 0; k < pid_iovs[i]; k++) {
				iov = (struct iovec *)(*mem + *mem_size + 24 + k * sizeof(struct iovec));
				iov->iov_base = current->iov.iov_base;
				iov->iov_len = current->iov.iov_len;
				current = current->next;
			}
			*mem_size = *mem_size + 24 + sizeof(struct iovec) * pid_iovs[i] + pid_data_list[j].read_hot_num * PAGE_SIZE;
		}
	}

	pr_warn("run to here\n");
	pid_local_remote_iov = args;
	for (i = 0; i < pid_array_size; i++) {
		args[i].pid = pid_array[i];
		args[i].local_iov = &local_iov[i];
		// args[i].remote_iov = merge_ReadList_iov(pid_data_list[i].ReadList, pid_data_list[i].read_hot_num);
	}

	pr_warn("run to here\n");
	for (i = 0; i < pid_array_size; i++)
		pthread_create(&threads[i], NULL, p_read_pages, (void *)&args[i]);
	pr_warn("run to here\n");
	for (i = 0; i < pid_array_size; i++)
		pthread_join(threads[i], NULL);

	return;
}

// //   page client
// void rdma_read_pretransfer(struct resources *res, struct data_buffer *pre_mr, int type){
//     struct ibv_send_wr sr;
//     struct ibv_sge *sge;
//     struct ibv_send_wr *bad_wr;
//     int max_sge = 4 * 1024 * 1024, now = 0, i, num_sge = 0;
//     // memset(&sge, 0, sizeof(sge));
//     if (type == 1){
//         struct ibv_mr * mr;
//         pre_mr->l_addr1 = (unsigned long)malloc(pre_mr->length1);
//         mr = ibv_reg_mr(res->pd, (void *)pre_mr->l_addr1, pre_mr->length1,
//                                 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);

//         pre_mr->l_mr1.length = mr->length;
//         pre_mr->l_mr1.handle = mr->handle;
//         pre_mr->l_mr1.lkey = mr->lkey;
//         pre_mr->l_mr1.rkey = mr->rkey;
//         num_sge = (int)(round_up(pre_mr->length1, max_sge) / max_sge);
//         pr_warn("lkey:%d, rkey:%d length:%ld, num_sge:%d\n", pre_mr->l_mr1.lkey, pre_mr->l_mr1.rkey, pre_mr->l_mr1.length, num_sge);
//         sge = (struct ibv_sge *)malloc(sizeof(struct ibv_sge) * num_sge);
//         for (i = 0; i < num_sge; i++){
//             if (i == num_sge - 1)
//                 sge[i].length = pre_mr->length1 - now;
//             else
//                 sge[i].length = max_sge;
//             sge[i].lkey = pre_mr->l_mr1.lkey;
//             sge[i].addr = pre_mr->l_addr1 + now;
//             now += max_sge;
//         }
//     }else if(type == 2){
//         struct ibv_mr * mr;

//         pre_mr->l_addr2 = (unsigned long)malloc(pre_mr->length2);
//         mr = ibv_reg_mr(res->pd, (void *)pre_mr->l_addr2, pre_mr->length2,
//                                 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);

//         pre_mr->l_mr2.length = mr->length;
//         pre_mr->l_mr2.handle = mr->handle;
//         pre_mr->l_mr2.lkey = mr->lkey;
//         pre_mr->l_mr2.rkey = mr->rkey;
//         num_sge = (int)(round_up(pre_mr->length2, max_sge) / max_sge);
//         pr_warn("lkey:%d, rkey:%d length:%ld, num_sge:%d\n", pre_mr->l_mr2.lkey, pre_mr->l_mr2.rkey, pre_mr->l_mr2.length, num_sge);
//         sge = (struct ibv_sge *)malloc(sizeof(struct ibv_sge) * (int)(round_up(pre_mr->length2, max_sge) / max_sge));
//         for (i = 0; i < (int)(round_up(pre_mr->length2, max_sge) / max_sge); i++){
//             if (i == (int)(round_up(pre_mr->length2, max_sge) / max_sge) - 1)
//                 sge[i].length = pre_mr->length2 - now;
//             else
//                 sge[i].length = max_sge;
//             sge[i].lkey = pre_mr->l_mr2.lkey;
//             sge[i].addr = pre_mr->l_addr2 + now;
//             now += max_sge;
//         }
//     }else{
//         pr_err("type error\n");
//         return;
//     }

//     memset(&sr, 0, sizeof(sr));
//     sr.next = NULL;
//     sr.wr_id = pre_wr_id++;
//     sr.sg_list = sge;
//     sr.num_sge = num_sge;
//     sr.opcode = IBV_WR_RDMA_READ;
//     sr.send_flags = IBV_SEND_SIGNALED;
//     sr.wr.rdma.remote_addr = pre_mr->r_addr;
//     sr.wr.rdma.rkey = pre_mr->mr.rkey;
//     for(i = 0; i < num_sge; i++)

//     if(ibv_post_send(res->qp, &sr, &bad_wr) != 0)
//         pr_err("send ");
//     return;
// }

#define MAX_BLOCK_SIZE	(1 * 1024 * 1024) 
#define SIGNAL_INTERVAL 64		  

void rdma_read_pretransfer(struct resources *res, struct data_buffer *pre_mr, int type)
{
	struct ibv_send_wr *wr_list = NULL, *bad_wr;
	struct ibv_sge *sge_list = NULL;
	uint64_t total_length, remote_addr;
	uint64_t *local_addr_ptr;
	struct ibv_mr *mr;
	int num_blocks, i, times, time_i, now_block = 0;
	int max_wr_queue_size = 100;
	uint64_t total_length_aligned;

	
	if (!res || !pre_mr || (type != 1 && type != 2)) {
		pr_err("Invalid parameters\n");
		return;
	}

	
	if (type == 1) {
		total_length = pre_mr->length1;
		local_addr_ptr = &pre_mr->l_addr1;
	} else {
		total_length = pre_mr->length2;
		local_addr_ptr = &pre_mr->l_addr2;
	}
	remote_addr = pre_mr->r_addr;

	
	*local_addr_ptr = (uint64_t)aligned_alloc(4096, total_length); 
	if (!*local_addr_ptr) {
		pr_err("Memory allocation failed\n");
		return;
	}
	total_length_aligned = round_up(total_length, 4096);
	pr_warn("注册%ld的内存\n", total_length_aligned);
	memset((void *)*local_addr_ptr, 0, total_length_aligned);
	mr = ibv_reg_mr(res->pd, (void *)*local_addr_ptr, total_length_aligned,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
	if (!mr) {
		pr_err("MR registration failed: %s\n", strerror(errno));
		free((void *)*local_addr_ptr);
		return;
	}

	
	num_blocks = (total_length + MAX_BLOCK_SIZE - 1) / MAX_BLOCK_SIZE;
	pr_warn("num_block size:%d\n", num_blocks);
	
	wr_list = calloc(num_blocks, sizeof(struct ibv_send_wr));
	sge_list = calloc(num_blocks, sizeof(struct ibv_sge));
	if (!wr_list || !sge_list) {
		pr_err("Allocation failed\n");
		goto cleanup;
	}

	// times = round_up(num_blocks, max_wr_queue_size) / max_wr_queue_size;
	times = num_blocks / max_wr_queue_size;
	times = (num_blocks % max_wr_queue_size > 0) ? times + 1 : times;

	pr_warn("times:%d\n", times);
	for (time_i = 0; time_i < times; time_i++) {
		
		now_block = (time_i == times - 1) ? num_blocks % max_wr_queue_size : max_wr_queue_size;
		now_block = (now_block == 0) ? max_wr_queue_size : now_block;
		for (i = 0; i < now_block; i++) {
			uint64_t block_offset = i * MAX_BLOCK_SIZE + time_i * max_wr_queue_size * MAX_BLOCK_SIZE;
			int block_size = (i + time_i * max_wr_queue_size == num_blocks - 1) ? (total_length % MAX_BLOCK_SIZE) : MAX_BLOCK_SIZE;
			block_size = (block_size == 0) ? MAX_BLOCK_SIZE : block_size;
			// pr_warn("time_i:%d i:%d block_size:%d, off:%lx\n", time_i, i, block_size, block_offset);
			
			sge_list[i + time_i * max_wr_queue_size] = (struct ibv_sge){
				.addr = *local_addr_ptr + block_offset,
				.length = block_size,
				.lkey = mr->lkey
			};

			
			//.send_flags = (i == num_blocks - 1) ? IBV_SEND_SIGNALED : 0,
			wr_list[i + time_i * max_wr_queue_size] = (struct ibv_send_wr){
				.next = (i < now_block - 1) ? &wr_list[i + 1 + time_i * max_wr_queue_size] : NULL,
				.sg_list = &sge_list[i + time_i * max_wr_queue_size],
				.num_sge = 1,
				.opcode = IBV_WR_RDMA_READ,
				.send_flags = (i == now_block - 1) ? IBV_SEND_SIGNALED : 0,
				.wr = {
					.rdma = {
						.remote_addr = remote_addr + block_offset,
						.rkey = pre_mr->mr.rkey } }
			};
		}
		pr_warn("type:%d, RDMA: remote_addr:0x%lx, local_addr:0x%lx, length:%ld, now_block:%d\n", type, remote_addr + time_i * max_wr_queue_size * MAX_BLOCK_SIZE, *local_addr_ptr + time_i * max_wr_queue_size * MAX_BLOCK_SIZE, total_length, now_block);
		
		if (ibv_post_send(res->qp, &wr_list[time_i * max_wr_queue_size], &bad_wr)) {
			pr_err("ibv_post_send failed at block %ld\n", bad_wr - &wr_list[time_i * max_wr_queue_size]);
		}

		poll_completion(res);
	}
cleanup:
	free(wr_list);
	free(sge_list);
	
}

// dumper, page server
static void update_read_pid_data_list(void *mem)
{
	int i, j, k, k1 = 0;
	struct access_area *access_area;
	struct epoch_area *PidEpochArea;
	struct __vma_area *vma;
	struct epoch_area *epoch_area_item;
	
	PidEpochArea = (struct epoch_area *)mem;
	
	for (i = 0; i < pid_array_size; i++) {
		
		epoch_area_item = (struct epoch_area *)((void *)PidEpochArea + i * ONE_AREA_SIZE);
		access_area = (struct access_area *)(epoch_area_item)->areas[epoch_area_item->num_area - 1];
		pr_warn("run to here4, num_area:%d\n", epoch_area_item->num_area);
		pr_warn("hot num:%d\n", pid_data_list[i].read_hot_num);
		for (j = 0; j < pid_data_list[i].read_hot_num; j++) {
			for (k = 0; k < access_area->num_vma; k++) {
				vma = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * k);
				if (pid_data_list[i].ReadList[j] >= vma->start && pid_data_list[i].ReadList[j] <= vma->end) {
					
					
					for (k1 = 0; k1 < PidVma[i]->num_vma; k1++) {
						if (PidVma[i]->vmas[k1].start != vma->start) {
							continue;
						}
						// if(ca_bitmap_get(vma->dirty_bitmap, pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k].start) == 0){
						if (!test_bit((pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k1].start) / PAGE_SIZE, vma->dirty_bitmap)) {
							
							// ca_bitmap_set(PidVma[i]->vmas[k].bitmap, (pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k].start) / PAGE_SIZE, 1);
							
							set_bit((pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k1].start) / PAGE_SIZE, PidVma[i]->vmas[k1].bitmap);
						}
						
						
					}
				}
			}
			// for (k = 0; k < access_area->num_vma; k++){
			//     vma = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * k);
			//     if (pid_data_list[i].ReadList[j] >= vma->start && pid_data_list[i].ReadList[j] <= vma->end){
			
			
			//         // pr_warn("%lx %lx\n", (uint64_t)vma,(uint64_t)vma->dirty_bitmap);
			//         // pr_warn("%lx %lx %lx\n", pid_data_list[i].ReadList[j], vma->start,vma->end);
			//         // pr_warn("%lx\n",(uint64_t)PidVma[i]->vmas[k1].start);
			//         if(PidVma[i]->vmas[k1].start != vma->start){
			//             continue;
			//         }
			//         // if(ca_bitmap_get(vma->dirty_bitmap, pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k].start) == 0){
			//         if (test_bit((pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k1].start)/ PAGE_SIZE, vma->dirty_bitmap)){
			
			//             // ca_bitmap_set(PidVma[i]->vmas[k].bitmap, (pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k].start) / PAGE_SIZE, 1);
			//             set_bit((pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k1].start) / PAGE_SIZE, PidVma[i]->vmas[k1].bitmap);
			//         }
			
			//         k1++;
			
			//     }
			// }
		}
	}
	
}

// get the dirty flag list of the vma
void *get_vma_dirtylist(void *arg)
{
	int i, ret, fd;
	struct epoch_area *EpochArea;
	// int area_size = 1024 * 4096;
	struct access_area *access_area;
	int sock;
	void *mem;
	struct get_vma_dirtylist_arg *temp_arg = (struct get_vma_dirtylist_arg *)arg;

	sock = temp_arg->sock;
	mem = temp_arg->mem;

	fd = open("/dev/collect_access", O_RDWR);
	ret = ioctl(fd, IOCTL_ALLOC_MEMORY, 0);
	pr_warn("mem address:0x%lx\n", (uint64_t)mem);

	// PidEpochArea = (struct epoch_area *)mem;
	for (i = 0; i < pid_array_size; i++) {
		struct ioctl_data *iodata;

		
		reset_mem_point();
		// push dirty flag to the access_area
		EpochArea = init_epoch_area(mem + ONE_AREA_SIZE * i);
		memset(EpochArea, 0, ONE_AREA_SIZE);
		;

		iodata = (struct ioctl_data *)malloc(sizeof(struct ioctl_data));
		iodata->pid = pid_array[i];
		iodata->addr = (unsigned long)get_mem_point();
		pr_warn("开始收集:pid: %d, addr: %lx\n", iodata->pid, iodata->addr);
		ret = ioctl(fd, IOCTL_MODIFY_PTE, iodata);
		if (ret != 0)
			pr_err("Failed to ioctl modify pte\n");
		pr_warn("数据成功收集，准备更新地址\n");
		address_translation((struct access_area *)get_mem_point());
		pr_warn("run to here\n");
		update_mem_point((struct epoch_area *)(EpochArea), (struct access_area *)get_mem_point());
		pr_warn("数据成功收集，更新地址完毕,vma_num:%ld\n", EpochArea->areas[0]->num_vma);
		pr_warn("偏移量：EpochArea->areas:%p, EpochArea->areas[0]:%p\n", EpochArea->areas, EpochArea->areas[0]);
		pr_warn("偏移量：EpochArea:%p, num_vma:%p\n", EpochArea, &EpochArea->areas[0]->num_vma);
		// address_translation(EpochArea->areas[0]);
	}

	// revise the address due to the page have copyed form kernel to user space
	pr_warn("run to here\n");
	ret = ioctl(fd, IOCTL_FREE_MEMORY, 0);
	if (ret != 0) {
		pr_err("Failed to ioctl free memory\n");
	}
	pr_warn("run to here\n");
	// // analyze the ditdy flag list to get the dirtylist
	// for (i = 0; i < pid_array_size; i++)
	// {
	//     access_area = (struct epoch_area*)(epoch_area + i * area_size)->areas[0];
	
	// }
	update_read_pid_data_list(mem);
	pr_warn("run to here, sock:%d\n", sock);

	update_state(sock, END_PAGE_DIRTY);
	pr_warn("update END_PAGE_DIRTY\n");
	return NULL;
}

// used to public variable update for page-client
void update_pid_array(uint64_t *pids, int size)
{
	int i;

	pr_warn("更新pid_array, size:%d\n", size);
	pid_array_size = size;
	pid_array = (pid_t *)malloc(sizeof(pid_t) * size);
	for (i = 0; i < size; i++)
		pid_array[i] = (pid_t)pids[i];
}

void *p_load_page(void *args)
{
	int i, uffd = -1;
	struct uffdio_copy uffdio_copy;
	int pid = *(int *)args;
	struct true_readiov *head = (struct true_readiov *)(args + 4), *current;
	pr_warn("run to here pid_array_size:%d\n", pid_array_size);
	for (i = 0; i < pid_array_size; i++) {
		pr_warn("pid_array[i]:%d, pid:%d\n", pid_array[i], pid);
		if (pid_array[i] == pidset[i]) {
			uffd = uffdset[i];
			break;
		}
	}
	pr_warn("run to here\n");
	current = head;
	do {
		uffdio_copy.src = current->addr;
		uffdio_copy.dst = (unsigned long)current->iov.iov_base;
		uffdio_copy.len = current->iov.iov_len;
		uffdio_copy.mode = 0;
		pr_warn("写read数据: src:%lx, dst:%lx, length:%ld\n", (uint64_t)current->addr, (uint64_t)uffdio_copy.dst, (uint64_t)uffdio_copy.len);
		if (ioctl_mul(&uffdio_copy, pid) == -1) {
			// perror("ioctl");
		}
		current = current->next;
	} while (current != head);
	return NULL;
}

// load the page to memory
/**
 * the data structure of the local_iov[i].buffer is as follows:
 * the number of iovec: 8 bytes
 * the array of iovec: iovec[0] + iovec[1] + ... + iovec[n]
 * the page data: page[0] + page[1] + ... + page[n]
 * 
 * steps:
 * 1. get the dirty flag of the page 
 * 2. if the page is dirty, the page in the buffer should be invalidate, the page can not read to the process memory
 * 3. read the other pages to the process memory
 */
void *page_client_load_page(void *args)
{
	int i, j, k, ret;
	struct data_buffer *pre_mr = (struct data_buffer *)args;
	struct epoch_area *PidEpochArea;
	struct access_area *access_area;
	struct __vma_area *vma;
	void *mem;
	struct true_readiov **PidReadIov, *current;
	int lens = 0;
	pthread_t *threads;
	struct p_load_page_args *p_load_page_args;

	PidEpochArea = (struct epoch_area *)pre_mr->l_addr2;
	mem = (void *)pre_mr->l_addr1;

	pr_warn("run to here mem:%p leng:%ld; PidEpochArea:%p length:%ld\n", mem, pre_mr->length1, PidEpochArea, pre_mr->length2);
	PidReadIov = (struct true_readiov **)malloc(sizeof(struct true_readiov *) * pid_array_size);
	pr_warn("run to here\n");
	memset(PidReadIov, 0, sizeof(struct true_readiov) * pid_array_size);
	pr_warn("run to here\n");
	for (i = 0; i < pid_array_size; i++) {
		struct access_area *access_area;
		struct __vma_area *vma;
		unsigned long start, end;
		struct iovec *iov;
		unsigned long iov_num = 0;
		struct true_readiov *readiov;

		
		
		iov_num = *(unsigned long *)(*(unsigned long *)(mem + 16 * i + 8) + (unsigned long)mem);
		pr_warn("pid:%ld, point to buffer:%lx, iov_num:%ld\n", *(u_int64_t *)mem, *(uint64_t *)(mem + 8), iov_num);
		readiov = (struct true_readiov *)malloc(sizeof(struct true_readiov) * iov_num);
		pr_warn("run to here\n");
		for (j = 0; j < (int)iov_num; j++) {
			iov = (struct iovec *)(mem + 24 + sizeof(struct iovec) * j);
			pr_warn("run to here\n");
			readiov[j].addr = *(unsigned long *)(mem + 24 + sizeof(struct iovec) * iov_num + lens);
			pr_warn("run to here\n");
			readiov[j].iov.iov_base = (void *)iov->iov_base;
			readiov[j].iov.iov_len = iov->iov_len;
			lens += readiov->iov.iov_len;
			pr_warn("run to here\n");
			
			if (PidReadIov[i] == NULL) {
				PidReadIov[i] = &readiov[j];
				readiov[j].prev = &readiov[j];
				readiov[j].next = &readiov[j];
			} else {
				readiov[j].prev = PidReadIov[i]->prev;
				readiov[j].next = PidReadIov[i];
				PidReadIov[i]->prev->next = &readiov[j];
				PidReadIov[i]->prev = &readiov[j];
			}
		}
		pr_warn("run to here\n");
		current = PidReadIov[i];
		access_area = (struct access_area *)(PidEpochArea + i * ONE_AREA_SIZE)->areas[0];
		while (j < access_area->num_vma) {
			vma = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);
			if (vma->start > (unsigned long)current->iov.iov_base + current->iov.iov_len) {
				j++;
				continue;
			} else if (vma->end < (unsigned long)current->iov.iov_base) {
				j++;
				continue;
			}
			/*
                This page is dirty, so this page must be transferred to page client again.
                TODO zxz: set this page's transfered flag to 0 in bitmap
            */
			for (k = 0; k < vma->size / PAGE_SIZE; k++) {
				// if (ca_bitmap_get(vma->dirty_bitmap, k)){
				if (test_bit(k, vma->dirty_bitmap)) {
					if (vma->start + k * PAGE_SIZE > (unsigned long)current->iov.iov_base && vma->start + k * PAGE_SIZE < (unsigned long)current->iov.iov_base + current->iov.iov_len) {
						struct true_readiov *readiov_i = (struct true_readiov *)malloc(sizeof(struct true_readiov));

						readiov_i->addr = current->addr + vma->start + (k + 1) * PAGE_SIZE - (unsigned long)current->iov.iov_base;
						readiov_i->iov.iov_base = (void *)(vma->start + k * PAGE_SIZE + PAGE_SIZE);
						readiov_i->iov.iov_len = (unsigned long)current->iov.iov_base + current->iov.iov_len - vma->start - k * PAGE_SIZE - PAGE_SIZE;
						readiov_i->prev = current;
						readiov_i->next = current->next;
						current->next->prev = readiov_i;
						current->next = readiov_i;
					} else if (vma->start + k * PAGE_SIZE == (unsigned long)current->iov.iov_base) {
						current->iov.iov_base = (void *)(vma->start + (k + 1) * PAGE_SIZE);
						current->iov.iov_len = current->iov.iov_len - PAGE_SIZE;
					} else if (vma->start + k * PAGE_SIZE + PAGE_SIZE == (unsigned long)current->iov.iov_base + current->iov.iov_len) {
						current->iov.iov_len = current->iov.iov_len - PAGE_SIZE;
					}
				}
			}
		}
	}
	pr_warn("run to here: pid_array_size:%d\n", pid_array_size);
	p_load_page_args = (struct p_load_page_args *)malloc(sizeof(struct p_load_page_args) * pid_array_size);
	threads = (pthread_t *)malloc(sizeof(pthread_t) * pid_array_size);
	for (i = 0; i < pid_array_size; i++) {
		p_load_page_args[i].pid = pid_array[i];
		p_load_page_args[i].PidReadIov = PidReadIov[i];
		pthread_create(&threads[i], NULL, p_load_page, (void *)&p_load_page_args[i]);
	}
	pr_warn("run to here\n");
	for (i = 0; i < pid_array_size; i++) {
		pthread_join(threads[i], NULL);
	}
	return NULL;
}

// struct p_read_pages_args_V2
// {
//     int pid;
//     int num_pages;
//     -- unsigned long *addr_set;
//     -- PAGES
// };

void read_pages_V2(volatile void **mem, uint64_t *mem_size)
{
	int i, j, k, lens = 0, ret;
	struct iov_list *current;
	struct p_read_pages_args_V2 *args;
	struct local_iov *local_iov;
	struct iovec riov, liov;
	unsigned long all_pages = 0;

	struct vmas_t *vma_can_be_lazy;
	int num_vma = 0;

	
	// for(i = 0; i < pid_array_size; i++){
	//     for(j=0;j<pid_data_list[i].read_hot_num;j++){
	//         pr_warn("cccccccccccccccccccccccccccccRead list: j:%d addr:%lx\n",j,pid_data_list[i].ReadList[j]);
	//     }
	// }
	/* mem structure: [pid, read_hot_num,(address, page data) * read_hot_num], [pid, read_hot_num,(address, page data) * read_hot_num] */
	for (i = 0; i < pid_array_size; i++) {
		all_pages += pid_data_list[i].read_hot_num;
	}
	pr_warn("all_pages:%ld\n", all_pages);
	*mem_size = 16 * (uint64_t)pid_array_size + (uint64_t)all_pages * (8 + PAGE_SIZE);
	if (*mem_size < ONE_AREA_SIZE * (uint64_t)pid_array_size + 10 * PAGE_SIZE)
		*mem_size = ONE_AREA_SIZE * (uint64_t)pid_array_size + 10 * PAGE_SIZE;
	// *mem_size = ONE_AREA_SIZE * item_num;
	*mem = (void *)malloc(*mem_size);
	memset((void *)*mem, 1, *mem_size);
	pr_warn("申请的mem_size为:%ld\n", *mem_size);

	for (i = 0; i < pid_array_size; i++) {
		*(unsigned long *)(*mem + lens) = pid_data_list[i].pid;
		*(unsigned long *)(*mem + lens + 8) = pid_data_list[i].read_hot_num;
		for (j = 0; j < pid_data_list[i].read_hot_num; j++) {
			// pr_warn("ReadList %d: 0x%lx\n", j, pid_data_list[i].ReadList[j]);
			*(unsigned long *)(*mem + lens + 16 + 8 * j) = pid_data_list[i].ReadList[j];
		}
		lens += 16 + (8 + PAGE_SIZE) * pid_data_list[i].read_hot_num;
	}

	lens = 0;
	for (i = 0; i < pid_array_size; i++) {
		for (j = 0; j < pid_data_list[i].read_hot_num; j++) {
			liov.iov_base = (void *)(*mem + lens + 16 + 8 * pid_data_list[i].read_hot_num + j * PAGE_SIZE);
			liov.iov_len = PAGE_SIZE;

			riov.iov_base = (void *)pid_data_list[i].ReadList[j];
			riov.iov_len = PAGE_SIZE;
			ret = process_vm_readv(pid_data_list[i].pid,
					       &liov, 1, 
					       &riov, 1, 
					       0);	 
							 pr_warn("从 %lx 读到 %lx, %lx  %lx  %lx  %lx\n", (uint64_t)riov.iov_base, (uint64_t)liov.iov_base,
							  *(uint64_t *)(liov.iov_base),*(uint64_t *)(liov.iov_base + 64), *(uint64_t *)(liov.iov_base+ 128), *(uint64_t *)(liov.iov_base+256));
							 // if(j == 9999)
							
							//                                                  *(uint64_t *)(liov.iov_base - 4096), *(uint64_t *)(liov.iov_base ));
			if (ret == -1) {
				
				for (k = 0; k < PidVma[i]->num_vma; k++) {
					if (pid_data_list[i].ReadList[j] >= PidVma[i]->vmas[k].start && pid_data_list[i].ReadList[j] < PidVma[i]->vmas[k].end) {
						for (;j < pid_data_list[i].read_hot_num&& pid_data_list[i].ReadList[j] >= PidVma[i]->vmas[k].start && pid_data_list[i].ReadList[j] < PidVma[i]->vmas[k].end;j++) {
							clear_bit((pid_data_list[i].ReadList[j] - PidVma[i]->vmas[k].start) / PAGE_SIZE, PidVma[i]->vmas[k].bitmap);
						}
						break;
					}
				}
			}
			if (j % 100000 == 0) {
				pr_warn("完成%d页面\n", j);
			}
		}
		lens += 16 + (8 + PAGE_SIZE) * pid_data_list[i].read_hot_num;
	}
	pr_warn("run to here\n");
}

void *page_client_load_page_V2(void *args)
{
	int ret, index;
	volatile uint64_t i, j, k;
	volatile struct data_buffer *pre_mr = (struct data_buffer *)args;
	volatile struct epoch_area *PidEpochArea;
	volatile struct access_area *access_area;
	volatile struct __vma_area *vma;
	volatile void *mem;
	volatile struct uffdio_copy uffdio_copy;
	volatile uint64_t lens = 0, off = 8;
	volatile int all_pages;
	volatile int uffd = -1;
	volatile void *lazy_vma = NULL, *Pid_lazy_vmas = NULL;
	uint64_t num;

	PidEpochArea = (struct epoch_area *)(pre_mr->l_addr2 + ACCESS_VMA_SIZE);
	mem = (void *)pre_mr->l_addr1;
	Pid_lazy_vmas = (void *)pre_mr->l_addr2;

	num = *(uint64_t *)(mem + lens + 8);
	pr_warn("run to herePidEpochArea:%p\n", PidEpochArea);
	pr_warn("data[0]:%lx, data[1]:%lx\n", *(uint64_t *)PidEpochArea, *(uint64_t *)(PidEpochArea + 8));
	pr_warn("run to heremem[0]:%ld, mem[1]:%ld, mem[2]:%lx\n", *(uint64_t *)mem, *(uint64_t *)(mem + 8), *(uint64_t *)(mem + 16));
	pr_warn("输出内存数据:%lx %lx %lx %lx\n", *(uint64_t *)(mem + 16 + 8 * num + 4096 * 9996), *(uint64_t *)(mem + 16 + 8 * num + 4096 * 9997),
		*(uint64_t *)(mem + 16 + 8 * num + 4096 * 9998), *(uint64_t *)(mem + 16 + 8 * num + 4096 * 9999));
	for (index = 0; index < pid_array_size; index++) {
		struct access_area *access_area;
		struct __vma_area *vma;
		unsigned long start, end;
		struct iovec *iov;
		unsigned long page_num = 0;
		struct true_readiov *readiov;

		
		// (uint64_t)((PidEpochArea + index * ONE_AREA_SIZE)->areas) += ((uint64_t)PidEpochArea - pre_mr->r_addr);
		
		// *(uint64_t *)((uint64_t)PidEpochArea + index * ONE_AREA_SIZE + 8) = ((uint64_t)PidEpochArea + index * ONE_AREA_SIZE + 4096);
		access_area = (struct access_area *)((struct epoch_area *)((uint64_t)PidEpochArea + index * ONE_AREA_SIZE))->areas[0];
		
		address_translation(access_area);
		
		page_num = *(uint64_t *)(mem + lens + 8);
		

		// for (i = 0; i < *(uint64_t *)Pid_lazy_vmas; i++){
		//     uint64_t pid = *(uint64_t *)(Pid_lazy_vmas);
		//     uint64_t num = *(uint64_t *)(Pid_lazy_vmas + 8 + index);
		//     if (pid == pid_array[index]){
		//         lazy_vma = Pid_lazy_vmas + off;
		//         break;
		//     }else{
		//         off += 16 + num * 16;
		//     }
		// }

		for (i = 0; i < pid_array_size; i++) {
			uint64_t pid = *(uint64_t *)(Pid_lazy_vmas + 8 + PAGE_SIZE * i);
			if (pid == pid_array[index]) {
				lazy_vma = Pid_lazy_vmas + 8 + PAGE_SIZE * i;
				break;
			}
		}
		
		// for (k = 0; k < *(uint64_t *)(lazy_vma + 8); k++) {
		// 	pr_warn("start:%lx, end:%lx\n", *(uint64_t *)(lazy_vma + 16 + (k * 16)), *(uint64_t *)(lazy_vma + 16 + (k * 16 + 8)));
		// }

		for (j = 0; j < access_area->num_vma; j++) {
			vma = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);
			pr_warn("access_area vma start:%lx, end:%lx\n", vma->start, vma->end);
		}
		pr_warn("page_num: %ld\n",page_num);
		for (i = 0; i < page_num; i++) {
			for (j = 0; j < access_area->num_vma; j++) {
				volatile int jump = 1;
				int num_lazy_vma;
				uint64_t addr;
				addr = *(uint64_t *)(mem + lens + 16 + 8 * i);
				vma = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);

				if (vma->start > addr || vma->end <= addr) {
					continue;
				}

				num_lazy_vma = *(uint64_t *)(lazy_vma + 8);
				for (k = 0; k < num_lazy_vma; k++) {
					// if(k == 3 || k == 5 || k == 15 || k == 17)
					//     continue;
					if (addr >= *(uint64_t *)(lazy_vma + 16 + (k * 16)) && addr < *(uint64_t *)(lazy_vma + 16 + (k * 16) + 8)) {
						jump = 0;
						break;
					}
				}

				if (jump)
					break;

				
				
				// if(ca_bitmap_get(vma->dirty_bitmap, *(uint64_t *)(mem + lens + 16 + 8 * i) - vma->start) == 0){
				if (test_bit((*(uint64_t *)(mem + lens + 16 + 8 * i) - vma->start) / PAGE_SIZE, vma->dirty_bitmap) == 0) {
					
					uffdio_copy.src = (uint64_t)(mem + lens + 16 + 8 * page_num + i * PAGE_SIZE);
					uffdio_copy.dst = *(uint64_t *)(mem + lens + 16 + 8 * i);
					uffdio_copy.len = PAGE_SIZE;
					uffdio_copy.mode = 0;
					// if (*(uint64_t *)uffdio_copy.src == 0x101010101010101 && *(uint64_t *)(uffdio_copy.src + 64) == 0x101010101010101 && *(uint64_t *)(uffdio_copy.src + 128) == 0x101010101010101) {
					// 	// pr_warn("================continue=====================\n");
					// 	break;
					// }
					// if(uffdio_copy.dst <0x20000000000){
					//     // pr_warn("================continue=====================\n");
					//     continue;

					// }
					
					//                                 *(uint64_t *)(uffdio_copy.src + 128), *(uint64_t *)(uffdio_copy.src + 256));
					// pr_warn("pre-transfer i:%ld src: 0x%lx, dst: 0x%lx   content:%lx %lx %lx %lx\n",i, (uint64_t)uffdio_copy.src, (uint64_t)uffdio_copy.dst,
					// 													 *(uint64_t *)(uffdio_copy.src), *(uint64_t *)(uffdio_copy.src + 64), *(uint64_t *)(uffdio_copy.src + 128), *(uint64_t *)(uffdio_copy.src + 256));
					if (ioctl_mul(&uffdio_copy, pid_array[index]) == -1) {
						perror("ioctl");
					}
				} else {
					
				}
			}
		}
		lens += 16 + (8 + PAGE_SIZE) * page_num;
	}
	return NULL;
}
