#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>



#include "test_access.h"
#include "types.h"
#include <string.h>
#include <fcntl.h>
// #define test_bit(bit, bitmap) ((*bitmap) & (1UL << (bit)))
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define MAX_PAGES_NUM	   10 * 1024 * 1024
#define SHARED_MEM_SIZE	   4096 * 4096 * 20
#define IOCTL_MODIFY_PTE   _IOW('m', 1, struct ioctl_data)
#define IOCTL_ALLOC_MEMORY _IOW('m', 2, int)
#define IOCTL_FREE_MEMORY  _IOW('m', 3, int)
#define SAMPLE_TIMES	   10
#define SAMPLE_INTERVAL	   2

struct ioctl_data {
	int pid;
	unsigned long addr;
	// char *addr;
	// char *path;
};
int sl_size = 0;

// create shared memory
// void *create_share_memory(struct ioctl_data *data)
// {
//     int fd;
//     char path[128];
//     struct epoch_area *area;
//     // mode_t old_umask;
//     // old_umask = umask(0000);
//     snprintf(path, sizeof(path), "/dev/shm/epoch_access_area_%d", data->pid);
//     fd = open(path, O_RDWR | O_CREAT, 0666);
//     if (fd < 0)
//     {
//         printf("Failed to open shared memory file\n");
//         return NULL;
//     }

//     if (ftruncate(fd, SHARED_MEM_SIZE) == -1)
//     {
//         perror("ftruncate");
//         close(fd);
//         exit(EXIT_FAILURE);
//     }

//     area = (struct epoch_area *)mmap(NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
//     if (area == MAP_FAILED)
//     {
//         printf("Failed to map shared memory\n");
//         return NULL;
//     }
//     close(fd);
//     // umask(old_umask);
//     return area;
// }

struct all_vma_area {
	unsigned long start;
	unsigned long end;
	unsigned long size;
	unsigned long *bitmap;
	struct score_list *score;

	struct all_vma_area *prev;
	struct all_vma_area *next;
};

#define NEW_VMA(vma)                                                      \
	vma = (struct all_vma_area *)malloc(sizeof(struct all_vma_area)); \
	if (!vma)                                                         \
		return NULL;                                              \
	memset(vma, 0, sizeof(struct all_vma_area));


static inline float score_policy(float score, int index, int times)
{
	return (float)index / times;
}


void swap_nodes(struct score_list **head, struct score_list *node1, struct score_list *node2)
{
	if (node1 == node2)
		return;

	struct score_list *prev1 = node1->prev;
	struct score_list *next1 = node1->next;
	struct score_list *prev2 = node2->prev;
	struct score_list *next2 = node2->next;

	
	if (next1 == node2) {
		node1->next = next2;
		node1->prev = node2;
		node2->next = node1;
		node2->prev = prev1;
		if (prev1)
			prev1->next = node2;
		if (next2)
			next2->prev = node1;
	} else if (next2 == node1) {
		node2->next = next1;
		node2->prev = node1;
		node1->next = node2;
		node1->prev = prev2;

		if (next1)
			next1->prev = node2;
		if (prev2)
			prev2->next = node1;
	} else {
		node1->next = next2;
		node1->prev = prev2;
		node2->next = next1;
		node2->prev = prev1;
		if (prev1)
			prev1->next = node2;
		if (next1)
			next1->prev = node2;
		if (prev2)
			prev2->next = node1;
		if (next2)
			next2->prev = node1;
	}

	if (node1->prev == NULL)
		*head = node1;
	if (node2->prev == NULL)
		*head = node2;
}

struct score_list *score_list_sort(struct score_list *list)
{
	// sort the score list by score
	struct score_list *head = list;
	struct score_list *cur_i = list;
	struct score_list *cur_j = list;
	struct score_list *temp = NULL;
	while (cur_i != NULL) {
		cur_j = cur_i->next;
		while (cur_j != NULL) {
			// printf("i_addr:%p j_addr:%p\n", cur_i->addr, cur_j->addr);
			if (cur_i->score < cur_j->score) {
				swap_nodes(&head, cur_i, cur_j);
				temp = cur_i;
				cur_i = cur_j;
				cur_j = temp;
				// printf("i_addr:%p j_addr:%p exchange\n", cur_i->addr, cur_j->addr);
			}
			cur_j = cur_j->next;
		}
		cur_i = cur_i->next;
	}

	return head;
}

int is_exist(struct all_vma_area *vma_head, struct all_vma_area *vma)
{
	struct all_vma_area *temp = vma_head;
	while (temp != NULL) {
		if (temp->start == vma->start && temp->end == vma->end) {
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

struct score_list *analyze_access(struct epoch_area *epoch_area)
{
	int ret = 0, i, j;
	struct access_area *access_area;
	struct all_vma_area *vma_tail = NULL, *vma, *vma_head = NULL;
	struct __vma_area *vml;
	int score_list_size = 0;
	int epoch_i, access_i, vma_i;
	int all_vma_num = 0;

	struct score_list *Scorelist, *head = NULL;
	// printf("analyze_access: enter\n");

	// ----------------- step1: merge all vma -----------------
	
	for (i = 0; i < epoch_area->num_area; i++) {
		access_area = epoch_area->areas[i];
		for (j = 0; j < access_area->num_vma; j++) {
			NEW_VMA(vma);
			vml = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);
			vma->start = vml->start;
			vma->end = vml->end;
			if (is_exist(vma_head, vma)) {
				continue;
			}
			vma->size = vml->size;
			score_list_size += (int)(vma->size / PAGE_SIZE);
			vma->bitmap = vml->bitmap;
			if (!vma_tail) {
				vma->next = NULL;
				vma->prev = NULL;
				vma_tail = vma;
				vma_head = vma;
			} else {
				// insert to the tail
				vma_tail->next = vma;
				vma->prev = vma_tail;
				vma_tail = vma;
				vma_tail->next = NULL;
			}
		}
	}
	// printf("analyze_access: vma list create success!\n");
	Scorelist = (struct score_list *)malloc(sizeof(struct score_list) * score_list_size);
	memset(Scorelist, 0, sizeof(struct score_list) * score_list_size);

	// init all vma area
	score_list_size = 0;
	vma = vma_head;
	while (vma != NULL) {
		unsigned long addr;
		vma->score = Scorelist + score_list_size;
		score_list_size += (int)(vma->size / PAGE_SIZE);

		addr = vma->start;
		for (i = 0; i < (int)(vma->size / PAGE_SIZE); i++) {
			// vma->score[i].addr = addr + PAGE_SIZE;//?
			vma->score[i].addr = addr;
			addr += PAGE_SIZE;
		}
		all_vma_num++;
		vma = vma->next;
	}
	// printf("analyze_access: vma scorelist success\n");

	for (i = 0; i < score_list_size; i++) {
		if (i == 0) {
			Scorelist[i].prev = NULL;
			Scorelist[i].next = &Scorelist[i + 1];
		} else if (i == score_list_size - 1) {
			Scorelist[i].prev = &Scorelist[i - 1];
			Scorelist[i].next = NULL;
		} else {
			Scorelist[i].prev = &Scorelist[i - 1];
			Scorelist[i].next = &Scorelist[i + 1];
		}
	}

	// ----------------- step2: collect access -----------------
	// judge whether the vma_area is overlap, then compute the score
	for (epoch_i = 0; epoch_i < epoch_area->num_area; epoch_i++) {
		access_area = epoch_area->areas[epoch_i];
		vma = vma_head;
		j = 0;
		struct __vma_area *vml = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);
		while (vma != NULL && j < access_area->num_vma) {
			unsigned long start, end;
			start = vma->start > vml->start ? vma->start : vml->start;
			end = vma->end < vml->end ? vma->end : vml->end;
			if (start <= end) {
				// [start:end] is the overlap area
				unsigned long *bitmap = vml->bitmap;
				unsigned long *dirty_bitmap = vml->dirty_bitmap;
				int offset = (start - vml->start) / PAGE_SIZE;
				for (i = 0; i < (end - start) / PAGE_SIZE; i++) {
					if (ca_bitmap_get(bitmap, offset + i)) {
						vma->score[offset + i].times++;
						
						vma->score[offset + i].score = score_policy(vma->score[offset + i].score, epoch_i, epoch_area->num_area);
					}
					if (ca_bitmap_get(dirty_bitmap, offset + i)) {
						vma->score[offset + i].dirty_times++;
					}
				}
			}
			if (vma->end < vml->end) {
				vma = vma->next;
			} else {
				j++;
				vml = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);
			}
		}
	}
	// printf("analyze_access: count score success\n");
	sl_size = score_list_size;
	for (i = 0; i < score_list_size; i++) {
		if (Scorelist[i].times == 0 && Scorelist[i].dirty_times == 0) {
			sl_size--;
			if (Scorelist[i].prev != NULL) {
				Scorelist[i].prev->next = Scorelist[i].next;
			}
			if (Scorelist[i].next != NULL) {
				Scorelist[i].next->prev = Scorelist[i].prev;
			}
		} else if (head == NULL) {
			head = &Scorelist[i];
		}
	}

	printf("analyze_access: prepare sort list of length %d\n", score_list_size);

	// printf("analyze_access: sort success\n");
	return head;
}

void print_info(struct epoch_area *epoch_area)
{
	int ret = 0, i, j, k;
	struct access_area *access_area;
	struct all_vma_area *vma_tail = NULL, *vma, *vma_head = NULL;
	struct __vma_area *vml;
	int score_list_size = 0;
	int epoch_i, access_i, vma_i;
	int all_vma_num = 0;
    FILE *print_log;

	struct score_list *Scorelist, *head = NULL;
    print_log = fopen("/var/lib/criu/print.log", "w");
	// ----------------- step2: collect access -----------------
	// judge whether the vma_area is overlap, then compute the score
	for (epoch_i = 0; epoch_i < epoch_area->num_area; epoch_i++) {
		access_area = epoch_area->areas[epoch_i];
		for (j = 0; j < access_area->num_vma; j++) {
			vml = (struct __vma_area *)((void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * j);
			unsigned long *bitmap = vml->bitmap;
			unsigned long *dirty_bitmap = vml->dirty_bitmap;
			for (k = 0; k < (vml->end - vml->end) / PAGE_SIZE; k++) {
				if (test_bit(k,bitmap)) {
                    fprintf(print_log, "%lx access\n",vml->start+k*PAGE_SIZE);
                }
                if (test_bit(k,dirty_bitmap)) {
                    fprintf(print_log, "%lx dirty\n",vml->start+k*PAGE_SIZE);
                }
			}
		}
	}
    fclose(print_log);
}

struct score_list *get_dirty_list(struct score_list *Scorelist)
{
	struct score_list *dirty_list = NULL;
	struct score_list *dirty_list_tail = NULL;
	struct score_list *cur = Scorelist;
	struct score_list *temp;
	int num = 0;
	
	while (cur != NULL) {
		if (cur->dirty_times > 0) {
			temp = cur->next;
			num++;
			// delete from the list
			if (cur->next != NULL) {
				cur->next->prev = cur->prev;
			}
			if (cur->prev != NULL) {
				cur->prev->next = cur->next;
			}
			cur->next = NULL;
			cur->prev = NULL;
			// insert to the dirty list
			if (dirty_list == NULL) {
				dirty_list = cur;
				dirty_list_tail = cur;
			} else {
				dirty_list_tail->next = cur;
				cur->prev = dirty_list_tail;
				dirty_list_tail = cur;
			}
			cur = temp;
		} else {
			cur = cur->next;
		}
	}
	printf("dirty list size:%d\n", num);
	return dirty_list;
}

int address_translation(struct access_area *access)
{
	unsigned long user_bitmap = (unsigned long)access + ACCESS_VMA_SIZE;
	struct __vma_area *first_vma = (struct __vma_area *)((void *)access + sizeof(struct access_area));
	unsigned long kernel_bitmap = (unsigned long)first_vma->bitmap;
	for (int i = 0; i < access->num_vma; i++) {
		struct __vma_area *vma = (struct __vma_area *)((void *)access + sizeof(struct access_area) + sizeof(struct __vma_area) * i);
		// printf("bitmap:%ld\n",vma->bitmap);
		vma->bitmap = (unsigned long *)((unsigned long)vma->bitmap - kernel_bitmap + user_bitmap);
		vma->dirty_bitmap = (unsigned long *)((unsigned long)vma->dirty_bitmap - kernel_bitmap + user_bitmap);
		// printf("bitmap:%ld\n",vma->bitmap);
	}
}

int main(int argc, char *argv[])
{
	int ret, i, fd;
	struct ioctl_data data;
	struct epoch_area *EpochArea;
	struct score_list *ScoreList;
	struct score_list *dirtylist;
	clock_t start_time, end_time;
	double cpu_time_used;

	pid_t pid = atoi(argv[1]);
	data.pid = pid;
	start_time = clock();
	EpochArea = (struct epoch_area *)malloc(SHARED_MEM_SIZE);
	// EpochArea = (struct epoch_area *)create_share_memory(&data);
	end_time = clock();

	cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	printf("malloc time used: %.4f seconds\n", cpu_time_used);
	if (!EpochArea) {
		printf("Failed to create shared memory\n");
		return -1;
	}
	EpochArea = init_epoch_area(EpochArea);

	fd = open("/dev/collect_access", O_RDWR);
	if (fd < 0) {
		printf("Failed to open collect_access\n");
		return -1;
	}
	printf("open dev success\n");
	start_time = clock();
	ret = ioctl(fd, IOCTL_ALLOC_MEMORY, 0);
	if (ret < 0) {
		printf("Failed to ioctl init_memory\n");
		return -1;
	}

	end_time = clock();

	cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	printf("kernel alloc memory time used: %.4f seconds\n", cpu_time_used);

	for (i = 0; i < SAMPLE_TIMES; i++) {
		data.addr = (unsigned long)get_mem_point();
		start_time = clock();
		ret = ioctl(fd, IOCTL_MODIFY_PTE, &data);
		if (ret < 0) {
			printf("Failed to ioctl collect_access\n");
			return -1;
		}
		end_time = clock();

		cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
		printf("one access time used: %.4f seconds\n", cpu_time_used);
		start_time = clock();
		address_translation((struct access_area *)get_mem_point());
		end_time = clock();

		cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
		printf("address translation time used: %.4f seconds\n", cpu_time_used);
		update_mem_point(EpochArea, (struct access_area *)get_mem_point());
		
		sleep(SAMPLE_INTERVAL);
	}
	start_time = clock();
	ret = ioctl(fd, IOCTL_FREE_MEMORY, 0);
	if (ret < 0) {
		printf("Failed to ioctl init_memory\n");
		return -1;
	}
	end_time = clock();

	cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	printf("kernel free memory time used: %.4f seconds\n", cpu_time_used);
	printf("ioctl success\n");

	start_time = clock();
    print_info(EpochArea);
	// ScoreList = analyze_access(EpochArea);
	end_time = clock();

	cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	printf("analyze time used: %.4f seconds\n", cpu_time_used);
	printf("ioctl success\n");

	// start_time = clock();
	// dirtylist = get_dirty_list(ScoreList);
	// end_time = clock();

	// cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	// printf("get dirty time used: %.4f seconds\n", cpu_time_used);
	// printf("ioctl success\n");

	// start_time = clock();
	// // ScoreList = score_list_sort(ScoreList);
	// end_time = clock();

	// cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	// printf("sort time used: %.4f seconds\n", cpu_time_used);
	// printf("ioctl success\n");

	// struct score_list *cur = dirtylist;
	// printf("dirty list:\n");
	// while (cur != NULL)
	// {
	//     printf("addr:%p access:%d dirty:%d\n", cur->addr, cur->times, cur->dirty_times);
	//     cur = cur->next;
	// }

	// cur = ScoreList;
	// printf("score list:\n");
	// while (cur != NULL)
	// {
	//     printf("addr:%p access:%d dirty:%d\n", cur->addr, cur->times, cur->dirty_times);
	//     cur = cur->next;
	// }

	return 0;
}