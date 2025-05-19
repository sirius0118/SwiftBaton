#include <string.h>
#include "hot-mem.h"

#define PAGE_SIZE 4096
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y)	   ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y)   ((x) & ~__round_mask(x, y))

// ####### Just last record #######
uint64_t nr_dirty = 0;

struct last_record * LR_init(long size){
    struct last_record *LR = (struct last_record *)malloc(size);
    return LR;
}

int LR_add(struct last_record *LR, uint64_t pid, uint64_t addr){
    if (unlikely(nr_dirty + 1 > MAX_LAST_RECORD_SIZE / 16))
        return -1;
    LR[nr_dirty].pid = pid;
    LR[nr_dirty].addr = addr;
    nr_dirty += 1;

    return 0;
}

void LR_clean(struct last_record *LR)
{
    memset(LR, 0, sizeof(struct last_record) * MAX_LAST_RECORD_SIZE);
    nr_dirty = 0;
}

struct share_LR *share_LR_init(void *mem, int size)
{
    struct share_LR *SLR = (struct share_LR *)mem;
    SLR->stop = 0;
    SLR->can_be_write = 0;
    SLR->nr_dirty = 0;
    SLR->max_items = size / sizeof(struct last_record) - 2;
    // SLR->LR = (struct last_record *)SLR + sizeof(struct share_LR);

    return SLR;
}

int SLR_add(struct share_LR *SLR, uint64_t pid, uint64_t addr)
{
    struct last_record *LR;
    if (unlikely(SLR->nr_dirty + 1 > SLR->max_items))
        return -1;
    LR = get_LR(SLR);
    LR[SLR->nr_dirty].pid = pid;
    LR[SLR->nr_dirty].addr = addr;
    SLR->nr_dirty += 1;

    return 0;
}


//  ###### For LRU algorithm ######

struct LRU_list *LRU_init()
{
    struct LRU_list *LRU = (struct LRU_list *)malloc(sizeof(struct LRU_list));
    LRU->head = NULL;
    LRU->tail = NULL;
    return LRU;
}

void LRU_add(struct LRU_list *list, uint64_t addr)
{
    struct LRU_page *page = (struct LRU_page *)malloc(sizeof(struct LRU_page));
    page->addr = addr;
    page->next = NULL;
    if (list->head == NULL){
        list->head = page;
        list->tail = page;
    }else{
        list->tail->next = page;
        list->tail = page;
    }
}

void LRU_del(struct LRU_list *list, uint64_t addr)
{
    struct LRU_page *page = list->head;
    struct LRU_page *pre = NULL;
    while (page != NULL){
        if (page->addr == addr){
            if (pre == NULL){
                list->head = page->next;
            }else{
                pre->next = page->next;
            }
            if (page->next == NULL){
                list->tail = pre;
            }
            free(page);
            break;
        }
        pre = page;
        page = page->next;
    }
}

// ############# For hot memory printing #############

void hot_mem_init(struct pid_vma* pv, struct vm_area_list *vma_list, int pid)
{
    struct vma_area *vma;
    struct hmvma_set *hms;
    struct hmvma *hm;

    hms = (struct hmvma_set *)malloc(sizeof(struct hmvma_set));
    hmvma_set_init(hms);
    hms->pid = pid;

    list_for_each_entry(vma, &vma_list->h, list) {
        // struct hmvma *hm;
        if (!vma_entry_can_be_lazy(vma->e))
            continue;
        hm = (struct hmvma *)malloc(sizeof(struct hmvma));
        hmvma_init(hm);
        hm->start = vma->e->start;
        hm->end = vma->e->end;
        // hm->lazy_page = vma_entry_can_be_lazy(vma->e);
        
        hm->page_transed = (unsigned long *)malloc((int)((get_hotmem_start(hm->end - PAGE_SIZE) - get_hotmem_start(hm->start)) / MAX_TRANSFER_SIZE + 1));
        memset(hm->page_transed, 0, (int)((get_hotmem_start(hm->end - PAGE_SIZE) - get_hotmem_start(hm->start)) / MAX_TRANSFER_SIZE + 1));
        list_add_tail(&hm->list, &hms->list);
    }
    
    list_add_tail(&hms->h, &pv->h);
}


// ############# Collection softdity #############


void CleanSoftdirty(uint64_t pid)
{
    int fd;
    char clear_refs_path[64];
    const char *clear_value = "4";

    snprintf(clear_refs_path, sizeof(clear_refs_path), "/proc/%ld/clear_refs", pid);

    fd = open(clear_refs_path, O_WRONLY);
    if (fd == -1) {
        pr_err("Error opening clear_refs file");
        exit(EXIT_FAILURE);
    }

    if (write(fd, clear_value, 1) == -1) {
        pr_err("Error writing to clear_refs file");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}


void CollectSoftdirty(struct share_LR *SLR, uint64_t pid)
{
    int fd, softdirty;
    FILE *maps_file;
    uint64_t index, pagemap_value;
    char line[256];
    char maps_path[128], pagemap_path[128];
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", pid);
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%ld/pagemap", pid);

    fd = open(pagemap_path, O_RDONLY);

    maps_file = fopen(maps_path, "r");

    while (fgets(line, sizeof(line), maps_file))
    {
        unsigned long start, end;
        if( sscanf(line, "%lx-%lx", &start, &end) == 2 ){
            for( uint64_t addr = start; addr < end; addr += PAGE_SIZE){
                // printf("nr_dirty:%ld\n", nr_dirty);
                index = addr / PAGE_SIZE * PAGEMAP_LENGTH;
                if (lseek(fd, index, SEEK_SET) == -1){
                    pr_err("lseek error");
                    break;
                }

                if (read(fd, &pagemap_value, PAGEMAP_LENGTH) != PAGEMAP_LENGTH){
                    close(fd);
                    break;
                }
                softdirty = (pagemap_value >> 55) & 1;
                
                if (softdirty)
                    if (SLR_add(SLR, pid, addr)){                    
                        close(fd);
                        break;
                    }
            }
        }
    }
}


// ################ Hot Memory Predict ################



