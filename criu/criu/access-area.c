
#ifdef MODULE
#include <linux/module.h>   // for MODULE_LICENSE, MODULE_AUTHOR, etc.
#include <linux/kernel.h>
// #define NULL ((void *)0)
#endif
#define NULL ((void *)0)
#include "access-area.h"
#include "log.h"
// #include <stdlib.h>

#define PAGE_SIZE 4096



static void *mem_point = 0;

static void *kmem_point=0;

void *reset_mem_point(){
    mem_point = 0;
    return NULL;
}

void *get_mem_point(){
    return mem_point;
}

void *get_kmem_point(){
    return kmem_point;
}





struct epoch_area * init_epoch_area(void *mem){
    // unsigned long value = (unsigned long)mem;
    // value = ROUND_UP(value, 4096);
    // mem = (void *)value;
    struct epoch_area *area = (struct epoch_area *)mem;
    #ifdef MODULE
    printk(KERN_INFO "init_epoch_area: enter\n");
    if(area == NULL){
        printk(KERN_ERR "init_epoch_area: area is NULL\n");
    }
    printk(KERN_INFO "init_epoch_area: area is %p\n", area);
    #endif
    area->num_area = 0;
    #ifdef MODULE
    printk(KERN_INFO "init_epoch_area: set num_area 0\n");
    #endif
    // area->areas = NULL;
    mem_point = mem + 4096;

    return area;
}

int kernel_init_access(struct access_area *access){
    kmem_point = (void *)access;
    access->num_vma = 0;
    kmem_point+=4096;
    return 0;
}


int update_mem_point(struct epoch_area *area,struct access_area *access){
    struct __vma_area *last_vma = (struct __vma_area *)((void *)access + sizeof(struct access_area) + sizeof(struct __vma_area) * (access->num_vma-1));
    unsigned long value;
    pr_warn("run to here\n");
    mem_point = last_vma->dirty_bitmap + last_vma->size/PAGE_SIZE;
    value = (unsigned long)mem_point;
    value = ROUND_UP(value, 4096);
    mem_point=(void *)value;
    area->areas[area->num_area] = access;
    area->num_area++;
    return 0;
}



// int epoch_add_access(struct epoch_area *area){
//     unsigned long value = (unsigned long)mem_point;
//     #ifdef MODULE
//     printk(KERN_INFO "epoch_add_access: enter\n");
//     #endif
//     area->num_area++;
//     value = ROUND_UP(value, 4096);
//     mem_point = (void *)value;
//     area->areas = mem_point;
//     mem_point += 4096;

//     return 0;
// }

int access_add_vma(struct access_area *access, struct __vma_area *vma){
    struct __vma_area *tem_vma;
    tem_vma = (struct __vma_area *)((void *)access + sizeof(struct access_area) + sizeof(struct __vma_area) * access->num_vma);
    tem_vma->size = vma->end - vma->start;
    tem_vma->start = vma->start;
    tem_vma->end = vma->end;
    tem_vma->bitmap = kmem_point;
    kmem_point += tem_vma->size/PAGE_SIZE;
    tem_vma->dirty_bitmap = kmem_point;
    kmem_point += tem_vma->size/PAGE_SIZE;
    // kmem_point += ROUND_UP(tem_vma->size/PAGE_SIZE+1, 8);
    access->num_vma++;

    return 0;
}

unsigned long * kernel_get_bitmap(struct access_area *access, int vma_index){
    struct __vma_area *vma = (struct __vma_area *)((void *)access + sizeof(struct access_area) + sizeof(struct __vma_area) * vma_index);
    return vma->bitmap;
}


// unsigned long * get_bitmap(struct epoch_area *area, int index, int vma_index){
//     struct access_area *access = &area->areas[index];
//     struct __vma_area *vma = (struct __vma_area *)((void *)access + sizeof(struct access_area) + sizeof(struct __vma_area) * vma_index);
//     return vma->bitmap;
// }

int ca_bitmap_set(unsigned long *bitmap, unsigned long addr, int value){
    int index = addr / 64;
    int offset = addr % 64;
    #ifdef MODULE
    // printk(KERN_INFO "ca_bitmap_set: index is %d&offset is %d\n",index,offset);
    #endif
    if (value)
        bitmap[index] |= (1 << offset);
    else
        bitmap[index] &= ~(1 << offset);
    return 0;
}

int ca_bitmap_get(unsigned long *bitmap, unsigned long addr){
    int index = addr / 64;
    int offset = addr % 64;
    return bitmap[index] & (1 << offset);
}


unsigned long * kernel_get_dirty_bitmap(struct access_area *access, int vma_index){
    struct __vma_area *vma = (struct __vma_area *)((void *)access + sizeof(struct access_area) + sizeof(struct __vma_area) * vma_index);
    return vma->dirty_bitmap;
}


