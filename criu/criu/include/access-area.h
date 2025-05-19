#ifndef __CR__ACCESS_AREA_H__
#define __CR__ACCESS_AREA_H__

#ifdef MODULE
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxz");
MODULE_DESCRIPTION("Collect Access Bit");
MODULE_VERSION("0.01");
#endif

#define ROUND_UP(x, y) (((x) + (y) - 1) / (y) * (y))
#define ROUND_DOWN(x, y) ((x) / (y) * (y))

#define ACCESS_VMA_SIZE 409600

struct __vma_area{
    unsigned long size;
    unsigned long start;
    unsigned long end;
    unsigned long *bitmap;
    unsigned long *dirty_bitmap;
};

struct access_area{
    unsigned long num_vma;
    // struct __vma_area *vml;
    // unsigned long *bitmap;
};

// first page storage the epoch area
struct epoch_area{
    int num_area;
    struct access_area *areas[105];
};

void *get_mem_point(void);
void *reset_mem_point(void);
void *get_kmem_point(void);

int kernel_init_access(struct access_area *access);
unsigned long * kernel_get_bitmap(struct access_area *access, int vma_index);
struct epoch_area * init_epoch_area(void *area);
int update_mem_point(struct epoch_area *area,struct access_area *access);
// int epoch_add_access(struct epoch_area *area);
int access_add_vma(struct access_area *access, struct __vma_area *vma);

int ca_bitmap_set(unsigned long *bitmap, unsigned long addr, int value);
int ca_bitmap_get(unsigned long *bitmap, unsigned long addr);

unsigned long * kernel_get_dirty_bitmap(struct access_area *access, int vma_index);



#endif
