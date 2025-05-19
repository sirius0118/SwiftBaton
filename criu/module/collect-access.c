
#include <linux/module.h>
#include <linux/mm_types.h>
#include <asm/tlbflush.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>

#include <linux/spinlock.h>
#include <linux/mman.h> // Add this line to include the definitions for PROT_READ and PROT_WRITE
#include <linux/pgtable.h>
#include <linux/sched/task.h>
#include <asm/pgtable.h>

#include <asm/mmu_context.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include <linux/ktime.h>
#include <linux/vmalloc.h>
#include <linux/timekeeping.h>




#include "access-area.h"


// #include <linux/sched.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxz");
MODULE_DESCRIPTION("Collect Access Bit");
MODULE_VERSION("0.01");

static DEFINE_SPINLOCK(modify_pte_lock);

#define DEVICE_NAME "collect_access"
#define IOCTL_MODIFY_PTE _IOW('m', 1, struct ioctl_data)
#define IOCTL_ALLOC_MEMORY _IOW('m', 2, int)
#define IOCTL_FREE_MEMORY _IOW('m', 3, int)
#define SHARED_MEM_SIZE (ACCESS_MEM_SIZE*100)
#define ACCESS_MEM_SIZE (20 * 1024 * 1024)
#define __PMD_SIZE 4096 * 512


// void (*flush_tlb_page_func)(struct vm_area_struct *vma, unsigned long uaddr);


static struct class *dev_class;
struct access_area *access_area;
void *mem_begin;

struct ioctl_data
{
    int pid;
    unsigned long addr;
    // char *addr;
    // char *path;
};

static struct cdev my_cdev;
static dev_t dev_num;


static inline void flush_tlb_single_page(unsigned long addr)
{
    asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
}



static int collect_access(struct ioctl_data *data)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    // spinlock_t *ptl;
    // int accessed;
    struct task_struct *task;
    struct pid *pid;
    struct mm_struct *mm;
    unsigned long flags;
    struct vm_area_struct *vma;
    struct __vma_area vma_bitmap;
    bool is_changed=0;

    //TEST
    int access_num=0,dirty_num=0;
    ktime_t start_time, end_time, elapsed_time_ns;
    int isprint=0,isprint2=5;

    int vma_i;
    // pmd_i, pte_i;

    // flush_tlb_page_func = (void *) kallsyms_lookup_name("flush_tlb_page");
    // if(!flush_tlb_page_func) {
    //     pr_alert("Could not retrieve flush_tlb_page function\n");
    //     return -ENXIO;
    // }

    // ----------------- step1: collect vma -----------------
    // printk(KERN_INFO "collect_access: step1\n");
    start_time = ktime_get();
    pid = find_get_pid(data->pid);
    if (!pid)
        return -EINVAL;
    // printk(KERN_INFO "collect_access: get pid success\n");
    task = pid_task(pid, PIDTYPE_PID);
    if (!task)
        return -EINVAL;
    // printk(KERN_INFO "collect_access: get task success\n");
    mm = task->mm;
    if (!mm)
        return -EINVAL;
    // printk(KERN_INFO "collect_access: get mm success\n");
    

    
    memset(mem_begin, 0, ACCESS_MEM_SIZE);
    kernel_init_access(access_area);
    end_time = ktime_get();
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    printk(KERN_INFO "collect_access: init(including memset) took %lld ns\n", elapsed_time_ns);
    // printk(KERN_INFO "collect_access: epoch add success\n");
    start_time = ktime_get();
    down_read(&mm->mmap_lock);
    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        if(!(vma->vm_flags & VM_READ)){
            continue;
        }
        vma_bitmap.start = vma->vm_start;
        vma_bitmap.end = vma->vm_end;
        vma_bitmap.size = vma->vm_end - vma->vm_start;
        vma_bitmap.bitmap = NULL;
        vma_bitmap.dirty_bitmap = NULL;
        printk(KERN_INFO "collect_access: vma get loop start:%lx end:%lx size:%ld\n", vma_bitmap.start, vma_bitmap.end, vma_bitmap.size);
        access_add_vma(access_area, &vma_bitmap);
    }
    up_read(&mm->mmap_lock);
    end_time = ktime_get();
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    printk(KERN_INFO "collect_access: add vma took %lld ns\n", elapsed_time_ns);

    // ----------------- step2: collect access -----------------
    // printk(KERN_INFO "collect_access: step2\n");

    // for (vma_i = 0; vma_i < access_area->num_vma; vma_i++)
    // {
    //     struct __vma_area *vma = (void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * vma_i;
    //     unsigned long start = vma->start;
    //     unsigned long end = vma->end;
    //     unsigned long size = vma->size;
    //     printk(KERN_INFO "collect_access: vma process loop start:%ld end:%ld size:%ld\n", start, end, size);
    // }
    
    for (vma_i = 0; vma_i < access_area->num_vma; vma_i++)
    {
        // printk(KERN_INFO "collect_access: vma process loop\n");
        // int pte_num;
        unsigned long *bitmap = kernel_get_bitmap(access_area, vma_i);
        unsigned long *dirty_bitmap = kernel_get_dirty_bitmap(access_area, vma_i);
        // printk(KERN_INFO "collect_access: get bitmap in loop\n");
        unsigned long index = 0;
        struct __vma_area *vma = (void *)access_area + sizeof(struct access_area) + sizeof(struct __vma_area) * vma_i;
        unsigned long start = vma->start;
        unsigned long end = vma->end;
        unsigned long size = vma->size;
        unsigned long addr = start;
        printk(KERN_INFO "start collect_access vma %lx %lx %ld\n",start,end,size);
        for (addr = start; addr < end; addr += PAGE_SIZE)
        {
            is_changed=0;
            if(isprint){
                start_time = ktime_get();
            }
            pgd = pgd_offset(mm, addr);
            if (pgd_none(*pgd) || pgd_bad(*pgd))
            {
                printk(KERN_ERR "collect_access: pgd error\n");
                continue;
            }

            p4d = p4d_offset(pgd, addr);
            if (p4d_none(*p4d) || p4d_bad(*p4d))
            {
                printk(KERN_ERR "collect_access: p4d error, %lx\n", addr);
                continue;
            }

            pud = pud_offset(p4d, addr);
            if (pud_none(*pud) || pud_bad(*pud))
            {
                // printk(KERN_ERR "collect_access: pud error\n");
                continue;
            }

            pmd = pmd_offset(pud, addr);
            if (pmd_none(*pmd) || pmd_bad(*pmd))
            {
                // printk(KERN_ERR "collect_access: pmd error\n");
                continue;
            }
            pte = pte_offset_map(pmd, addr);
            if (!pte)
            {
                // printk(KERN_ERR "collect_access: pte error\n");
                continue;
            }
            if(isprint){
                end_time = ktime_get();
                elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
                printk(KERN_INFO "collect_access: get pte took %lld ns\n", elapsed_time_ns);
                start_time = ktime_get();
            }
            // printk(KERN_INFO "pte get: %lx\n",addr);
           
            spin_lock_irqsave(&modify_pte_lock, flags); 
            if (pte_flags(*pte) & _PAGE_ACCESSED)
            {
                // printk(KERN_INFO "RWinfo: addr:%lx access\n",addr);
                access_num++;
                is_changed=1;
                // ret = ca_bitmap_set(bitmap, index, 1);
                set_bit((addr-start)/PAGE_SIZE, bitmap);
                *pte=pte_clear_flags(*pte, _PAGE_ACCESSED);
            }

            if (pte_flags(*pte) & _PAGE_DIRTY)
            {
                // printk(KERN_INFO "RWinfo: addr:%lx dirty\n",addr);
                dirty_num++;
                // ret = ca_bitmap_set(dirty_bitmap, index, 1);
                set_bit((addr-start)/PAGE_SIZE, dirty_bitmap);
                is_changed=1;
                *pte=pte_clear_flags(*pte, _PAGE_DIRTY);
            }
            
            
            pte_unmap(pte);
            spin_unlock_irqrestore(&modify_pte_lock, flags);
            if(isprint){
                end_time = ktime_get();
                elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
                printk(KERN_INFO "collect_access: set bitmap took %lld ns\n", elapsed_time_ns);
                start_time = ktime_get();
            }
            if(is_changed)flush_tlb_single_page(addr);
            if(isprint){
                end_time = ktime_get();
                elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
                printk(KERN_INFO "collect_access: flush tlb took %lld ns\n", elapsed_time_ns);
                isprint--;
            }
            // printk(KERN_INFO "collect_access: pte process finish in loop\n");
            index += 1;
        }
    }
    
    
    // __flush_tlb_all();
    
    // printk(KERN_INFO "collect_access: access_num is %d, dirty_num is %d\n", access_num,dirty_num);
    printk(KERN_INFO "collect_access: copy size is %dB\n", (unsigned long)get_kmem_point()-(unsigned long)access_area);
    start_time = ktime_get();
    if (copy_to_user((void __user *)(data->addr), access_area, (unsigned long)get_kmem_point()-(unsigned long)access_area))
    {
        printk(KERN_ERR "collect_access: copy to user error\n");
        vfree(mem_begin); 
        return -EFAULT;
    }
    end_time = ktime_get();
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    printk(KERN_INFO "collect_access: copy to user addr:%lx took %lld ns\n", (unsigned long)data->addr, elapsed_time_ns);

    return 0;
}

// test function
static long copy_to_user_ioctl(char *arg)
{
    char *kernel_data;
    size_t data_size = 1 * 1024 * 1024; 
    ktime_t start_time, end_time, elapsed_time_ns;
    printk(KERN_INFO "cgg: copy_to_user_ioctl has been called\n");
    start_time = ktime_get();
    
    kernel_data = kmalloc(data_size, GFP_KERNEL);
    if (!kernel_data)
    {
        printk(KERN_ERR "cgg: kmalloc error\n");
        return -ENOMEM;
    }
    end_time = ktime_get();
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    printk(KERN_INFO "copy_to_user_ioctl: kmalloc took %lld ns\n", elapsed_time_ns);

    
    start_time = ktime_get();
    memset(kernel_data, 'A', data_size);
    end_time = ktime_get();
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    printk(KERN_INFO "copy_to_user_ioctl: memset took %lld ns\n", elapsed_time_ns);

    
    start_time = ktime_get();
    if (copy_to_user((void __user *)arg, kernel_data, data_size))
    {
        printk(KERN_ERR "cgg: copy to user error\n");
        kfree(kernel_data); 
        return -EFAULT;
    }

    end_time = ktime_get();

    
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));

    printk(KERN_INFO "copy_to_user_ioctl: copy_to_user took %lld ns\n", elapsed_time_ns);

    
    start_time = ktime_get();
    kfree(kernel_data);
    end_time = ktime_get();
    elapsed_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    printk(KERN_INFO "copy_to_user_ioctl: kfree took %lld ns\n", elapsed_time_ns);
    printk(KERN_INFO "cgg: copy to user operation executed successfully\n");
    return 0;
}

// alloc memory
static long alloc_memory(void)
{
    
    unsigned long value;
    mem_begin = vmalloc(ACCESS_MEM_SIZE);
    value = (unsigned long)mem_begin;
    value = ROUND_UP(value, 4096);
    access_area = (struct access_area *)value;
    if (!mem_begin)
    {
        printk(KERN_ERR "alloc_memory: mem_begin is null\n");
        return -ENOMEM;
    }
    if (!access_area)
    {
        printk(KERN_ERR "alloc_memory: kmalloc error\n");
        return -ENOMEM;
    }
    return 0;
}

// free memory
static long free_memory(void)
{
    vfree(mem_begin);
    return 0;
}


static long modify_pte_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ioctl_data data;
    // printk(KERN_INFO "modify_pte_ioctl: enter\n");
    if (cmd == IOCTL_ALLOC_MEMORY)
    {

        alloc_memory();
        return 0;
    }
    else if (cmd == IOCTL_FREE_MEMORY)
    {
        free_memory();
        return 0;
    }
    else if (cmd == IOCTL_MODIFY_PTE)
    {
        if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        {
            printk(KERN_ERR "modify_pte_ioctl: copy error\n");
            return -EFAULT;
        }

        // printk(KERN_INFO "modify_pte_ioctl: check success&prepare call collect_access\n");
        if (!access_area)
        {
            printk(KERN_ERR "modify_pte_ioctl: you need to call IOCTL_ALLOC_MEMORY before IOCTL_MODIFY_PTE\n");
            return -EFAULT;
        }

        return collect_access(&data);
    }
    else
    {
        printk(KERN_ERR "modify_pte_ioctl: invalid cmd\n");
        return -EINVAL;
    }
}


static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = modify_pte_ioctl,
};

static int __init modify_pte_init(void)
{
    int ret;
    printk(KERN_INFO "AccessCollecter init begin\n");

    
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0)
    {
        printk(KERN_ERR "AccessCollecter: Failed to allocate char device region\n");
        return ret;
    }

    
    cdev_init(&my_cdev, &fops);
    my_cdev.owner = THIS_MODULE;

    
    ret = cdev_add(&my_cdev, dev_num, 1);
    if (ret < 0)
    {
        printk(KERN_ERR "AccessCollecter: Failed to add char device\n");
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    
    dev_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(dev_class))
    {
        printk(KERN_ERR "AccessCollecter: Failed to create device class\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_class);
    }

    
    if (device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME) == NULL)
    {
        printk(KERN_ERR "AccessCollecter: Failed to create device\n");
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -ENOMEM;
    }

    printk(KERN_INFO "AccessCollecter: Module loaded, device major=%d, minor=%d\n",
           MAJOR(dev_num), MINOR(dev_num));
    printk(KERN_INFO "AccessCollecter init end\n");

    return 0;
}


static void __exit modify_pte_exit(void)
{
    
    device_destroy(dev_class, dev_num);
    
    class_destroy(dev_class);
    
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "AccessCollecter: Module unloaded\n");
}

module_init(modify_pte_init);
module_exit(modify_pte_exit);
