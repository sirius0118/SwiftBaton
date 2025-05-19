
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

#include "uffd.h"
#include "rst-malloc.h"
#include "restorer.h"
#include "pstree.h"
#include "common/scm.h"
#include "fdstore.h"
#include "util.h"

#include "mul-uffd.h"

extern int item_num;
extern uint64_t pidset[MAX_PROCESS];    

volatile struct pid_uffd_region_set *PidUffdSet;

void * shmmap(uint64_t size){
    return mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
}

static mutex_t uffd_mutex;

void InitPidUffdSet()
{
    int i = 0;
    pr_warn("run to here\n");
    root_item->pid->real = -1;
    pr_warn("run to here\n");
    root_item->pid->ns[0].virt = 1;
    pr_warn("run to here\n");
    PidUffdSet = (struct pid_uffd_region_set *)shmmap(sizeof(struct pid_uffd_region_set) * item_num);
    pr_warn("run to here\n");
    pr_warn("总item数量:%d, real:%d, virt:%d\n", item_num, root_item->pid->real, root_item->pid->ns[0].virt);
    for(i = 0; i < item_num; i++)
    {
        pr_warn("run to here pid:%ld\n", pidset[i]);
        PidUffdSet[i].pid = pidset[i];
        pr_warn("run to here\n");
        // PidUffdSet[i].uffd_region = NULL;
        pr_warn("run to here\n");
        PidUffdSet[i].nr_uffd_region = 0;
    }
    pr_warn("run to here\n");
}


void PidUffdSet_taskargs(void *args, int pid)
{
    int i, j, index = -1;
    struct uffd_region *uffd_region;
    struct vma *vma;
    struct task_restore_args *ta = (struct task_restore_args *)args;

    for( i = 0; i < item_num; i++ ){
        if (PidUffdSet[i].pid == pid){
            index = i;
            break;
        }
    }

    ta->uffd_set.pid = PidUffdSet[index].pid;
    ta->uffd_set.nr_uffd_region = PidUffdSet[index].nr_uffd_region;

    // ta->uffd_set.uffd_region = (struct uffd_region *)rst_mem_align_cpos(RM_PRIVATE);
    // uffd_region = rst_mem_alloc(sizeof(struct uffd_region) * PidUffdSet[index].nr_uffd_region, RM_PRIVATE);
    uffd_region = ta->uffd_set.uffd_region;
    for ( i = 0; i < PidUffdSet[index].nr_uffd_region; i++ ){  
        uffd_region[i].uffd = PidUffdSet[index].uffd_region[i].uffd;
        uffd_region[i].start = PidUffdSet[index].uffd_region[i].start;
        uffd_region[i].end = PidUffdSet[index].uffd_region[i].end;
        uffd_region[i].nr_vma = PidUffdSet[index].uffd_region[i].nr_vma;
        // uffd_region[i].vma = (struct vma *)rst_mem_align_cpos(RM_PRIVATE);
        vma = uffd_region[i].vma;
        for ( j = 0; j < PidUffdSet[index].uffd_region[i].nr_vma; j++ ){
            vma[j].start = PidUffdSet[index].uffd_region[i].vma[j].start;
            vma[j].end = PidUffdSet[index].uffd_region[i].vma[j].end;
        }
    }
}


// send uffd to page client, and send the region info to page client
void PidUffdSet_sendfd(int sockfd, int pid)
{
    int i, nr_uffd = -1, index = -1, ret;
    int *uffds = NULL;

    for ( i = 0; i < item_num; i++ ){
        if (PidUffdSet[i].pid == pid ){
            index = i;
            nr_uffd = PidUffdSet[i].nr_uffd_region;
            uffds = (int *)malloc(sizeof(int) * nr_uffd);
            break;
        }
    }

    for ( i = 0; i < nr_uffd; i++ ){
        uffds[i] = PidUffdSet[index].uffd_region[i].uffd;
    }
    ret = send(sockfd, &pid, sizeof(pid), 0);
    pr_debug("send pid:%d, nr_uffd:%d, uffd:%d\n", pid, nr_uffd, uffds[0]);
    ret = send(sockfd, &nr_uffd, sizeof(nr_uffd), 0);
    ret = send_fds(sockfd, NULL, 0, uffds, nr_uffd, NULL, 0);
    if (ret < 0){
        pr_err("send uffd to page client failed\n");
        return;
    }
}

void update_PidUffdSet(int pid, int nr_uffd, int *uffds){
    int i, index = -1;
    for(i = 0; i < item_num; i++){
        if (PidUffdSet[i].pid == pid){
            index = i;
            break;
        }
    }
    pr_warn("index为:%d, nr_uffd:%d, uffdset:%p, uffd:%d\n", index, nr_uffd, uffds, uffds[0]);
    for(i = 0; i < nr_uffd; i++){
        PidUffdSet[index].uffd_region[i].uffd = uffds[i];
        pr_debug("%d uffd:%d\n", i, PidUffdSet[index].uffd_region[i].uffd);
    }
    // pr_warn("update uffd done! uffd[0]:%d \n", PidUffdSet[index].uffd_region[0].uffd);
}

void PidUffdSet_recvfd(int sockfd, int *pid, int **uffds, int *nr_uffd)
{
    int ret = -1;
    int i;
    // int nr_uffd;
    // get the number of uffd
    mutex_init(&uffd_mutex);
    ret = recv(sockfd, pid, sizeof(int), 0);
    ret = recv(sockfd, nr_uffd, sizeof(int), 0);
    *uffds = (int *)malloc(*nr_uffd * 4);
    ret = recv_fds(sockfd, *uffds, *nr_uffd, NULL, 0);
    pr_warn("recv pid:%d, nr_uffd:%d, uffd:%d\n", *pid, *nr_uffd, *uffds[0]);
    if(ret < 0){
        pr_err("recv uffd from page client failed\n");
        return;
    }
}

// send the uffd region info to page client
void PidUffdSet_send_region(int sockfd, int pid)
{
    int i, j, ret, index = -1;
    pr_warn("enter PidUffdSet_send_region \n");
    pr_warn("pid:%d\n",pid);
    for ( i = 0; i < item_num; i++ ){
        if (PidUffdSet[i].pid == pid ){
            pr_warn("success! PidUffdSet[i].pid:%ld\n",PidUffdSet[i].pid);
            index = i;
            break;
        }
    }
    pr_warn("prepare to send index:%d fd:%d pid:%ld nr_region:%d\n", index, sockfd, PidUffdSet[index].pid, PidUffdSet[index].nr_uffd_region);
    ret = send(sockfd, (void *)(PidUffdSet + index), sizeof(struct pid_uffd_region_set), 0);
    // ret = send(sockfd, PidUffdSet[index].uffd_region, sizeof(struct uffd_region) * PidUffdSet[index].nr_uffd_region, 0);
    // for ( i = 0; i < PidUffdSet[index].nr_uffd_region; i++ ){
    //     ret = send(sockfd, PidUffdSet[index].uffd_region[i].vma, sizeof(struct vma) * PidUffdSet[index].uffd_region[i].nr_vma, 0);
    // }
    pr_warn("send over\n");
    if (ret < 0){
        pr_err("send uffd region to page client failed\n");
        return;
    }  
}

void PidUffdSet_recv_region(int sockfd, int pid, int *uffdset)
{
    int i, j, ret, index = -1;
    struct pid_uffd_region_set *temp_pid_uffd_region_set;
    struct uffd_region *temp_uffd_region;
    struct vma *temp_vma;

    for ( i = 0; i < item_num; i++ ){
        if (PidUffdSet[i].pid == pid ){
            index = i;
            break;
        }
    }
    ret = recv(sockfd, (void *)(PidUffdSet + i), sizeof(struct pid_uffd_region_set), 0);
    // temp_pid_uffd_region_set = (struct pid_uffd_region_set *)malloc(sizeof(struct pid_uffd_region_set));
    // ret = recv(sockfd, temp_pid_uffd_region_set, sizeof(struct pid_uffd_region_set), 0);
    // PidUffdSet[index].nr_uffd_region = temp_pid_uffd_region_set->nr_uffd_region;
    // // PidUffdSet[index].uffd_region = (struct uffd_region *)malloc(sizeof(struct uffd_region) * PidUffdSet[index].nr_uffd_region);
    // ret = recv(sockfd, PidUffdSet[index].uffd_region, sizeof(struct uffd_region) * PidUffdSet[index].nr_uffd_region, 0);
    // for ( i = 0; i < PidUffdSet[index].nr_uffd_region; i++ ){
    //     temp_uffd_region = (struct uffd_region *)malloc(sizeof(struct uffd_region));
    //     ret = recv(sockfd, temp_uffd_region, sizeof(struct uffd_region), 0);
    //     PidUffdSet[index].uffd_region[i].uffd = uffdset[i];
    //     PidUffdSet[index].uffd_region[i].nr_vma = temp_uffd_region->nr_vma;
    //     // PidUffdSet[index].uffd_region[i].vma = (struct vma *)malloc(sizeof(struct vma) * PidUffdSet[index].uffd_region[i].nr_vma);
    //     ret = recv(sockfd, PidUffdSet[index].uffd_region[i].vma, sizeof(struct vma) * PidUffdSet[index].uffd_region[i].nr_vma, 0);
    // }
    if (ret < 0){
        pr_err("recv uffd region from page client failed\n");
        return;
    }
}



void PidUffdSet_fullfill(int pid, int sockfd)
{
    int i;
    unsigned long memsize;
    struct pstree_item *item;

    // fullfill the uffd region for each pid
    for (i = 0; i < item_num; i++)
    {
        if(pid != -1 && PidUffdSet[i].pid != pid)
            continue;
        
        memsize = 0;
        for_each_pstree_item(item)
        {
            struct vma_area *vma;
	        struct vm_area_list *vmas = &rsti(item)->vmas;
            unsigned long feature[20];
            int uffd = 0;
            int first = 1;

            memset(feature, 0, sizeof(feature));
            // PidUffdSet[i].uffd_region = (struct uffd_region *)shmmap(sizeof(struct uffd_region) * nr_region);
            list_for_each_entry(vma, &vmas->h, list)
            {
                memsize += vma->e->end - vma->e->start;
                if (memsize > REGION_SIZE || first == 1){
                    memsize = vma->e->end - vma->e->start;
                    first = 0;
                    pr_warn("create uffd here\n");
                    PidUffdSet[i].nr_uffd_region++;
                    pr_warn("run to here\n");
                    uffd = uffd_open(O_CLOEXEC | O_NONBLOCK, &feature[PidUffdSet[i].nr_uffd_region - 1], NULL);
                    pr_warn("run to here\n");
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].uffd = uffd;
                    pr_warn("create uffd done:%d\n", uffd);
                    // PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].vma = (struct vma *)shmmap(sizeof(struct vma) * nr_vma[PidUffdSet[i].nr_uffd_region - 1]);
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].start = vma->e->start;
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].end = vma->e->end;
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].nr_vma = 1;
                    pr_warn("run to here\n");
                    // PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].vma = (struct vma *)malloc(sizeof(struct vma));
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].vma[0].start = vma->e->start;
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].vma[0].end = vma->e->end;
                    pr_warn("run to here\n");
                }else{
                    pr_warn("run to here nr_vma:%d\n", PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].nr_vma);
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].nr_vma++;
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].vma[PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].nr_vma - 1].start = vma->e->start;
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].vma[PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].nr_vma - 1].end = vma->e->end;
                    PidUffdSet[i].uffd_region[PidUffdSet[i].nr_uffd_region - 1].end = vma->e->end;
                }
            }
        }
        break;
    }
}


__attribute__((optimize("O0"))) int ioctl_mul(volatile struct uffdio_copy *data, int pid)
{
    int i, index = -1,err,nr_region;
    volatile struct uffdio_copy uffdio_copy;
    // struct pid_uffd_region_set *mul_uffdset=NULL;
    // mutex_lock(&uffd_mutex);
    for(i = 0; i < item_num; i++){
        if (PidUffdSet[i].pid == pid){
            index = i;
            break;
        }
    }
    nr_region=PidUffdSet[index].nr_uffd_region;
    
    for(i = 0; i < nr_region; i++){
        if (data->dst >= PidUffdSet[index].uffd_region[i].start && data->dst + uffdio_copy.len  < PidUffdSet[index].uffd_region[i].end){
            uffdio_copy.src = data->src;
            uffdio_copy.dst = data->dst;
            uffdio_copy.len = data->len;
            uffdio_copy.mode = data->mode;
            
            if (ioctl(PidUffdSet[index].uffd_region[i].uffd, UFFDIO_COPY, &uffdio_copy)<0){
                err=errno;
                pr_err("error:code:%d uffd:%d, src:%llx, dst:%llx, len:%lld\n",err, PidUffdSet[index].uffd_region[i].uffd, uffdio_copy.src, uffdio_copy.dst, uffdio_copy.len);
                // mutex_unlock(&uffd_mutex);
                return err;
            }
           
            
        }
    }
    // mutex_unlock(&uffd_mutex);
    
    return 0;
}









