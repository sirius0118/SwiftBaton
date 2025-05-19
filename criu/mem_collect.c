#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>


#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define PAGEMAP_LENGTH 8
// ########### Just last record ##########
#define MAX_LAST_RECORD_SIZE (16 * 1024 *1024)
#define MAX_TRANSFER_SIZE (1 << 22)    // 4MB = 1024 pages
#define PAGE_SIZE 4096
#define MAX_PID 1024

int init = 0;
int time_interval = 60;
pthread_mutex_t mutex;

struct last_record{
    uint64_t pid;
    uint64_t addr;
};
struct share_LR
{
    int stop;
    int can_be_write;
    int nr_dirty;
    int max_items;
    // struct last_record *LR;
};
#define get_LR(p) (struct last_record *)(p + sizeof(struct share_LR))

struct share_LR *share_LR_init(void *mem, int size)
{
    struct share_LR *SLR = (struct share_LR *)mem;
    SLR->stop = 0;
    SLR->can_be_write = 1;
    SLR->nr_dirty = 0;
    SLR->max_items = size / sizeof(struct last_record) - 2;
    // SLR->LR = (struct last_record*)(SLR + sizeof(struct share_LR));

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

void CleanSoftdirty(uint64_t pid)
{
    int fd;
    char clear_refs_path[64];
    const char *clear_value = "4";

    snprintf(clear_refs_path, sizeof(clear_refs_path), "/proc/%ld/clear_refs", pid);

    fd = open(clear_refs_path, O_WRONLY);
    if (fd == -1) {
        perror("Error opening clear_refs file");
        exit(EXIT_FAILURE);
    }

    if (write(fd, clear_value, 1) == -1) {
        perror("Error writing to clear_refs file");
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
                    break;
                }
                if (read(fd, &pagemap_value, PAGEMAP_LENGTH) != PAGEMAP_LENGTH){
                    close(fd);
                    break;
                }
                softdirty = (pagemap_value >> 55) & 1;
                
                if (softdirty){
                    int ret;

                    pthread_mutex_lock(&mutex);
                    ret = SLR_add(SLR, pid, addr);
                    pthread_mutex_unlock(&mutex);
                    if (ret){                    
                        close(fd);
                        break;
                    }
                }
            }
        }
    }
}

static inline void * sharemem_open(char *path, int size)
{
    int dirfd, shm_fd;
    void *shm_ptr;
    dirfd = open("/dev/shm", O_RDONLY | O_DIRECTORY);
    if (dirfd == -1) {
        perror("open /dev/shm");
        exit(1);
    }

    
    shm_fd = syscall(SYS_openat, dirfd, path, O_CREAT | O_RDWR, 0777);
    close(dirfd);
    if (shm_fd == -1) {
        perror("syscall openat");
        exit(1);
    }

    
    if (ftruncate(shm_fd, size) == -1) {
        perror("syscall ftruncate");
        close(shm_fd);
        exit(1);
    }

    
    shm_ptr = mmap(0, size, , MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        close(shm_fd);
        exit(1);
    }

    return shm_ptr;
}

void get_child_pids(pid_t pid, pid_t *pidset, int *num_children) {
    char path[100];
    FILE *fp;
    char buffer[4096];

    *num_children = 0;
    // Construct the path to the children file
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);

    // Open the children file
    if (!(fp = fopen(path, "r"))) {
        perror("fopen");
        return;
    }

    // Read the contents of the file
    if (fgets(buffer, sizeof(buffer), fp)) {
        char *token = strtok(buffer, " ");
        while (token != NULL) {
            pidset[*num_children] = atoi(token);
            (*num_children)++;
            token = strtok(NULL, " ");
        }
    }

    // Close the file
    fclose(fp);
}

int get_all_pid(pid_t pid, pid_t *pidall, pid_t *len) {
    pid_t pidset[100];
    int num_children;

    // pid_t pidall[1000];
    int now = 0;

    for(int i=0;i<1000;i++)
        pidall[i] = 0;

    pidall[now] = pid;
    *len = 1;

    while (pidall[now] != 0)
    {
        get_child_pids(pidall[now], pidset, &num_children);
        for (int i = 0; i < num_children; i++) {
            pidall[*len + i] = pidset[i];
        }
        *len += num_children;
        now++;
    } 
    // for (int i = 0; i < *len; i++) {
    //     printf("Child PID: %d\n", pidall[i]);
    // }
    return 0;
}

struct thread_arg
{
    pid_t pid;
    struct share_LR *SLR;
};


void * collect(void *arg){
    struct thread_arg * tharg;
    tharg = (struct thread_arg *)arg;

    
    while (1) {
        if(tharg->SLR->stop == 1)
            break;
        if(tharg->SLR->can_be_write == 0){
            sleep(time_interval);
            continue;
        }

        CollectSoftdirty(tharg->SLR, tharg->pid);
        CleanSoftdirty(tharg->pid);
        sleep(time_interval);
        pthread_mutex_lock(&mutex);
        if (init == 0){
            tharg->SLR = share_LR_init(tharg->SLR, MAX_LAST_RECORD_SIZE / 16 - 2);
            init = 1;
        }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}


int main(int argc, char *argv[])
{
    int pid;
    int time;
    char path[50];

    void *mem;
    struct share_LR *SLR;
    pid_t pidall[MAX_PID];
    int len;
    pthread_t th_collect[MAX_PID];

    // Initialize the mutex
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        perror("pthread_mutex_init");
        exit(EXIT_FAILURE);
    }

    if (argc < 2) {
        printf("Usage: %s <pid> <interval>\n", argv[0]);
        return -1;
    }else if(argc == 2){
        pid = atoi(argv[1]);
    }else if(argc == 3){
        pid = atoi(argv[1]);
        time_interval = atoi(argv[2]);
    }else{
        printf("Usage: %s <pid> <interval>\n", argv[0]);
        return -1;
    }

    
    sprintf(path, "criu-%d", pid);
    mem = sharemem_open(path, MAX_LAST_RECORD_SIZE);

    
    SLR = share_LR_init(mem, MAX_LAST_RECORD_SIZE / 16 - 2);

    
    get_all_pid(pid, pidall, &len);

    
    for (int i = 0; i < len; i++) {
        struct thread_arg *tharg;
        tharg = (struct thread_arg *)malloc(sizeof(struct thread_arg));
        tharg->pid = pidall[i];
        tharg->SLR = SLR;
        pthread_create(&th_collect[i], NULL, collect, (void *)tharg);
    }

    
    for (int i = 0; i < len; i++) {
        pthread_join(th_collect[i], NULL);
    }

    return 0;
}