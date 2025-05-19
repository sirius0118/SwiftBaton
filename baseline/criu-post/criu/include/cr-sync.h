#ifndef __CR_SYNC_H__
#define __CR_SYNC_H__
#include <sys/socket.h>

enum STATE{
    READY = 0,

    DUMP_NAMESPACE_DONE,
    START_PROCESS_DUMP,
    END_PROCESS_DUMP,
    END_PAGE_CLIENT,

    END_PAGE_PRTRANSFER,
    END_PAGE_DIRTY
};

extern enum STATE now_state;

extern int sync_fd;

extern int syncServerInit(char *ip, int port);
extern int syncClientInit(char *ip, int port);
extern int syncServerInit_unix(char *socket_path);
extern int syncClientInit_unix(char *socket_path);

extern int sync_wait(int sockfd);

// extern int get_peer_state(int sockfd);
extern int wait_state(int sockfd, enum STATE state);
extern int notify_peer(int sockfd, enum STATE state);
extern int update_state(int sockfd, enum STATE state);

#endif