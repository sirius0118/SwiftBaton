#ifndef __CR_RDMA_H__
#define __CR_RDMA_H__

#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "common/shregion.h"

#define PF_IB_PORT 1
#define TRANS_IB_PORT 2
#define TCP_PORT 12345

#define MAX_POLL_CQ_TIMEOUT 2000000 // ms

#define MSG "This is alice, how are you?"
#define RDMAMSGR "RDMA read operation"
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE 4096


#if __BYTE_ORDER == __LITTLE_ENDIAN
    static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
    static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
    static inline uint64_t htonll(uint64_t x) { return x; }
    static inline uint64_t ntohll(uint64_t x) { return x; }
#else
    #error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif


// structure of page fault parameters
struct PF_PageRequest
{
    // if pid == -1 denote all the page has been migrated to destination machine
    uint64_t pid;
    uint64_t addr;
};

struct PF_PageResponse
{
    uint64_t pid;
    uint64_t addr;
    char page[4096];
};

// structure of test parameters
struct config_t {
    const char *dev_name; // IB device name
    char *server_name;    // server hostname
    uint32_t tcp_port;    // server TCP port
    int ib_port;          // local IB port to work with
    int gid_idx;          // GID index to use
};

// structure to exchange data which is needed to connect the QPs
struct cm_con_data_t {
    uint64_t addr;   // buffer address
    uint32_t rkey;   // remote key
    uint32_t qp_num; // QP number
    uint16_t lid;    // LID of the IB port
    uint8_t gid[16]; // GID
} __attribute__((packed));

// structure of system resources
struct resources {
    struct ibv_device_attr device_attr; // device attributes
    struct ibv_port_attr port_attr;     // IB port attributes
    struct cm_con_data_t remote_props;  // values to connect to remote side
    struct ibv_context *ib_ctx;         // device handle
    struct ibv_pd *pd;                  // PD handle
    struct ibv_cq *cq;                  // CQ handle
    struct ibv_qp *qp;                  // QP handle
    struct ibv_mr **mr;                  // MR handle for buf
#ifdef DOCKER
    struct ibv_mr *mr_buf;
#endif
    char *buf;                          // memory buffer pointer, used for
                                        // RDMA send ops
    int sock;                           // TCP socket file descriptor
    struct config_t config;
};


extern struct resources PF_res;
extern struct resources TS_res;
extern struct resources FT_res;

extern int sock_connect(const char *server_name, int port);
extern int sock_sync_data(int sockfd, int xfer_size, char *local_data,
                   char *remote_data);

extern void resources_init(struct resources *res);
extern int resources_create(struct resources *res);
extern int resources_create_ts(struct resources *res);
extern int resources_destroy(struct resources *res);

extern int connect_qp(struct resources *res, int pagesk, int server);

extern int modify_qp_to_init(struct resources *res, struct ibv_qp *qp);
extern int modify_qp_to_rtr(struct resources *res, struct ibv_qp *qp, uint32_t remote_qpn,
                            uint16_t dlid, uint8_t *dgid);
extern int modify_qp_to_rts(struct resources *res, struct ibv_qp *qp);

extern int poll_completion(struct resources *res);
extern int post_send(struct resources *res, int opcode, int mr_index, uintptr_t addr, long len);
extern int post_receive(struct resources *res, int mr_index, uintptr_t addr, long len);

extern int send_page_request(struct resources *res, struct PF_PageRequest *request);
extern int receive_page_request(struct resources *res, struct mul_shregion_t *shregion);

extern int send_page_response(struct resources *res, struct mul_shregion_t *shregion, uint64_t pid) ;

extern int receive_page_response(struct resources *res, struct mul_shregion_t *shregion);

extern int send_ack(struct resources *res);
extern int wait_ack(struct resources *res);

extern int rdma_write(struct resources *res, uint64_t remote_off, uint64_t local_addr, int length, int mr_index);
extern int rdma_read(struct resources *res, uint64_t remote_off, uint64_t local_addr, int length);
#endif




// int example() 
// {
//     struct resources res;
//     char temp_char;

//     // init all the resources, so cleanup will be easy
//     resources_init(&res);

//     // create resources before using them
//     resources_create(&res);

//     // connect the QPs
//     connect_qp(&res);

//     // let server post the sr
//     if (!config.server_name)
//         post_send(&res, IBV_WR_SEND);


//     // in both sides we expect to get a completion
//     // @server: there's a send completion
//     // @client: there's a recv completion
//     poll_completion(&res);

//     // after polling the completion we have the message in the client buffer too
//     if (config.server_name) {
//         INFO("Message is: %s\n", res.buf);
//     } else {
//         // setup server buffer with read message
//         strcpy(res.buf, RDMAMSGR);
//     }

//     // sync so we are sure server side has data ready before client tries to
//     // read it
//     sock_sync_data(res.sock, 1, "R",
//                    &temp_char); // just send a dummy char back and forth

//     // Now the client performs an RDMA read and then write on server. Note that
//     // the server has no idea these events have occured.

//     if (config.server_name) {
//         // first we read contents of server's buffer
//         post_send(&res, IBV_WR_RDMA_READ);
//         poll_completion(&res);

//         INFO("Contents of server's buffer: %s\n", res.buf);

//         // now we replace what's in the server's buffer
//         strcpy(res.buf, RDMAMSGW);
//         INFO("Now replacing it with: %s\n", res.buf);

//         post_send(&res, IBV_WR_RDMA_WRITE);
//         poll_completion(&res);
//     }

//     // sync so server will know that client is done mucking with its memory
//     sock_sync_data(res.sock, 1, "W", &temp_char);
//     if (!config.server_name)
//         INFO("Contents of server buffer: %s\n", res.buf);

//     // whatever
//     resources_destroy(&res);

//     return 0;
// }