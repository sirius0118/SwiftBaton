#include "RDMA.h"
#include <stdlib.h>
#include "linux/userfaultfd.h"
#include <errno.h>
#include <sys/ioctl.h>
#include "cr_options.h"
#include "log.h"

#ifdef MUL_UFFD
#include "mul-uffd.h"
#endif

extern struct mul_shregion_t *SharedRegions;
extern struct transfer_t *TransferRegions;

static long recv_id = 100;
static long send_id = 100;
static long wr_count = 0;
#define CHECK(expr)                                                            \
    {                                                                          \
        int rc = (expr);                                                       \
        if (rc != 0) {                                                         \
            perror(strerror(errno));                                           \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    }

const char* qp_state_to_string(enum ibv_qp_state state) {
    switch (state) {
        case IBV_QPS_RESET: return "RESET";
        case IBV_QPS_INIT: return "INIT";
        case IBV_QPS_RTR: return "RTR";
        case IBV_QPS_RTS: return "RTS";
        case IBV_QPS_SQD: return "SQD";
        case IBV_QPS_SQE: return "SQE";
        case IBV_QPS_ERR: return "ERR";
        default: return "UNKNOWN";
    }
}

void query_qp_state(struct ibv_qp *qp) {
    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr;
    int ret;

    ret = ibv_query_qp(qp, &attr, IBV_QP_STATE, &init_attr);
    if (ret) {
        perror("Failed to query QP");
        return;
    }

    pr_info("Current QP state: %s\n", qp_state_to_string(attr.qp_state));
}
// \begin socket operation
//
// For simplicity, the example program uses TCP sockets to exchange control
// information. If a TCP/IP stack/connection is not available, connection
// manager (CM) may be used to pass this information. Use of CM is beyond the
// scope of this example.

// Connect a socket. If servername is specified a client connection will be
// initiated to the indicated server and port. Otherwise listen on the indicated
// port for an incoming connection.
int sock_connect(const char *server_name, int port) {
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;

    // @man getaddrinfo:
    //  struct addrinfo {
    //      int             ai_flags;
    //      int             ai_family;
    //      int             ai_socktype;
    //      int             ai_protocol;
    //      socklen_t       ai_addrlen;
    //      struct sockaddr *ai_addr;
    //      char            *ai_canonname;
    //      struct addrinfo *ai_next;
    //  }
    struct addrinfo hints = {.ai_flags = AI_PASSIVE,
                             .ai_family = AF_INET,
                             .ai_socktype = SOCK_STREAM};

    // resolve DNS address, user sockfd as temp storage
    sprintf(service, "%d", port);
    CHECK(getaddrinfo(server_name, service, &hints, &resolved_addr));

    for (iterator = resolved_addr; iterator != NULL;
         iterator = iterator->ai_next) {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype,
                        iterator->ai_protocol);
        assert(sockfd >= 0);

        if (server_name == NULL) {
            // Server mode: setup listening socket and accept a connection
            listenfd = sockfd;
            CHECK(bind(listenfd, iterator->ai_addr, iterator->ai_addrlen));
            CHECK(listen(listenfd, 1));
            sockfd = accept(listenfd, NULL, 0);
        } else {
            // Client mode: initial connection to remote
            CHECK(connect(sockfd, iterator->ai_addr, iterator->ai_addrlen));
        }
    }

    return sockfd;
}

// Sync data across a socket. The indicated local data will be sent to the
// remote. It will then wait for the remote to send its data back. It is
// assumned that the two sides are in sync and call this function in the proper
// order. Chaos will ensure if they are not. Also note this is a blocking
// function and will wait for the full data to be received from the remote.
int sock_sync_data(int sockfd, int xfer_size, char *local_data,
                   char *remote_data) {
    int read_bytes = 0;
    int write_bytes = 0;

    write_bytes = write(sockfd, local_data, xfer_size);
    // pr_info("write_bytes=%d, xfer_size=%d\n", write_bytes, xfer_size);
    assert(write_bytes == xfer_size);

    read_bytes = read(sockfd, remote_data, xfer_size);
    // pr_info("write_bytes=%d, xfer_size=%d\n", write_bytes, xfer_size);
    assert(read_bytes == xfer_size);

    pr_info("SYNCHRONIZED!\n\n");

    // FIXME: hard code that always returns no error
    return 0;
}
// \end socket operation


// Poll the CQ for a single event. This function will continue to poll the queue
// until MAX_POLL_TIMEOUT ms have passed.
int poll_completion(struct resources *res) {
    struct ibv_wc wc;
    int poll_result;
    unsigned long start_time_ms;
    unsigned long curr_time_ms;
    struct timeval curr_time;

    // poll the completion for a while before giving up of doing it
    gettimeofday(&curr_time, NULL);
    start_time_ms = (curr_time.tv_sec * 1000) + (curr_time.tv_usec / 1000);
    do {
        poll_result = ibv_poll_cq(res->cq, 1, &wc);
        gettimeofday(&curr_time, NULL);
        curr_time_ms = (curr_time.tv_sec * 1000) + (curr_time.tv_usec / 1000);
    } while ((poll_result == 0) &&
             ((curr_time_ms - start_time_ms) < MAX_POLL_CQ_TIMEOUT));

    if (poll_result < 0) {
        // poll CQ failed
        pr_err("poll CQ failed\n");
        goto die;
    } else if (poll_result == 0) {
        pr_err("Completion wasn't found in the CQ after timeout\n");
        goto die;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        pr_err("Got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",
              wc.status, wc.vendor_err);
        goto die;
    }

    // FIXME: ;)
    return 0;
die:
    exit(EXIT_FAILURE);
}

// This function will create and post a send work request.
int post_send(struct resources *res, int opcode, int mr_index, uintptr_t addr, long len) {
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    // prepare the scatter / gather entry
    memset(&sge, 0, sizeof(sge));

    sge.addr = (uintptr_t)addr;
    sge.length = len;
    sge.lkey = res->mr[mr_index]->lkey;

    // prepare the send work request
    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = send_id++;
    
    sr.sg_list = &sge;

    sr.num_sge = 1;
    sr.opcode = opcode;
    sr.send_flags = IBV_SEND_SIGNALED;

    if (opcode != IBV_WR_SEND) {
        
        sr.wr.rdma.remote_addr = res->remote_props.addr;
        sr.wr.rdma.rkey = res->remote_props.rkey;
    }
    
    // there is a receive request in the responder side, so we won't get any
    // into RNR flow
    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));

    // switch (opcode) {
    // case IBV_WR_SEND:
    //     pr_info("Send request was posted\n");
    //     break;
    // case IBV_WR_RDMA_READ:
    //     pr_info("RDMA read request was posted\n");
    //     break;
    // case IBV_WR_RDMA_WRITE:
    //     pr_info("RDMA write request was posted\n");
    //     break;
    // default:
    //     pr_info("Unknown request was posted\n");
    //     break;
    // }

    // FIXME: ;)
    return 0;
}

int post_receive(struct resources *res, int mr_index, uintptr_t addr, long len) {
    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;

    // prepare the scatter / gather entry
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)addr;
    sge.length = len;
    sge.lkey = res->mr[mr_index]->lkey;

    // prepare the receive work request
    memset(&rr, 0, sizeof(rr));

    rr.next = NULL;
    rr.wr_id = recv_id++;
    rr.sg_list = &sge;
    rr.num_sge = 1;

    // post the receive request to the RQ
    // pr_info("Receive request is posting. id:%ld\n", recv_id);
    CHECK(ibv_post_recv(res->qp, &rr, &bad_wr));
    // pr_info("Receive request was posted\n");

    return 0;
}

static int post_receive_connect_cq(struct resources *res, uintptr_t addr, long len) {
    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;

    // prepare the scatter / gather entry
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)addr;
    sge.length = len;
    sge.lkey = res->mr_buf->lkey;

    // prepare the receive work request
    memset(&rr, 0, sizeof(rr));

    rr.next = NULL;
    rr.wr_id = recv_id++;
    rr.sg_list = &sge;
    rr.num_sge = 1;

    // post the receive request to the RQ
    // pr_info("Receive request is posting. id:%ld\n", recv_id);
    CHECK(ibv_post_recv(res->qp, &rr, &bad_wr));
    // pr_info("Receive request was posted\n");

    return 0;
}


// Res is initialized to default values
void resources_init(struct resources *res) {
    memset(res, 0, sizeof(*res));
    res->sock = -1;
}

int resources_create(struct resources *res) {
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;

    size_t size;
    int i;
    // int mr_flags = 0;
    int cq_size = 0;
    int num_devices;

    // \begin acquire a specific device
    // get device names in the system
    dev_list = ibv_get_device_list(&num_devices);
    assert(dev_list != NULL);

    if (num_devices == 0) {
        pr_err("Found %d device(s)\n", num_devices);
        goto die;
    }
    pr_warn("dev_name为：%s\n", res->config.dev_name);
    // search for the specific device we want to work with
    
    for (i = 0; i < num_devices; i++) {
        if (!res->config.dev_name) {
            res->config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
            pr_info("Device not specified, using first one found: %s\n",
                 res->config.dev_name);
        }

        if (strcmp(ibv_get_device_name(dev_list[i]), res->config.dev_name) == 0) {
            ib_dev = dev_list[i];
            break;
        }
    }

    // device wasn't found in the host
    if (!ib_dev) {
        pr_err("IB device %s wasn't found\n", res->config.dev_name);
        goto die;
    }

    // get device handle
    res->ib_ctx = ibv_open_device(ib_dev);
    assert(res->ib_ctx != NULL);
    // \end acquire a specific device

    // query port properties
    CHECK(ibv_query_port(res->ib_ctx, res->config.ib_port, &res->port_attr));

    
    res->pd = ibv_alloc_pd(res->ib_ctx);
    assert(res->pd != NULL);

    // a CQ with one entry
    cq_size = 1;
    res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
    assert(res->cq != NULL);

    // // a buffer to hold the data
    // size = MSG_SIZE;
    // res->buf = (char *)calloc(1, size);
    // assert(res->buf != NULL);

    // // only in the server side put the message in the memory buffer
    // if (!res->config.server_name) {
    //     strcpy(res->buf, MSG);
    // }

    
    // register the memory buffer
    // mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
            //    IBV_ACCESS_REMOTE_WRITE;

    // res->mr = (struct ibv_mr **)calloc(item_num + 1, sizeof(struct ibv_mr *));
    
    // if(isPageServer){
    //     for ( int i = 0; i < item_num; i++ ){
    //         res->mr[i] = ibv_reg_mr(res->pd, SharedRegions->shregions[i], sizeof(struct shregion_t), mr_flags);
    //     }
    // }
    
    // res->mr[item_num] = ibv_reg_mr(res->pd, res->buf, 4096 * 2, mr_flags);

    // assert(res->mr[item_num] != NULL);

    // \begin create the QP
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 0;
    qp_init_attr.send_cq = res->cq;
    qp_init_attr.recv_cq = res->cq;
    qp_init_attr.cap.max_send_wr = 100;
    qp_init_attr.cap.max_recv_wr = 100;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    res->qp = ibv_create_qp(res->pd, &qp_init_attr);
    assert(res->qp != NULL);

    return 0;
die:
    exit(EXIT_FAILURE);
}

int resources_create_ts(struct resources *res) {
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;

    int i;
    // int mr_flags = 0;
    int cq_size = 0;
    int num_devices;

    // \begin acquire a specific device
    // get device names in the system
    dev_list = ibv_get_device_list(&num_devices);
    assert(dev_list != NULL);

    if (num_devices == 0) {
        pr_err("Found %d device(s)\n", num_devices);
        goto die;
    }

    // search for the specific device we want to work with
    
    for (i = 0; i < num_devices; i++) {
        if (!res->config.dev_name) {
            res->config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
            pr_info("Device not specified, using first one found: %s\n",
                 res->config.dev_name);
        }

        if (strcmp(ibv_get_device_name(dev_list[i]), res->config.dev_name) == 0) {
            ib_dev = dev_list[i];
            break;
        }
    }

    // device wasn't found in the host
    if (!ib_dev) {
        pr_err("IB device %s wasn't found\n", res->config.dev_name);
        goto die;
    }

    // get device handle
    res->ib_ctx = ibv_open_device(ib_dev);
    assert(res->ib_ctx != NULL);
    // \end acquire a specific device

    // query port properties
    CHECK(ibv_query_port(res->ib_ctx, res->config.ib_port, &res->port_attr));

    
    res->pd = ibv_alloc_pd(res->ib_ctx);
    assert(res->pd != NULL);

    // a CQ with one entry
    cq_size = 1;
    res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
    assert(res->cq != NULL);

    // res->buf = buf;
    // assert(res->buf != NULL);

    
    // register the memory buffer
    // mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
    //            IBV_ACCESS_REMOTE_WRITE;

    res->mr = (struct ibv_mr **)calloc(item_num + 1, sizeof(struct ibv_mr *));
    

    // res->mr[0] = ibv_reg_mr(res->pd, res->buf, TRANSFER_REGION_SIZE, mr_flags);

    // assert(res->mr[0] != NULL);

    // \begin create the QP
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = res->cq;
    qp_init_attr.recv_cq = res->cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    res->qp = ibv_create_qp(res->pd, &qp_init_attr);
    assert(res->qp != NULL);

    return 0;
die:
    exit(EXIT_FAILURE);
}

// Transition a QP from the RESET to INIT state
int modify_qp_to_init(struct resources *res, struct ibv_qp *qp) {
    struct ibv_qp_attr attr;
    int flags;

    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = res->config.ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
                           IBV_ACCESS_REMOTE_WRITE;

    flags =
        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    CHECK(ibv_modify_qp(qp, &attr, flags));

    return 0;
}

// Transition a QP from the INIT to RTR state, using the specified QP number
int modify_qp_to_rtr(struct resources *res, struct ibv_qp *qp, uint32_t remote_qpn,
                            uint16_t dlid, uint8_t *dgid) {
    struct ibv_qp_attr attr;
    int flags;

    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = res->config.ib_port;

    if (res->config.gid_idx >= 0) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = res->config.gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    CHECK(ibv_modify_qp(qp, &attr, flags));

    return 0;
}

// Transition a QP from the RTR to RTS state
int modify_qp_to_rts(struct resources *res, struct ibv_qp *qp) {
    struct ibv_qp_attr attr;
    int flags;

    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12; // 18
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    CHECK(ibv_modify_qp(qp, &attr, flags));

    return 0;
}

// Connect the QP, then transition the server side to RTR, sender side to RTS.
int connect_qp(struct resources *res, int pagesk, int server) {
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    char temp_char;
    union ibv_gid my_gid;


    
    if(pagesk <= 0){
        res->sock = sock_connect(opts.addr, opts.port);
        if (res->sock < 0) {
            pr_err("Failed to establish TCP connection to server %s, port %d\n",
                    opts.addr, opts.port);
            goto die;
        }
    }else{
        
        res->sock = pagesk;
    }

    memset(&my_gid, 0, sizeof(my_gid));

    if (res->config.gid_idx >= 0) {
        CHECK(ibv_query_gid(res->ib_ctx, res->config.ib_port, res->config.gid_idx,
                            &my_gid));
    }

    // \begin exchange required info like buffer (addr & rkey) / qp_num / lid,
    // etc. exchange using TCP sockets info required to connect QPs
    local_con_data.addr = htonll((uintptr_t)res->buf);
#ifndef DOCKER
    local_con_data.rkey = htonl(res->mr[item_num]->rkey);
#else
    local_con_data.rkey = htonl(res->mr_buf->rkey);
#endif
    local_con_data.qp_num = htonl(res->qp->qp_num);
    local_con_data.lid = htons(res->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);

    pr_info("\n Local LID      = 0x%x\n", res->port_attr.lid);

    sock_sync_data(res->sock, sizeof(struct cm_con_data_t),
                   (char *)&local_con_data, (char *)&tmp_con_data);

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    // save the remote side attributes, we will need it for the post SR
    res->remote_props = remote_con_data;
    // \end exchange required info
    pr_info("Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
    pr_info("Remote rkey = 0x%x\n", remote_con_data.rkey);
    pr_info("Remote QP number = 0x%x\n", remote_con_data.qp_num);
    pr_info("Remote LID = 0x%x\n", remote_con_data.lid);

    if (res->config.gid_idx >= 0) {
        uint8_t *p = remote_con_data.gid;
        int i;
        printf("Remote GID = ");
        for (i = 0; i < 15; i++)
            printf("%02x:", p[i]);
        printf("%02x\n", p[15]);
    }

    // modify the QP to init
    modify_qp_to_init(res, res->qp);
    query_qp_state(res->qp);
    // let the client post RR to be prepared for incoming messages
    // if (res->config.server_name) {
    // post_receive(res, item_num, (uintptr_t)res->buf, 5);
    // }
    if (server)
        post_receive_connect_cq(res, (uintptr_t)res->buf, sizeof(struct PF_PageRequest));
    // else
    //     post_receive(&PF_res, item_num, (uintptr_t)PF_res.buf, sizeof(struct PF_PageResponse));	
    // modify the QP to RTR
    
    modify_qp_to_rtr(res, res->qp, remote_con_data.qp_num, remote_con_data.lid,
                     remote_con_data.gid);
    query_qp_state(res->qp);

    // modify QP state to RTS
    
    modify_qp_to_rts(res, res->qp);
    query_qp_state(res->qp);
    // sync to make sure that both sides are in states that they can connect to
    // prevent packet lose
    sock_sync_data(res->sock, 1, "Q", &temp_char);

    // FIXME: ;)
    return 0;
die:
    exit(-1);
}

// Cleanup and deallocate all resources used
int resources_destroy(struct resources *res) {
    ibv_destroy_qp(res->qp);
    for (int i = 0; i < item_num + 1; i++)
        ibv_dereg_mr(res->mr[i]);
    free(res->buf);
    ibv_destroy_cq(res->cq);
    ibv_dealloc_pd(res->pd);
    ibv_close_device(res->ib_ctx);
    // close(res->sock);

    // FIXME: ;)
    return 0;
}

int send_page_request(struct resources *res, struct PF_PageRequest *request) 
{
    
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;
    struct PF_PageRequest *req = request;

    memset(&sge, 0, sizeof(sge));

    sge.addr = (uintptr_t)req;
    sge.length = sizeof(struct PF_PageRequest);
    sge.lkey = res->mr[item_num]->lkey;

    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_SEND;
    sr.send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

    // there is a receive request in the responder side, so we won't get any
    // into RNR flow
    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));

    
    CHECK(poll_completion(res));

    return 0;
}

int receive_page_request(struct resources *res, struct mul_shregion_t *shregion)
{
    
    int     ret;
    int     index = 0;
    int     stop = 0;

    struct PF_PageRequest *req;
    struct shregion_t * sh;

    
    ret = poll_completion(res);

    
    if ((uint64_t)res->buf == -1){
        stop = 1;
    }

    ret = post_receive(res, item_num, (uintptr_t)res->buf, sizeof(struct PF_PageRequest));
    
    req = (struct PF_PageRequest *)res->buf;
    for (int i = 0; i< item_num; i++){
        if (shregion->PIDs[i] == req->pid){
            index = i;
            break;
        }
    }
    sh = shregion->shregions[index];
    
    
    WQenqueue(&sh->address_queue, req->addr);
    sh->isPageFault++;
    
    // ret = post_receive(res, item_num, (uintptr_t)res->buf, 8192);

    return stop && ret;
}

int send_page_response(struct resources *res, struct mul_shregion_t *shregion, uint64_t pid) 
{
    
    int     ret;
    int     index = 0;

    struct  ibv_send_wr     sr;
    struct  ibv_sge         sge;
    struct  ibv_send_wr     *bad_wr = NULL;
    struct  PF_PageResponse *resp;
    struct  shregion_t      *sh;
    // struct  address_data    *data;

    // resp = (struct  PF_PageResponse *)malloc(sizeof(struct  PF_PageResponse));
    // data = (struct  address_data *)malloc(sizeof(struct  address_data));
    for(int i = 0; i< item_num; i++){
        if (shregion->PIDs[i] == pid){
            index = i;
            break;
        }
    }
    sh = shregion->shregions[index];

    
    resp = (struct  PF_PageResponse *)CQdequeue(&sh->data_queue);
    resp->pid = pid;
    sh->isPageReady--;

    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)resp;
    sge.length = sizeof(struct PF_PageResponse);
    
    sge.lkey = res->mr[index]->lkey;

    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_SEND;
    sr.send_flags = IBV_SEND_SIGNALED;

    // there is a receive request in the responder side, so we won't get any
    // into RNR flow
    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));

    
    CHECK(poll_completion(res));
    
    return 0;
}


int receive_page_response(struct resources *res, struct mul_shregion_t *shregion)
{
    int     ret;
    int     index = 0;
    int     uffd = 0;
    struct PF_PageResponse *resp;
    struct uffdio_copy uffdio_copy;
    int pid;


    
    ret = poll_completion(res);

    
    resp = (struct PF_PageResponse *)res->buf;
    for (int i = 0; i< item_num; i++){
        if (shregion->PIDs[i] == resp->pid){
            index = i;
            break;
        }
    }
    pid = resp->pid;
    
    
    uffdio_copy.dst = (uint64_t)resp->addr;
    uffdio_copy.src = (uint64_t)resp->page;
    uffdio_copy.len = 4096;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    uffd += index;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) < 0){
        if(errno != EEXIST )
            pr_err("ioctl(UFFDIO_COPY) failed\n");
    }
    
    
    ret = post_receive(res, item_num, (uintptr_t)res->buf, 8192);

    return ret;
}

// send ack in TS
int send_ack(struct resources *res){
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res->buf;
    sge.length = 4;
    sge.lkey = res->mr[item_num]->lkey;

    memset(&sr, 0, sizeof(sr));
    sr.wr_id = (uintptr_t)res->buf;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_SEND_WITH_IMM;
    sr.send_flags = IBV_SEND_SIGNALED;
    sr.imm_data = 1;
    sr.send_flags |= IBV_SEND_INLINE;

    if(ibv_post_send(res->qp, &sr, &bad_wr)){
        pr_err("ibv_post_send failed\n");
    }

    return 0;
}

// ait ack in TS

int wait_ack(struct resources *res){
    int ret = 0;
    struct ibv_wc wc;

    while((ret = ibv_poll_cq(res->cq, 1, &wc)) > 0){
        if (wc.status == IBV_WC_SUCCESS){
            if (wc.opcode == IBV_WC_RECV){
                if (wc.wc_flags & IBV_WC_WITH_IMM){
                    uint32_t imm_data = ntohl(wc.imm_data);
                    if (imm_data == 1)
                        return 0;
                }
            }
        }
    }
    return ret;
}

// RDMA write & read
int rdma_write(struct resources *res, uint64_t remote_off, uint64_t local_addr, int length, int mr_index)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    wr_count++;
    // prepare the scatter / gather entry
    memset(&sge, 0, sizeof(sge));

    sge.addr = (uintptr_t)local_addr;
    sge.length = length;
    sge.lkey = res->mr[mr_index]->lkey;

    // prepare the send work request
    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = send_id++;
    
    sr.sg_list = &sge;

    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_WRITE;
    if (wr_count >= 100 )
        sr.send_flags = IBV_SEND_SIGNALED;
    else
        sr.send_flags = 0;

    sr.wr.rdma.remote_addr = res->remote_props.addr + remote_off;
    sr.wr.rdma.rkey = res->remote_props.rkey;


    // there is a receive request in the responder side, so we won't get any
    // into RNR flow
    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));
    
    if (wr_count >= 100){
        wr_count = 0;
        CHECK(poll_completion(res));
    }
    return 0;
}

int rdma_read(struct resources *res, uint64_t remote_off, uint64_t local_addr, int length)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    // prepare the scatter / gather entry
    memset(&sge, 0, sizeof(sge));

    sge.addr = (uintptr_t)local_addr;
    sge.length = length;
    sge.lkey = res->mr[item_num]->lkey;

    // prepare the send work request
    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = send_id++;
    
    sr.sg_list = &sge;

    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_WRITE;
    sr.send_flags = 0;

    sr.wr.rdma.remote_addr = res->remote_props.addr + remote_off;
    sr.wr.rdma.rkey = res->remote_props.rkey;

    
    // there is a receive request in the responder side, so we won't get any
    // into RNR flow
    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));
    // CHECK(poll_completion(res));
    return 0;
}

int rdma_fetch_and_read(struct resources *res, uint64_t remote_off, uint64_t local_addr, int length)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    // prepare the scatter / gather entry

    sge.addr = (uintptr_t)local_addr;
    sge.length = length;
    sge.lkey = res->mr[item_num]->lkey;

    // prepare the send work request
    memset(&sr, 0, sizeof(sr));

    sr.next = NULL;
    sr.wr_id = send_id++;
    
    sr.sg_list = &sge;

    sr.num_sge = 1;
    sr.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
    sr.send_flags = IBV_SEND_SIGNALED;

    sr.wr.rdma.remote_addr = res->remote_props.addr + remote_off;
    sr.wr.rdma.rkey = res->remote_props.rkey;

    
    // there is a receive request in the responder side, so we won't get any
    // into RNR flow
    CHECK(ibv_post_send(res->qp, &sr, &bad_wr));
    CHECK(poll_completion(res));
    return 0;
}

// Poll the CQ for a single event. This function will continue to poll the queue
// until MAX_POLL_TIMEOUT ms have passed.
static inline int poll_completion_async(struct resources *res) {
    struct ibv_wc wc;
    int poll_result;

    poll_result = ibv_poll_cq(res->cq, 1, &wc);

    if (poll_result < 0) {
        // poll CQ failed
        pr_err("poll CQ failed\n");
        return -1;
    } else if (poll_result == 0) {
        pr_err("Completion wasn't found in the CQ after timeout\n");
        return -1;
    } else if (poll_result > 0){
        return poll_result;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        pr_err("Got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",
              wc.status, wc.vendor_err);
        return -1;
    }

    return 0;
}