#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "cr-sync.h"
#include "log.h"

static enum STATE now_state = READY;

int syncServerInit(char *ip, int port){
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *ack = "ACK from Server";

    // create socket fd
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = port;

    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0){
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // listen for connections
    if(listen(server_fd, 3) < 0){
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // accept connection
    if((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0){
        perror("accept");
        exit(EXIT_FAILURE);
    }

    return new_socket;
}

int syncClientInit(char *ip, int port){
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // create socket fd
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = port;

    // convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0){
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    // connect to server
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect");
        exit(EXIT_FAILURE);
    }
    return sock;
}

int sync_wait(int sockfd){
    int read_bytes = 0, write_bytes = 0;
    char buffer[20];

    write_bytes = write(sockfd, "wait", 4);
    if (write_bytes < 0){
        perror("write");
        exit(EXIT_FAILURE);
    }

    read_bytes = read(sockfd, buffer, 4);
    if (read_bytes < 0){
        perror("read");
        exit(EXIT_FAILURE);
    }

    if (write_bytes == read_bytes)
        return 0;
    else
        return 1;
}


int wait_state(int sockfd, enum STATE state){
    int ret = 0;
    while (1){        
        if (now_state >= state){
            break;
        }
        pr_warn("wait_state: %d, now_state:%d \n", state, now_state);
        ret = recv(sockfd, &now_state, sizeof(state), 0);
        if (ret <= 0){
            perror("recv");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

int notify_peer(int sockfd, enum STATE state){
    int ret = 0;
    
    ret = send(sockfd, &state, sizeof(state), 0);
    return ret;
}

int update_state(int sockfd, enum STATE state){
    int ret = 0;
    now_state = state;
    ret = notify_peer(sockfd, state);
    return ret;
}


int syncServerInit_unix(char *socket_path) {
    int server_fd, new_socket;
    struct sockaddr_un address;
    int addrlen = sizeof(address);

    
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);

    
    unlink(socket_path); 
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    return new_socket;
}


int syncClientInit_unix(char *socket_path) {
    int sock = 0;
    struct sockaddr_un serv_addr;

    
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    return sock;
}








