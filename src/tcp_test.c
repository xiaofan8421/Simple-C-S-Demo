/* system headers */
#include <stdio.h> // printf
#include <stdlib.h> // atoi
#include <string.h> // strcpy, strncpy, memset, strerror
#include <stdbool.h> // bool
#include <signal.h> // signal
#include <stdint.h> // uint16_t
#include <unistd.h> // close, fcntl, select, read, write
#include <fcntl.h>  // fcntl
#include <sys/types.h>  // socket, setsockopt, inet_addr, connect, select, accept
#include <sys/socket.h> // socket, setsockopt, bind, listen, connect, accept, getpeername
#include <netinet/in.h> // inet_addr, listen
#include <arpa/inet.h> // inet_pton, inet_addr, htons, inet_ntop, ntohs
#include <errno.h> // errno
#include <sys/select.h> // select
#include <sys/time.h> // select
#include <netinet/tcp.h> // for TCP_NODELAY

//
#define VERSION         "0.1.0"
#define DEFAULT_IP_V6   "0.0.0.0"
#define IP_V6           "::"
#define DEFAULT_PORT    50001
#define BUF_IP          40
#define BUF_TMP         128


// global app status 
static bool g_running = false;


// cb declartion
typedef void(*signal_hander)(int);


static int signal_register(signal_hander func)
{
    if ((SIG_ERR == signal(SIGHUP, func)) || \
        (SIG_ERR == signal(SIGINT, func)) || \
        (SIG_ERR == signal(SIGQUIT, func)) || \
        (SIG_ERR == signal(SIGTERM, func)) || \
        (SIG_ERR == signal(SIGTSTP, func)) || \
        (SIG_ERR == signal(SIGALRM, func))) {
            printf("[signal_reg]: errno=%u, err=%s \n", \
                                errno, strerror(errno));
            return -1;
    }
    return 0;
}

static void signal_hander_func(int signal_type)
{
    switch (signal_type) {
        case SIGALRM:
        case SIGHUP:
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
        case SIGTSTP:
            g_running = false;
            break;
        default:
            break;
    }
}

__attribute__((noreturn)) static void usage(void)
{
    puts("TCP_TEST " VERSION
         " usage:\n"
         "\n"
         "tcp_test\t\"server\"\n\t<server ip>\n\t<server port>"
         "\n\n"
         "tcp_test\t\"client\"\n\t<server ip>\n\t<server port>\n");
    exit(254);
}

static int check_ip_addr(const char *in_ip)
{
    if (NULL == in_ip) {
        printf("[check_ip_addr]: ip is NULL! \n");
        return -1;
    }

    struct sockaddr_in addr4;
    if (1 == inet_pton(AF_INET, in_ip, &addr4.sin_addr)) {
        return AF_INET;
    }

    struct sockaddr_in6 addr6;
    if (1 == inet_pton(AF_INET6, in_ip, &addr6.sin6_addr)) {
        return AF_INET6;
    }

    return -1;
}

static int set_socket_option(int sock_fd)
{
    int ret = -1;
    const int opt = 1;

    ret = setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (-1 == ret) {
        printf("[set_sock_opt]: set TCP_NODELAY failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }
    /*
    // if need to set socket buf size
    uint64_t socket_buf_size = 64*1024*1024;  //64 MB
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &socket_buf_size, \
                     sizeof(socket_buf_size));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_RCVBUF 64M failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }
    */
    /*
    // if udp, no need for, udp has no snd buffer.
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &socket_buf_size, \
                     sizeof(socket_buf_size));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_SNDBUF 64M failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }
    */

    // reuse tcp server port for multi-thread perf improving!
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_REUSEPORT failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }

EXIT:
    return ret;
}

static int set_non_block(int sock_fd)
{
    int opt = -1;

    opt = fcntl(sock_fd, F_GETFL);
    if(-1 == opt) {
        printf("[set_non_block]: F_GETFL failed! errno=%u, err=%s \n", \
                                                errno, strerror(errno));
        goto EXIT;
    }

    opt |= O_NONBLOCK; 
    opt = fcntl(sock_fd, F_SETFL, opt);
    if(-1 == opt) {
        printf("[set_non_block]: F_SETFL failed! errno=%u, err=%s \n", \
                                                errno, strerror(errno));
        goto EXIT;
    }

EXIT:
    return opt;
}

static int gen_sock_net_addr(int domain, const char *in_ip, uint16_t port, \
                             struct sockaddr_in *out_addr4, \
                             struct sockaddr_in6 *out_addr6)
{
    if (NULL == in_ip) {
        printf("[gen_sock_net_addr]: ip is NULL! \n");
        return -1;
    }

    if (AF_INET == domain) {
        if (NULL == out_addr4) {
            return -1;
        }
        out_addr4->sin_family = AF_INET;
        out_addr4->sin_addr.s_addr = inet_addr(in_ip);
        out_addr4->sin_port = htons(port);
    } else if (AF_INET6 == domain) {
        if (NULL == out_addr6) {
            return -1;
        }
        out_addr6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, in_ip, &out_addr6->sin6_addr);
        out_addr6->sin6_port = htons(port);
    }

    return 0;
}


static int safe_read(int conn_fd, fd_set *set)
{
    int ret = -1;
    char tmp_buf[BUF_TMP] = {0};

    memset(tmp_buf, 0, sizeof(tmp_buf));
    ret = read(conn_fd, tmp_buf, sizeof(tmp_buf) - 1);
    if (-1 == ret) {
        printf("read failed! errno=%u, err=%s \n", errno, strerror(errno));
        return -1;
    } else if (0 == ret) {
        FD_CLR(conn_fd, set);
        close(conn_fd);
        return 1;
    }

    return 0;
}

static int safe_write(int conn_fd)
{
    int ret = -1;
    char tmp_buf[BUF_TMP] = {0};

    memset(tmp_buf, 0, sizeof(tmp_buf));
    strcpy(tmp_buf, "hello client! I'm select server! \n");
    //tmp_buf[ret] = '\0';
    ret = write(conn_fd, tmp_buf, strlen(tmp_buf));
    if (-1 == ret) {
        printf("write failed! errno=%u, err=%s \n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

// for test
static int inter_msg(int conn_fd, fd_set *set)
{
    int ret = -1;
    struct sockaddr_in client_addr;
    socklen_t addr_len = 0;
    char client_ip[BUF_IP] = {0};
    uint16_t client_port = 0;
    char tmp_buf[BUF_TMP] = {0};

    memset(&client_addr, 0, sizeof(client_addr));
    addr_len = sizeof(client_addr);

    if (-1 == getpeername(conn_fd, (struct sockaddr*)&client_addr, \
                          &addr_len)) {
        printf("getpeername failed! errno=%u, err=%s \n", \
                            errno, strerror(errno));
        return -1;
    }
    client_port = ntohs(client_addr.sin_port);
    memset(client_ip, 0, sizeof client_ip);
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, BUF_IP);
    //printf("msg from [IP=%s, port=%u] \n", client_ip, client_port);

    memset(tmp_buf, 0, sizeof(tmp_buf));
    ret = read(conn_fd, tmp_buf, sizeof(tmp_buf) - 1);
    if (-1 == ret) {
        printf("\nrecv from client [ip=%s, port=%u] failed! errno=%u, err=%s \n", \
                                client_ip, client_port, errno, strerror(errno));
        return -1;
    } else if (0 == ret) {
        printf("\nclient [ip=%s, port=%u] closed! \n", \
                        client_ip, client_port);
        FD_CLR(conn_fd, set);
        close(conn_fd);
        return 1;
    }

    tmp_buf[ret - 1] = '\0';
    printf("\nSuccessfully recv from client's [ip=%s, port=%u] %d bytes:%s \n", \
                                    client_ip, client_port, ret, tmp_buf);

    memset(tmp_buf, 0, sizeof(tmp_buf));
    strcpy(tmp_buf, "hello client! I'm select server! \n");
    //tmp_buf[ret] = '\0';
    ret = write(conn_fd, tmp_buf, strlen(tmp_buf));
    if (-1 == ret) {
        printf("\nsnd to client [ip=%s, port=%u] failed! errno=%u, err=%s \n", \
                                client_ip, client_port, errno, strerror(errno));
        return -1;
    }

    printf("\nSuccessfully snd msg to client[ip=%s, port=%u] %d bytes:%s \n", \
                                    client_ip, client_port, ret, tmp_buf);

    return 0;
}


int main(int argc, char **argv)
{
    int ret = -1;
    int domain = -1;
    int sock_fd = -1; // listen or connected socket
    int conn_fd = -1;   // established socket
    char server_ip[BUF_IP] = {0};   // server listen ip
    uint16_t server_port = 0;   // server listen port
    char client_ip[BUF_IP] = {0};   // client connect ip
    uint16_t client_port = 0;   // client connect port
    struct sockaddr_in server_addr; // server net addr
    struct sockaddr_in client_addr; // client net addr
    socklen_t addr_len = 0;
    bool is_server = true;  // default server

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));
    addr_len = sizeof(struct sockaddr_in);

    if (2 > argc) {
        usage();
        goto EXIT;
    }

    if (0 == strcmp(argv[1], "server")) {
        printf("work on server mode... \n");
        is_server = true;

        // default work on IPv4 here
        printf("default server ip:%s \n", DEFAULT_IP_V6);
        strcpy(server_ip, DEFAULT_IP_V6);
        printf("default server port:%u \n", DEFAULT_PORT);
        server_port = DEFAULT_PORT;
    } else if (0 == strcmp(argv[1], "client")) {
        printf("work on client mode... \n");
        if (4 != argc) {
            usage();
            goto EXIT;
        }
        is_server = false;
    } else {
        printf("unknown argv[1]=%s \n", argv[1]);
        goto EXIT;
    }

    if (NULL != argv[2]) {
        printf("argv[2]=%s \n", argv[2]);
        memset(server_ip, 0, BUF_IP);
        strncpy(server_ip, argv[2], strlen(argv[2]));
        if (NULL != argv[3]) {
            printf("argv[3]=%s \n", argv[3]);
            server_port = atoi(argv[3]);
        }
    }

    g_running = true;
    ret = signal_register(signal_hander_func);
    if (-1 == ret) {
        printf("signal_reg failed! \n");
        goto EXIT;
    }

    domain = check_ip_addr(server_ip);
    if ((AF_INET != domain) && (AF_INET6 != domain)) {
        printf("illegal server ip format! \n");
        goto EXIT;
    }

    sock_fd = socket(domain, SOCK_STREAM, 0);
    if (-1 == sock_fd) {
        printf("create socket failed! errno=%u, err=%s \n", \
                                    errno, strerror(errno));
        goto EXIT;
    }

    if (is_server) {
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        ret = gen_sock_net_addr(domain, server_ip, server_port, &addr4, &addr6);
        if (-1 == ret) {
            printf("gen_sock_net_addr failed! \n");
            goto EXIT;
        }

        if (AF_INET == domain) {
            ret = bind(sock_fd, (struct sockaddr*)&addr4, \
                       sizeof(struct sockaddr_in));
        } else if (AF_INET6 == domain) {
            ret = bind(sock_fd, (struct sockaddr*)&addr6, \
                       sizeof(struct sockaddr_in6));
        }
        if (-1 == ret) {
            printf("bind failed! errno=%u, err=%s \n", \
                                errno, strerror(errno));
            goto EXIT;
        }

        // default backlog is 128
        ret = listen(sock_fd, 128);
        if (-1 == ret) {
            printf("listen failed! errno=%u, err=%s \n", \
                                errno, strerror(errno));
            goto EXIT;
        }

        printf("one listening on %s,%u ... the other one waiting for accept... \n", \
                        server_ip, server_port);
    } else {
        server_addr.sin_family = domain;
        server_addr.sin_port = htons(server_port);
        inet_pton(domain, server_ip, &server_addr.sin_addr.s_addr);
        ret = connect(sock_fd, (struct sockaddr*)&server_addr, \
                      sizeof(server_addr));
        if (-1 == ret) {
            printf("connect failed! errno=%u, err=%s \n", \
                                    errno, strerror(errno));
            goto EXIT;
        }
        printf("connect server[ip=%s, port=%u] ok. ", \
                            server_ip, server_port);
    }

    ret = set_non_block(sock_fd);
    if (-1 == ret) {
        printf("set non block failed! \n");
        goto EXIT;
    }

    fd_set set,rset;
    int max_fd = 0;
    struct timeval to;
    memset(&to, 0, sizeof(to));
    FD_ZERO(&set);
    FD_SET(sock_fd, &set);
    if (max_fd < sock_fd) {
        max_fd = sock_fd;
    }

    while (g_running) {
        rset = set;
        to.tv_sec = 10;
        to.tv_usec = 0;
        ret = select(max_fd+1, &rset, NULL, NULL, &to);
        if (-1 == ret) {
            if (errno == EINTR || errno == EBADF) {
                continue;
            }
            printf("select failed! errno=%u, err=%s \n", \
                                    errno, strerror(errno));
            continue;
        } else if (0 == ret) {
            //tTime.tv_sec  = 10;
            //tTime.tv_usec = 0;
            printf("select timeout \n");
            continue;
        }

        if (FD_ISSET(sock_fd, &rset)) {
            if (is_server) {
                conn_fd = accept(sock_fd, (struct sockaddr *)&client_addr, \
                                 &addr_len);
                if (-1 == conn_fd) {
                    printf("accept failed! error=%u, err=%s \n", \
                                                errno, strerror(errno));
                    continue;
                }

                client_port = ntohs(client_addr.sin_port);
                memset(client_ip, 0, sizeof client_ip);
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, BUF_IP);
                printf("New Connection: Client[ip=%s, port=%u] \n", \
                                            client_ip, client_port);
                FD_SET(conn_fd, &set);
                if (max_fd < conn_fd) {
                    max_fd = conn_fd;
                }
                continue;
            } else { // client behavior
                //inter_msg(sock_fd, &set); // just for test
                safe_write(sock_fd);
                continue;
            }
        }

        for (int idx=0; idx<=max_fd; idx++) {
            // listen_fd here
            if (sock_fd == idx) {
                continue;
            }

            if (FD_ISSET(idx, &rset)) {
                conn_fd = idx;
                inter_msg(conn_fd, &set); // just for test
            }
        }
    }

EXIT:
    if (-1 != sock_fd) {
        close(sock_fd);
        sock_fd = -1;
    }

    if (-1 != conn_fd) {
        close(conn_fd);
        conn_fd = -1;
    }

    printf("\n exit.. \n");

    return 0;
}
