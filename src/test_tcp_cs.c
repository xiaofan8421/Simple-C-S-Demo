
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
#include <stdint.h> // uint64
#include <sys/time.h> // gettimeofday

/* third party headers */
#include <pcap.h>

/* project component/module headers */
#include "pkt_decap/pkt_decap.h"


//
#define VERSION             "0.2.0"
#define BUF_IP              40
#define BUF_TMP             4096
#define DEFAULT_IP_V4       "0.0.0.0"
#define DEFAULT_IP_V6       "::"
#define DEFAULT_PORT        50001
#define DEFAULT_PCAP_FILE   "test.pcap"

#define FIVE_SECONDS        5                   // 5s
#define SECONDS_TO_US       1000000             // 1s==10^6us
#define DIFFER(X, Y)   ((X) > (Y)) ? ((X) - (Y)) : 0


typedef struct tag_ts_rate_info {
    uint64_t    rate_gap;
    uint64_t    start_ts;
    uint64_t    pkts;
    uint64_t    bytes;
} ts_rate_t;

typedef struct tag_pkt_stat_info {
    uint64_t    pkts;
    uint64_t    bytes;
    uint64_t    errors;
    uint64_t    dropped;
    double      pps;
    double      Bps;
} pkt_stat_t;

// cb declartion
typedef void(*signal_hander)(int);


// global app status
static bool g_running = false;
ts_rate_t g_ts_rate;


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
    /*
    puts("TEST_TCP_CS " VERSION
         " usage:\n"
         "\n"
         "test_tcp_ts\t\"server\"\n\t<pcap file>\n\t[server ip]\n\t[server port]"
         "\n\n"
         "test_tcp_ts\t\"client\"\n\t<pcap file>\n\t<server ip>\n\t<server port>\n");
    */
    puts("TEST_TCP_CS " VERSION
         " usage:\n"
         "\n"
         "test_tcp_cs\t\"server\"\n\t[server ip]\n\t[server port]"
         "\n\n"
         "test_tcp_cs\t\"client\"\n\t<pcap file>\n\t<server ip>\n\t<server port>\n");
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

    uint64_t sock_buf_size = 64*1024*1024;  //64 MB
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, \
                     sizeof(sock_buf_size));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_RCVBUF 64M failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }

    /*
    // if udp, no need for, udp has no snd buffer.
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, \
                     sizeof(sock_buf_size));
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
    if (-1 == opt) {
        printf("[set_non_block]: F_GETFL failed! errno=%u, err=%s \n", \
                                                errno, strerror(errno));
        goto EXIT;
    }

    opt |= O_NONBLOCK;
    opt = fcntl(sock_fd, F_SETFL, opt);
    if (-1 == opt) {
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


//static int safe_read(int conn_fd, fd_set *set)
static int safe_read(int conn_fd, fd_set *set, pkt_stat_t *pkt_stat)
{
    int ret = -1;
    char *tmp_buf[BUF_TMP] = {0};

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

    pkt_stat->pkts++;
    pkt_stat->bytes += ret;

    return 0;
}

static int safe_write(int conn_fd)
{
    int ret = -1;
    char *tmp_buf = {0};

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
        printf("\nrecv from client[ip=%s, port=%u] failed! errno=%u, err=%s \n", \
                                client_ip, client_port, errno, strerror(errno));
        return -1;
    } else if (0 == ret) {
        printf("\nclient[ip=%s, port=%u] closed! \n", \
                        client_ip, client_port);
        FD_CLR(conn_fd, set);
        close(conn_fd);
        return 1;
    }

    tmp_buf[ret - 1] = '\0';
    printf("\nSuccessfully recv from client[ip=%s, port=%u] %d bytes:%s \n", \
                                    client_ip, client_port, ret, tmp_buf);

    memset(tmp_buf, 0, sizeof(tmp_buf));
    strcpy(tmp_buf, "hello client! I'm select server! \n");
    //tmp_buf[ret] = '\0';
    ret = write(conn_fd, tmp_buf, strlen(tmp_buf));
    if (-1 == ret) {
        printf("\nsnd to client[ip=%s, port=%u] failed! errno=%u, err=%s \n", \
                                client_ip, client_port, errno, strerror(errno));
        return -1;
    }

    printf("\nSuccessfully snd msg to client[ip=%s, port=%u] %d bytes:%s \n", \
                                    client_ip, client_port, ret, tmp_buf);

    return 0;
}


static int64_t gettime_us_hp(void)
{
    struct timeval  t;
    double      t_us;
    int64_t     time_us;

    gettimeofday(&t, NULL);
    t_us = 1000000.0 * (double)(t.tv_sec) + t.tv_usec;
    time_us = (int64_t)(t_us);

    return time_us;
}

static int stat_calc_rate(pkt_stat_t *pkt_stat, ts_rate_t *ts_rate)
{
    uint64_t tx_ts = gettime_us_hp();
    uint64_t dif_ts = (tx_ts - ts_rate->start_ts) / SECONDS_TO_US; // unit: s

#ifdef DEBUG
    if (FIVE_SECONDS <= dif_ts) {
#else
    if (ts_rate->rate_gap <= dif_ts) {
#endif
        uint64_t dif_pkts = DIFFER(pkt_stat->pkts, ts_rate->pkts);
        uint64_t dif_bytes = DIFFER(pkt_stat->bytes, ts_rate->bytes);
        pkt_stat->pps = 1.0 * dif_pkts / dif_ts;
        pkt_stat->Bps = 1.0 * dif_bytes / dif_ts;
        ts_rate->start_ts = tx_ts;
        ts_rate->pkts = pkt_stat->pkts;
        ts_rate->bytes = pkt_stat->bytes;

        printf("\n pkts:%lu, bytes:%lu, pps:%f, Gbps:%f \n", \
            pkt_stat->pkts, pkt_stat->bytes, pkt_stat->pps, pkt_stat->Bps/1024/1024/1024*8);
        return 0;
    }

    return -1;
}

int main(int argc, char **argv)
{
    int ret = -1;
    int domain = -1;
    int sock_fd = -1;
    int conn_fd = -1;
    char server_ip[BUF_IP] = {0};
    uint16_t server_port = 0;
    char client_ip[BUF_IP] = {0};
    uint16_t client_port = 0;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in6 server_addr6;
    struct sockaddr_in6 client_addr6;
    socklen_t addr_len = 0;
    bool is_server = true;
    char *pcap_file_name = NULL;
    fd_set set,rset;
    int max_fd = 0;
    struct timeval to;

    memset(&g_ts_rate, 0, sizeof(ts_rate_t));
    g_ts_rate.start_ts = gettime_us_hp();
    g_ts_rate.rate_gap = 5;
    pkt_stat_t pkt_stat;
    memset(&pkt_stat, 0, sizeof(pkt_stat_t));

    //if (3 > argc) {
    if (2 > argc) {
        usage();
        goto EXIT;
    }

    if (0 == strcmp(argv[1], "server")) {
        printf("work on server mode... \n");
        is_server = true;

        if (NULL != argv[2]) {
            memset(server_ip, 0, BUF_IP);
            strncpy(server_ip, argv[2], strlen(argv[2]));
            printf("server_ip: %s \n", server_ip);
            if (NULL != argv[3]) {
                server_port = atoi(argv[3]);
                printf("server_port: %u \n", server_port);
            } else {
                server_port = DEFAULT_PORT;
                printf("default server port: %u \n", server_port);
            }
        } else {
            // default work on IPv4 here
            strcpy(server_ip, DEFAULT_IP_V4);
            printf("default server ip: %s \n", server_ip);
        }
    } else if (0 == strcmp(argv[1], "client")) {
        printf("work on client mode... \n");
        if (3 > argc) {
            usage();
            goto EXIT;
        }
        is_server = false;

        pcap_file_name = argv[2];
        printf("pcap file_name: %s \n", pcap_file_name);

        if (NULL != argv[3]) {
            memset(server_ip, 0, BUF_IP);
            strncpy(server_ip, argv[3], strlen(argv[3]));
            printf("server_ip: %s \n", server_ip);
            if (NULL != argv[4]) {
                server_port = atoi(argv[4]);
                printf("server_port: %u \n", server_port);
            } else {
                server_port = DEFAULT_PORT;
                printf("default server port: %u \n", server_port);
            }
        } else {
            // default work on IPv4 here
            strcpy(server_ip, DEFAULT_IP_V4);
            printf("default server ip: %s \n", server_ip);
        }
    } else {
        usage();
        goto EXIT;
    }

/*
    printf("pcap file: argv[2]=%s \n", argv[2]);
    pcap_file_name = argv[2];

    if (NULL != argv[3]) {
        printf("argv[3]=%s \n", argv[3]);
        memset(server_ip, 0, BUF_IP);
        strncpy(server_ip, argv[3], strlen(argv[3]));
        if (NULL != argv[4]) {
            printf("argv[4]=%s \n", argv[4]);
            server_port = atoi(argv[4]);
        }
    }
*/

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

    if (AF_INET == domain) {
        memset(&server_addr, 0, sizeof(server_addr));
        memset(&client_addr, 0, sizeof(client_addr));
        addr_len = sizeof(struct sockaddr_in);
    } else if (AF_INET6 == domain) {
        memset(&server_addr6, 0, sizeof(server_addr6));
        memset(&client_addr6, 0, sizeof(client_addr6));
        addr_len = sizeof(struct sockaddr_in6);
    }

    sock_fd = socket(domain, SOCK_STREAM, 0);
    if (-1 == sock_fd) {
        printf("create socket failed! errno=%u, err=%s \n", \
                                    errno, strerror(errno));
        goto EXIT;
    }
/*
    ret = set_socket_option(sock_fd);
    if (-1 == ret) {
        goto EXIT;
    }
*/
    if (is_server) {
        ret = gen_sock_net_addr(domain, server_ip, server_port, &server_addr, \
                                &server_addr6);
        if (-1 == ret) {
            printf("gen_sock_net_addr failed! \n");
            goto EXIT;
        }

        if (AF_INET == domain) {
            ret = bind(sock_fd, (struct sockaddr*)&server_addr, \
                       sizeof(struct sockaddr_in));
        } else if (AF_INET6 == domain) {
            ret = bind(sock_fd, (struct sockaddr*)&server_addr6, \
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
        memset(&to, 0, sizeof(to));
        FD_ZERO(&set);
        FD_SET(sock_fd, &set);
        if (max_fd < sock_fd) {
            max_fd = sock_fd;
        }
    } else {
        if (AF_INET == domain) {
            server_addr.sin_family = domain;
            server_addr.sin_port = htons(server_port);
            inet_pton(domain, server_ip, &server_addr.sin_addr.s_addr);
            ret = connect(sock_fd, (struct sockaddr*)&server_addr, \
                          sizeof(server_addr));
        } else if (AF_INET6 == domain) {
            server_addr6.sin6_family = domain;
            server_addr6.sin6_port = htons(server_port);
            inet_pton(domain, server_ip, &server_addr6.sin6_addr);
            ret = connect(sock_fd, (struct sockaddr*)&server_addr6, \
                          sizeof(server_addr6));
        }
        
        if (-1 == ret) {
            printf("connect server[ip=%s, port=%u] failed! errno=%u, err=%s \n", \
                                  server_ip, server_port, errno, strerror(errno));
            return -1;
        }

        printf("tcp client connect server[ip=%s, port=%u] ok.\n", \
                                    server_ip, server_port);
    }

    ret = set_non_block(sock_fd);
    if (-1 == ret) {
        printf("set non block failed! \n");
        goto EXIT;
    }


    while (g_running) {
        stat_calc_rate(&pkt_stat, &g_ts_rate);
        if (is_server) { // server behavior
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
                //printf("select timeout \n");
                continue;
            }

            if (FD_ISSET(sock_fd, &rset)) {
                if (AF_INET == domain) {
                    conn_fd = accept(sock_fd, (struct sockaddr *)&client_addr, \
                                     &addr_len);
                } else if (AF_INET6 == domain) {
                    conn_fd = accept(sock_fd, (struct sockaddr *)&client_addr6, \
                                     &addr_len);
                }
                if (-1 == conn_fd) {
                    printf("accept failed! error=%u, err=%s \n", \
                                                errno, strerror(errno));
                    continue;
                }

                memset(client_ip, 0, sizeof client_ip);
                if (AF_INET == domain) {
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, BUF_IP);
                    client_port = ntohs(client_addr.sin_port);
                } else if (AF_INET6 == domain) {
                    inet_ntop(AF_INET, &client_addr6.sin6_addr, client_ip, BUF_IP);
                    client_port = ntohs(client_addr6.sin6_port);
                }

                printf("New Connection: conn_fd=%d, Client[ip=%s, port=%u] \n", \
                                            conn_fd, client_ip, client_port);
                FD_SET(conn_fd, &set);
                if (max_fd < conn_fd) {
                    max_fd = conn_fd;
                }

                continue;
            }

            for (int idx=0; idx<=max_fd; idx++) {
                // listen_fd here
                if (sock_fd == idx) {
                    continue;
                }

                if (FD_ISSET(idx, &rset)) {
                    conn_fd = idx;

                    //inter_msg(conn_fd, &set); // just for test
                    
                    // if no need it, hide it.
                    //safe_read(conn_fd, &set);
                    safe_read(conn_fd, &set, &pkt_stat);

                    continue;
                }
            }

        } else { // client behavior
            //inter_msg(sock_fd, &set); // just for test


            // if no need it, hide it.
            safe_read(conn_fd, &set);
            goto EXIT;
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
