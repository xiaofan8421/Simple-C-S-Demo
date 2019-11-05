/* system headers */
#include <stdio.h> // printf
#include <stdlib.h> // atoi
#include <string.h> // strcpy, strncpy, memset, strerror
#include <stdbool.h> // bool
#include <signal.h> // signal
#include <stdint.h> // uint16_t
#include <unistd.h> // close, fcntl, read, write
#include <fcntl.h>  // fcntl
#include <sys/time.h> // gettimeofday
#include <sys/types.h>  // socket, setsockopt, inet_addr
#include <sys/socket.h> // socket, setsockopt, bind
#include <netinet/in.h> // inet_addr
#include <arpa/inet.h> // inet_pton, inet_addr, htons, inet_ntop, ntohs
#include <errno.h> // errno
#include <sys/uio.h> // struct iovec
//#include <linux/ip.h>
//#include <linux/icmp.h>
#include <netinet/ip_icmp.h> // ICMPv4
//#include <netinet/ip.h>
#include <linux/errqueue.h> // struct sock_extended_err
#include <linux/icmpv6.h>   // ICMPv6
//#include <netinet/icmp6.h>
#include <pthread.h>


#define VERSION                 "0.1.0"
#define IMCP_MAX_TX_CNT         8
// udp_client恢复重连udp_fw_list中的某项存活的周期， 每3分钟
#define ICMP_RECOVER_PERIOD     (3*60*1000*1000) // us
#define ICMP_HB_INTERVAL        500 // ms
#define MAX_RECVMSG_BUF_SIZE    1024
#define MAX_RETRY_CNT           3
#define IP_BUF_SIZE             40
#define MAX_UDP_NUM             16
#define MAX_OUTGROUP_NUM        32
#define TEST_REMOTE_IP1         "192.168.3.13"
#define TEST_REMOTE_IP2         "192.168.3.14"
#define TEST_REMOTE_PORT1       50001
#define TEST_REMOTE_PORT2       50002


// ICMP back MSG format
/*
    New IP Header + ICMP Message (ICMP header + Original IP Header + Oirginal TCP/UDP Header)
*/


// rx_icmp thread args
typedef struct rx_icmp_err_info {
    volatile bool *running;
    int sock_fd;
    uint8_t *icmp_switch;
    int *domain;
} rx_icmp_err_t;

typedef struct tag_udp_fw_info {
    //uint32_t fw_id;
    int8_t alive; // flags. -1:dead, 1:alive
    char ip[IP_BUF_SIZE]; // fw dst ip
    uint16_t port; // fw dst port
} udp_fw_t;

typedef struct tag_outgroup_info {
    uint16_t id;
    //uint16_t fw_hash_idx; // choose which udp_fw will be delivered, if 0,then broadcast.
    uint16_t fw_num; // current udp_fw num
    udp_fw_t fw_list[MAX_UDP_NUM+1]; // udp_fw_list
    //hal_spinlock_t lock;
} outgroup_info_t;


// global app status 
static bool g_running = false;
static outgroup_info_t g_outgroup[MAX_OUTGROUP_NUM+1] = {0}; // idx <--> outgroup_id


// cb declartion
typedef void(*signal_hander)(int);


__attribute__((noreturn)) static void usage(void)
{
    puts("test_icmp_snoop " VERSION
         " usage:\n"
         "\n"
         "test_icmp_snoop\n\t<local_ip>\n\t<local_port>\n\t<remote_ip>\n\t<remote_port>\n");
    exit(254);
}

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

static int set_socket_option(int socket_fd)
{
    int ret = -1;
    const int opt = 1;

    /*
    // #include <netinet/tcp.h> // for TCP_NODELAY
    ret = setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (-1 == ret) {
        printf("[set_sock_opt]: set TCP_NODELAY failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }
    */

    /*
    uint64_t sock_buf_size = 64*1024*1024;  //64 MB
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, \
                     sizeof(sock_buf_size));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_RCVBUF 64M failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }
    */
    /*
    // if udp, no need for, udp has no snd buffer.
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, \
                     sizeof(sock_buf_size));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_SNDBUF 64M failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }
    */

    // reuse tcp server port for multi-thread perf improving!
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    if (-1 == ret) {
        printf("[set_sock_opt]: set SO_REUSEPORT failed! errno=%u, err=%s \n", \
                                                        errno, strerror(errno));
        goto EXIT;
    }

EXIT:
    return ret;
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

static int64_t gettime_us_hp(void)
{
    struct timeval  t;
    double          t_us = 0.0;
    int64_t         time_us = 0;

    memset(&t, 0, sizeof(t));
    gettimeofday(&t, NULL);
    t_us = 1000000.0 * (double)(t.tv_sec) + t.tv_usec;
    time_us = (int64_t)(t_us);

    return time_us;
}

static int find_outgroup(uint16_t outgroup_id, outgroup_info_t **outgroup)
{
    if (0 == g_outgroup[outgroup_id].fw_num) {
        return -1;
    }
    *outgroup = &g_outgroup[outgroup_id];
    return 0;
}

static int find_fw_node(const char *ip, uint16_t port, udp_fw_t **fw)
{
    if (NULL == ip) {
        return -1;
    }
    uint16_t o_idx = 1;
    uint16_t i_idx = 1;

    outgroup_info_t *outgroup = NULL;
    for (o_idx=1; o_idx<=MAX_OUTGROUP_NUM; o_idx++) {
        if (0 == find_outgroup(o_idx, &outgroup)) {
            for (i_idx=1; i_idx<=MAX_UDP_NUM; i_idx++) {
                if (outgroup->fw_list[i_idx].port == port && \
                    0 == strncmp(outgroup->fw_list[i_idx].ip, ip, strlen(ip))) {
                    *fw = &outgroup->fw_list[i_idx];
                    return 0;
                }
            }
        }
    }

    return -1;
}

static int udp_snd_zero_payload(int sock_fd, const char *udp_server_ip, \
                                uint16_t udp_server_port)
{
    int ret = 0;
    int domain = check_ip_addr(udp_server_ip);
    do {
        if (AF_INET == domain) {
            struct sockaddr_in dst_addr4;
            memset(&dst_addr4, 0, sizeof(dst_addr4));
            gen_sock_net_addr(AF_INET, udp_server_ip, udp_server_port, \
                                      &dst_addr4, NULL);
            // snd 0 bytes udp data to remote_udp_server for receiving icmp error
            ret = sendto(sock_fd, NULL, 0, 0, (struct sockaddr*)&dst_addr4, \
                         (socklen_t)sizeof(struct sockaddr_in));
        } else if (AF_INET6 == domain) {
            struct sockaddr_in6 dst_addr6;
            memset(&dst_addr6, 0, sizeof(dst_addr6));
            gen_sock_net_addr(AF_INET6, udp_server_ip, udp_server_port, \
                                      NULL, &dst_addr6);
            ret = sendto(sock_fd, NULL, 0, 0, (struct sockaddr*)&dst_addr6, \
                         (socklen_t)sizeof(struct sockaddr_in6));
        } else {
            printf("wrong domain=%d, ip=%s, port=%u", \
                            domain, udp_server_ip, udp_server_port);
            return -1;
        }

        if (-1 == ret) {
            /*
            if ((EWOULDBLOCK == errno) || (EAGAIN == errno)) {
                return -1;
            }*/
            //printf("can't send icmp snoop, errno=%u, err=%s", \
                                            errno, strerror(errno));
            continue;
            //return -1;
        }
    } while(0);
    //printf("udp client send icmp snoop len=%d", ret);

    return 0;
}

static int udp_rcv_icmpv4_err(int sock_fd, const char *udp_server_ip, \
                              uint16_t udp_server_port, int8_t *alive)
{
    int ret = 0;
    // Handle receiving ICMPv4 Errors 
    char buffer[MAX_RECVMSG_BUF_SIZE] = {0};
    struct iovec iov;                           /* Data array */
    struct msghdr msg;                          /* Message header */
    struct cmsghdr *cmsg = NULL;                /* Control related data */
    struct sock_extended_err *sock_err = NULL;  /* Struct describing the error */
    struct icmphdr icmph;                       /* ICMPv4 header */
    struct sockaddr_in remote;                  /* Our socket */

    memset(&iov, 0, sizeof(struct iovec));
    memset(&msg, 0, sizeof(struct msghdr));
    memset(&icmph, 0, sizeof(struct icmphdr));
    memset(&remote, 0, sizeof(struct sockaddr_in));
    iov.iov_base = &icmph;
    iov.iov_len = sizeof(icmph);
    msg.msg_name = (void *)&remote;
    msg.msg_namelen = sizeof(remote);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = buffer;
    msg.msg_controllen = sizeof(buffer);

    /* Receiving errors flag is set */
    ret = recvmsg(sock_fd, &msg, MSG_ERRQUEUE);
    if (0 > ret) {
        /*
        if (ECONNREFUSED == errno) {
            *alive = -1;
            return 0;
        }*/
        return -1;
    }

    int port = ntohs(remote.sin_port);
    printf("(ICMPv4): remote_port=%u, src_port=%u \n", \
                                port, udp_server_port);
    char ip[IP_BUF_SIZE] = {0};
    inet_ntop(AF_INET, &remote.sin_addr, ip, sizeof(ip));
    printf("(ICMPv4): remote_ip=%s, src_ip=%s \n", \
                                ip, udp_server_ip);
    /*
    // wrong, rx_icmp_pkts is not ordered
    if (port != udp_server_port) {
        return -1;
    if (0 != strncmp(udp_server_ip, ip, strlen(ip))) {
        return -1;
    }*/
    udp_fw_t *fw = NULL;
    ret = find_fw_node(ip, port, &fw);
    if (0 != ret || NULL == fw) {
        return -1;
    }
    alive = &fw->alive;

    printf("(ICMPv4): recvmsg: ret=%d errno=%d err=%s fd=%d \n", \
                            ret, errno, strerror(errno), sock_fd);

    /* Control messages are always accessed via some macros 
     * http://www.kernel.org/doc/man-pages/online/pages/man3/cmsg.3.html
     */
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        /* ip level */
        if (cmsg->cmsg_level == SOL_IP) {
            /* We received an error */
            if (cmsg->cmsg_type == IP_RECVERR) {
                //LOG(LOG_DBG, "We got IP_RECVERR message.");
                sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
                if (NULL != sock_err) {
                    /* We are intrested in ICMP errors */
                    if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) {
                        /* Handle ICMP errors types */
                        switch (sock_err->ee_type) {
                            case ICMP_NET_UNREACH:
                                /* Handle this error */
                                printf("(ICMPv4): Network Unreachable Error! \n");
                                *alive = -1;
                                break;
                            case ICMP_HOST_UNREACH:
                                /* Handle this error */
                                printf("(ICMPv4): Host Unreachable Error! \n");
                                *alive = -1;
                                break;
                            case ICMP_PORT_UNREACH:
                                printf("(ICMPv4): Port Unreachable Error! ip=%s,port=%u \n", \
                                                                    ip, port);
                                *alive = -1;
                                break;
                            /* Handle all other cases. Find more errors :
                            * http://lxr.linux.no/linux+v3.5/include/linux/icmp.h#L39
                            */
                            default:
                                break;
                        }
                    }
                }
            }
        }
    }

    return 0;
}

static int udp_rcv_icmpv6_err(int sock_fd, const char *udp_server_ip, \
                              uint16_t udp_server_port, int8_t *alive)
{
    int ret = 0;
    // Handle receving ICMPv6 Errors 
    char buffer[MAX_RECVMSG_BUF_SIZE] = {0};
    struct iovec iov;                           /* Data array */
    struct msghdr msg;                          /* Message header */
    struct cmsghdr *cmsg = NULL;                /* Control related data */
    struct sock_extended_err *sock_err = NULL;  /* Struct describing the error */
    struct icmp6hdr icmp6h;                     /* ICMPv6 header */
    struct sockaddr_in6 remote;                 /* Remote socket */

    memset(&iov, 0, sizeof(struct iovec));
    memset(&msg, 0, sizeof(struct msghdr));
    memset(&icmp6h, 0, sizeof(struct icmp6hdr));
    memset(&remote, 0, sizeof(struct sockaddr_in6));
    iov.iov_base = &icmp6h;
    iov.iov_len = sizeof(icmp6h);
    msg.msg_name = (void *)&remote;
    msg.msg_namelen = sizeof(remote);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = buffer;
    msg.msg_controllen = sizeof(buffer);

    /* Receiving errors flag is set */
    ret = recvmsg(sock_fd, &msg, MSG_ERRQUEUE);
    if (0 > ret) {
        if (ECONNREFUSED == errno) {
            *alive = -1;
            return 0;
        }
        //printf("(ICMPv6): recvmsg_ret=%d errno=%d err=%s fd=%d", \
                                    ret, errno, strerror(errno), sock_fd);
        return -1;
    }

    uint16_t port = ntohs(remote.sin6_port);
    printf("(ICMPv6): remote_port=%u, src_port=%u", \
                            port, udp_server_port);
    char ip[IP_BUF_SIZE] = {0};
    inet_ntop(AF_INET6, &remote.sin6_addr, ip, sizeof(ip));
    printf("(ICMPv6): remote_ip=%s, src_ip=%s", \
                            ip, udp_server_ip);
    udp_fw_t *fw = NULL;
    ret = find_fw_node(ip, port, &fw);
    if (0 != ret || NULL == fw) {
        return -1;
    }
    alive = &fw->alive;

    printf("(ICMPv6): recvmsg: ret=%d errno=%d err=%s fd=%d \n", \
                            ret, errno, strerror(errno), sock_fd);
    // err=11, dispose for the time being
    // need fixed
    if (0 != errno) {
        *alive = -1;
        return 0;
    } else {
        return -1;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        /* ip level */
        if (cmsg->cmsg_level == SOL_IPV6) {
            /* We received an error */
            if (cmsg->cmsg_type == IPV6_RECVERR) {
                //LOG(LOG_DBG, "We got IP_RECVERR message.");
                sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
                if (NULL != sock_err) {
                    /* We are intrested in ICMP errors */
                    if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) {
                        /* Handle ICMP errors types */
                        switch (sock_err->ee_type) {
                            case ICMPV6_NOROUTE: {
                                printf("ICMPv6 Network Unreachable Error! \n");
                                *alive = -1;
                            } break;
                            case ICMPV6_DEST_UNREACH: {
                                printf("ICMPv6 Dst Unreachable Error! \n");
                                *alive = -1;
                            } break;
                            case ICMPV6_ADDR_UNREACH: {
                                printf("ICMPv6 Dst Addr Unreachable Error! \n");
                                *alive = -1;
                            } break;
                            case ICMPV6_PORT_UNREACH: {
                                printf("ICMPv6 Port Unreachable Error! ip=%s,port=%u \n", \
                                                                    ip, port);
                                *alive = -1;
                            } break;
                            default:
                                break;
                        }
                    }
                }
            }
        }
    }

    return 0;
}

static void *__rcv_icmp_error(void *arg)
{
    rx_icmp_err_t *rx_icmp = arg;
    char opt = 1;

    while (*rx_icmp->running) {
        if (1 == *rx_icmp->icmp_switch) {
            if (0 == opt) {
                opt = 1;
                if (AF_INET == *rx_icmp->domain) {
                    setsockopt(rx_icmp->sock_fd, SOL_IP, IP_RECVERR, \
                               &opt, sizeof(opt));
                } else if (AF_INET6 == *rx_icmp->domain) {
                    setsockopt(rx_icmp->sock_fd, SOL_IPV6, IPV6_RECVERR, \
                               &opt, sizeof(opt));
                }
            }

            if (AF_INET == *rx_icmp->domain) {
                udp_rcv_icmpv4_err(rx_icmp->sock_fd, NULL, 0, NULL);
            } else if (AF_INET6 == *rx_icmp->domain) {
                udp_rcv_icmpv6_err(rx_icmp->sock_fd, NULL, 0, NULL);
            }
        } else {
            if (1 == opt) {
                opt = 0;
                if (AF_INET == *rx_icmp->domain) {
                    setsockopt(rx_icmp->sock_fd, SOL_IP, IP_RECVERR, \
                               (char*)&opt, sizeof(opt));
                } else if (AF_INET6 == *rx_icmp->domain) {
                    setsockopt(rx_icmp->sock_fd, SOL_IPV6, IPV6_RECVERR, \
                               (char*)&opt, sizeof(opt));
                }
            }
        }
        usleep(20);
    }
}


int main(int argc, char **argv)
{
    if (3 > argc) {
        usage();
        goto EXIT;
    }
    printf(" ICMP bind local [ip=%s, port=%u] \n", \
                            argv[1], atoi(argv[2]));
    printf(" ICMP tx remote [ip=%s, port=%u] \n", \
                            argv[3], atoi(argv[4]));

    int ret = -1;
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    pthread_t ptid;
    uint8_t icmp_switch = 1;
    int domain = -1;
    domain = check_ip_addr(argv[1]);
    if ((AF_INET != domain) && (AF_INET6 != domain)) {
        printf("illegal local ip format! \n");
        goto EXIT;
    }

    g_running = true;
    ret = signal_register(signal_hander_func);
    if (-1 == ret) {
        printf("signal_reg failed! \n");
        goto EXIT;
    }

    int sock_fd = -1;
    sock_fd = socket(domain, SOCK_DGRAM, 0);
    if (-1 == sock_fd) {
        printf("create socket failed! errno=%u, err=%s \n", \
                                        errno, strerror(errno));
        goto EXIT;
    }
    printf(" sock_fd=%d \n", sock_fd);

    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    ret = gen_sock_net_addr(domain, argv[1], atoi(argv[2]), &addr4, &addr6);
    if (-1 == ret) {
        printf("gen_sock_net_addr failed! \n");
        goto EXIT;
    }
    const char opt = 1;
    // Set the option, so we can receive errors
    if (AF_INET == domain) {
        ret = setsockopt(sock_fd, SOL_IP, IP_RECVERR, &opt, sizeof(opt));
        if (-1 == ret) {
            printf(" set sock IP_RECVERR failed! errno=%u, err=%s \n", \
                                                errno, strerror(errno));
            goto EXIT;
        }
        ret = bind(sock_fd, (struct sockaddr*)&addr4, \
                   sizeof(struct sockaddr_in));
    } else if (AF_INET6 == domain) {
        ret = setsockopt(sock_fd, SOL_IPV6, IPV6_RECVERR, &opt, sizeof(opt));
        if (-1 == ret) {
            printf(" set sock IPV6_RECVERR failed! errno=%u, err=%s \n", \
                                                errno, strerror(errno));
            goto EXIT;
        }
        ret = bind(sock_fd, (struct sockaddr*)&addr6, \
                   sizeof(struct sockaddr_in6));
    }
    if (-1 == ret) {
        printf("bind failed! errno=%u, err=%s \n", \
                            errno, strerror(errno));
        goto EXIT;
    }

    // tmp add outgroup for test
    memset(g_outgroup, 0, sizeof(outgroup_info_t) * MAX_OUTGROUP_NUM);
    g_outgroup[1].id = 1;
    g_outgroup[1].fw_num = 2;
    udp_fw_t udp_fw;
    memset(&udp_fw, 0, sizeof(udp_fw));
    strcpy(g_outgroup[1].fw_list[1].ip, TEST_REMOTE_IP1);
    g_outgroup[1].fw_list[1].port = TEST_REMOTE_PORT1;
    strcpy(g_outgroup[1].fw_list[2].ip, TEST_REMOTE_IP1);
    g_outgroup[1].fw_list[2].port = TEST_REMOTE_PORT2;

    // start another thread for rcv icmp err
    rx_icmp_err_t rx_icmp;
    memset(&rx_icmp, 0, sizeof(rx_icmp_err_t));
    rx_icmp.running = &g_running;
    rx_icmp.sock_fd = sock_fd;
    rx_icmp.icmp_switch = &icmp_switch;
    rx_icmp.domain = &domain;
    // set thread attribute
    ret = pthread_attr_init(&attr);
    if (0 != ret) {
        printf(" pthread_attr_init failed! \n");
        goto EXIT;
    }
    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (0 != ret) {
        printf("pthread_attr_setdetachstate failed! \n");
        goto EXIT;
    }
    ret = pthread_create(&ptid, &attr, &__rcv_icmp_error, &rx_icmp);
    if (0 != ret) {
        printf("create pthread failed! \n");
        goto EXIT;
    }

    outgroup_info_t *outgroup = NULL;
    uint32_t outgroup_id = 1;
    uint32_t fw_idx = 1;
    uint64_t start_ts = gettime_us_hp();
    uint64_t end_ts = 0;
    uint8_t tx_cnt = 0;
    while (g_running) {
        end_ts = gettime_us_hp();
        if (ICMP_RECOVER_PERIOD <= (end_ts - start_ts)) {
            for (outgroup_id=1; outgroup_id<=MAX_OUTGROUP_NUM; outgroup_id++) {
                ret = find_outgroup(outgroup_id, &outgroup);
                if ((0 != ret) || (NULL == outgroup)) {
                    continue;
                }
                printf("fw_num=%u, oid=%u \n", \
                        outgroup->fw_num, outgroup->id);
                for (fw_idx=1; fw_idx<=outgroup->fw_num; fw_idx++) {
                    tx_cnt = 0;
                    printf("recover %u_udp_fw \n", fw_idx);
                    outgroup->fw_list[fw_idx].alive = 1;
                    printf("fw_ip=%s, fw_port=%u \n", \
                            outgroup->fw_list[fw_idx].ip, \
                            outgroup->fw_list[fw_idx].port);
                    while (tx_cnt < IMCP_MAX_TX_CNT) {
                        udp_snd_zero_payload(sock_fd, \
                                             outgroup->fw_list[fw_idx].ip, \
                                             outgroup->fw_list[fw_idx].port);
                        tx_cnt++;
                    }
                }
            }
            start_ts = end_ts;
        }

        usleep(10000);
    } // while (run_info->running)

EXIT:

    ret = pthread_attr_destroy(&attr);
    if (0 != ret) {
        printf("pthread_attr_destroy err:%d \n", ret);
    }

    if (-1 != sock_fd) {
        close(sock_fd);
        sock_fd = -1;
    }

    printf("\n exit.. \n");
    return 0;
}
