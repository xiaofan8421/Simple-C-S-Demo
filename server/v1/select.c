/* system headers */
#include <stdio.h> // printf
#include <stdlib.h> // atoi
#include <string.h> // strcpy, strncpy, memset, strerror
#include <stdbool.h> // bool
#include <signal.h> // signal
#include <stdint.h> // uint16_t
#include <unistd.h> // close, fcntl, select, read, write
#include <fcntl.h>  // fcntl
#include <sys/types.h>  // socket, setsockopt, inet_addr, select, accept
#include <sys/socket.h> // socket, setsockopt, bind, listen, accept, getpeername
#include <netinet/in.h> // inet_addr, listen
#include <arpa/inet.h> // inet_pton, inet_addr, htons, inet_ntop, ntohs
#include <errno.h> // errno
#include <sys/select.h> // select
#include <sys/time.h> // select
#include <assert.h> // assert


//
#define IP_V4       "0.0.0.0"
#define IP_V6       "::"
#define PORT        50001
#define BUF_IP      40
#define BUF_TMP     128
#define MAX_ARRAY_SIZE 1024


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

int setNonBlock(int sockfd)
{
    int opts = -1;

    opts = fcntl(sockfd, F_GETFL);
    if(-1 == opts)
    {
        perror("fcntl() F_GETFL");
        printf("fcntl() F_GETFL failed!!! errno=%d\n", errno);
        return -1;
    }

    opts |= O_NONBLOCK; 
    opts = fcntl(sockfd, F_SETFL, opts);
    if(-1 == opts)
    {
        perror("fcntl() F_SETFL");
        printf("fcntl() F_SETFL failed!!! errno=%d\n", errno);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int nRet = 0;
    int nServerSocket = 0;
    int nClientSocket = 0;
    struct sockaddr_in tServerAddr;
    struct sockaddr_in tClientAddr;
    socklen_t nAddrLen = 0;
    char szBuff[MAX_ARRAY_SIZE + 1] = {0};
    char szIp[30] = {0};
    int nPort = 0;
    int nClientCount = 0;
    int nMaxFd = 0;
    fd_set set, rset;
    struct timeval tTime;
    int on = 1;

    g_running = true;
    nRet = signal_register(signal_hander_func);
    if (-1 == nRet) {
        printf("signal_reg failed! \n");
        return -1;
    }

    nServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == nServerSocket)
    {
        perror("socket()");
        printf("socket() failed!!! error=%d\n", errno);
        return -1;
    }

    nRet = setsockopt(nServerSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    if (-1 == nRet)
    {
        perror("setsockopt()");
        printf("setsockopt() failed!!! error=%d\n", errno);
        return -1;
    }
    assert(0 == nRet);

    memset(&tServerAddr, 0, sizeof(tServerAddr));
    tServerAddr.sin_family = AF_INET;
    tServerAddr.sin_port = htons(11024);
    tServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    nAddrLen = sizeof(tServerAddr);
    nRet = bind(nServerSocket, (struct sockaddr *)&tServerAddr, nAddrLen);
    if (-1 == nRet)
    {
        perror("bind()");
        printf("bind() failed!!! error=%d\n", errno);
        return -1;
    }
    assert(0 == nRet);

    nRet = listen(nServerSocket, 20);
    if (-1 == nRet)
    {
        perror("listen()");
        printf("listen() failed!!! error=%d\n", errno);
        return -1;
    }
    assert(0 == nRet);

    printf("listening....\n");

    FD_ZERO(&set);
    FD_SET(STDIN_FILENO, &set);
    nMaxFd = STDIN_FILENO;
    FD_SET(nServerSocket, &set);
    if (nMaxFd < nServerSocket)
        nMaxFd = nServerSocket;

    for (;;)
    {
        rset = set;
        //nRet = select(nMaxFd+1, &rset, NULL, NULL, -1); //非阻塞调用select
        //nRet = select(nMaxFd+1, &rset, NULL, NULL, NULL); //阻塞调用select
        tTime.tv_sec = 10;
        tTime.tv_usec = 0;
        nRet = select(nMaxFd + 1, &rset, NULL, NULL, &tTime); //设定10秒阻塞超时，超时后仍没有可读事件则返回0
        if (0 > nRet)
        {
            if (errno == EINTR)
                continue;
            printf("select failed!!! errno=%d\n", errno);
            continue;
        }
        else if (0 == nRet)
        {
            //tTime.tv_sec  = 10;
            //tTime.tv_usec = 0;
            printf("select timeout\n");
            continue;
        }

        if (FD_ISSET(nServerSocket, &rset))
        {
            nAddrLen = sizeof(tClientAddr);
            nClientSocket = accept(nServerSocket, (struct sockaddr *)&tClientAddr, &nAddrLen);
            if (-1 == nClientSocket)
            {
                perror("accept()");
                printf("accept() failed!!! error=%d\n", errno);
                continue;
            }
            assert(nClientSocket >= 0);

            nClientCount++;
            printf("\ncurrent client number:%d\n", nClientCount);
            nPort = ntohs(tClientAddr.sin_port);
            inet_ntop(AF_INET, &tClientAddr.sin_addr, szIp, sizeof szIp);
            printf("New Connection: Client's [IP=%s], [port=%d]\n", szIp, nPort);

            FD_SET(nClientSocket, &set);
            if (nMaxFd < nClientSocket)
                nMaxFd = nClientSocket;
            continue;
        }

        if (FD_ISSET(STDIN_FILENO, &rset))
        {
            nRet = read(STDIN_FILENO, szBuff, sizeof(szBuff) - 1);
            if (0 > nRet)
            {
                printf("read STDIN_FILENO error\n");
                continue;
            }
            else if (0 == nRet)
            {
                continue;
            }

            printf("nRet=%d\n", nRet);

            szBuff[nRet - 1] = '\0';
            if (!strcmp(szBuff, "quit"))
                break;
            else if (!strcmp(szBuff, "count -client"))
                printf("Current client's num:%d\n", nClientCount);
            else
                system(szBuff);

            continue;
        }

        for (int i = 0; i <= nMaxFd; i++)
        {
            if (nServerSocket == i)
                continue;

            if (FD_ISSET(i, &rset))
            {
                int nClientFd = i;

                if (-1 == getpeername(nClientFd, (struct sockaddr *)&tClientAddr, &nAddrLen))
                {
                    perror("getpeername()");
                    printf("getpeername() errno=%d\n", errno);
                    continue;
                }
                nPort = ntohs(tClientAddr.sin_port);
                inet_ntop(AF_INET, &tClientAddr.sin_addr, szIp, sizeof szIp);
                //printf("Client's [IP=%s], [port=%d]\n", szIp, nPort);

                memset(szBuff, 0, sizeof(szBuff));
                nRet = read(nClientFd, szBuff, sizeof(szBuff) - 1);
                if (0 == nRet)
                {
                    printf("\nclient [ip=%s]:[port=%d] closed !!!\n", szIp, nPort);
                    FD_CLR(nClientFd, &set);
                    close(nClientFd);
                    nClientCount--;
                    continue;
                }
                else if (0 > nRet)
                {
                    assert(-1 == nRet);
                    perror("read()");
                    printf("\nrecv from client [ip=%s]:[port=%d] failed !!! errno=%d\n", szIp, nPort, errno);
                    continue;
                }

                szBuff[nRet - 1] = '\0';
                printf("\nSuccessfully recv from client's [ip=%s]:[port=%d] %d bytes: %s\n", szIp, nPort, nRet, szBuff);

                if (!strcmp(szBuff, "quit") || !strcmp(szBuff, "exit"))
                {
                    FD_CLR(nClientFd, &set);
                    close(nClientFd);
                    nClientCount--;
                    printf("\nclient Active closed\n");
                    continue;
                }

                memset(szBuff, 0, sizeof(szBuff));
                strcpy(szBuff, "hello client! I'm select server");
                nRet = write(nClientSocket, szBuff, strlen(szBuff));
                if (0 > nRet)
                {
                    assert(-1 == nRet);
                    perror("write()");
                    printf("\nsend to client [ip=%s]:[port=%d] failed !!! errno=%d\n", szIp, nPort, errno);
                    break;
                }

                szBuff[nRet] = '\0';
                printf("\nSuccessfully send msg to client's [ip=%s]:[port=%d] %d bytes: %s\n", szIp, nPort, nRet, szBuff);
            }
        }
    }

    close(nServerSocket);

    return 0;
}
