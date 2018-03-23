#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#define MAX_ARRAY_SIZE 1024

int main(int argc, char **argv)
{
    int nSocketId = 0;
    int nRet = 0;
    struct sockaddr_in tServerAddr;
    char szBuff[MAX_ARRAY_SIZE+1] = {0};
    int nPort = 11024;

    nSocketId = socket(AF_INET, SOCK_STREAM, 0);
    if(-1 == nSocketId)
    {
        perror("socket()");
        printf("socket() failed!!! error=%d\n", errno);
        return -1;
    }    

    if(argc == 2)
    {
        nPort = atoi(argv[1]);
    }
    tServerAddr.sin_family = AF_INET;
    tServerAddr.sin_port = htons(nPort);
    inet_pton(AF_INET, "104.168.134.206", &tServerAddr.sin_addr.s_addr);

    nRet = connect(nSocketId, (struct sockaddr*)&tServerAddr, sizeof(tServerAddr));
    if(-1 == nRet)
    {
        perror("connect()");
        printf("connect() failed!!! error=%d\n", errno);
        return -1;
    }
    assert(0 == nRet);

    printf("connect server successed!!!\n");

    while(1)
    {
        memset(szBuff, 0, sizeof(szBuff));
        strcpy(szBuff, "Please input your msg:");
        write(STDOUT_FILENO, szBuff, strlen(szBuff));

        memset(szBuff, 0, sizeof(szBuff));
        nRet = read(STDIN_FILENO, szBuff, sizeof(szBuff)-1);
        /*
        while(1)
        {
            nRet = read(STDIN_FILENO, szBuff, sizeof(szBuff));
        }
        */
        nRet = write(nSocketId, szBuff, strlen(szBuff));
        if(0 > nRet)
        {
            assert(-1 == nRet);
            perror("write()");
            printf("send msg to server failed!!! error=%d\n", errno);
            continue;
        }

        if(!strcmp(szBuff, "quit") || !strcmp(szBuff, "exit"))
        {
            printf("client is quiting...i\n");
            break;
        }

        szBuff[nRet] = '\0';
        printf("Send: %s\n", szBuff);
        
        memset(szBuff, 0, sizeof(szBuff));
        nRet = read(nSocketId, szBuff, sizeof(szBuff));
        if(0 > nRet)
        {
            assert(-1 == nRet);
            perror("read()");
            printf("recv msg from server failed!!! errro=%d\n", errno);
            break;
        }
        else if(0 == nRet)
        {
            printf("disconnected to server!!!\n");
            break;
        }
        
        szBuff[nRet] = '\0';
        printf("Recv: %s\n", szBuff);

        if(!strcmp(szBuff, "netstat -plantu"))
        {
            system(szBuff);
        }

        if(!strcmp(szBuff, "quit") || !strcmp(szBuff, "exit"))
        {
            break;
        }

    }

    close(nSocketId);

    return 0;
}
