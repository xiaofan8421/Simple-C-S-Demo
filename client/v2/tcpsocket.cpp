#include "tcpsocket.h"

CTcpSocket::CTcpSocket()
{
    m_nSocket = INVALID_SOCKET;
    m_hThd = NULL;
    m_bRun = FALSE;

    memset(m_achBuf, 0, sizeof(m_achBuf));
    m_nBufLen = 0;
    m_wNeedRcvLen = 0;
}

CTcpSocket::~CTcpSocket()
{
    Destroy();
}


BOOL32 CTcpSocket::Create(u32 dwSvrIp, u16 dwSvrPort, pFuncRcvDataCB pRcvDataiCb, void *pContent)
{
   m_pRcvDataCB = pRcvDataiCb;
   m_pUsrContent = pContent;



    return TRUE;
}

void CTcpSocket::Destroy()
{

}

BOOL32 CTcpSocket::SendMsg()
{

    return TRUE;
}

BOOL32 CTcpSocket::SetSocketOption(SOCKET socket, BOOL32 bNonBlock)
{


    return TRUE;
}

void 

/*
int main(int argc, char **argv)
{


    return 0;
}
*/
