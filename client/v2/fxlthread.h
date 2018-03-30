#ifndef FXLTHREAD_H
#define FXLTHREAD_H

#ifdef _LINUX_
#define FUNCALLBACK void *
#define THDHANDLE ptheread_t
#define ThreadCreate(th,fun,prm) {int nRet = pthread_create(&th,NULL,fun,prm);}
#define WaitForThreadEnd(th) {void *p = NULL; pthread_join(th,&p);}
#define ThreadDetach(th) {pthread_detach(th);}
#define ThreadClose(th)
#define SocketClose(sock) close(sock)
#endif //_LINUX_

#endif  //FXLTHREAD_H
