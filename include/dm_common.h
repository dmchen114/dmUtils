#if !defined(_DM_TRANSPORT_COMMON_H_INCLUDED_)
#define _DM_TRANSPORT_COMMON_H_INCLUDED_

#pragma once

#ifdef WIN32

#include "winsock2.h"
#include "windows.h"
#include "time.h"

typedef int socklen_t;
typedef SOCKET Socket;
extern HINSTANCE g_hInstance;
typedef CRITICAL_SECTION THREAD_MUTEX_T;
typedef unsigned int size_t;
typedef HANDLE FILEDESC;
#define THREAD_LOCAL __declspec(thread)
#ifndef __cplusplus
typedef char bool;
#endif

#ifndef true
#define true	1
#define false	0
#endif

#define MY_EADDRINUSE		WSAEADDRINUSE
#define MY_EADDRNOTAVAIL	WSAEADDRNOTAVAIL
#define MY_ECONNREFUSED		WSAECONNREFUSED
#define MY_ETIMEDOUT		WSAETIMEDOUT
#define MY_ENOTSOCK			WSAENOTSOCK
#define MY_ECONNRESET		WSAECONNRESET
#define MY_EHOSTDOWN		WSAEHOSTDOWN
#define MY_EHOSTUNREACH		WSAEHOSTUNREACH
#define MY_EAFNOSUPPORT		WSAEAFNOSUPPORT
#define MY_EWOULDBLOCK		WSAEWOULDBLOCK
#define MY_EINPROGRESS		WSAEINPROGRESS
#define	MY_ECONNABORTED		WSAECONNABORTED
#define INLINE			__inline

#else

#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#ifdef _LINUX_
#include <sys/epoll.h>
#include <error.h>
#endif
#include <sys/time.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <netdb.h>

#define SOCKET int
#define Socket int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
typedef pthread_mutex_t THREAD_MUTEX_T;
typedef int FILEDESC;
#define THREAD_LOCAL __thread

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#if !defined(_countof)
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#define strcpy_s(a,b,c) strcpy(a,c)
#define gets_s(a,b)	gets(a)
#define closesocket close
#define memcpy_s(a,b,c,d) memcpy(a, c, d)
#define sprintf_s snprintf
#define vsprintf_s vsnprintf
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#if !defined __IPHONE__
#define INLINE inline
#else
#define INLINE
#endif
#define SD_BOTH 2

#define MY_EADDRINUSE		EADDRINUSE		
#define MY_EADDRNOTAVAIL	EADDRNOTAVAIL	
#define MY_ECONNREFUSED		ECONNREFUSED	
#define MY_ETIMEDOUT		ETIMEDOUT		
#define MY_ENOTSOCK			ENOTSOCK		
#define MY_ECONNRESET		ECONNRESET		
#define MY_EHOSTDOWN		EHOSTDOWN		
#define MY_EHOSTUNREACH		EHOSTUNREACH	
#define MY_EAFNOSUPPORT		EAFNOSUPPORT	
#define MY_EWOULDBLOCK		EWOULDBLOCK		
#define MY_EINPROGRESS		EINPROGRESS		
#define	MY_ECONNABORTED		ECONNABORTED	

#endif

#include "stdio.h"
#include <stdlib.h>
#include "stdint.h"
#include <errno.h>
#include "string.h"
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////
//Mutex
/////////////////////////////////////////////////
void InitLock(THREAD_MUTEX_T* pLock);
void Lock(THREAD_MUTEX_T* pLock);
void UnLock(THREAD_MUTEX_T* pLock);
void UnInitLock(THREAD_MUTEX_T* pLock);

////////////////////////////////
//File IO
////////////////////////////////
FILEDESC OpenFD(const char* fileName, const char *mode);
void CloseFD(FILEDESC fd);
int ReadFD(FILEDESC fd, char *pData, size_t nLen);
int WriteFD(FILEDESC fd, char *pData, size_t nLen);
size_t GetFileSizeFD(FILEDESC fd);

/////////////////////////////////////////////////
//Logs
/////////////////////////////////////////////////
enum
{
	logDebug,
	logInfo,
	logWarning,
	logError
};

void InitLog(const char* lpszPath);
void UnInitLog();
#if defined ENABLE_DMLOG
	#if defined ANDROID && defined ENABLE_ANDROIDLOG
		#include <utils/Log.h>
		#define logDebug ANDROID_LOG_DEBUG
		#define logWarning ANDROID_LOG_WARN
		#define logInfo ANDROID_LOG_INFO
		#define logError ANDROID_LOG_ERROR
		#define logMessage(LEVEL,...) __android_log_print(LEVEL,__FILE__,__VA_ARGS__)
	#elif defined __IPHONE__
		//#define logMessage(LEVEL,msg_fmt,args...) printf("[%s %d]" msg_fmt "\n",__FILE__,__LINE__,##args)
		#define logMessage(LEVEL,msg_fmt,args...) printf("[%d]" msg_fmt "\n",__LINE__,##args)
	#else
		void logMessage(int level, const char *format, ...);
	#endif
#else
	#define logMessage
#endif

/*
 * Command line functions
 * You MUST NOT call optGet before optInit or after optExitOnHelp
 * This is not the best command line parser interface in C, the only advance is it will yield to the least
 * code line while you are using it. A more elegant or comman way is to call get_opt_long instead.
 */
void optInit(int argc, char** argv);
const char* optGet(const char* lname, const char sname, int hasArg, int isMust, 
                   const char* desc, const char* defVal);
void optExitOnInvalid();

/////////////////////////////////////////////////////////////////////
//Parse address from format xx.xx.xx.xx:xxxx into IP and port
/////////////////////////////////////////////////////////////////////
void ParseAddr(unsigned char* szIn, unsigned short* pPort, char* pIP, int nIPLen);
unsigned long hextobin(const char *input, unsigned long len, char **out);
unsigned long bintohex(const char *input, unsigned long len, char **out);

#ifdef __cplusplus
}
#endif

#define P2P_PORT			17600
#define SERVER_CAPACITY		2048
#define UNUSED(x) (void)(x)
#define FREEBUF(x) if(x){ free(x); (x) = NULL;}

#endif //!define _DM_TRANSPORT_COMMON_H_INCLUDED_
