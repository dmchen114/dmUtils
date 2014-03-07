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
typedef CRITICAL_SECTION DM_LOCK_T;
typedef HANDLE LPDM_MUTEX;
typedef HANDLE LPDM_EVENT;
typedef HANDLE LPDM_SEMAPHORE;

typedef struct {
    HANDLE map;
    void *data;
    unsigned long size;
}DM_MMAP, *LPDM_MMAP;
typedef unsigned int size_t;
typedef HANDLE FILEDESC;
#define NULL_FILE_DESC   NULL
#define THREAD_LOCAL __declspec(thread)
#ifndef __cplusplus
typedef char bool;
#endif

#ifndef true
#define true	1
#define false	0
#endif

#define EVENT_WAIT_NORMAL   WAIT_OBJECT_0
#define EVENT_WAIT_TIMEOUT  WAIT_TIMEOUT
#define EVENT_WAIT_ABANDON  WAIT_ABANDONED
#define EVENT_WAIT_FAILURE  WAIT_FAILED

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
typedef pthread_mutex_t DM_LOCK_T;
typedef struct {
    void *data;
    unsigned long size;
}DM_MMAP, *LPDM_MMAP;
typedef struct{
    pthread_mutex_t *mutex;
    LPDM_MMAP context;
}DM_MUTEX, *LPDM_MUTEX;
typedef struct{
    pthread_cond_t *cond;
    pthread_mutex_t *mutex;
    LPDM_MMAP context;
}DM_EVENT, *LPDM_EVENT;
typedef struct{
    struct sem_t * sem;
    LPDM_MMAP context;
}DM_SEMAPHORE, *LPDM_SEMAPHORE;

typedef int FILEDESC;
#define NULL_FILE_DESC  0
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

#define EVENT_WAIT_NORMAL   0
#define EVENT_WAIT_TIMEOUT  ETIMEDOUT
#define EVENT_WAIT_ABANDON  EINVAL
#define EVENT_WAIT_FAILURE  EINVAL

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

/**
 * Mutex
 */
LPDM_MUTEX mutexNew(const char *name);
void mutexFree(LPDM_MUTEX m);
/*timeout in milliseconds, -1 for infinite.*/
unsigned long mutexLock(LPDM_MUTEX m, int timeout);
void mutexUnLock(LPDM_MUTEX m);

/**
 * Event
 **/
LPDM_EVENT eventNew(const char *name);
void eventFree(LPDM_EVENT e);
void eventSignal(LPDM_EVENT e);
/*timeout in milliseconds, -1 for infinite.*/
unsigned long eventWait(LPDM_EVENT e, int timeout);

/**
 *Lock
 */
void InitLock(DM_LOCK_T* pLock);
void Lock(DM_LOCK_T* pLock);
void UnLock(DM_LOCK_T* pLock);
void UnInitLock(DM_LOCK_T* pLock);

/**
 * Memory Map
 */
LPDM_MMAP mmapOpen(const char *path, unsigned long size);
void mmapClose(LPDM_MMAP m);

/**
 * Threads and processes
 */
typedef long (*DM_THREAD_CALLBACK)(void *arg);
typedef struct {
#ifdef WIN32
    HANDLE hThread;
    DWORD dwThreadId;
#else
    pthread_t hThread;
#endif
    DM_THREAD_CALLBACK cb;
    void *userdata;
}DM_THREAD, *LPDM_THREAD;

LPDM_THREAD thrNew(DM_THREAD_CALLBACK cb, void *userdata);
/** timeout in milliseconds*/
long thrJoin(LPDM_THREAD thr, int *exitcode, int timeout);

typedef struct {
#ifdef WIN32
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
#else
    pid_t dwProcessId;
#endif
    DM_THREAD_CALLBACK cb;
    void *userdata;
}DM_PROCESS, *LPDM_PROCESS;

LPDM_PROCESS procFork(DM_THREAD_CALLBACK cb, void *userdata);
long procJoin(LPDM_PROCESS proc, int *exitcode, int timeout);

/**
 * File IO
 */
FILEDESC fileOpen(const char* fileName, const char *mode);
void fileClose(FILEDESC fd);
int fileRead(FILEDESC fd, char *pData, size_t nLen);
int fileWrite(FILEDESC fd, char *pData, size_t nLen);
void fileFlush(FILEDESC fd);
size_t fileGetSize(FILEDESC fd);

/**
 * Logs
 */
/**
 * DMLog enables SYSLOG,CONSOLE,FILE, MMAP log drivers, you can select them when initialize, 
 * The behavior of different drivers is defined:
 *   - SYSLOG(1): 
 *       Windows> we use OutputDebugString, so you can use DebugView/Visual Studio to view.
 *       Linux>   we use syslog, you can find out the log under 
 *                /var/log/messages(CentOS) or /var/log/syslog(Ubuntu) or others..
 *       Android> it is logcat
 *             ...
 *   - CONSOLE(2): it just printf to console
 *   - FILE(3): it will write directly to a file in the same folder as binary, 
 *              it will not rotate and is slow when IO is not fast. NOT RECOMMENDED.
 *   - MMAP(4): it will write to a memory map file, it needs another binary called `dmlogd` 
 *              to capture them to files or any other places, for example, a server.
 *              This method is fast, and the default `dmlogd` provided in dmUtils can
 *              write to rotatable files with daily IO limitation, a python script is also
 *              available for CI to capture the logs.
 */

enum{
    LOG_DRIVER_SYSLOG = 1,
    LOG_DRIVER_CONSOLE = 2,
    LOG_DRIVER_FILE = 3,
    LOG_DRIVER_MMAP =4,
    LOG_DRIVER_MAX = 5
};

void logInit(int logType, const char* lpszPath);
void logUnInit();
void logEnableLevel(int level);
void dmLogMessage(int level, const char* filename, int lineno, const char *format, ...);

enum
{
    logDebugLevel,
    logInfoLevel,
    logWarningLevel,
    logErrorLevel,
    logLevelCount
};

#if defined(ENABLE_DMLOG)
	#if defined ANDROID
        #define ENABLE_ANDROIDLOG
		#include <utils/Log.h>
    #else
    #endif
	#if defined(__IPHONE__) || defined(__APPLE_CC__) || defined(__GNUC__)
		#define logDebug(format, args...) dmLogMessage(logDebugLevel, __FILE__, __LINE__, format, ##args)
		#define logInfo(format, args...) dmLogMessage(logInfoLevel, __FILE__, __LINE__, format, ##args)
		#define logWarning(format, args...) dmLogMessage(logWarningLevel, __FILE__, __LINE__, format, ##args)
		#define logError(format, args...) dmLogMessage(logErrorLevel, __FILE__, __LINE__, format, ##args)
	#else
		#define logDebug(format, ...) dmLogMessage(logDebugLevel, __FILE__, __LINE__, format, __VA_ARGS__)
		#define logInfo(format, ...) dmLogMessage(logInfoLevel, __FILE__, __LINE__, format, __VA_ARGS__)
		#define logWarning(format, ...) dmLogMessage(logWarningLevel, __FILE__, __LINE__, format, __VA_ARGS__)
		#define logError(format, ...) dmLogMessage(logErrorLevel, __FILE__, __LINE__, format, __VA_ARGS__)
	#endif
#else
		#define logDebug(...) 
		#define logInfo(...) 
		#define logWarning(...) 
		#define logError(...) 
#endif

int mmapLogWrite(const char *buffer, uint16_t len);
int mmapLogReadLine(char *buffer, uint16_t len);
int mmapLogWaitEvent(int timeout);

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

const char* dmBasename(char* path);
/////////////////////////////////////////////////////////////////////
//Parse address from format xx.xx.xx.xx:xxxx into IP and port
/////////////////////////////////////////////////////////////////////
void ParseAddr(unsigned char* szIn, unsigned short* pPort, char* pIP, int nIPLen);
unsigned long hextobin(const char *input, unsigned long len, char **out);
unsigned long bintohex(const char *input, unsigned long len, char **out);

#ifdef __cplusplus
}
#endif

#define UNUSED(x) (void)(x)
#define FREEBUF(x) if(x){ free(x); (x) = NULL;}

#endif //!define _DM_TRANSPORT_COMMON_H_INCLUDED_
