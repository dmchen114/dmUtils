#include "dm_common.h"

#if defined(ENABLE_DMLOG) && (ENABLE_DMLOG > LOG_DRIVER_MMAP)
    #undef ENABLE_DMLOG
    #define ENABLE_DMLOG LOG_DRIVER_SYSLOG
#endif

#if (ENABLE_DMLOG == LOG_DRIVER_MMAP)
#include <sys/mman.h>
typedef struct {
    uint64_t magic_code;    //Set to MAGIC value to mark it has been initialized.
    unsigned long writepos;
    unsigned long endpos;
}MMAP_FILE_HEADER;

#define LOG_MMAP_MAGIC_CODE 0x1AA901C671163914ULL

typedef struct{
    LPDM_MMAP handle;
    LPDM_MUTEX mutex;
    LPDM_EVENT event;
    unsigned long readpos;
}MMAP_LOG_FILE;

MMAP_LOG_FILE g_mmap_log;
#define NAMED_MUTEX_PATH    "/tmp/dm_log_mutex"
#define NAMED_EVENT_PATH    "/tmp/dm_log_event"
#define NAMED_MMAP_PATH     "/tmp/dm_log_mmap"
#define MMAP_LOG_FILE_SIZE  41943040    //40M
#endif

#if defined(ANDROID)
static int g_logLevelNative[logLevelCount] = {ANDROID_LOG_DEBUG, ANDROID_LOG_INFO, ANDROID_LOG_WARN, ANDROID_LOG_ERROR};
#elif defined(LINUX)
#include "syslog.h"
#include "sys/syscall.h"
static int g_logLevelNative[logLevelCount] = {LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR};
#else
static int g_logLevelNative[logLevelCount] = {0, 1, 2, 3};
#endif
static char g_logLevelString[logLevelCount] = {'D', 'I', 'W', 'E'};

/**
 * Mutex
 */
LPDM_MUTEX mutexNew(const char *name)
{
    LPDM_MUTEX m = NULL;
#ifdef WIN32
    m = CreateMutexA(NULL, FALSE, name);
    if(m == NULL){
        DWORD dwError = GetLastError();
        if(dwError == ERROR_ACCESS_DENIED)
            m = OpenMutexA(SYNCHRONIZE, FALSE, name);
    }
#else
	pthread_mutexattr_t mutexattr;

	pthread_mutexattr_init(&mutexattr);
    m = (LPDM_MUTEX)malloc(sizeof(DM_MUTEX));
    m->context = NULL;
    if(name){
        m->context = mmapOpen(name, sizeof(pthread_mutex_t));
        m->mutex = (pthread_mutex_t*)m->context->data;
        pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
    }
    else
        m->mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));

	pthread_mutex_init(m->mutex, &mutexattr);
	pthread_mutexattr_destroy(&mutexattr);
#endif
    return m;
}

void mutexFree(LPDM_MUTEX m)
{
#ifdef WIN32
    CloseHandle(m);
#else
    pthread_mutex_destroy(m->mutex);
    if(m->context)
        mmapClose(m->context);
    else
        free(m->mutex);
    free(m);
#endif
}

unsigned long mutexLock(LPDM_MUTEX m, int timeout)
{
#ifdef WIN32
    int to = timeout > 0 ? timeout : INFINITE;
    return WaitForSingleObject(m, to);
#else
    struct timespec to;
    if(timeout > 0)
    {
        to.tv_sec = timeout / 1000;
        to.tv_nsec = (timeout % 1000) * 1000000;
    }
    return pthread_mutex_timedlock(m->mutex, &to);
#endif
}

void mutexUnLock(LPDM_MUTEX m)
{
#ifdef WIN32
    ReleaseMutex(m);
#else
    pthread_mutex_unlock(m->mutex);
#endif
}

/**
 * Event
 **/
LPDM_EVENT eventNew(const char *name)
{
    LPDM_EVENT e;
#ifdef WIN32
    e = CreateEventA(NULL, FALSE, FALSE, name);
    return e;
#else
  	pthread_condattr_t condattr;
  	pthread_mutexattr_t mutexattr;

	pthread_condattr_init(&condattr);
	pthread_mutexattr_init(&mutexattr);
    e = (LPDM_EVENT)malloc(sizeof(DM_EVENT));
    e->context = NULL;
    if(name){
        e->context = mmapOpen(name, sizeof(pthread_cond_t) + sizeof(pthread_mutex_t));
        e->cond = (pthread_cond_t*)e->context->data;
        e->mutex = (pthread_mutex_t*)(e->context->data + sizeof(pthread_cond_t)); 
        pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
    }
    else{
        e->cond = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
        e->mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    }
	pthread_cond_init(e->cond, &condattr);
	pthread_mutex_init(e->mutex, &mutexattr);
	pthread_condattr_destroy(&condattr);
	pthread_mutexattr_destroy(&mutexattr);
    return e;
#endif
}

void eventFree(LPDM_EVENT e)
{
#ifdef WIN32
    CloseHandle(e);
#else
    pthread_cond_destroy(e->cond);
    pthread_mutex_destroy(e->mutex);
    if(e->context)
        mmapClose(e->context);
    else{
        free(e->mutex);
        free(e->cond);
    }
    free(e);
#endif
}

void eventSignal(LPDM_EVENT e)
{
#ifdef WIN32
    SetEvent(e);
#else
    pthread_cond_broadcast(e->cond);
#endif
}

/*timeout in milliseconds, -1 for infinite.*/
unsigned long eventWait(LPDM_EVENT e, int timeout)
{
#ifdef WIN32
    int to = timeout > 0 ? timeout : INFINITE;
    return WaitForSingleObject(e, to);
#else
    struct timespec to;
    if(timeout > 0)
    {
        to.tv_sec = timeout / 1000;
        to.tv_nsec = (timeout % 1000) * 1000000;
    }
    pthread_cond_timedwait(e->cond, e->mutex, &to);
#endif
}

/**
 * MMAP
 */
LPDM_MMAP mmapOpen(const char *path, unsigned long size)
{
    LPDM_MMAP m;
    m = (LPDM_MMAP)malloc(sizeof(DM_MMAP));
#ifdef WIN32
    m->map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, path);
    if(m->map == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create file mapping");
        free(m);
        return NULL;
    }
    m->data = MapViewOfFile(m->map, FILE_MAP_ALL_ACCESS, 0, 0, size);
    m->size = size;
#else
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0666);
    if(fd < 0){
        printf("Failed to create file from path.");
        free(m);
        return (NULL);
    }
    m->data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    m->size = size;
    close (fd);
    if(size > sizeof(unsigned long)){
        unsigned long *filepos = (unsigned long*)m->data;
        *filepos = sizeof(unsigned long);
    }
#endif
    return m;
}

void mmapClose(LPDM_MMAP m)
{
#ifdef WIN32
    UnmapViewOfFile(m->data);
    CloseHandle(m->map);
#else
    munmap(m->data, m->size);
#endif
    free(m);
}

#if (ENABLE_DMLOG == LOG_DRIVER_MMAP)
int mmapLogWrite(const char *buffer, uint16_t len)
{
    MMAP_FILE_HEADER *hd;
    char *mdata;
    mutexLock(g_mmap_log.mutex, -1);
    hd = (MMAP_FILE_HEADER*)g_mmap_log.handle->data;
    mdata = (char*)g_mmap_log.handle->data;
    if(len + hd->writepos + sizeof(uint16_t) > g_mmap_log.handle->size)    //We now rotate
    {
        hd->endpos = hd->writepos;
        hd->writepos = sizeof(MMAP_FILE_HEADER);
    }
    *((short*)(mdata + hd->writepos)) = len;
    memcpy_s(mdata + hd->writepos + sizeof(uint16_t), g_mmap_log.handle->size, buffer, len);
    hd->writepos += len + sizeof(uint16_t);
    if(hd->writepos > hd->endpos)
        hd->endpos = sizeof(MMAP_FILE_HEADER);
    mutexUnLock(g_mmap_log.mutex);
    eventSignal(g_mmap_log.event);

    return len;
}

int mmapLogReadLine(char *buffer, uint16_t len)
{
    MMAP_FILE_HEADER *hd;
    char *mdata;
    unsigned long rpos;
    int rlen;
    mutexLock(g_mmap_log.mutex, -1);
    hd = (MMAP_FILE_HEADER*)g_mmap_log.handle->data;
    mdata = (char*)g_mmap_log.handle->data;
    rpos = g_mmap_log.readpos;
    if(rpos == hd->writepos && hd->endpos == sizeof(MMAP_FILE_HEADER))
        rlen = -2;
    else
        rlen = *((uint16_t*)(mdata + rpos));

    if(rlen > 0 && len > rlen)
    {
        memcpy_s(buffer, len, mdata + rpos + sizeof(uint16_t), rlen);
        rpos += (rlen + sizeof(uint16_t));
        if(hd->endpos > hd->writepos && rpos >= hd->endpos)
            g_mmap_log.readpos = sizeof(MMAP_FILE_HEADER);
        else
            g_mmap_log.readpos = rpos;
    }
    else if(rlen > 0)
        rlen = -1;

    mutexUnLock(g_mmap_log.mutex);

    return rlen;
}

int mmapLogWaitEvent(int timeout)
{
    return eventWait(g_mmap_log.event, timeout);
}
#endif

/**
 * Lock
 */
void InitLock(DM_LOCK_T* pLock)
{
#ifdef WIN32
	InitializeCriticalSection(pLock);
#else
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
#if !defined __APPLE_CC__ 
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE_NP);
#else
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
#endif
	pthread_mutex_init(pLock, &mutexattr);
	pthread_mutexattr_destroy(&mutexattr);
#endif
}

void UnInitLock(DM_LOCK_T* pLock)
{
#ifdef WIN32
	DeleteCriticalSection(pLock);
#else
	pthread_mutex_destroy(pLock);
#endif // CM_WIN32
}

void Lock(DM_LOCK_T* pLock)
{
#ifdef WIN32
	EnterCriticalSection(pLock);
#else
	pthread_mutex_lock(pLock);
#endif
}

void UnLock(DM_LOCK_T* pLock)
{
#ifdef WIN32
	LeaveCriticalSection(pLock);
#else
	pthread_mutex_unlock(pLock);
#endif
}

///////////////////////////////
//File IO
///////////////////////////////
FILEDESC OpenFD(const char* fileName, const char *mode)
{
	FILEDESC fd = (FILEDESC) -1;
	int bRead = 0, bWrite = 0, bTrunc = 0, nModeLen = 3, i;
	int nMode = 0, dwCreationDisposition = 0;
	if(mode == NULL || fileName == NULL)
		return fd;
	nModeLen = min(strlen(mode), 3);
	for(i = 0; i < nModeLen; i++){
		switch(mode[i]){
		case 'r':
		case 'R':
			bRead = 1;
			break;
		case 'w':
		case 'W':
			bWrite = 1;
			break;
		case 't':
		case 'T':
			bTrunc = 1;
			break;
		default:
			break;
		}
	}
#ifdef WIN32
	//TODO, not ready
	if(bRead){
		nMode |= GENERIC_READ;
		dwCreationDisposition = OPEN_EXISTING;
	}
	if(bWrite){
		nMode |= GENERIC_WRITE;
	}
	if(bWrite && bTrunc){
		dwCreationDisposition = CREATE_ALWAYS;
	}else if(bWrite){
		dwCreationDisposition = OPEN_ALWAYS;
	}

	return CreateFile(fileName, nMode, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, dwCreationDisposition, 0, NULL);
#else
	UNUSED(dwCreationDisposition);
	if(bRead && !bWrite)
		nMode = O_RDONLY;
	if(bWrite && !bRead)
		nMode = O_WRONLY;
	if(bWrite && bRead)
		nMode = O_RDWR;
	if(bWrite)
		nMode |= O_CREAT;
	if(bTrunc)
		nMode |= O_TRUNC;

	return open(fileName, nMode);
#endif
}

void CloseFD(FILEDESC fd)
{
#ifdef WIN32
	CloseHandle(fd);
#else
	close(fd);
#endif
}

int ReadFD(FILEDESC fd, char *pData, size_t nLen)
{
#ifdef WIN32
	DWORD dwRead = 0;
	if(ReadFile(fd, pData, nLen, &dwRead, NULL))
		return dwRead;
	return -1;
#else
	return read(fd, pData, nLen);
#endif
}

int WriteFD(FILEDESC fd, char *pData, size_t nLen)
{
#ifdef WIN32
	DWORD dwWritten = 0;
	if(WriteFile(fd, pData, nLen, &dwWritten, NULL))
		return dwWritten;
	return -1;
#else
	return write(fd, pData, nLen);
#endif
}

size_t GetFileSizeFD(FILEDESC fd)
{
#ifndef WIN32
	struct stat buf;
	
	fstat(fd, &buf);
	return buf.st_size;
#else
	return GetFileSize(fd, NULL);
#endif
}

////////////////////////////////////////////////////////////
//Log
////////////////////////////////////////////////////////////
DM_LOCK_T g_LockLog;
int g_logLevel = -1;
FILE *g_hLogFile = NULL;

void logInit(const char* lpszPath)
{
#if !defined(ENABLE_DMLOG)
	return;
#else
    g_logLevel = logDebugLevel;
	InitLock(&g_LockLog);
    g_hLogFile = NULL;
#if (ENABLE_DMLOG==LOG_DRIVER_FILE)
	g_hLogFile = fopen(lpszPath, "w+t");
#endif
#if (ENABLE_DMLOG == LOG_DRIVER_MMAP)
    g_mmap_log.event = eventNew(NAMED_EVENT_PATH);
    g_mmap_log.mutex = mutexNew(NAMED_MUTEX_PATH);
    g_mmap_log.handle = mmapOpen(NAMED_MMAP_PATH, MMAP_LOG_FILE_SIZE);

    do{
        MMAP_FILE_HEADER *hd;
        mutexLock(g_mmap_log.mutex, -1);
        g_mmap_log.readpos = sizeof(MMAP_FILE_HEADER);
        hd = (MMAP_FILE_HEADER*)g_mmap_log.handle->data;
        if(hd->magic_code != LOG_MMAP_MAGIC_CODE){
            printf("It is the first process to create the memory map!\r\n");
            hd->magic_code = LOG_MMAP_MAGIC_CODE;
            hd->writepos = sizeof(MMAP_FILE_HEADER);
            hd->endpos = sizeof(MMAP_FILE_HEADER);
        }
        mutexUnLock(g_mmap_log.mutex);
    }while(0);
#endif
#if (ENABLE_DMLOG==LOG_DRIVER_SYSLOG)
  #ifdef LINUX
    openlog(NULL, LOG_CONS|LOG_PID, LOG_USER);
  #endif
#endif

#endif
}

void logUnInit()
{
#if !defined ENABLE_DMLOG
	return;
#else
#if (ENABLE_DMLOG==LOG_DRIVER_FILE)
	if(g_hLogFile != NULL)
	{
		fclose(g_hLogFile);
		g_hLogFile = NULL;
	}
#endif
	UnInitLock(&g_LockLog);
#if (ENABLE_DMLOG==LOG_DRIVER_SYSLOG)
  #ifdef LINUX
    closelog();
  #endif
#endif

#if (ENABLE_DMLOG == LOG_DRIVER_MMAP)
    eventFree(g_mmap_log.event);
    mutexFree(g_mmap_log.mutex);
    mmapClose(g_mmap_log.handle);
#endif

#endif
}

void logEnableLevel(int level)
{
    Lock(&g_LockLog);
    g_logLevel = level;
    UnLock(&g_LockLog);
}

int dmLogFormatHeader(char *buffer, int nSize, int level)
{
#if defined(WIN32) && defined(_MSC_VER)
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	return sprintf_s(buffer, nSize, "[%02d/%02d/%02d %02d:%02d:%02d.%03d pid=%d tid=%d][%c]", 
			         wtm.wMonth, wtm.wDay, wtm.wYear % 100, wtm.wHour, wtm.wMinute, 
			         wtm.wSecond, wtm.wMilliseconds, GetCurrentProcessId(), 
			         GetCurrentThreadId(), g_logLevelString[level]);
#else
	struct timeval timeVal;
	struct tm tmVar;

	gettimeofday(&timeVal, NULL);
	localtime_r((const time_t*)&timeVal.tv_sec, &tmVar);
	return sprintf_s(buffer, nSize, "[%02d/%02d/%02d %02d:%02d:%02d.%03lu pid=%d tid=%d][%c]", 
			         tmVar.tm_mon + 1, tmVar.tm_mday, (tmVar.tm_year + 1900) % 100,
			         tmVar.tm_hour, tmVar.tm_min, tmVar.tm_sec,
			         timeVal.tv_usec / 1000,
			         getpid(), (int)syscall(224), g_logLevelString[level]);
#endif
}

#define FORMAT_STRING() \
    nWritten = dmLogFormatHeader(s_buffer, 2046, level);    \
    nWritten += vsprintf_s(s_buffer + nWritten, 2046 - nWritten, format, ap);   \
    s_buffer[nWritten++] = '\n'; \
    s_buffer[nWritten] = '\0'; \


void dmLogMessage(int level, const char* filename, int lineno, const char *format, ...)
{
	va_list ap;
	static char s_buffer[2048];
    int nWritten = 0;

    if(level < g_logLevel) 
        return;

	Lock(&g_LockLog);
    s_buffer[2047] = 0;
	va_start(ap, format);
#if(ENABLE_DMLOG == LOG_DRIVER_SYSLOG)
#ifdef WIN32
    FORMAT_STRING();
    OutputDebugString(s_buffer);
#elif defined(ANDROID)
    __android_log_vprint(g_logLevelNative[level], dmBaseName(filename), format, ap);
#elif defined(LINUX)
    vsyslog(g_logLevelNative[level], format, ap);
#elif defined(__IPHONE__)
    FORMAT_STRING();
    printf(s_buffer);
#endif
#endif

#if (ENABLE_DMLOG == LOG_DRIVER_CONSOLE)
    FORMAT_STRING();
    printf(s_buffer);
#endif

#if (ENABLE_DMLOG == LOG_DRIVER_MMAP)
    FORMAT_STRING();
    mmapLogWrite(s_buffer, nWritten);
#endif

#if (ENABLE_DMLOG == LOG_DRIVER_FILE)
	if(g_hLogFile != NULL){
        FORMAT_STRING();
        fwrite(s_buffer, sizeof(char), nWritten, g_hLogFile);
	    fflush(g_hLogFile);
    }
#endif
	va_end(ap);
	UnLock(&g_LockLog);
}

/////////////////////////////////////////////////////////////////////
//command line
/////////////////////////////////////////////////////////////////////
typedef struct
{
    char short_name;
    char *long_name;
    char *description;
    int has_argument;
    int is_mandated;
}OptCmdOptions;

struct OptCmdDatas{
    int argc;
    char** argv;
    int nCount;
    OptCmdOptions *opts;
    int nSize;
    int isInvalid;
} g_opts;

void optInit(int argc, char** argv)
{
    g_opts.argc = argc;
    g_opts.argv = argv;
    g_opts.nCount = 0;
    g_opts.nSize = 32;
    g_opts.opts = (OptCmdOptions*)malloc(g_opts.nSize * sizeof(OptCmdOptions));
    memset(g_opts.opts, 0, (g_opts.nSize) * sizeof(OptCmdOptions));
    g_opts.isInvalid = 0;
}

const char* optGet(const char* lname, const char sname, int hasArg, int isMust, 
                   const char* desc, const char* defVal)
{
    OptCmdOptions* opts;
    int len, i;

    //Please make sure not to call any optGet after optExitOnHelp
    assert(g_opts.nSize > 0);

    //Reallocate if there are more than 32 options
    if(g_opts.nCount == g_opts.nSize)
    {
        opts = (OptCmdOptions*)malloc((g_opts.nSize + 32) * sizeof(OptCmdOptions));
        memset(opts, 0, (g_opts.nSize + 32) * sizeof(OptCmdOptions));
        memcpy(opts, g_opts.opts, g_opts.nSize * sizeof(OptCmdOptions));
        g_opts.nSize += 32;
        free(g_opts.opts);
        g_opts.opts = opts;
    }
    opts = &g_opts.opts[g_opts.nCount];
    opts->short_name = sname;
    len = strlen(lname) + 1;
    opts->long_name = (char*)malloc(len);
    strcpy_s(opts->long_name, len, lname);
    len = strlen(desc) + 1;
    opts->description = (char*)malloc(len);
    strcpy_s(opts->description, len, desc);
    opts->has_argument = hasArg;
    opts->is_mandated = isMust;

    g_opts.nCount += 1;

    //Parse the command line and findout the result.
  	for(i = 0; i < g_opts.argc; i++)
    {
        char *key = g_opts.argv[i];
        if(key[0] == '-')
		{
            char *stripped = key;
            while(*stripped != '\0' && *stripped == '-')
                stripped++;

            if(*stripped == '\0')
                continue;
            if((stripped[1] == '\0' && stripped[0] == sname) || _stricmp(stripped, lname) == 0)
            {
                if(hasArg){
                    if(i + 1 < g_opts.argc)
                        return g_opts.argv[i + 1];
                    else
                        return "";
                }else{
                    return "true";
                }
			}
		}
	}

    if(isMust)
        g_opts.isInvalid = 1;
    return defVal;
}

void optFreeOptions()
{
    int i;
    for(i = 0; i < g_opts.nCount; i++){
        OptCmdOptions *opts = &(g_opts.opts[i]);

        FREEBUF(opts->long_name);
        FREEBUF(opts->description);
    }
    g_opts.opts = NULL;
    g_opts.nSize = 0;
    FREEBUF(g_opts.opts);
    g_opts.nCount = 0;
}

void optExitOnInvalid()
{
    const char *val = optGet("help", 'h', 0, 0, "", "");
    if(val[0] != '\0' || g_opts.isInvalid)
    {
        int i;
        printf("Usage: %s [options]\r\n\r\nOptions:\r\n", g_opts.argv[0]);
        for(i = 0; i < g_opts.nCount; i++){
            OptCmdOptions *opt = &g_opts.opts[i];
            char *arg, *must;
            arg = (opt->has_argument) ? "argument" : "";
            must = (opt->is_mandated) ? "MUST" : "";
            if(opt->short_name != 0)
                printf("  -%c, --%s %s\t%s\t%s\r\n", opt->short_name, opt->long_name, arg, must, opt->description);
            else
                printf("  --%s %s\t%s\t%s\r\n", opt->long_name, arg, must, opt->description);
        }
        if(g_opts.isInvalid)
            printf("\r\n\r\nError: Some mandated option(s) are not set");
        exit(0);
    }
    optFreeOptions();
}

char* FindParamFromCmdLine(const char* key, int argc, char** argv)
{
	int i = 0;
	char* ret = NULL;

	for(i = 0; i < argc; i++)
	{
		printf((const char*)argv[i]);
		if(_stricmp(argv[i], key) == 0)
		{
			if(++i < argc && argv[i][0] != '-')
			{
				ret = argv[i];
			}
		}
	}
	return ret;
}

void ParseAddr(unsigned char* szIn, unsigned short* pPort, char* pIP, int nIPLen)
{
	char *szFind = strchr((char*)szIn, ':');
	int nAddrLen = 0;

	if(szIn == NULL || pPort == NULL || pIP == NULL)
		return;

	if(!szFind)
	{
		logError("ParseAddr, unknow aIpAddrAndPort=%s", szIn);
		*pPort = 0;
		szFind = (char*)szIn;
	}
	else 
	{
		*pPort = (unsigned short)atoi(szFind + 1);
	}

	nAddrLen = szFind - (char*)szIn;
	if(nAddrLen > 0)
	{
		memcpy_s(pIP, nIPLen, szIn, nAddrLen);
		pIP[nAddrLen] = '\0';
	}
}

unsigned long hextobin(const char *input, unsigned long len, char **out)
{
	unsigned long binlen = len / 2;
	unsigned long i = 0;
	
	assert(binlen * 2 == len); //len must be multiples of 2.
	assert(out);
	*out = (char*)malloc(binlen);
	for(i = 0; i < binlen; i += 1)
	{
		char itch[3];
		memcpy_s(itch, 2, input + i * 2, 2);
		itch[2] = 0;
		(*out)[i] = (char)strtol(itch, NULL, 16);
	}
	return binlen;
}

unsigned long bintohex(const char *input, unsigned long len, char **out)
{
	unsigned long hexlen = len * 2, i = 0;
	assert(out);
	*out = (char*)malloc(hexlen + 1);
	(*out)[hexlen] = 0;

	for(i = 0; i < len; i += 1)
	{
		sprintf_s(*out + i * 2, hexlen + 1 - i * 2, "%02x", (unsigned char)input[i]);
	}
	return hexlen;
}

const char* dmBasename(char* path)
{
    char* pos = strrchr(path, '\\');
    if(!pos)
        pos = strrchr(path, '/');

    if(pos)
        return pos + 1;
    return path;
}
