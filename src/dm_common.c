#include "dm_common.h"

////////////////////////////////////////////////////////////
//Mutex
////////////////////////////////////////////////////////////
void InitLock(THREAD_MUTEX_T* pLock)
{
#ifdef WIN32
	InitializeCriticalSection(pLock);
#else
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
#if !defined CM_SOLARIS && !defined MachOSupport 
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE_NP);
#else
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
#endif
	pthread_mutex_init(pLock, &mutexattr);
	pthread_mutexattr_destroy(&mutexattr);
#endif
}

void UnInitLock(THREAD_MUTEX_T* pLock)
{
#ifdef WIN32
	DeleteCriticalSection(pLock);
#else
	pthread_mutex_destroy(pLock);
#endif // CM_WIN32
}

void Lock(THREAD_MUTEX_T* pLock)
{
#ifdef WIN32
	EnterCriticalSection(pLock);
#else
	pthread_mutex_lock(pLock);
#endif
}

void UnLock(THREAD_MUTEX_T* pLock)
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
THREAD_MUTEX_T g_LockLog;
FILE *g_hLogFile = NULL;

void InitLog(const char* lpszPath)
{
#if !defined(ENABLE_DMLOG)
	return;
#else
	InitLock(&g_LockLog);
#if defined(WIN32) && defined(_MSC_VER) && defined(_DEBUG)
	return;
#endif
	g_hLogFile = fopen(lpszPath, "w+t");
#endif
}

void UnInitLog()
{
#if !defined ENABLE_DMLOG
	return;
#else
	if(g_hLogFile != NULL)
	{
		fclose(g_hLogFile);
		g_hLogFile = NULL;
	}
	UnInitLock(&g_LockLog);
#endif
}
#if defined ENABLE_DMLOG && !defined (ANDROID) && !defined (__IPHONE__)
void logMessage(int level, const char *format, ...)
{
	va_list ap;
	static char s_buffer[2048];
#ifdef WIN32
	SYSTEMTIME wtm;
#else
	struct timeval timeVal;
	struct tm tmVar;
#endif

	Lock(&g_LockLog);
	va_start(ap, format);
	if(g_hLogFile == NULL)
	{
#if defined(WIN32) && defined(_MSC_VER) && defined(_DEBUG)
		GetLocalTime(&wtm);
		sprintf_s(s_buffer, 2047, "[%02d/%02d/%04d %02d:%02d:%02d.%03d pid=%d tid=%d][l=%d]", 
			wtm.wMonth, wtm.wDay, wtm.wYear, wtm.wHour, wtm.wMinute, 
			wtm.wSecond, wtm.wMilliseconds, GetCurrentProcessId(), 
			GetCurrentThreadId(), level);
		OutputDebugString(s_buffer);
		vsprintf_s(s_buffer, 2047, format, ap);
		OutputDebugString(s_buffer);
		OutputDebugString("\r\n");
#else
		vprintf(format, ap);
		printf("\r\n");
#endif
	}
	else
	{
		vsprintf_s(s_buffer, 2047, format, ap);
#ifndef WIN32
		gettimeofday(&timeVal, NULL);
		localtime_r((const time_t*)&timeVal.tv_sec, &tmVar);
		fprintf(g_hLogFile, "[%02d/%02d/%04d %02d:%02d:%02d.%03lu pid=%d tid=%d][l=%d]%s\r\n", 
			tmVar.tm_mon + 1, tmVar.tm_mday, tmVar.tm_year + 1900,
			tmVar.tm_hour, tmVar.tm_min, tmVar.tm_sec,
			timeVal.tv_usec / 1000,
			getpid(), (int)pthread_self(), level,
			s_buffer);
#else
		GetLocalTime(&wtm);
		fprintf(g_hLogFile, "[%02d/%02d/%04d %02d:%02d:%02d.%03d pid=%d tid=%d][l=%d]%s\n", 
			wtm.wMonth, wtm.wDay, wtm.wYear, wtm.wHour, wtm.wMinute, 
			wtm.wSecond, wtm.wMilliseconds, GetCurrentProcessId(), 
			GetCurrentThreadId(), level, s_buffer);
#endif
		fflush(g_hLogFile);
	}
	va_end(ap);
	UnLock(&g_LockLog);
}
#endif

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
		logMessage(logError, "ParseAddr, unknow aIpAddrAndPort=%s", szIn);
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
