#include "dm_common.h"

FILEDESC g_file = NULL_FILE_DESC;
unsigned long g_filelen = 0;
unsigned long g_pagenum = 0;
unsigned long g_maxpages = 5;
unsigned long g_max_log_file_size = 10*1024*1024;
char g_savedpath[1024] = {0};

void saveLog(char *buffer, int nSize)
{
    if(g_file == NULL_FILE_DESC && g_filelen == 0)  //Open file
    {
        char szFileName[1024] = {0};
#if defined(WIN32)
    	SYSTEMTIME wtm;
	    GetLocalTime(&wtm);
        sprintf_s(szFileName, 1024, "%s/messages_%02d_%02d_%04d_%d_%d.log", g_savedpath, wtm.wMonth, wtm.wDay, 
            wtm.wYear, GetCurrentProcessId(), g_pagenum);
#else
	    struct timeval timeVal;
	    struct tm tmVar;

	    gettimeofday(&timeVal, NULL);
	    localtime_r((const time_t*)&timeVal.tv_sec, &tmVar);
        sprintf_s(szFileName, 1024, "%s/messages_%02d_%02d_%04d_%d_%d.log", g_savedpath, tmVar.tm_mon + 1, 
            tmVar.tm_mday, (tmVar.tm_year + 1900), getpid(), g_pagenum);
#endif
        
        g_file = fileOpen(szFileName, "w");
    }
    fileWrite(g_file, buffer, nSize);
    fileFlush(g_file);
    g_filelen += nSize;
    if(g_filelen >= g_max_log_file_size)
    {
        fileClose(g_file);
        g_file = NULL_FILE_DESC;
        g_filelen = 0;
        g_pagenum += 1;
        if(g_pagenum > g_maxpages)
        {
            logError("=======LOGS HAVE BEEN ROTATED======");
            g_pagenum = 0;
        }
    }
}

void readLogs()
{
    static char s_buffer[4096] = {0};
    int rlen;
    while(1){
        rlen = mmapLogReadLine(s_buffer, 4096);
        if(rlen > 0){
            s_buffer[rlen] = 0;
            saveLog(s_buffer, rlen);
        }
        else
            break;
    }
}

unsigned long parseFileSize(const char *optargs)
{
    int i, v;
    char ch, *copied;
   
    i = strlen(optargs);
    if(i <= 1)
        return 10*1024*1024;

    copied = (char*)malloc(i + 1);
    strcpy_s(copied, i + 1, optargs);
    copied[i - 1] = '\0';
    ch = optargs[i - 1];
    v = atoi(copied);
    free(copied);

    if(ch == 'M' || ch == 'm')
        return v * 1024 * 1024;
    else if(ch == 'K' || ch == 'k')
        return v * 1024;
    else if(ch == 'G' || ch == 'g')
        return v * 1024 * 1024;

    return atol(optargs);
}

int main(int argc, char **argv)
{
    const char * optargs;

    optInit(argc, argv);
    optargs = optGet("path", 'p', 1, 0, "Path to save the logs", "./");
    strcpy_s(g_savedpath, 1024, optargs);
    optargs = optGet("max-pages", 'm', 1, 0, "Maximize pages to save", "5");
    g_maxpages = atoi(optargs);
    optargs = optGet("file-size", 's', 1, 0, 
        "Size of a single log file, in mega-bytes, for example, 10M", "20M");
    g_max_log_file_size = parseFileSize(optargs);
    optExitOnInvalid();

    logInit(NULL);

    logInfo("====Before read logs====");
    readLogs();
    logInfo("====After read logs====");
    while(1){
        int nWaitRes = mmapLogWaitEvent(-1);
        if(nWaitRes == EVENT_WAIT_NORMAL || nWaitRes == EVENT_WAIT_TIMEOUT)
        {
            readLogs();
        }
        else
            break;
    }

    logUnInit();

    getchar();

    return 0;
}
