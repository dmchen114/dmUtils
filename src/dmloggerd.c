#include "dm_common.h"

void readLogs()
{
    static char s_buffer[4096] = {0};
    int rlen;
    while(1){
        rlen = mmapLogReadLine(s_buffer, 4096);
        if(rlen > 0){
            s_buffer[rlen] = 0;
            printf(s_buffer);
        }
        else
            break;
    }
}

int main(int argc, char **argv)
{
    logInit(NULL);

    readLogs();
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
