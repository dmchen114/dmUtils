#include "dm_common.h"

int main(int argc, char **argv)
{
    static char s_buffer[4096] = {0};
    logInit(NULL);

    while(1){
        int nWaitRes = mmapLogWaitEvent(-1);
        if(nWaitRes == EVENT_WAIT_NORMAL || nWaitRes == EVENT_WAIT_TIMEOUT)
        {
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
        else
            break;
    }

    logUnInit();

    getchar();

    return 0;
}
