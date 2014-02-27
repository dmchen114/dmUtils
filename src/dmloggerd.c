#include "dm_common.h"

int main(int argc, char **argv)
{
    static char s_buffer[4096] = {0};
    logInit(NULL);

    while(1){
        if(mmapLogWaitEvent(30)){
            int rlen = mmapLogReadLine(s_buffer, 4096);
            if(rlen > 0){
                s_buffer[rlen] = 0;
                printf(s_buffer);
            }
        }
    }

    logUnInit();

    getchar();

    return 0;
}
