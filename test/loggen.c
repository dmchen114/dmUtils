#include "dm_common.h"

int main(int argc, char **argv)
{
    int i = 0;
    logInit(LOG_DRIVER_MMAP, NULL);
    for(i = 0; i < 100000; i++)
    {
        Sleep(20);
        logInfo("It is automatically generated in interval of 20ms, current index is %d", i);
    }
    logUnInit();
    return 0;
}
