#include "dm_common.h"
#include "dm_socket.h"
#include "dm_timer.h"
#include "dm_test.h"

int main(int argc, char **argv)
{
    DECLARE_TESTCASE(mutex);
    DECLARE_TESTCASE(thread);
    //DECLARE_TESTCASE(basename);
    //DECLARE_TESTCASE(opt);
    //DECLARE_TESTCASE(timer);

    logInit(2, NULL);
	//P2PInit();
	RUN_ALL_CASES(argc, argv);
	//P2PUnInit();
    logUnInit();
}
