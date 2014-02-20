#include "dm_common.h"
#include "dm_socket.h"
#include "dm_timer.h"
#include "dm_test.h"

int main(int argc, char **argv)
{
    DECLARE_TESTCASE(basename);
    DECLARE_TESTCASE(opt);
    DECLARE_TESTCASE(timer);

	RUN_ALL_CASES(argc, argv);
}
