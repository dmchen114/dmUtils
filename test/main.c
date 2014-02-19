#include "dm_common.h"
#include "dm_socket.h"
#include "dm_timer.h"
#include "dm_test.h"

extern void test_timer();

int main(int argc, char **argv)
{
	test_timer();
	//test_rtcp();

	getchar();
}
