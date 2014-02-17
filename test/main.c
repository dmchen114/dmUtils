#include "dm_common.h"
#include "dm_socket.h"
#include "dm_timer.h"

extern void test_timer();
extern void test_rtcp();

int main(int argc, char **argv)
{
	test_timer();
	//test_rtcp();

	getchar();
}
