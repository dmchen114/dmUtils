#include "dm_common.h"
#include "dm_socket.h"
#include "dm_timer.h"
#include "dm_test.h"

#define TEST_TIME_UNIT 100

void on_test_timer(void* pPtr, unsigned long uID)
{
	unsigned long * timer_id = (unsigned long*)pPtr;
	logMessage(logInfo, "on_test_timer");
	*timer_id = RegisterTimer(1 * TEST_TIME_UNIT, on_test_timer, timer_id, 1);
}
void on_test_timer_repeat(void* pPtr, unsigned long uID)
{
	logMessage(logInfo, "on_test_timer_repeat");
}

int test_timer()
{
	unsigned long timer_id;
	long testl;
	NTP_TIME t1, t2;

	P2PInit();
	getUTCTime(&t1);
	Sleep(50);
	getUTCTime(&t2);
	logMessage(logInfo, "ref = %lu, val=%lu", 0xFFFFFFFF / 20, t2.fractions - t1.fractions); 
	testl = (unsigned long)(0xFFFFFFFFUL / 20) - t2.fractions + t1.fractions;
	assert(abs(testl) < 0x100000UL);
	timer_id = RegisterTimer(1 * TEST_TIME_UNIT, on_test_timer, &timer_id, 1);
	Sleep(6 * TEST_TIME_UNIT);
	CancelTimer(timer_id);

	timer_id = RegisterTimer(1 * TEST_TIME_UNIT, on_test_timer_repeat, &timer_id, 5);
	Sleep(6 * TEST_TIME_UNIT);
	CancelTimer(timer_id);

	P2PUnInit();
	OK(true, "test timer");

    return 0;
}

int test_opt()
{
    OK(false, "options");
    return 1;
}
