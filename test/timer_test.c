#include "dm_common.h"
#include "dm_socket.h"
#include "dm_timer.h"
#include "dm_test.h"

#define TEST_TIME_UNIT 100

void on_test_timer(void* pPtr, unsigned long uID)
{
	unsigned long * timer_id = (unsigned long*)pPtr;
	logInfo("on_test_timer");
	*timer_id = RegisterTimer(1 * TEST_TIME_UNIT, on_test_timer, timer_id, 1);
}
void on_test_timer_repeat(void* pPtr, unsigned long uID)
{
	logInfo("on_test_timer_repeat");
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
	logInfo("ref = %lu, val=%lu", 0xFFFFFFFF / 20, t2.fractions - t1.fractions); 
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
    OK(false, "Test false assert successfully");
    return 1;
}

int test_basename()
{
    const char* result = dmBasename("");
    OK(result[0] == 0, "empty test");
    result = dmBasename("\\");
    OK(result[0] == 0, "empty test");
    result = dmBasename("/");
    OK(result[0] == 0, "empty test");
    result = dmBasename("c:\\test\\test.cpp");
    OK(_stricmp(result, "test.cpp") == 0, "window style test");
    result = dmBasename("/opt/log/test.cpp");
    OK(_stricmp(result, "test.cpp") == 0, "linux style test");
    result = dmBasename("test.cpp");
    OK(_stricmp(result, "test.cpp") == 0, "normal test");

    return 0;
}

int test_mutex()
{
    LPDM_MUTEX m; 
    int fpid;
    int status;
    m = mutexNew("dm_Test_MUTEX");
#ifdef LINUX
    fpid=fork();
    if(fpid < 0)   
        printf("error in fork!");   
    else if(fpid == 0){
        mutexLock(m, -1);
        exit(0);
    }  
    else 
    {
        waitpid(fpid, &status, 0);
        mutexLock(m, -1);
        mutexUnLock(m);
        OK(1, "pass cross process mutex deadlock test");
    }
#endif
    return 0;
}
