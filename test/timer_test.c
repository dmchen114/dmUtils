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

	getUTCTime(&t1);
	Sleep(50);
	getUTCTime(&t2);
	logInfo("ref = %lu, val=%lu", 0xFFFFFFFF / 20, t2.fractions - t1.fractions); 
	testl = (unsigned long)(0xFFFFFFFFUL / 20) - t2.fractions + t1.fractions;
	assert(abs(testl) < 0xFFFFFFFFUL/100);
	timer_id = RegisterTimer(1 * TEST_TIME_UNIT, on_test_timer, &timer_id, 1);
	Sleep(6 * TEST_TIME_UNIT);
	CancelTimer(timer_id);

	timer_id = RegisterTimer(1 * TEST_TIME_UNIT, on_test_timer_repeat, &timer_id, 5);
	Sleep(6 * TEST_TIME_UNIT);
	CancelTimer(timer_id);

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

long process_callback_fortest(void *args)
{
    LPDM_MUTEX m;
    unsigned long tmbefore = get_tick_count();
    bool diff;

    if(NULL == args){
        m = mutexNew("dm_Test_MUTEX_cross_process");
        mutexLock(m, -1);
        mutexUnLock(m);
        diff = get_tick_count() > (tmbefore + 200);
        OK(diff , "Named Mutex across processes tested.");
        return diff ? 10 : 0;
    }
    else{
        m = mutexNew("dm_Test_MUTEX_cross_process");
        mutexLock(m, -1);
        return 0;
    }
}

int test_mutex()
{
    LPDM_MUTEX m; 
    LPDM_PROCESS proc;
    int fpid = 0;
    int status = 0;
    unsigned long tmbefore;

    m = mutexNew("dm_Test_MUTEX_cross_process");
    mutexLock(m, -1);
    proc = procFork(process_callback_fortest, NULL);
    Sleep(250);
    mutexUnLock(m);
    procJoin(proc, &status, -1);
    OK(status == 10, "pass cross process mutex test");
    proc = procFork(process_callback_fortest, (void*)123);
    procJoin(proc, &status, -1);
    tmbefore = get_tick_count();
    mutexLock(m, -1);
    mutexUnLock(m);
    OK(get_tick_count() < tmbefore + 50 , "pass cross mutex deadlock test.");

    return 0;
}

long thread_callback_fortest(void *args)
{
    LPDM_MUTEX m = (LPDM_MUTEX)args;
    unsigned long tmbefore = get_tick_count();
    bool diff;

    logInfo("Log from thread for test, before lock.");
    mutexLock(m, -1);
    mutexUnLock(m);
    logInfo("Log from thread for test, after lock.");
    diff = get_tick_count() > (tmbefore + 200);
    OK(diff , "Named Mutex across threads tested.");
    return diff ? 1 : 0;
}

int test_thread()
{
    int exitcode = 0;
    LPDM_THREAD thr;
    LPDM_MUTEX m = mutexNew(NULL);
    mutexLock(m, -1);
    thr = thrNew(thread_callback_fortest, m);
    Sleep(250);
    mutexUnLock(m);
    thrJoin(thr, &exitcode, -1);
    OK(exitcode == 1, "get thread exit code test case passed.");
    return 0;
}
