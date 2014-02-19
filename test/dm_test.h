#if !defined(_DM_C_TEST_FRAMEWORK_H_INCLUDED_)
#define _DM_C_TEST_FRAMEWORK_H_INCLUDED_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*dmTestCase)();

#ifdef WIN32
#define DM_COLOR_RED       FOREGROUND_RED
#define DM_COLOR_BLUE      FOREGROUND_BLUE
#define DM_COLOR_GREEN     FOREGROUND_GREEN
#else
#define DM_COLOR_RED       31
#define DM_COLOR_BLUE      34
#define DM_COLOR_GREEN     32
#endif

void dmRunTests(int argc, char **argv);
void dmRegisterCase(char* caseId, dmTestCase f);
void OK(bool condition, char* description); 
void colorPrintf(int color, const char* s);

#define DECLARE_TESTCASE(x) \
    do{ extern void test_##x(); \
    dmRegisterCase(#x, test_##x); }while(0); \


#define RUN_ALL_CASES dmRunTests

#ifdef __cplusplus
}
#endif

#endif //!defined _DM_C_TEST_FRAMEWORK_H_INCLUDED_