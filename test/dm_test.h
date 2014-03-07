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
void dmAssert(bool condition, char* description, char *filename, int lineno); 
void colorPrintf(int color, const char* s);

#define DECLARE_TESTCASE(x) \
    do{ extern int test_##x(); \
    dmRegisterCase(#x, test_##x); }while(0); \


#define RUN_ALL_CASES dmRunTests
#define OK(c, d)    do {dmAssert((c), (d), __FILE__, __LINE__); if(!(c)) return 1; } while(0);
#ifdef __cplusplus
}
#endif

#endif //!defined _DM_C_TEST_FRAMEWORK_H_INCLUDED_
