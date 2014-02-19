#if !defined(_DM_C_TEST_FRAMEWORK_H_INCLUDED_)
#define _DM_C_TEST_FRAMEWORK_H_INCLUDED_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dmTestCase)();

void dmRunAllTests();
void dmRegisterCase(const char* caseId, dmTestCase f);

#ifdef __cplusplus
}
#endif

#endif //!defined _DM_C_TEST_FRAMEWORK_H_INCLUDED_