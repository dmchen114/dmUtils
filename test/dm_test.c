#include "dm_common.h"
#include "dm_test.h"
#include "hashmap.h"

typedef struct{
    char key[255];
    dmTestCase fn;
}CASE_DATA;

struct {
    int nRunned;
    int nFailed;
}g_results;

map_t g_cases = NULL;

int dmTestRunCase(any_t userData, char *key, any_t value)
{
    CASE_DATA *cd = (CASE_DATA*)value;

    g_results.nRunned++;
    if(cd->fn())
        g_results.nFailed++;

    return MAP_OK;
}

int dmDeleteData(any_t userData, char *key, any_t value)
{
    free((CASE_DATA*)value);
    return MAP_OK;
}

void dmRunTests(int argc, char **argv)
{
    const char *optargs;

    optInit(argc, argv);
    optargs = optGet("case", 'c', 1, 0, "Run case by name", "");
    optExitOnInvalid();

    printf("Welcome to use dmUtils tiny C test framework.\r\n");
    printf("----------------------------------------------\r\n\r\n");
    g_results.nFailed = g_results.nRunned = 0;
    if(*optargs == 0){ //Run all cases
        hashmap_iterate(g_cases, dmTestRunCase, NULL);
    }else{
        CASE_DATA *cd = NULL;
        hashmap_get(g_cases, (char*)optargs, (any_t*)&cd);
        if(cd && cd->fn){
            g_results.nRunned++;
            if(cd->fn())
                g_results.nFailed++;
        }
    }
    printf("\r\n_________________________________\r\n");
    printf("%d case(s) run, %d case(s) failed.\r\n", g_results.nRunned, g_results.nFailed);
#ifdef WIN32
    printf("Press any key to exit...\r\n");
    getchar();
#endif
    hashmap_iterate(g_cases, dmDeleteData, NULL);
    hashmap_free(g_cases);

}

void dmRegisterCase(char* caseId, dmTestCase f)
{
    CASE_DATA *cd;
    if(g_cases == NULL)
        g_cases = hashmap_new();

    cd = (CASE_DATA*)malloc(sizeof(CASE_DATA));
    strcpy_s(cd->key, 255, caseId);
    cd->fn = f;
    hashmap_put(g_cases, caseId, cd);
}

void colorPrintf(int color, const char* s)
{
#ifdef WIN32
    HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO definfo;

    GetConsoleScreenBufferInfo(con, &definfo);

    SetConsoleTextAttribute(con, color);
    printf(s);
    SetConsoleTextAttribute(con, definfo.wAttributes);
#else
    printf("\033[0;%d;40m%s\033[0m", color, s);
#endif
}

void OK(bool condition, char* description)
{
    if(condition){
        colorPrintf(DM_COLOR_GREEN, "[PASS] ");
    }
    else{
        colorPrintf(DM_COLOR_RED, "[FAIL] ");
    }
    printf(description);
    printf("\r\n");
}
