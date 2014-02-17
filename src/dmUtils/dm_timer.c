#include "dm_common.h"
#include "dm_timer.h"
#include "dm_list.h"
#include "dm_socket.h"

List g_timer = NULL;
unsigned long g_ulTimerSeq = 419;
const uint64_t EPOCH_WINDOWS = 9435484800ULL;
const uint64_t EPOCH_LINUX = 2208988800ULL;
const uint64_t NTP_SCALE_FRAC = 4294967295ULL;

void InitTimerQue()
{
	g_timer = lstMakeEmpty(NULL);
}

void UnInitTimerQue()
{
	lstDeleteAll(g_timer);
	g_timer = NULL;
}

void ReSchedule(Position itExist)
{
	Position it, itPrev;
	time_node *pTemp, *timeVal;

	lstLock(g_timer);
	itPrev = lstHeader(g_timer);
	timeVal = (time_node*)lstRetrieve(itExist);
	for(it = lstFirst(g_timer); it != NULL; itPrev = it, it = lstAdvance(it))
	{
		pTemp = (time_node*)lstRetrieve(it);
		if(pTemp->ulNextTime > timeVal->ulNextTime)
			break;
	}
	lstInsertPos(g_timer, itPrev, itExist);
	lstUnLock(g_timer);
}

long ProcessTimer()
{
	Position it, itHead, itFirst, itPrev;
	struct time_node* tvTimer;
	unsigned long ulNow;
	long ulRet = -1;
	List events = lstMakeEmpty(NULL);

	ulNow = get_tick_count();
	if(g_timer == NULL)
		return -1;

	lstLock(g_timer);
	itFirst = it = lstFirst(g_timer);
	itPrev = itHead = lstHeader(g_timer);
	for(; it != NULL; itPrev = it, it = lstAdvance(it))
	{
		tvTimer = (struct time_node*)lstRetrieve(it);
		if(ulNow >= tvTimer->ulNextTime)
		{
			if(tvTimer->nRemainCount > 0)
				tvTimer->nRemainCount--;
			if(tvTimer->nRemainCount != 0)
				tvTimer->ulNextTime += tvTimer->nInterval;
		}
		else
		{
			ulRet = tvTimer->ulNextTime - ulNow;
			break;
		}
	}

	//Now move the events from the timer list and insert into a temp list.
	if(itPrev != itHead){
		itHead->Next = it;
		events->Next = itFirst;
		itPrev->Next = NULL;
	}

	lstUnLock(g_timer);
	itPrev = lstHeader(events);
	for(it = lstFirst(events); it != NULL; itPrev = it, it = lstAdvance(it))
	{
		tvTimer = (struct time_node*)lstRetrieve(it);
		if(!tvTimer)
			continue;

		tvTimer->OnTimer(tvTimer->pPtr, tvTimer->ulID);
		if(tvTimer->nRemainCount != 0)
		{
			Position itTemp = lstRemovePos(g_timer, itPrev);
			it = itPrev;
			if(itTemp)
				ReSchedule(itTemp);
		}else
		{
			free(tvTimer);
		}
	}
	lstDeleteAll(events);

	return ulRet;
}

unsigned long RegisterTimer(int milisecond, P2PTimerProc callback, void* pParam, int nRepeatTime)
{
	struct time_node* pTimerNode;
	struct time_node* pTemp;
	Position it, itPrev;

	pTimerNode = (struct time_node*)malloc(sizeof(struct time_node));
	pTimerNode->pPtr = pParam;
	pTimerNode->OnTimer = callback;
	pTimerNode->ulNextTime = get_tick_count() + milisecond;
	pTimerNode->nRemainCount = nRepeatTime;
	pTimerNode->ulID = g_ulTimerSeq++;
	pTimerNode->nInterval = milisecond;

	lstLock(g_timer);
	it = lstFirst(g_timer);
	itPrev = lstHeader(g_timer);
	while(it != NULL)
	{
		pTemp = (struct time_node*)lstRetrieve(it);
		if(pTemp->ulNextTime > pTimerNode->ulNextTime)
			break;
		itPrev = it;
		it = lstAdvance(it);
	}
	lstInsert(g_timer, pTimerNode, itPrev);
	lstUnLock(g_timer);

	NotifyHandler();

	return pTimerNode->ulID;
}

void CancelTimer(unsigned long ulTimerID)
{
	Position it, itPrev;
	struct time_node* pTemp;

	lstLock(g_timer);
	it = lstFirst(g_timer);
	itPrev = lstHeader(g_timer);
	while(it != NULL)
	{
		pTemp = (struct time_node*)lstRetrieve(it);
		if(pTemp->ulID == ulTimerID)
		{
			//Potential memory leak, should change to new function, lstDeletePos.
			it = lstAdvance(it);
			itPrev->Next = it;
			free(pTemp);
			break;
		}
		itPrev = it;
		it = lstAdvance(it);
	}

	lstUnLock(g_timer);
}

#ifdef WIN32
unsigned long get_tick_count()
{
	return GetTickCount();
}

void getUTCTime(NTP_TIME *ntp)
{
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);

	if(ntp){
		uint64_t tmpres, tmpfracs;

		tmpres |= ft.dwHighDateTime;
	    tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;
 
		tmpres -= EPOCH_WINDOWS;
		ntp->seconds = (unsigned long)(tmpres / 10000000UL);
		tmpfracs = (tmpres % 10000000UL);
		ntp->fractions = (unsigned long)((NTP_SCALE_FRAC * tmpfracs) / 10000000UL);
	}
}

#else
unsigned long get_tick_count()
{
	unsigned long   ret;
	struct  timeval time_val;

	gettimeofday(&time_val, NULL);
	ret = time_val.tv_sec * 1000 + time_val.tv_usec / 1000;

	return ret;
}

void getUTCTime(NTP_TIME *ntp)
{
	struct  timeval time_val;

	gettimeofday(&time_val, NULL);

	if(ntp){
		ntp->seconds = time_val.tv_sec + EPOCH_LINUX;
		ntp->fractions = (unsigned long)((NTP_SCALE_FRAC * time_val.tv_usec) / 1000000UL);
	}
}

void Sleep(unsigned long ms)
{
	usleep(ms * 1000);
}

#endif // CM_WIN32
