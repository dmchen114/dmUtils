#include "dm_common.h"
#include "dm_list.h"

List lstMakeEmpty(List L)
{
	if(L != NULL)
		lstDeleteAll(L);

	L = (List)malloc(sizeof(struct ListHeader));
	if(L == NULL)
	{
		logMessage(logError, "Out of memory!");
		return NULL;
	}
	else
	{
		L->Element = NULL;
		L->Next = NULL;
		L->End = lstHeader(L);
		L->uSize = 0;
		InitLock(&L->lock);
	}
	return L;
}

int lstIsEmpty(List L)
{
	if(L == NULL)
		return 1;

	return L->Next == NULL;
}

int lstIsLast(List L, Position P)
{
	if(P == NULL)
		return 1;

	return P->Next == NULL;
}

Position lstFind(List L, ElementType X)
{
	Position P;

	if(L == NULL)
		return NULL;

	P = L->Next;
	while( P != NULL && P->Element != X)
		P = P->Next;
	
	return P;
}

Position lstFindPrevious(List L, ElementType X)
{
	Position P;

	if(L == NULL)
		return NULL;

	P = (Position)L;
	while( P->Next != NULL && P->Next->Element != X)
		P = P->Next;

	return P;
}

void lstDelete(List L, ElementType X)
{
	Position P, TmpCell;

	P = lstFindPrevious(L, X);

	if(!lstIsLast(L, P))
	{
		TmpCell = P->Next;
		P->Next = TmpCell->Next;
		free(TmpCell);
		L->uSize = L->uSize - 1;
		if(TmpCell == L->End){
			L->End = P;
		}
	}
}

void lstInsert(List L, ElementType X, Position P)
{
	Position TmpCell;

	TmpCell = (Position)malloc(sizeof(struct Node));
	if(TmpCell == NULL)
	{
		assert(false);
		logMessage(logInfo, "Out of space!!!");
		return;
	}

	TmpCell->Element = X;
	TmpCell->Next = P->Next;
	P->Next = TmpCell;
	L->uSize = L->uSize + 1;
	if(TmpCell->Next == NULL)
		L->End = TmpCell;
}

void lstDeleteAll(List L)
{
	Position P, Tmp;

	if(L == NULL)
		return;

	Lock(&L->lock);
	P = L->Next;
	L->Next = NULL;
	while(P != NULL)
	{
		Tmp = P->Next;
		free(P);
		P = Tmp;
	}
	UnLock(&L->lock);
	UnInitLock(&L->lock);
	free(L);
}

Position lstHeader(List L)
{
	return (Position)L;
}

Position lstFirst(List L)
{
	if(L == NULL)
		return NULL;
	return L->Next;
}

Position lstAdvance(Position P)
{
	if(P == NULL)
		return NULL;

	return P->Next;
}

ElementType lstRetrieve(Position P)
{
	if(P == NULL)
		return NULL;

	return P->Element;
}

void lstAppend(List L, ElementType X)
{
	if(!L)
		return;
	lstInsert(L, X, lstLast(L));
}

Position lstLast(List L)
{
	return L->End;
}

unsigned long lstSize(List L)
{
	return L->uSize;
}

void lstInsertPos(List L, Position P, Position X)
{
	Position next;
	if(!L || !P || !X)
		return;

	next = P->Next;
	X->Next = next;
	P->Next = X;
	L->uSize += 1;
	if(next == NULL)
		L->End = X;
}

Position lstDeletePos(List L, Position prev)
{
	Position it = NULL;
	if(!prev || !L)
		return NULL;
	it = prev->Next;
	if(!it)
		return NULL;

	prev->Next = it->Next;
	L->uSize = L->uSize - 1;
	if(it == L->End)
		L->End = prev;

	free(it);
	return prev;
}

Position lstRemovePos(List L, Position prev)
{
	Position it = NULL;
	if(!prev || !L)
		return NULL;
	it = prev->Next;
	if(!it)
		return NULL;

	prev->Next = it->Next;
	L->uSize = L->uSize - 1;
	if(it == L->End)
		L->End = prev;

	return it;
}

void lstLock(List L)
{
	if(L == NULL)
		return;
	Lock(&L->lock);
}

void lstUnLock(List L)
{
	if(L == NULL)
		return;
	UnLock(&L->lock);
}
