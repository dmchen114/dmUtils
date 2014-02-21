#if !defined(_DM_UTILS_LIST_H_INCLUDED_)
#define _DM_UTILS_LIST_H_INCLUDED_

typedef void* ElementType;
struct Node;
typedef struct Node *PtrToNode;

typedef PtrToNode Position;

struct Node
{
	ElementType Element;
	Position Next;
};

typedef struct ListHeader
{
	ElementType Element;
	Position Next;
	Position End;
	size_t uSize;
	DM_LOCK_T lock;
}*List;

#ifdef __cplusplus
extern "C" {
#endif

List lstMakeEmpty(List L);
int lstIsEmpty( List L );
int lstIsLast(List L, Position P);
unsigned long lstSize(List L);

Position lstLast(List L);
void lstInsert(List L, ElementType X, Position P);
void lstAppend(List L, ElementType X);
//Insert a Node to position without new alloc memory.
void lstInsertPos(List L, Position P, Position X);

void lstDelete(List L, ElementType X);
void lstDeleteAll(List L);
//Delete next node (free memory) and return prev position for iteration
Position lstDeletePos(List L, Position prev);
//Remove next node from the list without free memory, and return the broken node.
Position lstRemovePos(List L, Position prev);

Position lstHeader(List L);
Position lstFirst(List L);
Position lstAdvance(Position P);
ElementType lstRetrieve(Position P);

void lstLock(List L);
void lstUnLock(List L);

#ifdef __cplusplus
}
#endif

#endif //!define _DM_UTILS_LIST_H_INCLUDED_
