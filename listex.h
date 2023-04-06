#ifndef _LISTEX_H_
#define _LISTEX_H_

# if __x86_64__
typedef unsigned long long ULONG_PTR, *PULONG_PTR;
# elif __i386__
typedef unsigned int ULONG_PTR, *PULONG_PTR;
# endif

struct _list_entry_ {
    struct _list_entry_* next;
    struct _list_entry_* prev;
};

#undef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) (\
    (type *)((char*)(address) -(ULONG_PTR)(&((type *)0)->field)))

#define list_entry_init(header) header->next = header; header->prev = header;

static __inline void list_entry_addtail(struct _list_entry_* header, struct _list_entry_* element) {
	struct _list_entry_* p = header;
	struct _list_entry_* n = 0;
	
	do {
		n = p->next;
		if (n == header) {
			p->next = element;
			element->prev = p;
			element->next = header;
			break;
		}

		p = n;
	} while (p != header);
}

static __inline void list_entry_insert(struct _list_entry_* prev,  struct _list_entry_* element) {
	element->prev = prev;
	element->next = prev->next->next;
	prev->next = element;
}


#endif