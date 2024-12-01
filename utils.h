#ifndef _UTILS_H_
#define _UTILS_H_

#include "types.h"

#include <stddef.h>
#include <assert.h>

int hexstr2bytes(const char *content, u_int64 *flag);
int strcpy_s(char *dest, int lenofdest, const char* src);
void* mallocarray(size_t nmemb, size_t size);
void* reallocarray(void* optr, size_t nmemb, size_t size);
int getCurrentDir(char *output, int bufsize);


#define memory_alloc(type, pointer, count) ({ \
            pointer = (type*)mallocarray(sizeof(type), count); \
            assert(pointer != 0);\
            if (pointer != 0) \
                memset(pointer, 0, count * sizeof(type)); \
})

#define free_0(pointer) free(pointer); pointer = 0;

#endif