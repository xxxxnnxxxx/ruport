#include "utils.h"

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

int hexstr2bytes(const char *content, u_int64 *flag) {
    if (content == 0 || flag == 0)
        return 0;

    char *result = (char*)flag;
    const char *p = content;
    int i = 0;
    while(1) {
        int cursor;
    p1:
        cursor = 1;
        if( p == content + strlen(content)|| i > 7) break;
    p2:
        if (*p <= '9' && *p >= '0') {
            result[i] += (*p - 0x30) << (cursor * 4);
            cursor--;
        } 
        else if (*p <= 'F' && *p >= 'A') {
            result[i] += (*p - 0x41 + 10) << (cursor * 4);
            cursor--;
        }
        else if (*p <= 'f' && *p >= 'a') {
            result[i] += (*p -0x61 + 10) << (cursor * 4);
            cursor--;
        }

        if (cursor == 1) {
            p++;
            goto p1;
        }
        else if (cursor == 0) {
            p++;
            goto p2;
        }
        else if (cursor == -1) {
            p++;
            i++;
            goto p1;
        }
    }

    return 1;
}


int strcpy_s(char *dest, int lenofdest, const char* src){
    int ret = -1;

    if (strlen(src) > lenofdest) {
        ret = -1;
        goto exit;
    }

    memccpy(dest, src, '\0', strlen(src));
    ret = strlen(src);
exit:

    return ret;
}

/*
from openbsd source code
*/
#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

void* reallocarray(void* optr, size_t nmemb, size_t size){
    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        nmemb > 0 && SIZE_MAX / nmemb < size) {
        errno = ENOMEM;
        return NULL;
    }
    return realloc(optr, size * nmemb);
}

void* mallocarray(size_t nmemb, size_t size) {
    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        nmemb > 0 && SIZE_MAX / nmemb < size) {
        errno = ENOMEM;
        return NULL;
    }

    return malloc(size * nmemb);
}

// 获取当前目录
int getCurrentDir(char *output, int bufsize) {
    if (getcwd(output, bufsize) != NULL) {
       return 0;
   } else {
       return 1;
   }
}