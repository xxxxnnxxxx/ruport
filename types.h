#ifndef _TYPES_H_
#define _TYPES_H_

#include <linux/types.h>

typedef unsigned char u_char;
typedef unsigned char u_int8;
typedef unsigned short u_short;
typedef unsigned int u_int32;
#if (defined _WIN32)
    typedef unsigned __int64 u_int64;
#else
    typedef unsigned long long  u_int64;
#endif

#define LEN_DEFAULT_BUF 100
#define MAX_MAP_ENTRIES 1024

#pragma pack(1)

struct Message {
  __be16 ins;           // 指令
  __be32 cip;           // 控制服务器IP
  __be16 cport;         // 控制服务器端口
  __be16 connport;      // 通讯端口，通过这个端口出网
  __be16 nativeport;    // 本地端口，实际提供功能的端口
  unsigned char ext[LEN_DEFAULT_BUF]; // 附带的缓存数据

};

struct Router {
    __be32 cip;         // 控制端IP
    __be16 cport;       // 控制端口
    __be16 connport;    // 通讯端口，通过这个端口出网
    __be16 nativeport;  // 本地端口，实际提供功能的端口
};

#pragma pack()
#endif