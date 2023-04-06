# ruPort

基于ebpf实现的端口复用功能控制程序，可以通过接受指令，复用对外开发的端口形式提供隐秘服务。全部程序不需要安装第三方的服务作为依托。

### 编译环境：

OS: ubuntu20.04 

Linux Kernel：5.13 

clang：13.0.1 

glibc: 2.35

### c3.py

insTool 下 c3.py 作为指令发送程序, 可以给ruPort发送指令，来指令特定的行为。