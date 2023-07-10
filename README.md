# ruPort

基于ebpf实现的端口复用功能控制程序，可以通过接受指令，复用对外开发的端口形式提供隐秘服务。全部程序不需要安装第三方的服务作为依托。

## 环境和编译：

目前在ubuntu20.04 和 ubuntu22.04 下编译通过

### 环境

    OS: ubuntu
    Linux Kernel：5.13 
    clang：13.0.1 or latest
    glibc: 2.35

### 编译

```bash
cd ruport
make
```

## 运行

### 参数

- `-i` —— 网络接口名称

如果不指定网络接口名称，程序内容可以直接获取，但有可能获取不到，

## c3.py

insTool 下 c3.py 作为指令发送程序, 可以给ruPort发送指令，来指令特定的行为。