# ruPort

基于ebpf实现的端口复用功能控制程序，可以通过接受指令，复用对外开发的端口形式提供隐秘服务。全部程序不需要安装第三方的服务作为依托。

## 环境和编译：

去掉原有的bpftool/libbpf的源码部分，通过安装 linux-tools-common & libbpf-dev,

```bash
sudo apt install linux-tools-common # bpftool
sudo apt install libbpf-dev # bpf headers and library
sudo apt install clang # clang 
```

### 环境

```bash
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
```

### 编译

```bash
make clean
make
```

## 运行

### 参数

- `-i` —— 网络接口名称

如果不指定网络接口名称，程序内容可以直接获取，但有可能获取不到，

## c3.py

insTool 下 c3.py 作为指令发送程序, 可以给ruPort发送指令，来指令特定的行为。