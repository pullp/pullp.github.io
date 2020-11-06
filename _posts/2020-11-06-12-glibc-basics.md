---
layout:     post
title:      glibc相关操作记录
subtitle:   play with glibc
date:       2020-11-06
author:     wxk1997
header-img: img/pwn-bg.png
catalog: true
tags:
    - ctf
    - pwn
    - glibc
---

# 1. 前言

| 更新时间  | 更新内容  |
|  ----     | ----      |
| 2020-11-06 | 初稿     |

--- 


# 2. 正文

> Let's play with glibc!

## 2.1. 编译 glibc

官网编译指南参考[4].

自己编译的话调试的时候可以看到glibc函数源码, 可以大大提升做题效率.

首先下载对应版本的glibc源码, 可以去官方镜像站下载[7]. (国内用户推荐去清华镜像站下载[3])

下载之后解压编译即可, 需要注意的是, 为了防止编译得到的libc和系统自带的libc发生冲突, 所以在编译的时候建议手动设置安装目录.

下面以在`ubuntu-18.04`上编译一个2.27版本的glibc为例.

```bash
$ pwd
/usr/src/glibc
$ wget https://mirrors.tuna.tsinghua.edu.cn/gnu/glibc/glibc-2.27.tar.xz #下载glbic 源码压缩包
$ tar xvf ./glibc-2.27.tar.xz # 解压源码
$ mkdir glibc-2.27_{build,out} # 新建编译目录(glibc_2.27_build)和安装目录(glibc_2.27_out)
$ cd glibc-2.27_build
$ ../glibc-2.27/configure '--prefix=/usr/src/glibc/glibc-2.27_out' # 配置安装目录
$ make && make install
```

编译完成之后可以去安装目录的lib文件夹夹下找到编译得到的 `libc.so` 和 `ld.so`

```bash
$ pwd
/usr/src/glibc/glibc-2.27_out
$ ls -al ./lib/libc-2.27.so
-rwxr-xr-x 1 wxk wxk 16778872 Nov  6 21:09 ./lib/libc-2.27.so
$ ls -al ./lib/ld-2.27.so
-rwxr-xr-x 1 wxk wxk 1398520 Nov  6 21:09 ./lib/ld-2.27.so
```

## 2.2. run with specific glibc

最简单的方法就是使用`LD_PRELOAD`环境变量声明想要使用的`libc.so`(目标libc). 

```bash
LD_PRELOAD=./libc.so ./program
```

但是这种方法不够稳定. 在加载目标libc的时候使用的还是系统自带的`ld.so`. libc和ld直接的ABI如果不一致的话就可能在加载libc或动态解析libc中函数地址时出错. 可能导致ABI版本不一样的原因有很多: libc和ld不是一个版本(不是同一个源码编译得到的); libc和ld编译时使用的编译器版本不一致或者编译时的编译参数不同. 严格来说, 只用同时编译得到的 ld 和 libc 的ABI版本才可以保证是完全一致的. 

所以为了可以稳定地使用目标libc, 我们最好使用对应的ld来加载程序和libc

```bash
LD_PRELOAD=./libc.so ./ld.so ./program
```

对应的pwntools代码如下

```python
#coding:utf-8
from pwn import *

io = process("./program", env={"LD_PRELOAD":"./libc.so"})
io = process(["./ld.so", "./program"], env={"LD_PRELOAD":"./libc.so"})
```

做ctf题时, libc常有, 而ld不常有. 但是我们可以通过libc-database[2]找到libc对应的ld.

举个例子, 我们现在拿到一个 `libc.so`, 但是直接使用`LD_PRELOAD`会报错. 我们需要找到这个libc对应的ld.

首先使用`file`命令获取`BuildID`

```bash
$ file ./libc.so
./libc.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c4fd86ec1eed57a09c79ce601f6c6e3796f574df, for GNU/Linux 2.6.32, stripped
```

用`BuildID`去libc-database的数据库里面搜索

```bash
$ libc-database git:(master) ./identify bid=c4fd86ec1eed57a09c79ce601f6c6e3796f574df
libc6_2.23-0ubuntu11.2_amd64
```

搜索命中, 接下来下载这个libc package, 就可以拿到ld了

```bash
$ ./download libc6_2.23-0ubuntu11.2_amd64
 -> Downloading package
  -> Extracting package
  -> Package saved to libs/libc6_2.23-0ubuntu11.2_amd64
$ ls  -al ./libs/libc6_2.23-0ubuntu11.2_amd64/ld-linux-x86-64.so.2
-rwxr-xr-x 1 wxk wxk 162632 Nov  6 22:04 ./libs/libc6_2.23-0ubuntu11.2_amd64/ld-linux-x86-64.so.2
```

## 2.3. compile with specific glibc

有时候出题时需要在编译时使用非系统自带的libc.主要就是用gcc编译时设置一些参数, 方法参考[8].

直接结合具体例子来讲. 以在`ubuntu-18.04`上编译一个使用`glibc 2.32`的程序为例.

首先需要有编译好的`glibc 2.32`. 这儿推荐使用docker-glibc-builder[1]. 方便快捷.

```bash
$ sudo docker run --rm --env STDOUT=1 sgerrand/glibc-builder 2.32 /usr/glibc-compat > glibc-bin.tar.gz # 编译得到 glibc package
$ tar xvf ./glibc-bin.tar.gz
$ cd usr/glibc-compat
$ pwd
/home/wxk/hitctf-pwn/usr/glibc-compat
$ export glibc_install=`pwd` # glibc_install这个环境变量之后使用gcc的时候要用到
$ sudo ln -s /home/wxk/hitctf-pwn/usr/glibc-compat /usr/glibc-compat # ld.so 会去 /usr/glibc-compat 找数据, 所以需要建立一个符号链接
```

test_glibc.c 内容如下
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <gnu/libc-version.h>

int main(){
  printf("gnu_get_libc_version() = %s\n", gnu_get_libc_version());
  printf("hello_world\n");
  printf("This is wxk speaking\n");
  return 0;
}
```

使用如下命令编译

```bash
$ echo $glibc_install # 确保这个环境变量没问题
$ gcc \
  -L "${glibc_install}/lib" \
  -I "${glibc_install}/include" \
  -Wl,--rpath="${glibc_install}/lib" \
  -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux-x86-64.so.2" \
  -std=c11 \
  -v \
  -o test_glibc.out \
  ./test_glibc.c 
$ ./test_glibc.out
gnu_get_libc_version() = 2.32
hello world
This is wxk speaking
$ ldd ./test_glibc.out
        linux-vdso.so.1 (0x00007fff333fd000)
        libc.so.6 => /home/wxk/hitctf-pwn/usr/glibc-compat/lib/libc.so.6 (0x00007f27730ec000)
        /home/wxk/hitctf-pwn/usr/glibc-compat/lib/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f2773090000)
```

## 2.4. Miscellaneous

介绍一些glibc相关的小技巧

### 2.4.1. 源码级调试glibc函数

方法参考一个stackoverflow问题[5]. 

首先使用的libc需要带有调试符号. 系统的自带的libc可以通过apt安装调试符号. 或者自己编译带符号的libc.

然后使用`dir`命令告诉`gdb`源码路径即可.

以调试`malloc`为例(使用系统自带libc).

```bash
$ sudo apt install libc6-dbg # 安装调试符号
$ sudo apt install glibc-source # 安装(下载)源码
$ cd /usr/src/glibc # 源码下载到这个文件夹下
$ ls
debian  glibc-2.27.tar.xz
$ sudo chmod 777 -R . # 当前目录默认不可写, 需要设置一下权限
$ tar xvf ./glibc-2.27.tar.xz # 解压源码
$ cd glibc-2.27/malloc # 进入malloc源码目录
$ pwd
/usr/src/glibc/glibc-2.27/malloc
$ echo "dir `pwd`" >> ~/.gdbinit # 将dir命令写入 .gdbinit文件, gdb启动时会自动执行
```

之后用gdb调试程序遇到malloc函数就可以看到源码了.


### 2.4.2. 通过函数地址得到 libc 版本

有些题目比较狗, 明明利用过程中需要用到libc中的一些偏移, 但是题目不给libc. 这个时候如果我们可以leak libc中一些符号(通常是函数)的地址, 就可以使用工具拿到libc的版本.

原理很简单, 因为libc加载到内存中时是按页对齐的, 一页是4KB(12bit). 所以不管libc地址怎么随机化, 低12bit都是保持不变的. 但是同一个符号在不同版本的libc中低12bit通常是不一样的. 因此可以利用符号地址的低12bit来判断libc版本. 有时候仅仅通过一个符号可以找到多个候选libc, 可以通过多泄露几个符号地址缩小搜索范围.

推荐使用libc-database[2]. 具体使用方法参考官方文档即可.
如果比赛时可以联网的话(个人认为不能联网的比赛都是垃圾比赛), 可以使用在线版的libc-database: 

[https://libc.rip](https://libc.rip)


# 3. 结语

这篇博客是基于之前在简书上的那一篇博客[9]的. 增加了一些新内容, 比如compile with specific libc, libc-database等. 也简化了一些使用方法. 整体结构脉络更加清晰了.

之后如果遇到glibc相关的知识, 本篇博客也会继续更新的. 

如果有任何疑问或者观点, 欢迎在评论区讨论 :P .

# 4. 参考

1. [编译glibc的docker - github](https://github.com/sgerrand/docker-glibc-builder)
2. [libc-database - github](https://github.com/niklasb/libc-database)
3. [清华tuna镜像站glibc文件夹](https://mirrors.tuna.tsinghua.edu.cn/gnu/glibc/)
4. [glibc官网编译指南](https://links.jianshu.com/go?to=https%3A%2F%2Fgnu.org%2Fsoftware%2Flibc%2Fmanual%2Fhtml_mono%2Flibc.html%23toc-Installing-the-GNU-C-Library)
5. [Include source code of malloc.c in gdb? - stackoverflow](https://stackoverflow.com/questions/29955609/include-source-code-of-malloc-c-in-gdb)
6. [patchelf - github](https://github.com/NixOS/patchelf)
7. [glibc官方镜像站](https://ftp.gnu.org/gnu/glibc/)
8. [How can I link to a specific glibc version? - stackoverflow](https://stackoverflow.com/questions/2856438/how-can-i-link-to-a-specific-glibc-version)
9. [同时使用多种版本的libc && 编译libc](https://www.jianshu.com/p/ee1ad4044ef7)