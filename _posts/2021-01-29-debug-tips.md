---

title: debug tips
tags:
  - ctf
  - pwn
categories:
  - tips
date: 2021-01-29 15:12:03
excerpt: "some tips about debug"
---

# 前言

| 更新时间  | 更新内容  |
|  ----     | ----      |
| 2021-02-02 | 初稿     |

记录一些关于调试的小技巧.

---

# 正文

## 传统pwn调试

介绍传统glibc pwn题调试的一些技巧:

### 关闭地址随机化

地址随机是一种针对攻击的缓解措施, 此处讨论的代码段的随机化. 我们使用`checksec`检查可执行文件保护措施的时候可以看到`PIE`这一项:

```bash
$ checksec /bin/ls
[*] '/bin/ls'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

**PIE**(**P**osition **I**ndependent **E**xecutables)表示这个程序是位置无关的, 即它可以被加载到内存任意地址处都可以正常执行. 默认情况下这类程序每次执行的时候在内存中的位置都是随机的(按页对齐). 因此极其不利于我们调试的时候进行查看内存, 下断点等操作. 因此我们需要想办法将随机化关掉.

负责将可执行文件加载到内存中的操作(应该)是内核中某块代码负责完成的, 好消息是, 内核给我们提供了一个选项: 用于控制将可执行文件加载到内存中时的随机化程度, 该选项的值可以为 0, 1, 2. 为0时内核在进行加载时就不会进行随机化操作, 为2时则会进行随机化操作. (1 和 2的区别我也不太清楚). 因此我们将该选项置为即可禁用加载时的随机化操作. 此时即使可执行文件支持随机化加载也无济于事了.

修改命令如下:

```bash
sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
```

**注意**: 关闭随机化会降低系统的安全性, 所以不建议在服务器上进行该操作.



我们在使用IDA分析这类PIE程序的时候, IDA通常是将elf文件的基地址当作0. 此时我们我们如果在IDA里面看了一下地址, 然后想去gdb里面下个断点或者看个内存什么的也不是很很方便, 需要加上一个基地址什么的. 我们可以通过如下操作在IDA中设置可执行文件的基地址:

```
Edit -> Segments -> Rebase Program... -> 在value栏输入程序基地址(gdb下使用`vmmap`指令查看 or `cat /proc/pid/maps`查看)
# 一个典型值是 : 0x0000555555554000 (纯经验, 不一定靠谱)
```

### 源码级调试glibc中的函数

参考笔者的另一篇文章: [glibc相关操作记录](https://pullp.github.io/2020/11/06/11-glibc-tips/#2-4-2-%E9%80%9A%E8%BF%87%E5%87%BD%E6%95%B0%E5%9C%B0%E5%9D%80%E5%BE%97%E5%88%B0-libc-%E7%89%88%E6%9C%AC)

### gdb 自动化 (commands)

参考笔者的另一篇文章: [gdb自动化操作](https://pullp.github.io/2020/09/05/7-gdb-commands/)

### 调试多进程程序

使用gdb提供的命令设置`fork`时跟随的执行流:

```
set follow-fork-mode child/parent
```

### 与pwntools联动

在pwntools中启动gdb调试有两种方法

```python
io = gdb.debug(["pwn", "arg1"], "gdb script")
```

```python
io = process(["pwn", "arg1"])
gdb.attach(io, "gdb script")
```

第一种方法get shell时会失败, 注意下即可

第二种方法程序启动之后就会一直执行到阻塞处(如等待用户输入), 所以下断点要下载阻塞之后, 否则可能断不下来.

### 与IDA联动

参考:[IDA远程调试Linux文件（QEMU）](https://www.cnblogs.com/from-zero/p/13300396.html)

## qemu system mode 调试

通常是kernel pwn. qemu 启动时加上以下参数

```bash
-S -gdb tcp::1234
```

其中:

- -S表示停在执行之前等待gdb连接
- -gdb tcp::1234 表示监听 1234 端口等待 gdb 连接

调试脚本模板如下:

```bash
#!/bin/sh
gdb -q \
    -ex "file vmlinux" \
    -ex "target remote localhost:1234"
    -ex "break *some_addr" \
    -ex "break some_symbol" \
    -ex "add-symbol-file file_path addr"
    -ex "continue" \
;
```



## qemu user-mode 调试

通常是一些非x86架构的题目. 对于非x86架构的题目调试的时候需要使用 `gdb-multiarch`, 同时对于不同架构, gdb插件的支持情况也有所不同. 比如 riscv:rv64下pwngdb就用不了, 但是gef可以使用(偶尔会报错).

用qeme启动时加上`-g port `参数, 设置监听gdb连接的端口.

### riscv调试

```bash
#直接启动
./qemu-riscv64 main

#调试启动
./qemu-riscv64 -g 1234 main

#调试脚本(如果是32位的话将 riscv:rv64 换成  riscv:rv32 即可)
#!/bin/sh
gdb-multiarch -q \
  -ex 'set architecture riscv:rv64' \
  -ex 'file main' \
  -ex 'target remote localhost:1234' \
;
```

### arm 调试

```bash
# 执行脚本
qemu-aarch64 -cpu ma  x -g 1234 -L . ./chall

# 调试脚本
gdb-multiarch -q \
  -ex 'set architecture aarch64' \
  -ex 'file pwn' \
  -ex 'target remote localhost:1234' \
  -ex continue \
;
```



其余架构的题目没有遇到过, 欢迎补充.



## 直接调试qemu程序

通常是一些qemu逃逸题目. 

下面的实例来自于[strng2 湖湘杯 2019 -- 安全客](https://www.anquanke.com/post/id/197650#h3-6)

```bash
$ strng2 cat ./debug 
file qemu-system-x86_64
b strng_mmio_read
b strng_mmio_write
b strng_pmio_read
b strng_pmio_write
set $state=0x555556a64db0
set $addr=$state+0xaf0
set $regs=$state+0xaf8
set $timer=$state+0xbf8
run -initrd ./rootfs.cpio -kernel ./vmlinuz-4.8.0-52-generic -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic -L ./dependency/usr/local/share/qemu -L pc-bios -device strng
$ strng2 sudo gdb --command=./debug
```

# 结语

都是一些经验之谈,欢迎补充 :smile:.

# 参考

- [strng2 湖湘杯 2019 -- 安全客](https://www.anquanke.com/post/id/197650#h3-6)
- [IDA远程调试Linux文件（QEMU）](https://www.cnblogs.com/from-zero/p/13300396.html)