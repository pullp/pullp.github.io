---
layout:     post
title:      gdb 自动化操作
excerpt:    才发现gdb有commands这个东西, 学习记录一下
date:       2020-09-05
author:     wxk1997
header-img: img/pwn-bg.png
catalog: true
tags:
    - gdb
    - python
---

# 前言

在做强网杯的一道vmpwn的时候, 有了这样一种需求.

> gdb可不可以实现这样一种功能: 在某处下个断点,  然后让程序运行到这个地方自动将当前的寄存器值保存到某个文件中然后继续执行. 最后得到一个包含执行过程中每次到达这个位置的时候的寄存器的值的文件

据我所知ollydbg是有这种功能的. 可以在每次断点处执行一个脚本. 在脚本中可以通过一些指令将寄存器中的内容保存到文件中并继续执行, 直到下次遇到这个断点或者程序退出.

经过搜索, 发现gdb提供了一个commands命令[2], 可以实现类似的功能. 在此记录一下.

# 正文

我们以这份代码为例, 我们希望得到每次循环中val的值.

```c
int main(){
    int val = 1;
    for (int i=0; i<100; i++){
        val = (7 * (val + 1) / 3) & 0xffff;
    }
    return 0;
}
```

源码编译得到二进制文件中main函数反汇编结果如下

```asm
00000000004004d6 <main>:
  4004d6: push   rbp
  4004d7: mov    rbp,rsp
  4004da: mov    DWORD PTR [rbp-0x8],0x1
  4004e1: mov    DWORD PTR [rbp-0x4],0x0
  4004e8: jmp    400517 <main+0x41>
  4004ea: mov    eax,DWORD PTR [rbp-0x8]
  4004ed: lea    edx,[rax+0x1]
  4004f0: mov    eax,edx
  4004f2: shl    eax,0x3
  4004f5: sub    eax,edx
  4004f7: mov    ecx,eax
  4004f9: mov    edx,0x55555556
  4004fe: mov    eax,ecx
  400500: imul   edx
  400502: mov    eax,ecx
  400504: sar    eax,0x1f
  400507: sub    edx,eax
  400509: mov    eax,edx
  40050b: and    eax,0xffff
  400510: mov    DWORD PTR [rbp-0x8],eax
  400513: add    DWORD PTR [rbp-0x4],0x1
  400517: cmp    DWORD PTR [rbp-0x4],0x63
  40051b: jle    4004ea <main+0x14>
  40051d: mov    eax,0x0
  400522: pop    rbp
  400523: ret
```

可以看到在 `0x400510` 处将计算得到的 `val` 从 `rax` 寄存器中存储到了栈上 `rbp-0x08`地址处.

那么我们就可以写以下gdb脚本 `dump.gs`

```gdb_script
b *0x400510
commands
silent
printf "val is %#x\n", $rax
c
end
```

然后在调试的时候加载这个脚本并直接`run`即可

```bash
root@vm$ gdb ./test
(gdb) source ./dump.gs
Breakpoint 1 at 0x400510: file test.c, line 9.
(gdb) run
```

就可以打印出每次循环时val的值

```
(gdb) run
val is 0x4
val is 0xb
val is 0x1c
val is 0x43
val is 0x9e
val is 0x173
val is 0x364
val is 0x7eb
...
```

现在可以将val的值打印到终端了. 那么如何将这些信息保存到文件中呢? 在 `run` 之前执行如下命令即可[3]

```
set logging on
```

再次run之后就可以看到当前目录下多了一个 `gdb.txt`. 里面就是打印的内容.

```bash
➜  local git:(master) ✗ cat ./gdb.txt
Starting program: ...
warning:...
warning: ...

val is 0x4
val is 0xb
val is 0x1c
...
```

目前位置虽然可以满足一开始的需求了, 但是每次操作的时候还是感觉很麻烦, 不过做题的时候时间原因到这儿就没有继续深究了. 现在有空了再看看有没有什么更加高效优雅的解决方案.

这个时候自然就想到万能的`python`了. 通过对官方文档[4]的简单阅读, 最终得到如下脚本. 可以将每次循环的值写入文件.

```python
# dump.py
gdb.execute("b *0x400510")
gdb.execute("start")
vals = []

for i in range(100):
    gdb.execute("continue")
    vals.append(str(int(gdb.parse_and_eval("$rax"))))

open("./vals", "w").write("\n".join(vals))
````

直接执行如下命令

```bash
gdb ./test -x ./dump.py
```

就可以得到一个包含了100次循环中`val`值的文件`./vals`

```bash
➜  local git:(master) ✗ cat ./vals
4
11
28
67
158
371
868
...
```


# 结语

常言道 `人生苦短, 我用python`, 诚不我欺. python灵活的语法以及强大的兼容性使得python在这类写脚本的场景中十分好用. 大多数时候都可以替代`shell脚本`了. 有时我甚至会想将来会不会又某个shell内置python的那一天. 自此 `shell 脚本`是路人.


# 参考

1. [so上有人提了和我类似的需求](https://stackoverflow.com/questions/13935443/gdb-scripting-execute-commands-at-selected-breakpoint)
2. [commands 官方文档](https://sourceware.org/gdb/onlinedocs/gdb/Break-Commands.html)
3. [如何将gdb的输出保存到文件](https://stackoverflow.com/questions/5941158/gdb-print-to-file-instead-of-stdout)
4. [Extending GDB using Python](https://sourceware.org/gdb/current/onlinedocs/gdb/Python.html#Python)