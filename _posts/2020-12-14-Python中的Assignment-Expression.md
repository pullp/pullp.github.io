---
title: Python中的Assignment Expression
excerpt: "最近在用python写一个项目, 选择了最新的python3.9, 在写代码的过程中难免要查询一些python相关的知识, 在查询过程中发现了python 3.8 中引入的一个新特性: `Assignment Expression`, 这个特性并不复杂, 不过感觉应用场景还是挺广泛的."
date: 2020-12-14
tags: python
categories: python基础
---


# 1. 前言

| 更新时间  | 更新内容  |
|  ----     | ----      |
| 2020-12-14 | 初稿     |

最近在用python写一个项目, 选择了最新的python3.9, 在写代码的过程中难免要查询一些python相关的知识, 在查询过程中发现了python 3.8 中引入的一个新特性: `Assignment Expression`, 这个特性并不复杂, 不过感觉应用场景还是挺广泛的. 本文中就是结合一些实例来介绍一下这个新特性, 更多相关信息建议阅读官方文档\[1\].

--- 

# 2. 正文

## 2.1. 基本用法

`Assiggnment Expression` 的标识符是 `:=`, 用于将一个表达式赋值给一个变量:

```python
NAME := expr
```

乍一看功能和 `=` 差不多. 


`:=` 和 `=`的区别在于, `:=`这个表达式会在赋值后返回左值. 而`=`表达式仅仅是赋值, 没有任何返回.

```
>>> res = (a := 1)
>>> print(res)
1
>>> res = (b = 1)
SyntaxError: invalid syntax
```

通过使用`Assiggnment Expression`我们可以使用一行代码来实现原来需要两行代码实现的功能

*下面的示例摘自\[2\]*

```python
# before use `Assiggnment Expression`
command = input("> ")
while command != "quit":
    print("You entered:", command)
    command = input("> ")
```

```python
# after use `Assiggnment Expression`
while (command := input("> ")) != "quit":
    print("You entered:", command)
```

## 2.2. 优先级

`:=` 和 `=` 的优先级也有区别:

`:=`的优先级比 `,` 高. (`=`的优先级比`,`低). 所以会有如下区别

```python
>>> a = 1, 2 # valid. 先计算 (1, 2), 然后赋值给 a 
>>> print(a)
(1, 2)
>>> b = (a := 1, 2) # 先计算 a := 1, 然后将 (a, 2) 赋值给 b
>>> prin(a)
1
>>> print(b)
(1, 2)
```

## 2.3. 使用限制

`:=`的使用是有限制的, 要求右边只能是一个变量(原文为"Single assignment targets other than a single NAME are not supported:").

对于如下情况就会报错

```python
some_instance = SomeClass()
some_instance.some_member := 123 # invalid

arr = [1,2]
arr\[0\] := 3 # invalid

(a, b) := (1, 2) # invalid
```

# 3. 结语


子曰:

> 人生苦短, 我用python

`:=`的出现使得python可以写出更简洁的代码, 挺好.

# 4. 参考

1. [Assignment Expressions --  PEP 572](https://www.python.org/dev/peps/pep-0572)
2. [“:=” syntax and assignment expressions: what and why? -- Stackoverflow](https://stackoverflow.com/questions/50297704/syntax-and-assignment-expressions-what-and-why)