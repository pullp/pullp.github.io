---
title: log in python
excerpt: "记录一下python中 logging 库的一些基本用法, 备忘"
date: 2020-12-15 19:25:11
tags: log
categories: python基础
---

# 1. 前言

| 更新时间  | 更新内容  |
|  ----     | ----      |
| 2020-12-15 | 初稿     |

---

大多数人写代码的时候难免会遇到代码出错的情况, 为了分析出问题的地点往往需要对程序进行调试, 而最快捷的调试方法应该就是`print调试大法`了. 通过打印执行过程中的变量来进行分析. 不过这种方法有一个缺点, 有时候问题比较复杂, 因此在分析问题过程中会在代码中插入大量的`print`语句来打印变量. 当成功定位到问题并修复问题之后我们想要删除那些`print`语句时就会遇到问题,  `print`语句太多, 一个个删除起来麻烦, 如果批量删除的话又可能误伤那些正常逻辑部分的代码. 此时我们可以考虑使用`日志(log)`功能, 当成功定位到问题之后只需要修改一句就可以不再看到那些打印的内容.


# 2. 正文

python官方提供了一个日志库: `logging`. 本文主要就是介绍该库的一些基础使用方法, 仅供参考. 更详细的使用方法敬请参考官方教程\[1\]. 

**如有出入, 以官方文档为准**

## 2.1. 基本用法

`logging`库非常好上手, 执行如下代码就可以往终端打印内容(log record).

```python
import logging

logging.warn("hello from logging")
```

`logging` 提供了五个打印函数:

```python
logging.debug()
logging.info()
logging.warning()
logging.error()
logging.critical()
```

这五个函数有不同的级别, `logging.debug()` 级别最低, `logging.critical()`级别最高.下表给出了五个级别的推荐使用场景:
| Level | When it's used |
| -- | -- |
| DEBUG | 打印详细的信息, 用于程序出问题时进行分析 |
| INFO | 记录一些内容用于确认程序在按照预期执行 |
| WARNING | 提醒一些非预期情况发生了. 或者用于提醒可能将要出现的问题(如磁盘空间不足). 但是程序仍然在正常执行 |
| ERROR | 由于一些更严重的问题, 程序某些功能无法正常工作 |
| CRITICAL | 出现了严重错误, 程序可能无法继续执行 |

 我们可以通过`logging.basicConfig()`函数来设置我们期望的日志级别`loglevel`(`loglevel`默认是`WARNING`). 仅当打印函数的级别大于等于当前的`loglevel`时, 打印的内容才会被输出到终端上.

因此如果执行如下代码:

```python
import logging

logging.debug("hello from debug")
logging.warning("hello from warning")
logging.error("hello from error")
```

我们就只能在终端上看见;

```
WARNING:root:hello from warning
ERROR:root:hello from error
```

为了让`logging.debug()`打印的内容也能被看见, 我们可以设置`loglevel`为`logging.DEBUG`

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.debug("hello from debug")
```

至此, 我们已经可以实现前言中的需求了(修改`loglevel`). 接下来我们会更深入地了解`logging`库, 了解一些更高级的用法, 来实现这样一个功能: 

将`level>=DEBUG`的日志输出到一个文件中, 同时将`level>=INFO`的日志打印到终端上.

## 2.2. Logger, Handler and  Filter

`logging`库使用了模块化的设计, 提供了几个组件: `logger`, `handler`, `filter`以及`formatter`.

- `logger` 向用户代码暴露调用接口(api)
- `handler` 负责将日志记录(log record)送达正确的目的地(可以是终端/文件/邮件/etc...)
- `filter` 负责对日志记录(log record)进行过滤操作
- `formatter` 决定日志记录(log record)最终输出格式.

为了将日志打印到终端上.
我们需要先有一个`logger`用于调用库提供的各种api, 下面是一种推荐的获取`logger`的方法. 

```python
logger = logging.getLogger(__name__)
```

我们可以通过调用`logger.setLevel()`函数来设置`logger`的`loglevel`

```python
logger.setLevel(logging.DEBUG)
```

然后我们需要一个`handler`负责将日志记录打印到终端上, `handler` 同样可以设置`loglevel`

```python
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
```

然后将这个`handler`和之前获得的`logger`绑定起来.

```python
# add ch to logger
logger.addHandler(ch)
```

之后使用`looger`记录日志, `logger`会先将日志的级别与自身的`loglevel`进行比较, 仅当日志级别大于等于自身`loglevel`时才会将日志输出给与其绑定的`handler`. `handler`在收到日志之后同样会将日志的级别与自身的`loglevel`进行比较, 仅当日志级别大于等于自身`loglevel`时才会将其输出到对应的目的地.

所以执行如下代码

```python
import logging

# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# create console handler and set level to info
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# add ch to logger
logger.addHandler(ch)

# 'application' code
logger.debug('debug message')
logger.info('info message')
logger.warning('warn message')
logger.error('error message')
logger.critical('critical message')
```

我们会在终端看到下输出, 没有`logger.dbeug()`的输出

```
info message
warn message
error message
critical message
```

此时我们就已经实现将级别大于等于`INFO`的日志输出到终端的功能了, 接下来要实现的就是将级别大于等于`DEBUG`都输出到文件中的功能.

实现起来也很简单: 创建一个输出到文件`handler`, 设置其`loglevel`为`DEBUG`并将其绑定到`logger`上即可. 将如下代码添加到上边的代码中.

```python
fh = logging.FileHandler("tmp.log")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
```

再次执行, 可以在`tmp.log`文件中看到`logger.debug()`输出的日志:

```
debug message
info message
warn message
error message
critical message
```

至此, 我们已经可以实现上一节末尾期望的功能, 但是还可以再完善一下. 比如每次打印日志的时候自动把时间日志级别等信息加上. 这个功能可以通过`Formatter`实现.

我们需要新建一个`formatter`, 然后将其和某个`handler`绑定起来, 之后这个`handler`的所有输出都会使用这个`formatter`进行格式化了. 比如我们给终端打印的`handler`添加一个`formatter`, 让其在每次打印日志时带上时间和级别信息. 将如下代码添加到之前程序对应部分.

```python
# create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# add formatter to ch
ch.setFormatter(formatter)
```

再次执行可以看到终端输出变成这样了:

```
2020-12-15 20:42:29,329 - __main__ - INFO - info message
2020-12-15 20:42:29,329 - __main__ - WARNING - warn message
2020-12-15 20:42:29,330 - __main__ - ERROR - error message
2020-12-15 20:42:29,331 - __main__ - CRITICAL - critical message
```

而`tmp.log`文件中的日志并没有变化.

如果基于`logger`和`handler`的`loglevel`的过滤方法还无法满足需求的时候, 就可以使用`fileter`来实现更加精细的过滤控制. 因为这个功能我也不熟悉, 所以也不敢胡说, 建议参考官方文档\[2\].

## 2.3. colorful log!

日志一多, 放眼望去白花花一大片. 想要定位到自己想要的信息就比较费力. 如果我们可以让不同级别的信息使用不同的颜色打印, 就可以提高定位到目标日志的效率.

这儿推荐`colorlog`库\[3\], 可以和`logging`库配合使用. 可以使用`pip`安装 `pip install colorlog`. 安装好之后在使用`colorlog`库提供的`formatter`. 其中有一个`log_color`字段, 可以用来给日志添加颜色. `colorlog`库还支持自定义各个`loglevel`的颜色(通过`log_colors`参数)

```
import logging
import colorlog

# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)


fh = logging.FileHandler("tmp.log")
fh.setLevel(logging.DEBUG)

# create formatter
formatter = colorlog.ColoredFormatter('%(log_color)s%(asctime)s - %(levelname)s - %(message)s',log_colors={
		'DEBUG':    'cyan',
		'INFO':     'green',
		'WARNING':  'yellow',
		'ERROR':    'red',
		'CRITICAL': 'red,bg_white',
	},)
# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
logger.addHandler(fh)

# 'application' code
logger.debug('debug message')
logger.info('info message')
logger.warning('warn message')
logger.error('error message')
logger.critical('critical message')
```

执行上面的代码, 就可以在终端上看到各种颜色的日志了

# 3. 结语

~~print调试大法好~~

log调试大法好

233

# 4. 参考

1. [Logging HOWTO -- Python](https://docs.python.org/3/howto/logging.html)

2. [Filter Objects -- logging库官方文档](https://docs.python.org/3/library/logging.html#logging.Filter)

3. [python-colorlog -- github](https://github.com/borntyping/python-colorlog)