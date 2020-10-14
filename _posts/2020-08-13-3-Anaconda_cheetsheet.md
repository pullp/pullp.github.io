---
layout:     post
title:      Anaconda常用操作
subtitle:   记录一些conda常用操作备忘
date:       2020-08-13
author:     wxk1997
header-img: img/default-bg.png
catalog: true
tags:
    - python
    - cheetsheet
---

# 前言

python这门语言的灵活性让人写起来很快乐, 但是不同版本之间的兼容性较差以及包管理问题经常会导致一些非常烦人的问题, 所以在一台机器上安装多个版本的python是一种很常见的需求. 

提供这种功能的工具有很多, 比如 `virtualen` 啥的, 但是用起来比较麻烦, 直到最近发现 anaconda 这个工具才算是终于找到一个舒服的解决方案了. 这个工具不但功能很强大, 而且用起来也很方便. 本文一则是介绍一下这个工具, 二则是记录一下这个工具常用操作, 以备不时之需. (顺便水一篇博客hhh)

# 正文

记录conda常用操作

## 环境和包管理

```
conda create ‐n env_name python=2.x|python=3.x # 创建env_name环境以及在该环境下安装package_name包
conda env remove ‐n env_name # 删除环境
conda activate env_name # 激活或者禁用当前环境
conda deactivate  # 退出当前环境
conda info ‐‐env / conda env list # 查看所有的环境，带*的为激活的环境

conda list # 列出当前环境下所有安装包
conda list ‐n my_env # 列出 my_env环境中所有的安装包

conda search package_name # 搜索是否有这个安装包，没有的话无法使用conda install 安装
conda install package_name # 在当前环境中安装 package_name 包
conda update package_name # 在当前环境中更新 package_name 包
```

## 禁用自启动

```
conda config --set auto_activate_base false
```

## 重命名环境

conda没有提供重命名功能, 所以可以先复制一个环境然后删除原先环境

```
conda create --name new_name --clone old_name
conda remove --name old_name --all # or its alias: `conda env remove --name old_name`
```

## 设置代理

修改 `~/.condarc`
```
proxy_servers:
  http: http://host:port
  https: http://host:port
```

## 添加清华源

```
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/free
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/bioconda
conda config --set show_channel_urls yes
```

## 更新conda

```
conda update conda
```

# 结语

经过一段时间的时候, 还是很喜欢这个工具的. 功能强大, 操作方便. 但是也有一些缺点, 首先是目前尚不支持powershell, 在windows下只能使用 cmd. 其次是性能感觉还是要差一点, 在使用ipython的过程中自动补齐会有一点延迟.

不过还是要推荐有同时使用多个版本python的需求的同学们试一下这个工具.

# 参考

1. [Anaconda 官网](https://www.anaconda.com/products/individual#linux)
2. [Anaconda 设置代理](https://docs.anaconda.com/anaconda/user-guide/tasks/proxy/)
3. [SO上关于重命名环境的问题](https://stackoverflow.com/questions/42231764/how-can-i-rename-a-conda-environment)