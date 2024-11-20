---
layout: post
title: how to patch vmdk
date: 2024-11-20 15:29 +0800
---

# 当没有root密码 该如何给vmdk打patch来进入系统呢？

核心：
* 生成已知密码
```
➜  ~ openssl passwd -6 123456
$6$Wn6EsJ4RFFqIxsLs$nVZCosJw2DnwI8I52KjeTYIj8j5ghA5/YjKylfeGyS1j.yr0ygGlzEeJfF0MW2ToO7lLhqzEt8LyOUtayPewz.
```
* 修改/etc/passwd 【推荐,不需要动/etc/shadow】
```
abc:$6$Wn6EsJ4RFFqIxsLs$nVZCosJw2DnwI8I52KjeTYIj8j5ghA5/YjKylfeGyS1j.yr0ygGlzEeJfF0MW2ToO7lLhqzEt8LyOUtayPewz.:0:0:root:/root:/usr/bin/zsh  
```
修改/etc/shadow【部分系统推荐,不需要动/etc/passwd】
```
test:$6$Wn6EsJ4RFFqIxsLs$nVZCosJw2DnwI8I52KjeTYIj8j5ghA5/YjKylfeGyS1j.yr0ygGlzEeJfF0MW2ToO7lLhqzEt8LyOUtayPewz.:20046:0:99999:7:::
```
其他还有很多值得关注的文件，如`/etc/rc.local`、`/etc/ssh/sshd_config`还有对应用户的`authorized_keys`等
```
PermitRootLogin yes
```

## 法一：使用diskgenius
diskgenius可以将vmdk挂载，从而进行文件读写，好处是浏览十分方便，读文件推荐用DG，挂载也很快。比较有意思的是写文件：

* 接下来神奇的来了，在对国产OS进行实验时，发现将文件复制到桌面，从外面改好 再复制到DG里（ 字节数一样）改动仍未生效，进恢复模式看后，shadow并未被修改一个是文件的修改时间会发生变化 一个可能会影响文件inode（猜的） 导致尽管在DG里看着是修改了 但是进系统后并没有改 

* 疑惑的是改其他一些文件没啥问题 改shadow就会这样；现在一个做法是直接去DG里打开shadow文件，查看文件原始数据的时候修改（右键文件-文件扇区跳转-文件数据起始扇区） 这样不论是读写权限、修改时间、字节数均不变 实现最稳定的修改，实践证明这是可行的，因此我觉得这主要是DG的bug

![alt text](/assets/img/2024-11-20-15-54-08.png)

因此 在使用DG时，最好修改passwd，修改这个文件是没啥问题的

## 法二：使用恢复模式
* 用DG修改shadow-，然后进恢复模式
* 恢复模式：在引导页界面，立马按`e`，编辑grub的config，将`ro`及之后的内容全部换成`rw init=/bin/bash`，`ctrl+x`后即可进入恢复模式，将shadow-拷贝至shadow
* `/sbin/reboot -f`

## 法三： 使用vmware workstation挂载一块磁盘

https://nosec.org/home/detail/4990.html

## 法四：使用linux进行挂载

`apt-get install qemu-utils kpartx`

### 步骤 1：将 VMDK 文件转换为 RAW 格式

首先，需要将 VMDK 文件转换为 RAW 格式，以便可以挂载和编辑：

```bash
qemu-img convert -O raw your-file.vmdk /tmp/disk.raw
```

### 步骤 2：创建设备映射
    
使用 `kpartx` 创建设备映射：
    
```bash
kpartx -av /tmp/disk.raw    
```
    
### 步骤 3： 挂载分区
    
找到你需要修改的分区，通常会被映射为类似于 `/dev/mapper/loop0p1`。挂载它：

```bash
mkdir /mnt/part1
mount /dev/mapper/loop0p1 /mnt/part1
```

### 步骤 4: 修改文件

在挂载点 `/mnt/part1` 中进行你需要的修改。例如，编辑一个文件：

```bash
vim /mnt/part1/etc/shadow
```

### 步骤 5: 卸载分区

修改完成后，卸载文件系统：

```bash
umount /mnt/part1
```

### 步骤 6: 删除设备映射

```bash
kpartx -d /tmp/disk.raw
```


### 步骤 7：将 RAW 文件转换回 VMDK 格式

```bash
qemu-img convert -O vmdk /tmp/disk.raw your-new-file.vmdk
```
此时可用新的文件进行挂载