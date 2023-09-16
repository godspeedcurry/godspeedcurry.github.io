---
layout: post
title: 微信小程序抓包
date: 2023-09-16 23:00 +0800
---
## burp
burp监听任意端口，如8081

## 使用clash的yaml进行流量代理

yaml内容
```yaml
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
dns:
    enable: true
    ipv6: false
    default-nameserver: [114.114.114.114, 183.60.83.19, 180.76.76.76, 180.184.1.1, 223.5.5.5, 119.29.29.29]
    enhanced-mode: fake-ip
    fake-ip-range: 198.18.0.1/16
    use-hosts: true
    nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query']
    fallback: ['https://doh.dns.sb/dns-query', 'https://dns.cloudflare.com/dns-query', 'https://dns.twnic.tw/dns-query', 'tls://8.8.4.4:853']
    fallback-filter: { geoip: true, ipcidr: [240.0.0.0/4, 0.0.0.0/32] }
proxies:
- { name: burp, type: http, server: 127.0.0.1, port: 8081}

proxy-groups:
- { name: auto, type: select, proxies: ['burp'] }

rules:
  - 'MATCH,auto'
```



![Alt text](/assets/img/2023-09-16-23-00-50.png)