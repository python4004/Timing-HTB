# Hack The Box - Timing
![home](https://user-images.githubusercontent.com/36403473/167136582-1b224c83-8ce5-4772-8766-304e5876294c.jpg)

### Brief of attacks :

1-LFI

2-source code rewiew (php)

2-File upload 



#### 1-Nmap

```
nmap -sC -sV  -P 10.10.11.135
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-06 13:06 GMT
Nmap scan report for Timing.htb (10.10.11.135)
Host is up (0.49s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```
 let's explore port `80` ,it opened just login page. 

![1](https://user-images.githubusercontent.com/36403473/167138043-200b10a8-6468-408b-a3ee-f84dd168432b.png)

so lets frist try `sql injection` but not work so lets explore directories i prefere `dirsearch` tool
```
[13:38:41] 200 -    0B  - /image.php
[13:38:48] 200 -    5KB - /login.php

```

