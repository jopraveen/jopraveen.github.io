---
title: HTB [Squashed]
date: 2023-02-07 01:28:05 +0200
categories: [linux,nfs,X11]
tags: [HACKTHEBOX MACHINES]
excerpt: Squashed is an easy hackthebox machine that was created by polarbearer & C4rm3l0 which involves a writeable share to upload a php shell on the webapp, for root we will enumeate X11 and get root credentials by taking screenshots
---

![](https://i.imgur.com/GRiYuEd.png)

## RECON

### port scan

```js
PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp    open  http     syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      42834/udp6  mountd
|   100005  1,2,3      45599/tcp6  mountd
|   100005  1,2,3      50879/tcp   mountd
|   100005  1,2,3      58687/udp   mountd
|   100021  1,3,4      33135/tcp6  nlockmgr
|   100021  1,3,4      40939/tcp   nlockmgr
|   100021  1,3,4      43633/udp   nlockmgr
|   100021  1,3,4      51459/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  syn-ack 3 (RPC #100227)
40939/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
45489/tcp open  mountd   syn-ack 1-3 (RPC #100005)
50879/tcp open  mountd   syn-ack 1-3 (RPC #100005)
54255/tcp open  mountd   syn-ack 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### WebApp Enumeration

- Nothing fancy, just a static web page with zero dynamic functionality

![](https://i.imgur.com/OqowpEQ.png)

- It's a php site
- So, let's enumerate the nfs

### NFS enumeration

![](https://i.imgur.com/0d9L7sE.png)

- We can mount these folders to our local
- There's a `Passwords.kdbx` file in **ross** user's Documents directory

```js
➜  squashed keepass2john Passwords.kdbx
! Passwords.kdbx : File version '40000' is currently not supported!
```

- Unfortunately we can't able to crack it
- Let's check the other mounted folder `/var/www/`

![](https://i.imgur.com/LCfEReG.png)
- Only the uid `2017` and `www-data` has access to it
- Let's create a user in our box and give him the uid => `2017`

![](https://i.imgur.com/1YoqU6t.png)

- We changed his uid successfully

![](https://i.imgur.com/np13v0e.png)

- Now we can able to access the contents of the **html** folder

## INITIAL FOOTHOLD

- Let's try to create a file here and see it's available in the webpage or not

![](https://i.imgur.com/3nTgiu8.png)

- Now time for a php rev shell

![](https://i.imgur.com/y1KiO5x.png)

- 1) Editing the php-rev shell and starting a ncat listener
- 2) Copying the rev shell to the mounted `/var/www/html/` folder
- 3) Triggering the rev shell
- 4) Got shell as `alex`

- Grab the **user.txt** in alex's home directory

## PRIVESC

![](https://i.imgur.com/FdZ15pn.png)

```js
ross        1578  0.0  0.1   6892  3384 ?        S    03:16   0:00  |   _ /bin/bash /usr/share/keepassxc/scripts/ross/keepassxc-start
ross        1593  0.1  4.9 777124 101232 ?       SLl  03:16   0:05  |       _ /usr/bin/keepassxc --pw-stdin --keyfile /usr/share/keepassxc/keyfiles/ross/keyfile.key /usr/share/keepassxc/databases/ross/Passwords.kdbx
```

- We can't access these files, so we need to switch to ross

### X11

- Now let's enumerate the other mounted directory `/home/ross`

![](https://i.imgur.com/3Z0khET.png)

- These files are new to me, so I've reffered [0xdf's writeup](https://0xdf.gitlab.io/2022/11/21/htb-squashed.html#shell-as-root) & [Bookhacktricks](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11)
- Here we can see we need the uid => `1001` to access these files, so let's do the thing that we did for the `2017` uid

![](https://i.imgur.com/Blw6wQT.png)

- Now we can able to access these files
- I'm going to copy these files to my local, coz mounted folders are slow

![](https://i.imgur.com/Uc2fQLj.png)

- This is `MIT-MAGIC-COOKIE-1` which means,

> MIT-magic-cookie-1: Generating 128bit of key ("cookie"), storing it in ~/.Xauthority (or where XAUTHORITY envvar points to). The client sends it to server plain! the splain! the server checks whether it has a copy of this "cookie" and if so, the connection is permitted. the key is generated by DMX.


- So we can use this file to authenticate

![](https://i.imgur.com/HRzPXbW.png)

- The display is connected in `:0`
- But we don't have access, so let's copy this file to alex's home directory

![](https://i.imgur.com/sASeGiT.png)

- I'm setting `XAUTHORITY=/home/alex/.Xauthority`, so it checks this file and we will be authenticated

![](https://i.imgur.com/KTRTcya.png)

- Now we can do multiple things, Interestingly we can take screenshots
- That's explained [here](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11#screenshots-capturing)

```js
xwd -root -screen -silent -display :0 > screenshot.xwd
```

![](https://i.imgur.com/3Aj51hB.png)

- 1) Sucessfully took the screenshot
- 2) But we don't have convert
- 3) So let's start a python server
- 4) And wget it to our local

![](https://i.imgur.com/C8S2Kmv.png)

- Converted it to `png` format
- We can see the root user's password there

![](https://i.imgur.com/waOggx3.png)

- creds => `root:cah$mei7rai9A`
- It worked and we're root!!

### References


- [0xdf's writeup](https://0xdf.gitlab.io/2022/11/21/htb-squashed.html#shell-as-root)
- [Stackoverflow](https://stackoverflow.com/questions/37157097/how-does-x11-authorization-work-mit-magic-cookie/37367518#37367518)
- [Bookhacktricks](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11)
