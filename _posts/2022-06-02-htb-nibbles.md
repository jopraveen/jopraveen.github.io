---

title: HTB [NIBBLES] [LINUX]

date: 2022-06-02 18:23:05 +0200

categories: [htb]

tags: [HACKTHEBOX MACHINES]

excerpt: Write up for the machine "nibbles" from HackTheBox
---

![](https://i.imgur.com/TnenIMs.png)

## Nibbles

**Enumeration:**

```css
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


**website:**

![](https://i.imgur.com/fZYq1an.png)
- lets see that `/nibbleblog`
- that's just a blog without any posts


**Directory bruteforcing:**
![](https://i.imgur.com/wWxY7QC.png)
- There are so many directories
- At the last of the site there's `Powered by Nibbleblog`
- Now let's search about nibble blog


![](https://i.imgur.com/lvc7QWP.png)

- Cool there are some exploits, let's try those things

![](https://i.imgur.com/wFsf0k2.png)
- Inorder to exploit this we need credentials

![](https://i.imgur.com/Oih9JQG.png)
- There's a user called admin
- Now we need to guess the password, let's try `nibble` `nibbles` like that

**RCE**
![](https://i.imgur.com/OXVSNQn.png)
- After few guesses we got the password `nibbles`
- And successfully got a shell

**priv esc:**

![](https://i.imgur.com/0SyZnMG.png)
- Here we can able to run `/home/nibbler/personal/stuff/monitor.sh` as root
- Unfortunately there's no such file or directory
- But there's a zip called `personal.zip` , let's unzip it
- Now we got our `monitor.sh` file

![](https://i.imgur.com/F9IiAo6.png)
- We can able to modify this file


![](https://i.imgur.com/79q1iq7.png)
- Simply let's set the suid bit to `/bin/bash` binary, so we can able to run `bash` as root 
- That's how we solved this!!

