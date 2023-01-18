---
title: HTB [Active]
date: 2023-01-18 11:28:05 +0200
categories: [windows,AD]
tags: [CTFTIME,ACTIVE DIRECTORY 101]
excerpt: Write up for the machine "Active" from HackTheBox
---


## Recon

```js
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-01-18 05:48:32Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5722/tcp  open  msrpc         syn-ack Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack Microsoft Windows RPC
49166/tcp open  msrpc         syn-ack Microsoft Windows RPC
49168/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -5h30m00s
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-01-18T05:49:27
|_  start_date: 2023-01-18T05:45:01
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 38772/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 10997/udp): CLEAN (Timeout)
|   Check 4 (port 38631/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```


- It's an Active directory machine
- No web servers are running, let's enum the smb

![](https://i.imgur.com/SZQrazV.png)

- Let's download everything from that share

![](https://i.imgur.com/GjJEGDb.png)

- [https://adsecurity.org/?p=2288](This post) from adsecurity explains about exploiting this groups policy files

```js
➜  active gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

- use `gpp-decrypt` to decrypt this password
- creds `active.htb\SVC_TGS:GPPstillStandingStrong2k18`


### More Shares

![](https://i.imgur.com/dFLJ46s.png)

- We can access more shares by using the creds

![](https://i.imgur.com/ruwqL9C.png)

- Grab the user.txt
- Let's use [bloodhound-python](https://github.com/fox-it/BloodHound.py) with these user creds
- `bloodhound-python` is a Python based ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/).

![](https://i.imgur.com/HFkEqSv.png)

- Now start `neo4j` and run `bloodhound` to import these files

![](https://i.imgur.com/KpMFT9n.png)


- Shortest Paths from Kerberoastable Users

![](https://i.imgur.com/VZWRaAD.png)

- Looks like the Administrator is kerberoastable
- So let's try kerberoasting to request a ticket

![](https://i.imgur.com/BWpCVqd.png)

![](https://youtu.be/PUyhlN-E5MU)


- I'm gonna use a script called `GetUserSPNs.py` from impacket

![](https://i.imgur.com/0rYpTu9.png)

- If you get this error, the most likely we need to sync our time to the machine time
- So run `ntpdate 10.10.10.100`

![](https://i.imgur.com/502SMxz.png)

- Let's crack this using john

![](https://i.imgur.com/hUaebJe.png)

- Now we have the Administrator creds `Administrator:Ticketmaster1968`

![](https://i.imgur.com/mTx2zYT.png)

- Now we have write permissions to the shares, so let's use `psexec.py` to get a shell

![](https://i.imgur.com/VA78cy7.png)

- rooted!!
