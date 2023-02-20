---
title: HTB [Bastion]
date: 2023-02-20 01:28:05 +0200
categories: [Windows,vhd,mRemoteNG]
tags: [HACKTHEBOX MACHINES]
excerpt: Bastion is an easy hackthebox machine that involves a READ/WRITE share over smb to get a vhd backup file, then we can use secretdump.py to get user hash & password, For root we will decrypt mRemoteNG password and ssh as Administrator
---

![](https://i.imgur.com/TbOu17d.png)

## RECON

### Port Scan

```js
PORT      STATE SERVICE      REASON  VERSION
22/tcp    open  ssh          syn-ack OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a56ae753c780ec8564dcb1c22bf458a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bG3TRRwV6dlU1lPbviOW+3fBC7wab+KSQ0Gyhvf9Z1OxFh9v5e6GP4rt5Ss76ic1oAJPIDvQwGlKdeUEnjtEtQXB/78Ptw6IPPPPwF5dI1W4GvoGR4MV5Q6CPpJ6HLIJdvAcn3isTCZgoJT69xRK0ymPnqUqaB+/ptC4xvHmW9ptHdYjDOFLlwxg17e7Sy0CA67PW/nXu7+OKaIOx0lLn8QPEcyrYVCWAqVcUsgNNAjR4h1G7tYLVg3SGrbSmIcxlhSMexIFIVfR37LFlNIYc6Pa58lj2MSQLusIzRoQxaXO4YSp/dM1tk7CN2cKx1PTd9VVSDH+/Nq0HCXPiYh3
|   256 cc2e56ab1997d5bb03fb82cd63da6801 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Mau7cS9INLBOXVd4TXFX/02+0gYbMoFzIayeYeEOAcFQrAXa1nxhHjhfpHXWEj2u0Z/hfPBzOLBGi/ngFRUg=
|   256 935f5daaca9f53e7f282e664a8a3a018 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB34X2ZgGpYNXYb+KLFENmf0P0iQ22Q0sjws2ATjFsiN
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2023-02-20T02:49:34
|_  start_date: 2023-02-20T02:44:00
|_clock-skew: mean: -19m59s, deviation: 34m35s, median: -1s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-02-20T03:49:36+01:00
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 65148/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 26941/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 11874/udp): CLEAN (Failed to receive data)
|   Check 4 (port 18741/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

- There's no webserver
- Let's enumerate SMB

![](https://i.imgur.com/PKM4P6l.png)

- We have READ/WRITE permissions in `Backups` share

![](https://i.imgur.com/bPK2QK1.png)

- It contains few files, So let's download all of them
- "WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd" This file is `5.1 GB`, so wait few minutes

![](https://i.imgur.com/t6TWMCJ.png)

- The `.vhd` images are interesting, I'm gonna transfer these files to windows to mount them

![](https://i.imgur.com/QU1vGYV.png)

- Successfully mounted them, Now time for enumeration

![](https://i.imgur.com/62rHejB.png)

- We have `SAM` , `SECURITY` and `SYSTEM` here, that's enough
- Now let's use `secretsdump.py` to dump the hashes

![](https://i.imgur.com/0fLsYSt.png)


## INTIAL FOOTHOLD

![](https://i.imgur.com/WTjmhfZ.png)

- Using the password `bureaulampje` for `L4mpje` over ssh gives us a shell


![](https://i.imgur.com/G6kGtnX.png)

- `mRemoteNG` is a remote connections manager tool to manage SSH, Telnet, VNC, etc...

![](https://i.imgur.com/mYYxSGG.png)

- This `confCons.xml` file has the password for `Administrator`
- But it's encrypted

## PRIVESC

![](https://i.imgur.com/VErQxur.png)

- Store that encrypted password in a file

![](https://i.imgur.com/83RiGtW.png)

- Then use `mRemoteNG-Decrypt` to decrypt it
- That's all now we can use that password to ssh as Administrator.

