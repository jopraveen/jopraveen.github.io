---
title: HTB [LaCasaDePapel]
date: 2023-02-20 02:28:05 +0200
categories: [vsftpd,ssl,memcache]
tags: [HACKTHEBOX MACHINES]
excerpt: LaCasaDePapel is an easy hackthebox machine that involves chaning vstfpd backdoor to read a private key file and generate a new ssl cert to exploit a LFI, for root we can create memcached.ini file to execute commands as root
---


![](https://i.imgur.com/OCN0wFo.png)

## RECON

### Port Scan

```js
PORT    STATE SERVICE  REASON  VERSION
21/tcp  open  ftp      syn-ack vsftpd 2.3.4
22/tcp  open  ssh      syn-ack OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 03e1c2c9791ca66b51348d7ac3c7c850 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNzmarvyIINA+hjsLo2xYn1PUyzuTflhtXQs8S1Z56FzbdzXs6FiwhoRGn63XuGCHqCfEzHmh1cg4HGLfGAMwe+AsdJ8hLd/ISNRECH8yvM+9k78Aio3pe+lYbiWSQWyJrQdeqJXyDJFSd6BR3Cr6/rwSvE7N3eWeQvxS+fsg5HOER6n8SOnXvqpWYUo+XmZxGzmluNfsqoJ6doJCyW3X4sTImTlpmRmee6iseo9neZO18aHsARxlkHCqUhp1SBzIiik3DurtH1tgrn8ntfNiK3q0FZJmh9qzu0P/L50j8bzlJdvAsLuqbYmVZhqFs0JfBVdyVTFMn4O0J+IqRrXAF
|   256 41e495a3390b25f9dadebe6adc59486d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNli8Xx10a0s+zrkT1eVfM1kRaAQaK+a/mxYxhPxpK0094QFQBcVrvrXb3+j4M8l2G/C9CtQRWVXpX8ajWhYRik=
|   256 300bc6662b8f5e4f2628750ef5b171e4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2uNaKo2PK5cMci4E7dNWQ6ipiEzG3cWUR56qqMZqYR
80/tcp  open  http     syn-ack Node.js (Express middleware)
|_http-favicon: Unknown favicon MD5: 621D76BDE56526A10B529BF2BC0776CA
|_http-title: La Casa De Papel
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack Node.js Express framework
| tls-nextprotoneg:
|   http/1.1
|_  http/1.0
|_ssl-date: TLS randomness does not represent time
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 621D76BDE56526A10B529BF2BC0776CA
| tls-alpn:
|_  http/1.1
|_http-title: La Casa De Papel
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Issuer: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-27T08:35:30
| Not valid after:  2029-01-24T08:35:30
| MD5:   6ea4933aa347ce508c405f9b1ea88e9a
| SHA-1: 8c477f3e53d8e76b4cdfeccaadb60551b1b638d4
| -----BEGIN CERTIFICATE-----
| MIIC6jCCAdICCQDISiE8M6B29jANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQDDBFs
| YWNhc2FkZXBhcGVsLmh0YjEZMBcGA1UECgwQTGEgQ2FzYSBEZSBQYXBlbDAeFw0x
| OTAxMjcwODM1MzBaFw0yOTAxMjQwODM1MzBaMDcxGjAYBgNVBAMMEWxhY2FzYWRl
| cGFwZWwuaHRiMRkwFwYDVQQKDBBMYSBDYXNhIERlIFBhcGVsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3M6VN7OD5sHW+zCbIv/5vJpuaxJF3A5q2rV
| QJNqU1sFsbnaPxRbFgAtc8hVeMNii2nCFO8PGGs9P9pvoy8e8DR9ksBQYyXqOZZ8
| /rsdxwfjYVgv+a3UbJNO4e9Sd3b8GL+4XIzzSi3EZbl7dlsOhl4+KB4cM4hNhE5B
| 4K8UKe4wfKS/ekgyCRTRENVqqd3izZzz232yyzFvDGEOFJVzmhlHVypqsfS9rKUV
| ESPHczaEQld3kupVrt/mBqwuKe99sluQzORqO1xMqbNgb55ZD66vQBSkN2PwBeiR
| PBRNXfnWla3Gkabukpu9xR9o+l7ut13PXdQ/fPflLDwnu5wMZwIDAQABMA0GCSqG
| SIb3DQEBCwUAA4IBAQCuo8yzORz4pby9tF1CK/4cZKDYcGT/wpa1v6lmD5CPuS+C
| hXXBjK0gPRAPhpF95DO7ilyJbfIc2xIRh1cgX6L0ui/SyxaKHgmEE8ewQea/eKu6
| vmgh3JkChYqvVwk7HRWaSaFzOiWMKUU8mB/7L95+mNU7DVVUYB9vaPSqxqfX6ywx
| BoJEm7yf7QlJTH3FSzfew1pgMyPxx0cAb5ctjQTLbUj1rcE9PgcSki/j9WyJltkI
| EqSngyuJEu3qYGoM0O5gtX13jszgJP+dA3vZ1wqFjKlWs2l89pb/hwRR2raqDwli
| MgnURkjwvR1kalXCvx9cST6nCkxF2TxlmRpyNXy4
|_-----END CERTIFICATE-----
Service Info: OS: Unix
```

- Four ports opened, anonymous login was disabled in `FTP`


### Web Enumeration

![](https://i.imgur.com/uFWOjoz.jpg)

- It's a nodejs application

![](https://i.imgur.com/GXLgE7g.png)

- Scanning the QR code gives us this link

![](https://i.imgur.com/jMFIVL6.png)

- I used that form to `Get Free Trial`, this time our link changes (see below)

![](https://i.imgur.com/xOgsyiV.png)

- We have an endpoint called `/qrcode` and they're passing `?qurl` to it to render the QR code image
- That's dynamically generated using our `email` & `token`

![](https://i.imgur.com/xIePhgE.png)

- I Visited `/qrcode` page manualy, it reveals the user's home directory with a bunch of error messages
- That makes sense, coz you can see the above request to `/qrcode` (See that burp suite pic above) sends a parameter `qurl` to render the image
- They're using [otpauth](https://www.npmjs.com/package/otpauth) here
- You can visit the above like to see the package info, and here's the [documentation](https://hectorm.github.io/otpauth/)
- But nothing interesting with this

#### HTTPS

![](https://i.imgur.com/jUVOaaJ.jpg)

- We have some certificate error, and we need to provide certificate to access this page ig
- Looking at the nmap result again tells us that we missed `vsftpd 2.3.4`, which is vulnerable to `Backdoor Command Execution`
- We're going to exploit this manually

## INITIAL FOOTHOLD

- First we need to use ftp to login as usual 
- The creds is our choice no matter what we're going to input

![](https://i.imgur.com/iFBGueO.png)

- Just add a `:)` smiley at the end of your username
- This will trigger the backdoor, and we can connect to it on port `6200` on the machine

![](https://i.imgur.com/z7ZhDZM.png)

- We can execute normal commands, but `system` is blocked there!!

![](https://i.imgur.com/ccaF65D.png)

- But we can use alternate functions to achieve our goal

![](https://i.imgur.com/q2Hvy3e.png)

- There are 5 users in this box

![](https://i.imgur.com/oJIzVgj.png)

- We don't have permissions to view the contents of `user.txt`

![](https://i.imgur.com/Gdszysk.png)

- There's a public key in dali's `.ssh` folder

![](https://i.imgur.com/W2cxPQ8.png)

- This is the file that contains ssl certificates
- Let's copy this to our local
- Before using that key we need to generate a `cert.pem` file

#### Generate Certificate

```bash
openssl s_client -showcerts -connect 10.10.10.131:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ca.crt
```

<br>

- First download the cert from browser

![](https://i.imgur.com/b1Z6G5q.png)

- Create a new private key for the server using openssl

![](https://i.imgur.com/LAEK3GW.png)

- Generate a CSR using the private key

![](https://i.imgur.com/keB4rl5.png)

- Now we can obtain the certificate

![](https://i.imgur.com/yHRDrqd.png)

- No more cert errors, that path looks interesting, hope we can do LFI using that!

![](https://i.imgur.com/woGBJnw.png)

- I've used `?path` parameter with `SEASON-1` value, it returned me a bunch of avi file links
- The `file/<some encoded string>` that looks like base64

![](https://i.imgur.com/qBQSjgN.png)

- Yes it is!!

#### LFI

![](https://i.imgur.com/s0G5jU7.png)

- Cool it works, now let's try to get the `id_rsa` key's of the users

![](https://i.imgur.com/J0FazmZ.png)

- We got the `id_rsa` key but it haven't worked for him

![](https://i.imgur.com/IdCjxZ4.png)

- Instead it worked for professor!
 
## PRIVESC

![](https://i.imgur.com/tsXCJRQ.png)

- This process gets executed often, coz this `memcached` program is `supervisord` process it will continue to run until it is stopped or restarted

![](https://i.imgur.com/4li3fQO.png)

- If we change this we can create our memcached.ini file
- And that will get executed by root

```ini
[program:memcached]
command = chmod u+s /bin/bash
```

![](https://i.imgur.com/QNE83Cs.png)

- After few minutes we can root it by `bash -p` ezpz
