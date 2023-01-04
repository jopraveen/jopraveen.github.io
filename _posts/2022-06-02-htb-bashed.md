---

title: HTB [BASHED] [LINUX]

date: 2022-06-02 15:23:05 +0200

categories: [htb]

tags: [HACKTHEBOX MACHINES]

excerpt: Write up for the machine "Bashed" from HackTheBox
---

## bashed 

![](https://i.imgur.com/fIMughL.png)

### Enumeration
**Nmap:**

```css
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

**Directory bruteforcing:**

![](https://i.imgur.com/i6hVUm2.png)
- /dev seems interesting to me


![](https://i.imgur.com/8zALkwd.png)
- Let's open the first one


![](https://i.imgur.com/jR9waYG.png)
- Here we can able to run commands, but we can't able to get a reverse shell
- So let's try to upload a php reverse shell to /uploads folder, so we can get a shell by triggering it

**reverse shell:**

![](https://i.imgur.com/m6LVy8r.png)

- Here we can able to run any command as **scriptmanager**


**priv esc:**

![](https://i.imgur.com/ZfBNaG7.png)

- Now time for linpeas


![](https://i.imgur.com/smyz31j.png)
- Let's see  `/scripts/test.txt`  file


![](https://i.imgur.com/TYEl6TK.png)
- This file is owned by root
- Also there's a test.py script


![](https://i.imgur.com/T62rnnA.png)
- It just opens this file and writes `testing 123!`
- We have the permission to modify this script
- Ig this script runs as root every minute
- Let's try to read root.txt and store its contents in a new file 


```python
r = open("/root/root.txt", "r").read()
f = open("flag.txt","w")
f.write(r)
f.close
```

- Now let's wait for 1 minute

![](https://i.imgur.com/BBwMWjr.png)

- Cool we solved it!!
-----
