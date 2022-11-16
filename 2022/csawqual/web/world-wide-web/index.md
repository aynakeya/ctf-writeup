---
title: "[Web] World Wide Web [CSAW CTF Qual 2022]"
date: 2022-09-11 16:23:00
---

# 0x0 Introduction

Isn't the Word Wide Web a fascinating place to be in? Words.. so many words.. all linked... NOTE: The flag doesn't have a wrapper. It needs to be wrapped with curly brackets and please put CTF in front of the curly brackets.

http://web.chal.csaw.io:5010


# 0x1 Walk Through

looking at the web request

we have a cookie `solChain=stuff%20center%20function` which contains all the url we have visited

write a script, start with `/stuff`, find next link in web page, visist that link with current cookie.

util we get a flag


# Solution

```
import requests
import re

find_reg = re.compile(r'<a href=\"([^\"]*)\">')
print(find_reg.findall('<a href="/audience">audience</a>'))
base_addr = "http://web.chal.csaw.io:5010"

next_path = "/stuff"

s = requests.Session()

while True:
    resp = s.get(base_addr+next_path)
    ps = find_reg.findall(resp.text)
    print(ps,s.headers)
    if len(ps) < 1:
        print(resp.text)
        break
    next_path = ps[0]
```

# Flag

`CTF{w0rdS_4R3_4mAz1nG_r1ght}`