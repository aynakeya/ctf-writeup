---
title: "MagpieCTF 2023 Writeup"
date: 2022-05-06 23:48:00
---

# 0x0 Before all

I don't like this ctf. And most of challenge is not worth to craft a writeup.

all files can be found in <https://github.com/infosec-ucalgary/magpieCTF-2023>

# 0x1 [PWN] no-password-here

[files](https://github.com/infosec-ucalgary/magpieCTF-2023/tree/main/challenges/binary-exploitation/no-password-here)

`scanf("%s")` buffer overflow

```
char Test[20];
... 
char input[20];
...
//Check password
if (strncmp(Test,input,20) == 0)
{
```

payload: `'A'*40`

flag: `magpie{5c4nf_n07_54f3}`


# 0x2 [PWN] no-password-here

[files](https://github.com/infosec-ucalgary/magpieCTF-2023/tree/main/challenges/binary-exploitation/this-outta-be-large-enough-right)

ret2win. fill stack with 56 + 4 padding. then overwrite eip

```
void win(){
    printf("Here is your flag:\n");
    exit(0);
}
void vuln(){
  char buf[56];
  gets(buf);
}
```

flag: `magpie{0mn1_fl4g_3v3rywh3r3}`

# 0x3 [Web] education-comes-first

[files](https://github.com/infosec-ucalgary/magpieCTF-2023/tree/main/challenges/web-exploitation/education-comes-first)


call `hex2a` in web console

```
hex2a('6d61677069657b57335f525f5337314c4c5f483352337d')
```

flag: `magpie{W3_R_S71LL_H3R3}`

# 0x4 [Forensic] there-is-no-flag

[files](https://github.com/infosec-ucalgary/magpieCTF-2023/tree/main/challenges/forensics/there-is-no-flag)

1. binwalk to extract Flag.PNG
2. recover modify png header
3. read flag

flag: `magpie{m15510n_c0mpl373_w17h_r35p3c7}`

# 0x5 [Network] eavesdropper

[files](https://github.com/infosec-ucalgary/magpieCTF-2023/tree/main/challenges/networks/eavesdropper)

1. open .pcapng file
2. find http request with largest request body, flag is in the http body

flag: `magpie{chOc0LatE_Ch1p_c0Ok1e5}`

# 0x5 [Network] knock-knock-anyone-there

1. bypass waf using `printf cmd_in_base_64 | base64 -d | sh`
2. setting up reverse shell
3. find password of user sappheiros using `cat /opt/backup/*` (`5up32_53cu23_p455w02d123`)
4. `su sappheiros`
5. first half flag is in `cat /home/sappheiros/message.txt`
5. `tcpdump -nnA host 172.16.238.30`
6. second half flag is hidden inside ids of icmp packets.

```
from scapy.all import *

pcap = rdpcap('dump.pcap')

data = [p[ICMP] for p in pcap if ICMP in p]

print(b''.join([bytes([d.id]) for d in data]).split(b'}'))
```

flag: `magpie{y0u_h4v3_7h3_p0w32_70_54v3_7h3_w021d}`