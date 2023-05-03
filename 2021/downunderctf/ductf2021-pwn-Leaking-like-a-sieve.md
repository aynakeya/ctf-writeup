---
title: "[writeup][DownUnderCTF 2021] pwn Leaking like a sieve"
date: 2021-10-09 14:06:08
tags:
    - writeup
    - ctf
    - ductf
    - pwn
    - buffer overflow
categories:
    - CTF
---

## Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

it is a typical printf problem. it ask as a string, and then out. 

we can use string format to get the data.

In x64 system. the first argument is in rdi, and 2-6 argument are stored in register.

<!-- more -->

| Register |                 Purpose                | Saved across calls |
|:--------:|:--------------------------------------:|:------------------:|
| %rax     | temp register; return value            | No                 |
| %rbx     | callee-saved                           | Yes                |
| %rcx     | used to pass 4th argument to functions | No                 |
| %rdx     | used to pass 3rd argument to functions | No                 |
| %rsp     | stack pointer                          | Yes                |
| %rbp     | callee-saved; base pointer             | Yes                |
| %rsi     | used to pass 2nd argument to functions | No                 |
| %rdi     | used to pass 1st argument to functions | No                 |
| %r8      | used to pass 5th argument to functions | No                 |
| %r9      | used to pass 6th argument to functions | No                 |
| %r10-r11 | temporary                              | No                 |
| %r12-r15 | callee-saved registers                 | Yes                |

However, after all the register are used, program get value from **stack** which is **rsp**.

and rsp indicate a local variable `var_60h`

according to the disassembly, `var_60h` is a pointer to s, which store the flag.
```
0x000011ef      lea     rax, [s]
0x000011f3      mov     qword [var_60h], rax
```

so we can let printf print 7th argument (which is rsp) as string.

by using `%p%p%p%p%p %s` or `%6$s`



## Code

```
int main (int argc, char **argv, char **envp);
; var int64_t var_60h @ rbp-0x60
; var FILE *stream @ rbp-0x58
; var char *format @ rbp-0x50
; var char *s @ rbp-0x30
; var int64_t var_8h @ rbp-0x8
0x000011d8      push    rbp
0x000011d9      mov     rbp, rsp
0x000011dc      sub     rsp, 0x60
0x000011e0      mov     rax, qword fs:[0x28]
0x000011e9      mov     qword [var_8h], rax
0x000011ed      xor     eax, eax
0x000011ef      lea     rax, [s]
0x000011f3      mov     qword [var_60h], rax

int main (int argc, char **argv, char **envp);
; var int64_t var_60h @ rbp-0x60
; var FILE *stream @ rbp-0x58
; var char *format @ rbp-0x50
; var char *s @ rbp-0x30
; var int64_t var_8h @ rbp-0x8

void main(void)
{
    int64_t iVar1;
    int64_t in_FS_OFFSET;
    int64_t var_60h;
    FILE *stream;
    char *format;
    char *s;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    buffer_init();
    iVar1 = fopen("./flag.txt", 0x2008);
    if (iVar1 == 0) {
        puts("The flag file isn\'t loading. Please contact an organiser if you are running this on the shell server.");
        exit(0);
    }
    fgets(&s, 0x20, iVar1);
    do {
        puts("What is your name?");
        fgets(&format, 0x20, _stdin);
        printf("\nHello there, ");
        printf(&format);
        putchar(10);
    } while( true );
}
```

## Flag

DUCTF{f0rm4t_5p3c1f13r_m3dsg!}