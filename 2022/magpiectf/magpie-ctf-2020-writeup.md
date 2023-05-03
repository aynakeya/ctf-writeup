---
title: "[web] a replication of go-fs [magpie ctf]"
date: 2022-03-07 10:01:39
tags:
    - writeup
    - ctf
    - web
categories:
    - CTF
---

# 0x0 Introduction

I participate magpie ctf a few weeks ago. Our team go 2nd place, which is pretty good. And we also got $512 (102 for each team members) for reward of getting 2nd

Anyway, there is a question in the magpie ctf called "our file belong to us" [\[linkhere\]](https://github.com/infosec-ucalgary/magpieCTF2022-public/tree/main/challenges/web/our_files_are_belong_only_to_us)

This is a pretty fun challenge I got a solution for.

Sadly, this challenge copy just paste code from another challenge called "go-fs" back in justifyCTF2020 with additional jwt authentication. but the basic idea is the same :(

<!-- more -->

# 0x1 exploit explaination

the basic idea is, this web challenge implement a custom file system. And the read/seek function use offset to locate a file. combine with a bug for range header founded in go 1.15. We can acess a file which is not intended to.

We want to access a file called `a_secret.bak` in order to get the secret for jwt token. However, the access to the file has been block by this code.
```
http.HandleFunc("/a_secret.bak", func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Served-by", VERSION)
	w.Write([]byte(`Error: Access to secret key only for authorized users.`))
})
```

according to original authors report ([https://github.com/golang/go/issues/40940](https://github.com/golang/go/issues/40940)). go 1.15 wrongly parse `range` header. Which allow go to read with a negative length of file.

In the customer file system. the negative read means it will read next file. (the file are consective in the memory)

therefore, to read `a_secret.bak`. the request a file right before the `a_scret.bak` with header `Range: bytes=--1`

`curl -H 'Range: bytes=--1' `

After we got the flag, it is just crafting a jwt token and login into the system to get the flag.


# 0x2 unintended solution

there is also another way to solve this challenge, which is related to the go implementation of the http `CONNECT` method.

in normal get/post, go will do a operation called **canonicalization**, which means if we type like `../flag`, the go will redirect us to `/flag`. 

However, if we do a `CONNECT` request, according to the go source code ([here](https://github.com/golang/go/blob/9bb97ea047890e900dae04202a231685492c4b18/src/net/http/server.go#L2354-L2364)), it will pass the path as is

```
// CONNECT requests are not canonicalized.
	if r.Method == "CONNECT" {
		// If r.URL.Path is /tree and its handler is not registered,
		// the /tree -> /tree/ redirect applies to CONNECT requests
		// but the path canonicalization does not.
		if u, ok := mux.redirectToPathSlash(r.URL.Host, r.URL.Path, r.URL); ok {
			return RedirectHandler(u.String(), StatusMovedPermanently), u.Path
		}

		return mux.handler(r.Host, r.URL.Path)
	}

```

In this case, if we do a `CONNECT` request with `../flag`, we can access `../flag` directly in the file system instead of checking the jwt.

solution: `curl --path-as-is -X CONNECT http://localhost/../flag`