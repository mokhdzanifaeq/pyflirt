# pyflirt
**pyflirt** is a map file genarator for binary file based on flirt signature. Since it is used with ollydbg, only intel x86 binary is currently supported. This tool was succesfully tested with ollydbg 1.10 MapConv plugin to import the map file.

Installation
============

**Dependencies**

Require [python capstone binding](https://github.com/aquynh/capstone/tree/master/bindings/python) for disassembly

**Install**

    git clone https://github.com/mokhdzanifaeq/pyflirt
    
Usage
=====
```
usage: pyflirt.py [-h] -b path -s path -o path

optional arguments:
  -h, --help           show this help message and exit
  -b path, --bin path  path of binary file to be analysed
  -s path, --sig path  path of signature file to be analysed
  -o path, --out path  path of map file to be generated
```

Screenshots
===========
**Before:**

![before](/screenshot/before.png?raw=true)

**After:**

![after](/screenshot/after.png?raw=true)

License
=======
Feel free to update the code as you like, fix bugs and implement new features.

Credits
=======
* rheax - understanding flirt file format
* [aquynh](https://github.com/aquynh) - capstone framework
