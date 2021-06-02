#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro VN engine Python library package

modules:
  mj.crypt - cryptographic and hashing functions.
  mj.name  - identifier name text parsing. (similar in function to `os.path`)
  mj.identifier  - identifier name and hash handling.

submodules:
  mj.database    - database of useful Majiro engine information (mainly known hash value names).
  mj.script      - tools and classes for reading and writing `.mjo` script files.

"""

__version__ = '1.0.0'
__date__    = '2021-05-04'
__author__  = 'Robert Jordan'

__all__ = ['MjoType', 'MjoScope', 'MjoModifier', 'MjoInvert', 'MjoDimension', 'MjoFlags', 'Opcode', 'Instruction', 'FunctionIndexEntry', 'MjoScript']

#######################################################################################


from .flags import MjoType, MjoScope, MjoModifier, MjoInvert, MjoDimension, MjoFlags
from .opcodes import Opcode
from .instruction import Instruction
from .mjoscript import FunctionIndexEntry, MjoScript


"""

from mj.script.mjoscript import MjoScript
with open('../data/mjs/console.mjo', 'rb') as f:
  script = MjoScript.disassemble_script(f, lookup=True)

l = [i for i in script.instructions if i.hashname is not None and i.hashname.name is not None]
len(l)
l[0].hashname
li = [i for i in l if i.opcode.mnemonic == 'ldc.i']
len(li)
li[0].hashname

"""


