#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script file reading and writing tools.

modules:
  mj.script.disassembler - export scripts to MjIL intermediate language.
  mj.script.flags        - script enum types and bitmasks.
  mj.script.instruction  - script bytecode instruction class.
  mj.script.mjoscript    - class for reading and writing binary `.mjo` script files.
  mj.script.opcodes      - collection of all instruction opcodes.

submodules:
  mj.script.analysis     - analysis of single-script control flow and functions.

"""

__version__ = '1.0.0'
__date__    = '2021-06-03'
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


