#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script tools library
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

#######################################################################################

from .opcodes import Opcode
from .script import Instruction, MjoScript
from .analysis import ControlFlowGraph

from . import crypt
from . import opcodes
from . import script
from . import analysis

