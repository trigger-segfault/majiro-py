#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script opcode flags and enums (mostly for variables)
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Based off Meta Language implementation by Haeleth - 2005
Converted to Python script with extended syntax by Robert Jordan - 2021
'''

__all__ = []

#######################################################################################

import enum
from collections import OrderedDict
from itertools import chain
from typing import Dict, Iterator, List, Optional, Union

from abc import abstractproperty

from ...flags import MjoType, MjoScope
from ...instruction import Instruction
from ...mjoscript import FunctionIndexEntry, MjoScript

from ....identifier import HashValue, HashName
from ....name import basename

# #region ## IMMUTABLE ##

# def __setattr__(self, name, value):
#     if hasattr(self, name):
#         raise AttributeError(f'{name!r} attribute is readonly')
#     super().__setattr__(name, value)

# #endregion

class _Block:
    """Base class for bytecode block analysis
    """
    def __init__(self):
        self.first_instruction_index:int = -1
        self.last_instruction_index:int = -1



    @abstractproperty
    def script(self) -> MjoScript:
        raise NotImplementedError('_Block.script')
    @property
    def instruction_count(self) -> int:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return -1
        return self.last_instruction_index - self.first_instruction_index + 1
    @property
    def instructions(self) -> List[Instruction]:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return []
        return self.script.instructions[self.first_instruction_index:self.last_instruction_index + 1]  # pylint: disable=no-member
        # for i in range(self.first_instruction_index, self.last_instruction_index + 1):
        #     yield self.script.instructions[i]
    @property
    def first_instruction(self) -> Instruction:
        self.script.instructions[self.first_instruction_index]
    @property
    def last_instruction(self) -> Instruction:
        self.script.instructions[self.last_instruction_index]
    @property
    def start_offset(self) -> int:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return -1
        return self.script.instructions[self.first_instruction_index].offset  # pylint: disable=no-member
        # for instruction in self.instructions:
        #     return instruction.offset
        # return -1

class BasicBlock(_Block):
    """Simple block of instructions
    """
    def __init__(self, function:'Function', name:str):
        super().__init__()
        self.function:'Function' = function
        self.name:str = name
        self.is_entry_block:bool = False
        self.is_exit_block:bool = False
        self.is_dtor_block:bool = False  # destructor {} syntax with op.847 (bsel.5)
        self.predecessors:List['BasicBlock'] = []
        self.successors:List['BasicBlock'] = []
    @property
    def script(self) -> MjoScript:
        return self.function._script
    @property
    def name(self) -> str:
        if self.is_entry_block:
            return 'entry'
        elif self.is_dtor_block:
            return 'destructor_{:05x}'.format(self.start_offset)
        elif self.is_exit_block:
            return 'exit_{:05x}'.format(self.start_offset)
        else:
            return 'block_{:05x}'.format(self.start_offset)
    @property
    def is_unreachable(self) -> bool:
        return not self.is_entry_block and not self.predecessors
    def is_destructor_entry_block(self):
        return len(self.predecessors) == 1 and self.predecessors[0].last_instruction.opcode.value == 0x847  #"bsel.5"

class _BlockContainer(_Block):
    """Block, and container for nested instruction blocks
    """
    def __init__(self):
        super().__init__()
        self.basic_blocks:List[BasicBlock] = []

    def basic_block_from_offset(self, offset:int) -> BasicBlock:
        for block in self.basic_blocks:
            if self.script.instructions[block.first_instruction_index].offset == offset:  # pylint: disable=no-member
                return block
        return None

class Function(_BlockContainer):
    """Function block, containing nested instruction blocks
    """
    def __init__(self, script:MjoScript, func_info:FunctionIndexEntry):
        super().__init__()
        self._script:MjoScript = script
        self.func_info:FunctionIndexEntry = func_info
        # self.name_hash:int = name_hash
        self.entry_block:BasicBlock = None
        self.exit_blocks:List[BasicBlock] = None
        self.parameter_types:List[MjoType] = None
    @property
    def hashname(self) -> HashName:
        return self.func_info.hashname
    @property
    def hash(self) -> int:
        return self.func_info.hashname.hash
    @property
    def name(self) -> str:
        return self.func_info.hashname.name
    @property
    def script(self) -> MjoScript:
        return self._script
    @property
    def is_entrypoint(self) -> bool:
        return self.start_offset == self.script.main_offset
