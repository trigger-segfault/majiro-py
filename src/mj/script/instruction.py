#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script IL formatting
"""

__version__ = '0.1.0'
__date__    = '2021-05-06'
__author__  = 'Robert Jordan'

__all__ = []

#######################################################################################

import io, struct
from collections import OrderedDict
from struct import calcsize, pack, unpack
from typing import Any, Callable, List, NoReturn, Optional, Dict, Tuple, Union

from .opcodes import Opcode
from .flags import MjoFlags, MjoType
from ..util.typecast import to_str, to_float, signed_i, signed_h, unsigned_I, unsigned_B, unsigned_H
from ..identifier import HashValue, HashName, IdentifierKind

class BasicBlock:
    pass # Dummy


class OperandsList(OrderedDict):
    _OPS:Dict[str,Tuple[Any,Callable]] = {
        's': ("", to_str), #, lambda v: v), #, str),
        'c': ((), lambda vl: tuple(signed_i(v) for v in vl)), #signed_i(v) for v in vl)),
        't': ((), lambda vl: tuple(MjoType(unsigned_B(v)) for v in vl)), #MjoType(unsigned_B(v)) for v in vl)),
        'f': (MjoFlags(0), lambda v: MjoFlags(unsigned_H(v))), #MjoFlags(unsigned_H(v))),
        'a': (0, unsigned_H), #, unsigned_H),
        'l': (0, unsigned_H), #, unsigned_H),
        'o': (0, signed_h), #, signed_h),
        'h': (0, HashValue), #unsigned_I), #, unsigned_I),
        '0': (0, unsigned_I), #, unsigned_I),
        'i': (0, signed_i), #, signed_i),
        'j': (0, signed_i), #, signed_i),
        'r': (0.0, to_float), #, float),
    }
    def __init__(self, encoding:str, operands:Optional[tuple]=...): #, *args, **kwargs):
        if isinstance(encoding, OrderedDict):
            if operands is not Ellipsis:
                raise TypeError(f'cannot pass dictionary and operands to {self.__class__.__name__}')
            # self.encoding = encoding.encoding if isinstance(encoding, OperandsList) else ''.join(encoding.keys())
            if isinstance(encoding, OperandsList):
                self.encoding = encoding.encoding
                super().__init__(encoding)
            else:
                self.encoding = ''.join(encoding.keys())
                super().__init__((k,self._OPS[k][1](v)) for k,v in zip(encoding, operands))
        else:
            self.encoding:str = encoding
            if operands is not Ellipsis and operands is not None:
                if len(operands) != len(encoding):
                    raise ValueError(f'operands length ({len(operands)}) does not match encoding length ({len(encoding)}')
                super().__init__((k,self._OPS[k][1](v)) for k,v in zip(encoding, operands))
            else:
                super().__init__((k,self._OPS[k][0]) for k in encoding)
    def __getitem__(self, key):
        if isinstance(key, int):  # index lookup
            key = self.encoding[key]
        return super().__getitem__(key)
    def __setitem__(self, key, value):
        if isinstance(key, int):  # index lookup
            key = self.encoding[key]
        elif key not in self.encoding:
            raise KeyError(f'{key!r} not in {self.__class__.__name__}')  # raise KeyError(key)
        super().__setitem__(key, self._OPS[key][1](value))  # super().__setitem__(key, value)
    def __delitem__(self, key):
        raise KeyError(f'can\'t delete keys from {self.__class__.__name__}')
    def reset(self):
        for k in self.encoding:  # reset values to defaults
            super().__setitem__(k, self._OPS[k][0])
    def clear(self):
        raise KeyError(f'can\'t clear keys from {self.__class__.__name__}')
    def move_to_end(self, key:str, last:bool=True):
        raise KeyError(f'can\'t move keys in {self.__class__.__name__}')


class Instruction:
    """MjoScript Instruction class
    """
    __slots__ = ('opcode', 'operands', '_external_key', 'offset', '_size', 'block', 'jump_target', 'switch_targets', 'hashname')
    def __init__(self, opcode:Opcode, operands:Optional[tuple]=None, *, offset:Optional[int]=None, block:Optional[BasicBlock]=None):
        # shared info:
        if isinstance(opcode, Opcode):
            self.opcode = opcode
        elif isinstance(opcode, int):
            self.opcode = Opcode.BYVALUE[opcode]
        elif isinstance(opcode, str):
            self.opcode = Opcode.fromname(opcode)
        else:
            raise TypeError(f'argument opcode must be Opcode, int or str type, not {opcode.__class__.__name__}')
        self.operands:Dict[str,Any] = OperandsList(self.opcode.encoding, operands)
        self._external_key:Optional[str] = None
        self.hashname:Optional[HashName] = None
        if 'h' in self.opcode.encoding:
            self.hashname = HashName(self.operands['h'])
        elif 'i' in self.opcode.encoding:
            self.hashname = HashName(self.operands['i'])

        # InstructionList representation:
        self.offset:Optional[int] = offset #None  # bytecode offset
        self._size:Optional[int] = None  # instruction size in bytecode
        # self.jump_offset:Optional[int] = None
        # self.switch_offsets:List[int] = None

        # ControlFlowGraph representation:
        self.block:Optional[BasicBlock] = block #None
        self.jump_target:Optional[BasicBlock] = None
        self.switch_targets:Optional[List[BasicBlock]] = None

        # if isinstance(location, int):
        #     self.offset = location
        # elif isinstance(location, BasicBlock):
        #     self.block = location
        # elif location is not None:
        #     raise TypeError(f'argument location must be int, BasicBlock or None type, not {location.__class__.__name__}')
        # self.calcsize()

    def __setattr__(self, name, value):
        if name in ('opcode', 'operands') and hasattr(self, name):
            raise AttributeError(f'{name!r} attribute is readonly')
        super().__setattr__(name, value)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.opcode.mnemonic!r}, {self.location!r}, {tuple(self.operands.values())!r})'

    @property
    def location(self) -> Optional[Union[int, BasicBlock]]:
        if self.offset is not None:
            return self.offset
        elif self.block is not None:
            return self.block
        return None

    @property
    def size(self) -> int:
        return self.calcsize() if self._size is None else self._size  # lazy size calculation as needed

    # def __getitem__(self, key):
    #     if isinstance(key, int):  # index lookup
    #         key = self.opcode.encoding[key]
    #     return self.operands[key]
    # def __setitem__(self, key, item):
    #     if isinstance(key, int):  # index lookup
    #         key = self.opcode.encoding[key]
    #     elif key not in self.opcode.encoding:
    #         raise KeyError(f'{key!r} not in {self.__class__.__name__}')
    #         # raise KeyError(key)
    #     self.operands[key] = item

    @property
    def external_key(self) -> Optional[str]:
        """external resource key for string lookup."""
        return self._external_key
    @external_key.setter
    def external_key(self, key:str): self._external_key = key

    #region ## OPERAND PROPERTIES ##

    # arguments/locals type list operand for argcheck, alloca opcodes. <uint16 (N), uint8[]>
    @property
    def type_list(self) -> List[MjoType]:
        """arguments/locals type list operand for argcheck, alloca opcodes. <uint16 (N), uint8[]>  ['t']"""
        return self.operands['t']
    @type_list.setter
    def type_list(self, value:List[MjoType]):
        self.operands['t'] = tuple(map(MjoType, value))
        self._size = None  # force size re-evaluation
    # string operand for ldstr, text, ctrl opcodes. <uint16 (N), cstring>
    @property
    def string(self) -> str:
        """string operand for ldstr, text, ctrl opcodes. <uint16 (N), cstring>  ['s']"""
        return self.operands['s']
    @string.setter
    def string(self, value:str):
        self.operands['s'] = value
        self._size = None  # force size re-evaluation
    # variable flags operand for ld*, st* opcodes. <uint16 (bitmask)>
    @property
    def flags(self) -> MjoFlags:
        """variable flags operand for ld*, st* opcodes. <uint16 (bitmask)>  ['f']"""
        return self.operands['f']
    @flags.setter
    def flags(self, value:MjoFlags): self.operands['f'] = MjoFlags(unsigned_H(value))
    # CRC-32 name hash operand for ld*, st*, call*, syscall* opcodes. <uint32>
    @property
    def hash(self) -> int:
        """CRC-32 name hash operand for ld*, st*, call*, syscall* opcodes. <uint32>  ['h']"""
        return self.operands['h']
    @hash.setter
    def hash(self, value:int):
        if value != self.operands['h']:
            self.operands['h'] = unsigned_I(value)
            self.hashname = HashName(self.operands['h'])
    # local variable stack offset operand for ld*, st* opcodes. <int16 (-1 for non-locals)>
    @property
    def var_offset(self) -> int:
        """local variable stack offset operand for ld*, st* opcodes. <int16 (-1 for non-locals)>  ['o']"""
        return self.operands['o']
    @var_offset.setter
    def var_offset(self, value:int): self.operands['o'] = signed_h(value)
    # VM address placeholder operand for call* opcodes. <uint32 (must always be 0)>
    @property
    def _call_addr(self) -> int:
        """VM address placeholder operand for call* opcodes. <uint32 (must always be 0)>  ['0']"""
        return self.operands['0']
    @_call_addr.setter
    def _call_addr(self, value:int): self.operands['0'] = unsigned_I(value)
    # integer operand for ldc.i opcode. <int32>
    @property
    def integer(self) -> int:
        """integer operand for ldc.i opcode. <int32>  ['i']"""
        return self.operands['i']
    @integer.setter
    def integer(self, value:int):
        if value != self.operands['i']:
            self.operands['i'] = signed_i(value)
            self.hashname = HashName(self.operands['i'])
    # floating point operand for ldc.r opcode. <float32>
    @property
    def real(self) -> float:
        """floating point operand for ldc.r opcode. <float32>  ['r']"""
        return self.operands['r']
    @real.setter
    def real(self, value:float): self.operands['r'] = float(value)
    # argument count operand for call*, syscall* opcodes. <uint16>
    @property
    def arg_num(self) -> int:
        """argument count operand for call*, syscall* opcodes. <uint16>  ['a']"""
        return self.operands['a']
    @arg_num.setter
    def arg_num(self, value:int): self.operands['a'] = unsigned_H(value)
    # line number operand for line opcode. <uint16 (1-indexed)>
    @property
    def line_num(self) -> int:
        """line number operand for line opcode. <uint16 (1-indexed)>  ['l']"""
        return self.operands['l']
    @line_num.setter
    def line_num(self, value:int): self.operands['l'] = unsigned_H(value)
    # jump offset operand for b* (branch) opcodes. <int32 (target)>
    @property
    def jump_offset(self) -> int:
        """jump offset operand for b* (branch) opcodes. <int32 (target)>  ['j']"""
        return self.operands['j']
    @jump_offset.setter
    def jump_offset(self, value:int): self.operands['j'] = signed_i(value)
    # switch case offsets operand for switch opcode. <uint16 (N), int32[] (targets)>
    @property
    def switch_offsets(self) -> List[int]:
        """switch case offsets operand for switch opcode. <uint16 (N), int32[] (targets)>  ['c']"""
        return self.operands['c']
    @switch_offsets.setter
    def switch_offsets(self, value:List[int]):
        self.operands['c'] = tuple(map(signed_i, value))
        self._size = None  # force size re-evaluation

    #endregion

    @property
    def is_jump(self) -> bool: return 'j' in self.opcode.encoding  #"b*" (?)
    @property
    def is_unconditional_jump(self) -> bool: return self.opcode.value == 0x82c  #"br"
    @property
    def is_switch(self) -> bool: return self.opcode.value == 0x850  #"switch"
    # def is_switch(self) -> bool: return 'c' in self.opcode.encoding  #"switch"
    @property
    def is_return(self) -> bool: return self.opcode.value == 0x82b  #"ret"
    @property
    def is_argcheck(self) -> bool: return self.opcode.value == 0x836  #"argcheck"
    @property
    def is_alloca(self) -> bool: return self.opcode.value == 0x829  #"alloca"
    @property
    def is_text(self) -> bool: return self.opcode.value == 0x840  #"text"
    @property
    def is_syscall(self) -> bool: return self.opcode.value in (0x834, 0x835)  #("syscall", "syscallp")
    @property
    def is_call(self) -> bool:    return self.opcode.value in (0x80f, 0x810)  #("call", "callp")
    @property
    def is_literal(self) -> bool: return self.opcode.value in (0x800, 0x801, 0x803)  #("ldc.i", "ldc.r", "ldstr")
    @property
    def is_load(self) -> bool: return self.opcode.value in (0x802, 0x837)  #("ld", "ldelem")
    @property
    def is_load_literal(self) -> bool: return self.opcode.value in (0x800, 0x801, 0x802, 0x803, 0x837)  #"ld*"
    @property
    def is_store(self) -> bool: return (0x1b0 <= self.opcode.value <= 0x320)  #"st*"

    #region ## MJO BINARY DATA ##

    # @classmethod
    # def create(cls, opcode:Opcode, location:Union[int, BasicBlock], operands:Optional[tuple]) -> 'Instruction':
    #     instr:Instruction = Instruction(opcode)

    @classmethod
    def read(cls, reader:io.BufferedReader, offset:Optional[int]=None, *, lookup:bool=False) -> 'Instruction':
        if offset is None:
            offset = reader.tell()
        # <uint16 (opcode)>
        value:int = unpack(f'<H', reader.read(2))[0]
        opcode:Opcode = Opcode.BYVALUE[value]
        instr:Instruction = Instruction(opcode, offset=offset)
        instr.read_operands(reader, lookup=lookup)
        return instr
    
    def write(self, writer:io.BufferedWriter) -> int:
        writer.write(pack('<H', self.opcode.value))
        return self.write_operands(writer)


    ###############################

    def calcsize(self) -> int:
        """update and return the new instruction size in bytes."""
        size = 2  # <uint16 (opcode)>
        for op,v in self.operands.items():
            if op == 's':       # <uint16 (N), cstring>
                cstr:bytes = v.encode('cp932')
                size += 2 + len(cstr) + 1  # cstring + null-terminator
            elif op == 't':     # <uint16 (N), uint8[]>
                size += 2 + len(v)
            elif op == 'c':     # <uint16 (N), int32[]>
                size += 2 + len(v) * 4
            elif op in 'falo':  # <uint16 | int16>
                size += 2
            elif op in 'h0ijr': # <uint32 | int32 | float32>
                size += 4
            else:
                raise Exception(f'Unknown operand encoding {op!r}')
        self._size = size
        return size

    def read_operands(self, reader:io.BufferedIOBase, *, lookup:bool=False) -> int:
        size = 2  # <uint16 (opcode)>
        for op in self.operands:
            if op == 's':     # <uint16 (N), cstring>
                cnt:int = unpack('<H', reader.read(2))[0]
                v = unpack(f'<{cnt}s', reader.read(cnt))[0].rstrip(b'\x00').decode('cp932')  # cstring + null-terminator
                size += 2 + cnt
            elif op == 't':   # <uint16 (N), uint8[]>
                cnt:int = unpack('<H', reader.read(2))[0]
                v = tuple(map(MjoType, unpack(f'<{cnt}B', reader.read(cnt))))
                size += 2 + cnt
            elif op == 'c':   # <uint16 (N), int32[]>
                cnt:int = unpack('<H', reader.read(2))[0]
                v = unpack(f'<{cnt}i', reader.read(cnt * 4))
                size += 2 + cnt * 4
            elif op in 'fal': # <uint16>
                v = unpack(f'<H', reader.read(2))[0]
                size += 2
            elif op == 'o':   # <int16>
                v = unpack(f'<h', reader.read(2))[0]
                size += 2
            elif op in 'h0':  # <uint32>
                v = unpack(f'<I', reader.read(4))[0]
                size += 4
            elif op in 'ij':  # <int32>
                v = unpack(f'<i', reader.read(4))[0]
                size += 4
            elif op == 'r':   # <float32>
                v = unpack(f'<f', reader.read(4))[0]
                size += 4
            else:
                raise Exception(f'Unknown operand encoding {op!r}')

            if op in 'hi':
                self.hashname = HashName(v, lookup=lookup)
            self.operands[op] = v
        self._size = size
        return size

    def write_operands(self, writer:io.BufferedIOBase) -> int:
        size = 2  # <uint16 (opcode)>
        for op,v in self.operands.items():
            if op == 's':     # <uint16 (N), cstring>
                cstr:bytes = v.encode('cp932')
                writer.write(pack(f'<H{len(cstr)+1}s', len(cstr)+1, cstr))
                size += 2 + len(cstr) + 1  # cstring + null-terminator
            elif op == 't':   # <uint16 (N), uint8[]>
                writer.write(pack(f'<H{len(v)}B', len(v), *v))
                size += 2 + len(v)
            elif op == 'c':   # <uint16 (N), int32[]>
                writer.write(pack(f'<H{len(v)}i', len(v), *v))
                size += 2 + len(v) * 4
            elif op in 'fal': # <uint16>
                writer.write(pack(f'<H', v))
                size += 2
            elif op == 'o':   # <int16>
                writer.write(pack(f'<h', v))
                size += 2
            elif op in 'h0':  # <uint32>
                writer.write(pack(f'<I', v))
                size += 4
            elif op in 'ij':  # <int32>
                writer.write(pack(f'<i', v))
                size += 4
            elif op == 'r':   # <float32>
                writer.write(pack(f'<f', v))
                size += 4
            else:
                raise Exception(f'Unknown operand encoding {op!r}')
        self._size = size
        return size

    #endregion
    
