#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script IL formatting
"""

__version__ = '0.1.0'
__date__    = '2021-05-06'
__author__  = 'Robert Jordan'

__all__ = []

#######################################################################################

## runtime imports:
# from ..crypt import crypt32  # when MjoScript.read()/write() requires [de|en]cryption

import io
from struct import calcsize, pack, unpack
from typing import Any, Callable, List, NoReturn, Optional, Dict, Tuple, Union

from .opcodes import Opcode
from .flags import MjoFlags, MjoType
from ..identifier import HashValue, HashName, IdentifierKind
from .instruction import Instruction


# function entry type declared in table in MjoScript header before bytecode
# FunctionIndexEntry = namedtuple('FunctionIndexEntry', ('name_hash', 'offset'))

class FunctionIndexEntry:
    """FunctionIndexEntry(hashname:Union[HashName,int,str], offset:int, is_entrypoint:bool=False)

    this class is immutable
    """
    __slots__ = ('hashname', 'offset', 'is_entrypoint')
    def __init__(self, hashname:Union[HashName,int,str], offset:int, is_entrypoint:bool=False, *, lookup:bool=False):
        if isinstance(hashname, HashName):
            self.hashname = hashname
        else:
            self.hashname = HashName(hashname, IdentifierKind.FUNCTION, lookup=lookup)
        self.offset = offset
        self.is_entrypoint = is_entrypoint

    #region ## IMMUTABLE ##

    def __setattr__(self, name, value):
        # if name != 'is_entrypoint' and hasattr(self, name):
        if hasattr(self, name):
            raise AttributeError(f'{name!r} attribute is readonly')
        super().__setattr__(name, value)

    #endregion

    def __repr__(self) -> str:
        entrypoint = f', is_entrypoint={self.is_entrypoint!r}' if self.is_entrypoint else ''
        return f'FunctionIndexEntry({self.hashname.value!r}, {self.offset!r}{entrypoint})'
    def __str__(self) -> str: return repr(self)

    @property
    def hash(self) -> HashValue:
        return self.hashname.hash

    @classmethod
    def read(cls, reader:io.BufferedReader, main_offset:int=-1, *, lookup:bool=False) -> 'FunctionIndexEntry':
        hash, offset = unpack('<II', reader.read(8))
        hash = HashName(hash, IdentifierKind.FUNCTION, lookup=lookup)
        return FunctionIndexEntry(hash, offset, offset == main_offset, lookup=lookup)
    def write(self, writer:io.BufferedWriter) -> int:
        return writer.write(pack('<II', self.hash, self.offset))
    

class MjoScript:
    """Majiro .mjo script type and disassembler
    """
    SIGNATURE_ENCRYPTED:bytes = b'MajiroObjX1.000\x00'  # encrypted bytecode
    SIGNATURE_DECRYPTED:bytes = b'MajiroObjV1.000\x00'  # decrypted bytecode (majiro)
    SIGNATURE_PLAIN:bytes = b'MjPlainBytecode\x00'  # decrypted bytecode (mjdisasm)

    def __init__(self, signature:bytes, main_offset:int, line_count:int, bytecode_size:int, functions:List[FunctionIndexEntry], instructions:List[Instruction]):
        self.signature:bytes = signature
        self.main_offset:int = main_offset
        self.line_count:int = line_count
        self.bytecode_size:int = bytecode_size
        self.functions:List[FunctionIndexEntry] = functions
        self.instructions:List[Instruction] = instructions

    @property
    def bytecode_offset(self) -> int:
        return 16 + 12 + len(self.functions) * 8 + 4
        # return calcsize(f'<16sIII{len(self.functions)*2}II')
    @property
    def is_readmark(self) -> bool:
        # preprocessor "#use_readflg on" setting, we need to export this with IL
        return bool(self.line_count)
    @property
    def main_function(self) -> FunctionIndexEntry:
        for func in self.functions:
            if func.offset == self.main_offset:
                return func
        return None

    # def get_resource_key(self, instruction:Instruction, *, options:ILFormat=ILFormat.DEFAULT) -> str:
    #     if options.resfile_directive and instruction.opcode.mnemonic == "text": # 0x840
    #         # count = 0
    #         number = 0
    #         for instr in self.instructions:
    #             if instr.opcode.mnemonic == "text": # 0x840
    #                 # count += 1
    #                 number += 1
    #                 if instr.offset == instruction.offset:
    #                     # number = count
    #                     # break
    #                     return f'L{number}' # number will be 1-indexed
    #         # return f'L{number}'
    #     return None
    #     # index = self.instruction_index_from_offset(instruction.offset)
    #     # number = len([1 for i in range(index) if self.instructions[i].opcode.mnemonic == "text"]) # 0x840

    #region ## READ/WRITE FUNCTIONS ##

    @classmethod
    def open(cls, filename:str, *, lookup:bool=False) -> 'MjoScript':
        with open(filename, 'rb') as file:
            return cls.read(file, lookup=lookup)

    def save(self, filename:str) -> 'MjoScript':
        with open(filename, 'wb+') as file:
            return self.write(file)

    @classmethod
    def read(cls, reader:io.BufferedReader, *, lookup:bool=False) -> 'MjoScript':
        # header:
        signature, main_offset, line_count, function_count = unpack('<16sIII', reader.read(28))
        is_encrypted:bool = (signature == cls.SIGNATURE_ENCRYPTED)
        assert(is_encrypted ^ (signature in (cls.SIGNATURE_DECRYPTED, cls.SIGNATURE_PLAIN)))

        # functions table:
        functions:List[FunctionIndexEntry] = []
        for _ in range(function_count):
            # func = FunctionIndexEntry.read(reader, main_offset)
            # if func.offset == main_offset:
            #     func.is_entrypoint = True
            # functions.append(func)
            functions.append(FunctionIndexEntry.read(reader, main_offset, lookup=lookup))

        # bytecode:
        bytecode_size:int = unpack('<I', reader.read(4))[0]

        # bytecode_offset:int = reader.tell()
        bytecode:bytes = reader.read(bytecode_size)
        if len(bytecode) != bytecode_size:
            raise Exception('unexpected end of file before end of bytecode')
        if is_encrypted:
            from ..crypt import crypt32
            bytecode = crypt32(bytecode)  # decrypt bytecode
        ms:io.BytesIO = io.BytesIO(bytecode)
        instructions:List[Instruction] = cls.read_bytecode(ms, lookup=lookup)

        return MjoScript(signature, main_offset, line_count, bytecode_size, functions, instructions)

    def write(self, writer:io.BufferedWriter) -> NoReturn:
        # header:
        if self.signature not in (self.SIGNATURE_ENCRYPTED, self.SIGNATURE_DECRYPTED):
            raise Exception(f'{self.__class__.__name__} signature must be {self.SIGNATURE_ENCRYPTED.decode("cp932")!r} or {self.SIGNATURE_DECRYPTED.decode("cp932")!r}, not {self.signature.decode("cp932")!r}')
        writer.write(pack('<16sIII', self.signature, self.main_offset, self.line_count, len(self.functions)))
        is_encrypted:bool = (self.signature == self.SIGNATURE_ENCRYPTED)
        assert(is_encrypted ^ (self.signature in (self.SIGNATURE_DECRYPTED, self.SIGNATURE_PLAIN)))

        # functions table:
        for func in self.functions:
            func.write(writer)

        # bytecode:
        writer.write(pack('<I', self.bytecode_size))

        # initialize full-length of bytecode ahead of time (is this actually efficient in Python?)
        ms:io.BytesIO = io.BytesIO(bytes(self.bytecode_size))
        self.write_bytecode(ms)
        ms.flush()

        bytecode:bytes = ms.getvalue()
        if is_encrypted:
            from ..crypt import crypt32
            bytecode = crypt32(bytecode)  # encrypt bytecode
        written_size = writer.write(bytecode)
        assert(written_size == self.bytecode_size)

    @classmethod
    def read_bytecode(cls, reader:io.BufferedReader, *, lookup:bool=False) -> List[Instruction]:
        # reader = StructIO(reader)

        pos:int = reader.tell()
        length = reader.seek(0, 2) - pos
        reader.seek(pos)
        # length:int = reader.length()
        offset:int = reader.tell()

        instructions:List[Instruction] = []
        while offset != length:
            instr:Instruction = Instruction.read(reader, offset, lookup=lookup)
            instructions.append(instr)
            assert(offset + instr.size == reader.tell())
            offset = reader.tell()

        return instructions

    def write_bytecode(self, writer:io.BufferedWriter) -> NoReturn:

        for instr in self.instructions:
            instr.write_instruction(writer)

    #endregion



    def instruction_index_from_offset(self, offset:int) -> int:
        for i,instr in enumerate(self.instructions):
            if instr.offset == offset:
                return i
        return -1


