#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script disassembler
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['Instruction', 'MjoScript', 'BasicBlock', 'Function']

#######################################################################################

import io, re
from abc import abstractproperty
from collections import namedtuple
from typing import Iterator, List, NoReturn, Optional, Tuple  # for hinting in declarations

from ._util import StructIO, DummyColors, Colors
from .flags import MjoType, MjoScope, MjoInvertMode, MjoModifier, MjoFlags
from .opcodes import Opcode
from . import crypt
from . import known_hashes

## FORMAT OPTIONS ##

#NOTE: This is a temporary class until the real formatter module is complete

class ILFormat:
    DEFAULT:'ILFormat' = None
    def __init__(self):
        self.color:bool = False  # print colors to the console
        self.braces:bool = True  # add braces around functions
        self.known_hashes:bool = True
        self.annotations:bool = True   # ; $known_hash, _knownvar, etc. [when: inline_hash=False]
                                       # ; $XXXXXXXX [when: inline_hash=True]
        self.inline_hash:bool = False  # $hashname (when known) [requires: known_hashes=True]
        self.explicit_inline_hash:bool = False  # ${hashname}  [requires: inline_hash=True]
        self.syscall_inline_hash:bool = False  # include inline hashing for syscalls
                                               # this will lose backwards compatibility as known hash names are updated
        self.int_inline_hash:bool = True  # inline hashes for integer literals
        #FIXME: Not implemented (still output to file)
        self.group_directive:str = None  # default group to disassemble with (removes @GROUPNAME when found)
        #FIXME: Not implemented
        # self.vartype_aliases:bool = False   # i, r, s, iarr, rarr, sarr
        self.modifier_aliases:bool = False  # inc.x, dec.x, x.inc, x.dec
        self.explicit_varoffset:bool = False  # always include -1 for non-local var offsets
        self.explicit_dim0:bool = False  # always include dim0 flag  #WHY WOULD YOU WANT THIS?

    def needs_explicit_hash(self, known_hash:str) -> bool:
        import re
        # return True if setting is enabled, or unsupported identifier characters exist
        #source: <https://stackoverflow.com/a/1325265/7517185>
        return self.explicit_inline_hash or bool(re.search(r'[^_%@#$0-9A-Za-z]', known_hash))
        
    
    @classmethod
    def properties(self) -> List[str]:
        return [k for k in ILFormat.DEFAULT.__dict__.keys() if k[0] != '_' and k != 'group_directive']  # quick dumb handling

    @property
    def colors(self) -> dict:
        return Colors if self.color else DummyColors

ILFormat.DEFAULT = ILFormat()


class Instruction:
    """Bytecode instruction of opcode, offset, operands, and optionally analysis data
    """
    def __init__(self, opcode:Opcode, offset:int):
        # general #
        self.opcode:Opcode = opcode
        self.offset:int = offset  # bytecode offset
        self.size:int = 0  # instruction size in bytecode

        # operands #
        self.flags:MjoFlags = MjoFlags(0)  # flags for ld* st* variable opcodes
        self.hash:int = 0  # identifier hash for ld* st* variable opcodes, and call* syscall* function opcodes
        self.var_offset:int = 0  # stack offset for ld* st* local variables (-1 used for non-local)
        self.type_list:List[MjoType] = None  # type list operand for argcheck opcode
        self.string:str = None  # string operand for ldstr, text, ctrl opcodes
        self.int_value:int = 0  # int operand for ldc.i opcode
        self.float_value:float = 0.0  # float operand for ldc.r opcode
        self.argument_count:int = 0  # argument count operand for call* syscall* function opcodes
        self.line_number:int = 0  # line number operand for line opcode
        self.jump_offset:int = 0  # jump offset operand for b* opcodes
        self.switch_cases:List[int] = None  # switch jump offset operands for switch opcode

        # analysis #
        self.jump_target:'BasicBlock' = None  # analyzed jump target location
        self.switch_targets:List['BasicBlock'] = None  # analyzed switch jump target locations

    @property
    def is_jump(self) -> bool: return self.opcode.is_jump
    @property
    def is_switch(self) -> bool: return self.opcode.mnemonic == "switch"  # 0x850
    @property
    def is_return(self) -> bool: return self.opcode.mnemonic == "ret"  # 0x82b
    @property
    def is_argcheck(self) -> bool: return self.opcode.mnemonic == "argcheck"  # 0x836
    @property
    def is_syscall(self) -> bool: return self.opcode.mnemonic in ("syscall", "syscallp")  # 0x834, 0x835
    @property
    def is_call(self) -> bool: return self.opcode.mnemonic in ("call", "callp")  # 0x80f, 0x810
    # ldc.i 0x800, ldstr 0x801, ldc.r 0x803
    @property
    def is_literal(self) -> bool: return self.opcode.mnemonic in ("ldc.i", "ldc.r", "ldstr")
    # ld 0x802, ldelem 0x837
    @property
    def is_load(self) -> bool: return self.opcode.mnemonic in ("ld", "ldelem")
    # st.* 0x1b0~0x200, stp.* 0x210~0x260, stelem.* 0x270~0x2c0, stelemp.* 0x2d0~0x320
    @property
    def is_store(self) -> bool: return self.opcode.mnemonic.startswith("st")

    def __str__(self) -> str:
        return self.format_instruction()
    def __repr__(self) -> str:
        return self.format_instruction()
        
    @classmethod
    def format_string(cls, string:str, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        import re
        colors:dict = options.colors
        # unescape single quotes and escape double-quotes
        # string = repr(string)[1:-1].replace('\\\'', '\'').replace('\"', '\\\"')
        string = repr(string)[1:-1]
        # this pattern ensures ignoring any leading escaped backslashes
        # unescape single-quotes
        string = re.sub(r'''(?<!\\)((?:\\\\)*)(?:\\('))''', r'\1\2', string)
        # escape double-quotes
        string = re.sub(r'''(?<!\\)((?:\\\\)*)(?:("))''', r'\1\\\2', string)
        if options.color:
            # brighten escapes
            string = re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[\\\\'\\"abfnrtv])''', r'{BRIGHT}\0{DIM}'.format(**colors), string)
        return '{DIM}{GREEN}"{}"{RESET_ALL}'.format(string, **colors)

    def check_known_hash(self) -> Optional[Tuple[str, bool]]: # (name, is_syscall)
        if self.is_syscall:
            return (known_hashes.SYSCALLS.get(self.hash, None), True)
        elif self.is_call:
            return (known_hashes.USERCALLS.get(self.hash, None), False)
        elif self.is_load or self.is_store:
            # TODO: this could be optimized to use the type flags
            #       and search in the scope-independent dicts
            return (known_hashes.VARIABLES.get(self.hash, None), False)
        elif self.opcode.mnemonic == "ldc.i": # 0x800
            name = (known_hashes.USERCALLS.get(self.int_value, None), False)
            # TODO: Uncomment if it's observed that int literals
            #       will use hashes for types other than usercalls
            # if name[0] is None:
            #     name = (known_hashes.VARIABLES.get(self.int_value, None), False)
            # if name[0] is None:
            #     name = (known_hashes.SYSCALLS.get(self.int_value, None), True)
            return name
        
        return None, False # not an opcode that relates to hashes

    def print_instruction(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_instruction(options=options), **kwargs)
    def format_instruction(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        colors:dict = options.colors
        sb:str = ''

        if self.opcode.mnemonic == "line":  # 0x83a
            sb += '{BRIGHT}{BLACK}{0.offset:06x}:{RESET_ALL} {BRIGHT}{BLACK}{0.opcode.mnemonic:<13}{RESET_ALL}'.format(self, **colors)
        else:
            sb += '{BRIGHT}{BLACK}{0.offset:06x}:{RESET_ALL} {BRIGHT}{WHITE}{0.opcode.mnemonic:<13}{RESET_ALL}'.format(self, **colors)

        if not self.opcode.encoding:
            sb = sb.rstrip()  # trim trailing whitespace normally added to pad operands
            return sb  # no operands, nothing to add

        ops_offset = len(sb)  # for even ~fancier formatting~
        # true if the integer literal field matches a known name hash
        # is_literal_hash:bool = False
        # literal_hash_type:str = None  # 'syscall', 'call', 'var'
        # # at the moment, only function hashes have been observed being pushed with ldc.i
        # #  set this constant to False to search through ALL hashes
        # LITERAL_USERCALLS_ONLY:bool = True
        known_hash_name, known_hash_is_syscall = None, False
        if options.known_hashes:
            known_hash_name, known_hash_is_syscall = self.check_known_hash()

        for operand in self.opcode.encoding:
            if operand == '0':
                # 4 byte address placeholder
                continue  # don't want the extra space in the operands

            sb += ' '
            if operand == 't':
                # type list
                sb += '[{!s}]'.format(', '.join('{BRIGHT}{CYAN}{!s}{RESET_ALL}'.format(t.name.lower(), **colors) for t in self.type_list))
            elif operand == 's':
                # string data
                sb += self.format_string(self.string, options=options)
                # sb += '{DIM}{GREEN}"{!s}"{RESET_ALL}'.format(self.format_string(self.string, options=options), **colors)
            elif operand == 'f':
                # flags
                flags = self.flags
                keywords:list = []
                #TODO: both type and scope names are match the legal names,
                #      but these should be explictly defined at some point
                keywords.append(flags.scope.name.lower())
                keywords.append(flags.type.name.lower())
                dimension = flags.dimension
                if dimension or options.explicit_dim0:  #NOTE: dim0 is still legal, but not required, or recommended...
                    keywords.append('dim{:d}'.format(dimension))
                invert:MjoInvertMode = flags.invert
                INVERT_NAMES = ('neg', 'notl', 'not')  # operators: (-x, !x, ~x)
                if invert:
                    keywords.append(INVERT_NAMES[invert.value - 1])
                # if invert is MjoInvertMode.Numeric:
                #     keywords.append('neg')   # operator: -x
                # elif invert is MjoInvertMode.Boolean:
                #     keywords.append('notl')  # operator: !x
                # elif invert is MjoInvertMode.Bitwise:
                #     keywords.append('not')   # operator: ~x
                # if invert:
                #     keywords.append('invert_{}'.format(invert.name.lower()))
                modifier = flags.modifier
                MODIFIER_NAMES = (('preinc','inc.x'), ('predec','dec.x'), ('postinc','x.inc'), ('postdec','x.dec'))
                if modifier:
                    keywords.append(MODIFIER_NAMES[modifier.value - 1][bool(options.modifier_aliases)])
                # if modifier is MjoModifier.PreIncrement:
                #     keywords.append('preinc')   # alias: inc.x
                # elif modifier is MjoModifier.PreDecrement:
                #     keywords.append('predec')   # alias: dec.x
                # elif modifier is MjoModifier.PostIncrement:
                #     keywords.append('postinc')  # alias: x.inc
                # elif modifier is MjoModifier.PostDecrement:
                #     keywords.append('postdec')  # alias: x.dec
                # if modifier:
                #     keywords.append('modifier_{}'.format(modifier.name.lower()))

                sb += '{BRIGHT}{CYAN}{}{RESET_ALL}'.format(' '.join(keywords), **colors)
            elif operand == 'h':
                # hash name
                # if known_hash_name and options.inline_hash and (options.syscall_inline_hash or not self.is_syscall):
                #     if self.is_syscall:
                #         sb += '{BRIGHT}{YELLOW}'.format(**colors)
                #     elif self.is_call:
                #         sb += '{BRIGHT}{BLUE}'.format(**colors)
                #     else: #elif self.is_load or self.is_store:
                #         sb += '{BRIGHT}{RED}'.format(**colors)
                # else:
                
                if self.is_syscall:
                    hash_color = '{BRIGHT}{YELLOW}'.format(**colors)
                elif self.is_call:
                    hash_color = '{BRIGHT}{BLUE}'.format(**colors)
                else: #elif self.is_load or self.is_store:
                    hash_color = '{BRIGHT}{RED}'.format(**colors)
                if known_hash_name and options.inline_hash and (options.syscall_inline_hash or not self.is_syscall):
                    known_hash_name2 = known_hash_name
                    if self.is_syscall:
                        known_hash_name2 = known_hash_name.lstrip('$') # requirement for syscall hash lookup syntax
                    if options.needs_explicit_hash(known_hash_name2):
                        sb += '{BRIGHT}{CYAN}${{{RESET_ALL}{}{}{RESET_ALL}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                    else:
                        sb += '{BRIGHT}{CYAN}${RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                else:
                    sb += '${:08x}{RESET_ALL}'.format(self.hash, **colors)
            elif operand == 'o':
                # variable offset
                #NEW: exclude -1 offsets for non-local variables, because that operand
                #     isn't used. still output erroneous var offsets
                if options.explicit_varoffset or self.var_offset != -1 or self.flags.scope is MjoScope.Local:
                    sb += '{:d}'.format(self.var_offset)
            # elif operand == '0':
            #     # 4 byte address placeholder
            #     pass
            elif operand == 'i':
                # integer constant
                # integer literals will sometimes use hashes for usercall function pointers
                # this entire if statement tree is terrifying...
                if known_hash_name is not None:
                    # hash_color = colors["RED"]  # default to variable hash name
                    if known_hash_is_syscall:
                        hash_color = '{BRIGHT}{YELLOW}'.format(**colors)
                    elif known_hash_name[0] == '$':
                        hash_color = '{BRIGHT}{BLUE}'.format(**colors)
                    else: #elif self.is_load or self.is_store:
                        hash_color = '{BRIGHT}{RED}'.format(**colors)
                    # if known_hash_name[0] in ('_','%','@','#'):
                    #     hash_color = colors["RED"]
                    # elif known_hash_name[0] == '$':
                    #     if known_hash_is_syscall:
                    #         hash_color = colors["YELLOW"]
                    #     else:
                    #         hash_color = colors["BLUE"]
                    # if options.inline_hash and (not known_hash_is_syscall or options.syscall_inline_hash):
                    #     sb += '{BRIGHT}{BLACK}; {DIM}{}${:08x}{RESET_ALL}'.format(hash_color, self.int_value, **colors)
                    # else:
                    #     sb += '{BRIGHT}{BLACK}; {DIM}{}{}{RESET_ALL}'.format(hash_color, known_hash_name, **colors)
                    if options.inline_hash and options.int_inline_hash and (options.syscall_inline_hash or not known_hash_is_syscall):
                        known_hash_name2 = known_hash_name
                        if known_hash_is_syscall:
                            known_hash_name2 = known_hash_name.lstrip('$') # requirement for syscall hash lookup syntax
                        if options.needs_explicit_hash(known_hash_name2):
                            sb += '{BRIGHT}{CYAN}${{{RESET_ALL}{}{}{RESET_ALL}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                        else:
                            sb += '{BRIGHT}{CYAN}${RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                    else:
                        # print as hex for simplicity
                        sb += '0x{:08x}'.format(self.int_value)
                else:
                    sb += '{:d}'.format(self.int_value)
            elif operand == 'r':
                # float constant
                sb += '{:n}'.format(self.float_value)
            elif operand == 'a':
                # argument count
                sb += '({:d})'.format(self.argument_count)
            elif operand == 'j':
                # jump offset
                if self.jump_target is not None:
                    sb += '{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(self.jump_target.name, **colors)
                else:
                    sb += '{BRIGHT}{MAGENTA}@~{:+04x}{RESET_ALL}'.format(self.jump_offset, **colors)
            elif operand == 'l':
                # line number
                sb += '{BRIGHT}{BLACK}#{:d}{RESET_ALL}'.format(self.line_number, **colors)
            elif operand == 'c':
                # switch case table
                if self.switch_targets: # is not None:
                    sb += ', '.join('{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(t.name, **colors) for t in self.switch_targets) # pylint: disable=not-an-iterable
                else:
                    sb += ', '.join('{BRIGHT}{MAGENTA}@~{:+04x}{RESET_ALL}'.format(o, **colors) for o in self.switch_cases)
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
        
        if known_hash_name is None or not options.annotations:
            pass  # no hash name comments
        elif self.is_syscall: # 0x834, 0x835
            # sb += '{BRIGHT}{BLACK}[{DIM}{YELLOW}{}{BRIGHT}{BLACK}]{RESET_ALL}'.format(known_hash_name, **colors)
            if options.inline_hash and options.syscall_inline_hash:
                sb += '  {BRIGHT}{BLACK}; {DIM}{YELLOW}${:08x}{RESET_ALL}'.format(self.hash, **colors)
            else:
                sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["YELLOW"]) + len(colors["RESET_ALL"]))
                sb += '{BRIGHT}{BLACK}; {DIM}{YELLOW}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif self.is_call: # 0x80f, 0x810
            # sb += '{BRIGHT}{BLACK}[{DIM}{BLUE}{}{BRIGHT}{BLACK}]{RESET_ALL}'.format(known_hash_name, **colors)
            if options.inline_hash:
                sb += '  {BRIGHT}{BLACK}; {DIM}{BLUE}${:08x}{RESET_ALL}'.format(self.hash, **colors)
            else:
                sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["BLUE"]) + len(colors["RESET_ALL"]))
                sb += '{BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif self.is_load or self.is_store:
            if options.inline_hash:
                sb += '  {BRIGHT}{BLACK}; {DIM}{RED}${:08x}{RESET_ALL}'.format(self.hash, **colors)
            else:
                sb += '  {BRIGHT}{BLACK}; {DIM}{RED}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif self.opcode.mnemonic == "ldc.i": # 0x800
            # check for loading function hashes (which are often passed to )
            #hash_color = colors["YELLOW"]  # default to syscall when hash type is not known, because we do syscalls without '$' sometimes
            # hash_color = colors["RED"]  # default to variable hash name
            # if known_hash_is_syscall:
            #     hash_color = colors["YELLOW"]
            # elif known_hash_name[0] == '$':
            #     hash_color = colors["BLUE"]
            if known_hash_is_syscall:
                hash_color = '{DIM}{YELLOW}'.format(**colors)
            elif known_hash_name[0] == '$':
                hash_color = '{DIM}{BLUE}'.format(**colors)
            else: #elif self.is_load or self.is_store:
                hash_color = '{DIM}{RED}'.format(**colors)
            # if known_hash_name[0] in ('_','%','@','#'):
            #     hash_color = colors["RED"]
            # elif known_hash_name[0] == '$':
            #     if known_hash_is_syscall:
            #         hash_color = colors["YELLOW"]
            #     else:
            #         hash_color = colors["BLUE"]
            if options.inline_hash and options.int_inline_hash and (not known_hash_is_syscall or options.syscall_inline_hash):
                sb += '  {BRIGHT}{BLACK}; {RESET_ALL}{}${:08x}{RESET_ALL}'.format(hash_color, self.int_value, **colors)
            else:
                sb = sb.ljust(ops_offset + 16)
                sb += '{BRIGHT}{BLACK}; {RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name, **colors)
        return sb

    @classmethod
    def read_instruction(cls, reader:StructIO, offset:int) -> 'Instruction':
        opcode_value:int = reader.unpackone('<H')
        opcode:Opcode = Opcode.BYVALUE.get(opcode_value, None)
        if not opcode:
            raise Exception('Invalid opcode found at offset 0x{:08X}: 0x{:04X}'.format(offset, opcode_value))
        instruction:Instruction = Instruction(opcode, offset)

        for operand in opcode.encoding:
            if operand == 't':
                # type list
                count = reader.unpackone('<H')
                instruction.type_list = [MjoType(b) for b in reader.unpack('<{:d}B'.format(count))]
            elif operand == 's':
                # string data
                size = reader.unpackone('<H')
                instruction.string = reader.read(size).rstrip(b'\x00').decode('cp932')
            elif operand == 'f':
                # flags
                instruction.flags = MjoFlags(reader.unpackone('<H'))
            elif operand == 'h':
                # hash name
                instruction.hash = reader.unpackone('<I')
            elif operand == 'o':
                # variable offset
                instruction.var_offset = reader.unpackone('<h')
            elif operand == '0':
                # 4 byte address placeholder
                assert(reader.unpackone('<I') == 0)
            elif operand == 'i':
                # integer constant
                instruction.int_value = reader.unpackone('<i')
            elif operand == 'r':
                # float constant
                instruction.int_value = reader.unpackone('<f')
            elif operand == 'a':
                # argument count
                instruction.argument_count = reader.unpackone('<H')
            elif operand == 'j':
                # jump offset
                instruction.jump_offset = reader.unpackone('<i')
            elif operand == 'l':
                # line number
                instruction.line_number = reader.unpackone('<H')
            elif operand == 'c':
                # switch case table
                count = reader.unpackone('<H')
                instruction.switch_cases = list(reader.unpack('<{:d}i'.format(count)))
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
        
        instruction.size = reader.tell() - offset
        return instruction


# function entry type declared in table in MjoScript header before bytecode
FunctionEntry = namedtuple('FunctionEntry', ('name_hash', 'offset'))


class MjoScript:
    """Majiro .mjo script type and disassembler
    """
    SIGNATURE_ENCRYPTED:bytes = b'MajiroObjX1.000\x00'  # encrypted bytecode
    SIGNATURE_DECRYPTED:bytes = b'MajiroObjV1.000\x00'  # decrypted bytecode (majiro)
    SIGNATURE_PLAIN:bytes = b'MjPlainBytecode\x00'  # decrypted bytecode (mjdisasm)
    def __init__(self, signature:bytes, main_offset:int, line_count:int, bytecode_offset:int, bytecode_size:int, functions:List[FunctionEntry], instructions:List[Instruction]):
        self.signature:bytes = signature
        self.main_offset:int = main_offset
        self.line_count:int = line_count
        self.bytecode_offset:int = bytecode_offset
        self.bytecode_size:int = bytecode_size
        self.functions:List[FunctionEntry] = functions
        self.instructions:List[Instruction] = instructions

    @property
    def is_readmark(self) -> bool:
        # preprocessor "#use_readflg on" setting, we need to export this with IL
        return bool(self.line_count)
    @property
    def main_function(self) -> FunctionEntry:
        for fn in self.functions:
            if fn.offset == self.main_offset:
                return fn
        return None

    def instruction_index_from_offset(self, offset:int) -> int:
        for i,instr in enumerate(self.instructions):
            if instr.offset == offset:
                return i
        return -1

    @classmethod
    def disassemble_script(cls, reader:io.BufferedReader) -> 'MjoScript':
        if not isinstance(reader, StructIO):
            reader = StructIO(reader)
        signature:bytes = reader.unpackone('<16s')
        is_encrypted:bool = (signature == cls.SIGNATURE_ENCRYPTED)
        assert(is_encrypted ^ (signature in (cls.SIGNATURE_DECRYPTED, cls.SIGNATURE_PLAIN)))

        # bytecode offset to main function, allows us to identify main function name_hash in entry table
        main_offset:int = reader.unpackone('<I')
        # field contains the last line number (as observed from line opcodes)
        #  this field is only non-zero in "story" scripts, which include the
        #  preprocessor command "#use_readflg on" when compiled
        line_count:int = reader.unpackone('<I')
        function_count:int = reader.unpackone('<I')
        functions:List[FunctionEntry] = []
        for _ in range(function_count):
            functions.append(FunctionEntry(*reader.unpack('<II')))

        bytecode_offset:int = reader.tell()
        bytecode_size:int = reader.unpackone('<I')
        bytecode:bytes = reader.read(bytecode_size)
        if is_encrypted:
            bytecode = crypt.crypt32(bytecode)  # decrypt bytecode
        ms = StructIO(io.BytesIO(bytecode))
        instructions:List[Instruction] = cls.disassemble_bytecode(ms)

        return MjoScript(signature, main_offset, line_count, bytecode_offset, bytecode_size, functions, instructions)

    @classmethod
    def disassemble_bytecode(self, reader:StructIO) -> List[Instruction]:
        if not isinstance(reader, StructIO):
            reader = StructIO(reader)
        length:int = reader.length()

        instructions:List[Instruction] = []
        offset:int = reader.tell()
        while offset != length:
            instruction:Instruction = Instruction.read_instruction(reader, offset)
            instructions.append(instruction)
            offset = reader.tell()
        return instructions

    def print_readmark(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_readmark(options=options), **kwargs)
    def format_readmark(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        #FIXME: temp solution to print all directives in one go
        colors:dict = options.colors
        setting = ('{GREEN}enable' if self.is_readmark else '{RED}disable').format(**colors)
        s = '{DIM}{YELLOW}readmark{RESET_ALL} {BRIGHT}{}{RESET_ALL}'.format(setting, **colors)
        s += '\n'
        if options.group_directive is None:
            s += '{DIM}{YELLOW}group{RESET_ALL} {BRIGHT}{RED}none{RESET_ALL}'.format(**colors)
        else:
            s += '{DIM}{YELLOW}group{RESET_ALL} {}'.format(Instruction.format_string(options.group_directive, options=options), **colors)
        return s



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
    def instructions(self) -> Iterator[Instruction]:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return []
        return self.script.instructions[self.first_instruction_index:self.last_instruction_index + 1]  # pylint: disable=no-member
        # for i in range(self.first_instruction_index, self.last_instruction_index + 1):
        #     yield self.script.instructions[i]
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
    def __init__(self, function:'Function'):
        super().__init__()
        self.function = function
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
            return 'destructor_{:06x}'.format(self.start_offset)
        elif self.is_exit_block:
            return 'exit_{:06x}'.format(self.start_offset)
        else:
            return 'block_{:06x}'.format(self.start_offset)

    def print_basic_block(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_basic_block(options=options), **kwargs)
    def format_basic_block(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        colors:dict = options.colors
        return '{BRIGHT}{MAGENTA}{.name!s}:{RESET_ALL}'.format(self, **colors)

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
    def __init__(self, script:MjoScript, name_hash:int):
        super().__init__()
        self._script:MjoScript = script
        self.name_hash:int = name_hash
        self.entry_block:BasicBlock = None
        self.exit_blocks:List[BasicBlock] = None
        self.parameter_types:List[MjoType] = None
    @property
    def script(self) -> MjoScript:
        return self._script
    @property
    def is_entrypoint(self) -> bool:
        return self.start_offset == self.script.main_offset

    def print_function(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_function(options=options), **kwargs)
    def format_function(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        colors:dict = options.colors

        # always "func" as, "void" can only be confirmed by all-zero return values
        s = '{BRIGHT}{BLUE}func '.format(**colors)
        # s = '{BRIGHT}{BLUE}func ${.name_hash:08x}{RESET_ALL}({!s})'.format(self, args, **colors)

        known_hash:str = None
        if options.known_hashes:
            known_hash = known_hashes.USERCALLS.get(self.name_hash, None)
        if known_hash is not None and options.inline_hash:
            if options.needs_explicit_hash(known_hash):
                s += '{BRIGHT}{CYAN}${{{BRIGHT}{BLUE}{}{BRIGHT}{CYAN}}}{BRIGHT}{BLUE}'.format(known_hash, **colors)
            else:
                s += '{BRIGHT}{CYAN}${BRIGHT}{BLUE}{}'.format(known_hash, **colors)
        else:
            s += '${.name_hash:08x}'.format(self)

        args = ', '.join('{BRIGHT}{CYAN}{!s}{RESET_ALL}'.format(t.name.lower(), **colors) for t in self.parameter_types) # pylint: disable=not-an-iterable
        s += '{RESET_ALL}({!s})'.format(args, **colors)

        # "entrypoint" states which function to declare as "main" to the IL assembler
        if self.is_entrypoint:
            s += ' {DIM}{YELLOW}entrypoint{RESET_ALL}'.format(**colors)
    
        # optional brace formatting
        if options.braces:
            s += ' {'

        #known_hash = known_hashes.USERCALLS.get(self.name_hash, None)
        if known_hash is not None and options.annotations:
            if options.inline_hash:
                s += '  {BRIGHT}{BLACK}; {DIM}{BLUE}${.name_hash:08x}{RESET_ALL}'.format(self, **colors)
            else:
                s += '  {BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash, **colors)
    
        return s
    def print_function_close(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_function_close(options=options), **kwargs)
    def format_function_close(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        return '}' if options.braces else ''


del abstractproperty, namedtuple, Iterator, NoReturn, Optional, Tuple  # cleanup declaration-only imports
