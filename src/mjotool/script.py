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

import io
from abc import abstractproperty
from collections import namedtuple
from typing import Iterator, List, NoReturn, Optional, Tuple  # for hinting in declarations

from ._util import StructIO, DummyColors, Colors
from .flags import MjoType, MjoScope, MjoInvertMode, MjoModifier, MjoFlags
from .opcodes import Opcode
from . import crypt
from . import known_hashes


## Hardcoded list until a better method is setup
KNOWN_SYSCALLS = {0x1295BBDA: "$event_hook_after", 0x078A756E: "$event_hook", 0x266A3C79: "$strupr$", 0xDF644F85: "$dialog_error_ok", 0x83D81F59: "$page_create", 0xF94B3586: "$page_create_withalfa", 0xDAD96289: "$page_create_file", 0x57EFA275: "$page_create_file_withalfa", 0xC50DFD06: "$page_release", 0x56BBBA3A: "$grp_copy", 0x6E83677A: "$get_variable", 0xCD290AEF: "$set_variable", 0x76EE6C90: "$do_event", 0xF3679C34: "$debugout", 0xA62AA5EB: "$is_fast_mode", 0xC21F8B49: "$is_auto_mode", 0x619DE833: "$is_report_no_pic", 0x4B5AC64B: "$is_log_no_pic", 0x6E6C641A: "$is_testplay", 0x5B87A41D: "$console_is_on", 0xB5A1E3C9: "$console_cls", 0xF1097A07: "$voice_stat", 0xD1F672C7: "$voice_wait", 0xEE154520: "$get_autospeed", 0xCF35F0E3: "$wait", 0x661AFB43: "$sprite_rotate", 0xE119D5BA: "$sprite_move", 0x4A02D664: "$sprite_priority_high", 0xFF7C52E6: "$sprite_alfa_set", 0xEF4581DC: "$sprite_create", 0x6584F13E: "$timer", 0xE06200C4: "$client_width", 0x109CA5DB: "$atoi", 0x8AEF9167: "$strmid$", 0x06906970: "$strleft$", 0xE5C70196: "$get_mojispeed", 0xC5270429: "$get_font_name$", 0x708B0256: "$sound2", 0x892E9B20: "$mk_read", 0xEE6B328D: "$timer_progress", 0x30FA2A29: "$console_setzerotime", 0x924EE3EB: "$rgb", 0x265E07D7: "$sprite_get_page", 0xD01BE374: "$grp_boxfill", 0x70612DB5: "$get_alfapage", 0x06B3C8AC: "$console_font", 0xD4066E31: "$histbuff_disable", 0x403960F8: "$console_set", 0x5FDCCCEE: "$console_color", 0xF1F8A206: "$console_locate_force", 0x4133D7A9: "$histbuff_enable", 0x111BD910: "$get_effectspeed", 0x6ED38886: "$set_autospeed", 0x6501CC30: "$set_mojispeed", 0x0C93FCB4: "$set_effectspeed", 0x44B5C4ED: "$save_menu_disable", 0x81CE0485: "$fast_mode_disable", 0x60085FA4: "$mouse_disable", 0x4D849AA6: "$save_menu_enable", 0x8C7F4C1E: "$fast_mode_enable", 0x44BC7555: "$mouse_enable", 0x1204D7E8: "$mk_unwait", 0x65F2E980: "$page_len_y", 0xF8FD08F6: "$page_len_x", 0xF80BC9B6: "$sprite_alfa_define", 0xD7771B72: "$sprite_alfa_wait", 0xF6A05538: "$sprite_create_ext", 0x58B31737: "$sprite_release", 0x01B4517C: "$sprite_xmodify_define", 0x6F384A3D: "$sprite_ymodify_define", 0xF2F9DAA8: "$thread_begin", 0xCF2B1E50: "$invalidate_disable", 0x979D1F16: "$console_off", 0xA2743878: "$console_on", 0x6DE6CDFC: "$invalidate_enable", 0x307F28BC: "$console_redraw", 0x69DB4512: "$strstr", 0xB0C8F550: "$strlen", 0x05EA6E4D: "$get_last_msg$", 0xF8004993: "$save_point", 0xFAC4F361: "$set_auto_mode", 0x818A4B92: "$reset_fast_mode", 0x4E1EB9D0: "$areaevent_reset", 0xA7C6E918: "$areaevent_setdefault", 0xF8D18340: "$areaevent_set", 0x0E42730D: "$console_curpos_x", 0x934D927B: "$console_curpos_y", 0xC29B30E3: "$sprite_animate_define", 0x3A3BFB29: "$areaevent_check", 0xED84E320: "$sound3", 0x008ACBC0: "$mk_wait", 0x3704c919: "$exit", 0x3a3ca0f1: "$do_load", 0x89018dd1: "$do_save", 0x4ffab7c4: "$is_save_menu_disable", 0x25401A1F: "$strright$", 0x35A89417: "$fontout", 0x57F6310D: "$fontout_locate", 0x90816C6E: "$fontout_color", 0xE186D19A: "$fontout_font", 0x959B0A16: "$abs", 0x8C283F7F: "$client_height", 0xD3C06820: "$pic_is_exist", 0xDFD5599E: "$invalidate_rect", 0xFD128A61: "$grp_sepia", 0x61BAE53C: "$grp_mulboxfill", 0x30636D6E: "$grp_extcopy", 0xC2C3C4F4: "$sprite_create_file", 0xF9705332: "$page_set_antidata", 0x5548EF5E: "$sprite_priority_high_single", 0x539B07BC: "$pic_len_x", 0xCE94E6CA: "$pic_len_y", 0xFDDF6C40: "$grp_extboxfill", 0x546F69C3: "$sound2_stop", 0x9EF1DDC3: "$set_fast_mode", 0xDFDBA8E4: "$sprite_animate_add"}

# __SYS__NumParams = crypt.hash32(b"__SYS__NumParams@")
# special variable that's always pushed to the stack when calling a user-function
SPECIAL_VARIABLES = {0xA704BDBD: "__SYS__NumParams@"}

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
    def format_string(cls, string:str, *, color:bool=False) -> str:
        import re
        colors:dict = Colors if color else DummyColors
        # unescape single quotes and escape double-quotes
        string = repr(string)[1:-1].replace('\\\'', '\'').replace('\"', '\\\"')
        if not color:
            return string
        # brighten escapes
        return re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[\\\\'\\"abfnrtv])''', r'{BRIGHT}\0{DIM}'.format(**colors), string)

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

    def print_instruction(self, *, color:bool=False, **kwargs) -> NoReturn:
        print(self.format_instruction(color=color), **kwargs)
    def format_instruction(self, *, color:bool=False) -> str:
        colors:dict = Colors if color else DummyColors
        sb:str = ''

        if self.opcode.mnemonic == "line":  # 0x83a
            sb += '{BRIGHT}{BLACK}{0.offset:06x}:{RESET_ALL} {BRIGHT}{BLACK}{0.opcode.mnemonic:<13}{RESET_ALL}'.format(self, **colors)
        else:
            sb += '{BRIGHT}{BLACK}{0.offset:06x}:{RESET_ALL} {BRIGHT}{WHITE}{0.opcode.mnemonic:<13}{RESET_ALL}'.format(self, **colors)

        ops_offset = len(sb)  # for even ~fancier formatting~
        # true if the integer literal field matches a known name hash
        # is_literal_hash:bool = False
        # literal_hash_type:str = None  # 'syscall', 'call', 'var'
        # # at the moment, only function hashes have been observed being pushed with ldc.i
        # #  set this constant to False to search through ALL hashes
        # LITERAL_USERCALLS_ONLY:bool = True
        known_hash_name, known_hash_is_syscall = self.check_known_hash()

        for operand in self.opcode.encoding:
            if operand == '0':
                # 4 byte address placeholder
                continue  # don't want the extra space in the operands

            sb += ' '
            if operand == 't':
                # type list
                sb += '[{!s}]'.format(', '.join('{BRIGHT}{CYAN}{!s}{RESET_ALL}'.format(t.name, **colors) for t in self.type_list))
            elif operand == 's':
                # string data
                sb += '{DIM}{GREEN}"{!s}"{RESET_ALL}'.format(self.format_string(self.string, color=color), **colors)
            elif operand == 'f':
                # flags
                flags = self.flags
                keywords:list = []
                keywords.append(flags.scope.name.lower())
                keywords.append(flags.type.name.lower())
                invert:MjoInvertMode = flags.invert
                if invert:
                    keywords.append('invert_{}'.format(invert.name.lower()))
                modifier = flags.modifier
                if modifier:
                    keywords.append('modifier_{}'.format(modifier.name.lower()))
                dimension = flags.dimension
                if dimension:
                    keywords.append('dim{:d}'.format(dimension))

                sb += '{BRIGHT}{CYAN}{}{RESET_ALL}'.format(' '.join(keywords), **colors)
            elif operand == 'h':
                # hash name
                if self.is_syscall:
                    sb += '{BRIGHT}{YELLOW}'.format(**colors)
                elif self.is_call:
                    sb += '{BRIGHT}{BLUE}'.format(**colors)
                else: #elif self.is_load or self.is_store:
                    sb += '{BRIGHT}{RED}'.format(**colors)
                sb += '${:08x}{RESET_ALL}'.format(self.hash, **colors)
            elif operand == 'o':
                # variable offset
                sb += '{:d}'.format(self.var_offset)
            # elif operand == '0':
            #     # 4 byte address placeholder
            #     pass
            elif operand == 'i':
                # integer constant
                # integer literals will sometimes use hashes for usercall function pointers
                if known_hash_name is not None:
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
                    sb += '{BRIGHT}{MAGENTA}@~{:04x}{RESET_ALL}'.format(self.jump_offset, **colors)
            elif operand == 'l':
                # line number
                sb += '{BRIGHT}{BLACK}#{:d}{RESET_ALL}'.format(self.line_number, **colors)
            elif operand == 'c':
                # switch case table
                if self.switch_targets: # is not None:
                    sb += ', '.join('{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(t.name, **colors) for t in self.switch_targets) # pylint: disable=not-an-iterable
                else:
                    sb += ', '.join('{BRIGHT}{MAGENTA}@~{:04x}{RESET_ALL}'.format(o, **colors) for o in self.switch_cases)
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
        
        if known_hash_name is None:
            pass # no hash name comments
        elif self.is_syscall: # 0x834, 0x835
            sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["YELLOW"]) + len(colors["RESET_ALL"]))
            # sb += '{BRIGHT}{BLACK}[{DIM}{YELLOW}{}{BRIGHT}{BLACK}]{RESET_ALL}'.format(known_hash_name, **colors)
            sb += '{BRIGHT}{BLACK}; {DIM}{YELLOW}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif self.is_call: # 0x80f, 0x810
            sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["BLUE"]) + len(colors["RESET_ALL"]))
            # sb += '{BRIGHT}{BLACK}[{DIM}{BLUE}{}{BRIGHT}{BLACK}]{RESET_ALL}'.format(known_hash_name, **colors)
            sb += '{BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif self.is_load or self.is_store:
            sb += '  {BRIGHT}{BLACK}; {DIM}{RED}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif self.opcode.mnemonic == "ldc.i": # 0x800
            sb = sb.ljust(ops_offset + 16)
            # check for loading function hashes (which are often passed to )
            hash_color = colors["RED"]
            if known_hash_name[0] == '$':
                if known_hash_is_syscall:
                    hash_color = colors["YELLOW"]
                else:
                    hash_color = colors["BLUE"]
            sb += '{BRIGHT}{BLACK}; {DIM}{}{}{RESET_ALL}'.format(hash_color, known_hash_name, **colors)
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
    def __init__(self, signature:bytes, main_offset:int, line_count:int, functions:List[FunctionEntry], instructions:List[Instruction]):
        self.signature:bytes = signature
        self.main_offset:int = main_offset
        self.line_count:int = line_count
        self.functions:List[FunctionEntry] = functions
        self.instructions:List[Instruction] = instructions

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

        bytecode_size:int = reader.unpackone('<I')
        bytecode:bytes = reader.read(bytecode_size)
        if is_encrypted:
            bytecode = crypt.crypt32(bytecode)  # decrypt bytecode
        ms = StructIO(io.BytesIO(bytecode))
        instructions:List[Instruction] = cls.disassemble_bytecode(ms)

        return MjoScript(signature, main_offset, line_count, functions, instructions)

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

    def print_basic_block(self, *, color:bool=False, **kwargs) -> NoReturn:
        print(self.format_basic_block(color=color), **kwargs)
    def format_basic_block(self, *, color:bool=False) -> str:
        colors:dict = Colors if color else DummyColors
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

    def print_function(self, *, color:bool=False, **kwargs) -> NoReturn:
        print(self.format_function(color=color), **kwargs)
    def format_function(self, *, color:bool=False) -> str:
        colors:dict = Colors if color else DummyColors
        annotation:str = ' {DIM}{YELLOW}entrypoint{RESET_ALL}'.format(**colors) if self.start_offset == self.script.main_offset else ''
        return '{BRIGHT}{BLUE}func ${.name_hash:08x}({!s}){RESET_ALL}{}'.format(self, ', '.join(t.name for t in self.parameter_types), annotation, **colors) # pylint: disable=not-an-iterable


del abstractproperty, namedtuple, Iterator, NoReturn, Optional, Tuple  # cleanup declaration-only imports
