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

import io, math, os, re  # math used for isnan()
from abc import abstractproperty
from collections import namedtuple
from struct import calcsize, pack, unpack
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union  # for hinting in declarations

from ..util.typecast import signed_i, unsigned_I
from ..util.color import DummyColors, Colors
# from ..util import StructIO, DummyColors, Colors, signed_i, unsigned_I
from .flags import MjoType, MjoScope, MjoInvert, MjoModifier, MjoDimension, MjoFlags
from .opcodes import Opcode
from .mjoscript import MjoScript, FunctionIndexEntry
from .instruction import BasicBlock, Instruction
from .analysis.control.block import BasicBlock, Function
from .analysis.control.flowpass import ControlFlowGraph
from ..identifier import HashValue, HashName, IdentifierKind
from ..database import hashes as known_hashes
from .. import crypt

## FORMAT OPTIONS ##

#NOTE: This is a temporary class until the real formatter module is complete

class ILFormat:
    # very lazy storage for default options
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
        self.group_directive:str = None  # default group to disassemble with (removes @GROUPNAME when found)
        self.resfile_directive:str = None  # output all `text` opcode lines to a csv file with the given name
        self._resfile_path:str = None  # defined by __main__ for quick access
        self.explicit_inline_resource:bool = False  # %{hashname}  [requires: resfile_directive="anything"]
        self.implicit_local_groups:bool = False  # always exclude empty group name from known local names
        self.annotate_hex:bool     = True  # enables/disables ; $XXXXXXXX annotations when using inline hashes

        # aliasing and operands:
        self.modifier_aliases:bool = False  # (variable flags) inc.x, dec.x, x.inc, x.dec
        self.invert_aliases:bool   = False  # (variable flags) -, -, -, -  (NOTE: there are no aliases, added for conformity)
        self.scope_aliases:bool    = False  # (variable flags) persist, save, -, -
        self.vartype_aliases:bool  = False  # (variable flags) i, r, s, iarr, rarr, sarr
        self.typelist_aliases:bool = False  # (typelist operand) i, r, s, iarr, rarr, sarr
        self.functype_aliases:bool = False  # (function declaration) i, r, s, iarr, rarr, sarr
        self.explicit_dim0:bool    = False  # (variable flags) always include dim0 flag  #WHY WOULD YOU WANT THIS?
        self.explicit_varoffset:bool = False  # always include -1 for non-local var offsets
        
        # space-savers:
        self.address_len:int       = 5     # len of XXXXX: addresses before every opcode
        self.address_labels:bool   = True  # include address labels at all before every opcode
        self.opcode_padding:int    = 13    # number of EXTRA spaces to pad opcodes with (from the start of the opcode)
                                           # one mandatory space is always added AFTER this for operands

    def set_address_len(self, bytecode_size:int) -> None:
        self.address_len = max(2, len(f'{bytecode_size:x}'))

    def address_fmt(self, offset) -> str:
        return '{{:0{0}x}}'.format(max(2, int(self.address_len))).format(offset)

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


# class Instruction:
#     """Bytecode instruction of opcode, offset, operands, and optionally analysis data
#     """
#     def __init__(self, opcode:Opcode, offset:int):
#         # general #
#         self.opcode:Opcode = opcode
#         self.offset:int = offset  # bytecode offset
#         self.size:int = 0  # instruction size in bytecode

#         # operands #
#         self.flags:MjoFlags = MjoFlags(0)  # flags for ld* st* variable opcodes
#         self.hash:int = 0  # identifier hash for ld* st* variable opcodes, and call* syscall* function opcodes
#         self.var_offset:int = 0  # stack offset for ld* st* local variables (-1 used for non-local)
#         self.type_list:List[MjoType] = None  # type list operand for argcheck opcode
#         self.string:str = None  # string operand for ldstr, text, ctrl opcodes
#         self.integer:int = 0  # int operand for ldc.i opcode (SHOULD ALWAYS BE STORED AS SIGNED)
#         self.real:float = 0.0  # float operand for ldc.r opcode
#         self.arg_num:int = 0  # argument count operand for call* syscall* function opcodes
#         self.line_num:int = 0  # line number operand for line opcode
#         self.jump_offset:int = 0  # jump offset operand for b* opcodes
#         self.switch_offsets:List[int] = None  # switch jump offset operands for switch opcode

#         # analysis #
#         self.jump_target:'BasicBlock' = None  # analyzed jump target location
#         self.switch_targets:List['BasicBlock'] = None  # analyzed switch jump target locations

#     @property
#     def is_jump(self) -> bool: return self.opcode.is_jump
#     @property
#     def is_switch(self) -> bool: return self.opcode.mnemonic == "switch"  # 0x850
#     @property
#     def is_return(self) -> bool: return self.opcode.mnemonic == "ret"  # 0x82b
#     @property
#     def is_argcheck(self) -> bool: return self.opcode.mnemonic == "argcheck"  # 0x836
#     @property
#     def is_syscall(self) -> bool: return self.opcode.mnemonic in ("syscall", "syscallp")  # 0x834, 0x835
#     @property
#     def is_call(self) -> bool: return self.opcode.mnemonic in ("call", "callp")  # 0x80f, 0x810
#     # ldc.i 0x800, ldstr 0x801, ldc.r 0x803
#     @property
#     def is_literal(self) -> bool: return self.opcode.mnemonic in ("ldc.i", "ldc.r", "ldstr")
#     # ld 0x802, ldelem 0x837
#     @property
#     def is_load(self) -> bool: return self.opcode.mnemonic in ("ld", "ldelem")
#     # st.* 0x1b0~0x200, stp.* 0x210~0x260, stelem.* 0x270~0x2c0, stelemp.* 0x2d0~0x320
#     @property
#     def is_store(self) -> bool: return self.opcode.mnemonic.startswith("st")


def format_string(string:str, *, options:ILFormat=ILFormat.DEFAULT) -> str:
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

def check_hash_group(name:str, syscall:bool=False, *, options:ILFormat=ILFormat.DEFAULT) -> Optional[str]: # name
    # attempt implicit groups/group directive:
    #  has found name   and not a syscall hash
    if name is not None and not syscall and (options.group_directive is not None or options.implicit_local_groups):
        # handle group stripping
        idx = name.find('@', 1)  # first char can't be group
        if idx != -1 and name.find('@', idx + 1) == -1:
            basename, group = name[:idx], name[idx+1:]
            if options.implicit_local_groups and basename[0] == '_' and group == '':
                # local var
                name = basename
            elif group == options.group_directive and basename[0] != '_':
                # same group as group directive, not allowed for locals
                name = basename
        else:
            # we can't handle this: group not found, or more than one '@'
            #  (more than one '@' does not make a valid group!!!)
            pass
    return name

def check_known_hash(self:Instruction, *, options:ILFormat=ILFormat.DEFAULT) -> Optional[Tuple[str, bool]]: # (name, is_syscall)
    name, syscall = (None, False)  # not an opcode that relates to hashes
    if self.is_syscall:
        name = known_hashes.SYSCALLS.get(self.hash, None)
        syscall = True
    elif self.is_call:
        name = known_hashes.FUNCTIONS.get(self.hash, None)
    elif self.is_load or self.is_store:
        # TODO: this could be optimized to use the type flags
        #       and search in the scope-independent dicts
        name = known_hashes.VARIABLES.get(self.hash, None)
    elif self.opcode.mnemonic == "ldc.i": # 0x800
        name = known_hashes.FUNCTIONS.get(unsigned_I(self.integer), None)
        # TODO: Uncomment if it's observed that int literals
        #       will use hashes for types other than usercalls
        if name is None:
            name = known_hashes.VARIABLES.get(unsigned_I(self.integer), None)
        if name is None:
            name = known_hashes.SYSCALLS.get(unsigned_I(self.integer), None)
            syscall = True

    return (check_hash_group(name, syscall, options=options), syscall)

def print_instruction(self:Instruction, *, options:ILFormat=ILFormat.DEFAULT, resource_key:str=None, **kwargs) -> None:
    print(format_instruction(self, options=options, resource_key=resource_key), **kwargs)

def format_instruction(self:Instruction, *, options:ILFormat=ILFormat.DEFAULT, resource_key:str=None) -> str:
    colors:dict = options.colors
    sb:str = ''

    if options.address_labels:
        address = options.address_fmt(self.offset)
        sb += '{BRIGHT}{BLACK}{0}:{RESET_ALL} '.format(address, **colors)
    if self.opcode.mnemonic == "line":  # 0x83a
        sb += '{BRIGHT}{BLACK}{0.opcode.mnemonic}{RESET_ALL}'.format(self, **colors)
    else:
        sb += '{BRIGHT}{WHITE}{0.opcode.mnemonic}{RESET_ALL}'.format(self, **colors)

    if not self.opcode.encoding:
        return sb  # no operands, nothing to add

    # padding after opcode (min 1 space, which is not included in padding option count)
    sb += ' ' + (' ' * max(0, options.opcode_padding - len(self.opcode.mnemonic)))

    known_hash_name, known_hash_is_syscall = None, False
    if options.known_hashes:
        known_hash_name, known_hash_is_syscall = check_known_hash(self, options=options)

    operands = []
    for operand in self.opcode.encoding:
        op = None  # if assigned, append to operands at bottom of loop

        if operand == 't':
            # type list
            types = ', '.join('{BRIGHT}{CYAN}{}{RESET_ALL}'.format(t.getname(options.typelist_aliases), **colors) for t in self.type_list)
            op = '[{}]'.format(types)
        elif operand == 's':
            # string data
            if resource_key is None:
                op = format_string(self.string, options=options)
            elif options.explicit_inline_resource:
                op = '{BRIGHT}{CYAN}%{{{RESET_ALL}{}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(resource_key, **colors)
            else:
                op = '{BRIGHT}{CYAN}%{RESET_ALL}{}'.format(resource_key, **colors)
        elif operand == 'f':
            # flags
            flags = self.flags
            keywords:list = []
            keywords.append(flags.scope.getname(options.scope_aliases))
            keywords.append(flags.type.getname(options.vartype_aliases))
            if flags.dimension or options.explicit_dim0:  #NOTE: dim0 is legal, just not required or recommended
                keywords.append(flags.dimension.getname(options.explicit_dim0))
            if flags.invert:
                keywords.append(flags.invert.getname(options.invert_aliases))
            if flags.modifier:
                keywords.append(flags.modifier.getname(options.modifier_aliases))

            # push joined flag keywords as one operand, since technically it is only one
            op = '{BRIGHT}{CYAN}{}{RESET_ALL}'.format(' '.join(keywords), **colors)
        elif operand == 'h':
            # hash value
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
                    op = '{BRIGHT}{CYAN}${{{RESET_ALL}{}{}{RESET_ALL}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                else:
                    op = '{BRIGHT}{CYAN}${RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
            else:
                op = '${:08x}{RESET_ALL}'.format(self.hash, **colors)
        elif operand == 'o':
            # variable offset
            #NEW: exclude -1 offsets for non-local variables, because that operand
            #     isn't used. still output erroneous var offsets (aka anything other than -1)
            if options.explicit_varoffset or self.var_offset != -1 or self.flags.scope is MjoScope.LOCAL:
                op = '{:d}'.format(self.var_offset)
        elif operand == '0':
            # 4 byte address placeholder
            pass
        elif operand == 'i':
            # integer constant
            # integer literals will sometimes use hashes for usercall function pointers
            # this entire if statement tree is terrifying...
            if known_hash_name is not None:
                if known_hash_is_syscall:
                    hash_color = '{BRIGHT}{YELLOW}'.format(**colors)
                elif known_hash_name[0] == '$':
                    hash_color = '{BRIGHT}{BLUE}'.format(**colors)
                else: #elif self.is_load or self.is_store:
                    hash_color = '{BRIGHT}{RED}'.format(**colors)

                if options.inline_hash and options.int_inline_hash and (options.syscall_inline_hash or not known_hash_is_syscall):
                    known_hash_name2 = known_hash_name
                    if known_hash_is_syscall:
                        known_hash_name2 = known_hash_name.lstrip('$') # requirement for syscall hash lookup syntax
                    if options.needs_explicit_hash(known_hash_name2):
                        op = '{BRIGHT}{CYAN}${{{RESET_ALL}{}{}{RESET_ALL}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                    else:
                        op = '{BRIGHT}{CYAN}${RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                else:
                    # print as hex for simplicity (this can also be printed with $XXXXXXXX notation)
                    op = '0x{:08x}'.format(unsigned_I(self.integer))
            else:
                op = '{:d}'.format(signed_i(self.integer))
        elif operand == 'r':
            # float constant
            if self.real == float('inf'):
                op = '+Inf'
            elif self.real == float('-inf'):
                op = '-Inf'
            elif math.isnan(self.real):
                op = 'NaN'
            else:
                op = '{:g}'.format(self.real)  # fixed or exponential
                try:
                    int(op, 10)  # test if no decimal or exponent
                    op += '.0'  # append '.0' for all floats that parse to integers
                except:
                    pass  # fine just the way it is
        elif operand == 'a':
            # argument count
            op = '({:d})'.format(self.arg_num)
        elif operand == 'j':
            # jump offset
            if self.jump_target is not None:
                op = '{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(self.jump_target.name, **colors)
            else:
                op = '{BRIGHT}{MAGENTA}@~{:+04x}{RESET_ALL}'.format(self.jump_offset, **colors)
        elif operand == 'l':
            # line number
            op = '{BRIGHT}{BLACK}#{:d}{RESET_ALL}'.format(self.line_num, **colors)
        elif operand == 'c':
            # switch case table
            if self.switch_targets: # is not None:
                op = ', '.join('{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(t.name, **colors) for t in self.switch_targets) # pylint: disable=not-an-iterable
            else:
                op = ', '.join(', '.join('{BRIGHT}{MAGENTA}@~{:+04x}{RESET_ALL}'.format(o, **colors) for o in self.switch_offsets))
        else:
            raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
        
        # append operand (if defined)
        if op is not None:
            operands.append(op)
    
    if operands: # append space-separated operands
        sb += ' '.join(operands)

    if known_hash_name is None or not options.annotations:
        pass  # no hash name comments
    elif self.is_syscall: # 0x834, 0x835
        if not options.inline_hash or not options.syscall_inline_hash:
            # sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["YELLOW"]) + len(colors["RESET_ALL"]))
            sb += '  {BRIGHT}{BLACK}; {DIM}{YELLOW}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif options.annotate_hex:
            sb += '  {BRIGHT}{BLACK}; {DIM}{YELLOW}${:08x}{RESET_ALL}'.format(self.hash, **colors)
    elif self.is_call: # 0x80f, 0x810
        if not options.inline_hash:
            # sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["BLUE"]) + len(colors["RESET_ALL"]))
            sb += '  {BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif options.annotate_hex:
            sb += '  {BRIGHT}{BLACK}; {DIM}{BLUE}${:08x}{RESET_ALL}'.format(self.hash, **colors)
    elif self.is_load or self.is_store:
        if not options.inline_hash:
            sb += '  {BRIGHT}{BLACK}; {DIM}{RED}{}{RESET_ALL}'.format(known_hash_name, **colors)
        elif options.annotate_hex:
            sb += '  {BRIGHT}{BLACK}; {DIM}{RED}${:08x}{RESET_ALL}'.format(self.hash, **colors)
    elif self.opcode.mnemonic == "ldc.i": # 0x800
        # check for loading function hashes (which are often passed to )
        if known_hash_is_syscall:
            hash_color = '{DIM}{YELLOW}'.format(**colors)
        elif known_hash_name[0] == '$':
            hash_color = '{DIM}{BLUE}'.format(**colors)
        else: #elif self.is_load or self.is_store:
            hash_color = '{DIM}{RED}'.format(**colors)

        ## testing reversal of the conditional branching behemoth below:
        # def test(a,b,c,d): return (not a or not b or (c and not d)) == (a and b and (not c or d))
        # [tuple(o) for o in combos if test(*o)]
        if not options.inline_hash or not options.int_inline_hash or (known_hash_is_syscall and not options.syscall_inline_hash):
            #sb = sb.ljust(ops_offset + 16)
            sb += '  {BRIGHT}{BLACK}; {RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name, **colors)
        elif options.annotate_hex:
            sb += '  {BRIGHT}{BLACK}; {RESET_ALL}{}${:08x}{RESET_ALL}'.format(hash_color, unsigned_I(self.integer), **colors)
    return sb


def get_resource_key(self:MjoScript, instruction:Instruction, *, options:ILFormat=ILFormat.DEFAULT) -> str:
    if options.resfile_directive and instruction.opcode.mnemonic == "text": # 0x840
        # count = 0
        number = 0
        for instr in self.instructions:
            if instr.opcode.mnemonic == "text": # 0x840
                # count += 1
                number += 1
                if instr.offset == instruction.offset:
                    # number = count
                    # break
                    return f'L{number}' # number will be 1-indexed
        # return f'L{number}'
    return None

#########################################

def print_readmark(self:MjoScript, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> None:
    print(format_readmark(self, options=options), **kwargs)
def format_readmark(self:MjoScript, *, options:ILFormat=ILFormat.DEFAULT) -> str:
    #FIXME: temp solution to print all directives in one go
    colors:dict = options.colors
    setting = ('{GREEN}enable' if self.is_readmark else '{RED}disable').format(**colors)
    s = '{DIM}{YELLOW}readmark{RESET_ALL} {BRIGHT}{}{RESET_ALL}'.format(setting, **colors)
    s += '\n'
    if options.group_directive is None:
        s += '{DIM}{YELLOW}group{RESET_ALL} {BRIGHT}{RED}none{RESET_ALL}'.format(**colors)
    else:
        s += '{DIM}{YELLOW}group{RESET_ALL} {}'.format(format_string(options.group_directive, options=options), **colors)
    if options.resfile_directive is not None:
        s += '\n'
        s += '{DIM}{YELLOW}resfile{RESET_ALL} {}'.format(format_string(options.resfile_directive, options=options), **colors)
    return s

#########################################

def print_basic_block(self:BasicBlock, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> None:
    print(format_basic_block(self, options=options), **kwargs)
def format_basic_block(self:BasicBlock, *, options:ILFormat=ILFormat.DEFAULT) -> str:
    colors:dict = options.colors
    return '{BRIGHT}{MAGENTA}{.name}:{RESET_ALL}'.format(self, **colors)

#########################################

def print_function(self:Function, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> None:
    print(format_function(self, options=options), **kwargs)
def format_function(self:Function, *, options:ILFormat=ILFormat.DEFAULT) -> str:
    colors:dict = options.colors

    # always "func" as, "void" can only be confirmed by all-zero return values
    s = '{BRIGHT}{BLUE}func '.format(**colors)

    known_hash:str = None
    if options.known_hashes:
        known_hash = known_hashes.FUNCTIONS.get(self.hash, None)
    if known_hash is not None:
        #TODO: move check hash function somewhere more fitting
        known_hash = check_hash_group(known_hash, False, options=options)
    if known_hash is not None and options.inline_hash:
        if options.needs_explicit_hash(known_hash):
            s += '{BRIGHT}{CYAN}${{{BRIGHT}{BLUE}{}{BRIGHT}{CYAN}}}{BRIGHT}{BLUE}'.format(known_hash, **colors)
        else:
            s += '{BRIGHT}{CYAN}${BRIGHT}{BLUE}{}'.format(known_hash, **colors)
    else:
        s += '${.hash:08x}'.format(self)

    args = ', '.join('{BRIGHT}{CYAN}{}{RESET_ALL}'.format(t.getname(options.functype_aliases), **colors) for t in self.parameter_types) # pylint: disable=not-an-iterable
    s += '{RESET_ALL}({})'.format(args, **colors)

    # "entrypoint" states which function to declare as "main" to the IL assembler
    if self.is_entrypoint:
        s += ' {DIM}{YELLOW}entrypoint{RESET_ALL}'.format(**colors)

    # optional brace formatting
    if options.braces:
        s += ' {'

    if known_hash is not None and options.annotations:
        if not options.inline_hash:
            s += '  {BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash, **colors)
        elif options.annotate_hex:
            s += '  {BRIGHT}{BLACK}; {DIM}{BLUE}${.hash:08x}{RESET_ALL}'.format(self, **colors)
    return s

def print_function_close(self:Function, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> None:
    print(format_function_close(self, options=options), **kwargs)
def format_function_close(self:Function, *, options:ILFormat=ILFormat.DEFAULT) -> str:
    return '}' if options.braces else ''

#########################################

## PRINT SCRIPT ##

def read_script(filename:str) -> MjoScript:
    """Read and return a MjoScript from file
    """
    with open(filename, 'rb') as f:
        return MjoScript.read(f, lookup=True)

def analyze_script(script:MjoScript) -> ControlFlowGraph:
    """Return the analysis of a script's control flow, blocks, functions, etc.

    argument can also be a filename
    """
    if isinstance(script, str):  # is argument filename?
        script = read_script(script)
    return ControlFlowGraph.build_from_script(script)

def print_script(filename:str, script:MjoScript, *, options:ILFormat=ILFormat.DEFAULT):
    """Print analyzed script IL instructions and blocks to console (PRINTS A LOT OF LINE)
    """
    cfg:ControlFlowGraph = analyze_script(script)
    options.set_address_len(script.bytecode_size)
    colors = options.colors

    # include extra indentation formatting for an easier time reading
    print('{BRIGHT}{WHITE}/// {}{RESET_ALL}'.format(os.path.basename(filename), **colors))
    script.print_readmark(options=options)
    # print()

    for function in cfg.functions:
        print()
        function.print_function(options=options)
        for i,basic_block in enumerate(function.basic_blocks):
            print(' ', end='')
            basic_block.print_basic_block(options=options)
            for instruction in basic_block.instructions:
                reskey = script.get_resource_key(instruction, options=options)
                print('  ', end='')
                instruction.print_instruction(options=options, resource_key=reskey)
            if i + 1 < len(function.basic_blocks):
                print(' ')
        function.print_function_close(options=options)
        # print()


## WRITE SCRIPT ##

def disassemble_script(filename:str, script:MjoScript, outfilename:str, *, options:ILFormat=ILFormat.DEFAULT):
    """Write analyzed script IL instructions and blocks to .mjil file
    """
    options.color = False
    options.set_address_len(script.bytecode_size)
    import csv
    cfg:ControlFlowGraph = analyze_script(script)

    resfile = reswriter = None
    from ..database.hashes import brute_force
    # print('Loading brute-force locals...', end='', flush=True)
    brute_force.load_locals_brute()
    # print('done!')
    groupname:str = known_hashes.GROUPS.get(script.main_function.hash)

    with open(outfilename, 'wt+', encoding='utf-8') as writer:
      try:
        if options.resfile_directive is not None:
            #respath = os.path.join(os.path.dirname(filename), options.resfile_directive)
            res_f = open(options._resfile_path or options.resfile_directive, 'wt+', encoding='utf-8')
            # sigh, no way to force quotes for one line
            # lineterminator='\n' is required to stop double-line termination caused by default behavior of "\r\n" on Windows
            reswriter = csv.writer(res_f, quoting=csv.QUOTE_MINIMAL, delimiter=',', quotechar='"', lineterminator='\n')
            reswriter.writerow(['Key','Value'])
        # include extra indentation formatting for language grammar VSCode extension
        writer.write('/// {}\n'.format(os.path.basename(filename)))
        writer.write(format_readmark(script, options=options) + '\n')
        # writer.write('\n')

        from mj.script.flags import MjoType
        from mj.identifier import HashName, HashValue
        from mj.crypt import hash32
        from mj.name import splitgroup, splitpostfix, splitprefix, splitsymbols, joingroup, joinsymbols
        import mj.name
        function_hashes:Dict[int, Function] = {}
        for function in cfg.functions:
            function_hashes[function.hash] = function
        class AnyVariable:
            __slots__ = ('scope', 'var_offset', 'hash', 'type', 'name')
            def __init__(self, scope:MjoScope, var_offset:int, hash:HashValue=None, type:MjoType=None, name:str=None):
                self.scope:MjoScope = MjoScope(scope)
                self.var_offset:int = var_offset
                self.hash:HashValue = HashValue(hash) if hash is not None else None
                self.type:MjoType = MjoType(type) if type is not None else None #MjoType.UNKNOWN
                self.name:str = name
            # @property
            # def var_offset(self) -> int: return None
            # @property
            # def scope(self) -> MjoScope: return None #MjoScope.UNKNOWN
            @property
            def namedisasm(self) -> str:
                return f'${self.name}' if self.name is not None else f'${self.hash:08x}'
            def __repr__(self) -> str:
                namerepr = f'"{self.name}"' if self.name is not None else (f'${self.hash:08x}' if self.hash is not None else '$????????')
                locrepr = f' {self.var_offset}' if self.scope is MjoScope.LOCAL else ''
                # return f'<{self.__class__.__name__}: {self.scope.getname()} {self.type.getname()} {namerepr}{locrepr} >'
                typestr = self.type.getname() if self.type is not None else '<?type>'
                scopestr = self.scope.getname() if self.scope is not None else '<?scope>'
                return f'<Variable: {scopestr} {typestr} {namerepr}{locrepr}>'
                # return f'<Variable: {self.scope.getname()} {self.type.getname()} {namerepr}{locrepr}>'
            def __str__(self) -> str: return self.__repr__()
        class GlobalVariable(AnyVariable):
            # __slots__ = AnyVariable.__slots__ + ('scope',)
            def __init__(self, scope:MjoScope, hash:HashValue=None, type:MjoType=None, name:str=None):
                super().__init__(scope, -1, hash, type, name)
            #     self.scope:MjoScope = MjoScope(scope)
            # @property
            # def var_offset(self) -> int: return -1
        class LocalVariable(AnyVariable):
            # __slots__ = AnyVariable.__slots__ + ('var_offset',)
            def __init__(self, var_offset:int, hash:HashValue=None, type:MjoType=None, name:str=None):
                super().__init__(MjoScope.LOCAL, var_offset, hash, type, name)
            #     self.var_offset:int = var_offset
            # @property
            # def scope(self) -> MjoScope: return MjoScope.LOCAL

        # class GlobalVariable:
        #     __slots__ = ('scope', 'hash', 'name', 'type')
        #     def __init__(self, scope:MjoScope, hash:HashValue=None, name:str=None, type:MjoType=None):
        #         self.scope:MjoScope = MjoScope(scope)
        #         self.hash:HashValue = HashValue(hash) if hash is not None else None
        #         self.name:str = name
        #         self.type:MjoType = MjoType(type) if type is not None else MjoType.UNKNOWN
        #     @property
        #     def var_offset(self) -> int: return -1
        # class LocalVariable:
        #     __slots__ = ('var_offset', 'hash', 'name', 'type')
        #     def __init__(self, var_offset:int, hash:HashValue=None, name:str=None, type:MjoType=None):
        #         self.var_offset:int = var_offset
        #         self.hash:HashValue = HashValue(hash) if hash is not None else None
        #         self.name:str = name
        #         self.type:MjoType = MjoType(type) if type is not None else MjoType.UNKNOWN
        #     @property
        #     def scope(self) -> MjoScope: return MjoScope.LOCAL

        found_names:Dict[int,str] = {}
        notfound_names:Set[str] = set()

        from ..util.color import Fore as F, Style as S

        for function in cfg.functions:
            writer.write('\n')
            variable_store:Dict[int, AnyVariable] = {}
            offset_vars:Dict[int, LocalVariable] = {} # {-1: LocalVariable(-1, HashValue(hash32('__SYS__NumParams@')), MjoType.INT, '__SYS__NumParams@')}
            writes_vars:Dict[int,AnyVariable] = {}
            reads_vars:Dict[int,AnyVariable] = {}
            accesses_vars:Dict[int,AnyVariable] = {}
            modifies_vars:Dict[int,AnyVariable] = {}
            # writes_vars:Set[AnyVariable] = set()
            # reads_vars:Set[AnyVariable] = set()
            # accesses_vars:Set[AnyVariable] = set()
            # modifies_vars:Set[AnyVariable] = set()
            # def offset_unk(var_offset:int) -> LocalVariable:
            #     return LocalVariable(var_offset, HashValue(0))
            def offset_get(var_offset:int) -> LocalVariable:
                localvar = offset_vars.get(var_offset)
                if localvar is None and var_offset == -1:
                    return local_update(var_offset, hash32('__SYS__NumParams@'), MjoType.INT, '__SYS__NumParams@')
                return local_update(var_offset)
                # return offset_unk(var_offset) if localvar is None else localvar
            def local_vars() -> List[LocalVariable]:
                if not offset_vars: return []
                maxoff = max(offset_vars.keys())
                # maxoff = max(v.var_offset for v in offset_vars.values())
                return [offset_get(i) for i in range(0, maxoff+1)]
            def param_vars() -> List[LocalVariable]:
                if not offset_vars: return []
                minoff = min(offset_vars.keys())
                # minoff = min(v.var_offset for v in offset_vars.values())
                # hasnumparam = bool([v.var_offset == -1 for v in offset_vars.keys()])
                return [offset_get(i) for i in range(-1 if -1 in offset_vars else -2, minoff-1, -1)]
            def global_update(scope:MjoScope, hash:HashValue, type:MjoType=None, name:str=None) -> GlobalVariable:
                if type is MjoType.UNKNOWN: type = None
                globalvar = variable_store.get(hash)
                if globalvar is None:
                    globalvar = GlobalVariable(scope, hash, type, name)

                if hash is not None:
                    hash = HashValue(hash)
                    if   globalvar.hash is None: globalvar.hash = hash
                    elif globalvar.hash != hash: print(f'mismatch hash {globalvar!r}')
                if type is not None:
                    type = MjoType(type)
                    if   globalvar.type is None: globalvar.type = type
                    elif globalvar.type != type: print(f'mismatch type {globalvar!r}')
                if name is not None:
                    if   globalvar.name is None: globalvar.name = name
                    elif globalvar.name != type: print(f'mismatch name {globalvar!r}')
                    
                if globalvar.name is None and globalvar.hash not in notfound_names:
                    globalvar.name = found_names.get(globalvar.hash)
                    if globalvar.scope is MjoScope.SAVEFILE:
                        globalvar.name = known_hashes.SAVEFILE_VARS.get(globalvar.hash)
                    elif scope is MjoScope.PERSISTENT:
                        globalvar.name = known_hashes.PERSISTENT_VARS.get(globalvar.hash)
                    elif scope is MjoScope.THREAD:
                        globalvar.name = known_hashes.THREAD_VARS.get(globalvar.hash)
                    if globalvar.name is None:
                        notfound_names.add(globalvar.hash)
                    if globalvar.name is None and globalvar.type is not None:
                        results = brute_force.find_custom_brutes(globalvar.hash, globalvar.scope.prefix, globalvar.type.postfix)
                        if not results:
                            notfound_names.add(globalvar.hash)
                        else:
                            groupresults = [r for r in results if mj.name.groupname(r)==groupname]
                            if len(results) > 1:
                                print(f'{S.DIM}{F.CYAN}Collisions for {globalvar.scope.getname()} var ${globalvar.hash:08x}: {results}{S.RESET_ALL}')
                                notupper = [s for s in (groupresults or results) if not s[1].isupper()]
                                if notupper: results = notupper
                                # if groupresults
                            elif not groupresults:
                                print(f'{S.BRIGHT}{F.CYAN}Brute-forced {globalvar.scope.getname()} var ${globalvar.hash:08x}: {results}{S.RESET_ALL}')
                            if groupresults:
                                print(f'{S.BRIGHT}{F.GREEN}Group matched {globalvar.scope.getname()} var ${globalvar.hash:08x}: {results}{S.RESET_ALL}')
                                # print(f'{S.DIM}{F.RED}Collisions for {globalvar.scope.getname()} var ${globalvar.hash:08x}:  {results}{S.RESET_ALL}')
                            globalvar.name = results[0]
                
                if globalvar.name is not None:
                    found_names.setdefault(globalvar.hash, globalvar.name)

                if globalvar.type is None and globalvar.name is not None:
                    postfix = mj.name.postfixsymbol(globalvar.name)
                    if postfix is not None:
                        globalvar.type = MjoType.frompostfix(postfix)
                
                variable_store[globalvar.hash] = globalvar

            def local_update(var_offset:int, hash:HashValue=None, type:MjoType=None, name:str=None) -> LocalVariable:
                if type is MjoType.UNKNOWN: type = None
                localvar = offset_vars.get(var_offset)
                if localvar is None and hash is not None:
                    localvar = variable_store.get(hash)
                if localvar is None:
                    localvar = LocalVariable(var_offset, hash, type, name)
                    
                if hash is not None:
                    hash = HashValue(hash)
                    if   localvar.hash is None: localvar.hash = hash
                    elif localvar.hash != hash: print(f'mismatch hash {localvar!r}')
                if type is not None:
                    type = MjoType(type)
                    if   localvar.type is None: localvar.type = type
                    elif localvar.type != type: print(f'mismatch type {localvar!r}')
                if name is not None:
                    if   localvar.name is None: localvar.name = name
                    elif localvar.name != type: print(f'mismatch name {localvar!r}')

                # if hash is not None and localvar.hash is None:
                #     localvar.hash = HashValue(hash)
                # if type is not None and localvar.type is None:
                #     localvar.type = MjoType(type)
                # if name is not None and localvar.name is None:
                #     localvar.name = name
                
                if localvar.name is None and localvar.hash is not None and localvar.hash not in notfound_names:
                    localvar.name = found_names.get(localvar.hash)
                    if localvar.name is None:
                        localvar.name = known_hashes.LOCAL_VARS.get(localvar.hash)
                    if localvar.name is None and localvar.type is not None:
                        results = brute_force.find_local_brute(localvar.hash, localvar.type.postfix)
                        if not results:
                            notfound_names.add(localvar.hash)
                        else:
                            if len(results) > 1:
                                print(f'{S.BRIGHT}{F.RED}Collisions for local var ${localvar.hash:08x}:  {results}{S.RESET_ALL}')
                                notupper = [s for s in results if not s[1].isupper()]
                                if notupper: results = notupper
                            else:
                                print(f'{S.BRIGHT}{F.YELLOW}Brute-forced local var ${localvar.hash:08x}: {results}{S.RESET_ALL}')
                            localvar.name = results[0]
                
                if localvar.name is not None:
                    found_names.setdefault(localvar.hash, localvar.name)

                if localvar.type is None and localvar.name is not None:
                    postfix = mj.name.postfixsymbol(localvar.name)
                    if postfix is not None:
                        localvar.type = MjoType.frompostfix(postfix)

                offset_vars[localvar.var_offset] = localvar
                if localvar.hash is not None:
                    variable_store[localvar.hash] = localvar
                return localvar
                # return offset_unk(var_offset) if localvar is None else localvar


            # param_vars = []
            # local_vars:List[Tuple[]] = []
            for i in range(function.first_instruction_index, function.last_instruction_index + 1):
                is_first, is_last = (i==function.first_instruction_index), (i==function.last_instruction_index)
                instr:Instruction = script.instructions[i]
                myvar = None
                if instr.is_argcheck:
                    for j,t in enumerate(instr.type_list):
                        # print(f'sigchk[{-2 - j}] = {t.name}')
                        local_update(-2 - j, type=t)
                elif instr.is_alloca:
                    for j,t in enumerate(instr.type_list):
                        # print(f'alloca[{j}] = {t.name}')
                        local_update(j, type=t)
                elif instr.is_load or instr.is_store:
                    flags = instr.flags
                    hash = instr.hash
                    var_offset = instr.var_offset
                    scope = flags.scope
                    type = flags.type
                    # element = instr.is_element
                    # elementtype = type
                    if instr.is_element:
                        type = type.array
                    if scope is MjoScope.LOCAL:
                        myvar = local_update(var_offset, hash, type)
                        # name = known_hashes.LOCAL_VARS.get(hash)
                    else:
                        myvar = global_update(scope, hash, type)
                    #     if scope is MjoScope.SAVEFILE:
                    #         name = known_hashes.SAVEFILE_VARS.get(hash)
                    #     elif scope is MjoScope.PERSISTENT:
                    #         name = known_hashes.PERSISTENT_VARS.get(hash)
                    #     elif scope is MjoScope.THREAD:
                    #         name = known_hashes.THREAD_VARS.get(hash)
                    # known_hashes

                    # if instr.is_store or flags.modifier is not MjoModifier.NONE:
                    #     if instr.is_element:
                    #         modifies_vars.add(myvar)
                    #     else:
                    #         writes_vars.add(myvar)
                    # if instr.is_load: # pop
                    #     if (is_last or script.instructions[i+1].opcode.value != 0x82f):
                    #         if instr.is_element:
                    #             accesses_vars.add(myvar)
                    #         else:
                    #             reads_vars.add(myvar)
                    #     else:
                    #         if instr.is_element:
                    #             modifies_vars.add(myvar)
                    #         else:
                    #             writes_vars.add(myvar)
                    if instr.is_store or flags.modifier is not MjoModifier.NONE:
                        if instr.is_element:
                            modifies_vars[hash] = myvar
                        else:
                            writes_vars[hash] = myvar
                    if instr.is_load: # pop
                        if (is_last or script.instructions[i+1].opcode.value != 0x82f):
                            if instr.is_element:
                                accesses_vars[hash] = myvar
                            else:
                                reads_vars[hash] = myvar
                        else:
                            if instr.is_element:
                                modifies_vars[hash] = myvar
                            else:
                                writes_vars[hash] = myvar
                # instruction.


            def repr_var(myvar:AnyVariable):
                # modes = []
                mode = rmode = wmode = ''
                if myvar.hash in reads_vars:    rmode += 'R'
                if myvar.hash in accesses_vars: rmode += 'A'
                if myvar.hash in writes_vars:   wmode += 'W'
                if myvar.hash in modifies_vars: wmode += 'M'
                if rmode and wmode: mode = f'{rmode}/{wmode}'
                elif rmode: mode = f'{rmode}o'
                elif wmode: mode = f'{wmode}o'
                # elif rmode or wmode: mode = f'{rmode or wmode}o'
                # else: mode = ''
                modestr = f' [{mode}]' if mode else ''
                if myvar.name is not None:
                    return f'{myvar.name}{modestr}'
                elif myvar.hash is not None:
                    if myvar.type is not None or myvar.scope is not None:
                        typestr = myvar.type.postfix if myvar.type is not None else ''
                        scopestr = myvar.scope.prefix if myvar.scope is not None else ''
                        return f'{scopestr}{{{myvar.hash:08x}}}{typestr}{modestr}'
                    else:
                        return f'${myvar.hash:08x}{modestr}'
                elif myvar.type is not None:
                    return f'{myvar.type.getname()}{modestr}'
                else:
                    return f'-{modestr}'

            mylocalvars = local_vars()
            myparamvars = param_vars()
            mythreadvars = [v for v in variable_store.values() if v.scope is MjoScope.THREAD]
            mysavevars = [v for v in variable_store.values() if v.scope is MjoScope.SAVEFILE]
            mypersistvars = [v for v in variable_store.values() if v.scope is MjoScope.PERSISTENT]
            def write_vars(name, listvars):
                if not listvars: return
                # print(name, listvars)
                writer.write(f';;{name:<7} : {", ".join(repr_var(v) for v in listvars)}\n')
            write_vars('persist', mypersistvars)
            write_vars('save', mysavevars)
            write_vars('thread', mythreadvars)
            write_vars('local', mylocalvars)
            write_vars('args', myparamvars)
            writer.write(format_function(function, options=options) + '\n')
            for i,basic_block in enumerate(function.basic_blocks):
                writer.write(' ' + format_basic_block(basic_block, options=options) + '\n')
                for instruction in basic_block.instructions:
                    reskey = script.get_resource_key(instruction, options=options) if reswriter is not None else None
                    if reskey is not None:
                        reswriter.writerow([reskey, instruction.string])
                    writer.write('  ' + format_instruction(instruction, options=options, resource_key=reskey) + '\n')
                if i + 1 < len(function.basic_blocks):
                    writer.write(' \n')
            writer.write(format_function_close(function, options=options) + '\n')
            # writer.write('\n')
        writer.flush()
        if resfile is not None:
            resfile.flush()
      finally:
        if resfile is not None:
            reswriter = None
            #reswriter.close()
            resfile.close()

del abstractproperty, namedtuple, Iterator, Tuple  # cleanup declaration-only imports
