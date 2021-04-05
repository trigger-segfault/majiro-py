#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script instruction opcodes
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Based off Meta Language implementation by Haeleth - 2005
Converted to Python script with extended syntax by Robert Jordan - 2021
'''

__all__ = ['Opcode']

# naming conventions based off of:
# <https://en.wikipedia.org/wiki/List_of_CIL_instructions>

#######################################################################################

from typing import Dict, List, NoReturn  # for hinting in declarations

from .flags import MjoType, MjoTypeMask


#region ## MAJIRO OPCODE CLASS ##

class Opcode:
    """Opcode definition
    """
    # global opcode definitions
    LIST:List['Opcode'] = []
    BYVALUE:Dict[int, 'Opcode'] = {}

    def __init__(self, value:int, mnemonic:str, operator:str, encoding:str, transition:str, *, aliases:tuple=()):
        # general #
        self.value:int      = value
        self.mnemonic:str   = mnemonic
        self.operator:str   = operator

        # parsing / analysis #
        self.encoding:str   = encoding    # instruction encoding
        self.transition:str = transition  # stack transition

        if aliases is None:
            aliases = ()
        elif not isinstance(aliases, tuple):
            raise TypeError('{0.__class__.__name__} argument \'aliases\' must be tuple or NoneType, not {1.__class__.__name__}'.format(self, aliases))
        self.aliases:tuple = aliases
    @property
    def is_jump(self) -> bool:
        return self.encoding == "j"

    def __repr__(self) -> str:
        return self.mnemonic
    def __str__(self) -> str:
        return self.mnemonic

#endregion


# global opcode definitions
# Opcode.LIST:List[Opcode] = []
# Opcode.BYVALUE:Dict[int, Opcode] = {}

#region ## OPCODE DEFINITION FUNCTIONS ##

# wrap opcode definitions setup in function scope
# def _init(LIST:List[Opcode], BYVALUE:Dict[int, Opcode]) -> List[Opcode]:
#     global LIST
#     global BYVALUE
#     opcodeslist:List[Opcode] = []

_POSTFIXES  = (".i", ".r", ".s", ".iarr", ".rarr", ".sarr")
#_TYPES      = (MjoType.Int,     MjoType.Float,     MjoType.String,     MjoType.IntArray,     MjoType.FloatArray,     MjoType.StringArray)
_TYPE_MASKS = (MjoTypeMask.Int, MjoTypeMask.Float, MjoTypeMask.String, MjoTypeMask.IntArray, MjoTypeMask.FloatArray, MjoTypeMask.StringArray)
_COMPARISON_TRANSITIONS = (("ii.i", "ii.b"), ("nn.f", "nn.b"), ("ss.s", "ss.b"), ("-", "II.b"), ("-", "FF.b"), ("-", "SS.b"))
_POP_TRANSITIONS        = (("i.i", "i."),    ("n.f", "n."),    ("s.s", "s."),    ("I.I", "I."), ("F.F", "F."), ("S.S", "S."))
_POPARRAY_TRANSITIONS   = (("i[i#d].i", "i[i#d]."), ("n[i#d].f", "n[i#d]."), ("s[i#d].s", "[i#d]s."), (), (), ())


def alias_type(postfix:str, *aliases:str) -> tuple:
    if not aliases:
        return aliases
    return tuple(a + postfix for a in aliases)

def alias_intonly(postfix:str, mnemonic:str, *aliases:str) -> tuple:
    return aliases + alias_type(postfix, mnemonic, *aliases)

def define_opcode(value:int, mnemonic:str, op:str, encoding:str, transition:str, *aliases:str) -> NoReturn:
    opcode = Opcode(value, mnemonic, op, encoding, transition, aliases=aliases)
    Opcode.LIST.append(opcode)
    existing = Opcode.BYVALUE.get(value, None)
    # LIST.append(opcode)
    # existing = BYVALUE.get(value, None)
    if existing:
        raise ValueError('Opcode \"{0.mnemonic!s}\" value 0x{0.value:03x} already defined by \"{1.mnemonic!s}\"'.format(opcode, existing))
    Opcode.BYVALUE[value] = opcode
    # BYVALUE[value] = opcode

def define_binary_operator(base_value:int, mnemonic:str, op:str, allowed_types:MjoTypeMask, is_comparison:bool, *aliases:str) -> NoReturn:
    for i, t_mask in enumerate(_TYPE_MASKS):
        if allowed_types & t_mask:
            comparison = _COMPARISON_TRANSITIONS[is_comparison]
            postfix = _POSTFIXES[i]
            if allowed_types == MjoTypeMask.Int:
                define_opcode(base_value, mnemonic, op, "", comparison, *alias_intonly(postfix, mnemonic, *aliases))
                return # no need to check for others
            else:
                define_opcode(base_value + i, mnemonic + postfix, op, "", comparison, *alias_type(postfix, *aliases))

def define_assignment_operator(base_value:int, mnemonic:str, op:str, allowed_types:MjoTypeMask, is_pop:bool, *aliases:str) -> NoReturn:
    for i, t_mask in enumerate(_TYPE_MASKS):
        if allowed_types & t_mask:
            pop = _POP_TRANSITIONS[is_pop]
            postfix = _POSTFIXES[i]
            if allowed_types == MjoTypeMask.Int:
                define_opcode(base_value, mnemonic, op, "fho", pop, *alias_intonly(postfix, mnemonic, *aliases))
                return # no need to check for others
            else:
                define_opcode(base_value + i, mnemonic + postfix, op, "fho", pop, *alias_type(postfix, *aliases))

def define_array_assignment_operator(base_value:int, mnemonic:str, op:str, allowed_types:MjoTypeMask, is_pop:bool, *aliases:str) -> NoReturn:
    for i, t_mask in enumerate(_TYPE_MASKS): #TODO: this is a waste, only the first 3 types should be enumerated
        if allowed_types & t_mask:
            pop = _POPARRAY_TRANSITIONS[is_pop]
            postfix = _POSTFIXES[i]
            if allowed_types == MjoTypeMask.Int:
                define_opcode(base_value, mnemonic, op, "fho", pop, *alias_intonly(postfix, mnemonic, *aliases))
                return # no need to check for others
            else:
                define_opcode(base_value + i, mnemonic + postfix, op, "fho", pop, *alias_type(postfix, *aliases))

#endregion

#region ## BEGIN OPCODE DEFINITIONS ##

# binary operators #
define_binary_operator(0x100, "mul",  "*",  MjoTypeMask.Numeric, False)
define_binary_operator(0x108, "div",  "/",  MjoTypeMask.Numeric, False)
define_binary_operator(0x110, "rem",  "%",  MjoTypeMask.Int, False, "mod")
define_binary_operator(0x118, "add",  "+",  MjoTypeMask.Primitive, False)
define_binary_operator(0x120, "sub",  "-",  MjoTypeMask.Primitive, False)
define_binary_operator(0x128, "shr",  ">>", MjoTypeMask.Int, False)
define_binary_operator(0x130, "shl",  "<<", MjoTypeMask.Int, False)
define_binary_operator(0x138, "cle",  "<=", MjoTypeMask.Primitive, True)
define_binary_operator(0x140, "clt",  "<",  MjoTypeMask.Primitive, True)
define_binary_operator(0x148, "cge",  ">=", MjoTypeMask.Primitive, True)
define_binary_operator(0x150, "cgt",  ">",  MjoTypeMask.Primitive, True)
define_binary_operator(0x158, "ceq",  "==", MjoTypeMask.All, True)
define_binary_operator(0x160, "cne",  "!=", MjoTypeMask.All, True)
define_binary_operator(0x168, "xor",  "^",  MjoTypeMask.Int, False)
define_binary_operator(0x170, "andl", "&&", MjoTypeMask.Int, False)
define_binary_operator(0x178, "orl",  "||", MjoTypeMask.Int, False)
define_binary_operator(0x180, "and",  "&",  MjoTypeMask.Int, False)
define_binary_operator(0x188, "or",   "|",  MjoTypeMask.Int, False)

# unary operators / nops #
define_opcode(0x190, "notl",  "!", "", "i.i", *alias_intonly(".i", "notl"))
define_opcode(0x198, "not",   "~", "", "i.i", *alias_intonly(".i", "not"))
define_opcode(0x1a0, "neg.i", "-", "", "i.i")
define_opcode(0x1a1, "neg.r", "-", "", "f.f")

define_opcode(0x191, "nop.191", None, "", "", "notl.r")  # original usage
define_opcode(0x1a8, "nop.1a8", None, "", "", "pos.i")   # assumed original usage
define_opcode(0x1a9, "nop.1a9", None, "", "", "pos.r")   # assumed original usage

# assignment operators #
define_assignment_operator(0x1b0, "st",     "=",   MjoTypeMask.All, False)
define_assignment_operator(0x1b8, "st.mul", "*=",  MjoTypeMask.Numeric, False)
define_assignment_operator(0x1c0, "st.div", "/=",  MjoTypeMask.Numeric, False)
define_assignment_operator(0x1c8, "st.rem", "%=",  MjoTypeMask.Int, False, "st.mod")
define_assignment_operator(0x1d0, "st.add", "+=",  MjoTypeMask.Primitive, False)
define_assignment_operator(0x1d8, "st.sub", "-=",  MjoTypeMask.Numeric, False)
define_assignment_operator(0x1e0, "st.shl", "<<=", MjoTypeMask.Int, False)
define_assignment_operator(0x1e8, "st.shr", ">>=", MjoTypeMask.Int, False)
define_assignment_operator(0x1f0, "st.and", "&=",  MjoTypeMask.Int, False)
define_assignment_operator(0x1f8, "st.xor", "^=",  MjoTypeMask.Int, False)
define_assignment_operator(0x200, "st.or",  "|=",  MjoTypeMask.Int, False)

define_assignment_operator(0x210, "stp",     "=",   MjoTypeMask.All, True)
define_assignment_operator(0x218, "stp.mul", "*=",  MjoTypeMask.Numeric, True)
define_assignment_operator(0x220, "stp.div", "/=",  MjoTypeMask.Numeric, True)
define_assignment_operator(0x228, "stp.rem", "%=",  MjoTypeMask.Int, True, "stp.mod")
define_assignment_operator(0x230, "stp.add", "+=",  MjoTypeMask.Primitive, True)
define_assignment_operator(0x238, "stp.sub", "-=",  MjoTypeMask.Numeric, True)
define_assignment_operator(0x240, "stp.shl", "<<=", MjoTypeMask.Int, True)
define_assignment_operator(0x248, "stp.shr", ">>=", MjoTypeMask.Int, True)
define_assignment_operator(0x250, "stp.and", "&=",  MjoTypeMask.Int, True)
define_assignment_operator(0x258, "stp.xor", "^=",  MjoTypeMask.Int, True)
define_assignment_operator(0x260, "stp.or",  "|=",  MjoTypeMask.Int, True)

# array assignment operators #
define_array_assignment_operator(0x270, "stelem",     "=",   MjoTypeMask.All, False)
define_array_assignment_operator(0x278, "stelem.mul", "*=",  MjoTypeMask.Numeric, False)
define_array_assignment_operator(0x280, "stelem.div", "/=",  MjoTypeMask.Numeric, False)
define_array_assignment_operator(0x288, "stelem.rem", "%=",  MjoTypeMask.Int, False, "stelem.mod")
define_array_assignment_operator(0x290, "stelem.add", "+=",  MjoTypeMask.Primitive, False)
define_array_assignment_operator(0x298, "stelem.sub", "-=",  MjoTypeMask.Numeric, False)
define_array_assignment_operator(0x2a0, "stelem.shl", "<<=", MjoTypeMask.Int, False)
define_array_assignment_operator(0x2a8, "stelem.shr", ">>=", MjoTypeMask.Int, False)
define_array_assignment_operator(0x2b0, "stelem.and", "&=",  MjoTypeMask.Int, False)
define_array_assignment_operator(0x2b8, "stelem.xor", "^=",  MjoTypeMask.Int, False)
define_array_assignment_operator(0x2c0, "stelem.or",  "|=",  MjoTypeMask.Int, False)

define_array_assignment_operator(0x2d0, "stelemp",     "=",   MjoTypeMask.All, True)
define_array_assignment_operator(0x2d8, "stelemp.mul", "*=",  MjoTypeMask.Numeric, True)
define_array_assignment_operator(0x2e0, "stelemp.div", "/=",  MjoTypeMask.Numeric, True)
define_array_assignment_operator(0x2e8, "stelemp.rem", "%=",  MjoTypeMask.Int, True, "stelemp.mod")
define_array_assignment_operator(0x2f0, "stelemp.add", "+=",  MjoTypeMask.Primitive, True)
define_array_assignment_operator(0x2f8, "stelemp.sub", "-=",  MjoTypeMask.Numeric, True)
define_array_assignment_operator(0x300, "stelemp.shl", "<<=", MjoTypeMask.Int, True)
define_array_assignment_operator(0x308, "stelemp.shr", ">>=", MjoTypeMask.Int, True)
define_array_assignment_operator(0x310, "stelemp.and", "&=",  MjoTypeMask.Int, True)
define_array_assignment_operator(0x318, "stelemp.xor", "^=",  MjoTypeMask.Int, True)
define_array_assignment_operator(0x320, "stelemp.or",  "|=",  MjoTypeMask.Int, True)

# 0800 range opcodes #
define_opcode(0x800, "ldc.i", None, "i", ".i")
define_opcode(0x801, "ldstr", None, "s", ".s", "ld.s")
define_opcode(0x802, "ld", None, "fho", ".#t", "ldvar")
define_opcode(0x803, "ldc.r", None, "r", ".f")

define_opcode(0x80f, "call",  None, "h0a", "[*#a].*")
define_opcode(0x810, "callp", None, "h0a", "[*#a].")

define_opcode(0x829, "alloca", None, "t", ".[#t]")  # official name
define_opcode(0x82b, "ret", None, "", "[*].", "return")

define_opcode(0x82c, "br", None, "j", ".", "jmp")
define_opcode(0x82d, "brtrue", None, "j", "p.", "jnz", "jne")
define_opcode(0x82e, "brfalse", None, "j", "p.", "brnull", "brzero", "jz", "je")

define_opcode(0x82f, "pop", None, "", "*.")

# non-sequential switch jumps (stores and reuses variable from br.v)
define_opcode(0x830, "br.v", None, "j", "p.1", "jmp.v")   # !!non-final name!!
define_opcode(0x831, "bne.v", None, "j", "p.1", "jne.v")  # !!non-final name!!
define_opcode(0x832, "bgt.v", None, "j", "p.1", "jgt.v")  # !!non-final name!!
define_opcode(0x833, "bge.v", None, "j", "p.1", "jge.v")  # !!non-final name!!
define_opcode(0x838, "ble.v", None, "j", "p.1", "jle.v")  # !!non-final name!!
define_opcode(0x839, "blt.v", None, "j", "p.1", "jlt.v")  # !!non-final name!!

define_opcode(0x834, "syscall",  None, "ha", "[*#a].*")
define_opcode(0x835, "syscallp", None, "ha", "[*#a].")

define_opcode(0x836, "argcheck", None, "t", ".", "sigchk")  # function arguments signature

define_opcode(0x837, "ldelem", None, "fho", "[i#d].~#t")

define_opcode(0x83a, "line", None, "l", ".")  # source script line number

# branch-selector opcodes #
# not fully understood, but all have relations to special
# block definitions: setskip, destructor, constructor(?)
define_opcode(0x83b, "bsel.1", None, "j", "???")   # !!non-final name!!
define_opcode(0x83c, "bsel.3", None, "j", "???")   # !!non-final name!!
define_opcode(0x83d, "bsel.2", None, "j", "???")   # !!non-final name!!

define_opcode(0x83e, "conv.i", None, "", "f.i")
define_opcode(0x83f, "conv.r", None, "", "i.f")

# visual novel opcodes #
define_opcode(0x840, "text", None, "s", ".")
define_opcode(0x841, "proc", None, "", ".")        # !!non-final name!!  process buffer created by text opcode
define_opcode(0x842, "ctrl", None, "s", "???")  # "[#s]." (varying effect on stack depending on string)

# more branch-selector opcodes #
define_opcode(0x843, "bsel.x", None, "j", ".")     # !!non-final name!!
define_opcode(0x844, "bsel.clr", None, "", ".")    # !!non-final name!!
define_opcode(0x845, "bsel.4", None, "j", ".")     # !!non-final name!!
define_opcode(0x846, "bsel.jmp.4", None, "", ".")  # !!non-final name!!
define_opcode(0x847, "bsel.5", None, "j", ".")     # !!non-final name!!

define_opcode(0x850, "switch", None, "c", "i.")

#endregion ## END OPCODE DEFINITIONS ##


del Dict, List, NoReturn  # cleanup declaration-only imports
