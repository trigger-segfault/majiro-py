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

__all__ = ['MjoType', 'MjoTypeMask', 'MjoScope', 'MjoInvertMode', 'MjoModifier', 'MjoFlags']

#######################################################################################

import enum


class MjoType(enum.IntEnum):
    """Type IDs for variables in Majiro
    """
    Int         = 0  #   '' postfix  (also used for handles/function pointers)
    Float       = 1  #  '%' postfix
    String      = 2  #  '$' postfix
    IntArray    = 3  #  '#' postfix
    FloatArray  = 4  # '%#' postfix
    StringArray = 5  # '$#' postfix

class MjoTypeMask(enum.IntFlag):
    """Mask for MjoType used exclusively during Opcodes definitions
    """
    Int         = 1 << MjoType.Int.value
    Float       = 1 << MjoType.Float.value
    String      = 1 << MjoType.String.value
    IntArray    = 1 << MjoType.IntArray.value
    FloatArray  = 1 << MjoType.FloatArray.value
    StringArray = 1 << MjoType.StringArray.value

    Numeric   = Int | Float
    Primitive = Int | Float | String
    Array     = IntArray | FloatArray | StringArray
    All       = Primitive | Array
    #All = Int | Float | String | IntArray | FloatArray | StringArray

class MjoScope(enum.IntEnum):
    """Scope (location) flags for ld* and st* opcodes
    """
    Persistent = 0  # '#' prefix
    SaveFile   = 1  # '@' prefix
    Thread     = 2  # '%' prefix
    Local      = 3  # '_' prefix

class MjoInvertMode(enum.IntEnum):
    """Invert (-/!/~) flags for ld* and st* opcodes
    """
    NoInvert = 0
    Numeric = 1  # -x
    Boolean = 2  # !x
    Bitwise = 3  # ~x

class MjoModifier(enum.IntEnum):
    """Modifier (++/--) flags for ld* and st* opcodes
    """
    NoModifier    = 0
    PreIncrement  = 1  # ++x
    PreDecrement  = 2  # --x
    PostIncrement = 3  # x++
    PostDecrement = 4  # x--
    IncrementX = 1 # alias
    DecrementX = 2 # alias
    XIncrement = 3 # alias
    XDecrement = 4 # alias


## MAJIRO FLAGS INT WRAPPER ##

class MjoFlags(int):
    """int wrapper with accessor properties for Majiro variable flags
    """
    # Dim      = 0b00011000_00000000,
    # Type     = 0b00000111_00000000,
    # Scope    = 0b00000000_11100000,
    # Invert   = 0b00000000_00011000,
    # Modifier = 0b00000000_00000111
    @classmethod
    def fromflags(cls, scope:MjoScope, type:MjoType, dimension:int=0, modifier:MjoModifier=MjoModifier.NoModifier, invert:MjoInvertMode=MjoInvertMode.NoInvert) -> 'MjoFlags':
        flags = 0
        flags |= ((modifier.value & 0x7))#<< 0)
        flags |= ((invert.value   & 0x3) <<  3)
        flags |= ((scope.value    & 0x7) <<  5)
        flags |= ((type.value     & 0x7) <<  8)
        flags |= ((dimension      & 0x3) << 11)
        return cls(flags)
    def __new__(cls, *args, **kwargs):
        return  super().__new__(cls, *args, **kwargs)
    @property
    def modifier(self) -> MjoModifier:
        return MjoModifier(self & 0x7)
    @property
    def invert(self) -> MjoInvertMode:
        return MjoInvertMode((self >> 3) & 0x3)
    @property
    def scope(self) -> MjoScope:
        return MjoScope((self >> 5) & 0x7)
    @property
    def type(self) -> MjoType:
        return MjoType((self >> 8) & 0x7)
    @property
    def dimension(self) -> int:
        return ((self >> 11) & 0x3)


# del enum  # cleanup declaration-only imports
