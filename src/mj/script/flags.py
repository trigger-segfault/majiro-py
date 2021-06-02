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

__all__ = ['MjoType', 'MjoScope', 'MjoInvert', 'MjoModifier', 'MjoDimension', 'MjoFlags']

#######################################################################################

import enum
from collections import OrderedDict
from itertools import chain
from typing import Any, Dict, Optional, Union

from .. import name as mj_name
from ..name import postfixsymbol, prefixsymbol


#######################################################################################

#region ## MAJIRO FLAGS ##

#NOTE: The #MjIL assembler language names and properties# are the most unpythonic thing I've ever seen... but it is Pythonic?
#      all flag MjIL names are defined in ## FLAG NAME DICTIONARIES ##
#      and flag functions are defined in ## FLAG NAME FUNCTIONS ##

class MjoType(enum.IntEnum):
    """Type (variable) flags for ld*, ldelem*, st*, and stelem* opcodes (same as internal IDs)
    """
    UNKNOWN      = -1 # ('?' postfix used internally to specify the name is unknown)
    #
    INT          = 0  #   '' postfix (int,         [i])  (also used for handles/function pointers)
    FLOAT        = 1  #  '%' postfix (float,       [r])  (includes legacy postfix: '!')
    STRING       = 2  #  '$' postfix (string,      [s])
    INT_ARRAY    = 3  #  '#' postfix (intarray,    [iarr])
    FLOAT_ARRAY  = 4  # '%#' postfix (floatarray,  [rarr])  (includes legacy postfix: '!#')
    STRING_ARRAY = 5  # '$#' postfix (stringarray, [sarr])
    #
    #NOTE: WHAT THE HELL!??  (also possibly "any")
    INTERNAL     = 8  #  '~' postfix (observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision)
    #                 #              (it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe)
    VOID         = 9  #  ''
    #
    def __bool__(self) -> bool: return self is not MjoType.UNKNOWN
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default:Any=...) -> 'MjoType': return _fromflagname(cls, name, default)
    #
    @property
    def postfix(self) -> str:
        if self is MjoType.INTERNAL:
            return self._POSTFIXES_ALT[self]  # INTERNAL only has an alt type since we still don't really understand it
        return self._POSTFIXES[self]
    @classmethod
    def frompostfix(cls, postfix:str, default:Any=..., *, allow_unk:bool=False, allow_alt:bool=False) -> 'MjoType':
        if not allow_unk and postfix == MjoType.UNKNOWN.postfix:
            if default is not Ellipsis:
                return default
            raise KeyError(postfix)
        name = None
        if allow_alt:
            name = cls._POSTFIX_ALT_LOOKUP.get(postfix)
        # do name checks here to "cleanly" handle default values
        if default is not Ellipsis:
            return name if name is not None else cls._POSTFIX_LOOKUP.get(postfix, default)
        else:
            return name if name is not None else cls._POSTFIX_LOOKUP[postfix]
    @classmethod
    def frompostfix_name(cls, fullname:str, default:Any=..., *, allow_unk:bool=False, allow_alt:bool=False) -> 'MjoType':
        postfix = postfixsymbol(fullname)
        return cls.frompostfix(postfix, default, allow_unk=allow_unk, allow_alt=allow_alt)
    # @classmethod
    # def getpostfix_fromname(cls, fullname:str) -> str:
    #     # from name lookup behavior has to be hardcoded :(
    #     # trim group name, if included
    #     #NOTE: realistically identifiers should have at least two chars before group
    #     name = basename(fullname)
    #     at_idx = name.find('@', 1)
    #     if at_idx != -1: name = name[:at_idx]
    #     # keep consistent parsing with '' postfix (which doesn't care if there's no room for an actual name)
    #     postfix = '' if len(name) > 0 else None
    #     for i in range(len(name) - 1, -1, -1): # (i=len(name)-1; i >= 0; i--)
    #         # consume as many postfix characters as possible to check invalid character usage
    #         #                            normal        doc   MAJIRO_INTER
    #         if i == 0 or name[i] not in ('%','$','#',  '?',  '!','~'): #cls._POSTFIX_LOOKUP:
    #         # if i == 0 or name[i] not in ('%','$','#',  '?',  '!'): #,'~'): #cls._POSTFIX_LOOKUP:
    #             postfix = name[i+1:]
    #             break
    #     return postfix
    #
    @property
    def python_type(self) -> type: return self._PYTHON_TYPES[self]
    @property
    def is_numeric(self) -> bool: return (MjoType.INT <= self <= MjoType.FLOAT)
    @property
    def is_reference(self) -> bool: return (MjoType.STRING <= self <= MjoType.STRING_ARRAY)
    @property
    def is_primitive(self) -> bool: return (MjoType.INT <= self <= MjoType.STRING)
    @property
    def is_array(self) -> bool: return (MjoType.INT_ARRAY <= self <= MjoType.STRING_ARRAY)
    @property
    def element(self) -> 'MjoType':
        return MjoType(self.value - MjoType.INT_ARRAY.value) if self.is_array else self
    @property
    def array(self) -> 'MjoType':
        if self is MjoType.UNKNOWN: return None
        return MjoType(self.value + MjoType.INT_ARRAY.value) if self.is_primitive else self
    #
    @property
    def typedef(self) -> 'Typedef':
        from ..identifier import Typedef
        return Typedef(self.value)
    @classmethod
    def fromtypedef(cls, typedef:'Typedef', default:Any=..., allow_unk:bool=False) -> 'MjoType':
        basetype = typedef.basetype
        if basetype.value > MjoType.STRING_ARRAY.value or (not allow_unk and basetype.value == MjoType.UNKNOWN.value):
            if default is Ellipsis:
                raise ValueError(f'no valid {cls.__name__} enum exists for {basetype!s}')
            return default
        return MjoType(basetype.value)
        
    #endregion

class MjoTypeMask(enum.IntFlag):
    """Mask for MjoType used exclusively during Opcodes definitions
    """
    VOID         = 0
    #
    INT          = 1 << MjoType.INT.value
    FLOAT        = 1 << MjoType.FLOAT.value
    STRING       = 1 << MjoType.STRING.value
    INT_ARRAY    = 1 << MjoType.INT_ARRAY.value
    FLOAT_ARRAY  = 1 << MjoType.FLOAT_ARRAY.value
    STRING_ARRAY = 1 << MjoType.STRING_ARRAY.value
    # combinations:
    NUMERIC   = INT | FLOAT
    PRIMITIVE = INT | FLOAT | STRING
    ARRAY     = INT_ARRAY | FLOAT_ARRAY | STRING_ARRAY
    ALL       = INT | FLOAT | STRING | INT_ARRAY | FLOAT_ARRAY | STRING_ARRAY


class MjoScope(enum.IntEnum):
    """Scope (location) flags for ld*, ldelem*, st*, and stelem* opcodes
    """
    UNKNOWN    = -1
    #
    PERSISTENT = 0  # '#' prefix (persistent, [persist])
    SAVEFILE   = 1  # '@' prefix (savefile,   [save])
    THREAD     = 2  # '%' prefix (thread)
    LOCAL      = 3  # '_' prefix (local,      [loc])
    #NOTE: not a real scope flag <INTERNAL USE ONLY>
    FUNCTION   = 8  # '$' prefix (func,       [void])
    SYSCALL    = 9  # '$' prefix, '@MAJIRO_INTER' group
    #
    def __bool__(self) -> bool: return self is not MjoScope.UNKNOWN
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default:Any=...) -> 'MjoScope': return _fromflagname(cls, name, default)
    #
    @property
    def prefix(self) -> str: return self._PREFIXES[self]
    @classmethod
    def fromprefix(cls, prefix:str, default:Any=..., allow_unk:bool=False) -> 'MjoScope':
        if not allow_unk and prefix == MjoScope.UNKNOWN.prefix:
            if default is not Ellipsis:
                return default
            raise KeyError(prefix)
        if default is not Ellipsis:
            return cls._PREFIX_LOOKUP.get(prefix, default)
        return cls._PREFIX_LOOKUP[prefix]
    @classmethod
    def fromprefix_name(cls, name:str, default:Any=..., allow_unk:bool=False) -> 'MjoScope':
        prefix = prefixsymbol(name)
        if allow_unk and prefix not in cls._PREFIX_LOOKUP:
            name = ''
        return cls.fromprefix(prefix, default, allow_unk=allow_unk)
    #
    @property
    def is_var(self) -> bool: return (MjoScope.PERSISTENT <= self <= MjoScope.LOCAL)
    @property
    def is_local_var(self) -> bool: return (self is MjoScope.LOCAL)
    @property
    def is_global_var(self) -> bool: return (MjoScope.PERSISTENT <= self <= MjoScope.THREAD)
    @property
    def is_func(self) -> bool: return (MjoScope.FUNCTION <= self <= MjoScope.SYSCALL)
    @property
    def is_call(self) -> bool: return (self is MjoScope.FUNCTION)
    @property
    def is_syscall(self) -> bool: return (self is MjoScope.SYSCALL)
    #
    @property
    def identifier(self) -> 'IdentifierKind':
        from ..identifier import IdentifierKind
        if self is MjoScope.FUNCTION: return IdentifierKind.FUNCTION
        if self is MjoScope.SYSCALL:  return IdentifierKind.SYSCALL
        return IdentifierKind(self.value)
    # @classmethod
    # def fromidentifier(cls, kind:'IdentifierKind') -> 'MjoScope':
    #     return MjoScope(kind.value) if kind.is_var else MjoScope.UNKNOWN
    @classmethod
    def fromidentifier(cls, kind:'IdentifierKind', default:Any=..., allow_unk:bool=False) -> 'MjoScope':
        from ..identifier import IdentifierKind
        if kind is IdentifierKind.FUNCTION: return MjoScope.FUNCTION
        if kind is IdentifierKind.SYSCALL:  return MjoScope.SYSCALL
        if kind.value > MjoScope.LOCAL.value or (not allow_unk and kind.value == MjoScope.UNKNOWN.value):
            if default is Ellipsis:
                raise ValueError(f'no valid {cls.__name__} enum exists for {kind!s}')
            return default
        return MjoScope(kind.value)
    #endregion


class MjoInvert(enum.IntEnum):
    """Invert (-/!/~) flags for ld* and ldelem* opcodes
    """
    NONE    = 0
    NUMERIC = 1  # -x (neg)
    BOOLEAN = 2  # !x (notl)
    BITWISE = 3  # ~x (not)
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default:Any=...) -> 'MjoInvert': return _fromflagname(cls, name, default)
    #
    @property
    def operator(self) -> str: return self._OPERATORS[self]
    #
    @property
    def supports(self) -> MjoTypeMask:
        if self is MjoInvert.NONE:
            return MjoTypeMask.ALL
        return MjoTypeMask.NUMERIC if (self is MjoInvert.NUMERIC) else MjoTypeMask.INT
    #endregion


class MjoModifier(enum.IntEnum):
    """Modifier (++/--) flags for ld* and ldelem* opcodes
    """
    NONE          = 0
    PREINCREMENT  = 1  # ++x (preinc,  [inc.x])
    PREDECREMENT  = 2  # --x (predec,  [dec.x])
    POSTINCREMENT = 3  # x++ (postinc, [x.inc])
    POSTDECREMENT = 4  # x-- (postdec, [x.dec])
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default:Any=...) -> 'MjoModifier': return _fromflagname(cls, name, default)
    #
    @property
    def operator(self) -> str: return self._OPERATORS[self]
    @property
    def is_pre(self) -> bool: return (MjoModifier.PREINCREMENT <= self <= MjoModifier.PREDECREMENT)
    @property
    def is_post(self) -> bool: return (MjoModifier.POSTINCREMENT <= self <= MjoModifier.POSTDECREMENT)
    #
    @property
    def supports(self) -> MjoTypeMask:
        return MjoTypeMask.ALL if (self is MjoModifier.NONE) else MjoTypeMask.INT
    #endregion


class MjoDimension(enum.IntEnum):
    """Dimension [,,] flags for ldelem* and stelem* opcodes
    """
    NONE          = 0  # [dim0]
    DIMENSION_1   = 1  # (dim1)
    DIMENSION_2   = 2  # (dim2)
    DIMENSION_3   = 3  # (dim3)
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default:Any=...) -> 'MjoDimension': return _fromflagname(cls, name, default)
    #
    @property
    def supports(self) -> MjoTypeMask:
        return MjoTypeMask.ALL if (self is MjoDimension.NONE) else MjoTypeMask.ARRAY
    #endregion

#endregion

#region ## MAJIRO FLAGS INT WRAPPER ##

class MjoFlags(int):
    """immutable int wrapper with accessor properties for Majiro variable bitmask flags
    """
    # Dim      = 0b00011000_00000000,
    # Type     = 0b00000111_00000000,
    # Scope    = 0b00000000_11100000,
    # Invert   = 0b00000000_00011000,
    # Modifier = 0b00000000_00000111,
    def __new__(cls, value:int=0): #*args, **kwargs):
        if type(value) is cls and cls is MjoFlags:
            return value
        return super().__new__(cls, value) #*args, **kwargs)
    @classmethod
    def fromflags(cls, scope:MjoScope, type:MjoType, dimension:int=0, modifier:MjoModifier=MjoModifier.NONE, invert:MjoInvert=MjoInvert.NONE) -> 'MjoFlags':
        """Return a new MjoFlags object with the specified bitmask flags
        """
        flags = 0
        flags |= ((modifier.value & 0x7))#<< 0)
        flags |= ((invert.value   & 0x3) <<  3)
        flags |= ((scope.value    & 0x7) <<  5)
        flags |= ((type.value     & 0x7) <<  8)
        #FIXME: Stop handling MjoDimension as int entirely??
        flags |= ((int(dimension) & 0x3) << 11)
        return cls(flags)
    def _replace(self, scope:MjoScope=..., type:MjoType=..., dimension:MjoDimension=..., modifier:MjoModifier=..., invert:MjoInvert=...) -> 'MjoFlags':
        """Return a new MjoFlags object replacing specified bitmask flags with new values
        """
        if scope     is Ellipsis: scope     = self.scope
        if type      is Ellipsis: type      = self.type
        if dimension is Ellipsis: dimension = self.dimension
        if modifier  is Ellipsis: modifier  = self.modifier
        if invert    is Ellipsis: invert    = self.invert
        return self.fromflags(scope=scope, type=type, dimension=dimension, modifier=modifier, invert=invert)
    @property
    def modifier(self) -> MjoModifier: return MjoModifier(self & 0x7)
    @property
    def invert(self) -> MjoInvert: return MjoInvert((self >> 3) & 0x3)
    @property
    def scope(self) -> MjoScope: return MjoScope((self >> 5) & 0x7)
    @property
    def type(self) -> MjoType: return MjoType((self >> 8) & 0x7)
    @property
    def dimension(self) -> MjoDimension: return MjoDimension((self >> 11) & 0x3)

#endregion

#region ## FLAG NAME DICTIONARIES ##

#TODO: is there really any need to be using OrderedDict's here?

# MjoType:
MjoType._NAMES = OrderedDict({
    MjoType.INT:          'int',
    MjoType.FLOAT:        'float',
    MjoType.STRING:       'string',
    MjoType.INT_ARRAY:    'intarray',
    MjoType.FLOAT_ARRAY:  'floatarray',
    MjoType.STRING_ARRAY: 'stringarray',
})
MjoType._ALIASES = OrderedDict({
    MjoType.INT:          'i',
    MjoType.FLOAT:        'r',
    MjoType.STRING:       's',
    MjoType.INT_ARRAY:    'iarr',
    MjoType.FLOAT_ARRAY:  'rarr',
    MjoType.STRING_ARRAY: 'sarr',
})
MjoType._LOOKUP = OrderedDict((v,k) for k,v in chain(MjoType._NAMES.items(), MjoType._ALIASES.items()))

MjoType._POSTFIXES = OrderedDict({
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    MjoType.UNKNOWN:      mj_name.DOC_POSTFIX_UNKNOWN,  # '?'
    #
    MjoType.INT:          mj_name.POSTFIX_INT,          # ''
    MjoType.FLOAT:        mj_name.POSTFIX_FLOAT,        # '%'
    MjoType.STRING:       mj_name.POSTFIX_STRING,       # '$'
    MjoType.INT_ARRAY:    mj_name.POSTFIX_INT_ARRAY,    # '#'
    MjoType.FLOAT_ARRAY:  mj_name.POSTFIX_FLOAT_ARRAY,  # '%#'
    MjoType.STRING_ARRAY: mj_name.POSTFIX_STRING_ARRAY, # '$#'
    #
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    MjoType.VOID:         mj_name.POSTFIX_VOID,         # '' same as INT
})
MjoType._POSTFIXES_ALT = OrderedDict({
    #NOTE: legacy float type prefix '!', observed with 3 syscalls: 
    #       * $46b18379 "$rand!@MAJIRO_INTER"         (still present)
    #       * $2cd009af "$dim_create!#@MAJIRO_INTER"  (removed in releases after Mahjong [v1509])
    #       * $20caeb0e "$dim_release!#@MAJIRO_INTER" (removed in releases after Mahjong [v1509])
    MjoType.FLOAT:        mj_name.LEGACY_POSTFIX_FLOAT,       # '!'
    MjoType.FLOAT_ARRAY:  mj_name.LEGACY_POSTFIX_FLOAT_ARRAY, # '!#'
    #
    # #NOTE: WHAT THE HELL!??
    # #      observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision.
    # #      it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe.
    MjoType.INTERNAL:     mj_name.POSTFIX_INTERNAL, # '~'
})
MjoType._POSTFIX_LOOKUP = OrderedDict((v,k) for k,v in MjoType._POSTFIXES.items() if k is not MjoType.VOID)
MjoType._POSTFIX_ALT_LOOKUP = OrderedDict((v,k) for k,v in MjoType._POSTFIXES_ALT.items())

MjoType._PYTHON_TYPES = OrderedDict({
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    MjoType.UNKNOWN:      object,  # any type
    #
    MjoType.INT:          int,
    MjoType.FLOAT:        float,
    MjoType.STRING:       str,
    MjoType.INT_ARRAY:    list,
    MjoType.FLOAT_ARRAY:  list,
    MjoType.STRING_ARRAY: list,
    #
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    MjoType.VOID:         type(None),
})

# MjoScope:
MjoScope._NAMES = OrderedDict({
    MjoScope.PERSISTENT: 'persistent',
    MjoScope.SAVEFILE:   'savefile',
    MjoScope.THREAD:     'thread',
    MjoScope.LOCAL:      'local',
    # #NOTE: not a real scope flag <INTERNAL USE ONLY, EXCLUDED FROM _LOOKUP>
    MjoScope.FUNCTION:   'call',
    MjoScope.SYSCALL:    'syscall',
})
MjoScope._ALIASES = OrderedDict({
    MjoScope.PERSISTENT: 'persist',
    MjoScope.SAVEFILE:   'save',
    # (no thread alias, already short enough for its infrequent usage)
    MjoScope.LOCAL:      'loc',
})
MjoScope._LOOKUP = OrderedDict((v,k) for k,v in chain(MjoScope._NAMES.items(), MjoScope._ALIASES.items())) #if k is not MjoScope.FUNCTION)

MjoScope._PREFIXES = OrderedDict({
    #NOTE: not a real scope flag <INTERNAL USE ONLY>
    MjoScope.UNKNOWN:    '',
    #
    MjoScope.PERSISTENT: mj_name.PREFIX_PERSISTENT, # '#'
    MjoScope.SAVEFILE:   mj_name.PREFIX_SAVEFILE,   # '@'
    MjoScope.THREAD:     mj_name.PREFIX_THREAD,     # '%'
    MjoScope.LOCAL:      mj_name.PREFIX_LOCAL,      # '_'
    # #NOTE: not a real scope flag <INTERNAL USE ONLY>
    MjoScope.FUNCTION:   mj_name.PREFIX_FUNCTION,   # '$'
    MjoScope.SYSCALL:    mj_name.PREFIX_FUNCTION,   # '$'
})
MjoScope._PREFIX_LOOKUP = OrderedDict((v,k) for k,v in MjoScope._PREFIXES.items() if k is not MjoScope.SYSCALL)

# MjoInvert:
MjoInvert._NAMES = OrderedDict({
    #NOTE: these names will conflict with "notl" and "not" opcode mnemonics, be prepared when parsing MjIL
    MjoInvert.NUMERIC: 'neg',
    MjoInvert.BOOLEAN: 'notl',
    MjoInvert.BITWISE: 'not',
})
MjoInvert._LOOKUP = OrderedDict((v,k) for k,v in MjoInvert._NAMES.items())

MjoInvert._OPERATORS = OrderedDict({
    MjoInvert.NONE:    None,
    MjoInvert.NUMERIC: '-',
    MjoInvert.BOOLEAN: '!',
    MjoInvert.BITWISE: '~',
})

# MjoModifier:
MjoModifier._NAMES = OrderedDict({
    MjoModifier.PREINCREMENT:  'preinc',
    MjoModifier.PREDECREMENT:  'predec',
    MjoModifier.POSTINCREMENT: 'postinc',
    MjoModifier.POSTDECREMENT: 'postdec',
})
MjoModifier._ALIASES = OrderedDict({
    MjoModifier.PREINCREMENT:  'inc.x',
    MjoModifier.PREDECREMENT:  'dec.x',
    MjoModifier.POSTINCREMENT: 'x.inc',
    MjoModifier.POSTDECREMENT: 'x.dec',
})
MjoModifier._LOOKUP = OrderedDict((v,k) for k,v in chain(MjoModifier._NAMES.items(), MjoModifier._ALIASES.items()))

MjoModifier._OPERATORS = OrderedDict({
    MjoModifier.NONE:          None,
    MjoModifier.PREINCREMENT:  '++',
    MjoModifier.PREDECREMENT:  '--',
    MjoModifier.POSTINCREMENT: '++',
    MjoModifier.POSTDECREMENT: '--',
})

# MjoDimension:
MjoDimension._NAMES = OrderedDict({
    #MjoDimension.NONE:        'dim0', # useless alias, not required
    MjoDimension.DIMENSION_1: 'dim1',
    MjoDimension.DIMENSION_2: 'dim2',
    MjoDimension.DIMENSION_3: 'dim3',
})
MjoDimension._ALIASES = OrderedDict({
    MjoDimension.NONE:        'dim0', # useless alias, not required
})
MjoDimension._LOOKUP = OrderedDict((v,k) for k,v in chain(MjoDimension._NAMES.items(), MjoDimension._ALIASES.items()))

#endregion

#region ## FLAG NAME FUNCTIONS ##

def _flagname(flag:Union[MjoScope,MjoType,MjoModifier,MjoInvert,MjoDimension,int], alias:bool=False) -> Optional[str]:
    """Return the name or alias/mnemonic for the given Majiro bitmask flag

    returns `None` for *.NONE flags, unless there is an alias and `alias` is True (MjoDimension only)
    """
    name = None
    #FIXME: Stop handling MjoDimension as int entirely??
    if not isinstance(flag, enum.Enum) and isinstance(flag, int):
        flag = MjoDimension(flag)
    if isinstance(flag, (MjoScope, MjoType, MjoModifier, MjoInvert, MjoDimension)):
        name = None
        if alias and hasattr(flag.__class__, '_ALIASES'):
            name = flag.__class__._ALIASES.get(flag) # optional alias
        if not flag:
            return name or flag.__class__._NAMES.get(flag) # return None for flags with NONE value
        else:
            return name or flag.__class__._NAMES[flag] # requried lookup
    else:
        raise TypeError(f'argument must be Mjo-Scope/Type/Modifier/Invert/Dimension or int object, not {flag.__class__.__name__}')

def _fromflagname(cls, name:str, default:Any=...) -> enum.Enum:
    """Returns the flag enum from the the specified name
    
    when `default` argument is defined:
        returns `default` on invalid name
    otherwise:
        raises `KeyError` on invalid name
    """
    if default is not Ellipsis:
        return cls._LOOKUP.get(name, default)
    return cls._LOOKUP[name]

#endregion

# print('MjoDimension._NAMES   :', ', '.join(MjoDimension._NAMES.values()))
# print('MjoDimension._ALIASES :', ', '.join(MjoDimension._ALIASES.values()))
# print('MjoType._NAMES        :', ', '.join(MjoType._NAMES.values()))
# print('MjoType._ALIASES      :', ', '.join(MjoType._ALIASES.values()))
# print('MjoScope._NAMES       :', ', '.join(MjoScope._NAMES.values()))
# print('MjoScope._ALIASES     :', ', '.join(MjoScope._ALIASES.values()))
# print('MjoModifier._NAMES    :', ', '.join(MjoModifier._NAMES.values()))
# print('MjoModifier._ALIASES  :', ', '.join(MjoModifier._ALIASES.values()))
# print('MjoInvert._NAMES      :', ', '.join(MjoInvert._NAMES.values()))


#######################################################################################

del chain, OrderedDict, Any, Dict, Union  # cleanup declaration-only imports
