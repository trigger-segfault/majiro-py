#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script identifier signatures and hashing.


"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

__all__ = ['GROUP_SYSCALL', 'GROUP_DEFAULT', 'GROUP_LOCAL', 'IdentifierKind', 'Typedef', 'HashValue', 'HashName']

#######################################################################################

## runtime imports:
# from .crypt import hash32       # used by verify()
# from .crypt import to_hash32    # used by HashName() when passed a str value
# from .database.hashes import *  # used by HashValue.lookup*() functions

import enum
from typing import Any, Optional, Tuple, Union

from . import name as mj_name
from .name import GROUP_LOCAL, GROUP_DEFAULT, GROUP_SYSCALL, splitgroup, joingroup, groupname, basename, hasgroup, splitsymbols, prefixsymbol, postfixsymbol


#######################################################################################

#region ## ENUM TYPES ##

class IdentifierKind(enum.IntEnum):
    """Identifier kind for names and hashes.
    """
    UNKNOWN    = -1
    PERSISTENT = 0
    SAVEFILE   = 1
    THREAD     = 2
    LOCAL      = 3
    FUNCTION   = 4
    SYSCALL    = 5
    CALLBACK   = 6
    # OTHER      = enum.auto()

    def __bool__(self) -> bool: return self is not IdentifierKind.UNKNOWN

    @property
    def is_var(self) -> bool: return (IdentifierKind.PERSISTENT <= self <= IdentifierKind.LOCAL)
    @property
    def is_global_var(self) -> bool: return (IdentifierKind.PERSISTENT <= self <= IdentifierKind.THREAD)
    @property
    def is_local_var(self) -> bool: return (self is IdentifierKind.LOCAL)
    @property
    def is_func(self) -> bool: return (IdentifierKind.FUNCTION <= self <= IdentifierKind.SYSCALL)
    @property
    def is_call(self) -> bool: return (self is IdentifierKind.FUNCTION)
    @property
    def is_syscall(self) -> bool: return (self is IdentifierKind.SYSCALL)
    @property
    def is_cb(self) -> bool: return (self is IdentifierKind.CALLBACK)

    def to_mjoscope(self, default:Any=None) -> Optional['MjoScope']:
        from .script.flags import MjoScope
        if IdentifierKind.PERSISTENT <= self <= IdentifierKind.LOCAL:
            return MjoScope(self.value)
        elif self is IdentifierKind.FUNCTION:
            return MjoScope.FUNCTION
        elif self is IdentifierKind.SYSCALL:
            return MjoScope.SYSCALL
        elif self is IdentifierKind.UNKNOWN:
            return MjoScope.UNKNOWN
        return default
    @classmethod
    def from_mjoscope(cls, mjoscope:'MjoScope', default:Any=None) -> 'IdentifierKind':
        from .script.flags import MjoScope
        if MjoScope.PERSISTENT <= mjoscope <= MjoScope.LOCAL:
            return IdentifierKind(mjoscope.value)
        elif mjoscope is MjoScope.FUNCTION:
            return IdentifierKind.FUNCTION
        elif mjoscope is MjoScope.SYSCALL:
            return IdentifierKind.SYSCALL
        elif mjoscope is MjoScope.UNKNOWN:
            return IdentifierKind.UNKNOWN
        return default

    @property
    def prefix(self) -> str: return self._PREFIXES[self]
    @classmethod
    def fromprefix(cls, prefix:str, default:Any=..., allow_unk:bool=False) -> 'IdentifierKind':
        if not allow_unk and prefix == IdentifierKind.UNKNOWN.prefix:
            if default is not Ellipsis:
                return default
            raise KeyError(prefix)
        if default is not Ellipsis:
            return cls._PREFIX_LOOKUP.get(prefix, default)
        return cls._PREFIX_LOOKUP[prefix]
    @classmethod
    def fromprefix_name(cls, name:str, default:Any=..., allow_unk:bool=False) -> 'IdentifierKind':
        prefix = prefixsymbol(name)
        if allow_unk and prefix not in cls._PREFIX_LOOKUP:
            name = ''
        return cls.fromprefix(prefix, default, allow_unk=allow_unk)


class Typedef(enum.IntFlag):
    """Identifier types and typedef aliases.
    """
    UNKNOWN      = -1   # ('?' postfix used internally to specify the name is unknown)
    #
    INT          = 0x0  #   '' postfix (int,         [i])  (also used for handles/function pointers)
    FLOAT        = 0x1  #  '%' postfix (float,       [r])  (includes legacy postfix: '!')
    STRING       = 0x2  #  '$' postfix (string,      [s])
    INT_ARRAY    = 0x3  #  '#' postfix (intarray,    [iarr])
    FLOAT_ARRAY  = 0x4  # '%#' postfix (floatarray,  [rarr])  (includes legacy postfix: '!#')
    STRING_ARRAY = 0x5  # '$#' postfix (stringarray, [sarr])
    #
    ANY          = 0x6
    VOID         = 0x7
    #
    _TYPEMASK    = 0x7
    #
    ## INT Typedefs ##
    # PTR Typedefs:
    PTR          = (0x1 << 3) | INT  # ptr flag
    _PTRMASK     = (_TYPEMASK | PTR)
    FILE         = (0x1 << 4) | PTR
    PAGE         = (0x2 << 4) | PTR
    SPRITE       = (0x3 << 4) | PTR
    # Non-PTR Typedefs:
    INT_UNK      = (0x1 << 4) | INT
    BOOL         = (0x2 << 4) | INT
    #
    ## ANY Typedefs ##
    # ANY          = 0x6
    # VOID         = (0x1 << 3) | ANY
    ANY_VOID     = (0x1 << 3) | ANY
    #NOTE: WHAT THE HELL!??  (also possibly "any")
    #  '~' postfix (observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision)
    #              (it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe)
    INTERNAL     = (0x2 << 3) | ANY
    #

    def __bool__(self) -> bool:
        return self is not IdentifierKind.UNKNOWN
    #
    @property
    def basetype(self) -> 'Typedef':
        """returns the base type of the Typedef."""
        return self if self is Typedef.UNKNOWN else Typedef(self.value & Typedef._TYPEMASK)
    #
    def is_int(self) -> bool:
        return self is not Typedef.UNKNOWN and (self & Typedef._TYPEMASK) is Typedef.INT
    def is_ptr(self) -> bool:
        return self is not Typedef.UNKNOWN and (self & Typedef._PTRMASK) is Typedef.PTR
    def is_float(self) -> bool:
        return self is not Typedef.UNKNOWN and (self & Typedef._TYPEMASK) is Typedef.FLOAT
    def is_string(self) -> bool:
        return self is not Typedef.UNKNOWN and (self & Typedef._TYPEMASK) is Typedef.STRING
    #
    def is_any(self) -> bool:
        return self is not Typedef.UNKNOWN and (self & Typedef._TYPEMASK) is Typedef.ANY
    def is_void(self) -> bool:
        return self is not Typedef.UNKNOWN and (self & Typedef._TYPEMASK) is Typedef.VOID or (self is Typedef.ANY_VOID)
    # def is_array(self) -> bool:
    #     return self is not Typedef.UNKNOWN and (Typedef.INT_ARRAY <= (self & Typedef._TYPEMASK) <= Typedef.STRING_ARRAY)
    #
    @property
    def is_numeric(self) -> bool: return (Typedef.INT <= self.basetype <= Typedef.FLOAT)
    @property
    def is_reference(self) -> bool: return (Typedef.STRING <= self.basetype <= Typedef.STRING_ARRAY)
    @property
    def is_primitive(self) -> bool: return (Typedef.INT <= self.basetype <= Typedef.STRING)
    @property
    def is_array(self) -> bool: return (Typedef.INT_ARRAY <= self.basetype <= Typedef.STRING_ARRAY)
    @property
    def element(self) -> 'Typedef':
        return Typedef(self.value - Typedef.INT_ARRAY.value) if self.is_array else self
    @property
    def array(self) -> 'Typedef':
        if self is Typedef.UNKNOWN: return None
        return Typedef(self.value + Typedef.INT_ARRAY.value) if self.is_primitive else self
    #
    #
    def to_mjotype(self, default:Any=None) -> 'MjoType':
        from .script.flags import MjoType
        base = self.basetype
        if Typedef.INT <= base <= Typedef.STRING_ARRAY:
            return MjoType(base.value)
        elif self is Typedef.UNKNOWN:
            return MjoType.UNKNOWN
        elif self is Typedef.INTERNAL:
            return MjoType.INTERNAL
        elif base is Typedef.VOID:
            return MjoType.VOID
        return default
    @classmethod
    def from_mjotype(cls, mjotype:'MjoType', default:Any=None) -> 'Typedef':
        from .script.flags import MjoType
        if MjoType.INT <= mjotype <= MjoType.STRING_ARRAY:
            return Typedef(mjotype.value)
        elif mjotype is MjoType.UNKNOWN:
            return Typedef.UNKNOWN
        elif mjotype is MjoType.INTERNAL:
            return Typedef.INTERNAL
        elif mjotype is MjoType.VOID:
            return Typedef.VOID
        return default
    
    @property
    def postfix(self) -> str:
        if self is Typedef.INTERNAL:
            return self._POSTFIXES_ALT[self]  # INTERNAL only has an alt type since we still don't really understand it
        return self._POSTFIXES[self]
    @classmethod
    def frompostfix(cls, postfix:str, default:Any=..., *, allow_unk:bool=False, allow_alt:bool=False) -> 'Typedef':
        if not allow_unk and postfix == Typedef.UNKNOWN.postfix:
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
    def frompostfix_name(cls, fullname:str, default:Any=..., *, allow_unk:bool=False, allow_alt:bool=False) -> 'Typedef':
        postfix = postfixsymbol(fullname)
        return cls.frompostfix(postfix, default, allow_unk=allow_unk, allow_alt=allow_alt)

# Typedef:
Typedef._POSTFIXES = {
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    Typedef.UNKNOWN:      mj_name.DOC_POSTFIX_UNKNOWN,  # '?'
    #
    Typedef.INT:          mj_name.POSTFIX_INT,          # ''
    Typedef.FLOAT:        mj_name.POSTFIX_FLOAT,        # '%'
    Typedef.STRING:       mj_name.POSTFIX_STRING,       # '$'
    Typedef.INT_ARRAY:    mj_name.POSTFIX_INT_ARRAY,    # '#'
    Typedef.FLOAT_ARRAY:  mj_name.POSTFIX_FLOAT_ARRAY,  # '%#'
    Typedef.STRING_ARRAY: mj_name.POSTFIX_STRING_ARRAY, # '$#'
    #
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    Typedef.ANY:          mj_name.POSTFIX_ANY,          # ''
    Typedef.VOID:         mj_name.POSTFIX_VOID,         # ''
    Typedef.INTERNAL:     mj_name.POSTFIX_INTERNAL,     # '~'
}
Typedef._POSTFIXES_ALT = {
    #NOTE: legacy float type prefix '!', observed with 3 syscalls: 
    #       * $46b18379 "$rand!@MAJIRO_INTER"         (still present)
    #       * $2cd009af "$dim_create!#@MAJIRO_INTER"  (removed in releases after Mahjong [v1509])
    #       * $20caeb0e "$dim_release!#@MAJIRO_INTER" (removed in releases after Mahjong [v1509])
    Typedef.FLOAT:        mj_name.LEGACY_POSTFIX_FLOAT,       # '!'
    Typedef.FLOAT_ARRAY:  mj_name.LEGACY_POSTFIX_FLOAT_ARRAY, # '!#'
    #
    # #NOTE: WHAT THE HELL!??
    # #      observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision.
    # #      it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe.
    # Typedef.INTERNAL:     mj_name.POSTFIX_INTERNAL,     # '~'
}
Typedef._POSTFIX_LOOKUP = dict((v,k) for k,v in Typedef._POSTFIXES.items() if k is not Typedef.VOID)
Typedef._POSTFIX_ALT_LOOKUP = dict((v,k) for k,v in Typedef._POSTFIXES_ALT.items())

# IdentifierKind:
IdentifierKind._PREFIXES = {
    #NOTE: not a real scope flag <INTERNAL USE ONLY>
    IdentifierKind.UNKNOWN:    '',
    #
    IdentifierKind.PERSISTENT: mj_name.PREFIX_PERSISTENT, # '#'
    IdentifierKind.SAVEFILE:   mj_name.PREFIX_SAVEFILE,   # '@'
    IdentifierKind.THREAD:     mj_name.PREFIX_THREAD,     # '%'
    IdentifierKind.LOCAL:      mj_name.PREFIX_LOCAL,      # '_'
    # #NOTE: not a real scope flag <INTERNAL USE ONLY>
    IdentifierKind.FUNCTION:   mj_name.PREFIX_FUNCTION,   # '$'
    IdentifierKind.SYSCALL:    mj_name.PREFIX_FUNCTION,   # '$'
    IdentifierKind.CALLBACK:   '',
}
IdentifierKind._PREFIX_LOOKUP = dict((v,k) for k,v in IdentifierKind._PREFIXES.items() if k not in (IdentifierKind.SYSCALL, IdentifierKind.CALLBACK))

#endregion

#region ## FLAG NAME DICTIONARIES ##

# #TODO: is there really any need to be using OrderedDict's here?

# # Typedef:
# Typedef._NAMES:Dict[Typedef,str] = {
#     Typedef.INT:          'int',
#     Typedef.FLOAT:        'float',
#     Typedef.STRING:       'string',
#     Typedef.INT_ARRAY:    'intarray',
#     Typedef.FLOAT_ARRAY:  'floatarray',
#     Typedef.STRING_ARRAY: 'stringarray',
# }
# Typedef._ALIASES:Dict[Typedef,str] = {
#     Typedef.INT:          'i',
#     Typedef.FLOAT:        'r',
#     Typedef.STRING:       's',
#     Typedef.INT_ARRAY:    'iarr',
#     Typedef.FLOAT_ARRAY:  'rarr',
#     Typedef.STRING_ARRAY: 'sarr',
# }
# Typedef._LOOKUP:Dict[str,Typedef] = dict((v,k) for k,v in chain(Typedef._NAMES.items(), Typedef._ALIASES.items()))

# Typedef._POSTFIXES:Dict[Typedef,str] = {
#     #NOTE: not a real type flag <INTERNAL USE ONLY>
#     Typedef.UNKNOWN:      '?',
#     #
#     Typedef.INT:          '',
#     Typedef.FLOAT:        '%',
#     Typedef.STRING:       '$',
#     Typedef.INT_ARRAY:    '#',
#     Typedef.FLOAT_ARRAY:  '%#',
#     Typedef.STRING_ARRAY: '$#',
# }
# Typedef._POSTFIXES_ALT:Dict[Typedef,str] = {
#     #NOTE: WHAT THE HELL!??
#     #      observed for syscall: $46b18379 "$rand!@MAJIRO_INTER", which returns a float between 0 and 1 (DOUBLE??)
#     Typedef.FLOAT:        '!',
#     #Typedef.FLOAT_ARRAY:  '!#',
#     #
#     #NOTE: WHAT THE HELL!??
#     #      observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision.
#     #      it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe.
#     Typedef.INTERNAL:     '~',
# }
# Typedef._POSTFIX_LOOKUP:Dict[str,Typedef] = dict((v,k) for k,v in chain(Typedef._POSTFIXES.items(), Typedef._POSTFIXES_ALT.items()))
# # Typedef._POSTFIX_LOOKUP:Dict[str,Typedef] = dict((v,k) for k,v in Typedef._POSTFIXES.items())
# # Typedef._POSTFIX_ALT_LOOKUP:Dict[str,Typedef] = dict((v,k) for k,v in Typedef._POSTFIXES_ALT.items())

# Typedef._PYTHON_TYPES:Dict[Typedef,type] = {
#     #NOTE: not a real type flag <INTERNAL USE ONLY>
#     Typedef.UNKNOWN:      object,  # any type
#     #
#     Typedef.INT:          int,
#     Typedef.FLOAT:        float,
#     Typedef.STRING:       str,
#     Typedef.INT_ARRAY:    list,
#     Typedef.FLOAT_ARRAY:  list,
#     Typedef.STRING_ARRAY: list,
#     #
#     Typedef.ANY:          object,
#     Typedef.VOID:         type(None),
# }

#endregion


def verify(hash:int, text:Union[str,bytes], init:int=0) -> bool:
    """verify(0x1d128f30, '$main@GLOBAL') -> True
    verify(0xdeadbeaf, '$main@GLOBAL') -> False

    verify that the input text data results in the given CRC-32 hash.
    """
    from .crypt import hash32
    return hash == hash32(text, init)

# class hexint(int):
#     """Hexadecimal integer representation as: '{self:#x}'"""
#     def __str__(self) -> str: return f'{self:#08x}'
#     __repr__ = __str__

# class hexint8(int):
#     """Hexadecimal 8-bit integer representation as: '{self:#02x}'"""
#     def __str__(self) -> str: return f'{self:#02x}'
#     __repr__ = __str__

# class hexint16(int):
#     """Hexadecimal 16-bit integer representation as: '{self:#04x}'"""
#     def __str__(self) -> str: return f'{self:#04x}'
#     __repr__ = __str__

# class hexint32(int):
#     """Hexadecimal 32-bit integer representation as: '{self:#08x}'"""
#     def __str__(self) -> str: return f'{self:#08x}'
#     __repr__ = __str__

# class hexint64(int):
#     """Hexadecimal 64-bit integer representation as: '{self:#016x}'"""
#     def __str__(self) -> str: return f'{self:#016x}'
#     __repr__ = __str__

class HashValue(int):
    """HashValue(int)

    this class is an immutable int wrapper
    """
    def __new__(cls, value:int):
        if type(value) is cls and cls is HashValue:
            return value  # return same instance
        return super().__new__(cls, value & 0xffffffff)

    #region ## PROPERTIES TO MATCH HashName ##

    @property
    def hash(self) -> int:            return self
    @property
    def name(self) -> Optional[str]:  return None
    @property
    def kind(self) -> IdentifierKind: return IdentifierKind.UNKNOWN

    #endregion

    #region ## INT REPR OVERRIDE ##

    def __repr__(self) -> str: return f'0x{self:08x}'
    def __str__(self) -> str:  return f'0x{self:08x}'

    #endregion

    #region ## HASH DATABASE LOOKUP ##

    # variables:
    def lookup_local(self) -> Optional[str]:
        from .database.hashes import LOCAL_VARS
        return LOCAL_VARS.get(self)
    def lookup_thread(self) -> Optional[str]:
        from .database.hashes import THREAD_VARS
        return THREAD_VARS.get(self)
    def lookup_savefile(self) -> Optional[str]:
        from .database.hashes import SAVEFILE_VARS
        return SAVEFILE_VARS.get(self)
    def lookup_persistent(self) -> Optional[str]:
        from .database.hashes import PERSISTENT_VARS
        return PERSISTENT_VARS.get(self)
    def lookup_var(self) -> Optional[str]:
        from .database.hashes import VARIABLES
        return VARIABLES.get(self)

    def lookup_varkind(self) -> Optional[str]:
        name = self.lookup_local()
        if name is not None: return (name, IdentifierKind.LOCAL)
        name = self.lookup_thread()
        if name is not None: return (name, IdentifierKind.THREAD)
        name = self.lookup_savefile()
        if name is not None: return (name, IdentifierKind.SAVEFILE)
        name = self.lookup_persistent()
        if name is not None: return (name, IdentifierKind.PERSISTENT)
        return (None, IdentifierKind.UNKNOWN)

    # functions:
    def lookup_function(self) -> Optional[str]:
        from .database.hashes import FUNCTIONS
        return FUNCTIONS.get(self)
    def lookup_syscall(self) -> Optional[str]:
        from .database.hashes import SYSCALLS
        name = SYSCALLS.get(self)
        return None if name is None else joingroup(name, GROUP_SYSCALL)
    def lookup_func(self) -> Optional[str]:
        return self.lookup_function() or self.lookup_syscall()

    def lookup_funckind(self) -> Tuple[Optional[str], IdentifierKind]:
        name = self.lookup_function()
        if name is not None: return (name, IdentifierKind.FUNCTION)
        name = self.lookup_syscall()
        if name is not None: return (name, IdentifierKind.SYSCALL)
        return (None, IdentifierKind.UNKNOWN)

    # callbacks:
    def lookup_callback(self) -> Optional[str]:
        from .database.hashes import CALLBACKS
        return CALLBACKS.get(self)
    def lookup_cbkind(self) -> Tuple[Optional[str], IdentifierKind]:
        name = self.lookup_callback()
        if name is not None: return (name, IdentifierKind.CALLBACK)
        return (None, IdentifierKind.UNKNOWN)

    # any:
    def lookup(self) -> Optional[str]:
        return self.lookup_var() or self.lookup_func() or self.lookup_callback()
    def lookupkind(self) -> Tuple[Optional[str], IdentifierKind]:
        name, kind = self.lookup_varkind()
        if name is not None: return (name, kind)
        name, kind = self.lookup_funckind()
        if name is not None: return (name, kind)
        name, kind = self.lookup_cbkind()
        if name is not None: return (name, kind)
        # name = self.lookup_callback()
        # if name is not None: return (name, IdentifierKind.CALLBACK)
        return (None, IdentifierKind.UNKNOWN)

    #endregion


class HashName:
    """HashName(value:Union[int,str], kind:IdentifierKind=...)

    this class is immutable
    """
    __slots__ = ('hash', 'name', 'kind')
    hash:HashValue
    name:Optional[str]
    kind:IdentifierKind
    
    def __init__(self, value:Union[int,str], kind:IdentifierKind=..., *, group:Optional[str]=None, hash:Optional[int]=None, lookup:bool=False):
        if isinstance(value, HashName):
            self.name = value.name
            self.hash = value.hash
            self.kind = value.kind if kind is Ellipsis else kind
        elif isinstance(value, str):
            from .crypt import to_hash32
            name = joingroup(value, group)

            # try to determine identifier type
            if kind is Ellipsis and name:
                idx = '#@%_$'.find(name[0])
                kind = IdentifierKind(idx) if (idx != -1) else IdentifierKind.CALLBACK
                if kind is IdentifierKind.FUNCTION and groupname(name) == GROUP_SYSCALL:
                    kind = IdentifierKind.SYSCALL
            # special implicit group handling
            if not hasgroup(name):
                if kind is IdentifierKind.SYSCALL:
                    name = joingroup(name, GROUP_SYSCALL)
                elif kind is IdentifierKind.LOCAL:
                    name = joingroup(name, GROUP_LOCAL)
                # elif lookup:
                #     # lookup names for all groups
                #     hashname, hashkind = 
            self.name = name
            self.hash = HashValue(to_hash32(value) if hash is None else hash)
            self.kind = IdentifierKind(kind)
        elif isinstance(value, int):
            self.hash = HashValue(value)
            if lookup:
                name, hashkind = self.hash.lookupkind()
                if kind is Ellipsis:
                    kind = hashkind
            else:
                name = None
            self.name = name
            self.kind = IdentifierKind.UNKNOWN if kind is Ellipsis else IdentifierKind(kind)
        else:
            raise TypeError(f'{self.__class__.__name__} argument value must be int or str, not {value.__class__.__name__}')

    #region ## IMMUTABLE ##

    def __setattr__(self, name, value):
        if hasattr(self, name):
            raise AttributeError(f'{name!r} attribute is readonly')
        super().__setattr__(name, value)

    #endregion

    #region ## PROPERTIES ##

    @property
    def value(self) -> Union[HashValue,str]: return self.hash if self.name is None else self.name

    #endregion

    #region ## SPECIAL METHODS ##

    def __int__(self) -> HashValue: return self.hash

    def __hash__(self) -> int: return self.hash
    def __eq__(self, other) -> bool:
        return (other is not None) and hasattr(other, '__int__') and (self.hash == int(other))
    def __ne__(self, other) -> bool:
        return (other is None) or not hasattr(other, '__int__') or (self.hash != int(other))

    def __str__(self) -> str: return f'0x{self.hash:08x}' if self.name is None else self.name
    def __repr__(self) -> str:
        kind = '' if self.kind is IdentifierKind.UNKNOWN else f', {self.kind!s}'
        if self.name is None:
            return f'{self.__class__.__name__}(0x{self.hash:08x}{kind})'
        else:
            return f'{self.__class__.__name__}({self.name!r}{kind})'

    #endregion


#######################################################################################

# class Identifier:
#     """Identifier(name:str, *, group:Optional[str]=None, doc:Optional[str]=None)

#     if name contains a '@' after the first character, group will be ignored
#     """
#     __slots__ = ('name', 'group', 'scope', 'type', 'doc')
#     name:str
#     group:Optional[str]
#     scope:IdentifierKind
#     type:Typedef
#     doc:Optional[str]
    
#     # group will be resolved from name if found
#     def __init__(self, name:str, *, group:Optional[str]=None, doc:Optional[str]=None):
#         name, namegroup = splitgroup(name)
#         self.name = name
#         self.group = group if namegroup is None else namegroup
#         self.scope = IdentifierKind.UNKNOWN
#         self.type = Typedef.UNKNOWN
#         self.doc = doc


#         if group and group[0] == '@':
#             raise ValueError(f'group must not contain \'@\' separator, got {group}')

#         # # realistically identifiers should have at least two chars before group
#         # base,group = splitgroup(name)
#         # at_idx = name.find('@', 1)
#         # if at_idx != -1: # group override from default
#         #     self.group = name[at_idx+1:]
#         #     self.name  = name[:at_idx]

#         # get scope / function:
#         self.scope = IdentifierKind.fromprefix_name(self.name, allow_unk=True)
#         # get type / return type:
#         self.type = Typedef.frompostfix_name(self.name, allow_unk=True, allow_alt=True)

#     @property
#     def fullname(self) -> str:
#         return self.name if self.group is None else f'{self.name}@{self.group}'
#     @property
#     def prefix(self) -> str:
#         return self.scope.prefix
#     @property
#     def postfix(self) -> str:
#         # dumb hack to handle '!' float alias postfix
#         return self.name[-len(self.type.postfix):]  # return self.type.postfix
#     @property
#     def basename(self) -> str:
#         return self.name[len(self.scope.prefix):-len(self.type.postfix)]
#     @property
#     def basename_noscope(self) -> str:
#         return self.name[len(self.scope.prefix):]
#     @property
#     def basename_notype(self) -> str:
#         return self.name[:-len(self.type.postfix)]
#     @property
#     def is_func(self) -> bool:
#         return self.scope.is_func #(self.scope is MjoScope.FUNCTION)
#     @property
#     def is_var(self) -> bool:
#         return self.scope.is_var #(MjoScope.PERSISTENT <= self.scope <= MjoScope.LOCAL)
#     @property
#     def is_array(self) -> bool: return self.type.is_array #(MjoType.INT_ARRAY <= self.type <= MjoType.STRING_ARRAY)
#     @property
#     def hash(self) -> int:
#         from .crypt import hash32
#         return hash32(self.fullname)
#     @property
#     def hashstr(self) -> str: return f'${self.hash:08x}'
#     @property
#     def definition_keyword(self) -> str: return ''

#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.fullname!r})'
#     def __str__(self) -> str:
#         return self.fullname

# #######################################################################################

# class VariableSig(Identifier):
#     __slots__ = Identifier.__slots__
#     def __init__(self, name:str, *, group:Optional[str]=None, doc:Optional[str]=None):
#         super().__init__(name, group=group, doc=doc)

#     @property
#     def definition_keyword(self) -> str:
#         return 'var'
#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.fullname!r})'
#     def __str__(self) -> str:
#         return f'{self.definition_keyword} {self.fullname}'

# class LocalSig(VariableSig):
#     __slots__ = VariableSig.__slots__
#     def __init__(self, name:str, *, doc:Optional[str]=None):
#         super().__init__(name, group=GROUP_LOCAL, doc=doc) # local group
#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.fullname!r})'
#     def __str__(self) -> str:
#         return f'{self.definition_keyword} {self.name}'

# #######################################################################################

# class ArgumentSig(LocalSig):
#     __slots__ = LocalSig.__slots__ + ('optional', 'variadic', 'default', 'tuple_last')
#     optional:bool
#     variadic:bool
#     default:Optional[str]
#     tuple_last:bool

#     def __init__(self, name:str, *, optional:bool=False, variadic:bool=False, default:Optional[str]=None, tuple_last:bool=False, doc:Optional[str]=None):
#         super().__init__(name, doc=doc) # local group
#         self.optional = optional
#         self.variadic = variadic
#         self.default = default
#         self.tuple_last = tuple_last
#     #
#     @property
#     def definition_keyword(self) -> str: return ''  # set back to empty
#     @property
#     def is_optional(self) -> bool: return self.optional  # alias to conform with naming
#     @property
#     def is_variadic(self) -> bool: return self.variadic  # alias to conform with naming
#     @property
#     def is_tuple_last(self) -> bool: return self.tuple_last  # alias to conform with naming
#     @property
#     def has_default(self) -> bool: return self.default is not None
#     @property
#     def default_repr(self) -> str: return '' if self.default is None else f' = {self.default}'
#     @property
#     def va_name(self) -> str: return f'...{self.name}' if self.variadic else self.name
#     @property
#     def default_name(self) -> str: return self.name if self.default is None else f'{self.name} = {self.default}'
#     #
#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.fullname!r}, optional={self.optional!r}, variadic={self.variadic!r}, default={self.default!r}, tuple_last={self.tuple_last!r})'
#     def __str__(self) -> str:
#         return f'[{self.va_name}]' if self.is_optional else self.va_name



# class FunctionSig(Identifier):
#     __slots__ = Identifier.__slots__ + ('is_void', '_arguments')
#     is_void:Optional[bool]
#     _ARG_TYPE = ArgumentSig

#     _RE_EOL         = re.compile(r"^(\s*)$")
#     _RE_WHITESPACE  = re.compile(r"^(\s+)")
#     _RE_VARIADIC    = re.compile(r"^(\.\.\.)")
#     _RE_PUNCTUATION = re.compile(r"^([(){}\[\],])")
#     _RE_DEFAULT     = re.compile(r"^=\s*(\"(?:\\.|[^\"])*\"|[_@#$%!?~.\-+'A-Za-z_0-9]+\*?(?:\([^)]*\))?)")
#     _RE_ARGUMENT    = re.compile(r"^([_@#$%!?~A-Za-z_][_@#$%!?~A-Za-z_0-9]*\*?)")
#     _RE_SET = ( _RE_EOL,
#                 _RE_WHITESPACE,
#                 _RE_VARIADIC,
#                 _RE_PUNCTUATION,
#                 _RE_DEFAULT,
#                 _RE_ARGUMENT )

#     def __init__(self, name:str, arguments:Union[List[ArgumentSig],str]=(), *, is_void:Optional[bool]=None, group:Optional[str]=None, doc:Optional[str]=None):
#         super().__init__(name, group=group, doc=doc)
#         self.is_void = is_void
#         self._arguments = []  # type: Union[List[ArgumentSig],str]
#         if arguments is None:
#             pass
#         elif isinstance(arguments, str):
#             self._arguments = arguments  # lazy parsing once requested
#         else:
#             self._arguments = list(arguments)

#     @property
#     def arguments(self) -> List[ArgumentSig]:
#         """handle lazy exanding (parsing) of arguments."""
#         if self._arguments is None:
#             return None
#         elif isinstance(self._arguments, str):
#             self._arguments = self.parse_arguments(self._arguments)
#             return 
#         else:
#             return self._arguments

#     def add_argument(self, arg:Union[str,ArgumentSig], *, optional:bool=..., variadic:bool=..., default:str=..., doc:str=...):
#         if isinstance(arg, self._ARG_TYPE):
#             if optional is Ellipsis: optional = arg.is_optional
#             if variadic is Ellipsis: variadic = arg.is_variadic
#             if default is Ellipsis:  default = arg.default
#             if doc is Ellipsis:      doc = arg.doc
#         else:
#             if optional is Ellipsis:
#                 optional = self._arguments[-1].is_optional if self._arguments else False
#             if variadic is Ellipsis:
#                 variadic = self._arguments[-1].is_variadic if self._arguments else False
#             if default is Ellipsis:  default = None
#             if doc is Ellipsis:      doc = None

#         if isinstance(arg, Identifier):
#             self._arguments.append(self._ARG_TYPE(arg.name, optional=optional, variadic=variadic, default=default, doc=doc))
#         else:
#             self._arguments.append(self._ARG_TYPE(arg, optional=optional, variadic=variadic, default=default, doc=doc))
#     def end_argument_tuple(self):
#         if self._arguments:
#             self._arguments[-1].tuple_last = True

#     # @property
#     # def return_type(self) -> FunctionReturn:
#     #     if self.is_void is None:
#     #         return FunctionReturn.UNKNOWN
#     #     return FunctionReturn.FUNC if self.is_void else FunctionReturn.VOID
#     @property
#     def has_optionals(self) -> bool:
#         if self._arguments is None: return None
#         any(a.is_optional for a in self.arguments)  # expand lazy arguments
#     @property
#     def has_variadics(self) -> bool:
#         if self._arguments is None: return None
#         any(a.is_variadic for a in self.arguments)  # expand lazy arguments
#     @property
#     def has_defaults(self) -> bool:
#         if self._arguments is None: return None
#         any(a.has_default for a in self.arguments)  # expand lazy arguments
#     @property
#     def has_arguments(self) -> bool:
#         if self._arguments is None:
#             return None
#         elif isinstance(self._arguments, str):
#             if self._arguments.strip().startswith('?'):
#                 return None  # unknown
#             return self._arguments.strip() not in ('', 'void')
#         else:
#             return bool(self._arguments)
#     @property
#     def definition_keyword(self) -> str: return 'void' if self.is_void is False else 'func'  # only use void when confirmed(?)

#     @property
#     def args_str(self) -> str:
#         if self._arguments is None:
#             return '???'
#         if isinstance(self._arguments, str):
#             return self._arguments
#         if not self._arguments:
#             return 'void'
#         arg_spans = []  # type: List[Tuple[bool, str, list]]  # optional, variadic ('...' or ''), *args:List[str]
#         optional = self._arguments[0].is_optional
#         variadic = self._arguments[0].is_variadic
#         arg_spans.append( (optional, '...' if variadic else '', []) )
#         last_arg = None
#         for arg in self._arguments:
#             if (last_arg and getattr(last_arg, 'tuple_last', False)) or arg.is_optional != optional or arg.is_variadic != variadic:
#                 arg_spans.append( (arg.is_optional, '...' if arg.is_variadic else '', []) )
#                 optional = arg.is_optional
#                 variadic = arg.is_variadic
#             arg_spans[-1][-1].append(getattr(arg, 'default_name', arg.name))
#             last_arg = arg
#         return ', '.join(('[{}{}]' if opt else '{}{}').format(var, ', '.join(args)) for opt,var,args in arg_spans)

#     @property
#     def args_repr(self) -> str:
#         if self._arguments is None:
#             return None
#         elif isinstance(self._arguments, str):
#             return self._arguments
#         else:
#             return self.args_str

#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.fullname!r}, {self.args_repr!r}, is_void={self.is_void!r})'
#     def __str__(self) -> str:
#         return f'{self.definition_keyword} {self.fullname}({self.args_str})'

#     def parse_arguments(self, text:str) -> List[ArgumentSig]:
#         self._arguments = []
#         if text is None or text.strip() in ('', 'void'):
#             return  # no arguments :)

#         last_s        = None  # type: str
#         last_p        = None  # type: Pattern
#         optional      = variadic      = False
#         next_optional = next_variadic = False
#         next_arg      = next_default  = None

#         def commit_arg():
#             self.add_argument(next_arg, optional=next_optional, variadic=next_variadic, default=next_default)
#             if not optional:
#                 self.end_argument_tuple()

#         eol = False
#         pos = 0
#         while not eol:
#             m = None
#             for p in self._RE_SET:
#                 m = p.search(text[pos:])
#                 if not m:
#                     continue
#                 s = m[1]
#                 if p is self._RE_EOL:
#                     pos += m.end()
#                     if last_s is not None and last_s in (',', '...', '['):
#                         raise ValueError(f'Unexpected <EOL> after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     elif optional:
#                         raise ValueError(f'Unexpected unclosing optional \'[\' in function arguments {text!r} at char {(pos+2)}')
#                     eol = True
#                     variadic = False
#                     #region ## COMMIT ARG ##
#                     if last_p in (self._RE_ARGUMENT, self._RE_DEFAULT):
#                         commit_arg()
#                         next_optional = next_variadic = False
#                         next_arg = next_default = None
#                     #endregion
#                     break
#                 elif p is self._RE_WHITESPACE:
#                     pos += m.end() # completely ignore
#                     break
#                 elif p is self._RE_ARGUMENT:
#                     if last_s is not None and last_s not in (',', '[', '...'):
#                         raise ValueError(f'Unexpected argument {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     next_arg = s
#                     next_optional = optional
#                     next_variadic = next_variadic or variadic
#                 elif p is self._RE_DEFAULT:
#                     if last_p is not self._RE_ARGUMENT:
#                         raise ValueError(f'Unexpected default value {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     next_default = s
#                 #else: #if p is RE_PUNCTUATION:
#                 elif s == '...':
#                     if last_s is not None and last_s not in (',', '['):
#                         raise ValueError(f'Unexpected variadic {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     next_variadic = True
#                     variadic = True
#                 elif s == '[':
#                     if optional:
#                         raise ValueError(f'Unexpected nested {s!r} in function arguments {text!r} at char {(pos+2)}')
#                     elif last_s is not None and last_s not in (','):
#                         raise ValueError(f'Unexpected punctuation {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     optional = True
#                     variadic = False
#                     if last_s is not None:
#                         self.end_argument_tuple()
#                 elif s == ']':
#                     if not optional:
#                         raise ValueError(f'Unexpected unmatched closing {s!r} in function arguments {text!r} at char {(pos+2)}')
#                     elif last_s is None or last_p not in (self._RE_ARGUMENT, self._RE_DEFAULT):
#                         raise ValueError(f'Unexpected closing {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     optional = variadic = False  # variadic continues inside [] tuples
#                     #region ## COMMIT ARG ##
#                     if last_p in (self._RE_ARGUMENT, self._RE_DEFAULT):
#                         commit_arg()
#                         next_optional = next_variadic = False
#                         next_arg = next_default = None
#                     #endregion
#                 elif s == ',':
#                     if last_s is None or last_s in (',', '[', '...'):
#                         raise ValueError(f'Unexpected closing {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
#                     variadic = variadic and optional  # variadic continues inside [] tuples
#                     #region ## COMMIT ARG ##
#                     if last_p in (self._RE_ARGUMENT, self._RE_DEFAULT):
#                         commit_arg()
#                         next_optional = next_variadic = False
#                         next_arg = next_default = None
#                     #endregion
#                 else:
#                     raise ValueError(f'Unexpected punctuation {s!r} in function arguments {text!r} at char {(pos+2)}')
                    
#                 pos += m.end()
#                 last_s = s
#                 last_p = p
#                 break
#             if m is None:
#                 raise ValueError(f'Failed to match function arguments {text!r} at char {(pos+2)}')

#         return self._arguments

# #######################################################################################

# class SyscallArgumentSig(ArgumentSig):
#     __slots__ = ArgumentSig.__slots__ + ('any', 'orig_name')
#     any:bool
#     orig_name:str

#     def __init__(self, name:str, *, optional:bool=False, variadic:bool=False, default:Optional[str]=None, tuple_last:bool=False, doc:Optional[str]=None):
#         self.any = name[-1] == '*' if name else False
#         self.orig_name = name
#         name = f'_{(name[:-1] if self.any else name)}'
#         super().__init__(name, optional=optional, variadic=variadic, default=default, tuple_last=tuple_last, doc=doc) # local group

#     @property
#     def is_any(self) -> bool: return self.any  # alias to conform with naming
#     @property
#     def default_name(self) -> str: return self.orig_name if self.default is None else f'{self.orig_name} = {self.default}'
#     @property
#     def va_name(self) -> str: return f'...{self.orig_name}' if self.variadic else self.orig_name

#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.orig_name!r}, optional={self.optional!r}, variadic={self.variadic!r}, default={self.default!r}, tuple_last={self.tuple_last!r})'
#     def __str__(self) -> str:
#         return f'[{self.va_name}{self.default_repr}]' if self.is_optional else f'{self.va_name}{self.default_repr}'

# class SyscallSig(FunctionSig):
#     __slots__ = FunctionSig.__slots__
#     _ARG_TYPE = SyscallArgumentSig

#     def __init__(self, name:str, arguments:Union[List[SyscallArgumentSig],str]=(), *, is_void:Optional[bool]=None, doc:Optional[str]=None):
#         self._arguments = [] # type: Union[List[SyscallArgumentSig],str]
#         super().__init__(name, arguments, is_void=is_void, group=GROUP_SYSCALL, doc=doc)

#     @property
#     def definition_keyword(self) -> str: return f'inter {super().definition_keyword}'

#     def __repr__(self) -> str:
#         return f'{self.__class__.__name__}({self.name!r}, {self.args_repr!r}, is_void={self.is_void!r})'
#     def __str__(self) -> str:
#         return f'{self.definition_keyword} {self.name}({self.args_str})'


#######################################################################################

del enum, Any, Optional, Tuple, Union  # cleanup declaration-only imports
