#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Utility methods for parsing, spliting, checking, and working with Majiro identifier name strings.

this module is designed to function similarly to the `os.path` module functions.
"""

__version__ = '1.0.0'
__date__    = '2021-05-07'
__author__  = 'Robert Jordan'

__all__ = ['GROUP_LOCAL', 'GROUP_DEFAULT', 'GROUP_SYSCALL', 'chgroup', 'joingroup', 'splitgroup', 'basename', 'groupname', 'hasgroup', 'splitsymbols', 'joinsymbols', 'splitprefix', 'splitpostfix', 'prefixsymbol', 'postfixsymbol', 'hasfullqual', 'hasbasequal', 'hasprefix', 'haspostfix']

#######################################################################################

import string
from typing import List, Optional, Tuple


#region ## PUBLIC CONSTANTS ##

# standard group names
GROUP_LOCAL:str   = ''
GROUP_DEFAULT:str = 'GLOBAL'
GROUP_SYSCALL:str = 'MAJIRO_INTER'

#endregion

#region ## GROUP CONSTANTS ##

# # function name used calculate hashes in GROUPS lookup dictionary
# GROUP_HASHNAME:str = '$main'
# separator character between name / group
GROUP_SEP:str = '@'
# minimum index to search for group separator character '@' at
MIN_GROUP_IDX:int = 2 #1

#endregion

#region ## PREFIX/POSTFIX SYMBOL CONSTANTS ##

# set of all known prefixes/postfixes
PREFIXES:List[str]  = ('#','@','%','_','$')
POSTFIXES:List[str] = ('', '%', '$', '#', '%#', '$#',  '!','~',  '?','*')
# used for documentation:
#   unknown: '?'
#  any type: '*'
DOC_POSTFIXES:List[str] = POSTFIXES + ('?','*')

# string of all known prefix/postfix/symbol chars
PREFIX_CHARS:str  = '#$%@_'
POSTFIX_CHARS:str = '#$%!~'
SYMBOL_CHARS:str  = '#$%@_!~'

# string of all known prefix/postfix/symbol chars
#  (with documentation-exclusive characters '?' and '*')
DOC_CHARS:str     = '?*'
DOC_POSTFIX_CHARS:str = POSTFIX_CHARS + DOC_CHARS
DOC_SYMBOL_CHARS:str  = '#$%@_!~' + DOC_CHARS

# string of all known characters that are legal in stripped names, and base names with prefixes/postfixes
NAME_CHARS:str = string.digits + string.ascii_uppercase + '_' + string.ascii_lowercase
FULLNAME_CHARS:str = string.digits + string.ascii_uppercase + string.ascii_lowercase + SYMBOL_CHARS  #NOTE: SYMBOL_CHARS already contains '_'
# string of all known cahracters that are legal in base names with prefixes/postfixes
#  (with documentation-exclusive characters '?' and '*')
DOC_FULLNAME_CHARS:str = FULLNAME_CHARS + DOC_CHARS

#endregion

#######################################################################################

#region ## NAME/GROUP HELPER FUNCTIONS ##

def chgroup(name:str, group:Optional[str], *, min_idx:int=...) -> str:
    """chgroup('$main@HELLO', 'WORLD') -> '$main@WORLD'
    chgroup('@page_back', 'GLOBAL') -> '@page_back@GLOBAL'
    chgroup('#save_info$@GLOBAL', None) -> '#save_info$'

    change the group in `name`, or add one if one doesn't exist.
    when `group` is None, the group is removed from `name`.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'chgroup() argument name must be str object, not {name.__class__.__name__}')
    if group is not None:
        if not isinstance(group, str):
            raise TypeError(f'chgroup() argument group must be str object or None, not {group.__class__.__name__}')
        elif GROUP_SEP in group:
            raise ValueError(f'chgroup() argument group cannot contain {GROUP_SEP!r} character, got {group!r}')

    at_idx = name.rfind(GROUP_SEP, MIN_GROUP_IDX if min_idx is Ellipsis else min_idx)
    if at_idx != -1:
        name = name[:at_idx]
    return name if group is None else f'{name}{GROUP_SEP}{group}'

def joingroup(name:str, group:Optional[str], *, min_idx:int=...) -> str:
    """joingroup('$main', 'GLOBAL') -> '$main@GLOBAL'
    joingroup('$main@HELLO', 'WORLD') -> '$main@HELLO'
    joingroup('#save_info$', None) -> '#save_info$'

    combine a `name` with the specified `group`.
    unlike `chgroup()`, the `group` argument will not be used if `name` is already fully-qualified.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'joingroup() argument name must be str object, not {name.__class__.__name__}')
    if group is None:
        return name
    elif not isinstance(group, str):
        raise TypeError(f'joingroup() argument group must be str object or None, not {group.__class__.__name__}')
    elif GROUP_SEP in group:
        raise ValueError(f'joingroup() argument group cannot contain {GROUP_SEP!r} character, got {group!r}')

    at_idx = name.rfind(GROUP_SEP, MIN_GROUP_IDX if min_idx is Ellipsis else min_idx)
    return name if (at_idx != -1) else (name if group is None else f'{name}{GROUP_SEP}{group}')

def splitgroup(fullname:str, default:Optional[str]=None, *, min_idx:int=...) -> Tuple[str, Optional[str]]:
    """splitgroup('$main@GLOBAL') -> ('$main', 'GLOBAL')
    splitgroup('_xy@') -> ('_xy', '')
    splitgroup('@page_back') -> ('@page_back', None)
    splitgroup('@page_back', 'MYGROUP') -> ('@page_back', 'MYGROUP')

    split a name into it's basename and group parts.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'splitgroup() argument fullname must be str object, not {fullname.__class__.__name__}')
    if default is not None and GROUP_SEP in default:
        raise ValueError(f'splitgroup() argument default cannot contain {GROUP_SEP!r} character, got {default!r}')

    at_idx = fullname.rfind(GROUP_SEP, MIN_GROUP_IDX if min_idx is Ellipsis else min_idx)
    return (fullname[:at_idx], fullname[at_idx+1:]) if (at_idx != -1) else (fullname, default)

def basename(fullname:str, *, min_idx:int=...) -> str:
    """basename('$main@GLOBAL') -> '$main'
    basename('_xy@') -> '_xy'
    basename('@page_back') -> '@page_back'

    return the base name without a group attached.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'basename() argument fullname must be str object, not {fullname.__class__.__name__}')

    at_idx = fullname.rfind(GROUP_SEP, MIN_GROUP_IDX if min_idx is Ellipsis else min_idx)
    return fullname[:at_idx] if (at_idx != -1) else fullname

def groupname(fullname:str, *, min_idx:int=...) -> Optional[str]:
    """groupname('$main@GLOBAL') -> 'GLOBAL'
    groupname('_xy@') -> ''
    groupname('@page_back') -> None

    return the group name without a base name attached.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'groupname() argument fullname must be str object, not {fullname.__class__.__name__}')

    at_idx = fullname.rfind(GROUP_SEP, MIN_GROUP_IDX if min_idx is Ellipsis else min_idx)
    return fullname[at_idx+1:] if (at_idx != -1) else None

def hasgroup(fullname:str, *, min_idx:int=...) -> bool:
    """hasgroup('$main@GLOBAL') -> True
    hasgroup('_xy@') -> True
    hasgroup('@page_back') -> False

    return True if a group is attached to `fullname`.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'hasgroup() argument fullname must be str object, not {fullname.__class__.__name__}')

    at_idx = fullname.rfind(GROUP_SEP, MIN_GROUP_IDX if min_idx is Ellipsis else min_idx)
    return at_idx != -1

#endregion

#######################################################################################

#region ## PREFIX/NAME/POSTFIX[/GROUP] HELPER FUNCTIONS ##

def splitsymbols(fullname:str, *, allow_doc:bool=False, min_idx:int=...) -> Tuple[Optional[str], str, Optional[str], Optional[str]]: #NameSymbols:
    """splitsymbols('$cos%@MAJIRO_INTER') -> ('$', 'cos', '%', 'MAJIRO_INTER')
    splitsymbols('$rand') -> ('$', 'rand', '', None)
    splitsymbols('hello#@WORLD') -> (None, 'hello', '#', 'WORLD')
    splitsymbols('hello#@WORLD') -> (None, 'hello', '#', 'WORLD')
    splitsymbols('') -> (None, '', None, None)
    splitsymbols('$') -> (None, '$', '', None)
    splitsymbols('$$') -> ('$', '$', '', None)
    splitsymbols('$$$') -> ('$', '$', '$', None)
    splitsymbols('$$$@') -> ('$', '$', '$', '')

    split a fully-qualified name between its prefix symbol, name, postfix symbol, and group parts.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'splitsymbols() argument fullname must be str object, not {fullname.__class__.__name__}')

    POSTFIXES_ = DOC_POSTFIXES if allow_doc else POSTFIXES

    prefix = postfix = None
    name, group = splitgroup(fullname, min_idx=min_idx)
    # namebase = name
    if len(name) > 1 and name[0] in PREFIXES:
        prefix, name = name[0], name[1:]
    if len(name) > 2 and name[-2:] in POSTFIXES_:
        name, postfix = name[:-2], name[-2:]
    elif len(name) > 1 and name[-1] in POSTFIXES_:
        name, postfix = name[:-1], name[-1]
    elif name:
        postfix = ''
    return (prefix, name, postfix, group)

def joinsymbols(prefix:Optional[str], name:str, postfix:Optional[str], group:Optional[str]=None, *, min_idx:int=...) -> str:
    """joinsymbols('$', 'cos', '%', 'MAJIRO_INTER') -> '$cos%@MAJIRO_INTER'
    joinsymbols('$', 'rand', '') -> '$rand'
    joinsymbols(None, 'rand', None, 'MAJIRO_INTER') -> 'rand@MAJIRO_INTER'

    join a prefix symbol, name, postfix symbol, and group into a fully-qualified name.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'joinsymbols() argument name must be str object, not {name.__class__.__name__}')
    if prefix is not None and not isinstance(prefix, str):
        raise TypeError(f'joinsymbols() argument prefix must be str object or None, not {prefix.__class__.__name__}')
    if postfix is not None and not isinstance(postfix, str):
        raise TypeError(f'joinsymbols() argument postfix must be str object or None, not {postfix.__class__.__name__}')
    return joingroup(f'{prefix or ""}{name}{postfix or ""}', group, min_idx=min_idx)


def splitprefix(name:str, *, min_idx:int=...) -> Tuple[Optional[str], str]:
    """splitprefix('$abs@MAJIRO_INTER') -> ('$', 'abs')
    splitprefix('$sin%') -> ('$', 'sin%')
    splitprefix('$rand') -> ('$', 'rand')
    splitprefix('rand') -> (None, 'rand')

    split a base name between the prefix symbol and name. (return name includes postfix symbol, if any)
    NOTE: this will automatically strip the group name.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'splitprefix() argument name must be str object, not {name.__class__.__name__}')

    name = basename(name, min_idx=min_idx)
    return (name[0], name[1:]) if (len(name) > 1 and name[0] in PREFIXES) else (None, name)

def splitpostfix(name:str, *, allow_doc:bool=False, min_idx:int=...) -> Tuple[str, Optional[str]]:
    """splitpostfix('$rand!@MAJIRO_INTER') -> ('$rand', '!')
    splitpostfix('$tan%') -> ('$tan', '%')
    splitpostfix('$rand') -> ('$rand', '')
    splitpostfix('_') -> ('_', '')
    splitpostfix('_a') -> ('_a', '')
    splitpostfix('') -> ('_', None)

    split a base name between the name and postfix symbol. (return name includes prefix symbol, if any)
    NOTE: this will automatically strip the group name.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'splitpostfix() argument name must be str object, not {name.__class__.__name__}')

    name = basename(name, min_idx=min_idx)
    min_len = 2 if (len(name) > 1 and name[0] in PREFIXES) else 1

    POSTFIXES_ = DOC_POSTFIXES if allow_doc else POSTFIXES

    if len(name) > min_len+1 and name[-2:] in POSTFIXES_:
        return (name[:-2], name[-2:])
    elif len(name) > min_len and name[-1] in POSTFIXES_:
        return (name[:-1], name[-1])
    elif len(name) >= min_len:
        return (name, '')
    return (name, None)


def prefixsymbol(name:str, *, min_idx:int=...) -> Optional[str]:
    """prefixsymbol('$abs@MAJIRO_INTER') -> '$'
    prefixsymbol('a') -> None

    returns the prefix symbol of a base name, if one exists and there's room for one.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'prefixsymbol() argument name must be str object, not {name.__class__.__name__}')

    name = basename(name, min_idx=min_idx)
    return name[0] if (len(name) > 1 and name[0] in PREFIXES) else None

def postfixsymbol(name:str, *, allow_doc:bool=False, min_idx:int=...) -> Optional[str]:
    """postfixsymbol('@pic_top_bak$#@PIC') -> '$#'
    postfixsymbol('$abs@MAJIRO_INTER') -> ''
    postfixsymbol('_') -> ''
    postfixsymbol('_a') -> ''
    postfixsymbol('') -> None

    returns the postfix symbol of a base name, if one exists and there's room for one.
    NOTE: this will automatically handle names with groups
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'postfixsymbol() argument name must be str object, not {name.__class__.__name__}')

    name = basename(name, min_idx=min_idx)
    min_len = 2 if (len(name) > 1 and name[0] in PREFIXES) else 1

    POSTFIXES_ = DOC_POSTFIXES if allow_doc else POSTFIXES

    if len(name) > min_len+1 and name[-2:] in POSTFIXES_:
        return name[-2:]
    elif len(name) > min_len and name[-1] in POSTFIXES_:
        return name[-1:]
    elif len(name) >= min_len:
        return ''
    return None

def hasfullqual(fullname:str, *, allow_doc:bool=False, min_idx:int=...) -> bool:
    """hasfullqual('$cos%@MAJIRO_INTER') -> True
    hasfullqual('$rand') -> False
    hasfullqual('$abs@MAJIRO_INTER') -> True
    hasfullqual('_xy@') -> True
    hasfullqual('_xy') -> False

    returns True if `fullname` is fully-qualified and contains all required identifier symbols.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'hasfullqual() argument fullname must be str object, not {fullname.__class__.__name__}')

    POSTFIXES_ = DOC_POSTFIXES if allow_doc else POSTFIXES

    name, group = splitgroup(fullname, min_idx=min_idx)
    # has group? / has prefix?
    if group is None or len(name) <= 1 or name[0] not in PREFIXES:
        return False
    # has postfix?
    return ((len(name) > 3 and name[-2:] in POSTFIXES_) or
            (len(name) > 2 and name[-1] in POSTFIXES_) or
            (len(name) >= 2))

def hasbasequal(fullname:str, *, allow_doc:bool=False, min_idx:int=...) -> bool:
    """hasbasequal('$cos%@MAJIRO_INTER') -> True
    hasbasequal('$rand') -> True
    hasbasequal('$abs@MAJIRO_INTER') -> True
    hasbasequal('_xy@') -> True
    hasbasequal('_') -> False
    hasbasequal('') -> False

    returns True if `fullname` is fully-qualified and contains all required identifier symbols, besides a group.
    """
    if fullname is None or not isinstance(fullname, str):
        raise TypeError(f'hasbasequal() argument fullname must be str object, not {fullname.__class__.__name__}')

    POSTFIXES_ = DOC_POSTFIXES if allow_doc else POSTFIXES

    name = basename(fullname, min_idx=min_idx)
    # has prefix?
    if len(name) <= 1 or name[0] not in PREFIXES:
        return False
    # has postfix?
    return ((len(name) > 3 and name[-2:] in POSTFIXES_) or
            (len(name) > 2 and name[-1] in POSTFIXES_) or
            (len(name) >= 2))

def hasprefix(name:str, *, min_idx:int=...) -> bool:
    """hasprefix('$abs@MAJIRO_INTER') -> True
    hasprefix('a') -> False

    returns True if `name` starts with a prefix symbol, and there's room for one.
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'hasprefix() argument name must be str object, not {name.__class__.__name__}')

    name = basename(name, min_idx=min_idx)
    return (len(name) > 1 and name[0] in PREFIXES)

def haspostfix(name:str, *, allow_doc:bool=False, min_idx:int=...) -> bool:
    """haspostfix('@pic_top_bak$#@PIC') -> True
    haspostfix('$abs@MAJIRO_INTER') -> True
    haspostfix('_') -> True
    haspostfix('_a') -> True
    haspostfix('') -> False

    returns True if `name` ends with a postfix symbol and there's room for one.
    NOTE: this will automatically handle names with groups
    """
    if name is None or not isinstance(name, str):
        raise TypeError(f'haspostfix() argument name must be str object, not {name.__class__.__name__}')

    name = basename(name, min_idx=min_idx)
    min_len = 2 if (len(name) > 1 and name[0] in PREFIXES) else 1

    POSTFIXES_ = DOC_POSTFIXES if allow_doc else POSTFIXES

    return ((len(name) > min_len+1 and name[-2:] in POSTFIXES_) or
            (len(name) > min_len and name[-1] in POSTFIXES_) or
            (len(name) >= min_len))

#endregion

#######################################################################################


del string, List, Optional, Tuple  # cleanup declaration-only imports
