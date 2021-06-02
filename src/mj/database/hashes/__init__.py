#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Known syscall, usercall, and variable hashes, and callbacks and group names.
"""

__version__ = '1.1.0'
__date__    = '2021-05-04'
__author__  = 'Robert Jordan'

__all__ = ['LOCAL_VARS', 'LOCAL_VARS_LOOKUP', 'THREAD_VARS', 'THREAD_VARS_LOOKUP', 'SAVEFILE_VARS', 'SAVEFILE_VARS_LOOKUP', 'PERSISTENT_VARS', 'PERSISTENT_VARS_LOOKUP', 'FUNCTIONS', 'FUNCTIONS_LOOKUP', 'SYSCALLS', 'SYSCALLS_LOOKUP', 'GROUPS', 'GROUPS_LOOKUP', 'CALLBACKS', 'CALLBACKS_LOOKUP', 'SYSCALLS_LIST', 'VARIABLES', 'VARIABLES_LOOKUP', 'ALL_FUNCTIONS', 'ALL_FUNCTIONS_LOOKUP',  'find_group', 'FUNC_MAIN',  'GROUP_LOCAL', 'GROUP_DEFAULT', 'GROUP_SYSCALL',  'LOCALVAR_NUMPARAMS', 'THREADVAR_INTERNALCASE']

#######################################################################################

## runtime imports:
# from ...crypt import hash32  # used in find_group()

from itertools import chain
from typing import Dict, Optional

from ._hashes import *
from ...name import GROUP_LOCAL, GROUP_DEFAULT, GROUP_SYSCALL, FUNC_MAIN, LOCALVAR_NUMPARAMS, THREADVAR_INTERNALCASE, joingroup


#######################################################################################

#region ## COMBINED LOOKUPS ##

# combine all variable type hashes into one dictionary for easy lookup,
#  since this isn't handled by the auto-generated file
VARIABLES:Dict[int,str] = dict(chain(LOCAL_VARS.items(), THREAD_VARS.items(), SAVEFILE_VARS.items(), PERSISTENT_VARS.items()))
VARIABLES_LOOKUP:Dict[str,int] = dict((v,k) for k,v in VARIABLES.items())

# combine all variable type hashes into one dictionary for easy lookup,
#  since this isn't handled by the auto-generated file
ALL_FUNCTIONS:Dict[int,str] = dict(chain(FUNCTIONS.items(), ((k,joingroup(v, GROUP_SYSCALL)) for k,v in SYSCALLS.items())))
ALL_FUNCTIONS_LOOKUP:Dict[str,int] = dict((v,k) for k,v in ALL_FUNCTIONS.items())

#endregion

#######################################################################################

#region ## GROUP LOOKUP ##

# FUNC_MAIN ('$main') is the name used to calculate hashes in GROUPS lookup dictionary
# this can be utilized to identify the group of any script, by purely checking the main function hash
def find_group(hash:int, name:str=FUNC_MAIN) -> Optional[str]:
    """find_group(0x1d128f30, '$main') -> 'GLOBAL'

    search for a group name that matches the hash value when combined into `name@GROUPNAME`.
    """
    if name == FUNC_MAIN:  # '$main@GROUPNAME' is built into _hashes.GROUPS dict
        return GROUPS.get(hash, None)

    from ...crypt import hash32
    init = hash32(f'{name}@')
    for group in GROUPS:
        if hash32(group, init) == hash:
            return group
    return None

#endregion


#######################################################################################

del joingroup, chain, Dict, Optional  # cleanup declaration-only imports
