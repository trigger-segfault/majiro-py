#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Known syscall, usercall, and variable hashes, and group names
"""

__version__ = '0.1.0'
__date__    = '2021-04-11'
__author__  = 'Robert Jordan'

__all__ = ['SYSCALLS', 'USERCALLS', 'VARIABLES', 'LOCAL_VARS', 'THREAD_VARS', 'SAVEFILE_VARS', 'PERSISTENT_VARS', 'GROUPS']

#######################################################################################

from typing import Dict

from ._hashes import LOCAL_VARS, THREAD_VARS, SAVEFILE_VARS, PERSISTENT_VARS, USERCALLS, SYSCALLS, GROUPS

# combine all variable type hashes into one for easy lookup,
#  since this isn't handled by the auto-generated file
VARIABLES:Dict[int,str] = {}
VARIABLES.update(LOCAL_VARS)
VARIABLES.update(THREAD_VARS)
VARIABLES.update(SAVEFILE_VARS)
VARIABLES.update(PERSISTENT_VARS)


del Dict  # cleanup declaration-only imports
