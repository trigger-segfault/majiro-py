#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro VN engine Python library package

modules:
  mj.crypt - cryptographic and hashing functions.
  mj.name  - identifier name text parsing. (similar in function to `os.path`)
  mj.identifier  - identifier name and hash handling.

submodules:
  mj.database    - database of useful Majiro engine information (mainly known hash value names).
  mj.script      - tools and classes for reading and writing `.mjo` script files.

"""

__version__ = '1.0.0'
__date__    = '2021-05-04'
__author__  = 'Robert Jordan'

# __all__ = ['LOCAL_VARS', 'LOCAL_VARS_LOOKUP', 'THREAD_VARS', 'THREAD_VARS_LOOKUP', 'SAVEFILE_VARS', 'SAVEFILE_VARS_LOOKUP', 'PERSISTENT_VARS', 'PERSISTENT_VARS_LOOKUP', 'FUNCTIONS', 'FUNCTIONS_LOOKUP', 'SYSCALLS', 'SYSCALLS_LOOKUP', 'GROUPS', 'GROUPS_LOOKUP', 'CALLBACKS', 'CALLBACKS_LOOKUP', 'SYSCALLS_LIST', 'VARIABLES', 'VARIABLES_LOOKUP']

#######################################################################################

from . import name, identifier

