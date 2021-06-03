#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro VN engine Python library package

modules:
  mj.crypt       - cryptographic, hashing, and unhashing functions.
  mj.name        - identifier name text parsing and constants. (similar to `os.path` module)
  mj.identifier  - identifier name and hash handling.
  mj.signature   - signature representation classes for variables, functions, etc.

submodules:
  mj.archive     - reading file entries from `.arc` archive files.
  mj.database    - useful Majiro engine information and extra analysis tools. (mainly unhashed names)
  mj.image       - reading and writing `.rct` and `.rc8` image pixel data.
  mj.project     - gathering and organizing codebase information for a game's scripts.
  mj.script      - reading and writing `.mjo` script files.
  mj.util        - helper functions used throughout the package.

"""

__version__ = '1.1.0'
__date__    = '2021-06-03'
__author__  = 'Robert Jordan'

# __all__ = ['LOCAL_VARS', 'LOCAL_VARS_LOOKUP', 'THREAD_VARS', 'THREAD_VARS_LOOKUP', 'SAVEFILE_VARS', 'SAVEFILE_VARS_LOOKUP', 'PERSISTENT_VARS', 'PERSISTENT_VARS_LOOKUP', 'FUNCTIONS', 'FUNCTIONS_LOOKUP', 'SYSCALLS', 'SYSCALLS_LOOKUP', 'GROUPS', 'GROUPS_LOOKUP', 'CALLBACKS', 'CALLBACKS_LOOKUP', 'SYSCALLS_LIST', 'VARIABLES', 'VARIABLES_LOOKUP']

#######################################################################################

from . import name, identifier

