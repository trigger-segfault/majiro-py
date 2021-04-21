#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""A package designed for standalone research and side-by-side documentation with tutorials played out in Python.

The primary focus is CRC-32 unhashing, and working on more efficient methods of solving the elusive syscall hashed names in Majiro.
"""

__version__ = '1.0.0'
__date__    = '2021-04-21'
__author__  = 'Robert Jordan'

#######################################################################################

from . import crctools
from . import syscall_list
