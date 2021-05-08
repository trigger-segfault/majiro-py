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

__all__ = []

#######################################################################################

import enum
from collections import OrderedDict
from itertools import chain
from typing import Dict, Optional, Union

import enum
from collections import OrderedDict
from itertools import chain
from typing import Dict, Iterator, List, Optional, Union

from abc import abstractproperty

from ...flags import MjoType, MjoScope
from ...instruction import Instruction
from ...mjoscript import FunctionIndexEntry, MjoScript

from ....identifier import HashValue, HashName
from ....name import basename
from .block import BasicBlock, Function


