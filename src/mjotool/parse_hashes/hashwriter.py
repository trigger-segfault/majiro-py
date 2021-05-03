#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Script to read and parse .mjh files and collect hashes for variable names and function signatures.
"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

#######################################################################################

## the code in this file is not fit for humans. or robots. or anyone. ##
## viewer discretion is advised, please look away                     ##

#######################################################################################

import enum, io, json, os, re, struct
from enum import auto
from collections import namedtuple, OrderedDict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union


from .._util import DummyColors, Colors
from .._util import Fore as F, Style as S
from ..flags import MjoType
from ..crypt import hash32
# from ..script import KNOWN_SYSCALLS, SPECIAL_VARIABLES
# from ..script import MjoScript
# from ..analysis import ControlFlowGraph
from .identifiers import *

MjsKnownFile = namedtuple('MjsKnownFile', ('includename', 'filename', 'encoding'))
MjsInclude = namedtuple('MjsInclude', ('filename', 'included'))

#######################################################################################


def select_hashes(hash_dict:Dict[int,str], *prefixes:str, sort:bool=True) -> List[Tuple[int,str]]:
    if not prefixes: # use all items
        hash_list = list(hash_dict.items())
    else:
        hash_list = []
        for prefix in prefixes:
            hash_list.extend((h,sig) for h,sig in hash_dict.items() if sig[0] == prefix)
    
    if sort:
        hash_list.sort(key=lambda v: v[1]) #.fullname)
    return hash_list

def select_groups(group_list:List[str], sort:bool=True) -> List[str]:
    group_list = list(group_list)
    if sort:
        group_list.sort()
    return group_list

def write_hashes_dict(writer:io.TextIOBase, hash_list:List[Tuple[int,str]], *, readable:bool=False, python:bool=False, tab:str='\t', singlequotes:bool=True):
    writer.write('{')

    for i,(h,sig) in enumerate(hash_list):
        # comma-separate after first item
        if i:        writer.write(',')
        # newline and indent
        if readable: writer.write('\n' + tab)
        
        if python: # we don't have to use butt-ugly string hex values
            writer.write('0x{:08X}:'.format(h)) 
        else:      # bleh, JSON doesn't support hex OR numeric keys
            writer.write('"{:08X}":'.format(h))
        
        # visual space between key and value
        if readable: writer.write(' ')

        if python and singlequotes: # just use normal-repr single-quotes
            # also a bad hack, because repr does not guarantee one quote or the other
            #  in CPython we trust
            writer.write(repr(sig)) #.fullname))
        else:
            #FIXME: bad hack for double-quotes
            writer.write('"{}"'.format(repr(sig)[1:-1])) #.fullname)[1:-1]))
        writer.flush()

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write('}')
    # extra newline after end of dict (for cleanliness)
    #if python:   writer.write('\n')

def write_groups_list(writer:io.TextIOBase, group_list:List[str], *, readable:bool=False, python:bool=False, tab:str='\t', singlequotes:bool=True):
    writer.write('[')

    for i,group in enumerate(group_list):
        # comma-separate after first item
        if i:        writer.write(',')
        # newline and indent
        if readable: writer.write('\n' + tab)

        if python and singlequotes: # just use normal-repr single-quotes
            # also a bad hack, because repr does not guarantee one quote or the other
            #  in CPython we trust
            writer.write(repr(group)) #.fullname))
        else:
            #FIXME: bad hack for double-quotes
            writer.write('"{}"'.format(repr(group)[1:-1])) #.fullname)[1:-1]))
        writer.flush()

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write(']')
    # extra newline after end of dict (for cleanliness)
    # if python:   writer.write('\n')

HashSelection = namedtuple('HashSelection', ('name', 'varname', 'hashes', 'prefixes'))
GroupSelection = namedtuple('GroupSelection', ('name', 'varname', 'groups'))

def write_python_file(writer:io.TextIOBase, hash_items:List[HashSelection], group_items:List[GroupSelection], *, readable:bool=True, sort:bool=True):
    all_names = []
    writer.write('#!/usr/bin/env python3\n')
    writer.write('#-*- coding: utf-8 -*-\n')
    writer.write('"""Known hashes and groups for Majiro  (this file was auto-generated)\n')
    writer.write('\n')
    writer.write('Contains:\n')
    hash_lists = []
    group_lists = []
    for i,item in enumerate(hash_items):
        hash_lists.append(select_hashes(item.hashes, *item.prefixes, sort=sort))
        writer.write('{:d} {} hashes\n'.format(len(hash_lists[-1]), item.name))
        all_names.append(item.varname)
    for i,item in enumerate(group_items):
        group_lists.append(select_groups(item.groups, sort=sort))
        writer.write('{:d} {} names\n'.format(len(group_lists[-1]), item.name))
        all_names.append(item.varname)
    writer.write('"""\n')
    writer.write('\n')
    writer.write('__date__    = {!r}\n'.format(__date__))
    writer.write('__author__  = {!r}\n'.format(__author__))
    writer.write('\n')
    writer.write('__all__ = {!r}\n'.format(all_names))
    writer.write('\n')
    writer.write('#######################################################################################\n')
    writer.write('\n')
    writer.write('from typing import Dict, Set\n')

    if hash_items:
        writer.write('\n')
    for i,item in enumerate(hash_items):
        hash_list = hash_lists[i]
        writer.write('\n{}:Dict[int,str] = '.format(item.varname))
        write_hashes_dict(writer, hash_list, readable=False, python=True)
        writer.write('\n')
    
    if group_items:
        writer.write('\n')
    for i,item in enumerate(group_items):
        group_list = group_lists[i]
        writer.write('\n{}:Set[str] = '.format(item.varname))
        write_groups_list(writer, group_list, readable=False, python=True)
        writer.write('\n')

    writer.write('\n\n')
    writer.write('del Dict, Set  # cleanup declaration-only imports\n')

def write_json_file(writer:io.TextIOBase, hash_items:List[HashSelection], group_items:List[GroupSelection], *, tab:str='\t', readable:bool=True, sort:bool=True):
    writer.write('{')
    first_item = True

    for item in hash_items:
        # comma-separate after first item
        if first_item:
            first_item = False
            # newline and indent
            if readable:   writer.write('\n' + tab)
        else:
            writer.write(',')
            # double-newline and indent
            if readable:   writer.write('\n\n' + tab)

        writer.write('"{}":'.format(item.varname))
        
        # visual space between key and value
        if readable:   writer.write(' ')

        hash_list = select_hashes(item.hashes, *item.prefixes, sort=sort)
        write_hashes_dict(writer, hash_list, readable=False, python=False)

    if readable and hash_items and group_items:
        writer.write(',\n\n') # visual separation between hashes and groups
        first_item = True   # set first item again because we already placed comma
    
    for item in group_items:
        # comma-separate after first item
        if first_item:
            first_item = False
            # newline and indent
            if readable:   writer.write('\n' + tab)
        else:
            writer.write(',')
            # double-newline and indent
            if readable:   writer.write('\n\n' + tab)

        writer.write('"{}":'.format(item.varname))
        
        # visual space between key and value
        if readable:   writer.write(' ')

        group_list = select_groups(item.groups, sort=sort)
        write_groups_list(writer, group_list, readable=False, python=False)

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write('}')
