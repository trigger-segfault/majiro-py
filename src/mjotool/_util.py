#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Utility classes and functions
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'

__all__ = ['StructIO', 'Colors', 'DummyColors', 'hd_span', 'print_hexdump']

#######################################################################################

import io, struct
from collections import namedtuple
from types import SimpleNamespace
from typing import Any, List, NoReturn, Union


## FILE HELPERS ##

class StructIO:
    """IO wrapper with built-in struct packing and unpacking.
    """
    __slots__ = ('_stream')
    def __init__(self, stream:Union[io.BufferedReader, io.BufferedWriter, io.BufferedRandom]):
        self._stream = stream
    def __getattr__(self, name):
        return self._stream.__getattribute__(name)
    def length(self) -> int:
        position = self._stream.tell()
        self._stream.seek(0, 2)
        length = self._stream.tell()
        self._stream.seek(position, 0)
        return length
    def unpack(self, fmt:str) -> tuple:
        return struct.unpack(fmt, self._stream.read(struct.calcsize(fmt)))
    def unpackone(self, fmt:str) -> Any:
        return struct.unpack(fmt, self._stream.read(struct.calcsize(fmt)))[0]
    def pack(self, fmt:str, *v) -> NoReturn:
        return self._stream.write(struct.pack(fmt, *v))


## COLOR HELPERS ##

# dummy color namespaces for disabled color
DummyFore = SimpleNamespace(RESET='', BLACK='', BLUE='', CYAN='', GREEN='', MAGENTA='', RED='', WHITE='', YELLOW='', LIGHTBLACK_EX='', LIGHTBLUE_EX='', LIGHTCYAN_EX='', LIGHTGREEN_EX='', LIGHTMAGENTA_EX='', LIGHTRED_EX='', LIGHTWHITE_EX='', LIGHTYELLOW_EX='')
DummyBack = SimpleNamespace(RESET='', BLACK='', BLUE='', CYAN='', GREEN='', MAGENTA='', RED='', WHITE='', YELLOW='', LIGHTBLACK_EX='', LIGHTBLUE_EX='', LIGHTCYAN_EX='', LIGHTGREEN_EX='', LIGHTMAGENTA_EX='', LIGHTRED_EX='', LIGHTWHITE_EX='', LIGHTYELLOW_EX='')
DummyStyle = SimpleNamespace(RESET_ALL='', BRIGHT='', DIM='', NORMAL='') #, BOLD='', ITALIC='', UNDERLINE='', BLINKING='', INVERSE='', INVISIBLE='', STRIKETHROUGH='')

# normal color namespaces 
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()  # comment out init if extended color support is needed in Windows Terminal
except ImportError:
    # colorama not installed. fine, I'll do it myself
    # this expects Windows Terminal or equivalent terminal color code support
    Fore = SimpleNamespace(RESET='\x1b[39m', BLACK='\x1b[30m', BLUE='\x1b[34m', CYAN='\x1b[36m', GREEN='\x1b[32m', MAGENTA='\x1b[35m', RED='\x1b[31m', WHITE='\x1b[37m', YELLOW='\x1b[33m', LIGHTBLACK_EX='\x1b[90m', LIGHTBLUE_EX='\x1b[94m', LIGHTCYAN_EX='\x1b[96m', LIGHTGREEN_EX='\x1b[92m', LIGHTMAGENTA_EX='\x1b[95m', LIGHTRED_EX='\x1b[91m', LIGHTWHITE_EX='\x1b[97m', LIGHTYELLOW_EX='\x1b[93m')
    Back = SimpleNamespace(RESET='\x1b[49m', BLACK='\x1b[40m', BLUE='\x1b[44m', CYAN='\x1b[46m', GREEN='\x1b[42m', MAGENTA='\x1b[45m', RED='\x1b[41m', WHITE='\x1b[47m', YELLOW='\x1b[43m', LIGHTBLACK_EX='\x1b[100m', LIGHTBLUE_EX='\x1b[104m', LIGHTCYAN_EX='\x1b[106m', LIGHTGREEN_EX='\x1b[102m', LIGHTMAGENTA_EX='\x1b[105m', LIGHTRED_EX='\x1b[101m', LIGHTWHITE_EX='\x1b[107m', LIGHTYELLOW_EX='\x1b[103m')
    # extended styles not part of colorama
    Style = SimpleNamespace(RESET_ALL='\x1b[0m', BRIGHT='\x1b[1m', DIM='\x1b[2m', NORMAL='\x1b[22m') #, BOLD='\x1b[1m', ITALIC='\x1b[3m', UNDERLINE='\x1b[4m', BLINKING='\x1b[5m', INVERSE='\x1b[7m', INVISIBLE='\x1b[8m', STRIKETHROUGH='\x1b[9m')

# dictionaries for easier **foreground** color formatting
# >>> '{DIM}{GREEN}{!s}{RESET_ALL}'.format('hello world', **Colors)
DummyColors = dict(**DummyFore.__dict__, **DummyStyle.__dict__)
Colors = dict(**Fore.__dict__, **Style.__dict__)


## HEXDUMP HELPERS ##

_hexdump_span = namedtuple('_hexdump_span', ('start', 'stop', 'text', 'left', 'right'))

class hd_span:
    """Highlighting span used by print_hexdump() highlights argument
    """
    def __init__(self, start:int=None, stop:int=None, braces:str='  ', textcolor:str=None, bracecolor:str=None, *, color:str=...):
        self.start = start
        self.stop  = stop
        if color is not Ellipsis:
            textcolor = bracecolor = color
        left  = braces[ :1] if braces else None
        right = braces[-1:] if braces else None
        if textcolor:            textcolor = '{}{{:02x}}{{RESET_ALL}}'.format(textcolor)
        if left  and left  != ' ' and bracecolor: left  = '{}{}{{RESET_ALL}}'.format(bracecolor, left)
        if right and right != ' ' and bracecolor: right = '{}{}{{RESET_ALL}}'.format(bracecolor, right)
        self._text  = textcolor or None
        self._left  = left  or None
        self._right = right or None

    def indices(self, size:int) -> tuple:
        start, stop, _ = slice(self.start, self.stop).indices(size)
        if stop == start:
            stop = -1
        text  = self._text
        left  = self._left
        right = self._right
        return _hexdump_span(start, stop, text, left, right)

def print_hexdump(data:bytes, start:int=None, stop:int=None, *highlights:List[hd_span], show_header:bool=True, color:bool=False):
    """
    highlight = (start, stop, color, openbrace, closebrace, colorall=False)
    """
    colors = Colors if color else DummyColors
    # ignore msb for chars, default to '.' for control chars, space, and del
    CHARMAP = tuple((chr(b&0x7f) if (32<b<127) else '.') for b in range(256))
    # # default to '.' for control chars, space, del, and non-ascii chars
    # CHARMAP = tuple((chr(b) if (32<b<127) else '.') for b in range(256))

    highlights = [h.indices(len(data)) for h in highlights]

    def hexbyte(i:int) -> str:
        left = '' if (i <= stop) else ' '
        text = '' if (i < stop) else '  '
        # right = '' if ((i & 0xf) == 0xf or i+1 == len(data)) else ...
        right = '' if (i & 0xf) == 0xf else ...
        # if (i & 0xf) != 0xf: right = ...   # don't attempt right brace handling when not at edge of row

        for h in highlights:
            if not (h.start <= i <= h.stop):
                continue

            if   not text and h.text  and i != h.stop:   text = h.text
            if   not left and h.left  and i == h.start:  left = h.left
            elif not left and h.right and i & 0xf and i == h.stop: left = h.right # previously ended span
            if  not right and h.right and i+1 == h.stop: right = h.right # end of span on right edge of row or end of final row

        return ((left or ' ') + (text or '{:02x}') + ((right or ' ') if right is not Ellipsis else '')).format(data[i] if i < len(data) else 0, **colors)

    start, stop, _ = slice(start, stop).indices(len(data))
    rowstart = start     & ~0xf  # floor, units of 16
    rowstop = (stop+0xf) & ~0xf  # ceil,  units of 16

    if show_header:
        print('{BRIGHT}{BLUE}  Offset: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F \t{RESET_ALL}'.format(**colors))

    for off in range(rowstart, rowstop, 16):
        # ignore bytes outside of specified range
        rowbytes = ''.join((hexbyte(i) if (start<=i<rowstop) else '   ') for i in range(off,off+16))
        # ignore bytes outside of specified range (inclusive stop for closing braces)
        # rowbytes = ''.join((hexbyte(i) if (start<=i<=stop) else '   ') for i in range(off,off+16))
        # ignore chars outside of specified range (use ' ')
        rowchars = ''.join((CHARMAP[data[i]] if (start<=i<stop) else ' ') for i in range(off,off+16))

        print('{BRIGHT}{BLUE}{:08x}:{RESET_ALL}{}   {BRIGHT}{GREEN}{!s}{RESET_ALL}'.format(off, rowbytes, rowchars, **colors))


del namedtuple, SimpleNamespace, Any, List, NoReturn, Union  # cleanup declaration-only imports
