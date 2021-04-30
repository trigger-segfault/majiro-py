#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Script to read and parse .mjh files and collect hashes for variable names and function signatures.
"""

__version__ = '0.1.0'
__date__    = '2021-04-11'
__author__  = 'Robert Jordan'

#######################################################################################

## the code in this file is not fit for humans. or robots. or anyone. ##
## viewer discretion is advised, please look away                     ##

#######################################################################################

import enum, io, json, os, re, struct, xml
from typing import List, Dict, NoReturn, Tuple, Union
from xml.sax.saxutils import escape

from mjotool.opcodes import Opcode
from mjotool.flags import MjoType, MjoTypeMask, MjoScope, MjoModifier, MjoInvert, MjoDimension, MjoFlags



#######################################################################################

class ClassWriter:
    __slots__ = ('_stream', 'level', 'indent_char')
    def __init__(self, stream:io.TextIOBase, level:int=0, indent_char:str='\t'):
        self._stream = stream
        self.level = level
        self.indent_char = indent_char
    def __getattr__(self, name):
        return self._stream.__getattribute__(name)
    
    def indent(self, text:str=None, *, noindent:bool=False):
        indent_str = '' if noindent else (self.level * self.indent_char)
        return self._stream.write(indent_str + ('' if text is None else str(text)))
    def indentline(self, line:str=None, *, noindent:bool=False):
        if line is None:
            self._stream.write('\n')  # no indentation on empty line
        else:
            return self.indent(('' if line is None else str(line)) + '\n', noindent=noindent)
    def write(self, text:str=None):
        self._stream.write('' if text is None else str(text))
    def writeline(self, line:str=None):
        return self.write(('' if line is None else str(line)) + '\n')

class MultiClassWriter:
    __slots__ = ('_streams')
    def __init__(self, *streams:io.TextIOBase):
        if not streams:
            raise ValueError(f'{self.__class__.__name__} must specify at least one stream')
        self._streams = streams
    def indent(self, text:str=None, *, noindent:bool=False):
        for stream in self._streams:
            stream.indent(text, noindent=noindent)
    def indentline(self, line:str=None, *, noindent:bool=False):
        for stream in self._streams:
            stream.indentline(line, noindent=noindent)
    def write(self, text:str=None):
        for stream in self._streams:
            stream.write(text)
    def writeline(self, line:str=None):
        for stream in self._streams:
            stream.writeline(line)
    def flush(self):
        for stream in self._streams:
            stream.flush()
    def close(self):
        for stream in self._streams:
            stream.close()
    @property
    def level(self) -> int:
        level = self._streams[0].level
        # print(f'level.getter() -> {level}')
        for stream in self._streams:
            if stream.level != level:
                raise Exception(f'{self.__class__.__name__} stream levels do not match {level} vs {stream.level}')
        return level
    @level.setter
    def level(self, level:int) -> NoReturn:
        # print(f'level.getter({level})')
        for stream in self._streams:
            stream.level = level


## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    # if argv is None:
    #     import sys
    #     argv = sys.argv[1:]
    import argparse
    parser = argparse.ArgumentParser(
        add_help=True)

    parser.add_argument('enumfile', metavar='CSFILE',
        help='output C# enum file')
    parser.add_argument('classfile', metavar='CSFILE',
        help='output C# static class file')
    parser.add_argument('-a', '--aliases', default=False, action='store_true', required=False,
        help='include opcode aliases')

    args = parser.parse_args(argv)

    # print(args)
    # return 0

    ###########################################################################

    OPCODE = 'Opcode'  #NOTE: compared to MajiroTools, .NET/Mono.Cecil use Op**C**ode

    def enum_name(name:str) -> str:
        return '_'.join(p.capitalize() for p in name.split('.'))
    
    def enum_code(value:int) -> str:
        return f'0x{value:03X}'
    
    def enum_opcode(name:str, value:int) -> str:
        return f'{OPCODE}.ByValue[(ushort){OPCODE}Values.{enum_name(name)}]'

    indent = 0
    indentstr = '\t'
    def write(writer:io.TextIOBase, line=None, noindent=False):
        if line:
            writer.write(('' if noindent else (indentstr*indent)) + line)
    def writeline(writer:io.TextIOBase, line=None, noindent=False):
        # if line:
        #     writer.write(('' if noindent else (indentstr*indent)) + line)
        write(line, noindent)
        writer.write('\n')

    with open(args.enumfile, 'wt+', encoding='utf-8') as writer_enum:
      with open(args.classfile, 'wt+', encoding='utf-8') as writer_cls:
        
        enmwriter = ClassWriter(writer_enum)
        clswriter = ClassWriter(writer_cls)
        writers = MultiClassWriter(enmwriter, clswriter)

        writers.indentline('using System;')
        writers.indentline()
        writers.indentline('namespace Majiro.Script {')
        writers.level += 1

        writers.indentline()
        enmwriter.indentline(f'public enum {OPCODE}Values : ushort {{')
        clswriter.indentline(f'public static class {OPCODE}s {{')
        writers.level += 1

        opcodes:List[Opcode] = list(Opcode.LIST)
        opcodes.sort(key=lambda o: o.value)

        max_name_len = 0
        for opcode in opcodes:
            names = [opcode.mnemonic]
            if args.aliases:
                names += list(opcode.aliases)
            max_name_len = max(max_name_len, max([len(n) for n in names]))

        for opcode in opcodes:
            names = [opcode.mnemonic]
            if args.aliases:
                names += list(opcode.aliases)
            for i,name in enumerate(names):
                is_alias:bool = (i > 0)
                enmwriter.indentline(f'{enum_name(name).ljust(max_name_len)} = {enum_code(opcode.value)},')
                clswriter.indentline(f'public static readonly {OPCODE} {enum_name(name).ljust(max_name_len)} = {enum_opcode(name, opcode.value)};')

        writers.level -= 1
        writers.indentline('}') # public enum {OPCODE}Values
        writers.level -= 1
        writers.indentline('}') # namespace Majiro.Script

        writers.flush()


    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

