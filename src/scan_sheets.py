#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.0.1'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

#######################################################################################

import io, os, struct
from mjotool._util import DummyColors, Colors, Fore as F, Style as S
from mjotool.script import Instruction, MjoScript, Function, ILFormat
from mjotool.crypt import hash32
from mjotool.flags import MjoType, MjoScope
from mjotool.analysis import ControlFlowGraph
from mjotool.sheets.majirodata import SheetSyscalls, SheetGroups, SheetFunctions, SheetVariables, SheetLocals, SheetCallbacks, SheetGames
from mjotool.sheets.csvsheet import CsvSheet
from mjotool.mjs.mjsreader import MjsReader, load_mjs_hashes
from mjotool.mjs.identifiers import GROUP_SYSCALL, GROUP_LOCAL, GROUP_DEFAULT, Identifier, SyscallSig, FunctionSig, VariableSig, ArgumentSig, LocalSig
from mjotool.sheets.rowtypes import Typedef, Status
from mjotool.known_hashes import GROUPS as KNOWN_GROUPS


#######################################################################################

def scan_sheet(sheettype:type, *, format:str='csv', update:bool=False):
    # class hexint8(int):
    #     def __new__(cls, *args, **kwargs): return super().__new__(cls, *args, **kwargs)
    #     def __repr__(self) -> str: return f'0x{self:08x}'
    #     def __str__(self)  -> str: return repr(self)
    print(sheettype.NAME)
    cache_file:str =  f'sheet_{sheettype.NAME}_cached.{format}'
    if not update and os.path.isfile(cache_file):
        print('Cached...')
        sheet:CsvSheet = sheettype.fromfile(cache_file, format=format)
    else:
        print('Downloading...')
        sheet:CsvSheet = sheettype.fromsheet(format=format, cache_file=cache_file)
    sheet.verify(error=True)
    # print(len(sheet), sheet)
    if isinstance(sheet, (SheetSyscalls, SheetFunctions, SheetVariables, SheetLocals)):
        for row in sheet:
            typename = '    ' if row.type is None else row.type.value
            hashvalue = '        ' if row.hash is None else f'{row.hash:08x}'
            name     = '    ' if row.name is None else row.name
            # if row.unhashed:
            #     print(f'{S.BRIGHT}{F.RED}{hashvalue}{S.RESET_ALL}\t{S.BRIGHT}{F.CYAN}{source}{S.RESET_ALL}\t{S.BRIGHT}{F.BLUE}{typename}{S.RESET_ALL}\t{S.BRIGHT}{F.YELLOW}{name}{S.RESET_ALL}', end='')
            # else:
            #     print(f'{S.DIM}{F.RED}{hashvalue}{S.RESET_ALL}\t{S.DIM}{F.CYAN}{source}{S.RESET_ALL}\t{S.DIM}{F.BLUE}{typename}{S.RESET_ALL}\t{S.DIM}{F.YELLOW}{name}{S.RESET_ALL}', end='')
            if row.unhashed:
                print(f'{S.BRIGHT}{F.RED}{hashvalue}{S.RESET_ALL}', end='')
            else:
                print(f'{S.DIM}{F.RED}{hashvalue}{S.RESET_ALL}', end='')
            if hasattr(row, 'source'):
                if isinstance(row.source, int):
                    source = f'{row.source:08x}'
                else:
                    source   = '        ' if not hasattr(row, 'source') or row.source is None else row.source.replace('\n', ', ').ljust(8)
                if row.unhashed:
                    print(f'\t{S.BRIGHT}{F.CYAN}{source}{S.RESET_ALL}', end='')
                else:
                    print(f'\t{S.DIM}{F.CYAN}{source}{S.RESET_ALL}', end='')
            if row.unhashed:
                print(f'\t{S.BRIGHT}{F.BLUE}{typename}{S.RESET_ALL}\t{S.BRIGHT}{F.YELLOW}{name}{S.RESET_ALL}', end='')
            else:
                print(f'\t{S.DIM}{F.BLUE}{typename}{S.RESET_ALL}\t{S.DIM}{F.YELLOW}{name}{S.RESET_ALL}', end='')
            if hasattr(row, 'source') and row.name:# and hasattr(row, 'group') and row.group and (row.group != GROUP_SYSCALL or not hasattr(row, 'arguments')):# and row.group is not GROUP_SYSCALL and row.group is not GROUP_LOCAL:
                if not hasattr(row, 'source'):
                    groupname = '@'
                else:
                    groupname = '' if not row.group else f'@{row.group}'
                print(f'{S.DIM}{F.GREEN}{groupname}{S.RESET_ALL}', end='')
            if hasattr(row, 'arguments') and row.arguments is not None and row.arguments[:1] != '?': # edge case to handle: "? (same as 59180bbb)"
                # if isinstance(sheet, SheetSyscalls):
                #     syssig = row.identifier
                #     syssig.parse_arguments(row.arguments)
                # else:
                if row.arguments == '':
                    print(f'({S.BRIGHT}{F.BLUE}void{S.RESET_ALL})', end='')
                elif isinstance(sheet, SheetSyscalls):
                    syssig = SyscallSig('$dummy', is_void=False)# row.identifier
                    syssig.parse_arguments(row.arguments)
                    print(f'({S.BRIGHT}{F.CYAN}{syssig.args_str}{S.RESET_ALL})', end='')
                else:
                    print(f'({S.BRIGHT}{F.CYAN}{row.arguments}{S.RESET_ALL})', end='')

                # print(f'\t{row.arguments or ""}', end='')
            print()
        #     if row.unhashed:
        #         if isinstance(sheet, SheetSyscalls):
        #             sig = SyscallSig(row.name, row.arguments, is_void=row.type is Typedef.VOID, doc=row.notes)
        #             ls[hexint8(sig.hash)] = sig
        #             print(repr(sig))
        #         elif isinstance(sheet, SheetFunctions):
        #             sig = FunctionSig(row.name, row.arguments, group=row.group, is_void=row.type is Typedef.VOID, doc=row.notes)
        #             ls[hexint8(sig.hash)] = sig
        #             print(repr(sig))
        # if isinstance(sheet, (SheetSyscalls, SheetFunctions)):
        #     print(repr(ls))
        #     print(len(repr(ls)))
        #     sig = SyscallSig(row.name, row.arguments, is_void=row.type is Typedef.VOID, doc=row.notes)
        #     ls.append(sig)
        #     print(repr(sig))
        # elif isinstance(sheet, SheetFunctions):
        #     sig = FunctionSig(row.name, row.arguments, group=row.group, is_void=row.type is Typedef.VOID, doc=row.notes)
        #     ls.append(sig)
        #     print(repr(sig))
    if isinstance(sheet, (SheetGroups, SheetCallbacks)):
        for row in sheet:
            hashvalue = '        ' if row.hash is None else f'{row.hash:08x}'
            name     = '    ' if row.name is None else row.name
            if isinstance(row.source, int):
                source = f'{row.source:08x}'
            else:
                source   = '        ' if row.source is None else row.source.replace('\n', ', ').ljust(8)
            # typename = row.type.value if row.type is not None else ''
            if row.unhashed:
                print(f'{S.BRIGHT}{F.RED}{hashvalue}{S.RESET_ALL}\t{S.BRIGHT}{F.CYAN}{source}{S.RESET_ALL}\t{S.BRIGHT}{F.GREEN}{name}{S.RESET_ALL}')
            else:
                print(f'{S.DIM}{F.RED}{hashvalue}{S.RESET_ALL}\t{S.DIM}{F.CYAN}{source}{S.RESET_ALL}\t{S.DIM}{F.GREEN}{name}{S.RESET_ALL}')

#######################################################################################

def scan_mjs(filename:str, *, debug_mode:bool=False, pre_greedy:bool=False):
    mjsreader = MjsReader(filename, encoding='utf-8', debug_mode=debug_mode, pre_greedy=pre_greedy)
    mjsreader.read()
    source = os.path.basename(filename)
    for sig in [*mjsreader.var_hashes.values(), *mjsreader.func_hashes.values()]:
        hashvalue = '        ' if sig.hash is None else f'{sig.hash:08x}'
        name     = '    ' if sig.name is None else sig.name
        typename = '    '
        if isinstance(sig, FunctionSig) and sig.is_void:
            typename = Typedef.VOID.value
        else:
            NAMES = ('VOID', 'INT', 'FLOAT', 'STRING', 'INT_ARRAY', 'FLOAT_ARRAY', 'STRING_ARRAY')
            for N in NAMES:
                if sig.type.name == N:
                    if sig.type is MjoType.INT:
                        typename = Typedef.INT_UNK.value
                    else:
                        typename = getattr(Typedef, N).value
                    break
        # if sig.type.name == Typedef.INT.name: typename = Typedef.INT.value
        # typename = '    ' if sig.type is None else sig.type.value
        print(f'{S.BRIGHT}{F.RED}{hashvalue}{S.RESET_ALL}\t{S.BRIGHT}{F.CYAN}{source}{S.RESET_ALL}\t{S.BRIGHT}{F.BLUE}{typename}{S.RESET_ALL}\t{S.BRIGHT}{F.YELLOW}{name}{S.RESET_ALL}', end='')
        if sig.group is not None:
            if sig.group == GROUP_LOCAL:
                groupname = '@'
            else:
                groupname = '' if not sig.group else f'@{sig.group}'
            print(f'{S.DIM}{F.GREEN}{groupname}{S.RESET_ALL}', end='')
        if isinstance(sig, FunctionSig):
            # if not sig.arguments:
            #     print(f'\t{""}', end='')
            # else:
            #     print(f'\t{sig.args_str}', end='')
            if not sig.arguments:
                print(f'({S.BRIGHT}{F.BLUE}void{S.RESET_ALL})', end='')
            else:
                print(f'({S.BRIGHT}{F.CYAN}{sig.args_str}{S.RESET_ALL})', end='')
        print()
    for grp in mjsreader.group_names:
        hashvalue = hash32(f'$main@{grp}')
        name = grp
        print(f'{S.BRIGHT}{F.RED}{hashvalue:08x}{S.RESET_ALL}\t{S.BRIGHT}{F.CYAN}{source}{S.RESET_ALL}\t{S.BRIGHT}{F.GREEN}{name}{S.RESET_ALL}')
    print('Total:', len([*mjsreader.var_hashes.values(), *mjsreader.func_hashes.values(), *mjsreader.group_names]))

#######################################################################################

## MAIN FUNCTION ##

def main(argv:list=None) -> int:

    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('-s','--syscalls', dest='sheets', action='append_const', const=SheetSyscalls)
    parser.add_argument('-g','--groups', dest='sheets', action='append_const', const=SheetGroups)
    parser.add_argument('-f','--functions', dest='sheets', action='append_const', const=SheetFunctions)
    parser.add_argument('-v','--variables', dest='sheets', action='append_const', const=SheetVariables)
    parser.add_argument('-l','--locals', dest='sheets', action='append_const', const=SheetLocals)
    parser.add_argument('-c','--callbacks', dest='sheets', action='append_const', const=SheetCallbacks)
    parser.add_argument('-G','--games', dest='sheets', action='append_const', const=SheetGames)
    parser.add_argument('-u','--update', dest='update', action='store_true', default=False)
    parser.add_argument('-a','--adv', dest='mjs', action='append_const', const='../data/mjs/adv.mjh.bak')
    parser.add_argument('-1','--old', dest='mjs', action='append_const', const='../data/mjs/console.mjs.old')
    parser.add_argument('-2','--old2', dest='mjs', action='append_const', const='../data/mjs/console.mjs.old2')
    parser.add_argument('--greedy', dest='mjs_pre_greedy', action='store_true', default=False)
    parser.add_argument('--debug', dest='mjs_debug_mode', action='store_true', default=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--csv', dest='format', action='append_const', const='csv', default='csv')
    group.add_argument('--tsv', dest='format', action='append_const', const='tsv')
    group.add_argument('--test-args', dest='test_args', default=None)
    
    args = parser.parse_args(argv)

    # print(args)
    # return 0
    
    ###########################################################################
    
    if hasattr(args, 'test_args') and args.test_args is not None:
        syssig = SyscallSig('$mysyscall', is_void=False)
        syssig.parse_arguments(args.test_args)
        print(str(syssig))
        
    ###########################################################################

    if hasattr(args, 'mjs') and args.mjs:
        for filename in args.mjs:
            scan_mjs(filename, debug_mode=args.mjs_debug_mode, pre_greedy=args.mjs_pre_greedy)

    ###########################################################################

    if hasattr(args, 'sheets') and args.sheets:
        for sheettype in args.sheets:
            scan_sheet(sheettype, format=args.format, update=args.update)

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())
