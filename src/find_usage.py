



import enum, io, os, re
from collections import namedtuple, OrderedDict
from types import SimpleNamespace
from typing import Any, Dict, Iterable, Iterator, List, Match, Optional, Pattern, Tuple, Union
# from mjotool._util import Fore as F, Style as S

# S2 = SimpleNamespace(RESET_ALL='\x1b[0m', BRIGHT='\x1b[1m', DIM='\x1b[2m', NORMAL='\x1b[22m', BOLD='\x1b[1m', ITALIC='\x1b[3m', UNDERLINE='\x1b[4m', BLINKING='\x1b[5m', INVERSE='\x1b[7m', INVISIBLE='\x1b[8m', STRIKETHROUGH='\x1b[9m')

Fore = SimpleNamespace(RESET='\x1b[39m', BLACK='\x1b[30m', BLUE='\x1b[34m', CYAN='\x1b[36m', GREEN='\x1b[32m', MAGENTA='\x1b[35m', RED='\x1b[31m', WHITE='\x1b[37m', YELLOW='\x1b[33m', LIGHTBLACK_EX='\x1b[90m', LIGHTBLUE_EX='\x1b[94m', LIGHTCYAN_EX='\x1b[96m', LIGHTGREEN_EX='\x1b[92m', LIGHTMAGENTA_EX='\x1b[95m', LIGHTRED_EX='\x1b[91m', LIGHTWHITE_EX='\x1b[97m', LIGHTYELLOW_EX='\x1b[93m')
Back = SimpleNamespace(RESET='\x1b[49m', BLACK='\x1b[40m', BLUE='\x1b[44m', CYAN='\x1b[46m', GREEN='\x1b[42m', MAGENTA='\x1b[45m', RED='\x1b[41m', WHITE='\x1b[47m', YELLOW='\x1b[43m', LIGHTBLACK_EX='\x1b[100m', LIGHTBLUE_EX='\x1b[104m', LIGHTCYAN_EX='\x1b[106m', LIGHTGREEN_EX='\x1b[102m', LIGHTMAGENTA_EX='\x1b[105m', LIGHTRED_EX='\x1b[101m', LIGHTWHITE_EX='\x1b[107m', LIGHTYELLOW_EX='\x1b[103m')
# extended styles not part of colorama
Style = SimpleNamespace(RESET_ALL='\x1b[0m', BRIGHT='\x1b[1m', DIM='\x1b[2m', NORMAL='\x1b[22m', BOLD='\x1b[1m', ITALIC='\x1b[3m', UNDERLINE='\x1b[4m', BLINKING='\x1b[5m', INVERSE='\x1b[7m', INVISIBLE='\x1b[8m', STRIKETHROUGH='\x1b[9m')

F, S, S2 = Fore, Style, Style

# def iter_mjolist(filename:str, commentlvl:int=0, verbose:bool=False) -> Iterator[Tuple[int,str,int]]:
def iter_mjolist(filename:str, commentlvl:int=0) -> Iterator[Tuple[int,str,int]]:
    """
    iter_mjolist() -> (linenum, file/comment, commentlvl)
    commentlvl : 0 no comments, 1 = doc comments, 2 = all comments, 3 = empty lines
    """
    with open(filename, 'rt', encoding='utf-8') as reader:
        for i,ln in enumerate(reader):
            if not ln:
                continue
            line = ln.replace('\r\n', '\n').strip()
            if not line:
                if commentlvl >= 3:
                    # if verbose:
                    #     print()
                    yield (i+1, line, 3)
            elif line.startswith('///'):
                # print line
                doc = line.lstrip('/').lstrip()
                if commentlvl >= 1:
                    # if verbose:
                    #     print(f'{S2.ITALIC}{S.DIM}{F.CYAN}{doc}{S.RESET_ALL}')
                    yield (i+1, doc, 1)
            elif line.startswith('//'):
                comment = line.lstrip('/').lstrip()
                if commentlvl >= 2:
                    # if verbose:
                    #     print(f'{S2.ITALIC}{S.DIM}{F.GREEN}{comment}{S.RESET_ALL}')
                    yield (i+1, comment, 2)
            else:
                file = line
                if len(line) >= 2 and line[0] == '"' and line[-1] == '"':
                    file = line[1:-1]
                # if verbose:
                #     print(f'{S.BRIGHT}{F.YELLOW}{file}{S.RESET_ALL}')
                yield (i+1, file, 0)
            # print(line)

def normpath(filepath:str) -> str:
    return filepath.replace('\\', '/')

# def normdir(filepath:str) -> str:
#     return normpath(os.path.dirname(filepath))

def normjoin(*args:str) -> str:
    return normpath(os.path.join(*args))

def read_list(lstfile:str, dispname:str, targets:set, instr_range:tuple, loglvl:int, recurse:bool):
    lstfile = normpath(lstfile)
    # print(f'{S.BRIGHT}{F.YELLOW}List file:{S.RESET_ALL} {S.BRIGHT}{F.MAGENTA}{dispname}{S.RESET_ALL}')
    print(f'{S.RESET_ALL}{S.BRIGHT}{F.MAGENTA}{dispname}/{S.RESET_ALL}')
    for num,inname,lvl in iter_mjolist(lstfile, loglvl):#, args.verbose):
        if lvl == 0:
            infile = normjoin(os.path.dirname(lstfile), inname)
            if os.path.isdir(infile):
                read_dir(infile, normjoin(dispname, os.path.basename(infile)), targets, instr_range, loglvl, recurse, is_base=True)
            else: #if infile.lower().endswith('.mjo'):
                read_script(infile, normjoin(dispname, os.path.basename(infile)), targets, instr_range, loglvl)
        elif lvl == 1:
            pass
        elif lvl == 2:
            pass
        elif lvl == 3:
            pass
        # else:
        #     pass  # skip, file not of interest
        # if lvl == 0:
        #     print(f'{S.BRIGHT}{F.YELLOW}{text}{S.RESET_ALL}')
        # elif lvl == 1:
        #     print(f'{S2.ITALIC}{S.NORMAL}{F.CYAN}{text}{S.RESET_ALL}')
        # elif lvl == 2:
        #     print(f'{S2.ITALIC}{S.DIM}{F.GREEN}{text}{S.RESET_ALL}')
        # elif lvl == 3:
        #     print(f'{text}')

def read_dir(dirname:str, dispname:str, targets:set, instr_range:tuple, loglvl:int, recurse:bool, *, is_base:bool=True):
    dirname = normpath(dirname)
    # print(f'{S.BRIGHT}{F.YELLOW}Directory:{S.RESET_ALL} {S.DIM}{F.CYAN}{dispname}/{S.RESET_ALL}')
    if is_base:
        print(f'{S.RESET_ALL}{S.DIM}{F.CYAN}{dispname}/{S.RESET_ALL}')
    for inname in os.listdir(dirname):
        infile = normjoin(dirname, inname)
        if os.path.isdir(infile):
            if recurse:
                read_dir(infile, normjoin(dispname, os.path.basename(infile)), targets, instr_range, loglvl, recurse, is_base=False)
        elif infile.lower().endswith('.mjo'):
            read_script(infile, normjoin(dispname, os.path.basename(infile)), targets, instr_range, loglvl)
        else:
            pass  # skip, file not of interest



def read_script(mjofile:str, dispname:str, targets:set, instr_range:tuple, loglvl:int):
    mjofile = normpath(mjofile)
    from mjotool.script import MjoScript, ILFormat, Function, FunctionEntry
    from mjotool import known_hashes
    options = ILFormat()
    with open(mjofile, 'rb') as file:
        script = MjoScript.disassemble_script(file)
    options.set_address_len(script.bytecode_size)
    options.color = True
    options.inline_hash = True
    options.int_inline_hash = True
    options.syscall_inline_hash = True
    options.annotate_hex = False
    options.modifier_aliases = True
    options.typelist_aliases = True
    options.vartype_aliases = True
    options.functype_aliases = True
    options.scope_aliases = True
    options.implicit_local_groups = True
    options.braces = False

    for fn in script.functions:
        if fn.offset == script.main_offset:
            options.group_directive = known_hashes.GROUPS.get(fn.name_hash)
            break
    
    instructions = script.instructions
    functions = script.functions
    first:bool = True
    fn_idx:int = -1
    fn_cur:FunctionEntry = functions[0]
    fn_next:FunctionEntry = None
    
    function:Function = None
    end_print_idx = -1000
    for i,instr in enumerate(instructions):
        if instr.is_syscall and instr.hash in targets:
            is_first = first
            if first:
                first = False
                # print(f'{S.BRIGHT}{F.YELLOW}{mjofile}:{S.RESET_ALL}')
                print(f'{S.BRIGHT}{F.YELLOW}{dispname}:{S.RESET_ALL}')
            if fn_cur is None or (fn_next is not None and instr.offset >= fn_next.offset):
                fn_cur = fn_next
                fn_idx += 1
                fn_next = functions[fn_idx] if (fn_idx < len(functions)) else None
                #
                function = Function(script, fn_cur.offset)
                func_instr_idx = script.instruction_index_from_offset(fn_cur.offset)
                for j in range(func_instr_idx, min(len(instructions), func_instr_idx + 4)):
                    if instructions[j].opcode.mnemonic == 'argcheck':
                        function.parameter_types = instructions[j].type_list
                        break
                
                fn_name = known_hashes.FUNCTIONS.get(fn_cur.name_hash, f'${fn_cur.name_hash:08x}')
                if function.parameter_types is None:
                    raise Exception(f'Could not find parameter type list of function {fn_name}')
                # if fn_name
                # print(f'{S.BRIGHT}{F.BLUE}{mjofile}')
                function.print_function(options=options)
            idx_range = (max(0, i - instr_range[0], end_print_idx), min(len(instructions), i + instr_range[1] + 1))
            end_print_idx = idx_range[1]
            if (idx_range[0] > end_print_idx) and not is_first:
                print(f'{S.BRIGHT}{F.BLACK}// ...{S.RESET_ALL}')
            for k in range(*idx_range):
                instructions[k].print_instruction(options=options)
    if not first:
        print()



def main(argv:list=None) -> int:
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('inputs', metavar='FILE/DIR', nargs='+', default=[])
    parser.add_argument('-l','--loglvl', metavar='LVL', type=int, default=0, choices=[-1, 0, 1, 2, 3])
    parser.add_argument('-r','--recurse', dest='recurse', action='store_true', default=False)
    parser.add_argument('-t','--targets', metavar='HASH',  type=lambda v: int(v, 16), nargs='+', required=True)
    parser.add_argument('-R','--range', metavar=('BACK','FWD'), type=int, nargs=2, default=(4,1))
    # parser.add_argument('-v','--verbose', dest='verbose', action='store_true', default=False)
    # parser.add_argument('-q','--quiet', dest='verbose', action='store_false')


    args = parser.parse_args(argv)

    # print(args)
    # return 0

    loglvl = args.loglvl
    recurse = args.recurse
    instr_range = tuple(args.range)
    targets = set(args.targets)

    for inname in args.inputs:
        infile = normpath(inname)
        if os.path.isdir(infile):
            read_dir(infile, os.path.basename(infile), targets, instr_range, loglvl, recurse, is_base=True)
        elif os.path.isfile(infile):
            if infile.lower().endswith('.mjo'):
                read_script(infile, os.path.basename(infile), targets, instr_range, loglvl)
            else:
                read_list(infile, os.path.basename(infile), targets, instr_range, loglvl, recurse)
        else:
            raise Exception('Input file {infile!r} not found!')
        # for num,text,lvl in iter_mjolist(infile, args.loglvl):#, args.verbose):
        #     if lvl == 0:
        #         print(f'{S.BRIGHT}{F.YELLOW}{text}{S.RESET_ALL}')
        #     elif lvl == 1:
        #         print(f'{S2.ITALIC}{S.NORMAL}{F.CYAN}{text}{S.RESET_ALL}')
        #     elif lvl == 2:
        #         print(f'{S2.ITALIC}{S.DIM}{F.GREEN}{text}{S.RESET_ALL}')
        #     elif lvl == 3:
        #         print(f'{text}')

        # list(iter_mjolist(infile, args.loglvl, args.verbose))

    return 0


if __name__ == '__main__':
    exit(main())
    # list(iter_mjolist('mjolist_scripts.lst'))

