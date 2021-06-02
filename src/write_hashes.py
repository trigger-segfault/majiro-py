#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Read Majiro Engine hashes and names from a multitude of files and write to output files
"""

__version__ = '1.2.0'
__date__    = '2021-06-02'
__author__  = 'Robert Jordan'

#######################################################################################

## the code in this file is not fit for humans. or robots. or anyone. ##
## viewer discretion is advised, please look away                     ##

#######################################################################################

import io, json, os
from collections import namedtuple
from typing import Dict, Iterable, List, Set, Tuple

# general use
from mj.util.color import Fore as F, Style as S
from mj.crypt import hash32
# load hashes from Python mj.database.hashes module
from mj.database import hashes as known_hashes
# load hashes from Google Sheets
from mj.database.sheets import SheetSyscalls, SheetGroups, SheetFunctions, SheetVariables, SheetLocals, SheetCallbacks, Status
# load hashes from mjs/mjh source scripts
from mjotool.mjs.mjsreader import MjsReader  # (only thing left still depending on mjotool package)



# used by write_python_file(), write_json_file()
HashSelection = namedtuple('HashSelection', ('name', 'varname', 'varlookup', 'hashes', 'prefixes', 'comment'))
GroupSelection = namedtuple('GroupSelection', ('name', 'varname', 'groups', 'type', 'comment'))

# comment formatting for write_python_file(), write_python_comment()
MULTI_FMT:str = '=' # replace N '=' prefixed chars with N '#' comment chars
HR_FMT:str = '==HR==' # replace full line with only this to `PYTHON_HR` seen below
PYTHON_HR:str = '#######################################################################################'

#######################################################################################


#region ## SELECT AND SORT ##

def select_hashes(hash_dict:Dict[int,Tuple[str,str]], *prefixes:str, sort:bool=True) -> List[Tuple[int,str]]:
    if not prefixes: # use all items
        hash_list = list(hash_dict.items())
    else:
        hash_list = []
        for prefix in prefixes:
            hash_list.extend((h,(sig,s)) for h,(sig,s) in hash_dict.items() if sig[0] == prefix)
    
    if sort:
        hash_list.sort(key=lambda v: v[1][1]) #.fullname)
    return [(h,sig) for h,(sig,_) in hash_list]

def select_groups(group_list:List[str], sort:bool=True) -> List[str]:
    group_list = list(group_list)
    if sort:
        group_list.sort()
    return group_list

#endregion

#region ## WRITE DICT/LIST ##

def write_hashes_dict(writer:io.TextIOBase, hash_list:List[Tuple[int,str]], *, readable:bool=False, python:bool=False, tab:str='\t', singlequotes:bool=True, pybraces:Tuple[str,str]=('{','}')):
    writer.write(pybraces[0] if python else '{')

    for i,(h,sig) in enumerate(hash_list):
        # comma-separate after first item
        if i:        writer.write(',')
        # newline and indent
        if readable: writer.write('\n' + tab)
        
        if python: # we don't have to use butt-ugly string hex values
            writer.write(f'0x{h:08x}:') 
        else:      # bleh, JSON doesn't support hex OR numeric keys
            writer.write(f'"{h:08x}":')
        
        # visual space between key and value
        if readable: writer.write(' ')

        if python and singlequotes: # just use normal-repr single-quotes
            # also a bad hack, because repr does not guarantee one quote or the other
            #  in CPython we trust
            writer.write(repr(sig)) #.fullname))
        else:
            #FIXME: bad hack for double-quotes
            r = repr(sig)[1:-1].replace('\\\'', '\'').replace('\"', '\\\"')
            writer.write(f'"{r}"') #.fullname)[1:-1]))
        writer.flush()

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write(pybraces[1] if python else '}')

def write_groups_list(writer:io.TextIOBase, group_list:List[str], is_hex:bool, *, readable:bool=False, python:bool=False, tab:str='\t', singlequotes:bool=True, pybraces:Tuple[str,str]=('[',']')):
    writer.write(pybraces[0] if python else '[')

    for i,group in enumerate(group_list):
        # comma-separate after first item
        if i:        writer.write(',')
        # newline and indent
        if readable: writer.write('\n' + tab)

        if is_hex:
            if python:
                writer.write(f'0x{group:08x}')
            else:
                writer.write(f'"{group:08x}"')
        elif python and singlequotes: # just use normal-repr single-quotes
            # also a bad hack, because repr does not guarantee one quote or the other
            #  in CPython we trust
            writer.write(repr(group)) #.fullname))
        else: # json
            #FIXME: bad hack for double-quotes
            r = repr(group)[1:-1].replace('\\\'', '\'').replace('\"', '\\\"')
            writer.write(f'"{r}"') #.fullname)[1:-1]))
        writer.flush()

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write(pybraces[1] if python else ']')

#endregion


#######################################################################################

#region ## WRITE PYTHON FILE ##

def write_python_comment(writer:io.TextIOBase, comment:str):
    if comment is None:
        return 

    # allow prefixed and postfixed newlines to act as extra spacing
    comment_lines = comment.replace('\r\n', '\n').split('\n')
    for j,comment_line in enumerate(comment_lines):
        if comment_line == HR_FMT:
            # format for: `#################...` horizontal rule
            writer.write(f'\n{PYTHON_HR}')
        elif not any((c not in ('',HR_FMT)) for c in comment_lines[:j+1]) or not any((c not in ('',HR_FMT)) for c in comment_lines[j:]):
            # format for: `` empty line without comment
            writer.write('\n')
        elif comment_line.startswith(MULTI_FMT):
            # format for: `### variable-thickness`
            trimmed = comment_line.lstrip(MULTI_FMT)
            punc = '#' * (len(comment_line) - len(trimmed))
            writer.write(f'\n{punc} {trimmed}')
        else:
            writer.write(f'\n# {comment_line}')

def write_python_file(writer:io.TextIOBase, hash_items:List[HashSelection], group_items:List[GroupSelection], *, readable:bool=True, sort:bool=True):
    all_names = []
    writer.write('#!/usr/bin/env python3\n')
    writer.write('#-*- coding: utf-8 -*-\n')
    writer.write('"""Known hashes, groups, and callbacks for Majiro  (this file was auto-generated)\n')
    writer.write('\n')
    writer.write('Contains:\n')
    hash_lists = []
    group_lists = []
    for i,item in enumerate(hash_items):
        hash_lists.append(select_hashes(item.hashes, *item.prefixes, sort=sort))
        writer.write(f' {len(hash_lists[-1]):<3d} {item.name} names\n')
        all_names.extend((item.varname, item.varlookup))
    for i,item in enumerate(group_items):
        group_lists.append(select_groups(item.groups, sort=sort))
        if item.type is int:
            writer.write(f' {len(group_lists[-1]):<3d} {item.name} hashes\n')
        else:
            writer.write(f' {len(group_lists[-1]):<3d} {item.name} names\n')
        all_names.append(item.varname)
    writer.write('"""\n')
    writer.write('\n')
    writer.write(f'__version__ = {__version__!r}\n')
    writer.write(f'__date__    = {__date__!r}\n')
    writer.write(f'__author__  = {__author__!r}\n')
    writer.write('\n')
    writer.write(f'__all__ = {all_names!r}\n')
    writer.write('\n')
    # writer.write('#######################################################################################\n')
    writer.write(f'{PYTHON_HR}\n')
    writer.write('\n')
    writer.write('from typing import Dict, List\n')

    if hash_items:
        writer.write('\n')
    for i,item in enumerate(hash_items):
        hash_list = hash_lists[i]
        write_python_comment(writer, item.comment)
        writer.write(f'\n{item.varname}:Dict[int,str] = ')
        write_hashes_dict(writer, hash_list, readable=False, python=True)
        writer.write(f'\n{item.varlookup}:Dict[str,int] = dict((v,k) for k,v in {item.varname}.items())')
        writer.write('\n')
    
    if group_items:
        writer.write('\n')
    for i,item in enumerate(group_items):
        group_list = group_lists[i]
        write_python_comment(writer, item.comment)
        writer.write(f'\n{item.varname}:List[{item.type.__name__}] = ')
        write_groups_list(writer, group_list, item.type is int, readable=False, python=True)
        writer.write('\n')

    # writer.write('\n\n#######################################################################################\n\n')
    writer.write(f'\n\n{PYTHON_HR}\n\n')
    writer.write('del Dict, List  # cleanup declaration-only imports\n')

#endregion

#region ## WRITE JSON FILE ##

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

        writer.write(f'"{item.varname}":')
        
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

        writer.write(f'"{item.varname}":')
        
        # visual space between key and value
        if readable:   writer.write(' ')

        group_list = select_groups(item.groups, sort=sort)
        write_groups_list(writer, group_list, item.type is int, readable=False, python=False)

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write('}')

#endregion


#######################################################################################

#region ## READ MJS HASHES ##

def load_mjs_hashes(filename:str, var_hashes:Dict[int,str], func_hashes:Dict[int,str], group_names:Set[str], *, verbose:bool):
    if verbose:
        print(f'{S.BRIGHT}{F.YELLOW}Including MJS Script:{S.RESET_ALL} {S.BRIGHT}{F.RED}{os.path.basename(filename)}{S.RESET_ALL}')
    mjsreader = MjsReader(filename, encoding='utf-8')
    mjsreader.read()
    # only parse, what you need - Liberty Mutable
    if var_hashes is not None:
        var_hashes.update((h,sig.fullname) for h,sig in mjsreader.var_hashes.items())
    if func_hashes is not None:
        func_hashes.update((h,sig.fullname) for h,sig in mjsreader.func_hashes.items())
    if group_names is not None:
        group_names.update(mjsreader.group_names)

#endregion

#region ## READ JSON HASHES ##

def parse_json_hashes(data:dict) -> Iterable[Tuple[int,str]]:
    # expects: {"HEXHASH": "IDENTIFIERNAME@GROUP", ...}
    # hex prefixes: "", "$", "0x", "0X"
    def parse_hash(key:str) -> int:
        if key[:1] == '$':
            key = key[1:]
        elif key[:2] in ('0x','0X'):
            key = key[2:]
        return int(key, 16)

    return ((parse_hash(k), v) for k,v in data.items())

def parse_json_groups(data:list) -> Iterable[str]:
    # expects: ["name1", "name2", ...]
    # strips "@" before name if present
    def parse_group(key:str) -> int:
        return key[1:] if (key[:1] == '@') else key

    if isinstance(data, dict):
        data = data.values()
    return (parse_group(k) for k in data)

def parse_json_callbacks(data:list) -> Iterable[str]:
    if isinstance(data, dict):
        data = data.values()
    return data

def load_json_hashes(filename:str, hash_dict:Dict[int,str], *, verbose:bool):
    if verbose:
        print(f'{S.BRIGHT}{F.YELLOW}Including JSON:{S.RESET_ALL} {S.BRIGHT}{F.CYAN}{os.path.basename(filename)}{S.RESET_ALL}')
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader) # expects: {"HEXHASH": "IDENTIFIERNAME@GROUP", ...}
                                 # hex prefixes: "", "$", "0x", "0X"
        hash_dict.update(parse_json_hashes(data))

def load_json_groups(filename:str, group_names:Set[str], *, verbose:bool):
    if verbose:
        print(f'{S.BRIGHT}{F.YELLOW}Including JSON:{S.RESET_ALL} {S.BRIGHT}{F.CYAN}{os.path.basename(filename)}{S.RESET_ALL}')
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader) # expects: ["name1", "name2", ...]
                                 # strips "@" before name if present
        group_names.update(parse_json_groups(data))

def load_json_callbacks(filename:str, evt_names:Set[str], *, verbose:bool):
    if verbose:
        print(f'{S.BRIGHT}{F.YELLOW}Including JSON:{S.RESET_ALL} {S.BRIGHT}{F.CYAN}{os.path.basename(filename)}{S.RESET_ALL}')
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader)
        evt_names.update(parse_json_callbacks(data))

def load_json_all(filename:str, var_hashes:Dict[int,str], func_hashes:Dict[int,str], sys_hashes:Dict[int,str], group_names:Set[str], evt_names:Set[str], *, verbose:bool):
    if verbose:
        print(f'{S.BRIGHT}{F.YELLOW}Including JSON:{S.RESET_ALL} {S.BRIGHT}{F.CYAN}{os.path.basename(filename)}{S.RESET_ALL}')
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader)

        if var_hashes and "variables" in data:
            var_hashes.update(parse_json_hashes(data["variables"]))
        if var_hashes and "local_vars" in data:
            var_hashes.update(parse_json_hashes(data["local_vars"]))
        if var_hashes and "thread_vars" in data:
            var_hashes.update(parse_json_hashes(data["thread_vars"]))
        if var_hashes and "savefile_vars" in data:
            var_hashes.update(parse_json_hashes(data["savefile_vars"]))
        if var_hashes and "save_vars" in data:
            var_hashes.update(parse_json_hashes(data["save_vars"]))
        if var_hashes and "persistent_vars" in data:
            var_hashes.update(parse_json_hashes(data["persistent_vars"]))
        if var_hashes and "persist_vars" in data:
            var_hashes.update(parse_json_hashes(data["persist_vars"]))

        if func_hashes and "functions" in data:
            func_hashes.update(parse_json_hashes(data["functions"]))
        if func_hashes and "usercalls" in data:
            func_hashes.update(parse_json_hashes(data["usercalls"]))

        if sys_hashes and "syscalls" in data:
            sys_hashes.update(parse_json_hashes(data["syscalls"]))
        if group_names and "groups" in data:
            group_names.update(parse_json_groups(data["groups"]))
        if group_names and "callbacks" in data:
            evt_names.update(parse_json_callbacks(data["callbacks"]))

#endregion

#region ## READ PYTHON HASHES ##

def load_python_hashes(var_hashes:Dict[int,str], func_hashes:Dict[int,str], sys_hashes:Dict[int,str], group_names:Set[str], evt_names:Set[str], sys_list:List[int], *, verbose:bool):
    if verbose:
        print(f'{S.BRIGHT}{F.YELLOW}Including Python Module:{S.RESET_ALL} {S.BRIGHT}{F.BLUE}known_hashes{S.RESET_ALL}')
    for h,v in known_hashes.SYSCALLS.items():
        sys_hashes[h] = v
    for h,v in known_hashes.FUNCTIONS.items():
        func_hashes[h] = v
    for h,v in known_hashes.VARIABLES.items():
        var_hashes[h] = v
    for v in known_hashes.GROUPS.values():
        group_names.add(v)
    for v in known_hashes.CALLBACKS.values():
        evt_names.add(v)
    
    if sys_list is not None:
        for v in known_hashes.SYSCALLS_LIST:
            sys_list.append(v)

#endregion

#region ## READ GOOGLE SHEET HASHES ##

def load_sheet(sheettype:type, format:str='csv', update:bool=False, *, verbose:bool):
    cache_file:str = f'sheet_{sheettype.NAME.replace(" ","")}_cached.{format}'
    if update or not os.path.isfile(cache_file):
        if verbose:
            print(f'{S.BRIGHT}{F.YELLOW}Including Sheet:{S.RESET_ALL} {S.BRIGHT}{F.GREEN}[Downloading]{S.RESET_ALL} {S.DIM}{F.GREEN}Majiro Data - {sheettype.NAME}{S.RESET_ALL}')
        sheet = sheettype.fromsheet(format=format, cache_file=cache_file)
    else:
        if verbose:
            print(f'{S.BRIGHT}{F.YELLOW}Including Sheet:{S.RESET_ALL} {S.BRIGHT}{F.MAGENTA}[Cached]{S.RESET_ALL} {S.DIM}{F.GREEN}Majiro Data - {sheettype.NAME}{S.RESET_ALL}')
        sheet = sheettype.fromfile(cache_file, format=format)

    for item in sheet.verify(error=False):
        print(f'{S.BRIGHT}{F.RED}Error: mismatch {F.BLUE}{item.hash:08x}{F.RED} != {F.YELLOW}{hash32(item.fullname):08x}{F.RED} for {F.YELLOW}"{item.name}"{S.RESET_ALL}')
    return sheet

def load_sheets_all(var_hashes:Dict[int,str], func_hashes:Dict[int,str], sys_hashes:Dict[int,str], group_names:Set[str], evt_names:Set[str], sys_list:List[int], *, verbose:bool, format:str='csv', update:bool=False, allow_collisions:list=()):
    # syscalls:
    for row in load_sheet(SheetSyscalls, format, update, verbose=verbose):
        if sys_list is not None and isinstance(row.hash, int): # make sure the row has a defined hash value
            sys_list.append(row.hash)
        if not row.unhashed and not (row.status is Status.COLLISION and row.fullname in allow_collisions):
            continue
        if '@' in row.name[1:] or row.name[:1] != '$':
            raise ValueError(f'Expected syscall name to contain no group and start with \'$\', got {row.name!r}')
        sys_hashes[row.hash] = row.name
    # functions:
    for row in load_sheet(SheetFunctions, format, update, verbose=verbose):
        if not row.unhashed and not (row.status is Status.COLLISION and row.fullname in allow_collisions):
            continue
        if '@' not in row.fullname[1:] or row.fullname[:1] != '$':
            raise ValueError(f'Expected function name to contain group and start with \'$\', got {row.fullname!r}')
        func_hashes[row.hash] = row.fullname
    # variables (local):
    for row in load_sheet(SheetLocals, format, update, verbose=verbose):
        if not row.unhashed and not (row.status is Status.COLLISION and row.fullname in allow_collisions):
            continue
        if '@' not in row.fullname[1:] or row.fullname[:1] not in ('_','%','@','#'):
            raise ValueError(f'Expected local name to contain group and start with [_%@#], got {row.fullname!r}')
        var_hashes[row.hash] = row.fullname
    # variables (non-local):
    for row in load_sheet(SheetVariables, format, update, verbose=verbose):
        if not row.unhashed and not (row.status is Status.COLLISION and row.fullname in allow_collisions):
            continue
        if '@' not in row.fullname[1:] or row.fullname[:1] not in ('_','%','@','#'):
            raise ValueError(f'Expected variable name to contain group and start with [_%@#], got {row.fullname!r}')
        var_hashes[row.hash] = row.fullname
    # groups:
    for row in load_sheet(SheetGroups, format, update, verbose=verbose):
        if not row.unhashed and not (row.status is Status.COLLISION and row.name in allow_collisions):
            continue
        if '@' in row.name:
            raise ValueError(f'Expected group name to contain no \'@\', got {row.name!r}')
        group_names.add(row.name)
    # callbacks:
    for row in load_sheet(SheetCallbacks, format, update, verbose=verbose):
        if not row.unhashed and not (row.status is Status.COLLISION and row.name in allow_collisions):
            continue
        evt_names.add(row.name)

#endregion

#######################################################################################

## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    ## PARSER SETUP ##

    DEFAULT_MJS = [f'../data/mjs/{f}' for f in [
        'adv.mjh.bak',
        'console.mjs.old',
        'console.mjs.old2',
    ]]
    # scenario.arc/originals.7z/* from "Ame no Marginal -Rain Marginal-"" (EN)
    #  this data is not included in the repository for obvious reasons
    AME_ORIGINALS = [f'../data/copyright/ame_originals/{f}' for f in [
        'おまけ.txt', 'オリジナル0.txt',
        'オリジナル01.txt', 'オリジナル02.txt', 'オリジナル03.txt', 'オリジナル04.txt', 'オリジナル05.txt',
        'オリジナル06.txt', 'オリジナル07.txt', 'オリジナル08.txt', 'オリジナル09.txt', 'オリジナル010.txt',
        'スタッフとも.txt',
    ]]

    import argparse
    parser = argparse.ArgumentParser(
        description='Read Majiro Engine hashes and names from a multitude of files and write to py+json output files',
        add_help=True)

    # pgroup = parser.add_mutually_exclusive_group()
    # parser.add_argument('-o', '--output', metavar='PYFILE', required=False, help='output python _hashes module file')
    parser.add_argument('-i', '--input', dest='inputs', metavar='MJSFILE', nargs='+', default=[], required=False, help='parse hashes and groups from mjs/mjh files')
    parser.add_argument('-I', '--input-mjs', dest='inputs2', action='store_const', const=DEFAULT_MJS, default=[], required=False, help='parse hashes and groups from all repo mjs/mjh files')
    parser.add_argument('-A', '--ame-mjs', dest='inputs3', action='store_const', const=AME_ORIGINALS, default=[], required=False, help='parse hashes and groups from all repo \"Ame no Marginal original\" script files (not included)')
    parser.add_argument('-P', '--python', dest='python', default=False, action='store_true', required=False, help='read hashes from python mj.database.hashes module')
    parser.add_argument('-G', '--google', dest='google', default=False, action='store_true', required=False, help='read hashes, groups, and callbacks from Google Sheets')
    parser.add_argument('-U', '--update', dest='update', default=False, action='store_true', required=False, help='update Google Sheet cached files and always download new copies')
    parser.add_argument('-H', '--hashes', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse user-defined hashes from json files')
    parser.add_argument('-s', '--syscalls', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse syscall hashes from json files')
    parser.add_argument('-g', '--groups', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse groups from json files')
    parser.add_argument('-c', '--callbacks', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse callbacks from json files')
    parser.add_argument('-a', '--all', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse "syscalls", "functions", "variables", and "groups" from json files')
    
    pgroup = parser.add_mutually_exclusive_group()
    pgroup.add_argument('--csv', dest='format', default='csv', action='store_const', const='csv', required=False, help='csv Google Sheets format')
    pgroup.add_argument('--tsv', dest='format', action='store_const', const='tsv', required=False, help='tsv Google Sheets format')
    
    parser.add_argument('-q','--quiet-includes', dest='verbose_includes', action='store_false', default=True, required=False, help='disable printing of included sources')
    parser.add_argument('-T','--test', dest='test_name', action='store_const', default='', const='__test', required=False, help='write hashes to files with \"__test\" appended to the name')

    ###########################################################################

    args = parser.parse_args(argv)

    # print(args)
    # return 0

    ## VARIABLE SETUP ##

    callback_names:Set[str] = set()
    group_names:Set[str] = set()
    var_hashes:Dict[int,str] = {}
    func_hashes:Dict[int,str] = {}
    sys_hashes:Dict[int,str] = {}
    sys_list:List[int] = []

    # predefined known hashes that won't show up as declarations
    EXTRA_VAR_HASHES = {0xa704bdbd:"__SYS__NumParams@"}
    EXTRA_FUNC_HASHES = {}
    EXTRA_SYS_HASHES = {} # nothing yet

    var_hashes.update(EXTRA_VAR_HASHES)
    func_hashes.update(EXTRA_FUNC_HASHES)
    sys_hashes.update(EXTRA_SYS_HASHES)

    ###########################################################################

    ## DEFAULT BEHAVIOR ##

    if not args.google and not args.python and not (args.inputs + args.inputs2 + args.inputs3 + args.hashes + args.syscalls + args.groups + args.callbacks + args.all):
        for scriptfile in DEFAULT_MJS:
            load_mjs_hashes(scriptfile, var_hashes, func_hashes, group_names, verbose=args.verbose_includes)

    ## LOAD FILES ##

    for scriptfile in set(args.inputs + args.inputs2 + args.inputs3):
        load_mjs_hashes(scriptfile, var_hashes, func_hashes, group_names, verbose=args.verbose_includes)
    
    for jsonfile in args.hashes:
        # combination of all user-defined hashes (these can be seperated later by the prefix)
        user_hashes:Dict[int,str] = {}
        load_json_hashes(jsonfile, user_hashes, verbose=args.verbose_includes)
        for k,v in user_hashes.items():
            if v.fullname == '$':
                func_hashes[k] = v
            else:
                var_hashes[k] = v
        del user_hashes

    for jsonfile in args.syscalls:
        load_json_hashes(jsonfile, sys_hashes, verbose=args.verbose_includes)

    for jsonfile in args.groups:
        load_json_groups(jsonfile, group_names, verbose=args.verbose_includes)

    for jsonfile in args.callbacks:
        load_json_callbacks(jsonfile, callback_names, verbose=args.verbose_includes)

    for jsonfile in args.all:
        load_json_all(jsonfile, var_hashes, func_hashes, sys_hashes, group_names, callback_names, verbose=args.verbose_includes)
    
    if args.python:
        sys_list = []
        load_python_hashes(var_hashes, func_hashes, sys_hashes, group_names, callback_names, sys_list, verbose=args.verbose_includes)

    if args.google:
        sys_list = []
        load_sheets_all(var_hashes, func_hashes, sys_hashes, group_names, callback_names, sys_list, format=args.format, update=args.update,
            allow_collisions=('%Op_internalCase~@MAJIRO_INTER',), verbose=args.verbose_includes)

    # add main function hashes for all known groups (even if they aren't used)
    for group in group_names:
        funcname = f'$main@{group}'
        func_hashes[hash32(funcname)] = funcname

    # generate hash lookups used for following types,
    #  group hashes are stored as a hash with the `$main` function for easy `#group` preprocessor identification
    group_hashes:Dict[int,str] = dict((hash32(f'$main@{g}'), g) for g in group_names)
    callback_hashes:Dict[int,str] = dict((hash32(c), c) for c in callback_names)


    ###########################################################################

    ### VALIDATION (NOTE: also performed by load_sheet())

    for h,v in list(var_hashes.items()) + list(func_hashes.items()):
        if hash32(v)!=h: print(f'{S.BRIGHT}{F.RED}Error: mismatch {F.BLUE}{h:08x}{F.RED} != {F.YELLOW}{hash32(v):08x}{F.RED} for {F.YELLOW}"{v}"{S.RESET_ALL}')
    for h,v in [(h,v+'@MAJIRO_INTER') for h,v in sys_hashes.items()]:
        if hash32(v)!=h: print(f'{S.BRIGHT}{F.RED}Error: mismatch {F.BLUE}{h:08x}{F.RED} != {F.YELLOW}{hash32(v):08x}{F.RED} for {F.YELLOW}"{v}"{S.RESET_ALL}')

    ###########################################################################

    # datasets to initialize with list comprehension
    def _fmt_local(name:str) -> str:
        return name[:-1] if (len(name) > 1 and name[-1] == '@') else name
    def _fmt_syscall(name:str) -> str:
        return name[:-len('@MAJIRO_INTER')] if name.endswith('@MAJIRO_INTER') else name
    def _strip_group(name:str) -> str:
        idx_at = name.rfind('@', 1)
        return name[:idx_at] if (idx_at != -1) else name

    def _fmt_names(names:Dict[int,str], fmt_func) -> Dict[int,Tuple[str,str]]:
        return dict((k, (fmt_func(v), _strip_group(v))) for k,v in names.items())
    def fmt_locals(names:Dict[int,str]) -> Dict[int,Tuple[str,str]]:  # pylint: disable=unused-variable
        return _fmt_names(names, _fmt_local)
    def fmt_syscalls(names:Dict[int,str]) -> Dict[int,Tuple[str,str]]:
        return _fmt_names(names, _fmt_syscall)
    def fmt_sort(names:Dict[int,str]) -> Dict[int,Tuple[str,str]]:
        return _fmt_names(names, str)
    def fmt_none(names:Dict[int,str]) -> Dict[int,Tuple[str,str]]:
        return dict((k,(v,v)) for k,v in names.items())

    PY_HASHES = (
        ('local_vars', var_hashes, ('_',), fmt_sort, 'hashes for all four variable types: local, thread, savefile, persistent\n'),#fmt_locals),
        ('thread_vars', var_hashes, ('%',), fmt_sort, None),
        ('savefile_vars', var_hashes, ('@',), fmt_sort, None),
        ('persistent_vars', var_hashes, ('#',), fmt_sort, None),
        #('variables', var_hashes, (), fmt_sort, None),
        #('usercalls', func_hashes, (), fmt_sort, None),
        ('functions', func_hashes, (), fmt_sort, '\n==HR==\n\nhashes for user-defined and system-defined internal functions\n'),
        ('syscalls', sys_hashes, (), fmt_syscalls, '\nsystem call hashes all use the group name `$syscall@MAJIRO_INTER`'),
        ('groups', group_hashes, (), fmt_none, '\n==HR==\n\ngroup hashes are listed as the hash of `$main@GROUPNAME`,\n this is done in order to identify a file\'s common group from the entrypoint function hash'),
        ('callbacks', callback_hashes, (), fmt_none, 'event "callback" names used with `$event_*` system calls'),
    )
    
    JSON_HASHES = (
        ('variables', var_hashes, (), fmt_sort, None),
        #('usercalls', func_hashes, (), fmt_sort, None),
        ('functions', func_hashes, (), fmt_sort, None),
        ('syscalls', sys_hashes, (), fmt_syscalls, None),
        ('groups', group_hashes, (), fmt_none, None),
        ('callbacks', callback_hashes, (), fmt_none, None),
    )
    GROUPS = (
        ('syscall', 'syscalls_list', sys_list, int, '==HR==\n\nlist of all system call hash values, whether or not a name is known for the hash'),
        #('groups', 'groups', group_names, None),
    )
    if not sys_list:
        GROUPS = ()
    
    if args.verbose_includes:
        print()
    NAMES = (('syscalls', sys_hashes), ('functions', func_hashes), ('variables', var_hashes), ('groups', group_names), ('callbacks', callback_names))
    print(f'{S.BRIGHT}{F.BLUE}Found:{S.RESET_ALL}', ', '.join(f"{S.BRIGHT}{F.WHITE}{len(v)} {k}{S.RESET_ALL}" for k,v in NAMES) + ',', f'and {S.BRIGHT}{F.WHITE}{len(sys_list)} total syscall hashes{S.RESET_ALL}')

    ###########################################################################

    print()

    # write python for our library
    hash_items = [HashSelection(n.replace('_', ' ').rstrip('s'), n.upper(), f'{n.upper()}_LOOKUP', fn(d), p,c) for n,d,p,fn,c in PY_HASHES]
    group_items = [GroupSelection(n1.replace('_', ' ').rstrip('s'), n2.upper(), l, t, c) for n1,n2,l,t,c in GROUPS]
    #filename = f'../src/mjotool/known_hashes/_hashes{args.test_name}.py'
    filename = f'../src/mj/database/hashes/_hashes{args.test_name}.py'
    print(f'{S.BRIGHT}{F.GREEN}Writing:{S.RESET_ALL} {S.BRIGHT}{F.BLUE}{filename}{S.RESET_ALL}')
    with open(filename, 'wt+', encoding='utf-8') as writer:
        write_python_file(writer, hash_items, group_items, readable=False, sort=True)
        writer.flush()

    # write compact af json for non-humans
    hash_items = [HashSelection(n, n, f'{n}_lookup', fn(d), p,c) for n,d,p,fn,c in JSON_HASHES]
    group_items = [GroupSelection(n1, n2, l, t, c) for n1,n2,l,t,c in GROUPS]
    filename = f'../data/known_hashes_compact{args.test_name}.json'
    print(f'{S.BRIGHT}{F.GREEN}Writing:{S.RESET_ALL} {S.BRIGHT}{F.CYAN}{filename}{S.RESET_ALL}')
    with open(filename, 'wt+', encoding='utf-8') as writer:
        write_json_file(writer, hash_items, group_items, tab='\t', readable=False, sort=True)
        writer.flush()
    # write """readable""" json for everybody else
    filename = f'../data/known_hashes_readable{args.test_name}.json'
    print(f'{S.BRIGHT}{F.GREEN}Writing:{S.RESET_ALL} {S.BRIGHT}{F.CYAN}{filename}{S.RESET_ALL}')
    with open(filename, 'wt+', encoding='utf-8') as writer:
        write_json_file(writer, hash_items, group_items, tab='\t', readable=True, sort=True)
        writer.flush()

    print(f'{S.BRIGHT}{F.WHITE}[Finished]{S.RESET_ALL}')
    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

