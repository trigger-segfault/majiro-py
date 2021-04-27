#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Read and validate syscalls stored in CSV from the Google Sheets document
<https://docs.google.com/spreadsheets/d/1p03_q6VTfYQEjlDhpypgoPdLQREhXwXz2ObTUkz5dlY>
"""

__version__ = '0.1.0'
__date__    = '2021-04-27'
__author__  = 'Robert Jordan'

__all__ = []

#######################################################################################

import csv, enum, io, os
from collections import namedtuple, OrderedDict
from itertools import chain
from types import SimpleNamespace
from typing import List, Dict, Tuple, Union

from mjotool._util import Fore as F, Style as S
from mjotool.flags import MjoType, MjoTypeMask, MjoScope
from mjotool.crypt import hash32

#######################################################################################

#region ## GOOGLE SHEET DOWNLOAD ##

SheetID = namedtuple('SheetID', ('longid', 'gid'))

def download_googlesheet(sheetid:Union[SheetID,str], gid:int=None, *, format:str='csv', encoding:str='utf-8', ignorestatus:bool=False) -> str:
    """download_googlesheet(longid, gid=0) -> csv:str
    download_googlesheet(SheetID(longid, gid)) -> csv:str
    download_googlesheet(SheetID(longid, gid), format='tsv') -> tsv:str
    """
    if isinstance(sheetid, tuple):
        sheetid, gid = sheetid
    if gid is None:
        gid = 0
    #source: <https://stackoverflow.com/a/37706008/7517185>
    url = f'https://docs.google.com/spreadsheets/d/{sheetid}/export?gid={gid}&format={format}&id={sheetid}'

    #source: <https://stackoverflow.com/a/7244263/7517185>
    import urllib.request  # this import is sloooooooooooow
    response = urllib.request.urlopen(url)
    if not ignorestatus and response.status != 200:
        raise Exception(f'Unexpected HTTP response status {response.status}')
    data = response.read()
    return data if (encoding is None) else data.decode(encoding)

#endregion

#######################################################################################

GROUP_SYSCALL:str = 'MAJIRO_INTER'
GROUP_DEFAULT:str = 'GLOBAL'
GROUP_LOCAL:str   = ''

MajiroData:str = r"1p03_q6VTfYQEjlDhpypgoPdLQREhXwXz2ObTUkz5dlY"
MajiroData_Syscalls:SheetID = SheetID(MajiroData, 0)

## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        add_help=True)

    parser.add_argument('inputs', metavar='CSVFILE', nargs='*',
        help='local csv syscalls file to read')
    parser.add_argument('-G', '--google', dest='sheets', default=[], const=MajiroData_Syscalls, action='append_const', required=False,
        help='download csv syscalls file from Google Sheets')
    parser.add_argument('-t', '--tsv', dest='format', const='tsv', default='csv', action='store_const', required=False,
        help='change the csv delimiter to tabs')
    parser.add_argument('-c', '--csv', dest='format', const='csv', action='store_const', required=False,
        help='change the csv delimiter to comma (default)')

    args = parser.parse_args(argv)

    # print(args)
    # return 0
    
    # arguments:
    inputs = args.sheets + args.inputs
    gformat:str = args.format
    delimiter:str = ',' if args.format == 'csv' else '\t'

    ###########################################################################

    # helpers for reading:
    class Field(enum.Enum):
        HASH      = 'Hash'      # hex hash value taken from the engine. Should be checked with hash32(f'${name}@MAJIRO_INTER')
        ADDRESS   = 'Address'   # hex syscall function address in ClosedGAME Majiro engine (expect "inline" values)
        RETURN    = 'Return'    # return value, uses type aliases for ints when necessary (expect other names like any/void, etc.)
        NAME      = 'Name'      # syscall name (sometimes ends with '?' for unsure names)
        ARGUMENTS = 'Arguments' # function arguments, there is a syntax to these, but at the moment they're not used
        STATUS    = 'Status'    # name status, is this name confirmed to be correct? (see Status enum below)
        NOTES     = 'Notes'     # other notes, only included for unexpected or strange behavior

    class Status(enum.Enum):
        NONE      = ''          # no status, not even inspected yet
        UNHASHED  = 'unhashed'  # name has been confirmed AND unhashed name matches hash value
        INCORRECT = 'incorrect' # guessed/likely name did not match hash value
        CONFIRMED = 'confirmed' # name is confirmed through inspection of .mjs soruce scripts
        LIKELY    = 'likely'    # name is likely, by going off of log/error messages found in asm
        GUESSED   = 'guessed'   # name is purely guessed (and may only be used to describe function)

    TYPEDEFS:Dict[MjoType,List[str]] = OrderedDict([
        (MjoType.UNKNOWN, ['']),
        (Ellipsis,        ['void','any','any/void']),
        (MjoType.INT,     ['int','bool', 'func*','file*','page*','sprite*']),
        (MjoType.FLOAT,   ['float']),
        (MjoType.STRING,  ['string']),
        (MjoType.INT_ARRAY,    ['int[]']),
        (MjoType.FLOAT_ARRAY,  ['float[]']),
        (MjoType.STRING_ARRAY, ['string[]']),
    ])
    TYPEDEF_LOOKUP:Dict[str,MjoType] = OrderedDict(chain(*[[(k,t) for k in keys] for t,keys in TYPEDEFS.items()]))

    # read a csv syscalls file using the known field column names (see Field enum)
    def read_file(reader:csv.DictReader):
        status_counts = OrderedDict() #[(c,0) for c in Status.__members__.values()])
        return_counts = OrderedDict()

        for row in reader:
            hashvalue:int = int(row[Field.HASH.value], 16)
            address:str   = row[Field.ADDRESS.value]
            retvalue:str  = row[Field.RETURN.value]
            name:str      = row[Field.NAME.value]
            args:str      = row[Field.ARGUMENTS.value]
            status:Status = Status(row[Field.STATUS.value])
            notes:str     = row[Field.NOTES.value]

            # name corrections:
            if name and name[0] != '$': # syscalls don't include '$' prefix
                name = f'${name}'
            fullname = f'{name}@{GROUP_SYSCALL}'
            if retvalue in ('file','page','sprite'): # older sheets before adding '*' for ptr types
                retvalue = f'{retvalue}*'

            # name lookups:
            rettype = TYPEDEF_LOOKUP[retvalue]

            # validation/errors/warnings:
            if name and status in (Status.UNHASHED, Status.LIKELY, Status.CONFIRMED):
                fullhash = hash32(fullname)
                if fullhash != hashvalue:
                    print(f'{S.BRIGHT}{F.RED}ERROR:{S.RESET_ALL} hashvalue mismatch! {hashvalue:08x} vs {fullhash:08x} : {name}')
            if name and (True or status in (Status.UNHASHED, Status.LIKELY, Status.CONFIRMED)):
                postfix = MjoType.frompostfix_name(name, allowunk=True)
                if rettype not in (Ellipsis, MjoType.UNKNOWN) and rettype != postfix:
                    print(f'{S.BRIGHT}{F.RED}ERROR:{S.RESET_ALL} return/postfix mismatch! {hashvalue:08x} : {name}')
            
            # statistics:
            status_counts.setdefault(status, 0)
            status_counts[status] += 1
            return_counts.setdefault(retvalue, 0)
            return_counts[retvalue] += 1
        
        # print statistics:
        max_len = max([len(k.value) for k in status_counts.keys()] + [len(k) for k in return_counts.keys()])

        # print status statistics:
        total = sum(status_counts.values())
        total_cat = sum([c for s,c in status_counts.items() if s is not Status.NONE])
        print(f'{S.BRIGHT}{F.BLUE}CATEGORIES: [STATUS]{S.RESET_ALL}')
        for k in Status.__members__.values():
            cnt = status_counts.get(k, 0)
            #for k,cnt in status_counts.items():
            if cnt == 0: print(f'{S.BRIGHT}{F.BLACK}',end='')
            print(f' {k.value.ljust(max_len)} : {cnt:d}{S.RESET_ALL}')
        print(f'{S.BRIGHT}{F.WHITE} {"total".ljust(max_len)} : {total_cat:d}/{total:d}{S.RESET_ALL}')

        # print return type statistics:
        for t,keys in TYPEDEFS.items():
            name = 'OTHER' if t is Ellipsis else t.name
            print(f'{S.BRIGHT}{F.BLUE}RETURNS: [{name}]{S.RESET_ALL}')
            for k in keys:
                cnt = return_counts.get(k, 0) # '*' now included for pointer int types
                if cnt == 0: print(f'{S.BRIGHT}{F.BLACK}',end='')
                print(f' {k.ljust(max_len)} : {cnt:d}{S.RESET_ALL}')


    # read from all inputs: (which includes Google Sheets for the -G option)
    for i,infile in enumerate(inputs):
        # special handling for Google Sheet input files:
        if isinstance(infile, SheetID):
            print(f'{S.BRIGHT}{F.YELLOW}Downloading:{S.RESET_ALL} {S.DIM}{F.GREEN}{infile!r}{S.RESET_ALL}')
            f = io.StringIO(download_googlesheet(infile, format=gformat))
        else:
            print(f'{S.BRIGHT}{F.CYAN}Reading:{S.RESET_ALL} {S.DIM}{F.CYAN}{infile!r}{S.RESET_ALL}')
            f = open(infile, 'rt', encoding='utf-8')
        with f:
            read_file(csv.DictReader(f, delimiter=delimiter))
        if i+1 < len(inputs):
            print()

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())
