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

import csv, enum, io, os, statistics, string
from collections import namedtuple, Counter, OrderedDict
from itertools import chain
from types import SimpleNamespace
from typing import List, Dict, Optional, Tuple, Union

from mjotool._util import Fore as F, Style as S
from mjotool.flags import MjoType, MjoTypeMask, MjoScope
from mjotool.crypt import hash32

#######################################################################################

#region ## GOOGLE SHEET DOWNLOAD ##

# SheetID = namedtuple('SheetID', ('longid', 'gid'))
class GoogleSheet(namedtuple('GoogleSheet', ('longid', 'gid'))):
    def __new__(cls, longid:str, gid:Optional[int]=None):
        return super().__new__(cls, longid, gid)
    
    def with_gid(self, gid:int) -> 'GoogleSheet':
        """gsheet.with_gid(gid) -> GoogleSheet(gsheet.longid, gid)
        """
        return GoogleSheet(self.longid, gid)

    @property
    def url(self) -> str:
        """gsheet.url -> csv_download_url:str

        alias for: gsheet.geturl()
        """
        return self.geturl()
    def geturl(self, gid:int=..., *, format:str='csv') -> str:
        """gsheet.get_url() -> csv_download_url:str
        gsheet.get_url([gid], format='tsv') -> tsv_download_url:str for new gid

        arguments:
          gid      - override GID "sheet" ID.
          format   - file format supported by Google Sheets (i.e. 'csv', 'tsv').

        returns:
          str - download url for Google Sheet.
        """
        #source: <https://stackoverflow.com/a/37706008/7517185>
        if gid is Ellipsis:
            gid = 0 if self.gid is None else self.gid
        elif gid is None:
            gid = 0
        return f'https://docs.google.com/spreadsheets/d/{self.longid}/export?gid={gid}&format={format}&id={self.longid}'
    
    def download(self, gid:int=..., *, format:str='csv', remove_crlf:bool=True, ignore_status:bool=False) -> str:
        """gsheet.download() -> csv_file:str
        gsheet.download([gid], format='tsv') -> tsv_file:str for new gid

        arguments:
          gid      - override GID "sheet" ID.
          format   - file format supported by Google Sheets (i.e. 'csv', 'tsv').
          remove_crlf   - replace all newlines '\\r\\n' (CRLF) with '\\n' (LF).
          ignore_status - do not raise exception for non-200 HTTP statuses.

        returns:
          str - text data of downloaded Google Sheet in specified format.
        """
        url:str = self.geturl(gid, format=format)

        #source: <https://stackoverflow.com/a/7244263/7517185>
        import urllib.request  # this import is sloooooooooooow
        response = urllib.request.urlopen(url)
        if not ignore_status and response.status != 200:
            raise Exception(f'Unexpected HTTP response status {response.status}')
        data:str = response.read().decode('utf-8')
        if remove_crlf:
            data = data.replace('\r\n', '\n')
        return data
    
    def open(self, gid:int=..., *, format:str='csv', remove_crlf:bool=True, ignore_status:bool=False) -> io.StringIO:
        """gsheet.open() -> io.StringIO(csv_file:str)
        gsheet.open([gid], format='tsv') -> io.StringIO(tsv_file:str for new gid)

        arguments:
          gid      - override GID "sheet" ID.
          format   - file format supported by Google Sheets (i.e. 'csv', 'tsv').
          remove_crlf   - replace all newlines '\\r\\n' (CRLF) with '\\n' (LF).
          ignore_status - do not raise exception for non-200 HTTP statuses.

        returns:
          io.StringIO - string reader of downloaded Google Sheet in specified format.
        """
        return io.StringIO(self.download(gid, format=format, remove_crlf=remove_crlf, ignore_status=ignore_status))

#endregion

#######################################################################################

GROUP_SYSCALL:str = 'MAJIRO_INTER'
GROUP_DEFAULT:str = 'GLOBAL'
GROUP_LOCAL:str   = ''

MajiroData:GoogleSheet = GoogleSheet(r"1p03_q6VTfYQEjlDhpypgoPdLQREhXwXz2ObTUkz5dlY")
## Hash|Address|Return|Name|Arguments|Status|Notes
MajiroData_Syscalls:GoogleSheet = MajiroData.with_gid(0)
## Hash|Source|Name|Status|Notes
MajiroData_Groups:GoogleSheet = MajiroData.with_gid(1562764366)
## Hash|Source|Return|Name|Group|Arguments|Status|Notes
MajiroData_Functions:GoogleSheet = MajiroData.with_gid(72122782)
## Hash|Source|Scope|Type|Name|Group|Status|Notes
MajiroData_Variables:GoogleSheet = MajiroData.with_gid(380736744)
## Hash|Type|Name|Status|Notes
MajiroData_Locals:GoogleSheet = MajiroData.with_gid(1596196937)
## Release|Developer|Name|Engine Build Date|Notes
MajiroData_Games:GoogleSheet = MajiroData.with_gid(2017266804)


## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        add_help=True)

    parser.add_argument('inputs', metavar='CSVFILE', nargs='*',
        help='local csv syscalls file to read')
    parser.add_argument('-G', '--google', dest='sheets', default=[], const=MajiroData_Syscalls, action='append_const', required=False,
        help='download csv syscalls file from Google Sheets')
    parser.add_argument('-C', '--google-cache', metavar='CSVFILE', dest='sheet_cache', action='store_const', const='syscalls_cached.{}', default=None, required=False,
        help='cache or used cached Google Sheets file \"syscalls_cached.<ext>\" (updates cache if -G option is present)')
    parser.add_argument('-o', '--google-output', metavar='CSVFILE', dest='sheet_output', default=None, required=False,
        help='save downloaded Google Sheets file to location')
    parser.add_argument('-t', '--tsv', dest='format', const='tsv', default='csv', action='store_const', required=False,
        help='change the csv delimiter to tabs')
    parser.add_argument('-c', '--csv', dest='format', const='csv', action='store_const', required=False,
        help='change the csv delimiter to comma (default)')
    parser.add_argument('-s', '--status', dest='show_status', default=False, action='store_true', required=False,
        help='show unhash status statistics')
    parser.add_argument('-r', '--returns', dest='show_returns', default=False, action='store_true', required=False,
        help='show return type statistics')
    parser.add_argument('-k', '--keywords', metavar='MIN', default=Ellipsis, type=int, action='store', nargs='?', required=False,
        help='show keyword statistics (optional argument removes counts <= MIN)')
    parser.add_argument('-l', '--letters', dest='letter_sort', default=None, action='store_false', required=False,
        help='show letter statistics (sort by: lowercase, uppercase, digits)')
    parser.add_argument('-L', '--letters-sort', dest='letter_sort', action='store_true', required=False,
        help='show letter statistics (sort by number of appearances)')
    parser.add_argument('-w', '--write-unknown', dest='write_unknown', default=False, action='store_true', required=False,
        help='output unknown hashes to file "syscalls_unknown.txt"')
    parser.add_argument('-W', '--write-collisions', dest='write_collisions', default=False, action='store_true', required=False,
        help='output collisions hashes to file "syscalls_collisions.txt"')

    args = parser.parse_args(argv)

    # print(args)
    # return 0
    
    # arguments:
    gformat:str = args.format
    delimiter:str = ',' if args.format == 'csv' else '\t'
    keywords_min:int = None if args.keywords is Ellipsis else (args.keywords or 0)
    letter_sort:bool = args.letter_sort
    show_status:bool = args.show_status
    show_returns:bool = args.show_returns
    inputs:list = args.sheets + args.inputs
    cache:str = args.sheet_cache
    cache_exists:bool = False
    SCRIPT_DIR:str = os.path.abspath(os.path.dirname(__file__))
    if cache:
        cache = cache.format(gformat)
        cachepath = os.path.join(SCRIPT_DIR, cache)
        cache_exists = os.path.isfile(cachepath)
        if not cache_exists and not args.sheets:
            raise argparse.ArgumentError('--google-cache', 'cached file not found! use -C with -G option to download and cache file')
        elif cache_exists and not args.sheets:
            # only use cache if -G option is missing (otherwise cache is updated)
            #NOTE: REMOVES args.sheets from inputs
            inputs = [cachepath] + args.inputs

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
        COLLISION = 'collision' # name is unhashed, but possibly only a collision, and not the original name
        PARTIAL   = 'partial'   # partial name has been unhashed through XOR proofs (either prefix or postfix)
        INCORRECT = 'incorrect' # guessed/likely name did not match hash value
        CONFIRMED = 'confirmed' # name is confirmed through inspection of .mjs soruce scripts
        LIKELY    = 'likely'    # name is likely, by going off of log/error messages found in asm
        GUESSED   = 'guessed'   # name is purely guessed (and may only be used to describe function)

    TYPEDEFS:Dict[MjoType,List[str]] = OrderedDict([
        (MjoType.UNKNOWN, ['']),
        (Ellipsis,        ['void','any','any/void']),
        (MjoType.INT,     ['int','bool','file*','page*','sprite*']),
        (MjoType.FLOAT,   ['float']),
        (MjoType.STRING,  ['string']),
        (MjoType.INT_ARRAY,    ['int[]']),
        (MjoType.FLOAT_ARRAY,  ['float[]']),
        (MjoType.STRING_ARRAY, ['string[]']),
    ])
    TYPEDEF_LOOKUP:Dict[str,MjoType] = OrderedDict(chain(*[[(k,t) for k in keys] for t,keys in TYPEDEFS.items()]))


    # read a csv syscalls file using the known field column names (see Field enum)
    def read_file(reader:csv.DictReader):
        if args.write_unknown:
            unkwriter = open('syscalls_unknown_cached.txt', 'wt+', encoding='utf-8')
        if args.write_collisions:
            clnwriter = open('syscalls_collisions_cached.txt', 'wt+', encoding='utf-8')
        status_counts = OrderedDict() #[(c,0) for c in Status.__members__.values()])
        return_counts = OrderedDict()
        keyword_counts = OrderedDict()
        letter_counts = OrderedDict()

        for row in reader:
            hashvalue:int = int(row[Field.HASH.value], 16)
            address:str   = row[Field.ADDRESS.value]
            retvalue:str  = row[Field.RETURN.value]
            name:str      = row[Field.NAME.value]
            arguments:str = row[Field.ARGUMENTS.value]
            status:Status = Status(row[Field.STATUS.value])
            notes:str     = row[Field.NOTES.value]

            # name corrections:
            if name and name[0] != '$': # syscalls don't include '$' prefix
                name = f'${name}'
            cleanname:str = name.strip('#@%$_')
            fullname = f'{name}@{GROUP_SYSCALL}'
            if retvalue in ('file','page','sprite'): # older sheets before adding '*' for ptr types
                retvalue = f'{retvalue}*'

            # name lookups:
            rettype = TYPEDEF_LOOKUP[retvalue]

            # if status not in (Status.UNHASHED, Status.CONFIRMED):
            if args.write_unknown and status not in (Status.UNHASHED, Status.CONFIRMED, Status.COLLISION):
                unkwriter.write(f'{hashvalue:08x} ')
            if args.write_collisions and status is Status.COLLISION:
                clnwriter.write(f'{hashvalue:08x} ')

            # validation/errors/warnings:
            if name and status in (Status.UNHASHED, Status.COLLISION, Status.LIKELY, Status.CONFIRMED):
                fullhash = hash32(fullname)
                if fullhash != hashvalue:
                    print(f'{S.BRIGHT}{F.RED}ERROR:{S.RESET_ALL} hashvalue mismatch! {hashvalue:08x} vs {fullhash:08x} : {name}')
            if name and (True or status in (Status.UNHASHED, Status.COLLISION, Status.LIKELY, Status.CONFIRMED)):
                postfix = MjoType.frompostfix_name(name, allowunk=True)
                if rettype not in (Ellipsis, MjoType.UNKNOWN) and rettype != postfix:
                    print(f'{S.BRIGHT}{F.RED}ERROR:{S.RESET_ALL} return/postfix mismatch! {hashvalue:08x} : {name}')
            
            # statistics:
            status_counts.setdefault(status, 0)
            status_counts[status] += 1
            return_counts.setdefault(retvalue, 0)
            return_counts[retvalue] += 1
            if status in (Status.UNHASHED, Status.COLLISION, Status.CONFIRMED):
                kwds = [n for n in cleanname.split('_') if n]
                for i,kwd in enumerate(kwds):
                    # [total, prefix, middle, postfix]
                    keyword_counts.setdefault(kwd, [0, 0, 0, 0])
                    keyword_counts[kwd][0] += 1
                    #NOTE: entire words are treated as prefix
                    if i == 0:
                        keyword_counts[kwd][1] += 1
                    elif i+1 < len(kwds):
                        keyword_counts[kwd][2] += 1
                    else:
                        keyword_counts[kwd][3] += 1
                    # letter stats:
                    for j,c in enumerate(kwd):
                        # [total, word prefix, word middle, word postfix]
                        letter_counts.setdefault(c, [0, 0, 0, 0])
                        letter_counts[c][0] += 1
                        if j == 0:
                            letter_counts[c][1] += 1
                        elif j+1 < len(kwd):
                            letter_counts[c][2] += 1
                        else:
                            letter_counts[c][3] += 1
        if args.write_unknown:
            unkwriter.flush()
            unkwriter.close()
            del unkwriter
        if args.write_collisions:
            clnwriter.flush()
            clnwriter.close()
            del clnwriter
        # print statistics:
        max_len = max([len(k.value) for k in status_counts.keys()] + [len(k) for k in return_counts.keys()])

        # print status statistics:
        if show_status:
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
        if show_returns:
            for t,keys in TYPEDEFS.items():
                name = 'OTHER' if t is Ellipsis else t.name
                print(f'{S.BRIGHT}{F.BLUE}RETURNS: [{name}]{S.RESET_ALL}')
                for k in keys:
                    cnt = return_counts.get(k, 0) # '*' now included for pointer int types
                    if cnt == 0: print(f'{S.BRIGHT}{F.BLACK}',end='')
                    print(f' {k.ljust(max_len)} : {cnt:d}{S.RESET_ALL}')
        
        # print keyword statistics
        max_kwd_len = max([len(k) for k in keyword_counts.keys()])
        COLS = (f'{S.BRIGHT}{F.GREEN}', f'{S.BRIGHT}{F.YELLOW}', f'{S.BRIGHT}{F.RED}', f'{S.DIM}{F.BLACK}')
        if keywords_min is not None:
            # kwds_sorted = list(keyword_counts.keys())
            # print(f' {S.BRIGHT}{F.BLUE}{"keyword".ljust(max_kwd_len)}{S.RESET_ALL} : {S.BRIGHT}{F.BLUE}total{S.RESET_ALL} {S.DIM}{F.GREEN}pre {F.YELLOW}mid {F.RED}post{S.RESET_ALL}  {S.BRIGHT}{F.BLUE}i  %  $  #  %#  $#{S.RESET_ALL}')
            # print('{S.BRIGHT}{F.BLUE}',end='')
            # print('')
            # print(f' keyword      : total pre mid post')
            # print(' sprite        : 37    37  37  37')
            # """
            #  keyword       : total pre mid post  i  %  $  #  %#  $#
            # KEYWORDS: [37]
            #  sprite        : 37,  [37, 0,  0  ]  00,
            # KEYWORDS: [28]
            #  set           : 28,  [19, 2,  7  ]  
            # KEYWORDS: [27]
            # """
            keyword_counts_sorted = {}
            for k,cnt in keyword_counts.items():
                keyword_counts_sorted.setdefault(cnt[0], []).append((k, cnt))
            cnts = list(keyword_counts_sorted.keys())
            cnts.sort(reverse=True)
            print()
            print(f' {S.BRIGHT}{F.BLUE}{"keyword".ljust(max_kwd_len)}{S.RESET_ALL} : {S.BRIGHT}{F.BLUE}total{S.RESET_ALL} {S.DIM}{F.GREEN}pre {F.YELLOW}mid {F.RED}post{S.RESET_ALL}')
            for cnt in cnts:
                if cnt <= keywords_min:
                    continue
                print(f'{S.DIM}{F.CYAN}KEYWORDS: [{cnt}]{S.RESET_ALL}')
                kwds = keyword_counts_sorted[cnt]
                # kwds.sort()
                kwds.sort(key=lambda k: k[0])
                for k,cnts in kwds:
                    # print(f' {k.ljust(max_kwd_len)} : {cnt:<3d}{S.RESET_ALL}   ',end='')
                    # {cnts[1:]}
                    cnts_parts = ''#[]
                    # cnts_parts = []
                    for j,cntx in enumerate(cnts[1:]):
                        comma = ',' if j < 2 else ''
                        just = 4 if j < 2 else 3
                        if not cntx:
                            j,cntx = -1,'0'
                            # j,cntx = -1,'-'
                        # cnts_parts.append(f'{COLS[j]}{cntx:<3}{S.RESET_ALL}')
                        # cnt_part = f"{cntx}{comma}".ljust(just)
                        # cnts_parts += f'{COLS[j]}{f"{cntx}{comma}".ljust(just))}'
                        cnts_parts += f'{COLS[j]}{cntx}{S.DIM}{F.BLACK}{comma}{S.RESET_ALL}' + (' ' * (3-len(str(cntx))))
                        # cnts_parts.append(f'{COLS[j]}{cntx:<3}{S.RESET_ALL}')
                        # cnts_parts += (',' if j < 2 else '')
                        # print(f'{COLS[j]}{cntx:<3}{S.RESET_ALL} ', end='')
                        # print(f'{(COLS[j] if cntx else COLS[-1])}{cntx:<3d}{S.RESET_ALL} ', end='')
                    # print(f' {k.ljust(max_kwd_len)} : {f"{cnt},".ljust(4)}{S.RESET_ALL} [{" ".join(cnts_parts)}]')
                    # print(f' {k.ljust(max_kwd_len)} : {f"{cnt},".ljust(4)}{S.RESET_ALL} [{cnts_parts}]')
                    print(f' {k.ljust(max_kwd_len)} : {cnt}{S.DIM}{F.BLACK},{S.RESET_ALL}{"".ljust(3-len(str(cnt)))} [{cnts_parts}]')
                    # print(f' {k.ljust(max_kwd_len)} : {cnt:<3d}{S.RESET_ALL}  [{" ".join(cnts_parts)}]')
                    # print()
            # for cnt,kwds in keyword_counts_sorted.items():
            #     print(f'{S.BRIGHT}{F.BLUE}KEYWORDS: [{cnt}]{S.RESET_ALL}')
            #     kwds.sort()
            #     print(f' {k.ljust(max_kwd_len)} : {cnt:d}{S.RESET_ALL}')

        # letter statistics:
        if letter_sort is not None:
            max_kwd_len = len("letter")
            # print(letter_counts)
            for c in string.ascii_lowercase + string.digits:
                letter_counts.setdefault(c, [0, 0, 0, 0]) # add any letters not appearing in syscalls
            letter_counts_alpha = list(letter_counts.items())
            letter_counts_alpha.sort(key=lambda pair: pair[0])

            #mean, median, mode, stdev, variance
            # def sort_letter(pair:tuple):
            #     l:str = pair[0]
            #     if l in string.ascii_lowercase:
            #         return chr(ord(l) - ord('a'))
            #     if l in string.ascii_lowercase:
            #         return chr(ord(l) - ord('a'))
            # sort to place in order of: lowercase, uppercase, digits
            letter_counts_alpha.sort(key=lambda pair: ('\x80'+pair[0]) if pair[0].isdigit() else pair[0].swapcase())
            letter_counts_ordered = list(letter_counts_alpha)
            letter_counts_ordered.sort(key=lambda pair: pair[1][0], reverse=True)
            letter_counts_nonzero_nums = [cnts[0] for l,cnts in letter_counts_ordered if cnts[0]]
            letter_counts_nonzero = [l for l,cnts in letter_counts_ordered if cnts[0]]
            letter_counts_zero = [l for l,cnts in letter_counts_ordered if not cnts[0]]
            if letter_sort is True:
                letter_counts_alpha = letter_counts_ordered
                # letter_counts_alpha = list(letter_counts_ordered)
            print()
            print(f'{S.DIM}{F.CYAN}LETTERS: [FREQUENCY]{S.RESET_ALL}')
            max_letter_count = max(letter_counts_nonzero_nums)
            print(f' appear: ',end='')#{S.BRIGHT}{F.WHITE}{"".join(letter_counts_nonzero)}{S.RESET_ALL}')#, end='')
            # cnt_mode = -1
            for l in letter_counts_nonzero:
                cnt = letter_counts[l][0]
                # if cnt_mode
                if cnt >= max_letter_count / 3:
                    print(f'{S.BRIGHT}{F.WHITE}',end='')
                elif cnt >= max_letter_count / 6:
                    print(f'{S.NORMAL}{F.WHITE}',end='')
                elif cnt >= max_letter_count / 25:
                    print(f'{S.DIM}{F.WHITE}',end='')
                else:
                    print(f'{S.BRIGHT}{F.BLACK}',end='')
                # if cnt >= max_letter_count / 3:
                #     print(f'{S.BRIGHT}{F.YELLOW}',end='')
                # elif cnt >= max_letter_count / 6:
                #     print(f'{S.DIM}{F.YELLOW}',end='')
                # elif cnt >= max_letter_count / 30:
                #     print(f'{S.DIM}{F.CYAN}',end='')
                # else:
                #     print(f'{S.BRIGHT}{F.BLUE}',end='')
                # if cnt >= max_letter_count / 2:
                #     print(f'{S.BRIGHT}{F.YELLOW}',end='')
                # elif cnt >= max_letter_count / 4:
                #     print(f'{S.BRIGHT}{F.GREEN}',end='')
                # elif cnt >= max_letter_count / 12:
                #     print(f'{S.DIM}{F.GREEN}',end='')
                # elif cnt >= max_letter_count / 30:
                #     print(f'{S.DIM}{F.CYAN}',end='')
                # elif cnt >= 10:
                #     print(f'{S.BRIGHT}{F.BLUE}',end='')
                # else:
                #     print(f'{S.DIM}{F.BLUE}',end='')
                # if cnt >= max_letter_count / 2:
                #     print(f'{S.BRIGHT}{F.RED}',end='')
                # elif cnt >= max_letter_count / 3:
                #     print(f'{S.NORMAL}{F.RED}',end='')
                # elif cnt >= max_letter_count / 5:
                #     print(f'{S.BRIGHT}{F.MAGENTA}',end='')
                # elif cnt >= max_letter_count / 12:
                #     print(f'{S.NORMAL}{F.MAGENTA}',end='')
                # elif cnt >= max_letter_count / 30:
                #     print(f'{S.NORMAL}{F.CYAN}',end='')
                # elif cnt >= 10:
                #     print(f'{S.BRIGHT}{F.BLUE}',end='')
                # else:
                #     print(f'{S.NORMAL}{F.BLUE}',end='')
                print(f'{l}{S.RESET_ALL}',end='')
            print()
            # print(f' appear: {S.BRIGHT}{F.WHITE}{"".join(letter_counts_nonzero)}{S.RESET_ALL}')#, end='')
            # print()
            print(f'  never: {S.BRIGHT}{F.BLACK}{"".join(letter_counts_zero)}{S.RESET_ALL}')#, end='')
            # print()
            print(f'    max: {max(letter_counts_nonzero_nums)}')
            print(f' median: {statistics.median(letter_counts_nonzero_nums)}')
            print(f'    min: {min(letter_counts_nonzero_nums)}')
            print(f'    sum: {sum(letter_counts_nonzero_nums)}')
            print(f'   mean: {statistics.mean(letter_counts_nonzero_nums):g}')
            # print(f'      mode: {repr(Counter(letter_counts_nonzero_nums).most_common(1)[0])[1:-1]}')
            print(f'  stdev: {statistics.stdev(letter_counts_nonzero_nums):g}')
            print()
            # print(f'       max: {max(letter_counts_nonzero_nums)}')
            # print(f'       min: {min(letter_counts_nonzero_nums)}')
            # print(f'       sum: {sum(letter_counts_nonzero_nums)}')
            # print(f'      mean: {statistics.mean(letter_counts_nonzero_nums)}')
            # print(f'    median: {statistics.median(letter_counts_nonzero_nums)}')
            # # print(f'      mode: {repr(Counter(letter_counts_nonzero_nums).most_common(1)[0])[1:-1]}')
            # print(f'     stdev: {statistics.stdev(letter_counts_nonzero_nums)}')
            # # print(f'    pstdev: {statistics.pstdev(letter_counts_nonzero_nums)}')
            # # print(f'  variance: {statistics.variance(letter_counts_nonzero_nums)}')
            # # print(f' pvariance: {statistics.pvariance(letter_counts_nonzero_nums)}')
            for l,cnts in letter_counts_ordered:
                cnt = cnts[0]

            print(f' {S.BRIGHT}{F.BLUE}{"letter".ljust(max_kwd_len)}{S.RESET_ALL} : {S.BRIGHT}{F.BLUE}total{S.RESET_ALL}  {S.DIM}{F.GREEN}pre  {F.YELLOW}mid  {F.RED}post{S.RESET_ALL}')
            print(f'{S.DIM}{F.CYAN}LETTERS: [COUNTS]{S.RESET_ALL}')
            for k,cnts in letter_counts_alpha: #string.ascii_lowercase:
                # cnts = letter_counts.get(k, (0, 0, 0, 0))
                cnt = cnts[0]
                cnts_parts = ''#[]
                # cnts_parts = []
                color = f'' if cnt else f'{S.BRIGHT}{F.BLACK}'
                for j,cntx in enumerate(cnts[1:]):
                    comma = ',' if j < 2 else ''
                    just = 5 if j < 2 else 4
                    if not cntx:
                        j,cntx = -1,'0'
                        # j,cntx = -1,'-'
                    # cnts_parts.append(f'{COLS[j]}{cntx:<3}{S.RESET_ALL}')
                    # cnt_part = f"{cntx}{comma}".ljust(just)
                    # cnts_parts += f'{COLS[j]}{f"{cntx}{comma}".ljust(just))}'
                    cnts_parts += f'{COLS[j]}{cntx}{S.DIM}{F.BLACK}{comma}{S.RESET_ALL}' + (' ' * (4-len(str(cntx))))
                    # cnts_parts.append(f'{COLS[j]}{cntx:<3}{S.RESET_ALL}')
                    # cnts_parts += (',' if j < 2 else '')
                    # print(f'{COLS[j]}{cntx:<3}{S.RESET_ALL} ', end='')
                    # print(f'{(COLS[j] if cntx else COLS[-1])}{cntx:<3d}{S.RESET_ALL} ', end='')
                # print(f' {k.ljust(max_kwd_len)} : {f"{cnt},".ljust(4)}{S.RESET_ALL} [{" ".join(cnts_parts)}]')
                # print(f' {k.ljust(max_kwd_len)} : {f"{cnt},".ljust(4)}{S.RESET_ALL} [{cnts_parts}]')
                print(f' {color}{k.ljust(max_kwd_len)} : {cnt}{S.DIM}{F.BLACK},{S.RESET_ALL}{"".ljust(4-len(str(cnt)))} {color}[{S.RESET_ALL}{cnts_parts}{color}]{S.RESET_ALL}')


        

        
        #kwds_sorted.sort()



    # read from all inputs: (which includes Google Sheets for the -G option)
    for i,infile in enumerate(inputs):
        # special handling for Google Sheet input files:
        if isinstance(infile, GoogleSheet):
            outfile:str = args.sheet_output
            print(f'{S.BRIGHT}{F.YELLOW}Downloading:{S.RESET_ALL} {S.DIM}{F.GREEN}{infile!r}{S.RESET_ALL}')
            sheet = infile.download(format=gformat)
            if cache is not None:
                print(f'{S.BRIGHT}{F.MAGENTA}Caching:{S.RESET_ALL} {S.DIM}{F.CYAN}{cache!r}{S.RESET_ALL}')
                with open(cachepath, 'wt+', encoding='utf-8') as swriter:
                    swriter.write(sheet)
                    swriter.flush()
            if outfile is not None:
                print(f'{S.BRIGHT}{F.MAGENTA}Saving:{S.RESET_ALL} {S.DIM}{F.CYAN}{outfile!r}{S.RESET_ALL}')
                with open(outfile, 'wt+', encoding='utf-8') as swriter:
                    swriter.write(sheet)
                    swriter.flush()
            f = io.StringIO(sheet)
        else:
            if infile is cachepath:
                inname = cache.replace("\\","/")
                print(f'{S.BRIGHT}{F.CYAN}Cached:{S.RESET_ALL} {S.DIM}{F.CYAN}{inname!r}{S.RESET_ALL}')
            else:
                inname = infile.replace("\\","/")
                print(f'{S.BRIGHT}{F.CYAN}Reading:{S.RESET_ALL} {S.DIM}{F.CYAN}{inname!r}{S.RESET_ALL}')
            f = open(infile, 'rt', encoding='utf-8')
        with f:
            read_file(csv.DictReader(f, delimiter=delimiter))
        if i+1 < len(inputs):
            print()

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())
