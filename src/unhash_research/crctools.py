#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Examples and tools showing the process of reversing (backing out) data from a CRC-32
result, and the limitations involved.

Requires: Python 3.6+

examples:
>>> backout_indices(crc32(b'$rgb'), 4)
>>> backout_data(crc32(b'$rgb'), crc32(b'$'), 3)
>>> inverse_crc32(crc32(b'$rgb@'), b'$rgb@')
>>> backout_ascii_explanation(crc32(b'$rgb'), 4, b'rgb', mode='both', legend=True)
"""

__version__ = '1.0.0'
__date__    = '2021-04-21'
__author__  = 'Robert Jordan'

__all__ = ['crc32', 'inverse_crc32', 'backout_indices', 'backout_data', 'backout_ascii_explanation']

#######################################################################################

#from zlib import crc32 as z_crc32


#region ## COLOR SETUP ##
# dummy color namespaces for disabled color
from types import SimpleNamespace
Fore2 = SimpleNamespace(RESET='', BLACK='', BLUE='', CYAN='', GREEN='', MAGENTA='', RED='', WHITE='', YELLOW='', LIGHTBLACK_EX='', LIGHTBLUE_EX='', LIGHTCYAN_EX='', LIGHTGREEN_EX='', LIGHTMAGENTA_EX='', LIGHTRED_EX='', LIGHTWHITE_EX='', LIGHTYELLOW_EX='')
Style2 = SimpleNamespace(RESET_ALL='', BRIGHT='', DIM='', NORMAL='') #, BOLD='', ITALIC='', UNDERLINE='', BLINKING='', INVERSE='', INVISIBLE='', STRIKETHROUGH='')

_Color_SHORTHANDS = dict(
    RESET  ='R',
    #
    BLACK  ='DBLK',
    BLUE   ='DBLU',
    GREEN  ='DGRN',
    CYAN   ='DCYN', # or 'CYA'?
    RED    ='DRED',  # not a very difficicult choice
    MAGENTA='DMAG', # or 'MGN'/'MGT'/'PUR'/'PRP'?
    YELLOW ='DYLW',
    WHITE  ='GRY',
    #
    LIGHTBLACK_EX  ='DGRY',
    LIGHTBLUE_EX   ='BLU',
    LIGHTGREEN_EX  ='GRN',
    LIGHTCYAN_EX   ='CYN',
    LIGHTRED_EX    ='RED',
    LIGHTMAGENTA_EX='MAG',
    LIGHTYELLOW_EX ='YLW',
    LIGHTWHITE_EX  ='WHT',
)

_Style_SHORTHANDS = dict(
    RESET_ALL='R',
    BRIGHT   ='L', # (light) or 'B'?
    DIM      ='D',
    NORMAL   ='N',
    BOLD     ='BD', # renders as BRIGHT in WinTerm :(
    ITALIC   ='IT',
    UNDERLINE='UL',
    BLINKING ='BLI',
    INVERSE  ='INVR',
    INVISIBLE='INVS',
    STRIKETHROUGH='ST',
)

Fore = SimpleNamespace(RESET='\x1b[39m', BLACK='\x1b[30m', BLUE='\x1b[34m', CYAN='\x1b[36m', GREEN='\x1b[32m', MAGENTA='\x1b[35m', RED='\x1b[31m', WHITE='\x1b[37m', YELLOW='\x1b[33m', LIGHTBLACK_EX='\x1b[90m', LIGHTBLUE_EX='\x1b[94m', LIGHTCYAN_EX='\x1b[96m', LIGHTGREEN_EX='\x1b[92m', LIGHTMAGENTA_EX='\x1b[95m', LIGHTRED_EX='\x1b[91m', LIGHTWHITE_EX='\x1b[97m', LIGHTYELLOW_EX='\x1b[93m')
Back = SimpleNamespace(RESET='\x1b[49m', BLACK='\x1b[40m', BLUE='\x1b[44m', CYAN='\x1b[46m', GREEN='\x1b[42m', MAGENTA='\x1b[45m', RED='\x1b[41m', WHITE='\x1b[47m', YELLOW='\x1b[43m', LIGHTBLACK_EX='\x1b[100m', LIGHTBLUE_EX='\x1b[104m', LIGHTCYAN_EX='\x1b[106m', LIGHTGREEN_EX='\x1b[102m', LIGHTMAGENTA_EX='\x1b[105m', LIGHTRED_EX='\x1b[101m', LIGHTWHITE_EX='\x1b[107m', LIGHTYELLOW_EX='\x1b[103m')
# extended styles not part of colorama
Style = SimpleNamespace(RESET_ALL='\x1b[0m', BRIGHT='\x1b[1m', DIM='\x1b[2m', NORMAL='\x1b[22m', BOLD='\x1b[1m', ITALIC='\x1b[3m', UNDERLINE='\x1b[4m', BLINKING='\x1b[5m', INVERSE='\x1b[7m', INVISIBLE='\x1b[8m', STRIKETHROUGH='\x1b[9m')

F = SimpleNamespace(**dict((_Color_SHORTHANDS[k],v) for k,v in Fore.__dict__.items()))#, **dict((k,v) for k,v in Fore.__dict__.items() if k not in _Color_SHORTHANDS.values()))
B = SimpleNamespace(**dict((_Color_SHORTHANDS[k],v) for k,v in Back.__dict__.items()))#, **dict((k,v) for k,v in Back.__dict__.items() if k not in _Color_SHORTHANDS.values()))
S = SimpleNamespace(**dict((_Style_SHORTHANDS[k],v) for k,v in Style.__dict__.items()), **dict((k,v) for k,v in Style.__dict__.items() if k not in _Style_SHORTHANDS.values()))

try:
    import colorama
    colorama.init()
except:
    pass  # hope you have a terminal that supports ANSI color codes~
#endregion

#region ## CRC-32 INITIALIZATION ##

## standard CRC-32 (used by zlib) table calculation
def _calc_crc32(num:int) -> int:
    """_calc_crc32(num) -> CRC_TABLE[num]
    calculate the value of an entry in the CRC_TABLE, at CRC_TABLE[num]
    """
    POLY = 0xEDB88320  # reversed polynomial
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ POLY
        else:         num >>= 1
    return num

def _find_crc32(num:int) -> int:
    """_find_crc32(_calc_crc32(0xd7)) -> 0xd7
    finds the index of the most significant byte in the CRC_TABLE
    """
    for x in range(256):
        y = _calc_crc32(x)
        if (y >> 24) == num:
            return x
    raise Exception('not found')

# CRC-32 TABLES for forward and inverse lookup
CRC_TABLE:list   = tuple(_calc_crc32(n) for n in range(256))
CRC_INDICES:list = tuple(_find_crc32(n) for n in range(256))  # indices for most-significant bytes in CRC_TABLE

#endregion

#region ## CRC-32 FUNCTIONS ##

def crc32(data:bytes, init:int=0) -> int:
    if isinstance(data, str): data = data.encode('cp932')
    #include if: from zlib import crc32 as z_crc32 is uncommented
    #return z_crc32(data, init)
    crc = init ^ 0xffffffff  # init
    for o in data:
        crc = (crc >> 8) ^ CRC_TABLE[(crc ^ o) & 0xff]
    return crc ^ 0xffffffff  # xorout

#include if: from zlib import crc32 as z_crc32 is uncommented
#assert(crc32(b'123456789') == z_crc32(b'123456789'))

def inverse_crc32(accum:int, data:bytes=b'') -> int:
    """inverse_crc32(crc32(b'$rgb@HELLO'), b'@HELLO') -> crc32(b'$rgb')
    inverse crc32 operation, this can be used to find an original accumulator at (end-N) if N postfix bytes are known
    
    another way to look at this function is naming it `backout_accum()`
    """
    if isinstance(data, str): data = data.encode('cp932')
    crc = accum ^ 0xffffffff  # xorout
    for o in reversed(data):
        x = CRC_INDICES[crc >> 24]
        y = CRC_TABLE[x]
        crc = (((crc ^ y) << 8) & 0xffffffff) | (o ^ x)
    return crc ^ 0xffffffff  # xorout or init??

def backout_indices(accum:int, count:int) -> list:
    """backout_indices(crc32(b'$rgb'), 3) -> [0xd1, 0xd1, 0x3c]
    the returned indices are equal to (least-significant accumulator byte XOR the input byte) each iteration
    this accumulator is not equal to the one input in the arguments, but the one present at that iteration in the operation.
    """
    if not (1 <= count <= 4):
        raise Exception(f'argument count must be between 1 and 4, not {count}')
    # back out up to 4 indices:
    crc  = accum ^ 0xffffffff  # xorout
    indices = []
    for _ in range(count):
        x = CRC_INDICES[crc >> 24]
        y = CRC_TABLE[x]
        # every iteration we lose another least-significant byte of known data:
        #NOTE: (crc ^ y) WILL ALWAYS result in 00XXXXXX
        #  (this is a property of the CRC_INDICES lookup table)
        crc = ((crc ^ y) << 8) | x  # (((crc ^ y) << 8) & 0xffffffff) | x
        indices.insert(0, x)
    
    return indices

def backout_data(accum:int, orig_accum:int, count:int) -> bytes:
    """backout_data(crc32(b'$rgb'), crc32(b'$'), 3) -> b'rgb'
    back out `count` (up to 4) known bytes from the result of a crc32 operation
    """
    if not (1 <= count <= 4):
        raise Exception(f'argument count must be between 1 and 4, not {count}')
    # back out up to 4 indices:
    crc = accum ^ 0xffffffff  # xorout
    indices = []
    for _ in range(count):
        x = CRC_INDICES[crc >> 24]
        y = CRC_TABLE[x]
        # every iteration we lose another least-significant byte of known data:
        #NOTE: (crc ^ y) WILL ALWAYS result in 00XXXXXX
        #  (this is a property of the CRC_INDICES lookup table)
        crc = ((crc ^ y) << 8) | x  # (((crc ^ y) << 8) & 0xffffffff) | x
        indices.insert(0, x)
    
    # forward crc for accum to get data from indices:
    crc = orig_accum ^ 0xffffffff  # xorout
    data = bytearray()
    for x in indices:
        data.append((crc ^ x) & 0xff)    # o == (crc ^ x) & 0xff
        crc = (crc >> 8) ^ CRC_TABLE[x]  # x == (crc ^ o) & 0xff
    
    #assert((crc ^ 0xffffffff) == accum)  # xorout or init??
    crc ^= 0xffffffff  # xorout or init??
    if crc != accum:
        #NOTE: if count==4, then it's impossible for this Exception to raise, as there
        #       is ALWAYS a combination to turn one accum into another with 4 bytes,
        #       however with 3 or less bytes, it's impossible(?) to find a second collision(?) [TODO: confirm]
        raise ValueError(f'final accumulator 0x{accum:08x} does not match expected output accumulator 0x{crc:08x}')
    
    return bytes(data)

#endregion

#region ## CRC-32 EXPLANATIONS/WALKTHROUGHS ##

def backout_ascii_explanation(data:bytes, count:int=4, init:int=None, *, mode:str=None, legend:bool=False):
    """Preview with color showing the process of backing out data from CRC-32,
    when the initial accumulator and data are unknown, but the data operated on is ASCII.
    
    positional arguments:
    - data : bytes|str - input data to calculate resulting accumulator of crc32 operation (uses argument init)
           : int       - resulting accumulator of crc32 operation (argument mode must be 'hide')
    - count : int      - number of bytes to back out of CRC-32 result (between 1 and 4)
    - init : int       - init value when data is bytes|str [default=0]
           : bytes|str - (optional) trailing data when data is int (accumulator) [default=None]
    keyword arguments:
    - mode : str
        'hide' - show unknown values with known MSBs
        'show' - show known values (data must be bytes|str, or init must not be None)
        'both' - show both known and unknown values side-by-side (data must be bytes|str, or init must not be None)
        None   - (default behavior) show known values if data is bytes|str, else hide known values (if data is int)
    - legend : bool    - show legend explaining use of color and characters [default=False]
    
    examples:
    >>> backout_ascii_explanation(b'$rgb', 4, show='both', legend=True)
    >>> backout_ascii_explanation(b'rgb', 3, 0xee010b5c)
    >>> backout_ascii_explanation(0xd061a65f, 3, b'rgb')
    >>> backout_ascii_explanation(0xd061a65f, 4)
    """
    if not (1 <= count <= 4):
        raise ValueError(f'argument count must be between 1 and 4, not {count}')
    if isinstance(data, int):  # data=accum, init=[data]
        accum, data = data, (init if init is not None else b'')
        if isinstance(data, str): data = init.encode('cp932')
        if mode is None: mode = 'hide' if init is None else 'both'
        elif init is None and mode in ('show','both'):
            raise ValueError(f'argument mode must be value \'hide\' when data is int')
    elif isinstance(data, (bytes,str)):  # data=data, init=[init]
        if isinstance(data, str): data = data.encode('cp932')
        accum = crc32(data, init if init is not None else 0)
        if mode is None: mode = 'show'
    else:
        raise TypeError(f'argument data must be int, bytes or str, not {data.__class__.__name__}')
    if mode not in ('hide','show','both'):
        raise ValueError(f'argument mode must be value \'show\', \'hide\' or \'both\', not {mode!r}')
    # helper function:
    def msb_preview(msb:bool) -> str:
        return 'M?' if msb else 'm?' #'X?' if msb else 'x?'
    
    if legend:
        ## ## LEGEND #################################################
        ## # green  : known | red  : unknown | M?/m? : MSB set/unset
        ## # d.cyan : const | yellow : shown | cyan  : CRC_TABLE[]
        print(f' {F.DGRY}## LEGEND #################################################{S.R}')
        print(f' {F.DGRY}# {F.GRN}green{F.DGRY}  : {S.R}known{F.DGRY} | {F.RED}red{F.DGRY}  : {S.R}unknown{F.DGRY} | {F.RED}{msb_preview(1)}{F.DGRY}/{F.RED}{msb_preview(0)}{F.DGRY} : {S.R}MSB set{F.DGRY}/{S.R}unset')
        print(f' {F.DGRY}# {F.DCYN}d.cyan{F.DGRY} : {S.R}const{F.DGRY} | {F.YLW}yellow{F.DGRY} : {S.R}shown{F.DGRY} | {F.CYN}cyan{F.DGRY}  : {S.R}CRC_TABLE[]')
        print(f' {F.DGRY}#{S.R}')
    
    crc = accum ^ 0xffffffff  # xorout
    msbs = []  # known most-significant bits of unknown bytes
    
    ## # revert xorout on final accumulator
    ## aaaaaaaa = AAAAAAAA ^ ffffffff
    print(f' {F.DGRY}# revert {F.DCYN}xorout{F.DGRY} on final {F.MAG}accumulator{S.R}')
    print(f' {F.MAG}{accum:08x}{S.R} = {F.GRN}{crc:08x}{S.R} ^ {F.DCYN}ffffffff{S.R}  {F.DGRY}# xorout{S.R}')
    
    for n in range(count + 1):  # count + 1: final cycle shows only final values
        x = CRC_INDICES[crc >> 24]
        y = CRC_TABLE[x]
        o = data[-n-1] if (n < len(data)) else 0x00  # only if we're in range of known input data
        msb = x & 0x80

        ## FORMATTING PREPERATION ##
        # msb from finding x: not used in msbs list until next iteration
        msb_unkown = msb_preview(msb)
        # format known and unknown, current and previous accumulator values:
        out_known,    in_known   = f'{crc:08x}'[:8-n*2], f'{(crc ^ y):08x}'[2:8-n*2]
        out_show,     in_show    = f'{crc:08x}'[8-n*2:], f'{(crc ^ y):08x}'[8-n*2:]  # accurate if we know `o`
        out_unknown = in_unknown = ''
        out_show2   = in_show2   = '' # unknowns for show (trimmed out_unknown, in_unknown)
        # calc MSBs for unknown values: based on fact that ASCII input never has MSB set
        for j in range(1, n+1):
            # previous MSBs from last XOR value
            out_unknown  = msb_preview(msbs[-j]) + out_unknown
            # update MSB to match XOR with current CRC_TABLE[x]
            msbs[-j] = ((y >> (j*8-8)) ^ msbs[-j]) & 0x80
            in_unknown = msb_preview(msbs[-j]) + in_unknown
        # handle going past amount of trailing data supplied with accumulator: e.g. kkssssss -> kkssssm?
        if n > len(data) or (n != count and n == len(data)):
            out_show  = out_show[:len(data)*2]  # shown (yellow)
            in_show   =  in_show[:len(data)*2]
            out_show2 = out_unknown[len(data)*2:]  # unknown (red)
            in_show2  =  in_unknown[len(data)*2:]
        
        ## DISPAY ITERATION ##
        # end of loop display:
        if n == count:
            ## # final values
            ## kkkkm?m?
            print(f' {F.DGRY}# final values{S.R}')
            if mode!='show':
                print(f' {F.GRN}{out_known}{F.RED}{out_unknown}{S.R}')
            if mode!='hide' and data:
                print(f' {F.GRN}{out_known}{F.YLW}{out_show}{F.RED}{out_show2}{S.R}')
            break
        
        ## # find x where CRC_TABLE[x] == yyXXXXXX
        ## kkkkm?m? = 00KKM?M? ^ yyyyyyyy
        ## xx = M? ^ m? '?'  # x
        print(f' {F.DGRY}# find {F.DGRN}x{F.DGRY} where{S.R} CRC_TABLE[{F.DGRN}x{S.R}]{S.R} == {F.CYN}{(crc>>24):02x}{F.DGRY}XXXXXX{S.R}')
        # explain: arriving at current accumulator
        if mode!='show':
            print(f' {F.GRN}{out_known}{F.RED}{out_unknown}{S.R} = {F.DCYN}00{F.GRN}{in_known}{F.RED}{in_unknown}{S.R} ^ {F.CYN}{y:08x}{S.R}')
        if mode!='hide' and data:
            print(f' {F.GRN}{out_known}{F.YLW}{out_show}{F.RED}{out_show2}{S.R} = {F.DCYN}00{F.GRN}{in_known}{F.YLW}{in_show}{F.RED}{in_show2}{S.R} ^ {F.CYN}{y:08x}{S.R}')
        
        # explain: x and relation to input char (o) and unknown previous accumulator least-significant byte
        if mode!='show':
            print(f' {F.DGRN}{x:02x}{S.R} = {F.DRED}{msb_unkown}{S.R} ^ {F.RED}{msb_preview(0)} {"?"!r}{S.R}  {F.DGRY}# x{S.R}')
        if mode!='hide' and n < len(data):
            print(f' {F.DGRN}{x:02x}{S.R} = {F.DYLW}{(o^x):02x}{S.R} ^ {F.YLW}{o:02x} {chr(o)!r}{S.R}  {F.DGRY}# x{S.R}')
        
        crc = ((crc ^ y) << 8) | (o ^ x)  # if current data is known, o = data[-n-1], else o = 0 (garbage)
        msbs.append(msb)

#endregion

#######################################################################################

## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    # ## PARSER SETUP ##
    # import argparse
    # parser = argparse.ArgumentParser(
    #     add_help=True)

    # # add_argument calls here
    # # ...
    # # ...

    # args = parser.parse_args(argv)

    # print(args)
    
    print(f"Example backing up 4 bytes from crc32(b'$rgb'), with only trailing bytes b'rgb' being known values")
    backout_ascii_explanation(crc32(b'$rgb'), 4, b'rgb', mode='both', legend=True)

    return 0

## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

