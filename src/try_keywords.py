#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Keyword smasher CRC-32 unhasher
"""

__version__ = '0.1.0'
__date__    = '2021-04-30'
__author__  = 'Robert Jordan'

__all__ = []

#######################################################################################

from collections import OrderedDict
from itertools import chain #, product
# from zlib import crc32

from mjotool.crypt import invhash32

#"%Op_internalCase~@MAJIRO_INTER"
#"%__SYS__Beanu3vParam@MAJIRO_INTER"

TARGET:int      = 0x11f91fd3
MINLEN:int      = 0
MAXLEN:int      = 12
CAPITALIZE:bool = False
UPPER:bool      = False
LOWER:bool      = True
UNDERSCORE:bool = True

PREFIXES = ['', '%', '_', '%%']
# all keywords will attempt joining with and without '_' char
WORDS = ['__SYS_','_SYS_','SYS_','SYS',
    'Switch','S', 'Branch', 'Case','C', 'Jump','Jmp', 'Statement','State', 'Mode',
    'Params','Param', 'Value','Val', 'Operand','Op', 'Temp','Tmp', 'Variable','Var','Va','V', 'Arg',
    'Store', 'Sel', 'Reg','R', 'Access', 'Local','Loc', 'Thread',
    'Input','In', 'Quick',
    'Pointer','Ptr','Pt',
    'Mode',
    'System','Internal','Inter',
    'Number','Num',
]
POSTFIXES = ['', '%', '$', '#', '%#', '$#', '?', '*', '&', '!', '~', '^']
#None == no '@'
GROUPS = [None, '', '-', '@', 'MAJIRO_INTER', 'INTER', 'MAJIRO', 'GLOBAL', 'VM_INTER', 'VM', 'GLOBAL_INTER', 'SYSTEM']


# prep variations:
def ordered_unique(items:list) -> tuple:
    # from collections import OrderedDict
    d = OrderedDict()
    for item in items:
        d.setdefault(item, None)
    return tuple(d.keys())

def iter_to_bytes(items:list) -> list:
    return [s.encode('cp932') for s in items]

def iter_to_str(items:list) -> list:
    return [s.decode('cp932') for s in items]

# def has_alpha(s:str) -> bool: return any(c.isalpha() for c in s)
# def has_alnum(s:str) -> bool: return any(c.isalnum() for c in s)
# def has_digit(s:str) -> bool: return any(c.isdigit() for c in s)
# def has_lower(s:str) -> bool: return any(c.islower() for c in s)
# def has_upper(s:str) -> bool: return any(c.isupper() for c in s)
# def append_diff(items:list, orig:str, word:str):
#     if orig != word:
#         items.append(word)

class Config:
    __slots__ = ('capitalize', 'upper', 'lower', 'underscore', 'minlen', 'maxlen', 'groups', 'words', 'prefixes', 'postfixes', 'targets')
    def __init__(self, capitalize:bool=CAPITALIZE, upper:bool=UPPER, lower:bool=LOWER, underscore:bool=UNDERSCORE, minlen:int=MINLEN, maxlen:int=MAXLEN, groups:list=GROUPS, words:list=WORDS, prefixes:list=PREFIXES, postfixes:list=POSTFIXES, targets:list=(TARGET,)):
        self.capitalize:bool = capitalize
        self.upper:bool = upper
        self.lower:bool = lower
        self.underscore:bool = underscore
        self.minlen:int = minlen
        self.maxlen:int = maxlen
        self.groups:list = groups
        self.words:list = words
        self.prefixes:list = prefixes
        self.postfixes:list = postfixes
        self.targets:list = targets


def prep_group(group:str, config:Config) -> list:
    return ['' if group is None else f'@{group}']

def prep_word(word:str, config:Config) -> list:
    words = [word]
    if config.capitalize: words.append(word.capitalize())
    if config.upper:      words.append(word.upper())
    if config.lower:      words.append(word.lower())
    if config.underscore: words.extend([w+'_' for w in words])
    return words

def prep(config:Config):
    from itertools import product
    groups:tuple    = ordered_unique(iter_to_bytes(chain(*[prep_group(g, config) for g in config.groups])))
    words:tuple     = ordered_unique(iter_to_bytes(chain(*[prep_word(w, config)  for w in config.words])))
    prefixes:tuple  = ordered_unique(iter_to_bytes(config.prefixes))
    postfixes:tuple = ordered_unique(iter_to_bytes(config.postfixes))
    targets:dict    = dict((invhash32(g, t), g) for t,g in product(config.targets, groups))
    # targets:dict    = dict((invhash32(g, config.target), g) for g in groups)
    return groups, words, prefixes, postfixes, targets

is_colorama_init = False

def do_printresult(B:tuple, T:dict):
    global is_colorama_init
    from zlib import crc32
    init = crc32(b''.join(B))
    group = T[init]
    result = crc32(group, init)
    from colorama import Fore as F, Style as S
    if not is_colorama_init:
        import colorama
        colorama.init()
        is_colorama_init = True

    parts = iter_to_str([*B] + [group])
    prefix  = f'{S.BRIGHT}{F.CYAN}{parts[0]}{S.RESET_ALL}'
    words   = f'{S.BRIGHT}{F.BLUE}{"".join(parts[1:-2])}{S.RESET_ALL}'
    # words   = f'{S.BRIGHT}{F.YELLOW}{"".join(parts[1:-2])}{S.RESET_ALL}'
    postfix = f'{S.DIM}{F.CYAN}{parts[-2]}{S.RESET_ALL}'
    group   = f'{S.DIM}{F.GREEN}{parts[-1]}{S.RESET_ALL}'
    hashval = f'{S.BRIGHT}{F.RED}{result:08x}{S.RESET_ALL}'
    # group = group.decode('cp932')
    # prefix = B[0].decode

    print(f"{hashval}\t{prefix}{words}{postfix}{group}{S.RESET_ALL}")
    # print(f"{S.BRIGHT}{F.RED}{result:08x}{S.RESET_ALL}\t{S.BRIGHT}{F.BLUE}{b''.join(B).decode('cp932')}{S.DIM}{F.CYAN}{group.decode('cp932')}{S.RESET_ALL}")

def do_wordmash(n:int, W:tuple, PR:tuple, PO:tuple, T:dict):
    from itertools import product
    # K:tuple = tuple([PR] + ([W]*n) + [PO])
    # N:int = n+2
    # L:list = [0]*(n+2) # +2 for prefix/postfix
    # B:list = [K[i][0] for i in range(n+2)]

    P = product(PR, *([W]*n), PO)
    # printres = do_printresult
    del n, product, W, PR, PO  # no longer used

    from zlib import crc32
    # for B in (b for b in P if crc32(b''.join(b)) in T):
    #     # print(f"{crc32(b''.join(B)):08x}\t{b''.join(B).decode('cp932')}{T[crc32(b''.join(B))].decode('cp932')}")
    #     do_printresult(B, T)
    #     # if crc32(b''.join(B)) in T:
    #     #     print(f"{crc32(b''.join(B)):08x}\t{b''.join(B).decode('cp932')}{T[crc32(b''.join(B))].decode('cp932')}")
    for B in P:
        if crc32(b''.join(B)) in T:
            do_printresult(B, T)
            # print(f"{crc32(b''.join(B)):08x}\t{b''.join(B).decode('cp932')}{T[crc32(b''.join(B))].decode('cp932')}")

#######################################################################################         

## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    global is_colorama_init

    import argparse
    parser = argparse.ArgumentParser(
        add_help=True)

    
    
    parser.add_argument('-u', '--upper',     dest='upper',     default=UPPER, action='store_true', required=False)
    parser.add_argument('-U', '--no-upper',  dest='upper',     action='store_false', required=False)
    parser.add_argument('-l', '--lower',     dest='lower',     default=LOWER, action='store_true', required=False)
    parser.add_argument('-L', '--no-lower',  dest='lower',     action='store_false', required=False)
    parser.add_argument('-c', '--capital',   dest='capitalize',default=CAPITALIZE, action='store_true', required=False)
    parser.add_argument('-C', '--no-capital',dest='capitalize',action='store_false', required=False)
    parser.add_argument('-s', '--underscore',   dest='underscore',default=UNDERSCORE, action='store_true', required=False)
    parser.add_argument('-S', '--no-underscore',dest='underscore',action='store_false', required=False)
    parser.add_argument('-m', '--min',       dest='minlen',    default=MINLEN, type=int, required=False)
    parser.add_argument('-M', '--max',       dest='maxlen',    default=MAXLEN, type=int, required=False)
    parser.add_argument('-g', '--group',     dest='groups',    default=GROUPS,    nargs='+', required=False)
    parser.add_argument('-w', '--words',     dest='words',     default=WORDS,     nargs='+', required=False)
    parser.add_argument('-p', '--prefixes',  dest='prefixes',  default=PREFIXES,  nargs='+', required=False)
    parser.add_argument('-P', '--postfixes', dest='postfixes', default=POSTFIXES, nargs='+', required=False)
    parser.add_argument('-t', '--target',    dest='targets',   default=[TARGET], nargs='+', type=lambda v: int(v, 16), required=False)
    parser.add_argument('--preview', default=False, action='store_true', required=False)

    args = parser.parse_args(argv)

    # print(args)
    # return 0

    config = Config() #**args.__dict__)
    for k,v in args.__dict__.items():
        if hasattr(config, k):
            setattr(config, k, v)

    ###########################################################################

    G, W, PR, PO, T = prep(config)
    if args.preview:
        from colorama import Style as S, Fore as F
        if not is_colorama_init:
            import colorama
            colorama.init()
            is_colorama_init = True
        print(  ' PREFIXES:', ', '.join(f'{S.BRIGHT}{F.CYAN}{s!s}{S.RESET_ALL}' for s in iter_to_str(PR)))
        print('\nPOSTFIXES:', ', '.join(f'{S.DIM}{F.CYAN}{s!s}{S.RESET_ALL}' for s in iter_to_str(PO)))
        print('\n   GROUPS:', ', '.join(f'{S.DIM}{F.GREEN}{s!s}{S.RESET_ALL}' for s in iter_to_str(G)))
        print('\n    WORDS:', ', '.join(f'{S.BRIGHT}{F.YELLOW}{s!s}{S.RESET_ALL}' for s in iter_to_str(W)))
    for n in range(config.minlen, config.maxlen+1):
        print(f'Word Depth: {n:d}')
        do_wordmash(n, W, PR, PO, T)

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

