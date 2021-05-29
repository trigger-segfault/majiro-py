#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Brute-force hashes lookup generation
"""

__version__ = '0.1.0'
__date__    = '2021-05-28'
__author__  = 'Robert Jordan'

__all__ = ['find_local_brute', 'load_locals_brute', 'unload_locals_brute', 'brute_force_patterns', 'brute_force_pattern']

#######################################################################################

from string import digits, ascii_lowercase, ascii_uppercase
from typing import Dict, List, Tuple, Union
from ...util.typecast import to_str, to_bytes

from ...crypt import hash32, invhash32 #, check_hashbegin, check_hashmid, check_hashend, check_hashdiffs, backout_data, backout_indices

# class hexint(int):
#     def __repr__(self): return f'0x{self:08x}'
#     __str__ = __repr__

def brute_force_pattern(I:int, O:bytes, P:List[str]) -> List[Tuple[int,bytes]]:
    from zlib import crc32 as c
    from itertools import product
    P = product(*P)
    del product
    # H = hexint
    if O:
        # print(next(P))
        return [(c(O,c(b,I)),b) for b in (bytes(B) for B in P)]
        # return [(H(c(O,c(b,I))),b) for b in (bytes(B) for B in P)]
    else:
        del O
        return [(c(b,I),b) for b in (bytes(B) for B in P)]
        # return [(H(c(b,I)),b) for b in (bytes(B) for B in P)]

# TRIED_PATTERNS = set()

def brute_force_patterns(dic:Dict[int,bytes], prefix:str, postfix:str, *args:Union[str, Tuple[int,str], Tuple[Tuple[int,int],str]]):
    if not args: raise Exception('no arguments')
    
    from zlib import crc32
    from itertools import chain, product

    # expand all arguments
    pattern_parts = []
    for i,arg in enumerate(args):
        if not isinstance(arg, tuple):
            arg = ((1, 1), to_bytes(arg))
        elif not isinstance(arg[0], tuple):
            arg = ((arg[0], arg[0]), to_bytes(arg[1]))
        else:
            arg = (arg[0], to_bytes(arg[1]))
        (minnum,maxnum),partstr = arg
        partstr = partstr.replace(b'a-z', to_bytes(ascii_lowercase))
        partstr = partstr.replace(b'A-Z', to_bytes(ascii_uppercase))
        partstr = partstr.replace(b'0-9', to_bytes(digits))
        # idx = partstr.find(b'-')
        # while idx != -1:
        #     if idx and partstr[idx-1:idx] != b'\\':

        #         for c in range(ord(partstr[idx]))
        partstr = partstr.replace(b'\\-', b'-')
        pattern_parts.append([[partstr]*r for r in range(minnum, maxnum+1)])

    init, post = crc32(to_bytes(prefix)), to_bytes(postfix)
    for i,pattern in enumerate(product(*pattern_parts)):
        pattern = tuple(chain(*pattern))
        # if pattern in TRIED_PATTERNS: print('ALREADY FOUND, SKIPPING')
        # else:                         TRIED_PATTERNS.add(pattern)
        def shorthand(item:bytes):
            item = item.replace(b'-', b'\\-')
            item = item.replace(to_bytes(ascii_lowercase), b'\x00a-z\x00')
            item = item.replace(to_bytes(ascii_uppercase), b'\x00A-Z\x00')
            item = item.replace(to_bytes(digits), b'\x000-9\x00')
            return to_str(item.replace(b'\x00', b''))
            # return to_str(b'[' + item.replace(b'\x00', b'') + b']')
        print(f'pattern[{i:>2}]:', '|'.join(shorthand(item) for item in pattern), flush=True)
        dic.update(brute_force_pattern(init, post, pattern))


BRUTE_LOCALS:Dict[int,bytes] = {}
POSTFIX_PATTERNS:List[bytes] = (b'',) + tuple(to_bytes(str(i)) for i in range(0, 26))
POSTFIX_PATTERNS2:List[bytes] = (b'',) + tuple(to_bytes(str(i)) for i in range(0, 11))
##POSTFIX_PATTERNS:List[bytes] = (b'',) + tuple(to_bytes(str(i)) for i in range(0, 100))


def load_locals_brute() -> Dict[int,bytes]:
    # print('Loading brute-force locals')
    if not BRUTE_LOCALS:
        bflocals = BRUTE_LOCALS
        # brute_force_patterns(bflocals,'_','@', *[ ("A-Za-z"), ((0,3), "a-z"), ((0,1), "0-9") ])
        # brute_force_patterns(bflocals,'_','@', *[ ("A-Za-z"), ((0,2), "a-z"), ((2), "0-9") ])

        brute_force_patterns(bflocals,'_','', *[ ((1,5), "a-z") ])
        # brute_force_patterns(bflocals,'_','', *[ ((5,5), "a-z") ])
        # brute_force_patterns(bflocals,'_','', *[ ((1,4), "a-z") ])
        ##brute_force_patterns(bflocals,'_','', *[ ("A-Za-z"), ((0,3), "a-z") ])

        # brute_force_patterns(bflocals,'_','', *[ ("A-Za-z"), ((0,3), "a-z"), ((0,1), "0-9") ])
        # brute_force_patterns(bflocals,'_','', *[ ("A-Za-z"), ((0,2), "a-z"), ((2), "0-9") ])
    return BRUTE_LOCALS

def find_custom_brute(H:int, prefix:str, postfix:str, group:str) -> List[str]:
    """find_local_brute(hash32('_tmp24@')) -> ['_tmp24@']
    find_local_brute(hash32('_Hell1@')) -> ['_Hell1@']
    """
    load_locals_brute()
    from zlib import crc32 as c
    from itertools import product as Pr
    C = invhash32
    # I = c(b'_')
    e = to_bytes(prefix or b'')
    o = to_bytes(postfix or b'') + b'@' + to_bytes(group or b'')
    # baselen = len(o) + 1
    X = tuple((c(b'_'+b'\0'*n) ^ c(e+b'\0'*n)) for n in range(1, 6))
    H = C(o, H)
    B = BRUTE_LOCALS
    P = POSTFIX_PATTERNS
    del c, postfix#, baselen

    return [(e+s+p+o).decode('cp932') for s,p in ((B.get(C(p, H)^x),p) for p,x in Pr(P,X)) if s is not None]
    #return [(e+[ss for ss in s if ss is not None][0]+p+o).decode('cp932') for s,p in (([B.get(C(p, H)^x) for x in X],p) for p in P) if any(s)]# is not None]

def find_custom_brutes(H:int, prefix:str, postfix:str, *groups:str) -> List[str]:
    """find_local_brute(hash32('_tmp24@')) -> ['_tmp24@']
    find_local_brute(hash32('_Hell1@')) -> ['_Hell1@']
    """
    if not groups:
        from ._hashes import GROUPS
        groups = tuple(g for g in GROUPS.values() if g not in ('','MAJIRO_INTER'))
        del GROUPS
    load_locals_brute()
    from zlib import crc32 as c
    from itertools import product as Pr
    C = invhash32
    # I = c(b'_')
    e = to_bytes(prefix or b'')
    O = tuple(to_bytes(postfix or b'') + b'@' + to_bytes(g or b'') for g in groups)
    # baselen = len(o) + 1
    X = tuple((n,c(b'_'+b'\0'*n) ^ c(e+b'\0'*n)) for n in range(1, 6))
    H = tuple((C(o, H),o) for o in O)
    B = BRUTE_LOCALS
    P = POSTFIX_PATTERNS2
    del c, prefix, postfix, groups#, baselen

    return [(e+s+p+o).decode('cp932') for s,p,i,o in ((B.get(C(p, h)^x),p,i,o) for p,(i,x),(h,o) in Pr(P,X,H)) if s is not None and len(s)==i]
    #return [(e+[ss for ss in s if ss is not None][0]+p+o).decode('cp932') for s,p in (([B.get(C(p, H)^x) for x in X],p) for p in P) if any(s)]# is not None]

def unload_locals_brute() -> bool:
    if BRUTE_LOCALS:
        BRUTE_LOCALS.clear()
        return True
    return False

def find_local_brute(H:int, postfix:str) -> List[str]:
    """find_local_brute(hash32('_tmp24@')) -> ['_tmp24@']
    find_local_brute(hash32('_Hell1@')) -> ['_Hell1@']
    """
    load_locals_brute()
    from zlib import crc32 as c
    C = invhash32
    # I = c(b'_')
    o = to_bytes(postfix or b'') + b'@'
    H = C(o, H)
    B = BRUTE_LOCALS
    P = POSTFIX_PATTERNS
    del c, postfix

    return ['_'+(s+p+o).decode('cp932') for s,p in ((B.get(C(p, H)),p) for p in P) if s is not None]

# def find_custom_brute(H:int, prefix:str, postfix:str, group:str) -> List[str]:
#     """find_local_brute(hash32('_tmp24@')) -> ['_tmp24@']
#     find_local_brute(hash32('_Hell1@')) -> ['_Hell1@']
#     """
#     load_locals_brute()
#     from zlib import crc32 as c
#     C = invhash32
#     # I = c(b'_')
#     e = to_bytes(prefix or b'')
#     o = to_bytes(postfix or b'') + b'@' + to_bytes(group or b'')
#     baselen = len(o) + 1
#     X = tuple((c(b'_'+b'\0'*n) ^ c(e+b'\0'*n)) for n in range(baselen, baselen + 7))
#     H = C(o, H)
#     B = BRUTE_LOCALS
#     P = POSTFIX_PATTERNS
#     del c, baselen, postfix

#     return [(e+s[0]+p+o).decode('cp932') for s,p in ([(B.get(C(p^x, H)),p) for x in X] for p in P) if s]# is not None]


def main(args:list=None) -> int:
    if args is None:
        import sys
        args = sys.argv[1:]
    
    if not args:
        args = ['brute_force_locals_cached3.py']

    print('Loading brute-force locals...')
    bflocals = load_locals_brute()
    print('Done!')
    
    def do_find_local(name:str):
        print(f'finding {name!r}... ', end='', flush=True)
        print(find_local_brute(hash32(name)), flush=True)

    def do_find_custom(name:str,prefix,postfix,group):
        print(f'finding \'{prefix}{name}{postfix}@{group}\'... ', end='', flush=True)
        print(find_custom_brute(hash32(f'{prefix}{name}{postfix}@{group}'),prefix,postfix,group), flush=True)

    if args[0] in ('-l','--loc'):
        for a in args[1:]:
            do_find_local(f'_{a}@')
        return 0
    elif args[0] in ('-f','--find'):
        i = 1
        from ...name import splitsymbols
        for a in args[1:]:
            do_find_custom(splitsymbols(a))
        #     do_find_local(f'_{a}@')
        # while i < len(args):
        #     do_find_custom(&args[i:i+4])
            # i += 4
            # do_find_local(f'{a}')
        return 0

    VAR_NAME:str = 'BRUTE_FORCE_LOCALS'
    with open(args[0], 'wt+', encoding='utf-8') as writer:
        writer.write('#!/usr/bin/env python3\n')
        writer.write('#-*- coding: utf-8 -*-\n\n')
        writer.write('"""Brute-forced local variable hashes\n')
        writer.write('"""\n\n')
        

        writer.write(f'__all__ = [{VAR_NAME!r}]\n\n')

        writer.write('#######################################################################################\n\n')

        writer.write('from typing import Dict\n\n\n')

        writer.write(f'{VAR_NAME}:Dict[int,str] = ')
        writer.write(repr(bflocals).replace(" ","").replace(":b'",":'").replace("'",'"'))
        writer.write('\n')

        writer.write('\n\n')
        writer.write('del Dict\n\n')

        writer.flush()


    return 0

if __name__ == '__main__':
    exit(main())



del Dict, List, Tuple, Union
