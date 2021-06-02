#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Brute-force hashes lookup generation
"""

__version__ = '0.1.1'
__date__    = '2021-06-01'
__author__  = 'Robert Jordan'

__all__ = ['BruteForceSet'] #, 'tocharset', 'fromcharset']

#######################################################################################

## runtime imports:
# from ..hashes import GROUPS
# from zlib import crc32
# from ...crypt import invhash32
# from ...name import joingroup
# from ...crypt import hash32  # used in find_group()

from itertools import chain, product
from typing import Dict, Iterator, List, Tuple, Union
from ...util.typecast import to_str, to_bytes


#######################################################################################

#region ## CHARSET PATTERNS ##

def tocharset(pattern:str, strip_duplicates:bool=False) -> str:
    """parse_charset('a-z0-9') -> 'abcdefghijklmnopqrstuvwxyz0123456789'
    """
    charset = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        #
        if c == '-':  # character range
            if i == 0:
                raise ValueError("Unescaped first '-' character in charset")
            elif i+1 == len(pattern):
                raise ValueError("Unescaped trailing '-' character in charset")
            i += 1  # consume '-'
            start = charset[-1]  # already parsed last character
            end = pattern[i]
            if end == '\\':
                if i+1 == len(pattern):
                    raise ValueError("Trailing '\\\\' escape in charset")
                i += 1  # consume '\'
                end = pattern[i]
            if ord(end) < ord(start):
                raise ValueError(f"Range [{start!r}-{end!r}], end char is less than start char")
            # add range: start char already added, start at +1
            charset.extend(chr(cc) for cc in range(ord(start)+1, ord(end)+1))
        #
        elif c == '\\':  # escape literal
            if i+1 == len(pattern):
                raise ValueError("Trailing '\\\\' escape in charset")
            i += 1  # consume '\'
            charset.append(pattern[i])
        #
        else:  # single character
            charset.append(c)
        #
        i += 1  # next character
    #
    # error-check resulting charset
    if not charset:
        raise ValueError('Charset is empty')
    #
    # string of duplicates to print in error message
    duplicates = []
    i = 0
    while i < len(charset):  # charset length is dynamic in this loop
        first = True
        c = charset[i]
        for j in range(i+1, len(charset)):
            if c == charset[j]:
                if not strip_duplicates and first:
                    first = False
                    duplicates.append(c)
                del charset[j]
        i += 1  # next character
    #
    if not strip_duplicates and duplicates:
        raise ValueError(f"Found {len(duplicates)} duplicates in charset: {''.join(duplicates)!r}")
    #
    return ''.join(charset)

def fromcharset(charset:str) -> str:
    pattern = []
    def endrange(c_start, c_last):
        if c_start in ('-','\\'): c_start = f'\\{c_start}'
        if c_start != c_last:
            if c_last in ('-','\\'): c_last = f'\\{c_last}'
            pattern.append(f'{c_start}-{c_last}')
        else:
            pattern.append(c_start)
    #
    c_start = c_last = charset[0]
    for c in charset[1:]:
        # end current pattern range?
        if ord(c) != ord(c_last)+1:
            endrange(c_start, c_last)
            c_start = c
        c_last = c
    endrange(c_start, c_last)
    #
    return ''.join(pattern)

#endregion

#######################################################################################

#region ## BRUTE-FORCE HASHSET ##

#BruteForcePattern
# str -> ((1,1), str)
# (count, str) -> ((count,count), str)
# ((min,max), str) -> ((min,max), str)
"""str -> ((1,1), str)
(count, str) -> ((count,count), str)
((min,max), str) -> ((min,max), str)
"""
BruteForcePattern = Union[str,  Tuple[int,str],  Tuple[Tuple[int,int], str]]


class BruteForceSet:
    """Utility class for pre-computing large numbers of hash/name pairs,
    and checking against them while balancing memory consumption.
    """
    __slots__ = ('patterns', 'hashes', 'min_len', 'max_len', 'prefix', 'def_postfix', 'def_groups', 'pre_postfixes')
    patterns:List[BruteForcePattern]
    hashes:Dict[int,bytes]
    min_len:int
    max_len:int
    prefix:str
    def_postfix:str
    def_groups:Tuple[str,...]
    pre_postfixes:Tuple[str,...]

    PRE_POSTFIXES:Tuple[str,...] = ('',) + tuple(str(i) for i in range(0, 16))

    def __init__(self, prefix:str='', *, def_postfix:str='', def_groups:List[str]=..., pre_postfixes:List[str]=...):
        # state:
        self.patterns = []
        self.hashes = {}
        self.min_len = 0
        self.max_len = 0
        #
        # during computation:
        self.prefix = prefix
        #
        # during find:
        self.def_postfix = def_postfix or ''
        if def_groups is Ellipsis:
            from ..hashes import GROUPS
            def_groups = tuple(GROUPS.values())
        elif not def_groups:
            def_groups = ('',)
        self.def_groups = tuple(def_groups)
        # postfixes that are calulated at find-time, in order to balance memory usage with CPU consumption
        if pre_postfixes is Ellipsis:
            pre_postfixes = self.PRE_POSTFIXES
        elif not pre_postfixes:
            pre_postfixes = ('',)
        self.pre_postfixes = tuple(pre_postfixes)
    #
    def __repr__(self) -> str:
        if self.hashes:
            return f'<{self.__class__.__name__}: patterns={len(self.patterns)} hashes={len(self.hashes)}>'
        else:
            return f'<{self.__class__.__name__}: patterns={len(self.patterns)} unloaded>'
        
    def __del__(self):
        self.hashes.clear()  # forcefully clear excessive memory usage
    #
    ## LOADING/UNLOADING:
    #
    @property
    def is_loaded(self) -> bool:
        """Returns True if compute() has already been run."""
        return bool(self.hashes)
    def unload(self) -> bool:
        """Unloads computed hashes from memory."""
        if self.hashes:
            self.hashes.clear()
            return True
        return False
    #
    ## SETUP/COMPUTATION:
    #
    def add_pattern(self, *parts:BruteForcePattern, strip_duplicates:bool=False):
        """Add pattern for hash computation.

        parts:
            str -> ((1,1), str)
            (count, str) -> ((count,count), str)
            ((min,max), str) -> ((min,max), str)
        
        str may be a charset style pattern, where `a-e` patterns are exanded to `abcde`, etc.
        escapes: { '-': '\\-',  '\\': '\\\\' }
        """
        if not parts:
            raise ValueError('Must specify at least one part')
        # expand all pattern parts
        pattern_parts = []
        for part in parts:
            if not isinstance(part, tuple):       # str -> ((1,1), str)
                (min_cnt,max_cnt),charset = ((1, 1), part)
            elif not isinstance(part[0], tuple):  # (count, str) -> ((count,count), str)
                (min_cnt,max_cnt),charset = ((part[0],part[0]) + part[1:])  # keep tuple unpack error checking
            else:                                 # ((min,max), str) -> ((min,max), str)
                (min_cnt,max_cnt),charset = part
            #
            charset = tocharset(charset, strip_duplicates)
            pattern_parts.append([[to_bytes(charset)]*r for r in range(min_cnt, max_cnt+1)])
        #
        self.patterns.extend(tuple(chain(*p)) for p in product(*pattern_parts))
    #
    def compute(self, verbose:bool=False):
        """Compute hashes from patterns added with `add_pattern`.
        """
        if not self.patterns:
            raise Exception('No patterns to compute')
        from zlib import crc32
        self.hashes.clear()
        #
        tried_patterns = set()
        init = crc32(to_bytes(self.prefix))
        self.min_len, self.max_len = 0xffffffff, 0
        for i,pattern in enumerate(self.patterns):
            if pattern in tried_patterns:
                continue  # duplicate pattern, skipping...
            tried_patterns.add(pattern)
            #
            if verbose:
                print(f'pattern[{i:>2}]:', '|'.join(fromcharset(to_str(item)) for item in pattern), flush=True)
            self.min_len = min(self.min_len, len(pattern))
            self.max_len = max(self.max_len, len(pattern))
            self.hashes.update(self._brute_compute(init, product(*pattern)))
    #
    @staticmethod
    def _brute_compute(I:int, P) -> List[Tuple[int,bytes]]:
        """_brute_compute(init, product(*pattern)) -> [(hash,match), ...]
        """
        from zlib import crc32 as c
        return [(c(B,I),B) for B in (bytes(B) for B in P)]
    #
    ## UNHASH FROM COMPUTED SET:
    #
    def find_hash_defprefix(self, hash:int, postfix:str='', *groups:str) -> List[str]:
        """find_hash_defprefix(hash32('_tmp24@'), '', '') -> ['_tmp24@']
        find_hash_defprefix(hash32('_str10$@'), '$', '') -> ['_str10$@']

        search for a hash using the default prefix generated for the database.
        """
        return self.find_hash(hash, self.prefix, postfix, *groups)
    #
    def find_hash(self, hash:int, prefix:str='', postfix:str='', *groups:str) -> List[str]:
        """find_hash(hash32('_tmp24@'), '_', '', '') -> ['_tmp24@']
        find_hash(hash32('_str10$@'), '_', '$', '') -> ['_str10$@']
        find_hash(hash32('@ret@BUTONMENU'), '@', '', 'GLOBAL', 'KOEKOE', 'BUTONMENU') -> ['@ret@BUTONMENU']

        search for a hash using a different prefix than in the database.
        """
        from zlib import crc32
        from ...crypt import invhash32
        from ...name import joingroup
        if not groups:
            groups = self.def_groups
            # from ..hashes import GROUPS
            # groups = tuple(g for g in GROUPS.values())# if g not in ('','MAJIRO_INTER'))
            # #groups = tuple(g for g in GROUPS.values() if g not in ('','MAJIRO_INTER'))
            # del GROUPS
        #
        pre_postfixes = self.pre_postfixes
        postfixes = tuple(to_bytes(joingroup(pr + postfix, g)) for pr,g in product(pre_postfixes, groups))
        # postfixes = tuple(to_bytes(joingroup(postfix, g)) for g in groups)
        #
        # pre-calculate: inverse hash/postfix pairs, needed to match patterns from self.hashes
        H = tuple((invhash32(po, hash), po) for po in postfixes)
        # H = tuple((invhash32(p+o, hash),p+o) for p,o in product(self.pre_postfixes, postfixes))
        #
        if prefix == self.prefix: # no need to transform hashes, use faster method
            return self._brute_find_hash(self.hashes, to_bytes(self.prefix), H)
        else:
            prefix = to_bytes(prefix or b'')
            postfix = to_bytes(postfix or b'')
            # see: <https://github.com/trigger-segfault/unhash_name/wiki/Lookup-hash-with-custom-prefix>
            # transformation of one hash prefix into another
            X = tuple((crc32(to_bytes(self.prefix) + bytes(n)) ^ crc32(prefix + bytes(n)), n) for n in range(self.min_len, self.max_len + 1))
            #
            return self._brute_find_hash_withprefix(self.hashes, prefix, product(H,X))
    #
    @staticmethod
    def _brute_find_hash(D:Dict[int,bytes], E:bytes, H) -> List[str]:
        """find_local_brute(hashdict, prefix, [(hash,postfix), ...]) -> [fullname, ...]
        """
        # joined: prefix `E`, match `s`, postfix `o`
        return [(E+s+o).decode('cp932') for s,o in (
                # iterate: inverse hash `h` postfix `o` patterns
                (D.get(h),o) for h,o in H
            ) if s is not None]  # was match found?
    #
    @staticmethod
    def _brute_find_hash_withprefix(D:Dict[int,bytes], E:bytes, HX) -> List[str]:
        """_find_custom_brutes(hashdict, prefix, product([(hash,postfix), ...], [(xor,n), ...])) -> [fullname, ...]
        """
        # joined: prefix `E`, match `s`, postfix `o`
        return [(E+s+o).decode('cp932') for s,o,n in (
                # iterate: inverse hash `h`, postfix `o` patterns -with- prefix transforms `x` of length `n`
                (D.get(h^x),o,n) for (h,o),(x,n) in HX
            ) if s is not None and len(s)==n]  # was match found? only valid if: transform length `n` is same as match


r"""

# TESTING:
from mj.crypt import hash32
from mj.database.unhashers import BruteForceSet
bf = BruteForceSet('_')
# bf.add_pattern(*[ ((1,5), "a-z") ])
bf.add_pattern(*[ ((1,4), "a-z") ])
bf.compute(True)
bf.min_len, bf.max_len
bf.find_hash(0x633b371d, '@', '')
bf.find_hash(hash32(b'_ret@'), '_', '', '')
# bf.find_hash_defprefix(hash32(b'_ret@'), '', '')

"""

#endregion

#######################################################################################

# ## MAIN FUNCTION ##

# def main(args:list=None) -> int:
#     from ...crypt import hash32
#     if args is None:
#         import sys
#         args = sys.argv[1:]
    
#     if not args:
#         args = ['brute_force_locals_cached3.py']

#     print('Loading brute-force locals...')

#     bf = BruteForceSet('_', pre_postfixes=('',) + tuple(str(n) for n in range(1, 26)))

#     # # bf.add_pattern(*[ ((1,5), "a-z") ])
#     # bf.add_pattern(*[ ((1,4), "a-z") ])
#     # bf.compute(True)
#     # bf.min_len, bf.max_len
#     # bf.find_hash(0x633b371d, '@', '')
#     # bf.find_hash(crc32(b'_ret@'), '_', '', '')
#     # # bf.find_hash_defprefix(crc32(b'_ret@'), '', '')
#     bf.add_pattern( ((1,5), "a-z") )
#     # bf.add_pattern( ((5,5), "a-z") )
#     # bf.add_pattern( ((1,4), "a-z") )
#     ##bf.add_pattern( ("A-Za-z"), ((0,3), "a-z") )

#     # bf.add_pattern( ("A-Za-z"), ((0,3), "a-z"), ((0,1), "0-9") )
#     # bf.add_pattern( ("A-Za-z"), ((0,2), "a-z"), ((2), "0-9") )

#     print('Done!')
    
#     def do_find_local(name:str):
#         print(f'finding {name!r}... ', end='', flush=True)
#         print(bf.find_hash_defprefix(hash32(name), ''), flush=True)

#     def do_find_custom(name:str,prefix,postfix,group):
#         print(f'finding \'{prefix}{name}{postfix}@{group}\'... ', end='', flush=True)
#         print(bf.find_hash(hash32(f'{prefix}{name}{postfix}@{group}'),prefix,postfix,group), flush=True)

#     if args[0] in ('-l','--loc'):
#         for a in args[1:]:
#             do_find_local(f'_{a}@')

#     elif args[0] in ('-f','--find'):
#         i = 1
#         from ...name import splitsymbols
#         for a in args[1:]:
#             do_find_custom(splitsymbols(a))

#     return 0


# ## MAIN CONDITION ##

# if __name__ == '__main__':
#     exit(main())


#######################################################################################

del Dict, Iterator, List, Tuple, Union  # cleanup declaration-only imports
