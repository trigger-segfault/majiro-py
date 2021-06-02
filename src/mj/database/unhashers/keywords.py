#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""CRC-32 keyword-based unhasher

Unhash CRC-32 names by combining keywords.
"""

__version__ = '1.0.1'
__date__    = '2021-06-02'
__author__  = 'Robert Jordan'

__all__ = ['KeywordsConfig', 'KeywordUnhasher']

#######################################################################################

## runtime imports:
# from zlib import crc32  # for faster unhash method

from collections import OrderedDict
from itertools import chain, product
from typing import Callable, Dict, Iterable, List, Tuple, Union

from ...crypt import hash32, invhash32
from ...util.typecast import to_bytes, to_str


####################################################################################### 

#region ## UTILITIES AND HELPERS ##

# exclude remaining duplicates while maintaining order
def ordered_unique(items:list) -> tuple:
    d = OrderedDict()
    for item in items:
        d.setdefault(item, None)
    return tuple(d.keys())

def list_to_bytes(items:Iterable[Union[str,bytes]]) -> List[bytes]: return [to_bytes(s) for s in items]
def list_to_str(items:Iterable[Union[str,bytes]]) -> List[str]:   return [to_str(s) for s in items]

# def has_alpha(s:str) -> bool: return any(c.isalpha() for c in s)
# def has_alnum(s:str) -> bool: return any(c.isalnum() for c in s)
# def has_digit(s:str) -> bool: return any(c.isdigit() for c in s)
# def has_lower(s:str) -> bool: return any(c.islower() for c in s)
# def has_upper(s:str) -> bool: return any(c.isupper() for c in s)

#endregion

#######################################################################################

#region ## WORDS CONFIG ##

# class WordsGroup:
#     __slots__ = ('normal', 'upper', 'lower', 'capitalize', 'underscore', 'trailing', 'words', 'positions')
#     def __init__(self, **kwargs):
#         # inputs:
#         self.words:list      = [] #WORDS
#         # variations:
#         self.normal:bool     = True  #NORMAL
#         self.upper:bool      = False #UPPER
#         self.lower:bool      = False #LOWER
#         self.capitalize:bool = False #CAPITALIZE
#         self.underscore:bool = False #UNDERSCORE
#         self.trailing:bool   = False #TRAILING
#         # complexity:
#         self.positions:list  = None
#         for k,v in kwargs.items():
#             if not k in self.__slots__:
#                 raise KeyError(k)
#             setattr(self, k, v)

#     def clone(self) -> 'WordsGroup':
#         kwargs = dict((k,getattr(self, k)) for k in self.__slots__)
#         for k,v in kwargs.items():
#             if isinstance(v, (list, set, dict, bytearray)):
#                 kwargs[k] = type(v)(v) # re-wrap
#         return type(self)(**kwargs)

class KeywordsConfig:
    __slots__ = ('normal', 'upper', 'lower', 'capitalize', 'underscore', 'trailing', 'minlen', 'maxlen', 'groups', 'groups_raw', 'words', 'words_raw', 'prefixes', 'postfixes', 'targets')
    # variations:
    normal:bool
    upper:bool
    lower:bool
    capitalize:bool
    underscore:bool
    trailing:bool
    # scan:
    minlen:int
    maxlen:int
    # inputs:
    groups:list
    groups_raw:list
    words:list
    words_raw:list
    prefixes:list
    postfixes:list
    targets:list

    # def __init__(self, **kwargs):
    def __init__(self, *, normal:bool=True, upper:bool=False, lower:bool=False, capitalize:bool=False, underscore:bool=False, trailing:bool=False, minlen:int=0, maxlen:int=0xffffffff, groups:List[str]=(), groups_raw:List[str]=(), words:List[str]=(), words_raw:List[str]=(), prefixes:List[str]=(), postfixes:List[str]=(), targets:List[int]=()):
        # variations:
        self.normal     = normal
        self.upper      = upper
        self.lower      = lower
        self.capitalize = capitalize
        self.underscore = underscore
        self.trailing   = trailing
        # scan:
        self.minlen = minlen
        self.maxlen = maxlen
        # inputs:
        self.groups     = groups
        self.groups_raw = groups_raw
        self.words      = words
        self.words_raw  = words_raw
        self.prefixes   = prefixes
        self.postfixes  = postfixes
        self.targets    = targets
        # # assign kwargs:
        # for k,v in kwargs.items():
        #     if not k in self.__slots__:
        #         raise KeyError(k)
        #     setattr(self, k, v)

#endregion

#region ## KEYWORDS UNHASHER ##

class KeywordUnhasher:
    Config = KeywordsConfig  # KeywordsConfig type within class for easier access

    config:KeywordsConfig
    count:int
    callback:Callable[['KeywordUnhasher',int,str,tuple,str,str,int],None]  # callback(unhasher, depth:int, prefix:str, words:tuple, postfix:str, group:str, result:int)
    groups:Tuple[bytes,...]
    words:Tuple[bytes,...]
    words_tr:Tuple[bytes,...]
    prefixes:Tuple[bytes,...]
    postfixes:Tuple[bytes,...]
    targets:Dict[int,Tuple[int,bytes,bytes]]
    init:int

    def __init__(self, config:KeywordsConfig, callback:Callable[['KeywordUnhasher',int,str,tuple,str,str,int],None]=None):
        self.config = config
        self.count = 0
        self.callback = self.result_callback if callback is None else callback

        # prepare all words and hash values:
        self.groups   = ordered_unique(list_to_bytes(chain([self._prep_group(g, True)  for g in self.config.groups_raw],
                                                                 [self._prep_group(g, False) for g in self.config.groups]))) or (b'',)

        self.words    = ordered_unique(list_to_bytes(chain(*[self._prep_word(w, True,  False) for w in self.config.words_raw],
                                                                 *[self._prep_word(w, False, False) for w in self.config.words])))
        self.words_tr = ordered_unique(list_to_bytes(chain(*[self._prep_word(w, True,  True)  for w in self.config.words_raw],
                                                                 *[self._prep_word(w, False, True)  for w in self.config.words])))
        if len(self.words_tr) == len(self.words) and self.words_tr[0] == self.words[0]:  # lazy check which usually is required when doing only-underscores
            self.words_tr = self.words  # nothing changed, keep original instance

        self.prefixes  = ordered_unique(list_to_bytes(self.config.prefixes))  or (b'',)
        self.postfixes = ordered_unique(list_to_bytes(self.config.postfixes)) or (b'',)

        if self.is_product_groups:
            self.targets = dict((t, (t,b'',b'')) for t in self.config.targets)
        elif self.is_product_postfixes:
            self.targets = dict((invhash32(g, t), (t,g,b'')) for t,g in product(self.config.targets, self.groups))
        else:
            self.targets = dict((invhash32(p+g, t), (t,g,p)) for t,p,g in product(self.config.targets, self.postfixes, self.groups))

        self.init = 0 if self.is_product_prefixes else hash32(self.prefixes[0])

    #region ## INTERNAL PREP ##

    def _prep_group(self, group:str, raw:bool) -> str:
        return group if raw else f'@{group}'
        # return '' if group is None else f'@{group}'
        # return ['' if group is None else f'@{group}']

    def _prep_word(self, word:str, raw:bool, trailing:bool) -> list:
        if raw:
            return [word]
        words = []
        if self.config.normal:     words.append(word)
        if self.config.capitalize: words.append(word.capitalize())
        if self.config.upper:      words.append(word.upper())
        if self.config.lower:      words.append(word.lower())
        if self.config.underscore and not (self.config.normal or self.config.capitalize or self.config.upper or self.config.lower):
            if trailing and not self.config.trailing:
                words.append(word)
            if not trailing or self.config.trailing:
                words.append(word+'_')
        # skip adding underscores? (this is for words list of last word at depth)
        elif self.config.underscore and (not trailing or self.config.trailing):
            words.extend([w+'_' for w in words] if words else [word+'_']) # lazy handling for empty list, just word_
        return words

    #endregion

    #region ## PROPERTIES ##

    @property
    def has_prefixes(self) -> bool: return self.prefixes != (b'')
    @property
    def has_postfixes(self) -> bool: return self.postfixes != (b'')
    @property
    def has_groups(self) -> bool: return self.groups != (b'')
    @property
    def is_product_prefixes(self) -> bool: return len(self.prefixes) > 1
    @property
    def is_product_postfixes(self) -> bool: return False # return len(self.postfixes) > 1
    @property
    def is_product_groups(self) -> bool: return self.is_product_postfixes and False # return len(self.groups) > 1
    @property
    def is_multitarget(self) -> bool: return len(self.targets) > 1
    
    #endregion

    #region ## DO UNHASH ##

    def do_depth(self, n:int):
        items = []
        #NOTE: this is baked into self.init when there's only one value
        if self.is_product_prefixes:
            items.append(self.prefixes)
        for _ in range(0, n-1):
            items.append(self.words)
        if n > 0:
            items.append(self.words_tr)
        #NOTE: these are ALWAYS baked into self.targets (but keep checks in case we want to change it)
        if self.is_product_postfixes:
            items.append(self.postfixes)
        if self.is_product_groups:
            items.append(self.groups)

        if not items:
            # no items, can't do depth==0, manually check hash
            from zlib import crc32 as c
            if c(b'', self.init) in self.targets:
                self._handle_result(()) # pass empty tuple
        else:
            # product to check every possible permutation of items
            P = product(*items)
            # pass self, because staticmethod
            if self.is_multitarget:
                self._do_unhash_multitarget(self, self.init, self.targets, P)
            else:
                self._do_unhash_singletarget(self, self.init, list(self.targets)[0], P)

    #endregion

    #region ## HANDLE RESULT AND CALLBACK ##

    @staticmethod
    def result_callback(unhasher:'KeywordUnhasher', depth:int, prefix:str, words:tuple, postfix:str, group:str, result:int):
        print(f'{result}\t{prefix}{"".join(words)}{postfix}{group}')

    def _handle_result(self, words:tuple):
        self.count += 1
        value = hash32(b''.join(words), self.init)
        result = self.targets[value][0]
        group, postfix = list_to_str(self.targets[value][1:3])
        prefix = to_str(self.prefixes[0])
        words  = list_to_str(words)

        if self.is_product_groups:
            (group, postfix), words = words[-2:], words[:-2]
        elif self.is_product_postfixes:
            postfix, words = words[-1], words[:-1]
        if self.is_product_prefixes:
            prefix, words = words[0], words[1:]

        self.callback(self, len(words), prefix, words, postfix, group, result)

    #endregion

    #region ## INTERNAL UNHASH LOOPS ##

    #TODO: is staticmethod faster?? (still pass self for info)
    @staticmethod  
    def _do_unhash_multitarget(self, I:int, T:dict, P):
        from zlib import crc32 as c
        # stupid method that overwrites use of P since it's no longer needed
        #TODO: is this faster?
        # <https://stackoverflow.com/questions/47456631/simpler-way-to-run-a-generator-function-without-caring-about-items>
        for P in (B for B in P if c(b''.join(B), I) in T):
            self._handle_result(P)
        # for B in P:
        #     if c(b''.join(B), I) in T: self._handle_result(B)
        # for P in P:
        #     if c(b''.join(P), I) in T: self._handle_result(P)

    @staticmethod
    def _do_unhash_singletarget(self, I:int, T:int, P):
        from zlib import crc32 as c
        # stupid method that overwrites use of P since it's no longer needed
        #TODO: is this faster?
        for P in (B for B in P if c(b''.join(B), I) == T):
            self._handle_result(P)
        # for B in P:
        #     if c(b''.join(B), I) == T: self._handle_result(B)
        # for P in P:
        #     if c(b''.join(P), I) == T: self._handle_result(P)
    
    #endregion

#endregion


#######################################################################################

del Callable, Dict, Iterable, List, Tuple, Union  # cleanup declaration-only imports
