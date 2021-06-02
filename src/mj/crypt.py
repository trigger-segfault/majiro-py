#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro encryption and hashing utils
"""

__version__ = '1.1.2'
__date__    = '2021-05-15'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['crypt32', 'initkey32', 'hash32', 'hash64', 'invhash32', 'check_hashmid', 'check_hashbegin', 'check_hashend', 'check_hashdiffs']

# <https://en.wikipedia.org/wiki/Cyclic_redundancy_check>
# <https://users.ece.cmu.edu/~koopman/crc/crc32.html>
# <https://users.ece.cmu.edu/~koopman/crc/crc64.html>
# <https://en.wikipedia.org/wiki/Symmetric-key_algorithm#Reciprocal_cipher>

#######################################################################################

from struct import pack
from typing import List, Optional, Tuple, Union
from zlib import crc32 as _crc32
from .util.typecast import to_bytes #, unsigned_I, unsigned_Q


#######################################################################################

#region ## TYPEDEFS AND HELPERS ##

StrBytes = Union[str,bytes]
IntBytes = Union[int,str,bytes]


def to_hash32(value:IntBytes) -> int:
    """to_hash32(bytes) -> hash32(bytes)
    to_hash32(str)   -> hash32(str)
    to_hash32(int)   -> unsigned_I(int)

    helper function to allow passing a hash name or value.
    """
    return (value & 0xffffffff) if isinstance(value, int) else hash32(value)

def to_hash64(value:IntBytes) -> int:
    """to_hash64(bytes) -> hash64(bytes)
    to_hash64(str)   -> hash64(str)
    to_hash64(int)   -> unsigned_Q(int)

    helper function to allow passing a hash name or value.
    """
    return (value & 0xffffffffffffffff) if isinstance(value, int) else hash64(value)

#endregion

#######################################################################################

#region ## CRC TABLE SETUP FUNCTIONS ##

CRC32_POLY:int = 0xEDB88320          # CRC-32 reversed polynomial
CRC64_POLY:int = 0x42F0E1EBA9EA3693  # CRC-64 forward polynomial (should have been 0xC96C5795D7870F42)

## standard CRC-32 (table calculation) used by zlib
def _calc32(num:int, poly:int=CRC32_POLY) -> int:
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ poly
        else:         num >>= 1
    return num

## NON-STANDARD CRC-64! (table calculation)
#NOTE: in asm, this uses the poly: 0x85E1C3D753D46D27, and bitshifts after XOR with poly
# behavior is identical to normal reverse CRC-64 implementation with common poly: 0x42F0E1EBA9EA3693
# (by mistake it seems the forward polynomial was used for the reverse CRC-64 implementation)
def _calc64(num:int, poly:int=CRC64_POLY) -> int:
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ poly
        else:         num >>= 1
    return num

## inverse for CRC-32 (xor against (crc << 8))
## this table stores 40-bit integer values to counter Python's lack of integer constraints.
# see: <https://stackoverflow.com/a/38676286/7517185>
def _invcalc32(num:int, poly:int=CRC32_POLY) -> int:
    unpoly = (poly << 1) | 0x1
    # NOTE: usage of msbyte (num << 32) is intentional in order to xor-out Python's lack of integer constraints.
    msbyte = num << 32
    num <<= 24
    for _ in range(8):
        if num & 0x80000000: num = (num << 1) ^ unpoly
        else:                num <<= 1
    return msbyte | num
    ## OLD DOCUMENTATIONAL METHOD:
    # for i in range(256):
    #     c = _calc32(i, poly)
    #     if (c >> 24) == num:
    #         return (c << 8) | i
    # raise ValueError(f'0x{num:02x} not found in CRC32_TABLE')

## DOCUMENTATIONAL USAGE ONLY:
## inverse for CRC-32 (find index of most significant byte in table)
def _index32(num:int, poly:int=CRC32_POLY) -> int:
    """_index32(_calc32(0xd7)) -> 0xd7
    finds the index of the most significant byte in the CRC32_TABLE
    """
    for i in range(256):
        if (_calc32(i, poly) >> 24) == num:
            return i
    raise ValueError(f'0x{num:02x} not found in CRC32_TABLE')

#endregion

#region ## CRC TABLES ##

CRC32_TABLE:Tuple[int,...]  = tuple(_calc32(n) for n in range(256))
CRC32_INVTABLE:Tuple[int,...] = tuple(_invcalc32(n) for n in range(256))
# only used for backout_* functions, as a documentational approach (can be substituted with: CRC32_INVTABLE[n] & 0xff)
CRC32_INDEX:Tuple[int,...]  = tuple(_index32(n) for n in range(256))
CRC64_TABLE:Tuple[int,...]  = tuple(_calc64(n) for n in range(256))
# 1024-byte Majiro script XOR decryption key (standard CRC-32 table output in little-endian)
CRYPT32_KEY:bytes = pack('<256I', *CRC32_TABLE)
# 2048-byte Majiro script XOR decryption key (broken Majiro CRC-64 table output in little-endian)
CRYPT64_KEY:bytes = pack('<256Q', *CRC64_TABLE)

#endregion

#region ## CRC XOR CIPHER FUNCTIONS ##

# XOR encryption/decryption method applied to b"MajiroObjX1.000\x00" bytecode and RCT image data
def crypt32(data:bytes, key_off:int=0, key:Optional[bytes]=None) -> bytes:
    """crypt32(encrypted32_bytes) -> decrypted32_bytes
    crypt32(decrypted32_bytes) -> encrypted32_bytes

    performs a reciprocal XOR cipher that encrypts or decrypts the given input data.
    """
    if key is None: key = CRYPT32_KEY
    # & 0x3ff == bitwise % 1024  (length of CRYPT32_KEY)
    return bytes(key[(key_off+i) & 0x3ff] ^ b for i,b in enumerate(data))

def crypt64(data:bytes, key_off:int=0, key:Optional[bytes]=None) -> bytes:
    """crypt64(encrypted64_bytes) -> decrypted64_bytes
    crypt64(decrypted64_bytes) -> encrypted64_bytes

    performs a reciprocal XOR cipher that encrypts or decrypts the given input data.
    """
    if key is None: key = CRYPT64_KEY
    # & 0x7ff == bitwise % 2048  (length of CRYPT64_KEY)
    return bytes(key[(key_off+i) & 0x7ff] ^ b for i,b in enumerate(data))

# XOR encryption/decryption method applied to RCT image data
# this key is found in start.mjo, as a string passed to
# the syscall `$pic_key_set@MAJIRO_INTER` (0x7a7b6ed4).
def initkey32(seed:IntBytes) -> bytes:
    """initkey32('mypassword') -> key:bytes
    initkey32(0xcb730b84) -> key:bytes

    returns an initialized key for `crypt32` by passing a password string or uint64 seed.
    """
    seed = to_hash32(seed)
    return pack('<256I', *[x^seed for x in CRC32_TABLE])

def initkey64(seed:IntBytes) -> bytes:
    """initkey64('mypassword') -> key:bytes
    initkey64(0xbcedc40d9f8ac29f) -> key:bytes

    returns an initialized key for `crypt64` by passing a password string or uint64 seed.
    """
    seed = to_hash64(seed)
    return pack('<256Q', *[x^seed for x in CRC64_TABLE])



#endregion

#region ## CRC HASH FUNCTIONS ##

# CRC-32 hash used on identifier names for lookup purposes
def hash32(text:StrBytes, value:int=0) -> int:
    """hash32('$main@GLOBAL') -> 0x1d128f30
    hash32('main@GLOBAL', 0xee010b5c) -> 0x1d128f30

    returns the CRC-32 hash of the input text data, with an optional init value.
    """
    return _crc32(to_bytes(text), value)
    ## non-zlib implementation:
    #TBL = CRC32_TABLE
    #value = ~value & 0xffffffff  # init (and mask to uint32)
    #for o in to_bytes(text):
    #    value = (value >> 8) ^ TBL[(value ^ o) & 0xff]
    #return value ^ 0xffffffff  # xorout

# incorrectly implemented CRC-64 hash used on archive filenames for lookup purposes
def hash64(text:StrBytes, value:int=0) -> int:
    """hash64('$main@GLOBAL') -> 0x9d4af639e1359980
    hash64('main@GLOBAL', 0xafdebf5dc98c3eee) -> 0x9d4af639e1359980

    returns the (incorrectly implemented) CRC-64 hash of the input text data,
    with an optional init value.
    """
    TBL = CRC64_TABLE
    value = ~value & 0xffffffffffffffff  # init (and mask to uint64)
    for o in to_bytes(text):
        value = (value >> 8) ^ TBL[(value ^ o) & 0xff]
    return value ^ 0xffffffffffffffff  # xorout

# inverse CRC-32 hash accumulator when N postfix bytes and CRC-32 result are known
def invhash32(text:StrBytes, value:int) -> int:
    """invhash32(b'@HELLO', hash32(b'$rgb@HELLO')) -> hash32(b'$rgb')

    Inverse CRC-32 operation, this can be used to find an original accumulator at (end-N) if N postfix bytes are known.
    """
    INVTBL = CRC32_INVTABLE
    value = ~value & 0xffffffff  # xorout (and mask to uint32)
    for o in reversed(to_bytes(text)):  # feed postfix text in reverse
        ##PYTHON OPTIMIZATION: INVTABLE contains uint40 that masks out value's MSbyte
        value = (value << 8) ^ INVTBL[value >> 24] ^ o
        # value = ((value & 0x00ffffff) << 8) ^ INVTBL[value >> 24] ^ o
        # idx = IDXTBL[value >> 24]
        # value = (((value ^ TBL[idx]) & 0x00ffffff) << 8) | (idx ^ o)
    return value ^ 0xffffffff  # xorout / init

# inverse CRC-32 hash accumulator when N postfix bytes and CRC-32 result are known
def _invcrc32(text:bytes, value:int) -> int:
    """invcrc32(b'@HELLO', hash32(b'$rgb@HELLO')) -> hash32(b'$rgb')

    Use this instead of `invhash32()` when it's guaranteed that: `text` is bytes.
    Inverse CRC-32 operation, this can be used to find an original accumulator at (end-N) if N postfix bytes are known.
    """
    INVTBL = CRC32_INVTABLE
    value = ~value & 0xffffffff  # xorout (and mask to uint32)
    for o in reversed(text):  # feed postfix text in reverse
        ##PYTHON OPTIMIZATION: INVTABLE contains uint40 that masks out value's MSbyte
        value = (value << 8) ^ INVTBL[value >> 24] ^ o
        # value = ((value & 0x00ffffff) << 8) ^ INVTBL[value >> 24] ^ o
    return value ^ 0xffffffff  # xorout / init

#endregion

#######################################################################################

#region ## CRC-32 PROOFS AND PARTIAL UNHASHING ##

def check_hashmid(value1:IntBytes, value2:IntBytes, diff1:StrBytes, diff2:StrBytes, max_len:int=64) -> list:
    """check_hashmid(0xf8fd08f6, 0x65f2e980, b'x', b'y') -> [13]

    finds the number of characters that appear after the specified differences.
    the lengths cannot vary between diff1 and diff2, but the beginning does not
    need to be known.
    return value can also be treated as bool, just like with `check_hashend`.

    arguments:
      value1 - hash value of name #1
      value2 - hash value of name #2
      diff1  - differences of name #1.
      diff2  - differences of name #2.
      max_len - stop scanning for matches after this length.

    returns:
      list  - list of int lengths that equal the number of characters after diff1/diff2.
      empty - no matches found for diff1 and diff2, length may be different.
    """
    if len(diff1) != len(diff2):
        raise ValueError('diff argument lengths do not match')
    init1, init2 = to_hash32(diff1), to_hash32(diff2)
    target = to_hash32(value1) ^ to_hash32(value2)
    return [i for i in range(max_len+1) if (hash32(bytes(i), init1) ^ hash32(bytes(i), init2))==target]

def check_hashbegin(value1:IntBytes, value2:IntBytes, diff1:StrBytes, diff2:StrBytes, begin:StrBytes=b'', max_len:int=64) -> list:
    """check_hashbegin(0x99a5de25, 0xeb5cc468, b'is', b'set', b'$') -> [18]

    finds the number of characters that appear after the specified differences.
    the beginning before diff1 and diff2 must also be known, but the lengths are
    allowed to vary between diff1 and diff2.
    return value can also be treated as bool, just like with `check_hashend`.

    arguments:
      value1 - hash value of name #1
      value2 - hash value of name #2
      diff1  - differences of name #1.
      diff2  - differences of name #2.
      end    - (optional) shared name beginning of both diff1 and diff2.
      max_len - stop scanning for matches after this length.

    returns:
      list  - list of int lengths that equal the number of characters after diff1/diff2.
      empty - no matches found for diff1 and diff2, length may be different.
    """
    init1, init2 = hash32(diff1, to_hash32(begin)), hash32(diff2, to_hash32(begin))
    target = to_hash32(value1) ^ to_hash32(value2)
    return [i for i in range(max_len+1) if (hash32(bytes(i), init1) ^ hash32(bytes(i), init2))==target]

def check_hashend(value1:IntBytes, value2:IntBytes, diff1:StrBytes, diff2:StrBytes, end:StrBytes=b'') -> bool:
    """check_hashend(0x2bd1709d, 0x7e0b8320, b'height', b'width', b'@MAJIRO_INTER') -> True
    check_hashend(0x2bd1709d, 0x7e0b8320, b'height@MAJIRO_INTER', b'width@MAJIRO_INTER') -> True

    confirms the difference in postfix of two hash values.
    the lengths are allowed to vary between diff1 and diff2.

    arguments:
      value1 - hash value of name #1
      value2 - hash value of name #2
      diff1  - postfix of name #1 up until there are no differences between name #2.
      diff2  - postfix of name #2 up until there are no differences between name #1.
      end    - (optional) shared name ending of both diff1 and diff2.

    returns:
      True  - the unhashed names must have identical prefixes and the specified postfixes.
      False - the unhashed names either have different prefixes or do not have the specified postfixes.
    """
    init1, init2 = invhash32(end, to_hash32(value1)), invhash32(end, to_hash32(value2))
    return invhash32(diff1, init1) == invhash32(diff2, init2)

def check_hashdiffs(value1A:IntBytes, value2A:IntBytes, value1B:IntBytes, value2B:IntBytes) -> bool:
    """check_hashdiffs(0xf8fd08f6, 0x65f2e980, 0x539b07bc, 0xce94e6ca) -> True

    comfirms if two hash pairs A and B share the same differences.
    use when the differences are not known.

    returns:
      True  - these two hash pairs A and B share the same differences.
      False - these two hash pairs do not share the same differences.
    """
    return (to_hash32(value1A) ^ to_hash32(value2A)) == (to_hash32(value1B) ^ to_hash32(value2B))

#endregion

#region ## CRC-32 BACKOUT UNHASHING ##

def backout_indices(init:IntBytes, count:int) -> List[int]:
    """backout_indices(hash32(b'$rgb'), 3) -> [0xd1, 0xd1, 0x3c]

    the returned indices are equal to (least-significant accumulator byte XOR the input byte) each iteration.
    this accumulator is not equal to the one input in the arguments, but the one present at that iteration in the operation.
    """
    if not (1 <= count <= 4):
        raise ValueError(f'argument count must be between 1 and 4, not {count}')
    TBL, IDXTBL = CRC32_TABLE, CRC32_INDEX
    # back out up to 4 indices:
    crc = to_hash32(init) ^ 0xffffffff  # xorout
    indices = []
    for _ in range(count):
        idx = IDXTBL[crc >> 24]
        # every iteration we lose another least-significant byte of known data:
        #NOTE: (crc ^ y) MUST ALWAYS result in 00XXXXXX
        #  (this is a property of the CRC32_INDEX lookup table)
        #  (the mask is kept for documentation, and in case of any unexpected behavior)
        crc = (((crc ^ TBL[idx]) & 0x00ffffff) << 8) | idx
        indices.insert(0, idx)
    
    return indices

def backout_data(init:IntBytes, orig_init:IntBytes, count:int) -> bytes:
    """backout_data(hash32(b'$rgb'), hash32(b'$'), 3) -> b'rgb'

    back out count (1 to 4) known bytes from the result of a CRC-32 operation.
    """
    # back out up to 4 indices:
    indices = backout_indices(init, count)
    TBL=CRC32_TABLE
    # forward crc for init to get data from indices:
    crc = to_hash32(orig_init) ^ 0xffffffff  # xorout
    data = bytearray()
    for idx in indices:
        data.append((crc ^ idx) & 0xff)       # chr == (crc ^ idx) & 0xff
        crc = (crc >> idx) ^ TBL[idx] # idx == (crc ^ chr) & 0xff

    crc ^= 0xffffffff  # xorout or init??
    if crc != to_hash32(init):
        #NOTE: if count==4, then it's impossible for this Exception to raise, as there
        #       is ALWAYS a combination to turn one init into another with 4 bytes,
        #       however with 3 or less bytes, it's impossible(?) to find a second collision(?)
        #       [TODO: confirm]
        raise Exception(f'final accumulator 0x{to_hash32(init):08x} does not match expected output accumulator 0x{crc:08x}')
    
    return bytes(data)

#endregion


#######################################################################################

del List, Optional, Tuple, Union  # cleanup declaration-only imports
