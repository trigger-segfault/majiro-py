#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro encryption and hashing utils
"""

__version__ = '1.1.1'
__date__    = '2021-05-07'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['crypt32', 'crypt64', 'hash32', 'hash64', 'invhash32', 'find_hashlen', 'check_hashend', 'check_hashdiffs']

# <https://en.wikipedia.org/wiki/Cyclic_redundancy_check>
# <https://users.ece.cmu.edu/~koopman/crc/crc32.html>
# <https://users.ece.cmu.edu/~koopman/crc/crc64.html>
# <https://en.wikipedia.org/wiki/Symmetric-key_algorithm#Reciprocal_cipher>

#######################################################################################

from struct import pack
from typing import Union
from zlib import crc32 as _crc32
from .util.typecast import to_bytes, unsigned_I, unsigned_Q


#region ## TYPEDEFS AND HELPERS ##

StrBytes = Union[str,bytes]
IntBytes = Union[int,str,bytes]

# def to_bytes(text:StrBytes) -> bytes:
#     """to_bytes(bytes) -> bytes
#     to_bytes(str) -> str.encode('cp932')

#     helper function to allow passing str or bytes.
#     """
#     return text.encode('cp932') if isinstance(text, str) else text

def to_hash32(value:IntBytes) -> int:
    """to_hash32(bytes) -> hash32(bytes)
    to_hash32(str)   -> hash32(str)
    to_hash32(int)   -> unsigned_I(int)

    helper function to allow passing a hash name or value.
    """
    return unsigned_I(value) if isinstance(value, int) else hash32(value)

def to_hash64(value:IntBytes) -> int:
    """to_hash64(bytes) -> hash64(bytes)
    to_hash64(str)   -> hash64(str)
    to_hash64(int)   -> unsigned_Q(int)

    helper function to allow passing a hash name or value.
    """
    return unsigned_Q(value) if isinstance(value, int) else hash64(value)

#endregion

#######################################################################################

#region ## CRC TABLE SETUP FUNCTIONS ##

## standard CRC-32 (table calculation) used by zlib
def _calc32(num:int) -> int:
    POLY = 0xEDB88320  # reversed polynomial
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ POLY
        else:         num >>= 1
    return num

## NON-STANDARD CRC-64! (table calculation)
#NOTE: in asm, this uses the poly: 0x85E1C3D753D46D27, and bitshifts after XOR with poly
# behavior is identical to normal reverse CRC-64 implementation with common poly: 0x42F0E1EBA9EA3693
# (by mistake it seems the forward polynomial was used for the reverse CRC-64 implementation)
def _calc64(num:int) -> int:
    POLY = 0x42F0E1EBA9EA3693  # forward polynomial (should have been 0xC96C5795D7870F42)
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ POLY
        else:         num >>= 1
    return num

## inverse for CRC-32 (find index of most significant byte in table)
def _invcalc32(num:int) -> int:
    """_invcalc32(_calc32(0xd7)) -> 0xd7
    finds the index of the most significant byte in the CRC32_TABLE
    """
    for i in range(256):
        if (_calc32(i) >> 24) == num:
            return i
    raise ValueError(f'0x{num:02x} not found in CRC32_TABLE')

#endregion

#region ## CRC TABLES ##

CRC32_TABLE:list  = tuple(_calc32(n) for n in range(256))
CRC32_INDEX:list  = tuple(_invcalc32(n) for n in range(256))
CRC64_TABLE:list  = tuple(_calc64(n) for n in range(256))
# 1024-byte Majiro script XOR decryption key (standard CRC-32 table output in little-endian)
CRYPT32_KEY:bytes = pack('<256I', *CRC32_TABLE)
# 2048-byte Majiro script XOR decryption key (broken Majiro CRC-64 table output in little-endian)
CRYPT64_KEY:bytes = pack('<256Q', *CRC64_TABLE)

#endregion

#region ## CRC XOR CIPHER FUNCTIONS ##

# XOR encryption/decryption method applied to b"MajiroObjX1.000\x00" bytecode
def crypt32(data:bytes, key_off:int=0, key:bytes=CRYPT32_KEY) -> bytes:
    """crypt32(encrypted32_bytes) -> decrypted32_bytes
    crypt32(decrypted32_bytes) -> encrypted32_bytes

    performs a reciprocal XOR cipher that encrypts or decrypts the given input data.
    """
    # & 0x3ff == bitwise % 1024  (length of CRYPT32_KEY)
    return bytes(key[(key_off+i) & 0x3ff] ^ b for i,b in enumerate(data))

def crypt64(data:bytes, key_off:int=0, key:bytes=CRYPT64_KEY) -> bytes:
    """crypt64(encrypted64_bytes) -> decrypted64_bytes
    crypt64(decrypted64_bytes) -> encrypted64_bytes

    performs a reciprocal XOR cipher that encrypts or decrypts the given input data.
    """
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
def hash32(text:StrBytes, init:int=0) -> int:
    """hash32('$main@GLOBAL') -> 0x1d128f30
    hash32('main@GLOBAL', 0xee010b5c) -> 0x1d128f30

    returns the CRC-32 hash of the input text data, with an optional init value.
    """
    return _crc32(to_bytes(text), unsigned_I(0 if init is None else init))
    ## non-zlib implementation:
    #crc = unsigned_I(init) ^ 0xffffffff
    #for b in to_bytes(text):
    #    crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ b) & 0xff]
    #return crc ^ 0xffffffff

# incorrectly implemented CRC-64 hash used on archive filenames for lookup purposes
def hash64(text:StrBytes, init:int=0) -> int:
    """hash64('$main@GLOBAL') -> 0x9d4af639e1359980
    hash64('main@GLOBAL', 0xafdebf5dc98c3eee) -> 0x9d4af639e1359980

    returns the (incorrectly implemented) CRC-64 hash of the input text data,
    with an optional init value.
    """
    crc = unsigned_Q(0 if init is None else init) ^ 0xffffffffffffffff
    for b in to_bytes(text):
        crc = (crc >> 8) ^ CRC64_TABLE[(crc ^ b) & 0xff]
    return crc ^ 0xffffffffffffffff

# inverse CRC-32 hash accumulator when N postfix bytes and CRC-32 result are known
def invhash32(text:StrBytes, init:int) -> int:
    """invhash32(b'@HELLO', hash32(b'$rgb@HELLO')) -> hash32(b'$rgb')

    inverse CRC-32 operation, this can be used to find an original accumulator at (end-N) if N postfix bytes are known.
    """
    crc = unsigned_I(init) ^ 0xffffffff  # xorout
    for o in reversed(to_bytes(text)):  # feed postfix text in reverse
        idx = CRC32_INDEX[crc >> 24]
        crc = (((crc ^ CRC32_TABLE[idx]) & 0x00ffffff) << 8) | (idx ^ o)
    return crc ^ 0xffffffff  # xorout or init??

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
    init1, init2 = hash32(diff1), hash32(diff2)
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
    init1, init2 = hash32(diff1, hash32(begin)), hash32(diff2, hash32(begin))
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

def backout_indices(init:IntBytes, count:int) -> list:
    """backout_indices(hash32(b'$rgb'), 3) -> [0xd1, 0xd1, 0x3c]

    the returned indices are equal to (least-significant accumulator byte XOR the input byte) each iteration.
    this accumulator is not equal to the one input in the arguments, but the one present at that iteration in the operation.
    """
    if not (1 <= count <= 4):
        raise ValueError(f'argument count must be between 1 and 4, not {count}')
    # back out up to 4 indices:
    crc = to_hash32(init) ^ 0xffffffff  # xorout
    indices = []
    for _ in range(count):
        idx = CRC32_INDEX[crc >> 24]
        # every iteration we lose another least-significant byte of known data:
        #NOTE: (crc ^ y) MUST ALWAYS result in 00XXXXXX
        #  (this is a property of the CRC32_INDEX lookup table)
        #  (the mask is kept for documentation, and in case of any unexpected behavior)
        crc = (((crc ^ CRC32_TABLE[idx]) & 0x00ffffff) << 8) | idx
        indices.insert(0, idx)
    
    return indices

def backout_data(init:IntBytes, orig_init:IntBytes, count:int) -> bytes:
    """backout_data(hash32(b'$rgb'), hash32(b'$'), 3) -> b'rgb'

    back out count (1 to 4) known bytes from the result of a CRC-32 operation.
    """
    # back out up to 4 indices:
    indices:list = backout_indices(init, count)
    
    # forward crc for init to get data from indices:
    crc = to_hash32(orig_init) ^ 0xffffffff  # xorout
    data = bytearray()
    for idx in indices:
        data.append((crc ^ idx) & 0xff)       # chr == (crc ^ idx) & 0xff
        crc = (crc >> idx) ^ CRC32_TABLE[idx] # idx == (crc ^ chr) & 0xff

    crc ^= 0xffffffff  # xorout or init??
    if crc != to_hash32(init):
        #NOTE: if count==4, then it's impossible for this Exception to raise, as there
        #       is ALWAYS a combination to turn one init into another with 4 bytes,
        #       however with 3 or less bytes, it's impossible(?) to find a second collision(?)
        #       [TODO: confirm]
        raise Exception(f'final accumulator 0x{to_hash32(init):08x} does not match expected output accumulator 0x{crc:08x}')
    
    return bytes(data)

#endregion


del Union  # cleanup declaration-only imports
# del pack, Union  # cleanup declaration-only imports
