#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro encryption and hashing utils
"""

__version__ = '1.0.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['crypt32', 'crypt64', 'hash32', 'hash64']

# <https://en.wikipedia.org/wiki/Cyclic_redundancy_check>
# <https://users.ece.cmu.edu/~koopman/crc/crc32.html>
# <https://users.ece.cmu.edu/~koopman/crc/crc64.html>

#######################################################################################

from zlib import crc32 as _crc32
from struct import pack
from typing import Union


## standard CRC-32 (table calculation) used by zlib
def _calc32(num:int) -> int:
    POLY = 0xEDB88320  # reversed polynomial
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ POLY
        else:         num >>= 1
    return num
## NON-STANDARD CRC-64! (table calculation)
# by mistake it seems the forward polynomial was used for the reverse calculation
def _calc64(num:int) -> int:
    POLY = 0x42F0E1EBA9EA3693  # forward polynomial (should have been 0xC96C5795D7870F42)
    for _ in range(8):
        if num & 0x1: num = (num >> 1) ^ POLY
        else:         num >>= 1
    return num


CRC32_TABLE:list  = tuple(_calc32(n) for n in range(256))
CRC64_TABLE:list  = tuple(_calc64(n) for n in range(256))
# 1024-byte Majiro script XOR decryption key (standard CRC-32 table output in little-endian)
CRYPT32_KEY:bytes = pack('<256I', *CRC32_TABLE)
# 2048-byte Majiro script XOR decryption key (broken Majiro CRC-64 table output in little-endian)
CRYPT64_KEY:bytes = pack('<256Q', *CRC64_TABLE)


# XOR encryption/decryption method applied to b"MajiroObjX1.000\x00" bytecode
def crypt32(data:bytes, key_offset:int=0) -> bytes:
    K = CRYPT32_KEY
    # & 0x3ff == bitwise % 1024  (length of CRYPT32_KEY)
    return bytes(K[(key_offset+i) & 0x3ff] ^ b for i,b in enumerate(data))

def crypt64(data:bytes, key_offset:int=0) -> bytes:
    K = CRYPT64_KEY
    # & 0x7ff == bitwise % 2048  (length of CRYPT64_KEY)
    return bytes(K[(key_offset+i) & 0x7ff] ^ b for i,b in enumerate(data))

# CRC-32 hash used on identifier names for lookup purposes
def hash32(text:Union[bytes,str]) -> int:
    if isinstance(text, str): text = text.encode('cp932')
    return _crc32(text)

# incorrectly implemented CRC-64 hash used on archive filenames for lookup purposes
def hash64(text:Union[bytes,str]) -> int:
    if isinstance(text, str): text = text.encode('cp932')
    crc = 0xffffffffffffffff
    for b in text:
        crc = (crc >> 8) ^ CRC64_TABLE[(crc ^ b) & 0xff]
    return crc ^ 0xffffffffffffffff


del pack, Union  # cleanup declaration-only imports
