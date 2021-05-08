#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Type-casting and ensuring functions
"""

__version__ = '0.1.0'
__date__    = '2021-05-06'
__author__  = 'Robert Jordan'

__all__ = ['to_bytes', 'to_str', 'to_float', 'signed_b', 'signed_h', 'signed_i', 'signed_q', 'unsigned_B', 'unsigned_H', 'unsigned_I', 'unsigned_Q']

#######################################################################################

from struct import pack, unpack
from typing import Union


#region ## STRING / BYTES HELPERS ##

def to_bytes(text:Union[bytes,str]) -> bytes:
    """to_bytes(bytes) -> bytes
    to_bytes(str) -> str.encode('cp932')

    helper function to allow passing bytes or str.
    """
    return text.encode('cp932') if isinstance(text, str) else text


def to_str(text:Union[str,bytes]) -> str:
    """to_str(str) -> str
    to_str(bytes) -> bytes.decode('cp932')

    helper function to allow passing str or bytes.
    """
    return text.decode('cp932') if isinstance(text, bytes) else text

#endregion

#region ## FLOAT HELPERS ##

def to_float(num:Union[float,int]) -> float:
    """to_float(float) -> float
    to_float(int) -> float(int)

    helper function to allow passing float or int.
    """
    return float(num) if isinstance(num, int) else num

#endregion

#region ## INT SIGNEDNESS HELPERS ##

def signed_b(num:int) -> int:
    """Return signed value of unsigned (or signed) 8-bit integer (struct fmt 'b')
    also performs bounds checking
    """
    if num > 0x7f: # greater than SCHAR_MAX
        return unpack('=b', pack('=B', num))[0]
    else: # lazy limits bounds checking
        return unpack('=b', pack('=b', num))[0]

def unsigned_B(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 8-bit integer (struct fmt 'B')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=B', pack('=b', num))[0]
    else: # lazy limits bounds checking
        return unpack('=B', pack('=B', num))[0]

def signed_h(num:int) -> int:
    """Return signed value of unsigned (or signed) 16-bit integer (struct fmt 'h')
    also performs bounds checking
    """
    if num > 0x7fff: # greater than SHRT_MAX
        return unpack('=h', pack('=H', num))[0]
    else: # lazy limits bounds checking
        return unpack('=h', pack('=h', num))[0]

def unsigned_H(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 16-bit integer (struct fmt 'H')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=H', pack('=h', num))[0]
    else: # lazy limits bounds checking
        return unpack('=H', pack('=H', num))[0]

def signed_i(num:int) -> int:
    """Return signed value of unsigned (or signed) 32-bit integer (struct fmt 'i')
    also performs bounds checking
    """
    if num > 0x7fffffff: # greater than INT_MAX
        return unpack('=i', pack('=I', num))[0]
    else: # lazy limits bounds checking
        return unpack('=i', pack('=i', num))[0]

def unsigned_I(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 32-bit integer (struct fmt 'I')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=I', pack('=i', num))[0]
    else: # lazy limits bounds checking
        return unpack('=I', pack('=I', num))[0]

def signed_q(num:int) -> int:
    """Return signed value of unsigned (or signed) 64-bit integer (struct fmt 'q')
    also performs bounds checking
    """
    if num > 0x7fffffffffffffff: # greater than LLONG_MAX
        return unpack('=q', pack('=Q', num))[0]
    else: # lazy limits bounds checking
        return unpack('=q', pack('=q', num))[0]

def unsigned_Q(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 64-bit integer (struct fmt 'Q')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=Q', pack('=q', num))[0]
    else: # lazy limits bounds checking
        return unpack('=Q', pack('=Q', num))[0]

#endregion


del Union  # cleanup declaration-only imports
