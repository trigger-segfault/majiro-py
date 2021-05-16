#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-15'
__author__  = 'Robert Jordan'
__credits__ = '''Port of morkt/GARbro's ImageRC8 and ImageRCT'''

__all__ = ['RctImage', 'Rc8Image']

#######################################################################################

## runtime imports:
# from ..crypt import initkey32, crypt32  # used by RctImage.read_pixels when encrypted

import enum, io, os, shutil, threading
from collections import namedtuple
from struct import calcsize, pack, unpack, iter_unpack, unpack_from, pack_into, Struct
from typing import Any, Callable, Iterable, Iterator, List, NoReturn, Optional, Dict, Tuple, Union



#######################################################################################

#region ## ALL MAJIRO FILE SIGNATURES ##

assert(b'\x98\x5a\x92\x9a'.decode('cp932') == '六丁')
# "Rokucho"
RCT_SIGNATURES:dict = {
    b'\x98\x5a\x92\x9aTC00': (0, False), # version 0, decrypted
    b'\x98\x5a\x92\x9aTS00': (0, True),  # version 0, encrypted
    b'\x98\x5a\x92\x9aTC01': (1, False), # version 1, decrypted
    b'\x98\x5a\x92\x9aTS01': (1, True),  # version 1, encrypted
}
RC8_SIGNATURES:dict = {
    b'\x98\x5a\x92\x9a8_00': (0, False), # version 0, decrypted
}
MJO_SIGNATURES:dict = {
    b'MajiroObjV1.000\x00': (1, False), # version 1, decrypted
    b'MajiroObjX1.000\x00': (1, True),  # version 1, encrypted
}
ARC_SIGNATURES:dict = {
    b'MajiroArcV1.000\x00': (1, False), # version 1, decrypted
    b'MajiroArcV2.000\x00': (2, False), # version 2, decrypted
    b'MajiroArcV3.000\x00': (3, False), # version 3, decrypted
}

#endregion

#region ## SHIFT TABLES ANALYSIS ##

# values analysis to understand purpose of shift table
# [values in brackets] only appear in RCT format,
# whiel values outside appear in both.
VALS = (
    None,None,None,None, -16, -32, -48, -64,[-80, -96],
      49,  33,  17,   1, -15, -31, -47, None,None,None,
    [ 50], 34,  18,   2, -14, -30,[-46],None,None,None,
    [ 51,  35,  19,   3, -13, -29, -45],None,None,None,
    None,[ 36,  20,   4, -12, -28],None,None,None,None,
)

def splitvals(vals) -> list:
    from itertools import chain
    return tuple(chain(*[([[v] for v in val] if isinstance(val,list) else [val]) for val in vals]))

def showvals(width=10, vals=VALS, fmt:str=' {:08b}', neg:bool=False, join:bool=True):
    def fmtval(v:int) -> str:
        if v is None: return ' '*len(fmt.format(0))
        return fmt.format(v if neg else (v&0xff))
    #
    i, last_opt = 0, False
    for val in splitvals(vals):
        if (i%width)==0: # start of new row
            print(']' if last_opt else '', end='\n' if i else '')
            last_opt = False
        if isinstance(val, list): # print RCT-exclusive (increment list)
            print((' ' if join else '|') if last_opt else '[', ', '.join(fmtval(v) for v in val), ',', sep='',end='')
            i += len(val)
        else:
            print(']' if last_opt else ' ', fmtval(val), ' ' if val is None else ',', sep='',end='')
            i += 1
        last_opt = isinstance(val, list)
    print()

"""
showvals()
showvals(fmt='{: 3d}',neg=True)
"""

#endregion

#region ## SHIFT TABLES ##

RC8_SHIFT_TABLE:List[int] = (
    -16, -32, -48, -64,
    49, 33, 17, 1, -15, -31, -47,
    34, 18, 2, -14, -30,
)
RCT_SHIFT_TABLE:List[int] = (
    -16, -32, -48, -64, -80, -96,
    49, 33, 17, 1, -15, -31, -47,
    50, 34, 18, 2, -14, -30, -46,
    51, 35, 19, 3, -13, -29, -45,
    36, 20, 4, -12, -28,
)

def _calc_shift(width:int, shift:int) -> int:
    shift_row = (shift & 0x0f)
    return (shift >> 4) - (shift_row * width)
    # shift >>= 4
    # shift_row *= width
    # shift -= (shift_row * width)

def init_shift_table(width:int, base_table:List[int]) -> List[int]:
    return tuple(_calc_shift(width, shift) for shift in base_table)

#endregion

#######################################################################################

#region ## BITMAP STRUCTS AND ENUMS ##

# LCS Color space
class LogicalColorSpace(enum.IntEnum):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/eb4bbd50-b3ce-4917-895c-be31f214797f>
    """
    LCS_CALIBRATED_RGB = 0x00000000
    LCS_sRGB = 0x73524742
    LCS_WINDOWS_COLOR_SPACE = 0x57696E20

class LogicalColorSpaceV5(enum.IntEnum):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/3c289fe1-c42e-42f6-b125-4b5fc49a2b20>
    """
    LCS_CALIBRATED_RGB = 0x00000000
    LCS_sRGB = 0x73524742
    LCS_WINDOWS_COLOR_SPACE = 0x57696E20
    LCS_PROFILE_LINKED = 0x4C494E4B
    LCS_PROFILE_EMBEDDED = 0x4D424544

class Compression(enum.IntEnum):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/4e588f70-bd92-4a6f-b77f-35d0feaf7a57>
    """
    BI_RGB = 0x0000
    BI_RLE8 = 0x0001
    BI_RLE4 = 0x0002
    BI_BITFIELDS = 0x0003
    BI_JPEG = 0x0004
    BI_PNG = 0x0005
    BI_CMYK = 0x000B
    BI_CMYKRLE8 = 0x000C
    BI_CMYKRLE4 = 0x000D

class ColorUsage(enum.IntEnum):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/30403797-a408-40ca-b024-dd8a1acb39be>
    """
    DIB_RGB_COLORS = 0x0000
    DIB_PAL_COLORS = 0x0001
    DIB_PAL_INDICES = 0x0002

class BinaryRasterOperation(enum.IntEnum):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/781a06bd-af9b-48b7-8e7d-d922de0f9c26>
    """
    R2_BLACK = 0x0001
    R2_NOTMERGEPEN = 0x0002
    R2_MASKNOTPEN = 0x0003
    R2_NOTCOPYPEN = 0x0004
    R2_MASKPENNOT = 0x0005
    R2_NOT = 0x0006
    R2_XORPEN = 0x0007
    R2_NOTMASKPEN = 0x0008
    R2_MASKPEN = 0x0009
    R2_NOTXORPEN = 0x000A
    R2_NOP = 0x000B
    R2_MERGENOTPEN = 0x000C
    R2_COPYPEN = 0x000D
    R2_MERGEPENNOT = 0x000E
    R2_MERGEPEN = 0x000F
    R2_WHITE = 0x0010

class BitCount(enum.IntFlag):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/792153f4-1e99-4ec8-93cf-d171a5f33903>
    """
    BI_BITCOUNT_0 = 0x0000
    BI_BITCOUNT_1 = 0x0001
    BI_BITCOUNT_2 = 0x0004
    BI_BITCOUNT_3 = 0x0008
    BI_BITCOUNT_4 = 0x0010
    BI_BITCOUNT_5 = 0x0018
    BI_BITCOUNT_6 = 0x0020

class GamutMappingIntent(enum.IntFlag):
    """source: <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/9fec0834-607d-427d-abd5-ab240fb0db38>
    """
    LCS_GM_ABS_COLORIMETRIC = 0x00000008
    LCS_GM_BUSINESS = 0x00000001
    LCS_GM_GRAPHICS = 0x00000002
    LCS_GM_IMAGES = 0x00000004


class CIEXYZ(namedtuple('_CIEXYZ', ('x', 'y', 'z'))):
    _struct_ = Struct('<III')
    def __new__(cls, x:int=..., y:int=..., z:int=...):
        num_args = sum(a is not Ellipsis for a in (x,y,z))
        if num_args == 0:
            x = y = z = 0
        elif num_args != len(cls._fields):
            raise TypeError('__new__() requires 0 or 3 arguments, not {num_args}')
        return super().__new__(cls, x, y, z)
    @classmethod
    def unpack(cls, buffer:bytes) -> 'CIEXYZ': return cls(*cls._struct_.unpack(buffer))
    @classmethod
    def unpack_from(cls, buffer:bytes, offset:int=0) -> 'CIEXYZ': return cls(*cls._struct_.unpack_from(buffer, offset))
    @classmethod
    def iter_unpack(cls, buffer:bytes) -> Iterator['CIEXYZ']: return iter((cls(*v) for v in cls._struct_.iter_unpack(buffer)))
    def pack(self) -> bytes: return self._struct_.pack(*self)
    def pack_into(self, buffer:bytearray, offset:int): self._struct_.pack_into(buffer, offset, *self)
    @classmethod
    def calcsize(cls) -> int: return cls._struct_.size

class CIEXYZTRIPLE(namedtuple('_CIEXYZTRIPLE', ('red', 'green', 'blue'))):
    _struct_ = Struct('<III III III')
    def __new__(cls, red:CIEXYZ=..., green:CIEXYZ=..., blue:CIEXYZ=...):
        num_args = sum(a is not Ellipsis for a in (red,green,blue))
        if num_args == 0:
            red = green = blue = CIEXYZ()
        elif num_args != len(cls._fields):
            raise TypeError('__new__() requires 0 or 3 arguments, not {num_args}')
        return super().__new__(cls, red, green, blue)
    @classmethod
    def unpack(cls, buffer:bytes) -> 'CIEXYZTRIPLE':
        return cls(*CIEXYZ.iter_unpack(buffer))
    @classmethod
    def unpack_from(cls, buffer:bytes, offset:int=0) -> 'CIEXYZTRIPLE':
        return cls(*CIEXYZ.iter_unpack(buffer[offset:offset+cls._struct_.size]))
    def pack(self) -> bytes: return self._struct_.pack(*self.red, *self.green, *self.blue)
    def pack_into(self, buffer:bytearray, offset:int): self._struct_.pack_into(buffer, offset, *self.red, *self.green, *self.blue)
    @classmethod
    def calcsize(cls) -> int: return cls._struct_.size


class BITMAPV5HEADER:
    __slots__ = ('size', 'width', 'height', 'planes', 'bitCount', 'compression', 'sizeImage', 'xPelsPerMeter', 'yPelsPerMeter', 'clrUsed', 'clrImportant', 'redMask', 'greenMask', 'blueMask', 'alphaMask', 'csType', 'endpoints', 'gammaRed', 'gammaGreen', 'gammaBlue', 'intent', 'profileData', 'profileSize', 'reserved')
    _struct_ = Struct('<I ii HH I iii II IIII I  IIIIIIIII  III I II  I')
    def __init__(self, size:int=124, width:int=0, height:int=0, planes:int=1, bitCount:int=0, compression:int=0, sizeImage:int=0, xPelsPerMeter:int=96, yPelsPerMeter:int=96, clrUsed:int=0, clrImportant:int=0, redMask:int=0, greenMask:int=0, blueMask:int=0, alphaMask:int=0, csType:int=0, endpoints:CIEXYZTRIPLE=CIEXYZTRIPLE(), gammaRed:int=0, gammaGreen:int=0, gammaBlue:int=0, intent:int=0, profileData:int=0, profileSize:int=0, reserved:int=0):
        for k,v in zip(self.__slots__, (size, width, height, planes, bitCount, compression, sizeImage, xPelsPerMeter, yPelsPerMeter, clrUsed, clrImportant, redMask, greenMask, blueMask, alphaMask, csType, endpoints, gammaRed, gammaGreen, gammaBlue, intent, profileData, profileSize, reserved)):
            setattr(self, k, v)
    def __iter__(self):
        return iter((getattr(self, s) for s in self.__slots__))
    def pack(self) -> bytes:
        from itertools import chain
        return self._struct_.pack(*chain(*[[int(v)] if not isinstance(v, CIEXYZTRIPLE) else chain(*v) for v in self]))
    @classmethod
    def calcsize(cls) -> int: return cls._struct_.size

class BITMAPINFOHEADER:
    __slots__ = ('size', 'width', 'height', 'planes', 'bitCount', 'compression', 'sizeImage', 'xPelsPerMeter', 'yPelsPerMeter', 'clrUsed', 'clrImportant')
    _struct_ = Struct('<I ii HH I iii II')
    def __init__(self, size:int=40, width:int=0, height:int=0, planes:int=1, bitCount:int=0, compression:int=0, sizeImage:int=0, xPelsPerMeter:int=96, yPelsPerMeter:int=96, clrUsed:int=0, clrImportant:int=0):
        for k,v in zip(self.__slots__, (size, width, height, planes, bitCount, compression, sizeImage, xPelsPerMeter, yPelsPerMeter, clrUsed, clrImportant)):
            setattr(self, k, v)
    #
    def __iter__(self):
        return iter((getattr(self, s) for s in self.__slots__))
    def pack(self) -> bytes: return self._struct_.pack(*self)
    @classmethod
    def calcsize(cls) -> int: return cls._struct_.size

class BITMAPFILEHEADER:
    __slots__ = ('signature', 'fileSize', 'reserved1', 'reserved2', 'pixelOffset')
    _struct_ = Struct('<2s I HH I')
    def __init__(self, signature:bytes=b'BM', fileSize:int=0, reserved1:int=0, reserved2:int=0, pixelOffset:int=0):
        for k,v in zip(self.__slots__, (signature, fileSize, reserved1, reserved2, pixelOffset)):
            setattr(self, k, v)
    #
    def __iter__(self):
        return iter((getattr(self, s) for s in self.__slots__))
    def pack(self) -> bytes: return self._struct_.pack(*self)
    @classmethod
    def calcsize(cls) -> int: return cls._struct_.size

#endregion

#######################################################################################

#region ## UTILITY METHODS ##

def copy_overlapped(buffer:bytearray, src:int, dst:int, count:int):
    """source: <https://github.com/morkt/GARbro/blob/c5e13f6db1d24a62eb621c38c6fc31387338d857/GameRes/Utility.cs#L80>
    """
    if dst > src:
        while count > 0:
            preceding = min(dst - src, count)
            buffer[dst:dst+preceding] = buffer[src:src+preceding]
            dst += preceding
            count -= preceding
    else:
        buffer[dst:dst+count] = buffer[src:src+count]

#endregion

#######################################################################################

#region ## ROKUCHO IMAGE TYPES ##

class RctImage:
    """source: <https://github.com/morkt/GARbro/blob/master/ArcFormats/Majiro/ImageRCT.cs>
    """
    def __init__(self, width:int, height:int, basename:str=None, pixels:bytes=None):
        self.version = 0
        self.encrypted = False
        self.width = width
        self.height = height
        self.datasize = 0
        self.pixels = pixels
        self.basename_len = 0
        self.basename = basename

    #region ## ROKUCHO READING ##

    def load(self, reader:io.BufferedReader, key:str=None):
        if isinstance(reader, str):
            with open(reader, 'rb') as file:
                return self.load(file)
        self.read_header(reader)
        self.read_basename(reader)
        print(self.version, self.encrypted, self.basename)
        if (self.encrypted and key is None) or self.basename:
            return 
        self.read_pixels(reader, key)
        return True

    def read_header(self, reader:io.BufferedReader) -> Tuple[int, int]:
        reader.seek(0)
        signature, self.width, self.height, self.datasize = unpack('<8sIII', reader.read(20))
        self.version, self.encrypted = RCT_SIGNATURES[signature]
        if self.version == 1:
            self.basename_len = unpack('<H', reader.read(2))[0]
        else:
            self.basename_len = 0

    def read_basename(self, reader:io.BufferedReader) -> List[bytes]:
        reader.seek(20)
        if self.basename_len:
            self.basename = reader.read(self.basename_len).rstrip(b'\x00').decode('cp932')
        else:
            self.basename = None

    def read_pixels(self, reader:io.BufferedReader, key:str):
        print(self.width, self.height, self.version, self.encrypted, self.basename)

        reader.seek(20 + ((2 + self.basename_len) if self.version==1 else 0))
        if self.encrypted:
            if key is None: raise ValueError('A password is needed')
            from ..crypt import initkey32, crypt32
            key = initkey32(key)
            reader = io.BytesIO(crypt32(reader.read(self.datasize), 0, key=key))

        shift_tbl = init_shift_table(self.width, RCT_SHIFT_TABLE)

        # start by reading one pixel
        buffer = bytearray(self.width * self.height * 3)
        buffer[0:3] = reader.read(3)
        left = len(buffer) - 3
        pos = 3

        while left > 0:
            ### CMD: <F NNNNN nn>
            cmd = reader.read(1)[0]

            if not (cmd & 0x80):###############################################
                ## READ: <0  nnnnnnn> [eeeeeeeeeeeeeeee]
                #         |  \_____|   |
                #  read flg        |---extra (if num == 0x7f)
                # read count: 3 + (num (0-0x7f) + [extra (0-0xffff)]) * 3
                ###############################################################
                n = cmd
                if n == 0x7f:  # add extra count?
                    n += unpack('<H', reader.read(2))[0]
                n = n*3 + 3  # read count is always a minimum of 3

                assert(n <= left)  # bounds check: dst data
                buffer[pos:pos+n] = reader.read(n)

            else:##############################################################
                ## COPY: <1 sssss nn> [eeeeeeeeeeeeeeee]
                #         | \___/ \|   |
                #  copy flg    |   |---extra (if num == 0x3)
                #    shift index   |
                # copy count: 3 + (num (0-0x3) + [extra (0-0xffff)]) * 3
                ###############################################################
                n = cmd & 0x3
                if n == 0x3:  # add extra count?
                    n += unpack('<H', reader.read(2))[0]
                n = n*3 + 3  # copy count is always a minimum of 3

                # shift determines where data is copied from (always negative)
                s = shift_tbl[(cmd>>2) & 0x1f] * 3

                assert(n <= left)             # bounds check: dst data
                assert(s < 0 and pos+s >= 0)  # bounds check: copy data
                copy_overlapped(buffer, pos+s, pos, n)

            left -= n
            pos += n

        self.pixels = bytes(buffer)

    #endregion

    #region ## PROPERTIES ##

    @property
    def size(self) -> Tuple[int, int]: return (self.width, self.height)
    @size.setter
    def size(self, value:Tuple[int, int]): self.width, self.height = value

    @property
    def planes(self) -> int: return 1
    @property
    def bpp(self) -> int: return 24
    @property
    def raw_stride(self) -> int: return (self.width * self.bpp + 7) // 8
    @property
    def stride(self) -> int: return ((self.width * self.bpp + 7) // 8 + 3) & ~0x3
    @property
    def raw_buffersize(self) -> int: return (self.raw_stride * self.height)
    @property
    def buffersize(self) -> int: return (self.stride * self.height)
    @property
    def compression(self) -> Compression: return Compression.BI_RGB

    #endregion

    #region ## BITMAP WRITING ##

    def save_bmp(self, writer:io.BufferedWriter):
        if isinstance(writer, str):
            with open(writer, 'wb+') as file:
                return self.save_bmp(file)

        header_size = BITMAPFILEHEADER.calcsize() # 14
        info_size = BITMAPINFOHEADER.calcsize() # 40

        palette_size = 0x0

        data_offset = header_size + info_size + palette_size
        file_size = data_offset + self.buffersize

        writer.seek(0)
        writer.write(BITMAPFILEHEADER(fileSize=file_size, pixelOffset=data_offset).pack())

        writer.write(BITMAPINFOHEADER(
            width=self.width,   height=self.height,
            planes=self.planes, bitCount=self.bpp,
            xPelsPerMeter=3780, yPelsPerMeter=3780,
            compression=self.compression, sizeImage=0,
            ).pack())

        self.write_pixels(writer)

        writer.flush()

    def write_pixels(self, writer:io.BufferedWriter):
        raw_stride = self.raw_stride
        stride = self.raw_stride
        for y in range(self.height - 1, -1, -1):
            writer.write(pack(f'<{stride}s', self.pixels[y*raw_stride:(y+1)*raw_stride]))
        # # else:
        # def makepix(i) -> bytes:
        #     return bytes(reversed(self.palette[self.pixels[i]]))
        # stride = self.raw_stride24
        # for y in range(self.height - 1, -1, -1):
        #     scanline = b''.join(makepix(y*raw_stride + x) for x in range(self.width))
        #     writer.write(pack(f'<{stride}s', scanline))

    #endregion

#######################################################################################

class Rc8Image:
    """source: <https://github.com/morkt/GARbro/blob/master/ArcFormats/Majiro/ImageRC8.cs>
    """
    def __init__(self, width:int, height:int, palette:List[bytes]=None, pixels:bytes=None):
        self.version = 0
        self.encrypted = False
        self.width = width
        self.height = height
        self.datasize = 0
        self.palette = [b'\x00\x00\x00']*256 if palette is None else palette
        self.pixels = pixels

    #region ## ROKUCHO READING ##

    def load(self, reader:io.BufferedReader):
        if isinstance(reader, str):
            with open(reader, 'rb') as file:
                return self.load(file)
        self.read_header(reader)
        self.read_palette(reader)
        self.read_pixels(reader)
        return True

    def read_header(self, reader:io.BufferedReader) -> Tuple[int, int]:
        reader.seek(0)
        signature, self.width, self.height, self.datasize = unpack('<8sIII', reader.read(20))
        self.version, self.encrypted = RC8_SIGNATURES[signature]

    def read_palette(self, reader:io.BufferedReader) -> List[bytes]:
        reader.seek(20)
        self.palette = unpack('<' + '3s'*256, reader.read(0x300))

    def read_pixels(self, reader:io.BufferedReader):
        reader.seek(20 + 0x300)
        shift_tbl = init_shift_table(self.width, RC8_SHIFT_TABLE)

        # start by reading one pixel
        buffer = bytearray(self.width * self.height)
        buffer[0] = reader.read(1)[0]
        left = len(buffer) - 1
        pos = 1

        while left > 0:
            ### CMD: <F NNNN nnn>
            cmd = reader.read(1)[0]

            if not (cmd & 0x80):###############################################
                ## READ: <0  nnnnnnn> [eeeeeeeeeeeeeeee]
                #         |  \_____|   |
                #  read flg        |---extra (if num == 0x7f)
                # read count: 1 + (num (0-0x7f) + [extra (0-0xffff)])
                ###############################################################
                n = cmd
                if n == 0x7f:  # add extra count?
                    n += unpack('<H', reader.read(2))[0]
                n += 1  # read count is always a minimum of 1

                assert(n <= left)  # bounds check: dst data
                buffer[pos:pos+n] = reader.read(n)

            else:##############################################################
                ## COPY: <1 ssss nnn> [eeeeeeeeeeeeeeee]
                #         | \__| \_|   |
                #  copy flg    |   |---extra (if num == 0x7)
                #    shift index   |
                # copy count: 3 + (num (0-0x7) + [extra (0-0xffff)])
                ###############################################################
                n = cmd & 0x7
                if n == 0x7:  # add extra count?
                    n += unpack('<H', reader.read(2))[0]
                n += 3  # copy count is always a minimum of 3

                # shift determines where data is copied from (always negative)
                s = shift_tbl[(cmd>>3) & 0xf]

                assert(n <= left)             # bounds check: dst data
                assert(s < 0 and pos+s >= 0)  # bounds check: copy data
                copy_overlapped(buffer, pos+s, pos, n)

            left -= n
            pos += n

        self.pixels = bytes(buffer)

    #endregion

    #region ## PROPERTIES ##

    @property
    def size(self) -> Tuple[int, int]: return (self.width, self.height)
    @size.setter
    def size(self, value:Tuple[int, int]): self.width, self.height = value

    @property
    def planes(self) -> int: return 1
    @property
    def bpp(self) -> int: return 8
    @property
    def raw_stride(self) -> int: return (self.width * self.bpp + 7) // 8
    @property
    def stride(self) -> int: return ((self.width * self.bpp + 7) // 8 + 3) & ~0x3
    @property
    def raw_buffersize(self) -> int: return (self.raw_stride * self.height)
    @property
    def buffersize(self) -> int: return (self.stride * self.height)
    @property
    def compression(self) -> Compression: return Compression.BI_RGB

    #endregion

    #region ## BITMAP WRITING ##

    def save_bmp(self, writer:io.BufferedWriter):
        if isinstance(writer, str):
            with open(writer, 'wb+') as file:
                return self.save_bmp(file)

        header_size = BITMAPFILEHEADER.calcsize() # 14
        info_size = BITMAPINFOHEADER.calcsize() # 40

        palette_size = 0x400

        data_offset = header_size + info_size + palette_size
        file_size = data_offset + self.buffersize

        writer.seek(0)
        writer.write(BITMAPFILEHEADER(fileSize=file_size, pixelOffset=data_offset).pack())

        writer.write(BITMAPINFOHEADER(
            width=self.width,   height=self.height,
            planes=self.planes, bitCount=self.bpp,
            xPelsPerMeter=3780, yPelsPerMeter=3780,
            compression=self.compression, sizeImage=0,
            clrUsed=len(self.palette), clrImportant=len(self.palette),
            ).pack())

        self.write_palette(writer)
        self.write_pixels(writer)

        writer.flush()

    def write_palette(self, writer:io.BufferedWriter):
        writer.write(pack('<' + '4s'*256, *[c+b'\xff' for c in self.palette]))

    def write_pixels(self, writer:io.BufferedWriter):
        raw_stride = self.raw_stride
        stride = self.raw_stride
        for y in range(self.height - 1, -1, -1):
            writer.write(pack(f'<{stride}s', self.pixels[y*raw_stride:(y+1)*raw_stride]))

    #endregion

#endregion


