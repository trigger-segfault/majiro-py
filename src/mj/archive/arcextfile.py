#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-15'
__author__  = 'Robert Jordan'
__credits__ = '''Implementation designed mostly copied from CPython zipfile.py'''

__all__ = ['MajiroArcExtFile']

#######################################################################################

import io, os
from struct import calcsize, pack, unpack
from typing import Any, Callable, List, Optional, Dict, Tuple, Union

from ..util.typecast import to_str


class MajiroArcExtFile(io.BufferedIOBase):
    """File-like object for reading an archive member.
       Is returned by MajiroArcFile.open().
    """

    # Max size supported by decompressor.
    MAX_N = 1 << 31 - 1

    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE = 4096

    # Chunk size to read during seek
    MAX_SEEK_READ = 1 << 24

    # def __init__(self, fileobj, mode, zipinfo, pwd=None, close_fileobj=False):
    def __init__(self, fileobj, mode, offset:int=..., size:int=..., name:str=None, pwd=None, close_fileobj=False):
        self._fileobj = fileobj
        self._pwd = pwd
        self._close_fileobj = close_fileobj

        # self._compress_type = None #zipinfo.compress_type
        # self._compress_left = size
        self._left = size

        self._decompressor = None #_get_decompressor(self._compress_type)

        self._eof = False
        self._readbuffer = b''
        self._offset = 0

        self.newlines = None

        self.mode = mode
        self.name = name #zipinfo.filename

        self._seekable = False
        # self._offset = offset if offset is not Ellipsis else 
        try:
            if fileobj.seekable():
                # if offset is not Ellipsis:
                #     fileobj.seek(offset)
                self._orig_start = fileobj.tell() if offset is Ellipsis else offset  # type: int
                if size is Ellipsis:
                    self._orig_file_size = fileobj.seek(0, 2) - self._orig_start
                else:
                    self._orig_file_size = size
                fileobj.seek(self._orig_start)

                # self._orig_compress_start = self._orig_start
                # self._orig_compress_size = self._orig_start

                # self._orig_file_size = zipinfo.file_size
                self._seekable = True
        except AttributeError:
            pass

        # self._decrypter = None
        # if pwd:
        #     # if zipinfo.flag_bits & 0x8:
        #     #     # compare against the file type from extended local headers
        #     #     check_byte = (zipinfo._raw_time >> 8) & 0xff
        #     # else:
        #     #     # compare against the CRC otherwise
        #     #     check_byte = (zipinfo.CRC >> 24) & 0xff
        #     h = self._init_decrypter()
        #     # if h != check_byte:
        #     #     raise RuntimeError("Bad password for file %r" % zipinfo.orig_filename)


    # def _init_decrypter(self):
    #     self._decrypter = _ZipDecrypter(self._pwd)
    #     # The first 12 bytes in the cypher stream is an encryption header
    #     #  used to strengthen the algorithm. The first 11 bytes are
    #     #  completely random, while the 12th contains the MSB of the CRC,
    #     #  or the MSB of the file time depending on the header type
    #     #  and is used to check the correctness of the password.
    #     header = self._fileobj.read(12)
    #     self._compress_left -= 12
    #     return self._decrypter(header)[11]

    def __repr__(self):
        result = [f'<{self.__class__.__name__}']
        # result = ['<%s.%s' % (self.__class__.__module__,
        #                       self.__class__.__qualname__)]
        if not self.closed:
            result.append(f' name={self.name!r} mode={self.mode!r}')
            # result.append(' name=%r mode=%r' % (self.name, self.mode))
            # if self._compress_type != ZIP_STORED:
            #     result.append(' compress_type=%s' %
            #                   compressor_names.get(self._compress_type,
            #                                        self._compress_type))
        else:
            result.append(' [closed]')
        result.append('>')
        return ''.join(result)

    def readline(self, limit=-1):
        """Read and return a line from the stream.
        If limit is specified, at most limit bytes will be read.
        """

        if limit < 0:
            # Shortcut common case - newline found in buffer.
            i = self._readbuffer.find(b'\n', self._offset) + 1
            if i > 0:
                line = self._readbuffer[self._offset: i]
                self._offset = i
                return line

        return io.BufferedIOBase.readline(self, limit)

    def peek(self, n=1):
        """Returns buffered bytes without advancing the position."""
        if n > len(self._readbuffer) - self._offset:
            chunk = self.read(n)
            if len(chunk) > self._offset:
                self._readbuffer = chunk + self._readbuffer[self._offset:]
                self._offset = 0
            else:
                self._offset -= len(chunk)

        # Return up to 512 bytes to reduce allocation overhead for tight loops.
        return self._readbuffer[self._offset: self._offset + 512]

    def readable(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return True

    def read(self, n=-1):
        """Read and return up to n bytes.
        If the argument is omitted, None, or negative, data is read and returned until EOF is reached.
        """
        if self.closed:
            raise ValueError("read from closed file.")
        if n is None or n < 0:
            buf = self._readbuffer[self._offset:]
            self._readbuffer = b''
            self._offset = 0
            while not self._eof:
                buf += self._read1(self.MAX_N)
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset:end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset:]
        self._readbuffer = b''
        self._offset = 0
        while n > 0 and not self._eof:
            data = self._read1(n)
            if n < len(data):
                self._readbuffer = data
                self._offset = n
                buf += data[:n]
                break
            buf += data
            n -= len(data)
        return buf

    def read1(self, n):
        """Read up to n bytes with at most one read() system call."""

        if n is None or n < 0:
            buf = self._readbuffer[self._offset:]
            self._readbuffer = b''
            self._offset = 0
            while not self._eof:
                data = self._read1(self.MAX_N)
                if data:
                    buf += data
                    break
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset:end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset:]
        self._readbuffer = b''
        self._offset = 0
        if n > 0:
            while not self._eof:
                data = self._read1(n)
                if n < len(data):
                    self._readbuffer = data
                    self._offset = n
                    buf += data[:n]
                    break
                if data:
                    buf += data
                    break
        return buf

    def _read1(self, n):
        # Read up to n compressed bytes with at most one read() system call,
        # decrypt and decompress them.
        if self._eof or n <= 0:
            return b''

        # # Read from file.
        # if self._compress_type == ZIP_DEFLATED:
        #     ## Handle unconsumed data.
        #     data = self._decompressor.unconsumed_tail
        #     if n > len(data):
        #         data += self._read2(n - len(data))
        # else:
        #     data = self._read2(n)
        data = self._read2(n)

        # if self._compress_type == ZIP_STORED:
        #     self._eof = self._compress_left <= 0
        # elif self._compress_type == ZIP_DEFLATED:
        #     n = max(n, self.MIN_READ_SIZE)
        #     data = self._decompressor.decompress(data, n)
        #     self._eof = (self._decompressor.eof or
        #                  self._compress_left <= 0 and
        #                  not self._decompressor.unconsumed_tail)
        #     if self._eof:
        #         data += self._decompressor.flush()
        # else:
        #     data = self._decompressor.decompress(data)
        #     self._eof = self._decompressor.eof or self._compress_left <= 0

        data = data[:self._left]
        self._left -= len(data)
        if self._left <= 0:
            self._eof = True

        return data

    def _read2(self, n):
        if self._left <= 0:
            return b''
        # if self._compress_left <= 0:
        #     return b''

        n = max(n, self.MIN_READ_SIZE)
        # n = min(n, self._compress_left)
        n = min(n, self._left)

        data = self._fileobj.read(n)
        # self._compress_left -= len(data)
        if not data:
            raise EOFError

        # if self._decrypter is not None:
        #     data = self._decrypter(data)
        return data

    def close(self):
        try:
            if self._close_fileobj:
                self._fileobj.close()
        finally:
            super().close()

    def seekable(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._seekable

    def seek(self, offset, whence=0):
        if self.closed:
            raise ValueError("seek on closed file.")
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        curr_pos = self.tell()
        if whence == 0: # Seek from start of file
            new_pos = offset
        elif whence == 1: # Seek from current position
            new_pos = curr_pos + offset
        elif whence == 2: # Seek from EOF
            new_pos = self._orig_file_size + offset
        else:
            raise ValueError("whence must be os.SEEK_SET (0), "
                             "os.SEEK_CUR (1), or os.SEEK_END (2)")

        if new_pos > self._orig_file_size:
            new_pos = self._orig_file_size

        if new_pos < 0:
            new_pos = 0

        read_offset = new_pos - curr_pos
        buff_offset = read_offset + self._offset

        if buff_offset >= 0 and buff_offset < len(self._readbuffer):
            # Just move the _offset index if the new position is in the _readbuffer
            self._offset = buff_offset
            read_offset = 0
        elif read_offset < 0:
            # Position is before the current position. Reset the ZipExtFile
            # self._fileobj.seek(self._orig_compress_start)
            self._fileobj.seek(self._orig_start)
            # self._compress_left = self._orig_compress_size
            self._left = self._orig_file_size
            self._readbuffer = b''
            self._offset = 0
            # self._decompressor = _get_decompressor(self._compress_type)
            self._eof = False
            read_offset = new_pos
            # if self._decrypter is not None:
            #     self._init_decrypter()

        while read_offset > 0:
            read_len = min(self.MAX_SEEK_READ, read_offset)
            self.read(read_len)
            read_offset -= read_len

        return self.tell()

    def tell(self):
        if self.closed:
            raise ValueError("tell on closed file.")
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        filepos = self._orig_file_size - self._left - len(self._readbuffer) + self._offset
        return filepos

