#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-15'
__author__  = 'Robert Jordan'
__credits__ = '''Port of morkt/GARbro's ArcMajiro
Implementation designed mostly copied from CPython zipfile.py'''

__all__ = ['MajiroArcFile']

#######################################################################################

## runtime imports:
# from ..crypt import hash32, hash64  # used by MajiroArcFile._write (unimplemented)

import io, os, shutil, threading
from struct import calcsize, pack, unpack
from typing import Any, Callable, List, Optional, Dict, Tuple, Union

from .arcextfile import MajiroArcExtFile
from ..util.typecast import to_bytes, to_str



class MajiroArcEntry:
    """MajiroArcEntry(hash:int, offset:int, size:int=..., name:str=...)
    this class is immutable
    """
    __slots__ = ('hash', 'offset', 'size', 'name')
    hash:int
    offset:int
    size:int
    name:str

    def __init__(self, hash:int, offset:int, size:int=..., name:str=...):
        self.hash = hash
        self.offset = offset
        if size is not Ellipsis:
            self.size = size
        if name is not Ellipsis:
            self.name = name

    #region ## IMMUTABLE ##

    def __setattr__(self, name, value):
        if hasattr(self, name):
            raise AttributeError(f'{name!r} attribute is readonly')
        super().__setattr__(name, value)

    #endregion

    def __repr__(self) -> str:
        size = f', size={self.size!r}' if hasattr(self, 'size') else ''
        name = f', name={self.name!r}' if hasattr(self, 'name') else ''
        return f'{self.__class__.__name__}(0x{self.hash:08x}, {self.offset!r}{size}{name})'
        #size = f', size={self.size!r}' if hasattr(self, 'size') else ''
        #return f'{self.__class__.__name__}({self.name!r}, 0x{self.hash:08x}, {self.offset!r}{size})'
    __str__ = __repr__

    @classmethod
    def read(cls, reader:io.BufferedReader, version:int) -> 'MajiroArcEntry':
        if version == 1:
            return cls(*unpack('<II', reader.read(8)))
        elif version == 2:
            return cls(*unpack('<III', reader.read(12)))
        elif version == 3:
            return cls(*unpack('<QII', reader.read(16)))
        else:
            raise ValueError(f'unknown version: {version!r}')

    def write(self, writer:io.BufferedWriter, version:int):
        if version == 1:
            return writer.write(pack('<II', self.hash, self.offset))
        elif version == 2:
            return writer.write(pack('<III', self.hash, self.offset, self.size))
        elif version == 3:
            return writer.write(pack('<QII', self.hash, self.offset, self.size))
        else:
            raise ValueError(f'unknown version: {version!r}')

    @classmethod
    def calcsize(cls, version:int) -> int:
        if   version == 1: return 8
        elif version == 2: return 12
        elif version == 3: return 16
        else: raise ValueError(f'unknown version: {version!r}')

    # @classmethod
    # def read(cls, reader:io.BufferedReader) -> 'MajiroArcEntry':
    #     hash, offset = unpack('<II', reader.read(8))
    #     hash = HashName(hash, IdentifierKind.FUNCTION, lookup=lookup)
    #     return FunctionIndexEntry(hash, offset, offset == main_offset, lookup=lookup)
    # def write(self, writer:io.BufferedWriter) -> int:
    #     return writer.write(pack('<II', self.hash, self.offset))

class _SharedFile:
    def __init__(self, file, pos, close, lock, writing):
        self._file = file
        self._pos = pos
        self._close = close
        self._lock = lock
        self._writing = writing
        self.seekable = file.seekable
        self.tell = file.tell

    def seek(self, offset, whence=0):
        with self._lock:
            if self._writing():
                raise ValueError("Can't reposition in the ZIP file while "
                        "there is an open writing handle on it. "
                        "Close the writing handle before trying to read.")
            self._file.seek(offset, whence)
            self._pos = self._file.tell()
            return self._pos

    def read(self, n=-1):
        with self._lock:
            if self._writing():
                raise ValueError("Can't read from the ZIP file while there "
                        "is an open writing handle on it. "
                        "Close the writing handle before trying to read.")
            self._file.seek(self._pos)
            data = self._file.read(n)
            self._pos = self._file.tell()
            return data

    def close(self):
        if self._file is not None:
            fileobj = self._file
            self._file = None
            self._close(fileobj)

class MajiroArcFile:
    """Majiro .arc file type and extractor
    """
    _SIGNATURES:Dict[bytes,int] = {
        b'MajiroArcV1.000\x00': 1,
        b'MajiroArcV2.000\x00': 2,
        b'MajiroArcV3.000\x00': 3,
    }
    _SIGNATURES_LOOKUP:Dict[int,bytes] = dict((v,k) for k,v in _SIGNATURES.items())
    _V_OLDEST:int = min(_SIGNATURES.values())
    _V_LATEST:int = max(_SIGNATURES.values())

    fp = None  # Set here since __del__ checks it
    _windows_illegal_name_trans_table = None

    def __init__(self, file, mode:str='r', entries:List[MajiroArcEntry]=None, *, version:Optional[int]=None):
        self.version = version
        self.mode = mode
        self.entries = [] if entries is None else entries  # type: List[MajiroArcEntry]
        if mode != 'r':
            raise ValueError(f'MajiroArcFile() only "r" mode is currently supported, got {mode!r}')
        # Check if we were passed a file-like object
        if isinstance(file, os.PathLike):
            file = os.fspath(file)
        if isinstance(file, str):
            # No, it's a filename
            self._filePassed = False
            self.filename = file
            modeDict = {'r' : 'rb', 'w': 'wb+', 'x': 'xb+'}
            filemode = modeDict[mode]
            while True:
                try:
                    self.fp = io.open(file, filemode)
                except OSError:
                    if filemode in modeDict:
                        filemode = modeDict[filemode]
                        continue
                    raise
                break
        else:
            self._filePassed = True
            self.fp = file
            self.filename = getattr(file, 'name', None)
        self._fileRefCnt = 1
        self._lock = threading.RLock()
        self._seekable = True
        self._writing = False
        
        try:
            self._read(self.fp)
        except:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)
            raise

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __del__(self):
        """Call the "close()" method in case the user forgot."""
        self.close()

    def close(self):
        """Close the file, and for mode 'w', 'x' and 'a' write the ending
        records."""
        if self.fp is None:
            return

        if self._writing:
            raise ValueError("Can't close the MajiroArc file while there is "
                             "an open writing handle on it. "
                             "Close the writing handle before closing the archive.")

        try:
            if self.mode in ('w', 'x', 'a') and self._didModify: # write ending records
                with self._lock:
                    if self._seekable:
                        self.fp.seek(self.start_dir)
                    self._write_end_record()
        finally:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)

    def _fpclose(self, fp):
        assert self._fileRefCnt > 0
        self._fileRefCnt -= 1
        if not self._fileRefCnt and not self._filePassed:
            fp.close()

    @property
    def signature(self) -> int:
        version = self._V_LATEST if self.version is None else self.version
        return self._SIGNATURES_LOOKUP[version]

    #region ## SIGNATURE CHECK FUNCTIONS ##

    @classmethod
    def checkfile(cls, filename:str) -> bool:
        if os.path.isfile(filename):
            with open(filename, 'rb') as file:
                return cls.check(file, False)
        return False
    @classmethod
    def check(cls, reader:io.BufferedReader, peek:bool=True) -> bool:
        signature = b''
        if hasattr(reader, 'peek'):
            signature = reader.peek(16)[:16]
        if len(signature) < 16:
            signature = reader.read(16)
            if peek: # and reader.seekable():  # restore position
                reader.seek(-len(signature), 1)
        return (signature in cls._SIGNATURES)

    #endregion

    def getinfo(self, name) -> MajiroArcEntry:
        # Make sure we have an info object
        if isinstance(name, MajiroArcEntry):
            # 'name' is already an info object
            return name
        elif isinstance(name, int):
            for entry in self.entries:
                if entry.hash == name:
                    return entry
        elif isinstance(name, (str,bytes)):
            name = to_str(name)
            for entry in self.entries:
                if entry.name == name:
                    return entry
            
        else:
            raise TypeError(f'_getinfo() name must be {MajiroArcEntry.__name__}, int, str or bytes, not {name.__class__.__name__}')

        raise KeyError(f'There is no item named {name!r} in the archive')
        # elif mode == 'w':
        #     raise ValueError('open() mode "w" not supported')
        #     # zinfo = MajiroArcEntry(name)
        #     # zinfo.compress_type = self.compression
        #     # zinfo._compresslevel = self.compresslevel
        # else:
        #     # Get info object for name
        #     zinfo = self.getinfo(name)

    def read(self, member:MajiroArcEntry) -> bytes:
        """Return file bytes for name."""
        if not self.fp:
            raise ValueError(
                "Attempt to use ZIP archive that was already closed")
        member = self.getinfo(member)
        # Open for reading:
        self._fileRefCnt += 1
        zef_file = _SharedFile(self.fp, member.offset,
                               self._fpclose, self._lock, lambda: self._writing)
        try:
            data = zef_file.read(member.size)
            return data
        except:
            zef_file.close()
            zef_file = None
            raise
        finally:
            if zef_file is not None:
                zef_file.close()
        # with self.open(name, "r") as fp:
        #     return fp.read()

    def open(self, member:MajiroArcEntry, mode='r') -> io.BufferedIOBase:
        if mode not in {'r', 'w'}:
            raise ValueError('open() requires mode "r" or "w"')
        # if pwd and not isinstance(pwd, bytes):
        #     raise TypeError("pwd: expected bytes, got %s" % type(pwd).__name__)
        # if pwd and (mode == "w"):
        #     raise ValueError("pwd is only supported for reading files")
        if not self.fp:
            raise ValueError(
                "Attempt to use ZIP archive that was already closed")
        member = self.getinfo(member)
        if mode == 'w':
            raise ValueError('open() mode "w" not supported')

        # # Make sure we have an info object
        # if isinstance(name, MajiroArcEntry):
        #     # 'name' is already an info object
        #     zinfo = name
        # elif mode == 'w':
        #     raise ValueError('open() mode "w" not supported')
        #     # zinfo = MajiroArcEntry(name)
        #     # zinfo.compress_type = self.compression
        #     # zinfo._compresslevel = self.compresslevel
        # else:
        #     # Get info object for name
        #     zinfo = self.getinfo(name)

        # if mode == 'w':
        #     return self._open_to_write(zinfo, force_zip64=force_zip64)

        if self._writing:
            raise ValueError("Can't read from the ZIP file while there "
                    "is an open writing handle on it. "
                    "Close the writing handle before trying to read.")

        # Open for reading:
        self._fileRefCnt += 1
        zef_file = _SharedFile(self.fp, member.offset,
                               self._fpclose, self._lock, lambda: self._writing)
        try:
            return MajiroArcExtFile(zef_file, mode, member.offset, member.size, member.name, None, True)
        except:
            zef_file.close()
            raise

    def _fpclose(self, fp):
        assert self._fileRefCnt > 0
        self._fileRefCnt -= 1
        if not self._fileRefCnt and not self._filePassed:
            fp.close()

    def extractall(self, path:str=None, members:List[MajiroArcEntry]=None):#, pwd=None):
        """Extract all members from the archive to the current working
           directory. `path' specifies a different directory to extract to.
           `members' is optional and must be a subset of the list returned
           by namelist().
        """
        if members is None:
            members = self.entries

        if path is None:
            path = os.getcwd()
        else:
            path = os.fspath(path)

        for zipinfo in members:
            self._extract_member(zipinfo, path)#, pwd)

    def namelist(self):
        """Return a list of file names in the archive."""
        return [data.name for data in self.entries]

    def infolist(self):
        """Return a list of class ZipInfo instances for files in the
        archive."""
        return self.entries

    def extract(self, member:MajiroArcEntry, path:str=None, to_dir:bool=...): #, pwd=None):
        """Extract a member from the archive to the current working directory,
           using its full name. Its file information is extracted as accurately
           as possible. `member' may be a filename or a ZipInfo object. You can
           specify a different directory using `path'.
        """
        if path is None:
            path = os.getcwd()

        if to_dir is Ellipsis:
            if os.path.isdir(path):
                to_dir = True
            elif os.path.isfile(path):
                to_dir = False
            else:
                to_dir = path[-1:] in (os.path.sep, os.path.altsep)

        return self._extract_member(member, path, to_dir)#, pwd)

    def _extract_member(self, member:MajiroArcEntry, targetpath, to_dir:bool=True): #, pwd):
        """Extract the ZipInfo object 'member' to a physical
           file on the path targetpath.
        """
        member = self.getinfo(member)

        # build the destination pathname, replacing
        # forward slashes to platform specific separators.
        arcname = member.name.replace('/', os.path.sep)

        if os.path.altsep:
            arcname = arcname.replace(os.path.altsep, os.path.sep)
        # interpret absolute pathname as relative, remove drive letter or
        # UNC path, redundant separators, "." and ".." components.
        arcname = os.path.splitdrive(arcname)[1]
        invalid_path_parts = ('', os.path.curdir, os.path.pardir)
        arcname = os.path.sep.join(x for x in arcname.split(os.path.sep)
                                   if x not in invalid_path_parts)
        if os.path.sep == '\\':
            # filter illegal characters on Windows
            arcname = self._sanitize_windows_name(arcname, os.path.sep)

        if to_dir:
            targetpath = os.path.join(targetpath, arcname)
        targetpath = os.path.normpath(targetpath)

        # Create all upper directories if necessary.
        upperdirs = os.path.dirname(targetpath)
        if upperdirs and not os.path.exists(upperdirs):
            os.makedirs(upperdirs)

        # if member.is_dir():
        #     if not os.path.isdir(targetpath):
        #         os.mkdir(targetpath)
        #     return targetpath

        with self.open(member) as source, \
             open(targetpath, "wb") as target:
            shutil.copyfileobj(source, target)

        return targetpath

    @classmethod
    def _sanitize_windows_name(cls, arcname, pathsep):
        """Replace bad characters and remove trailing dots from parts."""
        table = cls._windows_illegal_name_trans_table
        if not table:
            illegal = ':<>|"?*'
            table = str.maketrans(illegal, '_' * len(illegal))
            cls._windows_illegal_name_trans_table = table
        arcname = arcname.translate(table)
        # remove trailing dots
        arcname = (x.rstrip('.') for x in arcname.split(pathsep))
        # rejoin, removing empty parts.
        arcname = pathsep.join(x for x in arcname if x)
        return arcname

    # def open_entry(self, filename:str, entry:MajiroArcEntry) -> bytes:
    #     with open(filename, 'rb') as file:
    #         return self.read_entry(file, entry)

    # def read_entry(self, reader:io.BufferedReader, entry:MajiroArcEntry) -> bytes:
    #     reader.seek(entry.offset)
    #     data = reader.read(entry.size)
    #     if len(data) != entry.size:
    #         raise Exception('Could not read full entry data size')
    #     return data

    # def open_entry(self, filename:str, entry:MajiroArcEntry) -> bytes:
    #     with open(filename, 'rb') as file:
    #         return self.read_entry(file, entry)

    # def read_entry(self, reader:io.BufferedReader, entry:MajiroArcEntry) -> bytes:
    #     reader.seek(entry.offset)
    #     data = reader.read(entry.size)
    #     if len(data) != entry.size:
    #         raise Exception('Could not read full entry data size')
    #     return data

    # def open_entryio(self, filename:str, entry:MajiroArcEntry) -> io.BytesIO:
    #     with open(filename, 'rb') as file:
    #         return self.read_entryio(file, entry)

    # def read_entryio(self, reader:io.BufferedReader, entry:MajiroArcEntry) -> io.BytesIO:
    #     return io.BytesIO(self.read_entry(reader, entry))

    #region ## READ/WRITE FUNCTIONS ##

    # @classmethod
    # def open(cls, filename:str) -> 'MajiroArcFile':
    #     with open(filename, 'rb') as file:
    #         return cls.read(file)

    # def save(self, filename:str):
    #     with open(filename, 'wb+') as file:
    #         self.write(file)

    # @classmethod
    def _read(self, reader:io.BufferedReader) -> 'MajiroArcFile':
        signature, count, names_offset, data_offset = unpack('<16sIII', reader.read(28))
        version = self._SIGNATURES.get(signature)
        if version is None:
            raise Exception(f'Invalid MajiroArc signature: {signature!r}')

        entries = []  # type: List[MajiroArcEntry]
        for _ in range(count):
            entry = MajiroArcEntry.read(reader, version)
            if version == 1 and entries:
                entries[-1].size = entry.offset - entries[-1].offset
            entries.append(entry)
        if version == 1 and entries:
            entry = MajiroArcEntry.read(reader, version)
            entries[-1].size = entry.offset - entries[-1].offset

        reader.seek(names_offset, 0)
        names_pos, names_size = 0, (data_offset - names_offset)
        names_buf = reader.read(names_size)
        
        for entry in entries:
            null_idx = names_buf.index(b'\x00', names_pos)
            entry.name = to_str(names_buf[names_pos:null_idx])
            names_pos = null_idx + 1

        self.version = version
        self.entries = entries
        # return cls(version, entries)

    def _write(self, writer:io.BufferedWriter):
        version = self._V_LATEST if self.version is None else self.version
        signature = self._SIGNATURES_LOOKUP[version]
        #
        names_buf = b'\x00'.join(to_bytes(e.name) for e in self.entries) + b'\x00'
        entry_size = MajiroArcEntry.calcsize(version)
        table_size = entry_size * (len(self.entries) + int(version==1))

        ## write header
        names_offset = 28 + table_size
        data_offset = names_offset + len(names_buf)
        writer.write(pack('<16sIII', self.signature, len(self.entries), names_offset, data_offset))

        ## write file entries
        if version < 3:
            from ..crypt import hash32 as hashfunc
        else:
            from ..crypt import hash64 as hashfunc

        offset_next = data_offset
        for entry in self.entries:
            hash = hashfunc(entry.name)
            offset = offset_next
            offset_next += entry.size
            entry_new = MajiroArcEntry(hash, offset, entry.size)
            entry_new.write(writer, version)
        if version == 1:
            entry_new = MajiroArcEntry(0, offset_next)
            entry_new.write(writer, version)

        ## write names buffer
        writer.write(names_buf)

        ##TODO: write data buffer
        for entry in self.entries:
            writer.write(bytes(entry.size))

        writer.flush()

    #endregion

#   @classmethod
#   def read(cls, reader:io.BufferedReader):
#     #
#     signature, count, names_offset, data_offset = unpack('<16sIII', reader.read(28))
#     version = cls.SIGNATURES.index(signature) + 1
#     #
#     #table_size = count + (1 if version==1 else 0)
#     entry_size = 4 * (version + 1)
#     #table_size *= entry_size
#     table_size = entry_size * (count + (1 if version==1 else 0))
#     #
#     names_size = (data_offset - names_offset)
#     reader.seek(names_offset)
#     names:bytes = unpack(f'<{names_size}s', reader.read(names_size))[0]
#     names_pos = 0
#     table_pos = 28
#     hash_size, hfmt = (4,'I') if (version < 3) else (8,'Q')
#     reader.seek(table_pos + hash_size)
#     offset_next = unpack('<I', reader.read(4))[0]
#     #
#     entries = [None]*count
#     for i in range(count):
#       zero = names.find(b'\x00', names_pos)
#       if zero == -1:
#         break
#       name_len = zero - names_pos
#       name = to_str(names[names_pos:zero])
#       names_size -= name_len + 1
#       names_pos = zero + 1
#       offset = offset_next
#       reader.seek(table_pos + entry_size + hash_size)
#       offset_next = unpack('<I', reader.read(4))[0]
#       entry = ArcEntry(name, offset)
#       if version==1:
#         entry.size = (offset_next - offset) if (offset_next >= offset) else 0
#       else:
#         reader.seek(table_pos + hash_size + 4)
#         entry.size = unpack('<I', reader.read(4))[0]
#       table_pos += entry_size
#       entries[i] = entry
