#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

__all__ = ['CsvSheet']

#######################################################################################

import csv, io
from collections import UserList
from typing import Optional

from .googlesheets import GoogleSheet
from .rowtypes import _RowBase, _RowHashBase


#######################################################################################

SHEET_FORMAT_CSV:str = 'csv'  # comma-separated values
SHEET_FORMAT_TSV:str = 'tsv'  # tab-separated values


class CsvSheet(UserList):
    def __init_subclass__(cls, sheetname:str, sheetid:GoogleSheet, rowtype:type, **kwargs):
        cls.NAME:str = sheetname
        cls.SHEET:GoogleSheet = sheetid
        cls.ROW_TYPE:type = rowtype
        cls.IS_HASH_TYPE:bool = isinstance(cls.ROW_TYPE(), _RowHashBase)
        cls.FIELD_NAMES:tuple = tuple(col.col_name for col in cls.ROW_TYPE.COLS)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def read(self, file:io.TextIOBase, format:str='csv', *, overwrite:bool=True) -> int:
        if format not in ('csv', 'tsv'):
            raise ValueError(f'{self.__class__.__name__}.write() argument csv must be \'csv\' or \'tsv\', not {csv!r}')
        delimiter = ',' if format == 'csv' else '\t'

        # reader = csv.DictReader(file, self.FIELD_NAMES, delimiter=delimiter, quotechar='"', lineterminator='\n')
        reader = csv.DictReader(file, delimiter=delimiter, quotechar='"', lineterminator='\n')
        if overwrite:
            self.clear()
        old_len = len(self)
        for row in reader:
            myrow = self.ROW_TYPE.from_row(row)  # type: _RowBase
            self.append(myrow)
        return len(self) - old_len

    def write(self, file:io.TextIOBase, format:str='csv', *, preserve:bool=False) -> int:
        if format not in ('csv', 'tsv'):
            raise ValueError(f'{self.__class__.__name__}.write() argument csv must be \'csv\' or \'tsv\', not {csv!r}')
        delimiter = ',' if format == 'csv' else '\t'

        writer = csv.DictWriter(file, self.FIELD_NAMES, delimiter=delimiter, quotechar='"', lineterminator='\n')
        for myrow in self:
            writer.writerow(myrow.to_row(preserve=preserve))
        # if hasattr(file, 'flush'):
        #     file.flush()
        return len(self)


    @classmethod
    def fromsheet(cls, format:str='csv', cache_file:Optional[str]=None) -> 'CsvSheet':
        data = cls.SHEET.download(format=format, remove_crlf=True, ignore_status=False)

        if cache_file is not None:
            with open(cache_file, 'wt+', encoding='utf-8') as cache_writer:
                cache_writer.write(data)
                cache_writer.flush()

        mysheet = cls()
        mysheet.read(io.StringIO(data), format=format)
        return mysheet
    @classmethod
    def fromfile(cls, filename:str, format:str='csv') -> 'CsvSheet':
        with open(filename, 'rt', encoding='utf-8') as file:
            mysheet = cls()
            mysheet.read(file, format=format)
            return mysheet

    def import_sheet(self, format:str='csv', cache_file:Optional[str]=None, *, overwrite:bool=True) -> int:
        data = self.SHEET.download(format=format, remove_crlf=True, ignore_status=False)

        if cache_file is not None:
            with open(cache_file, 'wt+', encoding='utf-8') as cache_writer:
                cache_writer.write(data)
                cache_writer.flush()

        return self.read(io.StringIO(data), format=format, overwrite=overwrite)
    
    def import_file(self, filename:str, format:str='csv', *, overwrite:bool=True) -> int:
        with open(filename, 'rt', encoding='utf-8') as file:
            return self.read(file, format=format, overwrite=overwrite)

    def export(self, filename:str, format:str='csv', *, preserve:bool=False) -> int:
        with open(filename, 'wt+', encoding='utf-8') as file:
            result = self.write(file, format=format, preserve=preserve)
            file.flush()
            return result

    def verify(self, error:bool=False) -> list:
        items = None if error else []
        for i, row in enumerate(self):
            if not row.verify():
                if error:
                    raise Exception(f'Majiro Data - {self.NAME}: verification failed on row [{(i+2)}] for name {row.name!r}')
                else:
                    items.append(row)
        return items
                

#######################################################################################

del Optional  # cleanup declaration-only imports
