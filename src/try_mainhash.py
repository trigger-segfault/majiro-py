#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Quick interactive utility to try and find the groupname of a $main function
"""

#######################################################################################

from zlib import crc32

## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    EXIT:str = '-exit'
    print(f'type {EXIT!r} to end loop')
    text:str = input('> ')
    while text != EXIT:
        name:str = f'$main@{text.strip()}'
        value:int = crc32(name.encode('cp932'))
        print(f'\'{value:08x}')
        text = input('> ')
    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())
