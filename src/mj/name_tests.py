#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Utility methods for parsing, spliting, checking, and working with Majiro identifier name strings.

this module is designed to function similarly to the os.path module functions.
"""

__version__ = '1.0.0'
__date__    = '2021-05-07'
__author__  = 'Robert Jordan'

# __all__ = ['GROUP_LOCAL', 'GROUP_DEFAULT', 'GROUP_SYSCALL', 'chgroup', 'joingroup', 'splitgroup', 'basename', 'groupname', 'hasgroup', 'splitsymbols', 'joinsymbols', 'splitprefix', 'splitpostfix', 'prefixsymbol', 'postfixsymbol', 'hasprefix', 'haspostfix']

#######################################################################################

from .name import *

#######################################################################################

#region ## NAME/GROUP HELPER FUNCTIONS ##

assert(chgroup('$main@HELLO', 'WORLD') == '$main@WORLD')
assert(chgroup('@page_back', 'GLOBAL') == '@page_back@GLOBAL')
assert(chgroup('#save_info$@GLOBAL', None) == '#save_info$')

assert(joingroup('$main', 'GLOBAL') == '$main@GLOBAL')
assert(joingroup('$main@HELLO', 'WORLD') == '$main@HELLO')
assert(joingroup('#save_info$', None) == '#save_info$')

assert(splitgroup('$main@GLOBAL') == ('$main', 'GLOBAL'))
assert(splitgroup('_xy@') == ('_xy', ''))
assert(splitgroup('@page_back') == ('@page_back', None))
assert(splitgroup('@page_back', 'MYGROUP') == ('@page_back', 'MYGROUP'))

assert(basename('$main@GLOBAL') == '$main')
assert(basename('_xy@') == '_xy')
assert(basename('@page_back') == '@page_back')

assert(groupname('$main@GLOBAL') == 'GLOBAL')
assert(groupname('_xy@') == '')
assert(groupname('@page_back') is None)

assert(hasgroup('$main@GLOBAL') is True)
assert(hasgroup('_xy@') is True)
assert(hasgroup('@page_back') is False)


assert(splitsymbols('$cos%@MAJIRO_INTER') == ('$', 'cos', '%', 'MAJIRO_INTER'))
assert(splitsymbols('$rand') == ('$', 'rand', '', None))
assert(splitsymbols('hello#@WORLD') == (None, 'hello', '#', 'WORLD'))
assert(splitsymbols('hello#@WORLD') == (None, 'hello', '#', 'WORLD'))
assert(splitsymbols('') == (None, '', None, None))
assert(splitsymbols('$') == (None, '$', '', None))
assert(splitsymbols('$$') == ('$', '$', '', None))
assert(splitsymbols('$$$') == ('$', '$', '$', None))
assert(splitsymbols('$$$@') == ('$', '$', '$', ''))

assert(joinsymbols('$', 'cos', '%', 'MAJIRO_INTER') == '$cos%@MAJIRO_INTER')
assert(joinsymbols('$', 'rand', '') == '$rand')
assert(joinsymbols(None, 'rand', None, 'MAJIRO_INTER') == 'rand@MAJIRO_INTER')

assert(splitprefix('$abs@MAJIRO_INTER') == ('$', 'abs'))
assert(splitprefix('$sin%') == ('$', 'sin%'))
assert(splitprefix('$rand') == ('$', 'rand'))
assert(splitprefix('rand') == (None, 'rand'))

assert(splitpostfix('$rand!@MAJIRO_INTER') == ('$rand', '!'))
assert(splitpostfix('$tan%') == ('$tan', '%'))
assert(splitpostfix('$rand') == ('$rand', ''))
assert(splitpostfix('_') == ('_', ''))
assert(splitpostfix('_a') == ('_a', ''))
assert(splitpostfix('') == ('', None))

assert(prefixsymbol('$abs@MAJIRO_INTER') == '$')
assert(prefixsymbol('a') is None)

assert(postfixsymbol('@pic_top_bak$#@PIC') == '$#')
assert(postfixsymbol('$abs@MAJIRO_INTER') == '')
assert(postfixsymbol('_') == '')
assert(postfixsymbol('_a') == '')
assert(postfixsymbol('') is None)

assert(hasprefix('$abs@MAJIRO_INTER') is True)
assert(hasprefix('a') is False)

assert(haspostfix('@pic_top_bak$#@PIC') is True)
assert(haspostfix('$abs@MAJIRO_INTER') is True)
assert(haspostfix('_') is True)
assert(haspostfix('_a') is True)
assert(haspostfix('') is False)


#######################################################################################
