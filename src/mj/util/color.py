#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Terminal ANSI color printing helpers

dictionaries for easier **foreground** color formatting:
>>> from mj.util.color import Colors
>>> '{DIM}{GREEN}{!s}{RESET_ALL}'.format('hello world', **Colors)

alt usage with fstrings:
>>> from mj.util.color import Fore as F, Style as S
>>> f'{S.DIM}{F.GREEN}{"hello world"}{S.RESET_ALL}'
"""

__version__ = '0.1.0'
__date__    = '2021-05-06'
__author__  = 'Robert Jordan'

__all__ = ['ansi_support', 'Fore', 'Back', 'Style', 'StyleEx', 'DummyFore', 'DummyBack', 'DummyStyle', 'DummyStyleEx', 'rgbf', 'rgbb', 'colorama_enabled', 'vt_mode_enabled']

#######################################################################################

## runtime imports:
## [Windows only]
# import sys, os               # used by ansi_support()
# from platform import system  # used by ansi_support() if (os.environ.get('TERM') != 'ANSI')
#
# import colorama  # used if ansi_support(colorama=True)
#                  # ImportError is caught if colorama is not found,
#                  #  so it's safe to keep the package uninstalled.
#                  # used when calling enable_colorama() directly
# import ctypes, msvcrt  # used if ansi_support(vt_mode=True)
#                        # used when calling enable_vt_mode() directly

from types import SimpleNamespace
from typing import Optional, Tuple, Union


#######################################################################################

#region ## ANSI SUPPORT ##

_ANSI_SUPPORT:Optional[bool] = None
_ANSI_SUPPORT_RESULTS:Tuple[Optional[bool], Optional[bool]] = (None, None)

def ansi_support(vt_mode:bool=..., colorama:bool=...) -> Tuple[Optional[bool], Optional[bool]]:
    """has_ansi_support() -> (stdout:bool, stderr:bool)

    if color support fails due to windows and either `vt_mode` or `colorama` are True,
      one or both of those methods will be attempted, to forcefully enable color support.

    return values are None when Windows support fails and both `vt_mode` and `colorama` are Ellipsis

    ANSI support detection code for Python. 
    source: <https://gist.github.com/ssbarnea/1316877>
    """
    global _ANSI_SUPPORT, _ANSI_SUPPORT_RESULTS
    if _ANSI_SUPPORT is True:
        # print('is True')
        return _ANSI_SUPPORT_RESULTS #_ANSI_SUPPORT
    retry = ((vt_mode_enabled() is None and vt_mode is not Ellipsis and vt_mode) or
             (colorama_enabled() is None and colorama is not Ellipsis and colorama))
    if _ANSI_SUPPORT is False and not retry:
        # print('is False')
        return _ANSI_SUPPORT_RESULTS #_ANSI_SUPPORT
        
    import sys, os
    def handle_ansi_support(handle) -> bool:
        if os.environ.get('TERM') == 'ANSI':
            return True  # No platform test needed
        elif getattr(handle, 'isatty', bool)(): # get isatty() func, or dummy return False func()
            from platform import system  # only import if needed
            return None if (system() == 'Windows') else True
        return False
    
    results = [handle_ansi_support(h) for h in (sys.stdout, sys.stderr)]
    if any(r is None for r in results):
        vt_result = vt_mode_enabled()
        if vt_mode_enabled() is None and vt_mode is not Ellipsis:
            vt_result = (vt_mode and enable_vt_mode())
        if vt_result or colorama is Ellipsis: # ignore if vt_result fails, but we still want colorama status
            results = [(vt_result if r is None else r) for r in results]
    if any(r is None for r in results): # and (colorama is not Ellipsis):
        co_result = colorama_enabled()
        if not colorama_enabled() and colorama is not Ellipsis:
            co_result = (colorama and enable_colorama())
        results = [(co_result if r is None else r) for r in results]

    _ANSI_SUPPORT = bool(results[0] or _ANSI_SUPPORT_RESULTS[0])
    _ANSI_SUPPORT_RESULTS = tuple(bool(r or ro) for r,ro in zip(results, _ANSI_SUPPORT_RESULTS))  # we only really care about stdout
    return tuple(results)

#region ## COLORAMA ANSI SUPPORT ##

_COLORAMA_INIT:Optional[bool] = None

def colorama_enabled() -> bool:
    return _COLORAMA_INIT

def enable_colorama() -> bool:
    global _COLORAMA_INIT
    if not _COLORAMA_INIT:
        try:
            import colorama, sys
            # check if colorama was already initialized
            if ((getattr(sys.stdout, '__module__','').split('.')[0] != colorama.__package__) and 
                (getattr(sys.stderr, '__module__','').split('.')[0] != colorama.__package__)):
                colorama.init()
            _COLORAMA_INIT = True
        except ImportError:
            _COLORAMA_INIT = False
    return _COLORAMA_INIT

#endregion

#region ## WINDOWS ANSI SUPPORT

_WIN_ANSI_RESULT:Optional[bool] = None

def vt_mode_enabled() -> Optional[bool]:
    """vt_mode_enabled() -> (bool | None)

    return the state of enable_vt_mode(), None if not called yet
    """
    return _WIN_ANSI_RESULT

def enable_vt_mode() -> bool:
    """enable virtual terminal mode on Windows

    Modified from source below
    source: <https://bugs.python.org/issue30075#msg291732>
    """
    global _WIN_ANSI_RESULT
    if _WIN_ANSI_RESULT is not None:
        return _WIN_ANSI_RESULT
    from platform import system
    if system() != 'Windows':
        _WIN_ANSI_RESULT = False
        return _WIN_ANSI_RESULT
  
    import ctypes, msvcrt, os, sys
    from ctypes import wintypes

    def _check_bool(result, func, args):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return args

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    LPDWORD = ctypes.POINTER(wintypes.DWORD)
    kernel32.GetConsoleMode.errcheck = _check_bool
    kernel32.GetConsoleMode.argtypes = (wintypes.HANDLE, LPDWORD)
    kernel32.SetConsoleMode.errcheck = _check_bool
    kernel32.SetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.DWORD)

    ERROR_INVALID_PARAMETER = 0x0057
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

    def set_conout_mode(new_mode:int, mask:int=0xffffffff):
        # don't assume StandardOutput is a console.
        # open CONOUT$ instead
        fdhandle = os.open('CONOUT$', os.O_RDWR)
        try:
            handle = msvcrt.get_osfhandle(fdhandle)
            old_mode = wintypes.DWORD()
            kernel32.GetConsoleMode(handle, ctypes.byref(old_mode))
            mode = (new_mode & mask) | (old_mode.value & ~mask)
            kernel32.SetConsoleMode(handle, mode)
            return old_mode.value
        finally:
            os.close(fdhandle)

    # enable_vt_mode:
    mode = mask = ENABLE_VIRTUAL_TERMINAL_PROCESSING
    try:
        set_conout_mode(mode, mask)
        _WIN_ANSI_RESULT = True
    except WindowsError as ex:
        if ex.winerror != ERROR_INVALID_PARAMETER:
            raise
        _WIN_ANSI_RESULT = False

    return _WIN_ANSI_RESULT

#endregion

#endregion

#######################################################################################

#region ## COLOR FUNCTIONS ##

def rgbf(r:int, g:int, b:int, text:Optional[str]=None):
    return f'\x1b[38;2;{r};{g};{b}m{text or ""}'
def rgbb(r:int, g:int, b:int, text:Optional[str]=None):
    return f'\x1b[48;2;{r};{g};{b}m{text or ""}'

#endregion

#region ## COLOR NAMESPACES ##

# normal color namespaces 
Fore = SimpleNamespace(RESET='\x1b[39m', BLACK='\x1b[30m', BLUE='\x1b[34m', CYAN='\x1b[36m', GREEN='\x1b[32m', MAGENTA='\x1b[35m', RED='\x1b[31m', WHITE='\x1b[37m', YELLOW='\x1b[33m', LIGHTBLACK_EX='\x1b[90m', LIGHTBLUE_EX='\x1b[94m', LIGHTCYAN_EX='\x1b[96m', LIGHTGREEN_EX='\x1b[92m', LIGHTMAGENTA_EX='\x1b[95m', LIGHTRED_EX='\x1b[91m', LIGHTWHITE_EX='\x1b[97m', LIGHTYELLOW_EX='\x1b[93m', rgb=rgbf)
Back = SimpleNamespace(RESET='\x1b[49m', BLACK='\x1b[40m', BLUE='\x1b[44m', CYAN='\x1b[46m', GREEN='\x1b[42m', MAGENTA='\x1b[45m', RED='\x1b[41m', WHITE='\x1b[47m', YELLOW='\x1b[43m', LIGHTBLACK_EX='\x1b[100m', LIGHTBLUE_EX='\x1b[104m', LIGHTCYAN_EX='\x1b[106m', LIGHTGREEN_EX='\x1b[102m', LIGHTMAGENTA_EX='\x1b[105m', LIGHTRED_EX='\x1b[101m', LIGHTWHITE_EX='\x1b[107m', LIGHTYELLOW_EX='\x1b[103m', rgb=rgbb)
Style = SimpleNamespace(RESET_ALL='\x1b[0m', BRIGHT='\x1b[1m', DIM='\x1b[2m', NORMAL='\x1b[22m')
StyleEx = SimpleNamespace(**Style.__dict__, BOLD='\x1b[1m', ITALIC='\x1b[3m', UNDERLINE='\x1b[4m', BLINKING='\x1b[5m', INVERSE='\x1b[7m', INVISIBLE='\x1b[8m', STRIKETHROUGH='\x1b[9m')

# dummy color namespaces for disabled color
DummyFore = SimpleNamespace(**dict((k,'') for k,v in Fore.__dict__.items()))
DummyBack = SimpleNamespace(**dict((k,'') for k,v in Back.__dict__.items()))
DummyStyle = SimpleNamespace(**dict((k,'') for k,v in Style.__dict__.items()))
DummyStyleEx = SimpleNamespace(**dict((k,'') for k,v in StyleEx.__dict__.items()))


##LEGACY: dictionaries for "easier" **foreground** color formatting
# >>> '{DIM}{GREEN}{!s}{RESET_ALL}'.format('hello world', **Colors)
DummyColors = dict(**DummyFore.__dict__, **DummyStyle.__dict__)
Colors = dict(**Fore.__dict__, **Style.__dict__)


#endregion

#######################################################################################


del SimpleNamespace, Optional, Tuple, Union  # cleanup declaration-only imports
