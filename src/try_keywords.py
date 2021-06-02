#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""CRC-32 keyword-based unhasher

Unhash CRC-32 names by combining keywords.
"""

__version__ = '1.0.1'
__date__    = '2021-06-02'
__author__  = 'Robert Jordan'

#######################################################################################

## runtime imports:
# import traceback        # for error reporting while handling KeyboardInterrupt, and in verbose log files
# import argparse         # used in main()
# 
# # used in main() for optional color output (imports colorama if present, otherwise relies on terminal ANSI color support)
# from mj.util.color import Fore, Style, DummyFore, DummyStyle

from datetime import datetime

from mj.crypt import hash32, invhash32
from mj.util.typecast import to_bytes, to_str
from mj.database.unhashers import KeywordsConfig, KeywordUnhasher


#######################################################################################         

#region ## UTILITIES AND HELPERS ##

def list_to_str(items:list) -> list: return [to_str(s) for s in items]

#endregion

#######################################################################################         

## MAIN FUNCTION ##

def main(argv:list=None) -> int:

    #region ## PARSER SETUP ##
    import argparse
    parser = argparse.ArgumentParser(
        description='CRC-32 keyword-based unhasher. Recover CRC-32-hashed names by combining keywords.',
        add_help=True)

    ##NOTE: taken from argparse.py (CPython 3.6.8)
    # def _get_action_name(argument):
    def arg_repr(argument) -> str:
        if argument is None:
            return None
        elif argument.option_strings:
            return  '/'.join(argument.option_strings)
        elif argument.metavar not in (None, argparse.SUPPRESS):
            return argument.metavar
        elif argument.dest not in (None, argparse.SUPPRESS):
            return argument.dest
        else:
            return None
    def list_arg_repr(*arguments) -> list:
        return [arg_repr(a) for a in arguments]


    # inputs:
    group = parser.add_argument_group('input arguments', 'input keywords and target results, and optional pre/postfixes and groups')
    arg_t = group.add_argument('-t','--target', dest='targets', nargs='+', type=lambda v: int(v, 16), required=True,
        metavar='HEXVAL', help='include target hash values (required)')
    arg_w = group.add_argument('-w','--words',  dest='words',   nargs='+', default=[],
        metavar='WORD', help='include keywords (auto, variations applied) (required)')
    arg_W = group.add_argument('-W','--words-raw', dest='words_raw', nargs='+', default=[],
        metavar='WORD_RAW', help='include keywords (raw, no variations) (required)')
    
    # group = parser.add_argument_group('optional input arguments') #, 'additional prefixes, postfixes, and groups')
    arg_g = group.add_argument('-g','--groups',     dest='groups',     nargs='+', default=[],
        metavar='GROUP', help='include group names (auto, \'@\' is prepended)')
    arg_G = group.add_argument('-G','--groups-raw', dest='groups_raw', nargs='+', default=[], #type=lambda v: f'@{v}'
        metavar='GROUP_RAW', help='include group names (raw, \'@\' is not prepended)')
    arg_p = group.add_argument('-p','--prefixes',  dest='prefixes',  nargs='+', default=[],
        metavar='PRE', help='include prefixes (before keywords)')
    arg_P = group.add_argument('-P','--postfixes', dest='postfixes', nargs='+', default=[],
        metavar='POST', help='include postfixes (before group name)')

    # scan:
    group = parser.add_argument_group('scan options')
    arg_m = group.add_argument('-m','--min', dest='minlen', type=int, default=0,
        help=f'minimum word-depth to search at (default={0})')
    arg_M = group.add_argument('-M','--max', dest='maxlen', type=int, default=0xffffffff,
        help=f'maximum word-depth to search at (inclusive)')

    # variations:
    group = parser.add_argument_group('variation options', f'variations applied to passed-in keywords from {arg_repr(arg_w)}')
    group_n = group.add_mutually_exclusive_group(required=False)
    arg_n = group_n.add_argument('-n','--normal',    dest='normal', action='store_true', default=True,
        help='include original keywords (default)')
    arg_N = group_n.add_argument('-N','--no-normal', dest='normal', action='store_false',
        help='exclude original keywords')
    group_l = group.add_mutually_exclusive_group(required=False)
    arg_l = group_l.add_argument('-l','--lower',    dest='lower', action='store_true', default=False,
        help='include lowercase keywords')
    arg_L = group_l.add_argument('-L','--no-lower', dest='lower', action='store_false',
        help='exclude lowercase keywords (default)')
    group_u = group.add_mutually_exclusive_group(required=False)
    arg_u = group_u.add_argument('-u','--upper',    dest='upper', action='store_true', default=False,
        help='include UPPERCASE keywords')
    arg_U = group_u.add_argument('-U','--no-upper', dest='upper', action='store_false',
        help='exclude UPPERCASE keywords (default)')
    group_c = group.add_mutually_exclusive_group(required=False)
    arg_c = group_c.add_argument('-c','--capital',    dest='capitalize', action='store_true', default=False,
        help='include Capitalized keywords')
    arg_C = group_c.add_argument('-C','--no-capital', dest='capitalize', action='store_false',
        help='exclude Capitalized keywords (default)')
    group_s = group.add_mutually_exclusive_group(required=False)
    arg_s = group_s.add_argument('-s','--underscore',    dest='underscore', action='store_true', default=False,
        help='include underscore-appended_ keywords')
    arg_S = group_s.add_argument('-S','--no-underscore', dest='underscore', action='store_false',
        help='exclude underscore-appended_ keywords (default)')
    group_r = group.add_mutually_exclusive_group(required=False)
    arg_r = group_r.add_argument('-r','--trailing',    dest='trailing', action='store_true', default=True,
        help='include underscore-appended_ keywords for last word in depth (default)')
    arg_R = group_r.add_argument('-R','--no-trailing', dest='trailing', action='store_false',
        help=f'exclude underscore-appended_ keywords for last word in depth (requires {arg_repr(arg_s)})')

    # visuals:
    group = parser #parser.add_argument_group('visual options', 'display and console output')
    group.add_argument('--version', action='version', version=f'CRC-32 keyword-based unhasher : v{__version__} ({__date__})')
    group_prv = group.add_mutually_exclusive_group(required=False)
    group_prv.add_argument('--verbose',    dest='verbose', action='store_true', default=True,
        help='print prepared variations preview (default)')
    group_prv.add_argument('-q','--quiet', dest='verbose', action='store_false',
        help='do not print prepared variations preview')

    group_col = group.add_mutually_exclusive_group(required=False)
    group_col.add_argument('--color',    dest='color', action='store_true', default=True,
        help='enable console color output (default)')
    group_col.add_argument('--no-color', dest='color', action='store_false',
        help='disable console color output')

    group_tim = group.add_mutually_exclusive_group(required=False)
    group_tim.add_argument('--time',     dest='show_time', action='store_const', const='local', default=None,
        help='print local times in-front of matches')
    group_tim.add_argument('--time-utc', dest='show_time', action='store_const', const='utc',
        help='print UTC times in-front of matches')

    group_log = group.add_mutually_exclusive_group(required=False)
    group_log.add_argument('--log',         dest='log',         default=None,
        metavar='LOGFILE', help='output only matches to log file')
    group_log.add_argument('--log-verbose', dest='log_verbose', default=None,
        metavar='LOGFILE', help='output all information and matches to log file')
    #endregion

    ###########################################################################

    args = parser.parse_args(argv)

    # print(args)
    # return 0

    if not args.words and not args.words_raw:
        parser.error(f'one of the following arguments are required: {list_arg_repr(arg_w, arg_W)}')
    if not args.normal and not args.upper and not args.lower and not args.capitalize and not args.underscore:
        parser.error(f'all word variations are turned off! one of the following arguments are required: {list_arg_repr(arg_W, arg_n, arg_l, arg_u, arg_c, arg_s)}')

    config = KeywordsConfig()
    for k,v in args.__dict__.items():
        if hasattr(config, k):
            setattr(config, k, v)

    from mj.util.color import Fore, Style, DummyFore, DummyStyle
    F, S = (Fore, Style) if args.color else (DummyFore, DummyStyle)

    logfile = None
    finished = False

    ###########################################################################

    def gettime(sep:str='\t'):
        if args.show_time is None:
            return ''
        timekind = datetime.utcnow() if args.show_time == 'utc' else datetime.now()
        return f'[{timekind.strftime("%Y-%m-%d %H:%M:%S")}]{sep}'

    def result_callback(unhasher:KeywordUnhasher, depth:int, prefix:str, words:tuple, postfix:str, group:str, result:int):
        time = gettime()

        if logfile:
            logfile.write(f'{time}{result:08x}\t{prefix}{"".join(words)}{postfix}{group}\n')
            logfile.flush()

        prefix  = f'{S.BRIGHT}{F.CYAN}{prefix}{S.RESET_ALL}'
        words   = f'{S.BRIGHT}{F.BLUE}{"".join(words)}{S.RESET_ALL}'
        postfix = f'{S.DIM}{F.CYAN}{postfix}{S.RESET_ALL}'
        group   = f'{S.DIM}{F.GREEN}{group}{S.RESET_ALL}'
        result  = f'{S.BRIGHT}{F.RED}{result:08x}{S.RESET_ALL}'
        print(f'{S.BRIGHT}{F.BLACK}{time}{S.RESET_ALL}{result}\t{prefix}{words}{postfix}{group}')

    ###########################################################################

    unhasher = KeywordUnhasher(config, callback=result_callback)

    if args.log or args.log_verbose:
        logfile = open(args.log_verbose if args.log is None else args.log, 'at', encoding='utf-8')

    try:
        COUNT_KEYS = ('prefixes', 'postfixes', 'groups', 'words', 'targets')
        time = gettime()
        if logfile and args.log_verbose:
            # verbose ensures newline-separation
            logfile.write('\n')
            logfile.flush()

            logfile.write(f'{time}[verbose]\tbegin\n')
            logfile.write(f'[info]\t   COUNTS:\t{", ".join(f"{len(getattr(unhasher, k))} {k}" for k in COUNT_KEYS)}\n')
            logfile.write(f'[info]\t PREFIXES:\t{", ".join(list_to_str(unhasher.prefixes))}\n')
            logfile.write(f'[info]\tPOSTFIXES:\t{", ".join(list_to_str(unhasher.postfixes))}\n')
            logfile.write(f'[info]\t   GROUPS:\t{", ".join(list_to_str(unhasher.groups))}\n')
            logfile.write(f'[info]\t    WORDS:\t{", ".join(list_to_str(unhasher.words))}\n')
            logfile.write(f'[info]\t  TARGETS:\t{", ".join(f"{t:08x}" for t,_,_ in unhasher.targets.values())}\n')
            logfile.flush()

        if args.verbose:
            print(  '   COUNTS:', ', '.join(f'{S.BRIGHT}{F.WHITE}{len(getattr(unhasher, k))} {k!s}{S.RESET_ALL}' for k in COUNT_KEYS))
            print('\n PREFIXES:', ', '.join(f'{S.BRIGHT}{F.CYAN}{s!s}{S.RESET_ALL}' for s in list_to_str(unhasher.prefixes)))
            print('\nPOSTFIXES:', ', '.join(f'{S.DIM}{F.CYAN}{s!s}{S.RESET_ALL}' for s in list_to_str(unhasher.postfixes)))
            print('\n   GROUPS:', ', '.join(f'{S.DIM}{F.GREEN}{s!s}{S.RESET_ALL}' for s in list_to_str(unhasher.groups)))
            print('\n    WORDS:', ', '.join(f'{S.BRIGHT}{F.YELLOW}{s!s}{S.RESET_ALL}' for s in list_to_str(unhasher.words)))
            print('\n  TARGETS:', ', '.join(f'{S.BRIGHT}{F.RED}{t:08x}{S.RESET_ALL}' for t,_,_ in unhasher.targets.values()))
            print('\n  EXPECTS:', ', '.join(f'{S.DIM}{F.RED}{t:08x}{S.RESET_ALL}' for t in unhasher.targets.keys()))
        else:
            print(f'{S.BRIGHT}{F.BLACK}{time}{S.RESET_ALL}[Begin]')

        if not unhasher.is_multitarget:
            if logfile and args.log_verbose:
                logfile.write(f'{time}[info]\tsingletarget\n')
                logfile.flush()
            if args.verbose:
                print(f'{S.BRIGHT}{F.GREEN}[Single Target Mode]{S.RESET_ALL}')

        for n in range(config.minlen, config.maxlen+1):
            time = gettime()
            if logfile and args.log_verbose:
                logfile.write(f'{time}[info]\tdepth={n:d}\n')
                logfile.flush()
            if args.verbose:
                print(f'{S.BRIGHT}{F.BLACK}{time}{S.RESET_ALL}Word Depth: {n:d}')
            unhasher.do_depth(n)

        finished = True
        time = gettime()
        if logfile and args.log_verbose:
            logfile.write(f'{time}[verbose]\tfinished\n')
        print(f'{S.BRIGHT}{F.BLACK}{time}{S.RESET_ALL}{S.BRIGHT}{F.WHITE}[Finished]{S.RESET_ALL}')

    ###########################################################################

    except KeyboardInterrupt:
        # cleanly kill the process upon user-request:
        #  (remove this when killing the process to find the source hangups)
        time = gettime()
        if logfile and args.log_verbose:
            logfile.write(f'{time}[verbose]\texited\n')
        print(f'{S.BRIGHT}{F.BLACK}{time}{S.RESET_ALL}{S.BRIGHT}{F.BLACK}[Exited]{S.RESET_ALL}')
    except Exception as ex:
        import traceback
        time = gettime()
        print(f'{S.BRIGHT}{F.BLACK}{time}{S.RESET_ALL}[Error]\n{S.BRIGHT}{F.RED}{traceback.format_exc().rstrip()}{S.RESET_ALL}')  # rstrip, traceback may end in '\n'
        if logfile:
            if args.log_verbose:
                logfile.write(f'{time}[error]\n{traceback.format_exc().rstrip()}\n')  # rstrip, traceback may end in '\n'
            else:
                logfile.write(f'{time}[error]\n{ex}\n')
    finally:
        if logfile:
            logfile.flush()
            logfile.close()
            logfile = None

    return 0 if finished else 1


###########################################################################

## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

