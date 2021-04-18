#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script IL disassembler tool
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

#######################################################################################

import os
from ._util import DummyColors, Colors
from .script import MjoScript, ILFormat
from .analysis import ControlFlowGraph
from .assembler import MjILAssembler
from . import known_hashes


## READ / ANALYZE SCRIPT ##

def read_script(filename:str) -> MjoScript:
    """Read and return a MjoScript from file
    """
    with open(filename, 'rb') as f:
        return MjoScript.disassemble_script(f)

def analyze_script(script:MjoScript) -> ControlFlowGraph:
    """Return the analysis of a script's control flow, blocks, functions, etc.

    argument can also be a filename
    """
    if isinstance(script, str):  # is argument filename?
        script = read_script(script)
    return ControlFlowGraph.build_from_script(script)

def parse_script(filename:str) -> MjILAssembler:
    """Returns an assembler after parsing an .mjil assembler language file
    """
    return MjILAssembler(filename)

## PRINT SCRIPT ##

def print_script(filename:str, script:MjoScript, *, options:ILFormat=ILFormat.DEFAULT):
    """Print analyzed script IL instructions and blocks to console (PRINTS A LOT OF LINE)
    """
    cfg:ControlFlowGraph = analyze_script(script)
    options.set_address_len(script.bytecode_size)
    colors = options.colors

    # include extra indentation formatting for an easier time reading
    print('{BRIGHT}{WHITE}/// {}{RESET_ALL}'.format(os.path.basename(filename), **colors))
    script.print_readmark(options=options)
    # print()

    for function in cfg.functions:
        print()
        function.print_function(options=options)
        for i,basic_block in enumerate(function.basic_blocks):
            print(' ', end='')
            basic_block.print_basic_block(options=options)
            for instruction in basic_block.instructions:
                print('  ', end='')
                instruction.print_instruction(options=options)
            if i + 1 < len(function.basic_blocks):
                print(' ')
        function.print_function_close(options=options)
        # print()


## WRITE SCRIPT ##

def disassemble_script(filename:str, script:MjoScript, outfilename:str, *, options:ILFormat=ILFormat.DEFAULT):
    """Write analyzed script IL instructions and blocks to .mjil file
    """
    options.color = False
    options.set_address_len(script.bytecode_size)
    cfg:ControlFlowGraph = analyze_script(script)

    with open(outfilename, 'wt+', encoding='utf-8') as writer:
        # include extra indentation formatting for language grammar VSCode extension
        writer.write('/// {}\n'.format(os.path.basename(filename)))
        writer.write(script.format_readmark(options=options) + '\n')
        # writer.write('\n')

        for function in cfg.functions:
            writer.write('\n')
            writer.write(function.format_function(options=options) + '\n')
            for i,basic_block in enumerate(function.basic_blocks):
                writer.write(' ' + basic_block.format_basic_block(options=options) + '\n')
                for instruction in basic_block.instructions:
                    writer.write('  ' + instruction.format_instruction(options=options) + '\n')
                if i + 1 < len(function.basic_blocks):
                    writer.write(' \n')
            writer.write(function.format_function_close(options=options) + '\n')
            # writer.write('\n')
        writer.flush()

def assemble_script(script:MjoScript, outfilename:str):
    """Write script to .mjo file
    """
    with open(outfilename, 'wb+') as writer:
        script.signature = MjoScript.SIGNATURE_DECRYPTED
        script.assemble_script(writer)


## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog='python -m mjotool',
        description='Majiro script IL disassembler and assembler tool',
        add_help=True,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Disassembler Options:
[-G|--group] group directive
--------------------------------------------
"NAME" : strip group name from hash names that contain provided group

on|off [-H|--hash]  hashing options
--------------------------------------------
>k| K  : known_hashes  (enable all functionality below)
>a| A  : annotations   (';' comments for known hashes or hash values)
>i| I  : inline_hash   (inline hash function $name for known names)
 e|>E  : explicit_inline_hash  (explicit inline hash function ${name})
>s| S  : syscall_inline_hash   (inline hashing for syscalls - which work by lookup)
>l| L  : int_inline_hash       (inline hashing for matching int literals)
>g| G  : implicit_local_groups (strip empty @ group names from locals)

on|off [-A|--alias] aliasing/shorthand options
--------------------------------------------
 v|>V  : explicit_varoffset (remove -1 var offset for non-locals)
 m|>M  : modifier_aliases   (modifier flags: inc.x, dec.x, x.inc, x.dec)
 s|>S  : scope_aliases      (scope flags: persist, save, -, loc)
 t|>T  : vartype_aliases    (var type flags: i, r, s, iarr, rarr, sarr)
 l|>L  : typelist_aliases   (type list:      i, r, s, iarr, rarr, sarr)
 f|>F  : functype_aliases   (func arg types: i, r, s, iarr, rarr, sarr)
 d|>D  : explicit_dim0      (always include dimension flag: dim0)
""")
    #~~ i|>I  : invert_aliases~~
    parser.add_argument('-p','--print', metavar='MJO', action='append',
        help='print mjo script file/directory to the console')
    parser.add_argument('-d','--disasm', metavar=('MJO','MJIL'), action='append', nargs=2,
        help='disassemble mjo script file/directory to output file/directory')
    parser.add_argument('-a','--asm', metavar=('MJIL','MJO'), action='append', nargs=2,
        help='assemble mjil script file/directory to output file/directory')
    # parser.add_argument('input', metavar='MJO', action='store', nargs='+',
    #     help='.mjo script file/directory to read')
    parser.add_argument('-G', '--group', metavar='NAME', dest='group', action='store', default=None,
        required=False, help='group name directive disassembler option')
    parser.add_argument('-H', '--hash', metavar='FLGS', dest='hash_flags', action='store', default='',
        required=False, help='unhashing disassembler options')
    parser.add_argument('-A', '--alias', metavar='FLGS', dest='alias_flags', action='store', default='',
        required=False, help='alias naming disassembler options')
    parser.add_argument('-C', '--no-color', dest='color', action='store_false', default=True,
        required=False, help='disable color printing')
    # parser.add_argument('-o', '--output', metavar='MJIL', action='store', default=None,
    #     required=False, help='write to output file/directory instead of console')

    HASH_FLAGNAMES:dict = {
        'a': 'annotations',
        'k': 'known_hashes',
        'i': 'inline_hash',
        'e': 'explicit_inline_hash',
        's': 'syscall_inline_hash',
        'l': 'int_inline_hash',
        'g': 'implicit_local_groups',
    }
    ALIAS_FLAGNAMES:dict = {
        'v': 'explicit_varoffset',
        'm': 'modifier_aliases',
        's': 'scope_aliases',
        't': 'vartype_aliases',
        'l': 'typelist_aliases',
        'f': 'functype_aliases',
        'd': 'explicit_dim0',
    }
    HASH_FLAGNAME_LEN:int = max(len(n) for n in HASH_FLAGNAMES.values())
    ALIAS_FLAGNAME_LEN:int = max(len(n) for n in ALIAS_FLAGNAMES.values())
    FLAGNAME_LEN:int = max(HASH_FLAGNAME_LEN, ALIAS_FLAGNAME_LEN)
    
    try:  # try adding research module
        from ._research import _init_parser, _init_args, do_research
        parser.add_argument('-R', '--research', action='store_true', default=False,
        required=False, help='run custom research functions that are not intended for use')
        _init_parser(parser)  # add any custom arguments needed for research
    except ImportError:
        pass  # no _research.py, no problem

    args = parser.parse_args(argv)

    # print(args)
    # return 0

    options:ILFormat = ILFormat()

    ###########################################################################
    ##FIXME: make options configurable. for now, just change them here :)

    options.color  = args.color  # color, disabled by __main__.disassemble_script() when outputting to file
    options.braces = True  # function braces
    options.annotations  = True  # annotations that describe either known hash names, or original hashed values
    options.known_hashes = True  # check for known hash values
    options.inline_hash  = True  # inline hash function $name / ${name} for known hash values
    options.syscall_inline_hash  = True
    options.int_inline_hash      = True   # ldc.i with a known hash value will use inline hash
    options.explicit_inline_hash = False  # always use ${name} over $name
    options.implicit_local_groups= True  # always exclude empty group name from known local names

    options.explicit_varoffset   = False  # exclude -1 offset for non-locals
    options.modifier_aliases     = False  # inc.x, dec.x, x.inc...
    options.invert_aliases       = False  # (there are no aliases)
    options.scope_aliases        = False  # persist, save (shorthands)
    options.vartype_aliases      = False  # i, r, s, iarr... for variable type flags
    options.functype_aliases     = False  # i, r, s, iarr... for function signatures
    options.typelist_aliases     = False  # i, r, s, iarr... for type list operands
    options.explicit_dim0        = False  # a useless feature (but it's legal)
    
    options.group_directive      = None   # removes @GROUP for that matching this setting (DO NOT INCLUDE "@" in NAME)
    # options.group_directive      = "CONSOLE"
    ###########################################################################
    
    colors = Colors if args.color else DummyColors

    if args.group is not None:
        if '@' in args.group:
            raise argparse.ArgumentError('--group', f'"@" character cannot be present in name : {args.group!r}')
        options.group_directive = args.group
        print('{DIM}{CYAN}group opt:{RESET_ALL}'.format(**colors), '{DIM}{GREEN}{!r}{RESET_ALL}'.format(args.group, **colors))
    
    CONSUMED_HASH_FLAGS:set = set()
    CONSUMED_ALIAS_FLAGS:set = set()

    # visual names for flag on/off modes
    ONOFF:dict = {
        False: '{BRIGHT}{RED}off{RESET_ALL}'.format(**colors),
        True:  '{BRIGHT}{GREEN}on{RESET_ALL}'.format(**colors),
    }

    for f in args.hash_flags:
        if f.lower() not in HASH_FLAGNAMES:
            raise argparse.ArgumentError('--hash', f'unknown flag {f!r}')
        if f.lower() in CONSUMED_HASH_FLAGS:
            raise argparse.ArgumentError('--hash', f'flag {f!r} already used')
        CONSUMED_HASH_FLAGS.add(f.lower())
        opt_name = HASH_FLAGNAMES[f.lower()]
        opt_on = f == f.lower()
        setattr(options, opt_name, opt_on)  # lower=True
        print('{BRIGHT}{YELLOW}hash  opt:{RESET_ALL}'.format(**colors), opt_name.ljust(FLAGNAME_LEN), '=', ONOFF[opt_on])

    for f in args.alias_flags:
        if f.lower() not in ALIAS_FLAGNAMES:
            raise argparse.ArgumentError('--alias', f'unknown flag {f!r}')
        if f.lower() in CONSUMED_ALIAS_FLAGS:
            raise argparse.ArgumentError('--alias', f'flag {f!r} already used')
        CONSUMED_ALIAS_FLAGS.add(f.lower())
        opt_name = ALIAS_FLAGNAMES[f.lower()]
        opt_on = f == f.lower()
        setattr(options, opt_name, opt_on)  # lower=True
        print('{BRIGHT}{BLUE}alias opt:{RESET_ALL}'.format(**colors), opt_name.ljust(FLAGNAME_LEN), '=', ONOFF[opt_on])

    # color:bool = args.color
    # infiles:list = args.input
    # outfile:str  = args.output

    # if outfile is not None and len(infiles) > 1:
    #     raise Exception('--output option only supports one input file/directory')

    research:bool = getattr(args, 'research', False)
    if research:
        _init_args(args)  # research one-time setup

    # [--print]  loop through input files/directories
    for infile in (args.print or []):
        if not research:
            print('Printing:', infile)
        if os.path.isdir(infile):  # directory of .mjo files
            for name in os.listdir(infile):
                path = os.path.join(infile, name)
                if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjo':
                    continue
                
                if research:
                    do_research(args, path, options=options)
                else:
                    script = read_script(path)
                    print_script(path, script, options=options)
        else:  # single file
            if research:
                do_research(args, infile, options=options)
            else:
                script = read_script(infile)
                print_script(infile, script, options=options)
        if not research:
            print()

    # [--disasm]  loop through input files/directories
    for infile,outfile in (args.disasm or []):
        if not research:
            print('Disassembling:', infile)
        if os.path.isdir(infile):  # directory of .mjo files
            if outfile is not None:
                if os.path.isfile(outfile):
                    raise Exception('Cannot use output "{!s}" because it is not a directory'.format(outfile))
                elif not os.path.exists(outfile):
                    raise Exception('Output directory "{!s}" does not exist'.format(outfile))
            for name in os.listdir(infile):
                path = os.path.join(infile, name)
                if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjo':
                    continue

                script = read_script(path)
                outpath = os.path.join(infile, os.path.splitext(name)[0] + '.mjil')
                disassemble_script(path, script, outpath, options=options)
        else:  # single file
            script = read_script(infile)
            outpath = outfile
            if os.path.isdir(outfile):  # write to outfile/infilename.mjil
                name = os.path.basename(infile)
                outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjil')
            disassemble_script(infile, script, outpath, options=options)
        if not research:
            print()

    # [--asm]  loop through input files/directories
    for infile,outfile in (args.asm or []):
        if not research:
            print('Assembling:', infile)
        if os.path.isdir(infile):  # directory of .mjil files
            if outfile is not None:
                if os.path.isfile(outfile):
                    raise Exception('Cannot use output "{!s}" because it is not a directory'.format(outfile))
                elif not os.path.exists(outfile):
                    raise Exception('Output directory "{!s}" does not exist'.format(outfile))
            for name in os.listdir(infile):
                path = os.path.join(infile, name)
                if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjil':
                    continue
                
                assembler = parse_script(path)
                assembler.read()
                outpath = os.path.join(infile, os.path.splitext(name)[0] + '.mjo')
                assemble_script(assembler.script, outpath)
        else:  # single file
            assembler = parse_script(infile)
            assembler.read()
            outpath = outfile
            if os.path.isdir(outfile):  # write to outfile/infilename.mjil
                name = os.path.basename(infile)
                outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjo')
            assemble_script(assembler.script, outpath)
        if not research:
            print()

    # # loop through input files/directories
    # for infile in infiles:
    #     if not research:
    #         print(infile)

    #     if os.path.isdir(infile):  # directory of .mjo files
    #         if outfile is not None:
    #             if os.path.isfile(outfile):
    #                 raise Exception('Cannot use output "{!s}" because it is not a directory'.format(outfile))
    #             elif not os.path.exists(outfile):
    #                 raise Exception('Output directory "{!s}" does not exist'.format(outfile))
    #         for name in os.listdir(infile):
    #             path = os.path.join(infile, name)
    #             if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjo':
    #                 continue
                
    #             if research:
    #                 do_research(args, path, options=options)
    #             else:
    #                 script = read_script(path)
    #                 if outfile is not None:
    #                     outpath = os.path.join(infile, os.path.splitext(name)[0] + '.mjil')
    #                     disassemble_script(path, script, outpath, options=options)
    #                 else:
    #                     print_script(path, script, options=options)
    #     else:  # single file
    #         if research:
    #             do_research(args, infile, options=options)
    #         else:
    #             script = read_script(infile)
    #             if outfile is not None:
    #                 outpath = outfile
    #                 if os.path.isdir(outfile):  # write to outfile/infilename.mjil
    #                     name = os.path.basename(infile)
    #                     outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjil')
    #                 disassemble_script(infile, script, outpath, options=options)
    #             else:
    #                 print_script(infile, script, options=options)

    #     if not research:
    #         print()

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

