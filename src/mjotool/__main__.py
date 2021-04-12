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
from .script import MjoScript
from .analysis import ControlFlowGraph
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


## PRINT SCRIPT ##

def print_script(filename:str, script:MjoScript, *, color:bool=False):
    """Print analyzed script IL instructions and blocks to console (PRINTS A LOT OF LINE)
    """
    cfg:ControlFlowGraph = analyze_script(script)
    colors = Colors if color else DummyColors

    print('## {}'.format(os.path.basename(filename)))
    for function in cfg.functions:
        function.print_function(color=color, end='')
        # if function.start_offset == script.main_offset:
        #     print(' {DIM}{YELLOW}entrypoint{RESET_ALL}'.format(**colors), end='')
        print(' {', end='')
        known_hash = known_hashes.USERCALLS.get(function.name_hash, None)
        if known_hash is not None:
            print('  ; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash, **colors), end='')
        print()
        for basic_block in function.basic_blocks:
            basic_block.print_basic_block(color=color)
            for instruction in basic_block.instructions:
                instruction.print_instruction(color=color)
            print()
        print()
    print()


## WRITE SCRIPT ##

def write_script(filename:str, script:MjoScript, outfilename:str):
    """Write analyzed script IL instructions and blocks to .mjil file
    """
    cfg:ControlFlowGraph = analyze_script(script)

    with open(outfilename, 'wt+', encoding='utf-8') as writer:
        # include extra indentation formatting for language grammar VSCode extension
        writer.write('/// {}\n\n'.format(os.path.basename(filename)))
        for function in cfg.functions:
            writer.write(function.format_function(color=False)) # + ' {')
            # if function.start_offset == script.main_offset:
            #     writer.write(' entrypoint')
            writer.write(' {')
            known_hash = known_hashes.USERCALLS.get(function.name_hash, None)
            if known_hash is not None:
                writer.write('  ; {}'.format(known_hash))
            writer.write('\n')
            for i,basic_block in enumerate(function.basic_blocks):
                writer.write(' ' + basic_block.format_basic_block(color=False) + '\n')
                for instruction in basic_block.instructions:
                    writer.write('  ' + instruction.format_instruction(color=False) + '\n')
                if i + 1 < len(function.basic_blocks):
                    writer.write(' \n')
                else:
                    writer.write('}\n')
            writer.write('\n')
        writer.flush()


## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog='python -m mjotool',
        description='Majiro script IL disassembler tool',
        add_help=True)

    parser.add_argument('input', metavar='MJOFILE', action='store', nargs='+',
        help='.mjo script file/directory to read')
    parser.add_argument('-C', '--no-color', dest='no_color', action='store_true', default=False,
        required=False, help='disable color printing')
    parser.add_argument('-o', '--output', metavar='MJILFILE', action='store', default=None,
        required=False, help='write to output file/directory instead of console')

    try:  # try adding research module
        from ._research import _init_parser, _init_args, do_research
        parser.add_argument('-R', '--research', action='store_true', default=False,
        required=False, help='run custom research functions that are not intended for use')
        _init_parser(parser)  # add any custom arguments needed for research
    except ImportError:
        pass  # no _research.py, no problem

    args = parser.parse_args(argv)

    color:bool = not args.no_color
    infiles:list = args.input
    outfile:str  = args.output

    if outfile is not None and len(infiles) > 1:
        raise Exception('--output option only supports one input file/directory')

    research:bool = getattr(args, 'research', False)
    if research:
        _init_args(args)  # research one-time setup

    # loop through input files/directories
    for infile in infiles:
        if not research:
            print(infile)

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
                
                if research:
                    do_research(args, path, color=color)
                else:
                    script = read_script(path)
                    if outfile is not None:
                        outpath = os.path.join(infile, os.path.splitext(name)[0] + '.mjil')
                        write_script(path, script, outpath)
                    else:
                        print_script(path, script, color=color)
        else:  # single file
            if research:
                do_research(args, infile, color=color)
            else:
                script = read_script(infile)
                if outfile is not None:
                    outpath = outfile
                    if os.path.isdir(outfile):  # write to outfile/infilename.mjil
                        name = os.path.basename(infile)
                        outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjil')
                    write_script(infile, script, outpath)
                else:
                    print_script(infile, script, color=color)

        if not research:
            print()

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

