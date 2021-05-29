#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script opcode flags and enums (mostly for variables)
"""

__version__ = '0.1.0'
__date__    = '2021-05-07'
__author__  = 'Robert Jordan'
__credits__ = '''Based off Meta Language implementation by Haeleth - 2005
Converted to Python script with extended syntax by Robert Jordan - 2021
'''

__all__ = ['MjFunction', 'MjProject']

#######################################################################################


import os
from .mjproject import MjFunction, MjProject, MjoType
from ..script import MjoScript, MjoScope, Instruction, Opcode
from typing import Any, Callable, List, Optional, Dict, Tuple, Union


def save_project(projroot:str, projname:str='mjproject.json') -> MjProject:
    projfile:str = os.path.join(projroot, projname)
    proj = create_project(projroot)
    proj.save(projfile)
    return proj

def create_project(projroot:str) -> MjProject:

    proj = MjProject()
    dirs = ['']
    def read_script(fullname:str, relfile:str):
        relfile = relfile.replace('\\', '/')
        relname = os.path.splitext(relfile)[0]
        script = MjoScript.open(fullname, lookup=True)
        functions:List[MjFunction] = []
        for funcidx in script.functions:
            func = MjFunction(funcidx.hashname, relname)
            idx = script.instruction_index_from_offset(funcidx.offset)
            for i in range(idx, idx + 3):
                if script.instructions[i].is_argcheck:
                    func.parameter_types = script.instructions[i].type_list
                    break
            functions.append(func)
            proj.function_map.setdefault(func.hash, []).append(func)
        proj.script_files.append(relname)
        proj.script_functions[relname] = functions
            
    while dirs:
        indir = dirs.pop(0)
        fulldir = os.path.join(projroot, indir) if indir else projroot
        for infile in os.listdir(fulldir):
            relname = os.path.join(indir, infile) if indir else infile
            fullname = os.path.join(fulldir, infile)
            if os.path.isdir(fullname):
                dirs.append(relname)
            elif infile.lower().endswith('.mjo'):
                read_script(fullname, relname)

    return proj
