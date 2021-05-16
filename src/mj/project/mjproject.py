#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-07'
__author__  = 'Robert Jordan'
__credits__ = '''Based off Meta Language implementation by Haeleth - 2005
Converted to Python script with extended syntax by Robert Jordan - 2021
'''

__all__ = ['MjFunction', 'MjProject']

#######################################################################################

from typing import Dict, List, Optional, Tuple

from ..script.flags import MjoType
# from ..name import basename
from ..identifier import HashName, HashValue, IdentifierKind #, Typedef

class MjFunction:
    def __init__(self, hashname:HashName=HashName(0,IdentifierKind.FUNCTION), declaring_script:Optional[str]=None, parameter_types:Optional[List[MjoType]]=None):
        self._hashname:HashName = HashName(hashname, IdentifierKind.FUNCTION)
        self.declaring_script:str = declaring_script
        self.parameter_types:List[MjoType] = parameter_types
    @property
    def hashname(self) -> HashName:
        return self._hashname
    @hashname.setter
    def hashname(self, value:HashName):
        self._hashname = HashName(value, IdentifierKind.FUNCTION)
    @property
    def hash(self) -> int:
        return self._hashname.hash
    @hash.setter
    def hash(self, value:int) -> int:
        if value != self._hashname.hash:
            self._hashname = HashName(value, IdentifierKind.FUNCTION)
    @property
    def name(self) -> str:
        return self._hashname.name
    @name.setter
    def name(self, value:str):
        if value is None:
            if self._hashname.name is not None:
                self._hashname = HashName(self._hashname.hash, IdentifierKind.FUNCTION)
        elif value != self._hashname.name:
            self._hashname = HashName(value, IdentifierKind.FUNCTION)

    def serialize(self) -> dict:
        return {
            'Hash': int(self._hashname.hash),
            'Name': self._hashname.name,
            'DeclaringScript': self.declaring_script,
            'ParameterTypes': None if self.parameter_types is None else [t.value for t in self.parameter_types],
        }
    @classmethod
    def deserialize(cls, data:dict) -> 'MjFunction':
        hash, name = data.get('Hash'), data.get('Name')
        declaring_script = data.get('DeclaringScript')
        parameter_types = data.get('ParameterTypes')
        if name is None:
            hashname = HashName(hash, IdentifierKind.FUNCTION)
        else:
            hashname = HashName(name, IdentifierKind.FUNCTION, hash=hash)
        if parameter_types is not None:
            parameter_types = [MjoType(t) for t in parameter_types]
        return MjFunction(hashname, declaring_script, parameter_types)


class MjProject:
    def __init__(self, script_files:List[str]=None, script_functions:Dict[str,List[MjFunction]]=None, function_map:Dict[int,List[MjFunction]]=None):
        self.script_files:List[str] = [] if script_files is None else script_files
        self.script_functions:Dict[str,List[MjFunction]] = {} if script_functions is None else script_functions
        self.function_map:Dict[int,List[MjFunction]] = {} if function_map is None else function_map
    
    def try_get_function_name(self, hash:HashValue) -> str:
        functions:List[MjFunction] = self.function_map.get(hash)
        if not functions:
            return None
        return functions[0].name
    
    def save(self, filename:str):
        import json
        with open(filename, 'wt+', encoding='utf-8') as writer:
            json.dump(self.serialize(), writer, skipkeys=False, indent='\t', ensure_ascii=False)
            writer.flush()

    @classmethod
    def load(cls, filename:str) -> 'MjProject':
        import json
        with open(filename, 'rt', encoding='utf-8') as reader:
            data = json.load(reader) #, skipkeys=False, indent='\t')
            return cls.deserialize(data)

    
    def serialize(self) -> dict:
        funcs:List[Tuple[MjFunction, dict]] = []
        def get_func(func:MjFunction) -> dict:
            # avoid instance duplication when possible
            for other,funcdata in funcs:
                if other.hash == func.hash and other.name == func.name and other.declaring_script == func.declaring_script and other.parameter_types == func.parameter_types:
                    return funcdata
            funcs.append((func, func.serialize()))
            return funcs[-1][1]
        return {
            'ScriptFiles': self.script_files,
            'ScriptFunctions': dict((k,[get_func(f) for f in v]) for k,v in self.script_functions.items()),
            'FunctionMap': dict((int(k),[get_func(f) for f in v]) for k,v in self.function_map.items()),
        }

    @classmethod
    def deserialize(cls, data:dict) -> 'MjProject':
        script_files = data.get('ScriptFiles')
        script_functions = data.get('ScriptFunctions')
        function_map = data.get('FunctionMap')
        funcs:List[MjFunction] = []
        def get_func(funcdata:dict) -> MjFunction:
            func = MjFunction.deserialize(funcdata)
            # avoid instance duplication when possible
            for other in funcs:
                if other.hash == func.hash and other.name == func.name and other.declaring_script == func.declaring_script and other.parameter_types == func.parameter_types:
                    return other
            funcs.append(func)
            return func
        if script_functions is not None:
            script_functions = dict((k,[get_func(f) for f in v] if v is not None else None) for k,v in script_functions.items())
        if function_map is not None:
            # cast k to int, because JSON keys are always stored as strings
            function_map = dict((int(k),[get_func(f) for f in v] if v is not None else None) for k,v in function_map.items())
        return MjProject(script_files, script_functions, function_map)
        

