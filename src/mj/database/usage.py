#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script analyzer
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['UsageDatabase', 'ScriptUsageDatabase', 'FunctionUsageDatabase', 'UsageScope', 'UsageMask', 'load_game_usage', 'load_script_usage', 'read_script_usage', 'read_function_usage', 'load_function_usage']

#######################################################################################

## runtime imports:
# from .hashes import ...  # used to locate known hash names in multiple functions
# from .sheets import SheetSyscalls, RowSyscall, Status, Typedef  # used for Root UsageDatabase.__init__() to load syscalls

import enum, os
from typing import Dict, List, Optional, Tuple, Union

from ..crypt import hash32

from ..util.color import Fore as F, StyleEx as S
from ..util.typecast import to_bytes, to_str, to_float, unsigned_I, signed_i

from ..name import GROUP_SYSCALL, GROUP_DEFAULT, GROUP_LOCAL, LOCALVAR_NUMPARAMS, THREADVAR_INTERNALCASE, postfixsymbol
from ..identifier import HashValue, verify

from ..script.flags import MjoType, MjoScope, MjoInvert, MjoModifier, MjoDimension, MjoFlags
from ..script.opcodes import Opcode
from ..script.instruction import Instruction
from ..script.mjoscript import MjoScript
from ..script.analysis.control import Function, ControlFlowGraph

# from ..archive.arcfile import MajiroArcFile


#######################################################################################

## READ / ANALYZE SCRIPT ##

def read_script(filename:str) -> MjoScript:
    """Read and return a MjoScript from file
    """
    with open(filename, 'rb') as f:
        return MjoScript.read(f)

def analyze_script(script:Union[MjoScript,str]) -> ControlFlowGraph:
    """Return the analysis of a script's control flow, blocks, functions, etc.

    argument can also be a filename
    """
    if isinstance(script, str):  # is argument filename?
        script = read_script(script)
    return ControlFlowGraph.build_from_script(script)


#######################################################################################

class UsageMask(enum.IntFlag):
    NONE      = 0
    REFERENCE = (1 << 0)  # 'X' (ldc.i ${funchash}, FUTURE: include passing pointers to functions?)
    CALL      = (1 << 1)  # 'C' (call, syscall)
    #REFERENCE_CALL = REFERENCE | CALL

    READ      = (1 << 2)  # 'R' (ld, excludes: inc/dec -> pop, call/syscall where return is used)
    ACCESS    = (1 << 3)  # 'A' (ldelem)
    #READ_ACCESS = READ | ACCESS

    WRITE     = (1 << 4)  # 'W' (st, ld inc/dec)
    MODIFY    = (1 << 5)  # 'M' (stelem, FUTURE: include passing pointers to functions?)
    #WRITE_MODIFY = WRITE | MODIFY
    
    DEFINE    = (1 << 6)  # 'D' (not displayed)
    
    @property
    def letters(self) -> str:
        if not self: return ''
        s = ''
        if self & (UsageMask.REFERENCE | UsageMask.CALL | UsageMask.READ | UsageMask.ACCESS):
            if self & UsageMask.REFERENCE: s += 'X'
            if self & UsageMask.CALL:      s += 'C'
            # if self & (UsageMask.READ | UsageMask.ACCESS):
            #     if s: s += '/'
            if self & UsageMask.READ:      s += 'R'
            if self & UsageMask.ACCESS:    s += 'A'
        if self & (UsageMask.WRITE | UsageMask.MODIFY):
            if s: s += '/'
            if self & UsageMask.WRITE:     s += 'W'
            if self & UsageMask.MODIFY:    s += 'M'
        if s and not '/' in s: s += 'o'  # only one "group" of usage (reference/read -or- write)
        return s
    @property
    def display(self) -> str:
        if not self: return ''
        return f'[{self.letters}]'

#######################################################################################


class BasicIdentifier:
    __slots__ = ('scope', 'hash', 'type', 'name')
    scope:MjoScope
    hash:Optional[HashValue]
    type:Optional[MjoType]
    name:Optional[str]
    #
    SYSCALL_PREFIX:str = 'sys'
    NO_HASH:str = '????????'
    #
    def __init__(self, scope:MjoScope, hash:Optional[HashValue]=None, type:Optional[MjoType]=None, name:Optional[str]=None):
        self.scope = MjoScope(scope)
        # self.var_offset = var_offset
        self.hash = HashValue(hash) if hash is not None else None
        self.type = MjoType(type) if type is not None else None #MjoType.UNKNOWN
        self.name = name
        if name is None and scope is not None and hash is not None:
            from .hashes import LOCAL_VARS, THREAD_VARS, SAVEFILE_VARS, PERSISTENT_VARS, FUNCTIONS, SYSCALLS
            if self.scope is MjoScope.LOCAL:
                self.name = LOCAL_VARS.get(hash)
            elif self.scope is MjoScope.THREAD:
                self.name = THREAD_VARS.get(hash)
            elif self.scope is MjoScope.SAVEFILE:
                self.name = SAVEFILE_VARS.get(hash)
            elif self.scope is MjoScope.PERSISTENT:
                self.name = PERSISTENT_VARS.get(hash)
            elif self.scope is MjoScope.FUNCTION:
                self.name = FUNCTIONS.get(hash)
            elif self.scope is MjoScope.SYSCALL:
                self.name = SYSCALLS.get(hash)

    @property
    def value(self) -> int: return self.hash
    @value.setter
    def value(self, value:int) -> None: self.hash = value
    @property
    def is_var(self) -> bool: return self.scope.is_var
    @property
    def is_local_var(self) -> bool: return self.scope.is_local_var
    @property
    def is_global_var(self) -> bool: return self.scope.is_global_var
    @property
    def is_func(self) -> bool: return self.scope.is_func
    @property
    def is_call(self) -> bool: return self.scope.is_call
    @property
    def is_syscall(self) -> bool: return self.scope.is_syscall

    def __repr__(self) -> str:
        return self.name if self.name is not None else self.hash_repr()
    __str__ = __repr__

    def hash_repr(self) -> str:
        # usagestr = f' [{usage.letters}]' if self.usage else ''
        typestr  = self.type.postfix if self.type  is not None else '?'
        scopestr = self.scope.prefix if self.scope is not None else '?'
        if self.is_syscall: scopestr = self.SYSCALL_PREFIX
        hashstr  = f'{self.hash:08x}' if self.hash is not None else self.NO_HASH
        return f'{scopestr}{{{hashstr}}}{typestr}'
        # return f'{scopestr}{{{hashstr}}}{typestr}{usagestr}'

#######################################################################################

class UsageInfo:
    __slots__ = ('item', 'usage', 'count')
    item:Union[BasicIdentifier,Opcode]
    usage:UsageMask
    count:int

    def __init__(self, item:Union[BasicIdentifier,Opcode], usage:UsageMask=UsageMask.NONE, count:int=0):
        self.item = item
        self.usage = usage
        self.count = count

    def __getattr__(self, name):
        return self.item.__getattribute__(name)
    def __setattr__(self, name, value):
        if name not in self.__slots__:
            self.item.__setattr__(name, value)
        super().__setattr__(name, value)

    def __repr__(self) -> str:
        usagestr = f' [{self.usage.letters}]' if (self.usage & ~UsageMask.DEFINE) is not None else ''
        return f'{self.item!r}{usagestr}'
    __str__ = __repr__

    def merge_usage(self, other:'UsageInfo'):
        self.count += other.count
            
    def update_usage(self, usage:UsageMask, *args):
        self.usage |= usage
        if usage & ~UsageMask.DEFINE:
            self.count += 1
        # if usage & UsageMask.DEFINE:
        #     self.defines[int(hash)] = info

class LocalUsageInfo(UsageInfo):
    __slots__ = UsageInfo.__slots__ + ('var_offset',)
    var_offset:Optional[int]

    def __init__(self, item:BasicIdentifier, usage:UsageMask=UsageMask.NONE, count:int=0):
        super().__init__(item, usage, count)
        self.var_offset = None

    def merge_usage(self, other:'LocalUsageInfo'):
        super().merge_usage(other)
        if other.var_offset is not None:
            self.var_offset = other.var_offset  #TODO: keep this?
    def update_usage(self, usage:UsageMask, var_offset:int=None, *args):
        super().update_usage(usage, *args)
        # if var_offset is not None:
        #     if   self.var_offset is None: self.var_offset = var_offset
        #     elif self.var_offset != type: print(f'mismatch var_offset: {self!r}')
            

class FunctionUsageInfo(UsageInfo):
    __slots__ = UsageInfo.__slots__ + ('arg_counts', 'voidcalls')
    arg_counts:Dict[int,int]
    voidcalls:int

    def __init__(self, item:BasicIdentifier, usage:UsageMask=UsageMask.NONE, count:int=0):
        super().__init__(item, usage, count)
        self.arg_counts = {}  # type: Dict[int,int]
        self.voidcalls = 0

    @property
    def returncalls(self) -> int: return self.count - self.voidcalls

    def merge_usage(self, other:'FunctionUsageInfo'):
        super().merge_usage(other)
        for arg_num,count in other.arg_counts.items():
            self.arg_counts[arg_num] = self.arg_counts.setdefault(arg_num, 0) + count
        self.voidcalls += other.voidcalls
    def update_usage(self, usage:UsageMask, arg_num:int=None, voidcall:bool=None, *args):
        super().update_usage(usage, *args)
        if arg_num is not None:
            self.arg_counts[arg_num] = self.arg_counts.setdefault(arg_num, 0) + 1
        if voidcall:
            self.voidcalls += 1


#######################################################################################

class UsageScope(enum.IntEnum):
    ALL      = 0
    GAME     = 1
    SCRIPT   = 2
    FUNCTION = 3

LOCAL_NUMPARAMS = BasicIdentifier(MjoScope.LOCAL, hash32(LOCALVAR_NUMPARAMS), MjoType.INT, LOCALVAR_NUMPARAMS)
THREAD_OPINTERNALCASE = BasicIdentifier(MjoScope.THREAD, hash32(THREADVAR_INTERNALCASE), MjoType.INT, THREADVAR_INTERNALCASE)

class UsageDatabase:
    scope:UsageScope
    name:str
    parent:'UsageDatabase'
    children:List['UsageDatabase']

    locals:Dict[int,UsageInfo]
    threads:Dict[int,UsageInfo]
    saves:Dict[int,UsageInfo]
    persists:Dict[int,UsageInfo]
    #Dict[MjoType,Dict[int,UsageInfo]]
    calls:Dict[int,UsageInfo]
    syscalls:Dict[int,UsageInfo]
    opcodes:Dict[int,UsageInfo]

    defines:Dict[int,UsageInfo]

    scopes:Dict[Union[MjoScope,type],Dict[int,UsageInfo]]

    def __init__(self, scope:Union[UsageScope,Opcode], name:str, parent:'UsageDatabase'=None, *, cached:bool=True):
        self.scope  = scope
        self.name   = name
        self.parent = parent
        self.children = []

        self.locals   = {}
        self.threads  = {}
        self.saves    = {}
        self.persists = {}
        self.calls    = {}
        self.syscalls = {}
        self.opcodes = {}
        
        self.defines = {}
        self.scopes  = {
            MjoScope.PERSISTENT: self.persists,
            MjoScope.SAVEFILE: self.saves,
            MjoScope.THREAD: self.threads,
            MjoScope.LOCAL: self.locals,
            MjoScope.FUNCTION: self.calls,
            MjoScope.SYSCALL: self.syscalls,
            Opcode: self.opcodes,
        }
        
        if parent is None:
            from .sheets import SheetSyscalls, RowSyscall, Status, Typedef as Csv_Typedef
            # Preload special identifiers
            self.locals[LOCAL_NUMPARAMS.hash] = UsageInfo(LOCAL_NUMPARAMS)
            self.threads[THREAD_OPINTERNALCASE.hash] = UsageInfo(THREAD_OPINTERNALCASE)
            # self.update_identifier(MjoScope.LOCAL, hash32(LOCALVAR_NUMPARAMS), MjoType.INT, LOCALVAR_NUMPARAMS)
            # self.update_identifier(MjoScope.THREAD, hash32(THREADVAR_INTERNALCASE), MjoType.INT, THREADVAR_INTERNALCASE)
            
            # define all syscalls...
            #if sheet_syscalls is None:
            cache_file = f'sheet_{SheetSyscalls.NAME}_cached.csv'
            if cached and os.path.isfile(cache_file):
                sheet_syscalls = SheetSyscalls.fromfile(cache_file)
            else:
                sheet_syscalls = SheetSyscalls.fromsheet(cache_file=cache_file)
            typedefs = { 
                Csv_Typedef.UNKNOWN:  None,
                Csv_Typedef.VOID:     MjoType.VOID,

                Csv_Typedef.ANY:      MjoType.INT,
                Csv_Typedef.ANY_VOID: MjoType.INT,
                Csv_Typedef.INT_UNK:  MjoType.INT,
                Csv_Typedef.INT:      MjoType.INT,
                Csv_Typedef.BOOL:     MjoType.INT,
                Csv_Typedef.FILE:     MjoType.INT,
                Csv_Typedef.PAGE:     MjoType.INT,
                Csv_Typedef.SPRITE:   MjoType.INT,

                Csv_Typedef.FLOAT:    MjoType.FLOAT,
                Csv_Typedef.STRING:   MjoType.STRING,
                Csv_Typedef.INT_ARRAY:    MjoType.INT_ARRAY,
                Csv_Typedef.FLOAT_ARRAY:  MjoType.FLOAT_ARRAY,
                Csv_Typedef.STRING_ARRAY: MjoType.STRING_ARRAY,
            }  # type: Dict[Csv_Typedef, Union[MjoType,None]]
            def add_syscall_row(row:RowSyscall):
                name = row.name if row.status in (Status.UNHASHED, Status.CONFIRMED) else None
                type = typedefs[row.type] if row.type is not None else None
                hash = HashValue(int(row.hash))
                self.syscalls[int(hash)] = FunctionUsageInfo(BasicIdentifier(MjoScope.SYSCALL, hash, type, name))
            for item in sheet_syscalls:
                add_syscall_row(item)
            # VOID     = 'void'     # Return types only
            # ANY      = 'any'
            # ANY_VOID = 'any/void' # Return types only
            # INT_UNK  = 'int?'     # base type: int (usage unknown)
            # INT      = 'int'      # base type: int (usage known)
            # BOOL     = 'bool'     # base type: int (0 or 1)
            # FILE     = 'file*'    # base type: int (ptr to FILE)
            # PAGE     = 'page*'    # base type: int (ptr to PAGE)
            # SPRITE   = 'sprite*'  # base type: int (ptr to SPRITE)

    def __getitem__(self, scope:MjoScope) -> Dict[int,UsageInfo]:
        return self.scopes[scope]

    @property
    def root(self) -> 'UsageDatabase': return self.parent.root if self.parent is not None else self

    def update_opcode(self, instr:Instruction, usage:UsageMask=UsageMask.NONE) -> UsageInfo:
        if self.parent is not None:
            self.parent.update_opcode(instr)
        opcode = instr.opcode
        info = self.opcodes.get(opcode.value)
        if info is None:
            info = UsageInfo(opcode, usage)
            self.opcodes[int(opcode.value)] = info
        
        info.update_usage(usage)
        # if usage:
        #     info.usage |= usage
        #     if usage & ~UsageMask.DEFINE:
        #         info.count += 1
        
        return info
    
    def find_identifier(self, scope:MjoScope, hash:int) -> Tuple[Optional[UsageInfo], Optional['UsageDatabase']]:
        info = self.scopes[scope].get(hash)
        if info is None:
            if self.parent is not None:
                return self.parent.find_identifier(scope, hash)
            return None, None
        return info, self

    def _create_usage(self, item:BasicIdentifier, usage:UsageMask=UsageMask.NONE) -> UsageInfo:
        if item.scope is MjoScope.LOCAL:
            return LocalUsageInfo(item, usage) # args[0] = var_offset
        elif item.scope is MjoScope.FUNCTION:
            return FunctionUsageInfo(item, usage)
        else:
            return UsageInfo(item, usage)

    def update_identifier(self, scope:Union[MjoScope,Opcode], hash:int, usage:UsageMask=UsageMask.NONE, type:MjoType=None, name:str=None, *args) -> UsageInfo:
        item = None
        hash = HashValue(hash)
        if self.parent is not None:
            item = self.parent.update_identifier(scope, hash, usage & ~UsageMask.DEFINE, type, name).item
        info = self.scopes[scope].get(hash)
        if info is None:
            info = self._create_usage(item or BasicIdentifier(scope, hash, type, name), usage)#, *args)
            # info = UsageInfo(item or BasicIdentifier(scope, hash, type, name), usage)
            self.scopes[scope][int(hash)] = info

        info.update_usage(usage, *args)
        # if usage:
        #     info.usage |= usage
        #     if usage & ~UsageMask.DEFINE:
        #         info.count += 1
        if usage & UsageMask.DEFINE:
            self.defines[int(hash)] = info
        item = info.item
        
        #if hash is not None: # always True
        if self.parent is None:
            if   item.hash is None: item.hash = hash
            elif item.hash != hash: print(f'mismatch hash: {info!r}')
            if type is not None:
                type = MjoType(type)
                if   item.type is None: item.type = type
                elif item.type != type: print(f'mismatch type: {info!r}')
            if name is not None:
                if   item.name is None: item.name = name
                elif item.name != name: print(f'mismatch name: {info!r} {item.name!r} vs. {name!r}')

            # if item.name is None and item.hash is not None and item.hash not in notfound_names:
            #     item.name = found_names.get(item.hash)
            #     if item.name is None:
            #         from .hashes import LOCAL_VARS
            #         item.name = LOCAL_VARS.get(item.hash)
            #     if item.name is None and item.type is not None:
            #         results = brute_force.find_hash(item.hash, item.scope.prefix, item.type.postfix, '')
            #         if not results:
            #             notfound_names.add(item.hash)
            #         else:
            #             if len(results) > 1:
            #                 print(f'{S.BRIGHT}{F.RED}Collisions for {info!r}:  {results}{S.RESET_ALL}')
            #                 notupper = [s for s in results if not s[1].isupper()]
            #                 if notupper: results = notupper
            #             else:
            #                 print(f'{S.BRIGHT}{F.YELLOW}Brute-forced {info!r}: {results}{S.RESET_ALL}')
            #             item.name = results[0]
            
            # if item.name is not None:
            #     found_names.setdefault(item.hash, item.name)

            if item.type is None and item.name is not None:
                postfix = postfixsymbol(item.name)
                if postfix is not None:
                    item.type = MjoType.frompostfix(postfix)

        return info

class ScriptUsageDatabase(UsageDatabase):
    # defines:Dict[int,UsageInfo]

    def __init__(self, scope:UsageScope, name:str, cfg:ControlFlowGraph, parent:'UsageDatabase'=None):
        super().__init__(scope, name, parent)
        # self.defines = {}
        self._cfg = cfg

    @property
    def cfg(self) -> ControlFlowGraph: return self._cfg
    @property
    def script(self) -> ControlFlowGraph: return self._cfg.script

class FunctionUsageDatabase(UsageDatabase):
    # defines:Dict[int,UsageInfo]
    offsets:Dict[int,LocalUsageInfo]

    def __init__(self, scope:UsageScope, name:str, identity:BasicIdentifier, function:Function, parent:'ScriptUsageDatabase'=None):
        super().__init__(scope, name, parent)
        # self.defines = {}
        self.offsets = {}
        self._identity = identity
        self._function = function
    
    @property
    def cfg(self) -> ControlFlowGraph: return self.parent._cfg
    @property
    def script(self) -> MjoScript: return self._function.script
    @property
    def identity(self) -> BasicIdentifier: return self._identity
    @property
    def function(self) -> Function: return self._function

    def define_local(self, var_offset:int=None, type:MjoType=None, name:str=None, *args) -> LocalUsageInfo:
        info = self.offsets.get(var_offset)
        if info is None:
            item = BasicIdentifier(MjoScope.LOCAL, None, type, name)
            self.offsets[var_offset] = info = self._create_usage(item, UsageMask.DEFINE)#, var_offset, *args)
            info.var_offset = var_offset
        info.usage |= UsageMask.DEFINE
        return info

    def update_identifier(self, scope:Union[MjoScope,Opcode], hash:int, usage:UsageMask=UsageMask.NONE, type:MjoType=None, name:str=None, *args) -> UsageInfo:
        info = super().update_identifier(scope, hash, usage, type, name, *args)
        if scope is MjoScope.LOCAL:
            item = info.item
            var_offset, args = args[0], args[1:]
            offinfo = self.offsets.get(var_offset)
            if offinfo is None:
                self.offsets[var_offset] = info
            else:
                offitem = offinfo.item
                hash, type, name = offitem.hash, offitem.type, offitem.name
                if hash is not None:
                    if   item.hash is None: item.hash = HashValue(hash)
                    elif item.hash != hash: print(f'mismatch hash: {info!r}')
                if type is not None:
                    type = MjoType(type)
                    if   item.type is None: item.type = type
                    elif item.type != type: print(f'mismatch type: {info!r}')
                if name is not None:
                    if   item.name is None: item.name = name
                    elif item.name != name: print(f'mismatch name: {info!r}')
                info.usage |= offinfo.usage
            self.defines[int(item.hash)] = info
            info.var_offset = var_offset
        return info


#######################################################################################

def load_game_usage(self:UsageDatabase, basedir:str):
    newchildren = []  # type: List[ScriptUsageDatabase]
    for file in os.listdir(basedir):
        filepath = os.path.join(basedir, file)
        if file.lower().endswith('.mjo'):
            print('Adding:', file)
            child = ScriptUsageDatabase(UsageScope.SCRIPT, file, analyze_script(filepath), self)
            self.children.append(child)
            newchildren.append(child)
            # self.children.append(read_script_usage(file, script, self))
    for child in newchildren:
        print('Scanning:', child.name)
        load_script_usage(child)
    
    return self

def read_script_usage(name:str, script:MjoScript, parent:UsageDatabase=None) -> ScriptUsageDatabase:
    cfg = analyze_script(script)
    db = ScriptUsageDatabase(UsageScope.SCRIPT, name, cfg, parent)
    return load_script_usage(db)

def load_script_usage(self:ScriptUsageDatabase) -> ScriptUsageDatabase: #, parent:UsageDatabase=None) -> ScriptUsageDatabase:
    newchildren = []  # type: List[FunctionUsageDatabase]
    for function in self.cfg.functions:
        identity = self.update_identifier(MjoScope.FUNCTION, function.hash, UsageMask.DEFINE).item
        child = FunctionUsageDatabase(UsageScope.FUNCTION, self.name, identity, function, self)
        self.children.append(child)
        newchildren.append(child)
        #self.children.append(read_function_usage(f'func ${function.hash:08x}', identity, function, cfg, self))
    for child in newchildren:
        load_function_usage(child)

    return self

def read_function_usage(name:str, identity:BasicIdentifier, function:Function, cfg:ControlFlowGraph, parent:ScriptUsageDatabase=None) -> FunctionUsageDatabase:
    db = FunctionUsageDatabase(UsageScope.FUNCTION, name, identity, function, parent)
    return load_function_usage(db)

def load_function_usage(self:FunctionUsageDatabase) -> FunctionUsageDatabase: #, parent:ScriptUsageDatabase=None) -> FunctionUsageDatabase:
    function = self.function
    script = function.script

    for i in range(function.first_instruction_index, function.last_instruction_index + 1):
        is_first, is_last = (i==function.first_instruction_index), (i==function.last_instruction_index)
        instr = script.instructions[i]  # type: Instruction
        self.update_opcode(instr)
        myvar = None
        if instr.is_argcheck:
            for j,type in enumerate(instr.type_list):
                # print(f'sigchk[{-2 - j}] = {t.name}')
                self.define_local(-2 - j, type)
        elif instr.is_alloca:
            for j,type in enumerate(instr.type_list):
                # print(f'alloca[{j}] = {t.name}')
                self.define_local(j, type)

        elif instr.is_load or instr.is_store:
            name = None
            flags = instr.flags
            hash = instr.hash
            var_offset = instr.var_offset
            scope = flags.scope
            type = flags.type
            # element = instr.is_element
            # elementtype = type
            if instr.is_element:
                type = type.array

            # from .hashes import LOCAL_VARS, THREAD_VARS, SAVEFILE_VARS, PERSISTENT_VARS
            # if scope is MjoScope.LOCAL:
            #     self.update_identifier(scope, )
            #     myvar = local_update(var_offset, hash, type)
            #     # name = LOCAL_VARS.get(hash)
            # else:
            #     myvar = global_update(scope, hash, type)
            #     if scope is MjoScope.SAVEFILE:
            #         name = SAVEFILE_VARS.get(hash)
            #     elif scope is MjoScope.PERSISTENT:
            #         name = PERSISTENT_VARS.get(hash)
            #     elif scope is MjoScope.THREAD:
            #         name = THREAD_VARS.get(hash)

            # if instr.is_store or flags.modifier is not MjoModifier.NONE:
            #     if instr.is_element:
            #         modifies_vars.add(myvar)
            #     else:
            #         writes_vars.add(myvar)
            # if instr.is_load: # pop
            #     if (is_last or script.instructions[i+1].opcode.value != 0x82f):
            #         if instr.is_element:
            #             accesses_vars.add(myvar)
            #         else:
            #             reads_vars.add(myvar)
            #     else:
            #         if instr.is_element:
            #             modifies_vars.add(myvar)
            #         else:
            #             writes_vars.add(myvar)
            usage = UsageMask.NONE
            #find_identifier
            if instr.is_store or flags.modifier is not MjoModifier.NONE:
                if instr.is_element:
                    usage |= UsageMask.MODIFY
                else:
                    usage |= UsageMask.WRITE
            if instr.is_load: # pop
                if is_last or script.instructions[i+1].opcode.value != 0x82f:
                    if instr.is_element:
                        usage |= UsageMask.ACCESS
                    else:
                        usage |= UsageMask.READ
                else:
                    if instr.is_element:
                        usage |= UsageMask.MODIFY
                    else:
                        usage |= UsageMask.WRITE
            self.update_identifier(scope, hash, usage, type, None, var_offset)
        
        elif instr.opcode.value == 0x800: # "ldc.i"
            hash = unsigned_I(instr.integer)
            info, infodb = self.find_identifier(MjoScope.FUNCTION, hash)
            if info is not None:
                self.update_identifier(MjoScope.FUNCTION, hash, UsageMask.REFERENCE)
                
        elif instr.is_call or instr.is_syscall:
            name = None
            hash = instr.hash
            arg_num = instr.arg_num
            type = None
            scope = MjoScope.FUNCTION if instr.is_call else MjoScope.SYSCALL
            voidcall = instr.opcode.value in (0x810, 0x835) # "callp", "syscallp"
            # from .hashes import FUNCTIONS, SYSCALLS
            if not voidcall and not is_last and script.instructions[i+1].is_store:
                nextinstr = script.instructions[i+1]
                if nextinstr.is_element:
                    if nextinstr.flags.dimension != 0:
                        type = MjoType.INT # index operand
                    else:
                        type = nextinstr.flags.type.array
                else:
                    type = nextinstr.flags.type
            self.update_identifier(scope, hash, UsageMask.CALL, type, None, arg_num, voidcall)
            
        elif self.parent is not None and instr.is_return and not is_first:
            instr = script.instructions[i-1]
            type = None
            if instr.opcode.encoding.endswith('.i'):
                type = MjoType.INT
            elif instr.opcode.encoding.endswith('.f'):
                type = MjoType.FLOAT
            elif instr.opcode.encoding.endswith('.s'):
                type = MjoType.STRING
            elif instr.opcode.encoding.endswith('.I'):
                type = MjoType.INT_ARRAY
            elif instr.opcode.encoding.endswith('.F'):
                type = MjoType.FLOAT_ARRAY
            elif instr.opcode.encoding.endswith('.S'):
                type = MjoType.STRING_ARRAY
            elif instr.opcode.value == 0x800: # "ldc.i"
                type = MjoType.INT
            elif instr.opcode.value == 0x801: # "ldstr"
                type = MjoType.STRING
            elif instr.opcode.value == 0x803: # "ldc.r"
                type = MjoType.FLOAT
            elif instr.is_load or instr.is_store:
                type = instr.flags.type
            elif instr.is_call or instr.is_syscall and instr.opcode.value not in (0x810, 0x835): # "callp", "syscallp"
                scope = MjoScope.FUNCTION if instr.is_call else MjoScope.SYSCALL
                info, infodb = self.find_identifier(scope, instr.hash)
                if info is not None:
                    type = info.item.type
            if type is not None:
                self.parent.update_identifier(MjoScope.FUNCTION, self.identity.hash, type=type)
                
    return self


r"""

# TESTING:
from mj.script.mjoscript import MjoScript
from mj.database.usage import UsageDatabase, ScriptUsageDatabase, FunctionUsageDatabase, UsageScope, UsageMask, load_game_usage, load_script_usage, read_script_usage, read_function_usage, load_function_usage
alldb = UsageDatabase(UsageScope.ALL, '<root>')
majdb = UsageDatabase(UsageScope.GAME, 'Mahjong [v1509]', alldb)
alldb.children.append(majdb)
load_game_usage(majdb, r"../../Catalog/scripts/[v1509] Mahjong (NekoNeko Soft)")
[f for f in list(alldb.calls.values()) if f.type]
[f for f in list(alldb.calls.values()) if f.type and f.type.value != 0]
[f for f in list(alldb.locals.values()) if f.type and f.type.value != 0]

"""


#######################################################################################

del enum, Dict, List, Optional, Tuple, Union  # cleanup declaration-only imports
