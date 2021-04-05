# Majiro Bytecode #


## Type Codes

|     Type|int|flt|str|int\[\]|flt\[\]|str\[\]|
|--------:|:-:|:-:|:-:|:----:|:----:|:----:|
|**Value**|`0`|`1`|`2`|`3`   |`4`   |`5`   |
| **Name**|`i`|`r`|`s`|`iarr`|`rarr`|`sarr`|


`op.type` standard operator with type (some float operations will accept and cast ints to float)
`opl.type` for logical comparison that conflict with bitwise names
`st[.op].type[.nr]` store variable with optional compound assignment and optional pop from stack
`stelem[.op].type[.nr]` store at element index in variable with optional compound assignment and optional pop from stack
`[sys]call[.nr]` local or system function call with optional pop from stack
`conv.type` cast to integer or float literal
`ldc.type` push integer or float literal
`ldvar` load a variable
`ldelem` load element in variable

`op` is a valid alias for `.i`-only operators (this may be decided upon as the default name)

## Operator Opcodes

|Name   |int  |flt  |str  |int\[\]|flt\[\]|str\[\]|
|:------|:---:|:---:|:---:|:-:|:-:|:-:|
|`mul *`|`100`|`101`|-|-|-|-|
|`div /`|`108`|`109`|-|-|-|-|
|`rem %`|`110`|-|-|-|-|-|
|`add +`|`118`|`119`|`11a`|-|-|-|
|`sub -`|`120`|`121`|-|-|-|-|
|`shr >>`|`128`|-|-|-|-|-|
|`shl <<`|`130`|-|-|-|-|-|
|`le <=`|`138`|`139`|`13a`|-|-|-|
|`lt <`|`140`|`141`|`142`|-|-|-|
|`ge >=`|`148`|`149`|`14a`|-|-|-|
|`gt >`|`150`|`151`|`152`|-|-|-|
|`eq ==`|`158`|`159`|`15a`|`15b`|`15c`|`15d`|
|`ne !=`|`160`|`161`|`162`|`163`|`164`|`165`|
|`xor  ^`|`168`|-|-|-|-|-|
|`andl &&`|`170`|-|-|-|-|-|
|`orl ||`|`178`|-|-|-|-|-|
|`and &`|`180`|-|-|-|-|-|
|`or |`|`188`|-|-|-|-|-|
|`notl !`|`190`| ~~`191`~~ |-|-|-|-|
|`not ~`|`198`|-|-|-|-|-|
|`neg -`|`1a0`|`1a1`|-|-|-|-|
|*`pos +`*|*`1a8`*|*`1a9`*|-|-|-|-|
|`st =`|`1b0`|`1b1`|`1b2`|`1b3`|`1b4`|`1b5`|

|Op    |Sym |Keywords|
|:-----|:---|:-------|
|`mul` |`*` |<kbd>multiply</kbd>, <kbd>multiplication</kbd>, <kbd>times</kbd>|
|`div` |`/` |<kbd>divide</kbd>, <kbd>division</kbd>|
|`rem` |`%` |<kbd>remainder</kbd>, <kbd>modulus</kbd>, <kbd>modulo</kbd>|
|`add` |`+` |<kbd>add</kbd>, <kbd>addition</kbd>, <kbd>plus</kbd>|
|`sub` |`-` |<kbd>subtract</kbd>, <kbd>subtraction</kbd>, <kbd>minus</kbd>, <kbd>difference</kbd>|
|`shr` |`>>`|<kbd>bit shift right</kbd>, <kbd>right shift</kbd>|
|`shl` |`<<`|<kbd>bit shift left</kbd>, <kbd>left shift</kbd>|
|`le`  |`<=`|<kbd>less than or equals</kbd>|
|`lt`  |`<` |<kbd>less than</kbd>|
|`ge`  |`>=`|<kbd>greater than or equals</kbd>|
|`gt`  |`>` |<kbd>greater than</kbd>|
|`eq`  |`==`|<kbd>equals</kbd>|
|`ne`  |`!=`|<kbd>not equals</kbd>|
|`xor` |`^` |<kbd>bitwise xor</kbd>|
|`andl`|`&&`|<kbd>boolean and</kbd>|
|`orl` |`||`|<kbd>boolean or</kbd>|
|`and` |`&` |<kbd>bitwise and</kbd>|
|`or`  |`|` |<kbd>bitwise or</kbd>|
|`notl`|`!` |<kbd>boolean not</kbd>|
|`not` |`~` |<kbd>bitwise not</kbd>, <kbd>bitwise negate</kbd>|
|`neg` |`-` |<kbd>negate</kbd>, <kbd>negative</kbd>, <kbd>unary minus</kbd>|
|`pos` |`+` |<kbd>positive</kbd>, <kbd>unary plus</kbd>|
|`st`  |`=` |<kbd>store variable</kbd>, <kbd>assign variable</kbd>|
|`stelem`  |`=` |<kbd>store element</kbd>, <kbd>assign element</kbd>, <kbd>index</kbd>|


|Op        |Oper.|
|:---------|:---|
|`mul(*)`  |`*` |
|`div(/)`  |`/` |
|`rem(%)`  |`%` |
|`add(+)`  |`+` |
|`sub(-)`  |`-` |
|`shr(>>)` |`>>`|
|`shl(<<)` |`<<`|
|`le(<=)`  |`<=`|
|`lt(<)`   |`<` |
|`ge(>=)`  |`>=`|
|`gt(>)`   |`>` |
|`eq(==)`  |`==`|
|`ne(!=)`  |`!=`|
|`xor(^)`  |`^` |
|`andl(&&)`|`&&`|
|`orl(||)` |`||`|
|`and(&)`  |`&` |
|`or(|)`   |`|` |
|`notl(!)` |`!` |
|`not(~)`  |`~` |
|`neg(-)`  |`-` *(unary)*|
|`pos(+)`  |`+` *(unary)*|
|`st(=)`   |`=` |
|`stelem([]=)`
|`st.mul(*=)`
|`st(=).mul(*)`
|`ldvar(@)`
|`ldelem([])`

`mul *`, `div /`, `rem %`, `add +`, `sub -`, `shr >>`, `shl <<`, `le <=`, `lt <`, `ge >=`, `gt >`, `eq ==`, `ne !=`, `xor ^`, `andl &&`, `orl ||`, `and &`, `or |`, `notl !`, `not ~`, `neg -`, *`pos +`*


## Operator Opcode Names

|int     |flt     |str     |int\[\]|flt\[\]|str\[\]|
|:-------|:-------|:-------|:------|:------|:------|
|`mul.i` |`mul.r` |
|`div.i` |`div.r` |
|`rem.i` |
|`add.i` |`add.r` |`add.s` |
|`sub.i` |`sub.r` |
|`shr.i` |
|`shl.i` |
|`le.i`  |`le.r`  |`le.s`  |
|`lt.i`  |`lt.r`  |`lt.s`  |
|`ge.i`  |`ge.r`  |`ge.s`  |
|`gt.i`  |`gt.r`  |`gt.s`  |
|`eq.i`  |`eq.r`  |`eq.s`  |`eq.iarr`|`eq.rarr`|`eq.sarr`|
|`ne.i`  |`ne.r`  |`ne.s`  |`ne.iarr`|`ne.rarr`|`ne.sarr`|
|`xor.i` |
|`andl.i`|
|`orl.i` |
|`and.i` |
|`or.i`  |
|`notl.i`|~~`notl.r`~~|
|`not.i` |
|`neg.i` |`neg.r` |
|*`pos.i`*|*`pos.r`*|

## Store Variable Opcode Names

#### Store Variable OpCode Names (keep on stack)

|int       |flt       |str       |int\[\]  |flt\[\]  |str\[\]  |
|:---------|:---------|:---------|:--------|:--------|:--------|
|`st.i`    |`st.r`    |`st.s`    |`st.iarr`|`st.rarr`|`st.sarr`|
|`st.mul.i`|`st.mul.r`|
|`st.div.i`|`st.div.r`|
|`st.rem.i`|
|`st.add.i`|`st.add.r`|`st.add.s`|
|`st.sub.i`|`st.sub.r`|
|`st.shl.i`|
|`st.shr.i`|
|`st.and.i`|
|`st.xor.i`|
|`st.or.i` |

#### Store Variable OpCode Names (pop from stack)

|int          |flt          |str          |int\[\]     |flt\[\]     |str\[\]     |
|:------------|:------------|:------------|:-----------|:-----------|:-----------|
|`st.i.nr`    |`st.r.nr`    |`st.s.nr`    |`st.iarr.nr`|`st.rarr.nr`|`st.sarr.nr`|
|`st.mul.i.nr`|`st.mul.r.nr`|
|`st.div.i.nr`|`st.div.r.nr`|
|`st.rem.i.nr`|
|`st.add.i.nr`|`st.add.r.nr`|`st.add.s.nr`|
|`st.sub.i.nr`|`st.sub.r.nr`|
|`st.shl.i.nr`|
|`st.shr.i.nr`|
|`st.and.i.nr`|
|`st.xor.i.nr`|
|`st.or.i.nr` |

## Store Element Opcodes Names

#### Store Element OpCode Names (keep on stack)

|int           |flt           |str           |
|:-------------|:-------------|:-------------|
|`stelem.i`    |`stelem.r`    |`stelem.s`    |
|`stelem.mul.i`|`stelem.mul.r`|
|`stelem.div.i`|`stelem.div.r`|
|`stelem.rem.i`|
|`stelem.add.i`|`stelem.add.r`|`stelem.add.s`|
|`stelem.sub.i`|`stelem.sub.r`|
|`stelem.shl.i`|
|`stelem.shr.i`|
|`stelem.and.i`|
|`stelem.xor.i`|
|`stelem.or.i` |

#### Store Element *Pop*Code Names (pop from stack)

|int              |flt              |str              |
|:----------------|:----------------|:----------------|
|`stelem.i.nr`    |`stelem.r.nr`    |`stelem.s.nr`    |
|`stelem.mul.i.nr`|`stelem.mul.r.nr`|
|`stelem.div.i.nr`|`stelem.div.r.nr`|
|`stelem.rem.i.nr`|
|`stelem.add.i.nr`|`stelem.add.r.nr`|`stelem.add.s.nr`|
|`stelem.sub.i.nr`|`stelem.sub.r.nr`|
|`stelem.shl.i.nr`|
|`stelem.shr.i.nr`|
|`stelem.and.i.nr`|
|`stelem.xor.i.nr`|
|`stelem.or.i.nr` |

`notl.r`
`notl.i`
`not.i`

`neg.i`
`neg.r`

`mul.i`

`st.i`
`st.i.p`
`stmul.i`
`stmul.i.p`
`stdiv.i`
`stdiv.i.p`
`strem.i`
`strem.i.p`
`stadd.i`
`stadd.i.p`
`stsub.i`
`stsub.i.p`
`stshl.i`
`stshl.i.p`
`stshr.i`
`stshr.i.p`
`stand.i`
`stand.i.p`
`stxor.i`
`stxor.i.p`
`stor.i`
`stor.i.p`
`st.mul.i`
`st.mul.i.p`


`mul.s`
`st.s`
`st.s.p`
`stmul.s`
`stmul.s.p`
`st.mul.s`
`st.mul.s.p`


`mul`
`st`
`st.p`
`stmul`
`stmul.p`
`st.mul`
`st.mul.p`



## Other Opcodes

|Name		|Code |
|:----------|:---:|
|`ldc.i`	|`800`|
|`ldstr`	|`801`|
|`ldvar`	|`802`| <!-- alt: ldfld, ldobj, ldarg, ldloc, ldadr -->
|`ldc.r`	|`803`|
|`call`		|`80f`|
|`call.nr`	|`810`|
|`alloca`	|`829`|
|`ret`		|`82b`|
|			|`82d`|
|`jmp`		|`82c`|
|`brzero`	|`82e`|
|`pop`		|`82f`|
|			|`830`|
|`bne`		|`831`|
|			|`832`|
|			|`833`|
|`syscall`	|`834`|
|`syscall.p`|`835`|
|`checkargs`|`836`|
|`ldelem`	|`837`|
|			|`838`|
|			|`839`|
|`line`		|`83a`|
|			|`83b`|
|			|`83c`|
|			|`83d`|
|`conv.i`	|`83e`|
|`conv.r`	|`83f`|
|`text`		|`840`|
|`marker`	|`841`|
|`command`	|`842`|
|			|`843`|
|			|`844`|
|			|`845`|
|			|`846`|
|			|`847`|
|`switch`	|`850`|

## Store Opcodes (no pop)

|Name|int|flt|str|int\[\]|flt\[\]|str\[\]|
|:-|:-:|:-:|:-:|:-:|:-:|:-:|
|`sto =`|`1b0`|`1b1`|`1b2`|`1b3`|`1b4`|`1b5`|
|`mul*=`|`1b8`|`1b9`|-|-|-|-|
|`div/=`|`1c0`|`1c1`|-|-|-|-|
|`rem%=`|`1c8`|-|-|-|-|-|
|`add+=`|`1d0`|`1d1`|`1d2`|-|-|-|
|`sub-=`|`1d8`|`1d9`|-|-|-|-|
|`shl<<=`|`1e0`|-|-|-|-|-|
|`shr>>=`|`1e8`|-|-|-|-|-|
|`and&=`|`1f0`|-|-|-|-|-|
|`xor^=`|`1f8`|-|-|-|-|-|
|`or |=`|`120`|-|-|-|-|-|

Final results. I'm positive 0x110 is modulus, as it's the only conceivable operator you'd place with the rest of the arithmetic ones:

```
//mul:    (0x100, 0x101, -----) // arithmetic: *
//div:    (0x108, 0x109, -----) // arithmetic: /
//mod:    (0x110, -----, -----) // arithmetic: %
//add:    (0x118, 0x119, 0x11a) // arithmetic: +
//sub:    (0x120, 0x121, -----) // arithmetic: -
//rsh:    (0x128, -----, -----) // bitwise: >>
//lsh:    (0x130, -----, -----) // bitwise: <<
//lte:    (0x138, 0x139, 0x13a) // compare: <=
//lt:    (0x140, 0x141, 0x142) // compare: <
//gte:    (0x148, 0x149, 0x14a) // compare: >=
//gt:    (0x150, 0x151, 0x152) // compare: >
//equ:    (0x158, 0x159 0x15a, 0x15b, 0x15c, 0x15d) // compare: ==
//neq:    (0x160, 0x161, 0x162, 0x163, 0x164, 0x165) // compare: !=
//xor:    (0x168, -----, -----) // bitwise: ^
//andL:    (0x170, -----, -----) // logical: &&
//orL:    (0x178, -----, -----) // logical: ||
//andB:    (0x180, -----, -----) // bitwise: &
//orB:    (0x188, -----, -----) // bitwise: |
//not:    (0x190,N0x191, -----) // logical: !
//notB:    (0x198, -----, -----) // bitwise: ~
//negI:    (0x1a0, 0x1a1, -----) // arithmetic: - (negation)
//NOP: (N0x1a8,N0x1a9, -----) // [no operation] (reserved?)
//sto:    (0x1b0, 0x1b1, 0x1b2, 0x1b3, 0x1b4, 0x1b5) // assignment: =
```