# MjIL assembler language proposals #

## Hashes

### Valid hash hex value

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832417004786679858> -->

**Format:** `$XXXXXXXX`

* Hash hex values must be written in the following format: `$[0-9A-Fa-f]{8}`.
* Hash hex values shall always start with a `$`, immediately followed by 8 hexadecimal characters.
* Hash hex values must always contain **8** *0-padded* hex characters, upper and lowercase shall both be allowed.
* Hash hex values must be parsable for **hash operands**, **int operands**, and **function declaration hashes**.


### Inline hash function

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832322264669880360> -->
<!-- syscalls:   <https://discord.com/channels/@me/766128075352047646/832334425496748073> -->
<!-- functions:  <https://discord.com/channels/@me/766128075352047646/832337324511199321> -->
<!-- enforced:   <https://discord.com/channels/@me/766128075352047646/832409453315620926> -->

**Implicit:** `$nonvalidhex`<br>
**Explicit:** `${anythingbutbraces}`

**Requirements:**
* This function must be prepared to parse **hash operands**, **int operands**, and **function declaration hashes**.
* For implicit method (`$nonvalidhex`), any name that evaluates to a [Valid hash value](#valid-hash-value) will be ignored, and considered a hexidecimal representation of the hashed name.
* For implicit method (`$nonvalidhex`), matches shall only contain the following characters `[_%@#$0-9A-Za-z]`. Anything else shall be considered the end of the hash. (e.g. `func $$namedisp@CONSOLE(string)` **-&gt;** `func ${$namedisp@CONSOLE}(string)`)
* For both methods, the prefix character shall determine the type of lookup:
    * `$[_%@#].*` **:** variable &emsp;(matched content shall be processed by `crc32`)
	* `$[$].*` **:** function &emsp;(matched content shall be processed by `crc32`)
	* `$[^_%@#$].*` **:** syscall &emsp;(matched content shall use a lookup table)
	* As such, all syscalls must have the `$` prefix *(or any other prefix)* stripped by disassemblers.
* For explicit method (`${anythingbutbraces}`), all contents shall be considered part of the hash, (or of a syscall name based on the prefix). The only exception will be the closing `}` brace.
* (Handling escapes in explicit inline hash functions has not been discussed yet.)
* See [Implicit group directive](#implicit-group-directive), which describes extra handling performed by the inline hash function, before processing with `crc32`.

#### Examples

```
; ld/st hash operands (implicit)
ld            local string $_name$@ -2  ; $de39f0d4
st.s          savefile string $@face_fn$@CONSOLE   ; $bdd67fcb

; call/syscall (implicit)
call          $$is_sca@CONSOLE (0)  ; $158fcf1d
syscallp      $invalidate_rect (5)  ; $dfd5599e

; ldc.i (implicit)
ldc.i         $$cb_console_wrote@CONSOLE  ; $5378cb56
ldstr         "CONSOLE_WROTE"
syscallp      $event_hook (2)  ; $078a756e

; function declarations (implicit / explicit)
func $$namedisp(string) {
}
func ${$namedisp}(string) {
}
```


`$a0a0a0a0` -&gt; already a hash<br>
`$$anything` -&gt; append `@GROUP` and hash<br>
`$_anything` -&gt; append `@` and hash<br>
`$$anything@GROUP` -&gt; just hash<br>
`$notvalidhex` -&gt; look up in syscall table

## Directives

### Entrypoint directive

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/830893355868487720> -->

`entrypoint`

* The `entrypoint` keyword shall describe exactly **1** function that will be declared as the main offset be an assembler.
* The entrypoint keyword must appear after a function's declaration, on the same line, and before any opening brace `{`.
* (Implied entrypoint when a file contains only one function has not been disussed yet.)
* (Whether an entrypoint must contain no parameters has not been determined yet, however assemblers show allow it for the foreseeable future, a warning may be output in this scenario.)

#### Examples

```
; entrypoint declaration via hash value, and inline hash name
func $5ff01a4c() entrypoint {  ; $main@CONSOLE
}
func $$main@CONSOLE() entrypoint {  ; $5ff01a4c
}
```

### Readmark directive

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/830893543789821952> -->

`readmark enable|disable`

* Readmark determines if a script shall track if a line has been read by the player or not. For assemblers, this means assigning the `line_offset` field (dword @ `0x14`) in assembled `.mjo` scripts.
* When `readmark enable` is present, `line_offset` (dword @ `0x14`) must be assigned a non-zero value that is equal to the value of the highest `line` operand (1-indexed).
* When `readmark disable` is present, `line_offset` (dword @ `0x14`) must be assigned to zero.
* The readmark directive shall only be expected to appear *once* in a script.
* If the readmark directive is missing, the assembler shall choose an appropriate action specified by the user (assume `disable`, assume `enable` *(for story developers)*, or raise an error).
* The readmark directive should appear at the top of a script. It must be the first and only item on a line.


### Implicit group directive

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832330501821694022> -->
<!-- quotes:     <https://discord.com/channels/@me/766128075352047646/832339640836554772> -->
<!-- none:       <https://discord.com/channels/@me/766128075352047646/832393858204565555> -->

**Implicit:** `group "GROUPNAME"`<br>
**Explicit:** `group none`

* Implicit group directive is a functionality tied to the [Inline hash function](#inline-hash-function). When one of the above is encountered in a script. An implied group shall be set or turned off.
* When defining a group, doublequotes `""` **must** be used, and the `@` prefix of the group **cannot** be included. Including an `@` at the beginning of (or anywhere in) a group name, shall constitute an error upon assembly.
* The default setting shall be `group none`, unless explicitly stated otherwise by an assembler option.
* When running the [Inline hash function](#inline-hash-function) for a variable or function name, a group shall be included automatically.
    * If the hash name begins with an `_` character, the name is local **and must** include an empty group (append `@`), if none is explicitly specified in the name.
	* If the hash name begins with any other character that does not constitute a syscall, the group name last specified by a `group "GROUPNAME"` directive shall be appended (along with the `@`).
	* If a group name is missing for a **non-local** variable or function hash while the current setting is `group none`, an error shall be thrown by the assembler. (this functionality shall be run regardless of the `group` setting)
* The group directive may appear anywhere in a script, as many times as needed, however it must be the first and only item on a line.


***


## Variable instructions

### Variable flag names

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832317373133619250> -->
<!-- loc alias:  <https://discord.com/channels/@me/766128075352047646/833103888130244618> -->

The following names, *and only* the following names, must be supported for variable flag operands, and types used in other operands, or function declarations.

**Type flags and names:**

`int`, `float`, `string`, `intarray`, `floatarray`, `stringarray` **\[alias:** `i`, `r`, `s`, `iarr`, `rarr`, `sarr` **\]** **&lt;value:** `0`, `1`, `2`, `3`, `4`, `5` **&gt;**

**Scope flags:**

`local`, `thread`, `savefile`, `persistent`, **\[alias:** `loc`, -, `save`, `persist` **\]** **&lt;value:** `0`, `3`, `2`, `1`, `0` **&gt;**

**Modifier flags:**

-, `preinc`, `predec`, `postinc`, `postdec` **\[alias:** -, `x.inc`, `x.dec`, `inc.x`, `dec.x` **\]** **&lt;value:** \[`0`\], `1`, `2`, `3`, `4` **&gt;**

**Invert flags:**

-, `neg`, `not`, `notl` (type mnemonic is illegal, e.g. no `neg.r`) **&lt;value:** \[`0`\], `1`, `2`, `3` **&gt;**

**Dimension flags:**

-, `dim1`, `dim2`, `dim3` *(simply `dim{}`)* **\[alias:** `dim0`, -, -, - **\]** **&lt;value:** \[`0`\], `1`, `2`, `3` **&gt;**

#### Examples

```
; type (normal / alias)
ld            local string $_fn$@ -2  ; $a75141c4
ld            local s $_fn$@ -2  ; $a75141c4

; modifier (normal / alias)
ld            savefile int postinc $@re_enter_in_face_disp@CONSOLE   ; $caa5dbd1
ld            savefile int x.inc $@re_enter_in_face_disp@CONSOLE   ; $caa5dbd1

; invert flag
ld            savefile int notl $@force_play@CONSOLE   ; $47c73c5d

; dimension
ldelem        local intarray dim2 $_myarray#@  ; myarray[,]
```


### Default variable offset for non-locals

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832312292624171018> -->

*applies to: `ld`, `ldelem`, `st*`, `stelem*`*

* When disassembling or assembling any variable instruction with a type flag that is not `local`, and the variable offset operand is `-1`, the operand may be excluded.
* Disassemblers must output this operand if the value is not equal to `-1`

#### Examples

```
st.s          savefile string $@next_beep$@CONSOLE   ; $d4599c91
; unexpected var offset
st.s          savefile string $@next_beep$@CONSOLE -7  ; $d4599c91
```


***


## Branch instructions

### Explicit jump offset

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832308817605558343> -->

`@~04b`<br>
`@~+04b`<br>
`@~-a530`

* Explicit jump offsets are defined as `@~[+-]?[0-9A-Fa-f]+`, they defined the parameter written to the assembler without looking for a label.
* Disassemblers should output a `+` prefix for positive explicit offsets by default.
* Both `+` and no prefixes shall be parsed as a positive explicit jump offset by assemblers.
* Explicit jump offsets must be written in hexadecimal, a hex specifier (`0x`) should not be used.


***

## Denied proposals

### \[DENIED\] Consistent store with typeflags (use ld notation)

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832310822931791873> -->

```
; type becomes implied by typeflag
st       local intarray $XXXXXXXX 1
ld       local int $XXXXXXXX 2
ldc.i    3
stelem   local intarray dim1 $XXXXXXXX 1

; with compound assignment
st.xor        local intarray $XXXXXXXX 1
ld            local int $XXXXXXXX 2
ldc.i         3
stelem.sub    local intarray dim1 $XXXXXXXX 1
; should type be required for compounds, same as normal operator?
ld            local int $XXXXXXXX 2
ldc.i         3
stelem.sub.i  local intarray dim1 $XXXXXXXX 1
```

### \[DENIED\] Removal of typeflags (use st notation)

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832313946014482432> -->

```
; [proposed] no type flags (ld.i looks wrong next to ldc.i)
st.iarr  local $XXXXXXXX 1
ld.i     local $XXXXXXXX 2
ldc.i    3
stelem.i local dim1 $XXXXXXXX 1
```

### \[DENIED\] Explicit hash syntax without group handling

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832331524392222741> -->

```
$@{$cb_console_on} ->  crc32("$cb_console_on")

${$cb_console_on}  ->  crc32("$cb_console_on@CONSOLE")
```

### \[DENIED\] Seperate syntax for syscall lookup

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832332890364575794> -->

```
; for syscalls
syscall    %{$strcmp} (2)

; (%{} implies resource lookup, and could be used the same way for external string resources)
; for string resources
text       %{res0101}
```

***

## Future Discussions

### \[OPEN\] External string resource syntax

<!-- discussion: <https://discord.com/channels/@me/766128075352047646/832332890364575794> -->

```
; for syscalls
syscall    %{$strcmp} (2)

; (%{} implies resource lookup, and could be used the same way for external string resources)
; for string resources
text       %{res0101}
```
