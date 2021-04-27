# Majiro uncompiled scripts

The **most invaluable resources** in the reversing process. These are "old" versions of `console.mjo` before compilation, found as-is, plaintext and all. Comparing these with the compiled bytecode has helped with many breakthroughs in understanding usage of opcodes, instruction operands, and how they're related to source syntaxes.

These files also made it possible to identify how name hashes are formatted. Allowing for attempts at unhashing names to better understand bytecode scripts.

***

## Contents

* `adv.mjh.bak` (second header file included in all scripts, dated from 2007)
* `console.mjs.old` (the newer of the two "old" files)
* `console.mjs.old2` (the older of the two "old" files, contains more code examples, but aligns left with the disassembled `console.mjo`)
* `console.mjil` (disassembled `console.mjo`. see [List of Majiro IL instructions](https://github.com/AtomCrafty/MajiroTools/wiki/List-of-Majiro-IL-instructions) for an explanation of the opcodes, most follow CIL instructions' naming patterns)
* `new_order.txt.t` (probably notes written by a dev while making changes in other scripts. original name: `新命令？.txt.t`)

**Important:** `console.mjs.old*` scripts have had their text encoding changed to UTF-8.

### About adv.mjh non-renderable character defines

Near the top of `adv.mjh.bak` is a set of group defines `#define [?] \g(0)*||`. The unknown characters are in the [Private Use Area](https://www.fileformat.info/info/unicode/block/private_use_area/index.htm) block, and act as reserved escapes for custom characters, used by the Majiro Script compiler. The codepoints are listed as follows in the table below.

<details><summary>see table</summary>

Original Shift\_JIS codepoints are included for identification, since `adv.mjh.bak` has been encoded in UTF-8 for accessibility. The first codepoint `\uff08` in the final row is a [Fullwidth left parenthesis](https://www.fileformat.info/info/unicode/char/ff08/index.htm) '<code>&#xff08;</code>'.

|Shift\_JIS|Unicode |Group        |
|:---------|:-------|:------------|
|`\xf0\x40`|`\ue000`|`\g(0)*\|\|` |
|`\xf0\x41`|`\ue001`|`\g(1)*\|\|` |
|`\xf0\x42`|`\ue002`|`\g(2)*\|\|` |
|`\xf0\x43`|`\ue003`|`\g(3)*\|\|` |
|`\xf0\x44`|`\ue004`|`\g(4)*\|\|` |
|`\xf0\x45`|`\ue005`|`\g(5)*\|\|` |
|`\xf0\x46`|`\ue006`|`\g(6)*\|\|` |
|`\xf0\x47`|`\ue007`|`\g(7)*\|\|` |
|`\xf0\x48`|`\ue008`|`\g(8)*\|\|` |
|`\xf0\x49`|`\ue009`|`\g(9)*\|\|` |
|`\xf0\x4a`|`\ue00a`|`\g(10)*\|\|`|
|`\xf0\x4b`|`\ue00b`|`\g(11)*\|\|`|
|`\xf0\x4c`|`\ue00c`|`\g(12)*\|\|`|
|`\xf0\x4d`|`\ue00d`|`\g(13)*\|\|`|
|`\xf0\x4e`|`\ue00e`|`\g(14)*\|\|`|
|`\xf0\x4f`|`\ue00f`|`\g(15)*\|\|`|
|`\xf0\x50`|`\ue010`|`\g(16)*\|\|`|
|`\xf0\x51`|`\ue011`|`\g(17)*\|\|`|
|`\xf0\x52`|`\ue012`|`\g(18)*\|\|`|
|`\xf0\x53`|`\ue013`|`\g(19)*\|\|`|
|`\xf0\x54`|`\ue014`|`\g(20)*\|\|`|
|`\xf0\x55`|`\ue015`|`\g(21)*\|\|`|
|`\xf0\x56`|`\ue016`|`\g(22)*\|\|`|
|`\xf0\x57`|`\ue017`|`\g(23)*\|\|`|
|`\xf0\x58`|`\ue018`|`\g(24)*\|\|`|
|`\xf0\x59`|`\ue019`|`\g(25)*\|\|`|
|`\xf0\x5a`|`\ue01a`|`\g(26)*\|\|`|
|`\xf0\x5b`|`\ue01b`|`\g(27)*\|\|`|
|`\xf0\x5c`|`\ue01c`|`\g(28)*\|\|`|
|`\xf0\x5d`|`\ue01d`|`\g(29)*\|\|`|
|`\xf0\x5e`|`\ue01e`|`\g(30)*\|\|`|
|`\xf0\x5f`|`\ue01f`|`\g(31)*\|\|`|
|`\xf0\x60`|`\ue020`|`\g(32)*\|\|`|
|`\xf0\x61`|`\ue021`|`\g(33)*\|\|`|
|`\xf0\x62`|`\ue022`|`\g(34)*\|\|`|
|`\xf0\x63`|`\ue023`|`\g(35)*\|\|`|
|`\xf0\x64`|`\ue024`|`\g(36)*\|\|`|
|`\xf0\x65`|`\ue025`|`\g(37)*\|\|`|
|`\x81\x69\xf0\x5c`|`\uff08\ue01c`|`\g(40,39,38)*\|\|`|

</details>