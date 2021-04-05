# Majiro uncompiled scripts

The **most invaluable resources** in the reversing process. These are "old" versions of `console.mjo` before compilation, found as-is, plaintext and all. Comparing these with the compiled bytecode has helped with many breakthroughs in understanding usage of opcodes, instruction operands, and how they're related to source syntaxes.

These files also made it possible to identify how name hashes are formatted. Allowing for attempts at unhashing names to better understand bytecode scripts.

***

## Contents

* `console.mjs.old` (the newer of the two "old" files)
* `console.mjs.old2` (the older of the two "old" files, contains more code examples, but aligns left with the disassembled `console.mjo`)
* `console.mjil` (disassembled `console.mjo`. see [List of Majiro IL instructions](https://github.com/AtomCrafty/MajiroTools/wiki/List-of-Majiro-IL-instructions) for an explanation of the opcodes, most follow CIL instructions' naming patterns)

**Important:** `console.mjs.old*` scripts have had their text encoding changed to UTF-8.
