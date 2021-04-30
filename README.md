# majiro-py

Work-in-progress python library and tools created to aid in reversing the Majiro VN engine, in partnership with [AtomCrafty/MajiroTools](https://github.com/AtomCrafty/MajiroTools).

**Python Package Name:** `mjotool`<br>
**VSCode Extension Name:** `vscode-majiro`

**Warning:** This library *will* probably go through countless changes, refactors, and rewrites. Most of it, refactoring to catch up to the source C# project **mjotool** is based off of.


This library/tool is heavily tied to *and based on* [AtomCrafty/MajiroTools](https://github.com/AtomCrafty/MajiroTools), and additionally the repo's [Wiki knowledge base](https://github.com/AtomCrafty/MajiroTools/wiki).

***

## Contents

* Semi-functional Python tool for disassembling the Majiro script format. (`src/mjotool/`)
* VSCode extensions for disassembled Majiro IL script format syntax highlighting, WIP. (`plugin/vscode-majiro/`)


## Preview

*Disassembled Majiro IL from `console.mjo` using the VSCode language extension.*
<p align="center"><img src="./plugin/vscode-majiro/preview2.png"></p>


## External links

* [AtomCrafty/MajiroTools](https://github.com/AtomCrafty/MajiroTools) - C# tools for the MjIL specification, and home of the wiki.
* [trigger-segfault/unhash_name](https://github.com/trigger-segfault/unhash_name) - tool for recovering hashed variable and function names.
* [trigger-segfault/vscode_find_colors](https://github.com/trigger-segfault/vscode_find_colors) - tool for syntax highlighter design.
* [morkt/GARbro](https://github.com/morkt/GARbro) - tool for browsing and extracting archives: `.arc`, and images: `.rc8`, `.rct`.
* [Inori/FuckGalEngine/Majiro](https://github.com/Inori/FuckGalEngine/tree/master/Majiro) - various existing tools for Majiro, many of which contained valuable information on opcodes.