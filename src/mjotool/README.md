# mjotool

A python module program for disassembling Majiro `.mjo` scripts, and outputting analyzed instruction blocks.

Default behavior is to print an input script to the console, **which is VERY VERBOSE**.

## Usage

```
usage: python -m mjotool [-h] [-C] [-o MJILFILE] [-R] MJOFILE [MJOFILE ...]

positional arguments:
  MJOFILE               .mjo script file/directory to read

optional arguments:
  -h, --help            show this help message and exit
  -C, --no-color        disable color printing
  -o MJILFILE, --output MJILFILE
                        write to output file/directory instead of console

internal arguments:
  -R, --research        run custom research functions that are not intended
                        for use
```
