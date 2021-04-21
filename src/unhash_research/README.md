# Research package

Unlike the `_research.py` module included in `mjotool`, this package is designed for standalone research and side-by-side documentation with tutorials played out in Python.

The primary focus is CRC-32 unhashing, and working on more efficient methods of solving the elusive syscall hashed names in Majiro.


## TODO

See the PyPI package [crcsolver](https://pypi.org/project/crcsolver/), which contains some interesting modules like `subsetxor`. It seems this goes beyond using the brute-force method and determines outcomes that are impossible in advanced.

## crctools module

### Previews

##### *Explanation of flow when backing-out data, and what bytes go where during each iteration*
![](/docs/assets/crc_backout_flow.png)

##### *Explanation of backing-out ascii data from a CRC with only partial -or no- known trailing data*
![](/docs/assets/crc_backout_fullexample.png)

