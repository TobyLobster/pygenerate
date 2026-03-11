# pygenerate

**pygenerate** simplifies the disassembly and reassembly of BBC Micro programs. Given an SSD disk image, it generates everything needed to rebuild that image from source.

## Requirements

- Python 3
- The [beebasm](https://github.com/stardot/beebasm) or [acme](https://sourceforge.net/projects/acme-crossass/) assembler
- A recent version of [py8dis](https://github.com/ZornsLemma/py8dis)

All three tools must be callable from the command line before use.

## Usage
```sh
pygenerate.py path/to/disk/image.ssd
```

A folder with the same base name as the SSD is created in the current directory:

| Path | Description |
|------|-------------|
| `build.py` | Main build script |
| `control/` | Python scripts that control disassembly of binary files |
| `original/` | Original files being replicated |
| `readme.md` | Instructions for use |
| `source/` | Source code for each file on the disc |
| `tools/` | Python libraries used by the build process |

Run `build.py` to assemble the final files and SSD. Edit the files in `control/` to customise the disassembly.
