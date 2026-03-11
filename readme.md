# pygenerate

## Purpose
To make the disassembly and reassembly of BBC Micro programs easier. Given an SSD file it creates all the files needed to assemble the SSD from source.

## Requirements
* Python 3
* The beebasm or acme assembler
* A recent version of the py8dis disassembler

If each of these tools is callable from the command line, you're ready to go.

## Usage

    `pygenerate.py path/to/disk/image.ssd`

A folder with the same base name as the SSD is created in the current directory containing:

    build.py            the main build script
    control/            Python scripts that control disassembly of binary files
    original/           original files being replicated
    readme.md           instructions for use
    source/             source code for each file on the disc
    tools/              Python libraries used by the build process

Execute the `build.py` script to assemble the final files and SSD.
Edit the Python files in `control/` to control the disassembly.
