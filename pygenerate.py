#!/usr/bin/env python3
"""
BBC Micro file processor and build system generator.

Reads BBC Micro files from SSD/DSD disk images or loose files with .INF metadata,
generates editable source files (assembly, BASIC, text), and creates build scripts
to reassemble them into new disk images.

Usage:
    python3 pygenerate.py <filepath.ssd|filepath.dsd|directory> [--acme|--beebasm] [--verbose]

Requirements:
    - py8dis: https://github.com/ZornsLemma/py8dis
    - beebasm or acme assembler
    - dfsimage, bbc_basic_detokenizer (Python packages)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import bbc_basic_detokenizer
import dfsimage

if TYPE_CHECKING:
    from collections.abc import Sequence

# Character used to represent the pound sign in BBC Micro filenames
BBC_POUND = "`"
UNICODE_POUND = bytes((0xa3,)).decode("iso8859-1")

# Standard load address for sideways ROMs
SIDEWAYS_ROM_ADDRESS = 0x8000

script_dir = os.path.dirname(os.path.realpath(__file__))

class BBCMicroFile:
    """Represents a BBC Micro file with its metadata.

    Attributes:
        host_filepath: Path to the file on the host system.
        bbc_filepath: Original BBC Micro DFS filepath (e.g., "$.PROG").
        load_address: Memory address where the file should be loaded.
        exec_address: Memory address to begin execution.
        locked: Whether the file is locked on the DFS.
        length: File size in bytes (set after reading).
        source_filepath: Path to the generated source file.
    """

    def __init__(
        self,
        host_filepath: str = "",
        bbc_filepath: str = "",
        load_address: int = 0,
        exec_address: int = 0,
        locked: bool = False,
    ) -> None:
        self.host_filepath = host_filepath
        self.bbc_filepath = bbc_filepath
        self.load_address = load_address
        self.exec_address = exec_address
        self.locked = locked
        self.length: int | None = None
        self.source_filepath: str | None = None


class Config:
    """Configuration settings for the pygenerate tool.

    Attributes:
        ssd_filepath: Path to the BBC Micro disk image (SSD/DSD).
        loose_folder: Directory containing loose BBC Micro files.
        destination_folder: Output directory for generated files.
        extension: File extension of the source disk image.
        verbose: Whether to print verbose output.
        assembler: Assembler to use ('acme' or 'beebasm').
    """

    def __init__(self) -> None:
        self.ssd_filepath: str = ""
        self.loose_folder: str = ""
        self.destination_folder: str = ""
        self.extension: str = ""
        self.verbose: bool = False
        self.assembler: str = "beebasm"


config = Config()


def exit_with_message(code: int, message: str) -> None:
    """Print an error message and exit with the given code."""
    if code != 0:
        print(f"ERROR: {message} (exit code {code})")
    sys.exit(code)

def make_absolute_filepath(relative_filepath: str) -> str:
    """Convert a relative path to an absolute path based on the current working directory."""
    return os.path.join(os.getcwd(), relative_filepath)


def safe_copy(source: str, destination: str) -> None:
    """Copy a file, exiting with an error message on failure."""
    try:
        shutil.copy(source, destination)
    except FileNotFoundError:
        exit_with_message(-1, f"Could not find file '{source}' to copy to '{destination}'")
    except PermissionError:
        exit_with_message(-2, f"Permission denied when trying to access '{source}' or write to '{destination}'.")
    except IsADirectoryError:
        exit_with_message(-3, f"The source '{source}' is a directory, not a file.")
    except OSError as e:
        exit_with_message(-4, f"An OS error occurred: {e.strerror}.")
    except TypeError:
        exit_with_message(-5, "Invalid type for source or destination path.")


def run_subprocess(args: list[str], error_message: str, cwd: str | None = None) -> bytes:
    """Execute a subprocess and return stdout, exiting on failure."""
    if config.verbose:
        print(args)
    result = subprocess.run(args, capture_output=True, cwd=cwd)
    if result.returncode != 0:
        print(args)
        print(result.stderr.decode())
        exit_with_message(result.returncode, error_message)
    return result.stdout


def make_directory(directory: str) -> None:
    """Create a directory and any necessary parent directories."""
    os.makedirs(directory, exist_ok=True)


def list_files_without_inf_extension(dir_path: str) -> list[str]:
    """Return paths to files in a directory that don't have a .inf extension."""
    return [
        os.path.join(dir_path, filename)
        for filename in os.listdir(dir_path)
        if os.path.isfile(os.path.join(dir_path, filename))
        and not filename.lower().endswith('.inf')
    ]


def list_files_with_inf_extension(dir_path: str) -> list[str]:
    """Return paths to files in a directory that have a .inf extension."""
    return [
        os.path.join(dir_path, filename)
        for filename in os.listdir(dir_path)
        if os.path.isfile(os.path.join(dir_path, filename))
        and filename.lower().endswith('.inf')
    ]


# Character mapping from BBC Micro to host filesystem
_BBC_TO_HOST_CHAR_MAP = {
    "/": "#slash",
    "?": "#question",
    "<": "#less",
    ">": "#greater",
    "\\": "#backslash",
    ":": "#colon",
    "*": "#star",
    "|": "#bar",
    '"': "#quote",
    BBC_POUND: UNICODE_POUND,
}

# Reverse mapping from host filesystem to BBC Micro
_HOST_TO_BBC_CHAR_MAP = {v: k for k, v in _BBC_TO_HOST_CHAR_MAP.items()}


def convert_to_host_filename(bbc_filename: str) -> str:
    """Convert a BBC Micro DFS filename to a host filesystem-safe filename.

    Replaces characters that are invalid on common filesystems (e.g., /, ?, <, >)
    with safe placeholders like #slash, #question, etc.
    """
    result = bbc_filename
    for bbc_char, host_char in _BBC_TO_HOST_CHAR_MAP.items():
        result = result.replace(bbc_char, host_char)
    return result


def convert_to_bbc_filename(host_filename: str) -> str:
    """Convert a host filename back to the original BBC Micro DFS filename.

    Reverses the character replacements made by convert_to_host_filename().
    """
    result = host_filename
    for host_char, bbc_char in _HOST_TO_BBC_CHAR_MAP.items():
        result = result.replace(host_char, bbc_char)
    return result


def disk_metadata(disk_path: str) -> list[tuple[str, int]]:
    """Return a list of (title, boot_option) tuples for each side of a disk image."""
    with dfsimage.Image(disk_path) as img:
        return [(side.title, side.opt) for side in img.sides]


def extract_manually(disk_path: str, output_dir: str) -> None:
    """Extract files manually with full control."""
    os.makedirs(output_dir, exist_ok=True)

    with dfsimage.Image(disk_path) as img:
        for side in img.sides:
            # Create subdirectory per side if double-sided
            if img.heads > 1:
                side_dir = os.path.join(output_dir, f"side{side.head}")
                os.makedirs(side_dir, exist_ok=True)
            else:
                side_dir = output_dir

            for entry in side.files:
                name = convert_to_host_filename(entry.fullname)
                data = entry.readall()

                out_path = os.path.join(side_dir, name)
                with open(out_path, 'wb') as f:
                    f.write(data)

                if entry.locked:
                    locked = "L"
                else:
                    locked = ""
                inf = f"{entry.fullname:<12} {entry.load_address:08X} {entry.exec_address:08X} {locked}"
                inf_path = os.path.join(side_dir, name + ".inf")
                with open(inf_path, 'w') as f:
                    f.write(inf)

def read_inf(host_filepath: str) -> BBCMicroFile:
    """Read a .inf metadata file and return a BBCMicroFile with the parsed information."""
    result = BBCMicroFile(host_filepath)

    with open(host_filepath + ".inf", "r") as inf_file:
        input_string = inf_file.read()

        tokens = [word for word in input_string.split(' ') if word]
        if "L" in tokens:
            tokens.remove("L")
            result.locked = True
        if "Locked" in tokens:
            tokens.remove("Locked")
            result.locked = True
        result.bbc_filepath = tokens[0]
        result.load_address = int(tokens[1], 16)
        result.exec_address = int(tokens[2], 16)

    return result


def is_disassembly(file: dfsimage.Entry, content: bytes) -> bool:
    """Check if a file appears to be executable code that should be disassembled.

    Returns True if the exec_address points to a valid, non-zero byte within the file.
    """
    if file.exec_address == 0:
        return False
    if file.exec_address < file.load_address:
        return False
    if file.exec_address >= (file.load_address + len(content)):
        return False
    if content[file.exec_address - file.load_address] == 0:
        return False
    return True


def is_mostly_printable(data: bytes, threshold: float = 0.95) -> bool:
    """Check if at least threshold proportion of bytes are printable ASCII or CR."""
    if not data:
        return True
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b == 13)
    return printable_count >= (threshold * len(data))


def is_totally_printable(data: bytes) -> bool:
    """Check if all bytes are printable ASCII or carriage returns."""
    if not data:
        return True
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b == 13)
    return printable_count == len(data)


def show_usage() -> None:
    """Print usage information and requirements."""
    print("This utility reads BBC Micro files (from SSD, DSD, or a directory of files perhaps with associated .INF files), and:")
    print("    (a) creates editable source files based on the file contents (e.g. assembly language files for code, text files for BASIC),")
    print("    (b) assembles them into new binaries (identical to the original binaries) and")
    print("    (c) recreates an SSD or DSD from the results.")
    print("This utility requires:")
    print("    'py8dis' (https://github.com/ZornsLemma/py8dis) to be visible to Python, e.g. in PYTHONPATH or in the same directory as this python script.")
    print("    'beebasm' or 'acme' assembler (https://github.com/stardot/beebasm/ or https://sourceforge.net/projects/acme-crossass/)")
    print("")
    print("USAGE: pygenerate <filepath to ssd> {--acme} {--beebasm}")


def main(args: Sequence[str]) -> None:
    """Main entry point for pygenerate.

    Args:
        args: Command-line arguments (excluding the script name).
    """
    if len(args) == 0:
        show_usage()
        exit_with_message(0, "")

    # Parse arguments
    for i in range(0, len(args)):
        if args[i] == "--verbose":
            config.verbose = True
        elif args[i] == "--acme":
            config.assembler = "acme"
        elif args[i] == "--beebasm":
            config.assembler = "beebasm"
        elif args[i].lower().endswith(".ssd") or args[i].lower().endswith(".dsd"):
            config.ssd_filepath = make_absolute_filepath(args[i])
            config.destination_folder, config.extension = os.path.splitext(os.path.basename(config.ssd_filepath))
        elif args[i].startswith("-"):
            show_usage()
            exit_with_message(1, f"Unknown option {args[i]}")
        else:
            config.loose_folder = make_absolute_filepath(args[i])
            config.destination_folder, config.extension = os.path.splitext(os.path.basename(config.loose_folder))

    make_directory(config.destination_folder)

    original_directory  = os.path.join(config.destination_folder, "original")
    source_directory    = os.path.join(config.destination_folder, "source")
    control_directory   = os.path.join(config.destination_folder, "control")

    make_directory(original_directory)
    make_directory(source_directory)
    make_directory(control_directory)

    # Extract files from SSD into a list of loose files with .INF files
    if len(config.ssd_filepath) > 0:
        extract_manually(config.ssd_filepath, original_directory)
        config.loose_folder = original_directory

    # Enumerate the loose files (with or without a .inf file)
    files_to_process = []
    if len(config.loose_folder) > 0:
        disk_files = []

        binary_filenames = list_files_without_inf_extension(config.loose_folder)
        inf_filenames = list_files_with_inf_extension(config.loose_folder)

        for bin_file in binary_filenames:
            # Copy file to original directory if needed
            if config.loose_folder != original_directory:
                safe_copy(os.path.join(config.loose_folder, bin_file),
                          os.path.join(original_directory, bin_file))

            # Copy associated .inf file too if needed
            if bin_file + ".inf" in inf_filenames:
                # Copy file to original directory if needed
                if config.loose_folder != original_directory:
                    safe_copy(os.path.join(config.loose_folder, bin_file + ".inf"),
                              os.path.join(original_directory, bin_file + ".inf"))

                # Read info from the associated .inf file
                bbc_file = read_inf(bin_file)
            else:
                # Add a file without an associated .inf file
                bbc_file = BBCMicroFile(bin_file, bbc_filepath = os.path.basename(bin_file))
            files_to_process.append(bbc_file)

    if config.assembler == "acme":
        assemble = """args = ["acme", "--symbollist", symbols_filepath, "-r", report_filepath, "-o", binary_filepath, asm_filepath]
    run(args, "assembly failed")"""
    elif config.assembler == "beebasm":
        # beebasm -o disk/imogen -i source/imogen.asm -v > build/imogen.lst

        assemble = """args = ["beebasm", "-o", binary_filepath, "-i", asm_filepath, "-v"]

    report = run(args, "assembly failed")
    with open(report_filepath, "wb") as f:
        f.write(report)"""

    build_script = f"""#!/usr/bin/env python3
import os
import subprocess
import glob
import bbc_basic_tokenizer  # For tokenising BASIC programs
import dfsimage             # for writing BBC disk images


# Get the full directory path of this script
script_dir = os.path.dirname(os.path.realpath(__file__))

# Execute a subprocess, returning the stdout
def run(args, error_message, cwd=None):
    p = subprocess.run(args, capture_output=True, cwd=cwd)
    if p.returncode != 0:
        print(args)
        print(p.stderr.decode())
        print(error_message)
        exit(p.returncode)
    return p.stdout

def disassemble(python_filepath, asm_filepath):
    # Run a python control script to create Beebasm or Acme asm files

    python_filepath = os.path.join(script_dir, "control", python_filepath)
    asm_filepath = os.path.join(script_dir, "source", asm_filepath)

    # Create assembly files
    args = ["python3", python_filepath, "--{config.assembler}", "--output", asm_filepath]
    run(args, "disassemble failed")

def make_inf(binary_filepath, bbc_bin_filename, load_address, exec_address, locked):
    inf_text = f'{{bbc_bin_filename:<12}} {{load_address:08x}} {{exec_address:08x}} {{locked}}'
    with open(binary_filepath + ".inf", "w") as text_file:
        text_file.write(inf_text)

def assemble(asm_filepath, binary_filepath):
    asm_filepath     = os.path.join(script_dir, "source", asm_filepath)
    binary_filepath  = os.path.join(script_dir, "build", "disc", binary_filepath)
    asm_filename     = os.path.splitext(os.path.basename(asm_filepath))[0]
    symbols_filepath = os.path.join(script_dir, "build", asm_filename + "_symbols.txt")
    report_filepath  = os.path.join(script_dir, "build", asm_filename + "_report.txt")

    # Assemble
    {assemble}

def copy_text_to_bbc(source_filepath, destination_filepath):
    # Read the source file
    with open(source_filepath, "rb") as f:
        content = f.read()

    # Write the destination file, replacing the host line terminator with the BBC Micro line terminator (0x0d)
    with open(destination_filepath, "wb") as f:
        f.write(content.replace(os.linesep.encode(), b'\\x0d'))

def add_file(image, input_file, dfs, load_addr, exec_addr, locked=True):
    image.import_files(os_files=input_file, dfs_names=dfs, ignore_access=True, inf_mode=dfsimage.InfMode.NEVER, load_addr=0x00000000,  exec_addr=0x00000000, locked=True, replace=True)

# Make build/disc directory
os.makedirs(os.path.join(script_dir, "build", "disc"), exist_ok=True)
"""

    # Process each file, creating a control script for each binary we need to deal with
    for bbc_file in files_to_process:
        with open(bbc_file.host_filepath, "rb") as fh:
            content = fh.read()
            bbc_file.length = len(content)

            print(f'Processing file {bbc_file.bbc_filepath}')

            # Check if it's BASIC:
            listing, end_index, success = bbc_basic_detokenizer.decode_basic(content)
            if success:
                # BASIC program found
                basic_txt = "".join(listing)

                # Write the BASIC text out to source folder
                bbc_file.source_filepath = os.path.join(source_directory, os.path.basename(bbc_file.host_filepath) + "_basic.txt")
                with open(bbc_file.source_filepath, "w") as fh:
                    fh.write(basic_txt)

                if end_index < bbc_file.length:
                    print(f"with {len(content) - end_index} more bytes beyond the end of the BASIC program")

                # Convert to BASIC II format on disc
                build_script += f'\n# Create BASIC file {bbc_file.bbc_filepath}\n'
                build_script += f'source_filepath = os.path.join(script_dir, "source", "{os.path.basename(bbc_file.source_filepath)}")\n'
                build_script += f'destination_filepath = os.path.join(script_dir, "build", "disc", "{os.path.basename(bbc_file.host_filepath)}")\n'
                build_script += f'with open(source_filepath, "rb") as f:\n'
                build_script += f'    tokenized_result = bbc_basic_tokenizer.tokenize_file(f, input_file_contains_escaped_chars=True)\n'
                build_script += f'    with open(destination_filepath, "wb") as file:\n'
                build_script += f'        file.write(bytearray(tokenized_result))\n'
                # Create INF for destination file
                build_script += f'make_inf(destination_filepath, "{bbc_file.bbc_filepath}", 0x{bbc_file.load_address:08x}, 0x{bbc_file.exec_address:08x}, "{"L" if bbc_file.locked else ""}")\n'

            elif is_totally_printable(content):
                # Write the current file content into a file in source_directory, with carriage returns converted to the host OS line ending
                bbc_file.source_filepath = os.path.join(source_directory, os.path.basename(bbc_file.host_filepath) + ".txt")
                with open(bbc_file.source_filepath, "wb") as fh:
                    fh.write(content.replace(b'\x0d', os.linesep.encode()))

                build_script += f'\n# Create text file {bbc_file.bbc_filepath}\n'
                build_script += f'destination_filepath = os.path.join(script_dir, "build", "disc", "{os.path.basename(bbc_file.host_filepath)}")\n'
                build_script += f'copy_text_to_bbc(os.path.join(script_dir, "source", "{os.path.basename(bbc_file.source_filepath)}"), destination_filepath)\n'
                build_script += f'make_inf(destination_filepath, "{bbc_file.bbc_filepath}", 0x{bbc_file.load_address:08x}, 0x{bbc_file.exec_address:08x}, "{"L" if bbc_file.locked else ""}")\n'

            else:
                # Disassemble
                # Add to python control script that will invoke py8dis to disassemble the file
                control_script = f"# Control script for disassembling '{os.path.basename(bbc_file.host_filepath)}'\n\n"
                control_script += """from commands import *
import acorn
import os

config.set_label_references(False)
config.set_hex_dump(True)
#config.set_bytes_as_ascii(False)
config.set_show_autogenerated_labels(False)
config.set_show_cpu_state(False)
config.set_show_char_literals(False)
config.set_show_all_labels(False)

acorn.bbc()

py_dir = os.path.dirname(os.path.abspath(__file__))
"""
                # For tempest: move(0x0a00, 0x1900, 0x4300-0x1900)

                control_filepath = os.path.join(control_directory, os.path.basename(bbc_file.host_filepath) + ".py")

                host_filepath_relative_to_script = os.path.relpath(bbc_file.host_filepath, control_directory)

                control_script += f'# FILE {bbc_file.bbc_filepath}\n'
                control_script += f'load(0x{bbc_file.load_address:04x}, os.path.join(py_dir, "{host_filepath_relative_to_script}"), "6502")\n'
                if bbc_file.load_address == SIDEWAYS_ROM_ADDRESS:
                    control_script += 'acorn.is_sideways_rom()\n'
                if (bbc_file.load_address != 0) and (bbc_file.exec_address >= bbc_file.load_address) and (bbc_file.exec_address < (bbc_file.load_address + bbc_file.length)):
                    control_script += f'entry(0x{bbc_file.exec_address:04x}, "entry_point")\n'
                control_script += "\ngo()\n"

                # Write the control file
                with open(control_filepath, "w") as fh:
                    fh.write(control_script)

                # Execute the control file (calls py8dis to create the assembly file)
                build_script += f'\n# Create disassembly {bbc_file.bbc_filepath}\n'
                build_script += f'destination_filepath = os.path.join(script_dir, "build", "disc", "{os.path.basename(bbc_file.host_filepath)}")\n'
                asm_file = f"{os.path.basename(bbc_file.host_filepath)}_{config.assembler}.asm"
                build_script += f'disassemble("{os.path.basename(control_filepath)}", "{asm_file}")\n'

                # Assemble asm into new binaries
                build_script += f'assemble("{asm_file}", "{os.path.basename(bbc_file.host_filepath)}")\n'
                # Create INF for destination file
                build_script += f'make_inf(destination_filepath, "{bbc_file.bbc_filepath}", 0x{bbc_file.load_address:08x}, 0x{bbc_file.exec_address:08x}, "{"L" if bbc_file.locked else ""}")\n'

    # Create disc image
    build_script += f'\n# Create {config.extension}\n'
    build_script += f'with dfsimage.Image.create("{os.path.splitext(os.path.basename(config.ssd_filepath))[0]}_new.ssd") as image:\n'

    # Add title and opt to each side
    side_index = 0
    sides_metadata = disk_metadata(config.ssd_filepath)
    for side in sides_metadata:
        build_script += f"    image.sides[{side_index}].title = '{side[0]}'\n"
        build_script += f"    image.sides[{side_index}].opt = {side[1]}\n"
        side_index += 1

    # Add files
    for bbc_file in files_to_process:
        build_script += f"    add_file(image, os.path.join(script_dir, 'build', 'disc', '{os.path.basename(bbc_file.host_filepath)}'), '{bbc_file.bbc_filepath}', load_addr=0x{bbc_file.load_address:08x},  exec_addr=0x{bbc_file.exec_address:08x}, locked={bbc_file.locked})\n"

    # Copy dfsimage
    shutil.copytree(os.path.join(script_dir, "dfsimage"), os.path.join(config.destination_folder, "dfsimage"), dirs_exist_ok=True)

    # Write the build script
    with open(os.path.join(config.destination_folder, "build.py"), "w") as fh:
        fh.write(build_script)


if __name__ == "__main__":
    main(sys.argv[1:])
