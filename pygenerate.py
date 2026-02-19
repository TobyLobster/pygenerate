#!/usr/bin/env python3
"""
BBC Micro file processor and build system generator.

Reads BBC Micro files from SSD/DSD disk images or loose files with .INF metadata,
generates editable source files (assembly, BASIC as text, etc), and creates build scripts
to reassemble them into new disk images.

Usage:
    python3 pygenerate.py <filepath.ssd|filepath.dsd|directory> [--acme|--beebasm] [--verbose]

Requirements:
    - py8dis: https://github.com/ZornsLemma/py8dis
    - beebasm or acme assembler: https://github.com/stardot/beebasm/ or https://sourceforge.net/projects/acme-crossass/
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
BBC_POUND = chr(96)
UNICODE_POUND = "\u00A3"

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

    def has_valid_exec(self, basic_memory_ranges = []):
        # Check the execution address is not within the range of BASIC code
        for r in basic_memory_ranges:
            if (self.exec_address >= r[0]) and (self.exec_address < (r[0] + r[1])):
                return False
        # Check the exec address is non-zero and within the range of the load address and length
        return (self.load_address & 0xffff != 0) and (self.exec_address & 0xffff != 0) and (self.exec_address & 0xffff >= self.load_address & 0xffff) and (self.exec_address & 0xffff < (self.load_address & 0xffff + self.length))

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
        exit_with_message(-4, f"An OS error occurred: {e.strerror or e}.")
    except TypeError:
        exit_with_message(-5, "Invalid type for source or destination path.")

def safe_move(source: str, destination: str) -> None:
    """Move a file or directory, exiting with an error message on failure."""
    try:
        shutil.move(source, destination)
    except FileNotFoundError:
        exit_with_message(-1, f"Could not find '{source}' to move to '{destination}'.")
    except PermissionError:
        exit_with_message(-2, f"Permission denied when accessing '{source}' or writing to '{destination}'.")
    except IsADirectoryError:
        # shutil.move can raise this if a file operation is attempted on a directory on some platforms
        exit_with_message(-3, f"The source '{source}' is a directory, not a file.")
    except shutil.Error as e:
        # Raised by shutil.move for specific move-related errors (e.g., same file, cross-device issues)
        exit_with_message(-4, f"Shutil error while moving: {e}")
    except OSError as e:
        exit_with_message(-5, f"An OS error occurred: {e.strerror or e}")
    except TypeError:
        exit_with_message(-6, "Invalid type for source or destination path.")

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


def is_hidden(name: str) -> bool:
    return name.startswith('.') and name not in ('.', '..')

def list_files_without_extension(dir_path: str) -> list[str]:
    """Return paths to files in a directory that don't have any extension."""
    return [
        os.path.join(dir_path, filename)
        for filename in os.listdir(dir_path)
        if not is_hidden(filename)
        and os.path.isfile(os.path.join(dir_path, filename))
        and not filename.lower().endswith('.inf')
        and not filename.lower().endswith('.py')
        and not filename.lower().endswith('.md')
    ]


def list_files_with_inf_extension(dir_path: str) -> list[str]:
    """Return paths to files in a directory that have a .inf extension."""
    return [
        os.path.join(dir_path, filename)
        for filename in os.listdir(dir_path)
        if not is_hidden(filename)
        and os.path.isfile(os.path.join(dir_path, filename))
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


def disc_metadata(disk_path: str) -> list[tuple[str, int]]:
    """Return a list of (title, boot_option) tuples for each side of a disk image."""
    with dfsimage.Image(disk_path) as img:
        return [(side.title, side.opt) for side in img.sides]


def extract_manually(disk_path: str, output_dir: str) -> None:
    """Extract files manually with full control."""
    os.makedirs(output_dir, exist_ok=True)
    result = []

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
                inf = f"{entry.fullname:<12} {entry.load_address:06X} {entry.exec_address:06X} {locked}"
                inf_path = os.path.join(side_dir, name + ".inf")
                with open(inf_path, 'w') as f:
                    f.write(inf)

                bbc_file = BBCMicroFile(out_path, bbc_filepath = entry.fullname, load_address = entry.load_address, exec_address = entry.exec_address, locked = entry.locked)
                result.append(bbc_file)
    return result


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
    if file.exec_address & 0xffff == 0:
        return False
    if file.exec_address & 0xffff < file.load_address & 0xffff:
        return False
    if file.exec_address & 0xffff >= (file.load_address & 0xffff + len(content)):
        return False
    if content[file.exec_address & 0xffff - file.load_address & 0xffff] == 0:
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
    print("    (a) Creates editable source/ files based on the file contents (e.g. assembly language files for code, text files for BASIC, etc),")
    print("    (b) Creates editable control/ files that control how the code gets disassembled (See py8dis documentation for details)")
    print("    (c) Creates a build.py script that:")
    print("        (i) disassembles the binary files according to the control/ files to get assembly files, then")
    print("        (ii) reassembles them into new build/disc/ binaries (identical to the original binaries), and")
    print("        (iii) recreates a new SSD or DSD from these.")
    print("The idea is to use pygenerate once to create an initial pass at a disassembly, then repeatedly call build.py after updating the control files to label the assembly better")
    print("This utility requires:")
    print("    'py8dis' (https://github.com/ZornsLemma/py8dis) to be visible to Python, e.g. in PYTHONPATH or in the same directory as this python script.")
    print("    'beebasm' or 'acme' assembler (https://github.com/stardot/beebasm/ or https://sourceforge.net/projects/acme-crossass/)")
    print("")
    print("USAGE: pygenerate <filepath to ssd> {--acme} {--beebasm}")

# write bytes from binary file as plain hex values (one line or configurable)
def bin_to_hextext(src_path: str, dst_path: str, bytes_per_line: int = 16, uppercase: bool = False) -> None:
    """
    Read a binary file and write a text file of hex values.
    Each line contains bytes_per_line hexadecimal byte values separated by spaces.
    """
    fmt = "{:02X}" if uppercase else "{:02x}"
    with open(src_path, "rb") as fin, open(dst_path, "w", encoding="utf-8") as fout:
        while True:
            chunk = fin.read(bytes_per_line)
            if not chunk:
                break
            line = " ".join(fmt.format(b) for b in chunk)
            fout.write(line + "\n")

def handle_code(bbc_file, source_directory, control_directory, asm_file, basic_memory_ranges):
    control_filepath = os.path.join(control_directory, os.path.basename(bbc_file.host_filepath) + ".py")
    host_filepath_relative_to_script = os.path.relpath(bbc_file.host_filepath, control_directory)

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

"""
    # Check for a bad load address, one that goes beyond the end of memory. Make up a low load address if so.
    # If it's still too big, then treat it separately
    big_file = False
    if ((bbc_file.load_address & 0xffff) + bbc_file.length) >= 0x10000:
        load_address = 0x200
        if (load_address + bbc_file.length) >= 0x10000:
            big_file = True
    else:
        load_address = bbc_file.load_address & 0xffff

    if big_file:
        # copy from bbc_file to text form (hex bytes) in source/<file>_hex.txt
        hex_text_basename = f"{os.path.basename(bbc_file.host_filepath)}_hex.txt"
        hex_text_filepath = os.path.join(source_directory, hex_text_basename)
        bin_to_hextext(bbc_file.host_filepath, hex_text_filepath)

        # Make the binary file from the hex text form: 'source/<file>_hex.txt' to 'build/disk/<file>'
        build_script = f'destination_filepath = script_dir / "build" / "disc" / "{os.path.basename(bbc_file.host_filepath)}"\n'
        build_script = f'hextext_to_bin("source/{hex_text_basename}", destination_filepath)\n'
        return (build_script, True)

    control_script += f'load(0x{load_address:04x}, "original/{os.path.basename(bbc_file.host_filepath)}", "6502")\n'
    if load_address == SIDEWAYS_ROM_ADDRESS:
        control_script += 'acorn.is_sideways_rom()\n'

    # TODO: Really only one range is supported atm
    for r in basic_memory_ranges:
        control_script += f'include_binary_file(0x{r[0] & 0xffff:04x}, "build/{os.path.basename(bbc_file.host_filepath)}_basic")\n'

    if bbc_file.has_valid_exec(basic_memory_ranges):
        control_script += f'entry(0x{bbc_file.exec_address & 0xffff:04x}, "entry_point")\n'
    control_script += "\ngo()\n"

    # Write the control file
    with open(control_filepath, "w") as fh:
        fh.write(control_script)

    # Execute the control file (calls py8dis to create the assembly file)
    build_script = f'disassemble("{os.path.basename(control_filepath)}", "{asm_file}")\n'

    # Assemble asm into new binaries
    build_script += f'assemble("{asm_file}", "{os.path.basename(bbc_file.host_filepath)}")\n'
    return (build_script, False)

def parse_arguments(args: Sequence[str]) -> None:
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

def main(args: Sequence[str]) -> None:
    """Main entry point for pygenerate.

    Args:
        args: Command-line arguments (excluding the script name).
    """
    parse_arguments(args)

    make_directory(config.destination_folder)

    original_directory  = os.path.join(config.destination_folder, "original")
    source_directory    = os.path.join(config.destination_folder, "source")
    control_directory   = os.path.join(config.destination_folder, "control")

    make_directory(original_directory)
    make_directory(source_directory)
    make_directory(control_directory)

    # Extract files from SSD into a list of loose files with .INF files
    files_to_process = []
    if len(config.ssd_filepath) > 0:
        files_to_process = extract_manually(config.ssd_filepath, original_directory)
    elif len(config.loose_folder) > 0:
        # Enumerate loose files (with or without a .inf file)
        disk_files = []

        binary_filenames = list_files_without_extension(config.loose_folder)
        inf_filenames = list_files_with_inf_extension(config.loose_folder)

        for bin_file in binary_filenames:
            # Move files to 'original' directory
            destination = os.path.join(original_directory, os.path.basename(bin_file))
            safe_move(bin_file, destination)

            # Copy associated .inf file too if needed
            if bin_file + ".inf" in inf_filenames:
                # Read info from the associated .inf file
                bbc_file = read_inf(bin_file)

                # Move INF file to 'original' directory
                safe_move(bin_file + ".inf", destination + ".inf")
            else:
                # Add a file without an associated .inf file
                bbc_file = BBCMicroFile(bin_file, bbc_filepath = os.path.basename(bin_file))

            # Update host filepath to the new location (after the safe.move)
            bbc_file.host_filepath = destination
            files_to_process.append(bbc_file)

    if config.assembler == "acme":
        assemble = """args = ["acme", "--symbollist", symbols_filepath, "-r", report_filepath, "-o", str(binary_filepath_full), str(asm_filepath_full)]
    run_subprocess(args, "assembly failed", script_dir)"""
    elif config.assembler == "beebasm":
        assemble = """args = ["beebasm", "-o", str(binary_filepath_full), "-i", str(asm_filepath_full), "-v"]

    report = run_subprocess(args, "assembly failed", script_dir)
    with open(report_filepath, "wb") as f:
        f.write(report)"""

    build_script = f"""#!/usr/bin/env python3
\"\"\"Build script for creating BBC Micro disk images for {os.path.basename(config.destination_folder)}.

This script:
- Disassembles the binaries using control files (see py8dis) into {config.assembler} assembly
- Assembles them back into binaries
- Tokenizes BBC BASIC programs from text files
- Packages everything into an SSD disk image
\"\"\"

import os
import subprocess
import sys
from pathlib import Path

import bbc_basic_tokenizer  # For tokenising BASIC programs
import dfsimage             # For writing BBC disk images


# Get the full directory path of this script
script_dir = Path(__file__).resolve().parent

def hextext_to_bin(src_path: str, dst_path: str) -> None:
    \"\"\"
    Read a text file containing hexadecimal byte values (space or newline separated)
    and write them back to a binary file.
    Lines may contain comments (starting with '#') or extra whitespace, which are ignored.
    \"\"\"
    import re

    hex_byte_re = re.compile(r"\\b([0-9A-Fa-f]{{2}})\\b")
    with open(src_path, "r", encoding="utf-8") as fin, open(dst_path, "wb") as fout:
        for line in fin:
            # drop inline comments
            line = line.split("#", 1)[0]
            for m in hex_byte_re.finditer(line):
                fout.write(bytes([int(m.group(1), 16)]))

def run_subprocess(args: list[str], error_message: str, cwd: Path | None = None) -> bytes:
    \"\"\"Execute a subprocess and return stdout.

    Args:
        args: Command and arguments to execute.
        error_message: Message to display if the command fails.
        cwd: Working directory for the subprocess.

    Returns:
        The stdout output from the subprocess.
    \"\"\"
    p = subprocess.run(args, capture_output=True, cwd=cwd)
    if p.returncode != 0:
        print(args)
        print(p.stderr.decode())
        print(error_message)
        sys.exit(p.returncode)
    return p.stdout


def disassemble(python_filepath: str, asm_filepath: str) -> None:
    \"\"\"Run a Python control script to create BeebAsm assembly files.

    Args:
        python_filepath: Relative path to the control script (within 'control' dir).
        asm_filepath: Relative path for the output assembly file (within 'source' dir).
    \"\"\"
    python_filepath_full = script_dir / "control" / python_filepath
    asm_filepath_full = script_dir / "source" / asm_filepath

    args = ["python3", str(python_filepath_full), "--beebasm", "--output", str(asm_filepath_full)]
    run_subprocess(args, "disassemble failed", script_dir)


def make_inf(binary_filepath: Path, bbc_bin_filename: str, load_address: int, exec_address: int, locked: str) -> None:
    \"\"\"Create a .inf metadata file for a BBC Micro binary.

    Args:
        binary_filepath: Path to the binary file.
        bbc_bin_filename: DFS filename (e.g. '$.TEMPEST').
        load_address: Memory address where the file should be loaded.
        exec_address: Memory address to execute from.
        locked: Lock status ('L' for locked, '' for unlocked).
    \"\"\"
    inf_text = f'{{bbc_bin_filename:<12}} {{load_address:06X}} {{exec_address:06X}} {{locked}}'
    with open(str(binary_filepath) + ".inf", "w") as text_file:
        text_file.write(inf_text)


def assemble(asm_filepath: str, binary_filepath: str) -> None:
    \"\"\"Assemble a BeebAsm source file to a binary.

    Args:
        asm_filepath: Relative path to the assembly source (within 'source' dir).
        binary_filepath: Relative path for the output binary (within 'build/disc' dir).
    \"\"\"
    asm_filepath_full = script_dir / "source" / asm_filepath
    binary_filepath_full = script_dir / "build" / "disc" / binary_filepath
    asm_filename = asm_filepath_full.stem
    report_filepath = script_dir / "build" / f"{{asm_filename}}_report.txt"

    # Assemble
    {assemble}


def copy_text_to_bbc(source_filepath: Path, destination_filepath: Path) -> None:
    \"\"\"Copy a text file, converting line endings to BBC Micro format.

    Args:
        source_filepath: Path to the source text file.
        destination_filepath: Path for the output file.
    \"\"\"
    with open(source_filepath, "rb") as f:
        content = f.read()

    # Replace host line terminator with BBC Micro line terminator (0x0d)
    with open(destination_filepath, "wb") as f:
        f.write(content.replace(os.linesep.encode(), b'\\x0d'))


def tokenize_basic(source_filepath: Path, destination_filepath: Path) -> None:
    \"\"\"Tokenize a BBC BASIC source file.

    Args:
        source_filepath: Path to the BASIC source text file.
        destination_filepath: Path for the tokenized output file.
    \"\"\"
    with open(source_filepath, "rb") as f:
        tokenized_result = bbc_basic_tokenizer.tokenize_file(f, input_file_contains_escaped_chars=True)
        with open(destination_filepath, "wb") as file:
            file.write(bytearray(tokenized_result))
        return len(tokenized_result)


def add_file(
    image: dfsimage.Image,
    input_file: Path | str,
    dfs: str,
    load_addr: int,
    exec_addr: int,
    locked: bool = True,
) -> None:
    \"\"\"Add a file to a DFS disk image.

    Args:
        image: The DFS image to add the file to.
        input_file: Path to the file to add.
        dfs: DFS filename (e.g. '$.TEMPEST').
        load_addr: Memory address where the file should be loaded.
        exec_addr: Memory address to execute from.
        locked: Whether the file should be locked.
    \"\"\"
    image.import_files(
        os_files=str(input_file),
        dfs_names=dfs,
        ignore_access=True,
        inf_mode=dfsimage.InfMode.NEVER,
        load_addr=load_addr,
        exec_addr=exec_addr,
        locked=locked,
        replace=True,
    )

# Make build/disc directory
(script_dir / "build" / "disc").mkdir(parents=True, exist_ok=True)
"""

    # Process each file, creating a control script for each binary we need to deal with
    for bbc_file in files_to_process:
        with open(bbc_file.host_filepath, "rb") as fh:
            content = fh.read()
            bbc_file.length = len(content)

            print(f'Processing file {bbc_file.bbc_filepath}', end='')

            # Check if it's BASIC:
            listing, end_index, success = bbc_basic_detokenizer.decode_basic(content)
            if success:
                # BASIC program found
                basic_txt = "".join(listing)

                # Write the BASIC text out to source folder
                bbc_file.source_filepath = os.path.join(source_directory, os.path.basename(bbc_file.host_filepath) + "_basic.txt")
                with open(bbc_file.source_filepath, "w") as fh:
                    fh.write(basic_txt)

                needs_assembly = end_index < bbc_file.length
                if needs_assembly:
                    if (bbc_file.exec_address & 0xffff >= bbc_file.load_address & 0xffff + end_index) and (bbc_file.exec_address & 0xffff < (bbc_file.load_address & 0xffff + bbc_file.length)):
                        print(f" as BASIC + {len(content) - end_index} bytes of machine code beyond the end of the BASIC program")
                    else:
                        print(f" as BASIC + {len(content) - end_index} bytes of data beyond the end of the BASIC program")
                else:
                    print(f" as BASIC")

                # We only support one BASIC snippet per file currently
                basic_snippet = [(bbc_file.load_address & 0xffff, end_index)]

                # Convert to BASIC II format on disc
                build_script += f'\n# Create BASIC file {bbc_file.bbc_filepath}\n'
                build_script += f'source_filepath = script_dir / "source" / "{os.path.basename(bbc_file.source_filepath)}"\n'
                build_script += f'destination_filepath = script_dir / "build" / "disc" / "{os.path.basename(bbc_file.host_filepath)}"\n'
                if needs_assembly:
                    build_script += f'tokenized_basic = script_dir / "build" / "{os.path.basename(bbc_file.host_filepath)}_basic"\n'
                    build_script += f'tokenize_basic(source_filepath, tokenized_basic)\n'

                    asm_file = f"{os.path.basename(bbc_file.host_filepath)}_{config.assembler}.asm"
                    build_script_result, big_file = handle_code(bbc_file, source_directory, control_directory, asm_file, basic_snippet)

                    if big_file:
                        build_script += f'\n# Create hex file {bbc_file.bbc_filepath}\n'
                    else:
                        build_script += f'\n# Create disassembly {bbc_file.bbc_filepath}\n'
                    build_script += build_script_result
                else:
                    build_script += f'tokenize_basic(source_filepath, destination_filepath)\n'

                # Create INF for destination file
                build_script += f'make_inf(destination_filepath, "{bbc_file.bbc_filepath}", 0x{bbc_file.load_address:06x}, 0x{bbc_file.exec_address:06x}, "{"L" if bbc_file.locked else ""}")\n'

            elif is_totally_printable(content):
                print(" as text")
                # Write the current file content into a file in source_directory, with carriage returns converted to the host OS line ending
                bbc_file.source_filepath = os.path.join(source_directory, os.path.basename(bbc_file.host_filepath) + ".txt")
                with open(bbc_file.source_filepath, "wb") as fh:
                    fh.write(content.replace(b'\x0d', os.linesep.encode()))

                build_script += f'\n# Create text file {bbc_file.bbc_filepath}\n'
                build_script += f'destination_filepath = script_dir / "build" / "disc" / "{os.path.basename(bbc_file.host_filepath)}"\n'
                build_script += f'copy_text_to_bbc(script_dir / "source" / "{os.path.basename(bbc_file.source_filepath)}", destination_filepath)\n'
                build_script += f'make_inf(destination_filepath, "{bbc_file.bbc_filepath}", 0x{bbc_file.load_address:06x}, 0x{bbc_file.exec_address:06x}, "{"L" if bbc_file.locked else ""}")\n'

            else:
                if bbc_file.has_valid_exec():
                    print(" as machine code")
                else:
                    print(" as binary data")
                # Disassemble
                # Add to python control script that will invoke py8dis to disassemble the file
                # For tempest: move(0x0a00, 0x1900, 0x4300-0x1900)

                asm_file = f"{os.path.basename(bbc_file.host_filepath)}_{config.assembler}.asm"
                build_script_result, big_file = handle_code(bbc_file, source_directory, control_directory, asm_file, [])

                if big_file:
                    build_script += f'\n# Create hex file {bbc_file.bbc_filepath}\n'
                else:
                    build_script += f'\n# Create disassembly {bbc_file.bbc_filepath}\n'
                build_script += f'destination_filepath = script_dir / "build" / "disc" / "{os.path.basename(bbc_file.host_filepath)}"\n'
                build_script += build_script_result

                # Create INF for destination file
                build_script += f'make_inf(destination_filepath, "{bbc_file.bbc_filepath}", 0x{bbc_file.load_address:06x}, 0x{bbc_file.exec_address:06x}, "{"L" if bbc_file.locked else ""}")\n'

    # Create disc image
    build_script += f'\n# Create {config.extension}\n'
    if config.ssd_filepath:
        ssd_title = os.path.splitext(os.path.basename(config.ssd_filepath))[0]
    else:
        ssd_title = os.path.basename(config.destination_folder)

    build_script += f'with dfsimage.Image.create(str(script_dir / "{ssd_title}_new.ssd")) as image:\n'

    # Add title and opt to each side, based on original SSD
    if config.ssd_filepath:
        side_index = 0
        sides_metadata = disc_metadata(config.ssd_filepath)
        for side in sides_metadata:
            build_script += f"    image.sides[{side_index}].title = '{side[0]}'\n"
            build_script += f"    image.sides[{side_index}].opt = {side[1]}\n"
            side_index += 1

    # Add files
    files_to_process.reverse()
    for bbc_file in files_to_process:
        build_script += f"    add_file(image, script_dir / 'build' / 'disc' / '{os.path.basename(bbc_file.host_filepath)}', '{bbc_file.bbc_filepath}', load_addr=0x{bbc_file.load_address:06x}, exec_addr=0x{bbc_file.exec_address:06x}, locked={bbc_file.locked})\n"

    # Copy dfsimage and basic tokenizer
    shutil.copytree(os.path.join(script_dir, "dfsimage"), os.path.join(config.destination_folder, "dfsimage"), dirs_exist_ok=True)
    safe_copy(os.path.join(script_dir, "bbc_basic_tokenizer.py"), os.path.join(config.destination_folder, "bbc_basic_tokenizer.py"))

    # Write the build script
    with open(os.path.join(config.destination_folder, "build.py"), "w") as fh:
        fh.write(build_script)


if __name__ == "__main__":
    main(sys.argv[1:])
