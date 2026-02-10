#!/usr/bin/env python3

import shutil           # for copying files
import sys              # for exiting the script with an exit code
import os               # for path manipulation
import subprocess       # for running other processes
import re               # for parsing INF files

import dfsimage                 # for reading BBC disk images
import bbc_basic_detokenizer    # For identifying and detokenising BASIC

script_dir = os.path.dirname(os.path.realpath(__file__))

class BBCMicroFile:
    def __init__(self, host_filepath="", bbc_filepath = "", load_address=0, exec_address=0, locked=False):
        self.host_filepath = host_filepath  # Host system filepath
        self.bbc_filepath  = bbc_filepath   # BBC Micro DFS filepath
        self.load_address = load_address    # Load address
        self.exec_address = exec_address    # Exec address
        self.locked = locked                # Lock status

        # Derived values
        self.length = None
        self.source_filepath = None


class Config:
    def __init__(self, ssd_filepath="", loose_folder = "", destination_folder="", extension="", verbose=False):
        self.ssd_filepath        = ""            # The filepath to the BBC Micro disk image (SSD / DSD)
        self.loose_folder        = ""            # The folder where the loose BBC Micro files are to be found
        self.destination_folder  = ""            # Destination folder
        self.extension           = ""            # Extension SSD / DSD
        self.verbose             = False
        self.assembler           = "beebasm"     # Can be 'acme' or 'beebasm'

config = Config()

def exit(code, message):
    if code != 0:
        print("ERROR: " + message + " (exit code " + str(code) + ")")
    sys.exit(code)

# Convert a relative path to an absolute path
def make_absolute_filepath(relative_filepath):
    # Get path to current working directory
    dirname = os.getcwd()
    return os.path.join(dirname, relative_filepath)

# Copy a file
def safe_copy(source, destination):
    try:
        shutil.copy(source, destination)
    except FileNotFoundError:
        exit(-1, "Could not find file '" + source + "' to copy to '" + destination + "'")
    except:
        exit(-2, "Could not copy file '" + source + "' to '" + destination + "'")

# Execute a subprocess, returning the stdout
def run(args, error_message, cwd=None):
    if config.verbose:
        print(args)
    p = subprocess.run(args, capture_output=True, cwd=cwd)
    if p.returncode != 0:
        print(args)
        print(p.stderr.decode())
        exit(p.returncode, error_message)
    return p.stdout

# Make a directory
def make_directory(directory):
    os.makedirs(directory, exist_ok=True)

# Make a list of the files in a directory that *don't* have a .inf extension
def list_files_without_inf_extension(dir_path):
    return [os.path.join(dir_path, f) for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f)) and not f.lower().endswith('.inf')]

# Make a list of the files in a directory that *do* have a .inf extension
def list_files_with_inf_extension(dir_path):
    return [os.path.join(dir_path, f) for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f)) and f.lower().endswith('.inf')]


# Translate a BBC Micro FS filename into a filename suitable for the host environment
def convert_to_host_filename(bbc_filename):
    filename = bbc_filename.replace("/" , "#slash")
    filename = filename.replace("?"     , "#question")
    filename = filename.replace("<"     , "#less")
    filename = filename.replace(">"     , "#greater")
    filename = filename.replace("\\"    , "#backslash")
    filename = filename.replace(":"     , "#colon")
    filename = filename.replace("*"     , "#star")
    filename = filename.replace("|"     , "#bar")
    filename = filename.replace("\""    , "#quote")
    return filename

# Convert back a host filename previously converted from a BBC Micro FS filename
def convert_to_bbc_filename(host_filename):
    filename = host_filename.replace("#slash"   , "/")
    filename = filename.replace("#question"     , "?")
    filename = filename.replace("#less"         , "<")
    filename = filename.replace("#greater"      , ">")
    filename = filename.replace("#backslash"    , "\\")
    filename = filename.replace("#colon"        , ":")
    filename = filename.replace("#star"         , "*")
    filename = filename.replace("#bar"          , "|")
    filename = filename.replace("#quote"        , "\"")
    return filename

def extract_manually(disk_path: str, output_dir: str):
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
                inf = f"{entry.fullname} {entry.load_address:08X} {entry.exec_address:08X} {locked}"
                inf_path = os.path.join(side_dir, name + ".inf")
                with open(inf_path, 'w') as f:
                    f.write(inf)

def read_inf(host_filepath: str) -> BBCMicroFile:
    result = BBCMicroFile(host_filepath)

    with open(host_filepath + ".inf", "r") as file:
        input_string = file.read()

        args = [word for word in input_string.split(' ') if word]
        if "L" in args:
            args.remove("L")
            result.locked = True
        if "Locked" in args:
            args.remove("Locked")
            result.locked = True
        result.bbc_filepath = args[0]
        result.load_address = int(args[1], 16)
        result.exec_address = int(args[2], 16)

    return result

def is_disassembly(file: dfsimage.Entry, content: bytes) -> bool:
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
    """Check if at least threshold of bytes are printable ASCII or newlines."""
    if not data:
        return True
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (10, 13))
    return printable_count >= (threshold * len(data))

def is_totally_printable(data: bytes) -> bool:
    """Check if at least threshold of bytes are printable ASCII or newlines."""
    if not data:
        return True
    printable_count = sum(1 for b in data if 32 <= b <= 126 or b in (10, 13))
    return printable_count == len(data)

def disassemble(python_filename, asm_filename):
    """Run a python control script to create Beebasm or Acme assembly"""

    # Get paths
    path, ext = os.path.splitext(asm_filename)
    assembler_filename = path + "_" + config.assembler + ext

    # Create disassembly
    args = ["python3", python_filename, "--" + config.assembler, "--output", assembler_filename]
    run(args, "disassemble failed")

def run(args, error_message, cwd=None):
    # For debugging...
    # print(args)
    p = subprocess.run(args, capture_output=True, cwd=cwd)
    if p.returncode != 0:
        print(f"COMMAND: {' '.join(args)}")
        print(p.stderr.decode())
        exit(p.returncode, error_message)
    return p.stdout

def main(args):
    if len(args) == 0:
        print("This utility takes either a BBC Micro SSD (or DSD) file, or a directory of loose BBC Micro files (possibly with associated .INF files), and:")
        print("    (a) creates editable source files based on the binary files (e.g. assembly language files for code, text files for BASIC),")
        print("    (b) assembles them into new binaries (identical to the original binaries) and")
        print("    (c) creates an SSD or DSD from the results.")
        print("This utility requires 'py8dis' (https://github.com/ZornsLemma/py8dis) to be visible to Python, e.g. in PYTHONPATH or in the same directory as this python script.")
        print("")
        print("USAGE: pygenerate <filepath to ssd>")
        exit(0, "")

    # Parse arguments
    for i in range(0, len(args)):
        if args[i] == "-verbose":
            config.verbose = True
        elif args[i].lower().endswith(".ssd") or args[i].lower().endswith(".dsd"):
            config.ssd_filepath = make_absolute_filepath(args[i])
            config.destination_folder, config.extension = os.path.splitext(os.path.basename(config.ssd_filepath))
        else:
            config.loose_folder = make_absolute_filepath(args[i])
            config.destination_folder, config.extension = os.path.splitext(os.path.basename(config.loose_folder))

    make_directory(config.destination_folder)

    original_directory  = os.path.join(config.destination_folder, "original")
    source_directory    = os.path.join(config.destination_folder, "source")
    tools_directory     = os.path.join(config.destination_folder, "tools")

    make_directory(original_directory)
    make_directory(source_directory)
    make_directory(tools_directory)

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

    # Start creating a bash script that builds the new files
    go_script = """# error out if any command fails
set -e

"""


    # Process each file, creating a control script for each binary we need to deal with
    for file in files_to_process:
        with open(file.host_filepath, "rb") as f:
            content = f.read()
            file.length = len(content)

            print(f'Processing file {file.bbc_filepath}')

            # Check if it's BASIC:
            listing, end_index, success = bbc_basic_detokenizer.decode_basic(content)
            if success:
                # BASIC program found
                basic_txt = "".join(listing)

                # Write the BASIC text out to source folder
                file.source_filepath = os.path.join(source_directory, os.path.basename(file.host_filepath) + "_basic.txt")
                with open(file.source_filepath, "w") as f:
                    f.write(basic_txt)

                if (end_index < file.length):
                    print(f"with {len(content) - end_index} more bytes beyond the end of the BASIC program")
            elif is_totally_printable(content):
                # Copy current file content into a file in source_directory
                file.source_filepath = os.path.join(source_directory, os.path.basename(file.host_filepath) + ".txt")
                with open(file.source_filepath, "wb") as f:
                    f.write(content)
            else:
                # Disassemble
                # Add to python control script that will invoke py8dis to disassemble the file
                control_script = f"# Control script for disassembling '{config.destination_folder}'\n\n"
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

                control_filepath = os.path.join(tools_directory, "build.py")

                host_filepath_relative_to_script = os.path.relpath(file.host_filepath, tools_directory)

                control_script += f'# FILE {file.bbc_filepath}\n'
                control_script += f'load(0x{file.load_address:04x}, os.path.join(py_dir, "{host_filepath_relative_to_script}"), "6502")\n'
                if file.load_address == 0x8000:
                    control_script += f'acorn.is_sideways_rom()'
                if (file.load_address != 0) and (file.exec_address >= file.load_address) and (file.exec_address < (file.load_address + file.length)):
                    control_script += f'entry(0x{file.exec_address:04x}, "entry_point")\n'
                control_script += "\ngo()\n"

                # Write the control file
                with open(control_filepath, "w") as f:
                    f.write(control_script)

                go_script += f"python3 tools/build.py --{config.assembler} --output source/{host_filepath_relative_to_script}_{config.assembler}.asm\n"

                # Execute the control file (calls py8dis to create the assembly file)
                asm_filepath = os.path.join(source_directory, os.path.basename(file.host_filepath) + ".asm")
                disassemble(control_filepath, asm_filepath)

    # Write the go script
    with open(os.path.join(config.destination_folder, "go"), "w") as f:
        f.write(go_script)

    # Assemble the files using acme or beebasm
    if config.assembler == "acme":
        pass
    elif config.assembler == "beebasm":
        pass
    else:
        pass

def test():
    image = dfsimage.Image("../tempest/Disc010-Tempest.ssd", open_mode=dfsimage.OpenMode.EXISTING)

    for side in image.sides:
        # The lower four bits of the option byte are the !BOOT option, usually in the range 0-3
        boot_option = side.opt_byte & 15
        if boot_option > 3:
            boot_option_string = str(boot_option)
        else:
            boot_option_string = ["Ignore", "*LOAD", "*RUN", "*EXEC"][boot_option]
        print(f'Found a side with title "{side.title}" and the "{boot_option_string}" boot option')

        for file in side.files:
            print(f'Found file {file.index}: "{file.fullname}" {hex(file.load_address)[2:]} {hex(file.exec_address)[2:]} {hex(file.size)[2:]}')
            content = file.readall()

            # First check if it's BASIC:
            listing, end_index, success = bbc_basic_detokenizer.decode_basic(content)
            if success:
                # BASIC program found
                basic_txt = "".join(listing)

                file.basic_end_index = end_index
                if (end_index < len(content)):
                    print(f"with {len(content) - end_index} more bytes beyond the end of the BASIC program")
            elif is_mostly_printable(content):
                # Text file found
                print(content)
            elif is_disassembly(file, content):
                # disassemble
                print("Disasssembly")
            else:
                # hex
                print("Hex")

if __name__=="__main__":
    main(sys.argv[1:])
