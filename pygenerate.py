#!/usr/bin/env python3

import shutil           # for copying files
import sys              # for exiting the script with an exit code
import os               # for path manipulation
import subprocess       # for running other processes
import re               # for parsing INF files

import dfsimage                 # for reading BBC disk images
import bbc_basic_detokenizer    # For identifying and detokenising BASIC

BBC_POUND = "`"
UNICODE_POUND = bytes((0xa3, )).decode("iso8859-1")

script_dir = os.path.dirname(os.path.realpath(__file__))

class BBCMicroFile:
    def __init__(self, host_filepath="", bbc_filepath="", load_address=0, exec_address=0, locked=False):
        self.host_filepath = host_filepath  # Host system filepath
        self.bbc_filepath  = bbc_filepath   # BBC Micro DFS filepath
        self.load_address = load_address    # Load address
        self.exec_address = exec_address    # Exec address
        self.locked = locked                # Lock status

        # Derived values
        self.length = None
        self.source_filepath = None

class Config:
    def __init__(self):
        self.ssd_filepath        = ""            # The filepath to the BBC Micro disk image (SSD / DSD)
        self.loose_folder        = ""            # The folder where the loose BBC Micro files are to be found
        self.destination_folder  = ""            # Destination folder
        self.extension           = ""            # Extension SSD / DSD
        self.verbose             = False
        self.assembler           = "beebasm"     # Can be 'acme' or 'beebasm'

config = Config()

def exit_with_message(code, message):
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
        exit_with_message(-1, f"Could not find file '{source}' to copy to '{destination}'")
    except PermissionError:
        exit_with_message(-2, f"Permission denied when trying to access '{source}' or write to '{destination}'.")
    except IsADirectoryError:
        exit_with_message(-3, f"The source '{source}' is a directory, not a file.")
    except OSError as e:
        exit_with_message(-4, f"An OS error occurred: {e.strerror}.")
    except TypeError:
        exit_with_message(-5, f"Invalid type for source or destination path.")

# Execute a subprocess, returning the stdout
def run(args, error_message, cwd=None):
    if config.verbose:
        print(args)
    p = subprocess.run(args, capture_output=True, cwd=cwd)
    if p.returncode != 0:
        print(args)
        print(p.stderr.decode())
        exit_with_message(p.returncode, error_message)
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
    filename = filename.replace(BBC_POUND, UNICODE_POUND)
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
    filename = filename.replace(UNICODE_POUND, BBC_POUND)
    return filename

def disk_metadata(disk_path: str):
    with dfsimage.Image(disk_path) as img:
        return ([(side.title, side.opt) for side in img.sides])

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
                inf = f"{entry.fullname:<12} {entry.load_address:08X} {entry.exec_address:08X} {locked}"
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

def is_mostly_printable(data: bytes, threshold: float=0.95) -> bool:
    """Check if at least threshold of bytes are printable ASCII or carriage returns."""
    if not data:
        return True
    printable_count = sum(1 for b in data if 32 <= b <= 126 or (b == 13))
    return printable_count >= (threshold * len(data))

def is_totally_printable(data: bytes) -> bool:
    """Check if at least threshold of bytes are printable ASCII or carriage returns."""
    if not data:
        return True
    printable_count = sum(1 for b in data if 32 <= b <= 126 or (b == 13))
    return printable_count == len(data)

def show_usage():
    print("This utility reads BBC Micro files (from SSD, DSD, or a directory of files perhaps with associated .INF files), and:")
    print("    (a) creates editable source files based on the file contents (e.g. assembly language files for code, text files for BASIC),")
    print("    (b) assembles them into new binaries (identical to the original binaries) and")
    print("    (c) recreates an SSD or DSD from the results.")
    print("This utility requires:")
    print("    'py8dis' (https://github.com/ZornsLemma/py8dis) to be visible to Python, e.g. in PYTHONPATH or in the same directory as this python script.")
    print("    'beebasm' or 'acme' assembler (https://github.com/stardot/beebasm/ or https://sourceforge.net/projects/acme-crossass/)")
    print("")
    print("USAGE: pygenerate <filepath to ssd> {--acme} {--beebasm}")

def main(args):
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

                # Convert to BASIC II format on disc
                build_script += f'\n# Create BASIC file {file.bbc_filepath}\n'
                build_script += f'source_filepath = os.path.join(script_dir, "source", "{os.path.basename(file.source_filepath)}")\n'
                build_script += f'destination_filepath = os.path.join(script_dir, "build", "disc", "{os.path.basename(file.host_filepath)}")\n'
                build_script += f'with open(source_filepath, "rb") as f:\n'
                build_script += f'    tokenized_result = bbc_basic_tokenizer.tokenize_file(f, input_file_contains_escaped_chars=True)\n'
                build_script += f'    with open(destination_filepath, "wb") as file:\n'
                build_script += f'        file.write(bytearray(tokenized_result))\n'
                # Create INF for destination file
                build_script += f'make_inf(destination_filepath, "{file.bbc_filepath}", 0x{file.load_address:08x}, 0x{file.exec_address:08x}, "{"L" if file.locked else ""}")\n'

            elif is_totally_printable(content):
                # Write the current file content into a file in source_directory, with carriage returns converted to the host OS line ending
                file.source_filepath = os.path.join(source_directory, os.path.basename(file.host_filepath) + ".txt")
                with open(file.source_filepath, "wb") as f:
                    f.write(content.replace(b'\x0d', os.linesep.encode()))

                build_script += f'\n# Create text file {file.bbc_filepath}\n'
                build_script += f'destination_filepath = os.path.join(script_dir, "build", "disc", "{os.path.basename(file.host_filepath)}")\n'
                build_script += f'copy_text_to_bbc(os.path.join(script_dir, "source", "{os.path.basename(file.source_filepath)}"), destination_filepath)\n'
                build_script += f'make_inf(destination_filepath, "{file.bbc_filepath}", 0x{file.load_address:08x}, 0x{file.exec_address:08x}, "{"L" if file.locked else ""}")\n'

            else:
                # Disassemble
                # Add to python control script that will invoke py8dis to disassemble the file
                control_script = f"# Control script for disassembling '{os.path.basename(file.host_filepath)}'\n\n"
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

                control_filepath = os.path.join(control_directory, os.path.basename(file.host_filepath) + ".py")

                host_filepath_relative_to_script = os.path.relpath(file.host_filepath, control_directory)

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

                # Execute the control file (calls py8dis to create the assembly file)
                build_script += f'\n# Create disassembly {file.bbc_filepath}\n'
                build_script += f'destination_filepath = os.path.join(script_dir, "build", "disc", "{os.path.basename(file.host_filepath)}")\n'
                asm_file = f"{os.path.basename(file.host_filepath)}_{config.assembler}.asm"
                build_script += f'disassemble("{os.path.basename(control_filepath)}", "{asm_file}")\n'

                # Assemble asm into new binaries
                build_script += f'assemble("{asm_file}", "{os.path.basename(file.host_filepath)}")\n'
                # Create INF for destination file
                build_script += f'make_inf(destination_filepath, "{file.bbc_filepath}", 0x{file.load_address:08x}, 0x{file.exec_address:08x}, "{"L" if file.locked else ""}")\n'

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
    for f in files_to_process:
        #build_script += f"    image.import_files(os_files=f\"{{os.path.join(script_dir, 'build', 'disc', '{os.path.basename(f.host_filepath)}')}}\", dfs_names='{f.bbc_filepath}', ignore_access=True, inf_mode=dfsimage.InfMode.NEVER, load_addr=0x{f.load_address:08x},  exec_addr=0x{f.exec_address:08x}, locked={f.locked}, replace=True)\n"
        build_script += f"    add_file(image, os.path.join(script_dir, 'build', 'disc', '{os.path.basename(f.host_filepath)}'), '{f.bbc_filepath}', load_addr=0x{f.load_address:08x},  exec_addr=0x{f.exec_address:08x}, locked={f.locked})\n"

    # Copy dfsimage
    shutil.copytree(os.path.join(script_dir, "dfsimage"), os.path.join(config.destination_folder, "dfsimage"), dirs_exist_ok=True)

    # Write the build script
    with open(os.path.join(config.destination_folder, "build.py"), "w") as f:
        f.write(build_script)


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
