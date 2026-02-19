#!/usr/bin/env python3

"""
BBC BASIC II tokenizer.

Converts an ASCII BASIC text file into a tokenized BBC BASIC II format file.

By default, if the input contains an escaped character string such as "\x07" this is converted back to the single character equivalent.
To disable this behaviour add the "--no_escape" argument.

Based on beebasm's 'basic_tokenize.cpp', https://github.com/stardot/beebasm

This file is licensed under the GNU General Public License version 3.

Example:
    with open("program.txt", "rb") as f:
        tokens = tokenize_file(f)
"""
import errno
import sys
from enum import IntFlag
from typing import BinaryIO

# Character constants
CR = 0x0D
LF = 0x0A
LINE_NUMBER_TOKEN = 0x8D


class KeywordFlags(IntFlag):
    """Flags controlling how keywords are tokenized.

    Attributes:
        NONE: No special handling.
        C: Complete word only - don't match if followed by alphanumeric.
        M: Middle of statement - clears start_of_line flag.
        S: Start of statement - sets start_of_line flag.
        F: Function - consume following alphanumerics (for FN/PROC names).
        L: Line number follows - enable line number tokenization.
        R: Rest of line is raw - copy remainder without tokenizing.
        P: Pseudo-variable - use alternate token at start of line.
    """
    NONE = 0
    C = 0x01
    M = 0x02
    S = 0x04
    F = 0x08
    L = 0x10
    R = 0x20
    P = 0x40


class TokenizeError(Exception):
    """Raised when BASIC tokenization fails.

    Attributes:
        line_number: The source line number where the error occurred.
        error_string: Description of the error.
    """

    def __init__(self, line_number: int, error_string: str):
        self.line_number = line_number
        self.error_string = error_string
        super().__init__(str(self))

    def __repr__(self) -> str:
        return f"Line {self.line_number}: {self.error_string}"

    def __str__(self) -> str:
        return f"Error: Line {self.line_number}: {self.error_string}"


class _Keyword:
    """Represents a BBC BASIC keyword with its token and parsing flags.

    Attributes:
        name: The keyword text (e.g., "PRINT").
        token: The token byte value (0x80-0xFF).
        flags: Bitfield controlling tokenization behavior.
    """

    def __init__(self, name: str, token: int, flags: KeywordFlags):
        self.name = name
        self.token = token
        self.flags = flags

    def __repr__(self) -> str:
        return f"Keyword '{self.name}', token {self.token}, flags {self.flags}"

# The order is important because it determines which abbreviations get precedence.
# For example, "P." is PRINT because PRINT is first in the P section.
_keyword_list = [
    _Keyword("AND",         0x80, KeywordFlags.NONE),
    _Keyword("ABS",         0x94, KeywordFlags.NONE),
    _Keyword("ACS",         0x95, KeywordFlags.NONE),
    _Keyword("ADVAL",       0x96, KeywordFlags.NONE),
    _Keyword("ASC",         0x97, KeywordFlags.NONE),
    _Keyword("ASN",         0x98, KeywordFlags.NONE),
    _Keyword("ATN",         0x99, KeywordFlags.NONE),
    _Keyword("AUTO",        0xC6, KeywordFlags.L),
    _Keyword("BGET",        0x9A, KeywordFlags.C),
    _Keyword("BPUT",        0xD5, KeywordFlags.M | KeywordFlags.C),
    _Keyword("COLOUR",      0xFB, KeywordFlags.M),
    _Keyword("CALL",        0xD6, KeywordFlags.M),
    _Keyword("CHAIN",       0xD7, KeywordFlags.M),
    _Keyword("CHR$",        0xBD, KeywordFlags.NONE),
    _Keyword("CLEAR",       0xD8, KeywordFlags.C),
    _Keyword("CLOSE",       0xD9, KeywordFlags.M | KeywordFlags.C),
    _Keyword("CLG",         0xDA, KeywordFlags.C),
    _Keyword("CLS",         0xDB, KeywordFlags.C),
    _Keyword("COS",         0x9B, KeywordFlags.NONE),
    _Keyword("COUNT",       0x9C, KeywordFlags.C),
    _Keyword("DATA",        0xDC, KeywordFlags.R),
    _Keyword("DEG",         0x9D, KeywordFlags.NONE),
    _Keyword("DEF",         0xDD, KeywordFlags.NONE),
    _Keyword("DELETE",      0xC7, KeywordFlags.L),
    _Keyword("DIV",         0x81, KeywordFlags.NONE),
    _Keyword("DIM",         0xDE, KeywordFlags.M),
    _Keyword("DRAW",        0xDF, KeywordFlags.M),
    _Keyword("ENDPROC",     0xE1, KeywordFlags.C),
    _Keyword("END",         0xE0, KeywordFlags.C),
    _Keyword("ENVELOPE",    0xE2, KeywordFlags.M),
    _Keyword("ELSE",        0x8B, KeywordFlags.L | KeywordFlags.S),
    _Keyword("EVAL",        0xA0, KeywordFlags.NONE),
    _Keyword("ERL",         0x9E, KeywordFlags.C),
    _Keyword("ERROR",       0x85, KeywordFlags.S),
    _Keyword("EOF",         0xC5, KeywordFlags.C),
    _Keyword("EOR",         0x82, KeywordFlags.NONE),
    _Keyword("ERR",         0x9F, KeywordFlags.C),
    _Keyword("EXP",         0xA1, KeywordFlags.NONE),
    _Keyword("EXT",         0xA2, KeywordFlags.C),
    _Keyword("FOR",         0xE3, KeywordFlags.M),
    _Keyword("FALSE",       0xA3, KeywordFlags.C),
    _Keyword("FN",          0xA4, KeywordFlags.F),
    _Keyword("GOTO",        0xE5, KeywordFlags.L | KeywordFlags.M),
    _Keyword("GET$",        0xBE, KeywordFlags.NONE),
    _Keyword("GET",         0xA5, KeywordFlags.NONE),
    _Keyword("GOSUB",       0xE4, KeywordFlags.L | KeywordFlags.M),
    _Keyword("GCOL",        0xE6, KeywordFlags.M),
    _Keyword("HIMEM",       0x93, KeywordFlags.P | KeywordFlags.M | KeywordFlags.C),
    _Keyword("INPUT",       0xE8, KeywordFlags.M),
    _Keyword("IF",          0xE7, KeywordFlags.M),
    _Keyword("INKEY$",      0xBF, KeywordFlags.NONE),
    _Keyword("INKEY",       0xA6, KeywordFlags.NONE),
    _Keyword("INT",         0xA8, KeywordFlags.NONE),
    _Keyword("INSTR(",      0xA7, KeywordFlags.NONE),
    _Keyword("LIST",        0xC9, KeywordFlags.L),
    _Keyword("LINE",        0x86, KeywordFlags.NONE),
    _Keyword("LOAD",        0xC8, KeywordFlags.M),
    _Keyword("LOMEM",       0x92, KeywordFlags.P | KeywordFlags.M | KeywordFlags.C),
    _Keyword("LOCAL",       0xEA, KeywordFlags.M),
    _Keyword("LEFT$(",      0xC0, KeywordFlags.NONE),
    _Keyword("LEN",         0xA9, KeywordFlags.NONE),
    _Keyword("LET",         0xE9, KeywordFlags.S),
    _Keyword("LOG",         0xAB, KeywordFlags.NONE),
    _Keyword("LN",          0xAA, KeywordFlags.NONE),
    _Keyword("MID$(",       0xC1, KeywordFlags.NONE),
    _Keyword("MODE",        0xEB, KeywordFlags.M),
    _Keyword("MOD",         0x83, KeywordFlags.NONE),
    _Keyword("MOVE",        0xEC, KeywordFlags.M),
    _Keyword("NEXT",        0xED, KeywordFlags.M),
    _Keyword("NEW",         0xCA, KeywordFlags.C),
    _Keyword("NOT",         0xAC, KeywordFlags.NONE),
    _Keyword("OLD",         0xCB, KeywordFlags.C),
    _Keyword("ON",          0xEE, KeywordFlags.M),
    _Keyword("OFF",         0x87, KeywordFlags.NONE),
    _Keyword("OR",          0x84, KeywordFlags.NONE),
    _Keyword("OPENIN",      0x8E, KeywordFlags.NONE),
    _Keyword("OPENOUT",     0xAE, KeywordFlags.NONE),
    _Keyword("OPENUP",      0xAD, KeywordFlags.NONE),
    _Keyword("OSCLI",       0xFF, KeywordFlags.M),
    _Keyword("PRINT",       0xF1, KeywordFlags.M),
    _Keyword("PAGE",        0x90, KeywordFlags.P | KeywordFlags.M | KeywordFlags.C),
    _Keyword("PTR",         0x8F, KeywordFlags.P | KeywordFlags.M | KeywordFlags.C),
    _Keyword("PI",          0xAF, KeywordFlags.C),
    _Keyword("PLOT",        0xF0, KeywordFlags.M),
    _Keyword("POINT(",      0xB0, KeywordFlags.NONE),
    _Keyword("PROC",        0xF2, KeywordFlags.F | KeywordFlags.M),
    _Keyword("POS",         0xB1, KeywordFlags.C),
    _Keyword("RETURN",      0xF8, KeywordFlags.C),
    _Keyword("REPEAT",      0xF5, KeywordFlags.NONE),
    _Keyword("REPORT",      0xF6, KeywordFlags.C),
    _Keyword("READ",        0xF3, KeywordFlags.M),
    _Keyword("REM",         0xF4, KeywordFlags.R),
    _Keyword("RUN",         0xF9, KeywordFlags.C),
    _Keyword("RAD",         0xB2, KeywordFlags.NONE),
    _Keyword("RESTORE",     0xF7, KeywordFlags.L | KeywordFlags.M),
    _Keyword("RIGHT$(",     0xC2, KeywordFlags.NONE),
    _Keyword("RND",         0xB3, KeywordFlags.C),
    _Keyword("RENUMBER",    0xCC, KeywordFlags.L),
    _Keyword("STEP",        0x88, KeywordFlags.NONE),
    _Keyword("SAVE",        0xCD, KeywordFlags.M),
    _Keyword("SGN",         0xB4, KeywordFlags.NONE),
    _Keyword("SIN",         0xB5, KeywordFlags.NONE),
    _Keyword("SQR",         0xB6, KeywordFlags.NONE),
    _Keyword("SPC",         0x89, KeywordFlags.NONE),
    _Keyword("STR$",        0xC3, KeywordFlags.NONE),
    _Keyword("STRING$(",    0xC4, KeywordFlags.NONE),
    _Keyword("SOUND",       0xD4, KeywordFlags.M),
    _Keyword("STOP",        0xFA, KeywordFlags.C),
    _Keyword("TAN",         0xB7, KeywordFlags.NONE),
    _Keyword("THEN",        0x8C, KeywordFlags.L | KeywordFlags.S),
    _Keyword("TO",          0xB8, KeywordFlags.NONE),
    _Keyword("TAB(",        0x8A, KeywordFlags.NONE),
    _Keyword("TRACE",       0xFC, KeywordFlags.L | KeywordFlags.M),
    _Keyword("TIME",        0x91, KeywordFlags.P | KeywordFlags.M | KeywordFlags.C),
    _Keyword("TRUE",        0xB9, KeywordFlags.C),
    _Keyword("UNTIL",       0xFD, KeywordFlags.M),
    _Keyword("USR",         0xBA, KeywordFlags.NONE),
    _Keyword("VDU",         0xEF, KeywordFlags.M),
    _Keyword("VAL",         0xBB, KeywordFlags.NONE),
    _Keyword("VPOS",        0xBC, KeywordFlags.C),
    _Keyword("WIDTH",       0xFE, KeywordFlags.M),
    _Keyword("PAGE",        0xD0, KeywordFlags.NONE),
    _Keyword("PTR",         0xCF, KeywordFlags.NONE),
    _Keyword("TIME",        0xD1, KeywordFlags.NONE),
    _Keyword("LOMEM",       0xD2, KeywordFlags.NONE),
    _Keyword("HIMEM",       0xD3, KeywordFlags.NONE),
]


class _Reader:
    """Buffered character reader that normalizes line endings.

    Handles CR, LF, and CRLF line endings, converting all to CR internally.
    Tracks the current source line number for error reporting.
    """

    def __init__(self, file: BinaryIO, contains_escaped_characters: bool):
        self.file = file
        self.contains_escaped_characters = contains_escaped_characters
        self.line = 1
        self.current = 0
        self.end = False
        self.errno = 0
        self.previous_char_was_cr = False
        self.next_char()

    def read_one_char(self) -> int | None:
        """Read a single byte from the file."""
        c = self.file.read(1)
        if c:
            # Characters can be escaped as "\x0a" etc, handle this as needed
            if self.contains_escaped_characters:
                if c == b'\\':
                    c = self.file.read(1)
                    if c == b'x':
                        d1hex = self.file.read(1)
                        d2hex = self.file.read(1)
                        val = int(d1hex+d2hex, 16)
                        # If the value is 0x0d or 0x0a then we have a CR or LF
                        # *within* the bounds of a line. This is not possible
                        # to enter from the BASIC prompt, but can be done via
                        # poking in memory for example and the result is still
                        # considered valid BASIC.
                        # This occurs in some games where a REM statement has
                        # binary data after it.
                        # To help with parsing, we encode these as non-ASCII
                        # values and only convert them back when writing the
                        # file.
                        if val == CR:
                            val = ord('\u23CE')
                        if val == LF:
                            val = ord('\u2193')
                        return val
            return ord(c)
        return None

    def line_number(self) -> int:
        """Return the current source line number."""
        return self.line

    def current_char(self) -> str | None:
        """Return the current character as a string, or None at EOF."""
        if self.current is not None:
            return chr(self.current)
        return None

    def is_end(self) -> bool:
        """Return True if at end of file."""
        return self.end

    def next_char(self) -> None:
        """Advance to the next character, normalizing line endings."""
        if self.current == CR:
            if self.end:
                return
            self.line += 1
        next_char = self.read_one_char()

        # Skip over LF if CR was previous character (handle CRLF)
        if self.previous_char_was_cr and next_char == LF:
            next_char = self.read_one_char()
        if next_char is None:
            if self.file.readable():
                self.errno = errno.errorcode
            self.end = True
            self.current = CR
        elif next_char == LF:
            # Convert LF to CR
            self.previous_char_was_cr = False
            self.current = CR
        else:
            self.previous_char_was_cr = (next_char == CR)
            self.current = next_char


class _Writer:
    """Buffer for building a tokenized BASIC line.

    Each line has the format: CR, high byte of line number, low byte,
    line length, then tokenized content.
    """

    def __init__(self):
        self.buffer = bytearray(255)
        self.length = 0
        self.fail = False

    def init(self, line_number: int) -> None:
        """Initialize buffer for a new line with the given line number."""
        self.fail = False
        self.buffer[0:4] = bytearray([CR, (line_number >> 8) & 0xFF, line_number & 0xFF, 0])
        self.length = 4

    def finish(self) -> bool:
        """Finalize the line, writing its length. Returns True on success."""
        if not self.fail:
            assert self.length < 0x100
            self.buffer[3] = self.length
        return not self.fail

    def write(self, c: int | str) -> None:
        """Append a character or byte to the buffer."""
        if isinstance(c, str):
            # When reading, if we found a CR or LF in the middle of a BASIC line, we
            # temporarily preserved them as non-ASCII UTF-8 characters so they don't
            # parse as the end of a line. Here we convert them back to regular CR
            # and LF for writing to a file.
            if c == '\u23CE':
                c = CR
            elif c == '\u2193':
                c = LF
            else:
                c = ord(c)
        if self.length < len(self.buffer):
            self.buffer[self.length] = c
            self.length += 1
        else:
            self.fail = True

    def data(self) -> bytearray:
        """Return the buffer contents up to current length."""
        return self.buffer[:self.length]


def _skip_write(test_func, reader: _Reader, writer: _Writer) -> None:
    """Read and write characters while test_func returns True."""
    while not reader.is_end() and test_func(reader.current_char()):
        writer.write(reader.current_char())
        reader.next_char()


def _is_not_cr(c: str) -> bool:
    """Return True if character is not carriage return."""
    return c != chr(CR)


def _is_alpha(c: str) -> bool:
    """Return True if character is an uppercase letter."""
    return 'A' <= c <= 'Z'


def _is_digit(c: str) -> bool:
    """Return True if character is a digit."""
    return '0' <= c <= '9'


def _is_alpha_digit(c: str) -> bool:
    """Return True if character is alphanumeric or underscore."""
    return ('_' <= c <= 'z') or ('A' <= c <= 'Z') or _is_digit(c)


def _is_dot_digit(c: str) -> bool:
    """Return True if character is a dot or digit."""
    return c == '.' or _is_digit(c)


def _is_hex_digit(c: str) -> bool:
    """Return True if character is a hexadecimal digit."""
    return ('A' <= c <= 'F') or _is_digit(c)


def _tokenize_linenum(reader: _Reader, writer: _Writer) -> bool:
    """Tokenize a line number reference (e.g., in GOTO/GOSUB).

    Line numbers are encoded as 3 bytes after the LINE_NUMBER_TOKEN.
    Raises an error if the number was too large.
    """
    buffer = bytearray(6)
    zero_count = 0

    while reader.current_char() == '0':
        zero_count += 1
        reader.next_char()

    index = 0
    acc = 0
    while _is_digit(reader.current_char()):
        c = reader.current_char()
        acc = 10 * acc + (ord(c) - ord('0'))
        if acc >= 0x8000:
            for _ in range(zero_count):
                writer.write(ord('0'))
            for i in range(index):
                writer.write(buffer[i])
            _skip_write(_is_digit, reader, writer)
            raise TokenizeError(reader.line_number(), f"Found the line number {acc} which is too big (maximum allowed is 32767)")

        buffer[index] = ord(c)
        index += 1
        reader.next_char()

    writer.write(LINE_NUMBER_TOKEN)
    writer.write((((acc & 0xC000) >> 12) | ((acc & 0xC0) >> 2)) ^ 0x54)
    writer.write((acc & 0x3F) | 0x40)
    writer.write((acc >> 8) | 0x40)
    return


def _read_next_char(reader: _Reader) -> str | None:
    """Advance reader and return the new current character."""
    reader.next_char()
    return reader.current_char()


def _parse_keyword(reader: _Reader, writer: _Writer) -> _Keyword | None:
    """Attempt to parse and match a keyword from the current position.

    Handles full keywords and abbreviations (e.g., "P." for PRINT).
    Returns the matched keyword or None if no match found.
    """
    match_count = 0
    match_name = None

    for keyword in _keyword_list:
        if not match_count or (match_count <= len(keyword.name) and match_name[:match_count] == keyword.name[:match_count]):
            while (match_count < len(keyword.name) and
                   reader.current_char() == keyword.name[match_count]):
                reader.next_char()
                match_count += 1

            if match_count:
                if match_count == len(keyword.name):
                    if keyword.flags & KeywordFlags.C:
                        if _is_alpha_digit(reader.current_char()):
                            for i in range(match_count):
                                writer.write(ord(keyword.name[i]))
                            _skip_write(_is_alpha_digit, reader, writer)
                            return None
                    return keyword

                if reader.current_char() == '.':
                    reader.next_char()
                    return keyword

                match_name = keyword.name

    if match_count:
        for i in range(match_count):
            writer.write(ord(match_name[i]))
        if _is_alpha(match_name[match_count - 1]):
            _skip_write(_is_alpha_digit, reader, writer)
    else:
        _skip_write(_is_alpha_digit, reader, writer)
    return None


def _tokenize_line_contents(reader: _Reader, writer: _Writer) -> None:
    """Tokenize the contents of a single BASIC line.

    Processes keywords, strings, numbers, and special characters,
    writing tokenized output to the writer.
    """
    start_of_line = True
    tokenize_numbers = False

    while True:
        c = reader.current_char()

        if c == chr(CR):
            return

        if c == ' ':
            writer.write(c)
            reader.next_char()
            continue

        if c == '&':
            writer.write(c)
            reader.next_char()
            _skip_write(_is_hex_digit, reader, writer)
            continue

        if c == '"':
            writer.write(c)
            while True:
                c = _read_next_char(reader)
                if c == chr(CR):
                    return
                writer.write(ord(c))
                if c == '"':
                    break
            reader.next_char()
            continue

        if c == ':':
            writer.write(c)
            reader.next_char()
            start_of_line = True
            tokenize_numbers = False
            continue

        if c == ',':
            writer.write(c)
            reader.next_char()
            continue

        if c == '*':
            if start_of_line:
                _skip_write(_is_not_cr, reader, writer)
                return
            writer.write(c)
            reader.next_char()
            start_of_line = False
            tokenize_numbers = False
            continue

        if _is_dot_digit(c):
            if c != '.' and tokenize_numbers:
                _tokenize_linenum(reader, writer)
                continue
            _skip_write(_is_dot_digit, reader, writer)
            start_of_line = False
            tokenize_numbers = False
            continue

        if not _is_alpha_digit(reader.current_char()):
            start_of_line = False
            tokenize_numbers = False
            writer.write(reader.current_char())
            reader.next_char()
            continue

        keyword = _parse_keyword(reader, writer)
        if not keyword:
            start_of_line = False
            tokenize_numbers = False
            continue
        else:
            token = keyword.token
            flags = keyword.flags

            if (flags & KeywordFlags.C) and _is_alpha_digit(reader.current_char()):
                assert False
                start_of_line = False
                tokenize_numbers = False
                continue

            if (flags & KeywordFlags.P) and start_of_line:
                token += 0x40

            writer.write(token)

            if flags & KeywordFlags.M:
                start_of_line = False
                tokenize_numbers = False

            if flags & KeywordFlags.S:
                start_of_line = True
                tokenize_numbers = False

            if flags & KeywordFlags.F:
                _skip_write(_is_alpha_digit, reader, writer)

            if flags & KeywordFlags.L:
                tokenize_numbers = True

            if flags & KeywordFlags.R:
                _skip_write(_is_not_cr, reader, writer)
                return


def tokenize_line(reader: _Reader, writer: _Writer, previous_line_number: int, tokenized: list[int]) -> int:
    """Tokenize a line of BBC BASIC.

    Args:
        reader: A file-like class to read the input data
        writer: A file-like class to write the output data
        previous_line_number: The previous line number found (used to make sure they are increasing)
        tokenized: List to store the output bytes

    Returns:
        A list of bytes representing the tokenized BASIC program.

    Raises:
        TokenizeError: If tokenization fails (e.g., line too long,
            line numbers out of order or out of range).
    """
    # Skip leading spaces
    while reader.current_char() == ' ':
        reader.next_char()

    # Read line number
    line_number = 0
    saw_digit = False
    while _is_digit(reader.current_char()):
        saw_digit = True
        line_number = 10 * line_number + (ord(reader.current_char()) - ord('0'))
        if line_number > 0x7FFF:
            break
        reader.next_char()

    # Create a line number if none present
    if saw_digit:
        if line_number <= previous_line_number:
            # I treat this as a warning, as there are files out there whose line numbers
            # are in the wrong order and we want to be able to recreate them from ASCII.
            #raise TokenizeError(reader.line_number(), "Line numbers must increase")
            print(f"WARNING: Line numbers are not in order: line {line_number} occurs after line {previous_line_number}.")
    else:
        line_number = previous_line_number + 1 if previous_line_number >= 0 else 1
    previous_line_number = line_number

    # Check for line numbers out of range
    if line_number > 0x7FFF:
        raise TokenizeError(reader.line_number(), f"Line number {line_number} too big")

    # Tokenize the line
    writer.init(line_number)
    _tokenize_line_contents(reader, writer)

    # Error if the line is too long
    if not writer.finish():
        raise TokenizeError(reader.line_number(), "Line too long after tokenizing")

    # Add the tokenized line to the tokenized data
    # Length four is an empty line, but happens, e.g. In $.MENU of in Revs 4 Tracks ( https://bbcmicro.co.uk/game.php?id=1128 )
    if writer.length >= 4:
        tokenized.extend(writer.data())

    return previous_line_number


def tokenize_file(file: BinaryIO, input_file_contains_escaped_chars: bool = True) -> list[int]:
    """Tokenize a BBC BASIC source file.

    Args:
        file: A binary file object containing ASCII BASIC source code.
        input_file_contains_escaped_chars: Convert input strings like '\x07' to the binary equivalent byte

    Returns:
        A list of bytes representing the tokenized BASIC program.

    Raises:
        TokenizeError: If tokenization fails (e.g., line too long,
            line numbers out of order or out of range).
    """
    reader = _Reader(file, input_file_contains_escaped_chars)
    previous_line_number = -1
    writer = _Writer()

    tokenized: list[int] = []
    while not reader.is_end():
        previous_line_number = tokenize_line(reader, writer, previous_line_number, tokenized)

        reader.next_char()
    tokenized.append(CR)
    tokenized.append(0xFF)

    return tokenized


def main(args: list[str]) -> None:
    """Main entry point for command-line tokenization."""
    try:
        with open(args[0], "rb") as f:
            input_file_contains_escaped_chars = True

            if "--no_escape" in args:
                args.remove("--no_escape")
                input_file_contains_escaped_chars = False

            tokenized_result = tokenize_file(f, input_file_contains_escaped_chars)
            with open(args[1], 'wb') as file:
                file.write(bytearray(tokenized_result))
    except TokenizeError as e:
        print(e)
    except IndexError:
        print("BBC BASIC II tokenizer.")
        print("")
        print("Converts detokenized ASCII BASIC source code into tokenized BBC BASIC II format.")
        print("")
        print('By default, if the input contains an escaped character string such as "\\x07" this is converted back to the single character equivalent.')
        print('To disable this behaviour add the "--no_escape" argument.')
        print("")
        print("Usage: python3 bbc_basic_tokenizer.py <input_text_file> <output_tokenized_file> {--no_escape}")
        exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
