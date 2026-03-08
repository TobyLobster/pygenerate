#!/usr/bin/env python3

"""
BBC BASIC II detokenizer.

Converts a tokenized BBC BASIC II format file into an ASCII BASIC text file.

Unprintable characters are by default converted to "\x07" style strings to give a pure ASCII result.
To override this behaviour, add the "--no_escape" argument. This allows non-printable characters to be output.

Based on the PD JavaScript version at https://github.com/shawty/BBCB_DFS_Catalog/blob/master/dfscat.js
which was based on the original list.pl code from MMB_Utils https://github.com/sweharris/MMB_Utils

The public functions are:

    decode_basic_file   - give it a filepath of a BASIC program to detokenize
    decode_basic        - give it bytes in memory of a BASIC program to detokenize
    
"""
import sys
import argparse
from io import BytesIO
import bbc_basic_tokenizer as bbt

# BBC BASIC tokens mapping
TOKENS = {
    128: 'AND',      192: 'LEFT$(',
    129: 'DIV',      193: 'MID$(',
    130: 'EOR',      194: 'RIGHT$(',
    131: 'MOD',      195: 'STR$',
    132: 'OR',       196: 'STRING$(',
    133: 'ERROR',    197: 'EOF',
    134: 'LINE',     198: 'AUTO',
    135: 'OFF',      199: 'DELETE',
    136: 'STEP',     200: 'LOAD',
    137: 'SPC',      201: 'LIST',
    138: 'TAB(',     202: 'NEW',
    139: 'ELSE',     203: 'OLD',
    140: 'THEN',     204: 'RENUMBER',
    142: 'OPENIN',   205: 'SAVE',
    143: 'PTR',      207: 'PTR',
    144: 'PAGE',     208: 'PAGE',
    145: 'TIME',     209: 'TIME',
    146: 'LOMEM',    210: 'LOMEM',
    147: 'HIMEM',    211: 'HIMEM',
    148: 'ABS',      212: 'SOUND',
    149: 'ACS',      213: 'BPUT',
    150: 'ADVAL',    214: 'CALL',
    151: 'ASC',      215: 'CHAIN',
    152: 'ASN',      216: 'CLEAR',
    153: 'ATN',      217: 'CLOSE',
    154: 'BGET',     218: 'CLG',
    155: 'COS',      219: 'CLS',
    156: 'COUNT',    220: 'DATA',
    157: 'DEG',      221: 'DEF',
    158: 'ERL',      222: 'DIM',
    159: 'ERR',      223: 'DRAW',
    160: 'EVAL',     224: 'END',
    161: 'EXP',      225: 'ENDPROC',
    162: 'EXT',      226: 'ENVELOPE',
    163: 'FALSE',    227: 'FOR',
    164: 'FN',       228: 'GOSUB',
    165: 'GET',      229: 'GOTO',
    166: 'INKEY',    230: 'GCOL',
    167: 'INSTR(',   231: 'IF',
    168: 'INT',      232: 'INPUT',
    169: 'LEN',      233: 'LET',
    170: 'LN',       234: 'LOCAL',
    171: 'LOG',      235: 'MODE',
    172: 'NOT',      236: 'MOVE',
    173: 'OPENUP',   237: 'NEXT',
    174: 'OPENOUT',  238: 'ON',
    175: 'PI',       239: 'VDU',
    176: 'POINT(',   240: 'PLOT',
    177: 'POS',      241: 'PRINT',
    178: 'RAD',      242: 'PROC',
    179: 'RND',      243: 'READ',
    180: 'SGN',      244: 'REM',
    181: 'SIN',      245: 'REPEAT',
    182: 'SQR',      246: 'REPORT',
    183: 'TAN',      247: 'RESTORE',
    184: 'TO',       248: 'RETURN',
    185: 'TRUE',     249: 'RUN',
    186: 'USR',      250: 'STOP',
    187: 'VAL',      251: 'COLOUR',
    188: 'VPOS',     252: 'TRACE',
    189: 'CHR$',     253: 'UNTIL',
    190: 'GET$',     254: 'WIDTH',
    191: 'INKEY$',   255: 'OSCLI',
}
LINE_START_BYTE     = 0x0D      # CR
END_OF_PROGRAM      = 0xFF
ENCODED_LINE_NUMBER = 0x8D
TOKEN_REM           = 0xF4      # 244
TOKEN_DATA          = 0xDC      # 220
BACKSLASH           = 0x5C      # 92

# Create the reverse dictionary, keywords to tokens. The order matters for abbreviating keywords.
TOKENS_REV = [
    ("AND",         0x80),
    ("ABS",         0x94),
    ("ACS",         0x95),
    ("ADVAL",       0x96),
    ("ASC",         0x97),
    ("ASN",         0x98),
    ("ATN",         0x99),
    ("AUTO",        0xC6),
    ("BGET",        0x9A),
    ("BPUT",        0xD5),
    ("COLOUR",      0xFB),
    ("CALL",        0xD6),
    ("CHAIN",       0xD7),
    ("CHR$",        0xBD),
    ("CLEAR",       0xD8),
    ("CLOSE",       0xD9),
    ("CLG",         0xDA),
    ("CLS",         0xDB),
    ("COS",         0x9B),
    ("COUNT",       0x9C),
    ("DATA",        0xDC),
    ("DEG",         0x9D),
    ("DEF",         0xDD),
    ("DELETE",      0xC7),
    ("DIV",         0x81),
    ("DIM",         0xDE),
    ("DRAW",        0xDF),
    ("ENDPROC",     0xE1),
    ("END",         0xE0),
    ("ENVELOPE",    0xE2),
    ("ELSE",        0x8B),
    ("EVAL",        0xA0),
    ("ERL",         0x9E),
    ("ERROR",       0x85),
    ("EOF",         0xC5),
    ("EOR",         0x82),
    ("ERR",         0x9F),
    ("EXP",         0xA1),
    ("EXT",         0xA2),
    ("FOR",         0xE3),
    ("FALSE",       0xA3),
    ("FN",          0xA4),
    ("GOTO",        0xE5),
    ("GET$",        0xBE),
    ("GET",         0xA5),
    ("GOSUB",       0xE4),
    ("GCOL",        0xE6),
    ("HIMEM",       0x93),
    ("INPUT",       0xE8),
    ("IF",          0xE7),
    ("INKEY$",      0xBF),
    ("INKEY",       0xA6),
    ("INT",         0xA8),
    ("INSTR(",      0xA7),
    ("LIST",        0xC9),
    ("LINE",        0x86),
    ("LOAD",        0xC8),
    ("LOMEM",       0x92),
    ("LOCAL",       0xEA),
    ("LEFT$(",      0xC0),
    ("LEN",         0xA9),
    ("LET",         0xE9),
    ("LOG",         0xAB),
    ("LN",          0xAA),
    ("MID$(",       0xC1),
    ("MODE",        0xEB),
    ("MOD",         0x83),
    ("MOVE",        0xEC),
    ("NEXT",        0xED),
    ("NEW",         0xCA),
    ("NOT",         0xAC),
    ("OLD",         0xCB),
    ("ON",          0xEE),
    ("OFF",         0x87),
    ("OR",          0x84),
    ("OPENIN",      0x8E),
    ("OPENOUT",     0xAE),
    ("OPENUP",      0xAD),
    ("OSCLI",       0xFF),
    ("PRINT",       0xF1),
    ("PAGE",        0x90),
    ("PTR",         0x8F),
    ("PI",          0xAF),
    ("PLOT",        0xF0),
    ("POINT(",      0xB0),
    ("PROC",        0xF2),
    ("POS",         0xB1),
    ("RETURN",      0xF8),
    ("REPEAT",      0xF5),
    ("REPORT",      0xF6),
    ("READ",        0xF3),
    ("REM",         0xF4),
    ("RUN",         0xF9),
    ("RAD",         0xB2),
    ("RESTORE",     0xF7),
    ("RIGHT$(",     0xC2),
    ("RND",         0xB3),
    ("RENUMBER",    0xCC),
    ("STEP",        0x88),
    ("SAVE",        0xCD),
    ("SGN",         0xB4),
    ("SIN",         0xB5),
    ("SQR",         0xB6),
    ("SPC",         0x89),
    ("STR$",        0xC3),
    ("STRING$(",    0xC4),
    ("SOUND",       0xD4),
    ("STOP",        0xFA),
    ("TAN",         0xB7),
    ("THEN",        0x8C),
    ("TO",          0xB8),
    ("TAB(",        0x8A),
    ("TRACE",       0xFC),
    ("TIME",        0x91),
    ("TRUE",        0xB9),
    ("UNTIL",       0xFD),
    ("USR",         0xBA),
    ("VDU",         0xEF),
    ("VAL",         0xBB),
    ("VPOS",        0xBC),
    ("WIDTH",       0xFE),
#    ("PAGE",        0xD0),
#    ("PTR",         0xCF),
#    ("TIME",        0xD1),
#    ("LOMEM",       0xD2),
#    ("HIMEM",       0xD3),
]

# Get just the list of names
temp = [s[0] for s in TOKENS_REV]

# Add all valid abbreviations to TOKENS_REV
for t in TOKENS_REV:
    for i in range(1,len(t[0])):
        partial = t[0][0:i]+"."
        if partial not in temp:
            temp.append(partial)
            TOKENS_REV.append((partial, t[1]))

# finally, make a dictionary from the tuples, encoding the names as bytes() for the keys
TOKENS_REV = { t[0].encode("ascii"):t[1] for t in TOKENS_REV }

# List of tokens for pseudo-variables (LHS versions): LOMEM, HIMEM, PAGE, PTR, TIME
PSEUDO_VARIABLES_LHS = frozenset([207, 208, 209, 210, 211])

def escape(byte_value: int, escape_non_printable: bool) -> list:
    """If escapes are required, then change a backslash to a double backslash 
    and any non-printable characters to \xFF format"""
    if byte_value == BACKSLASH:
        if not escape_non_printable:
            return [BACKSLASH]
        # A backslash character normally signifies the start of a markup e.g. \{TAB},
        # but here we are just trying to use a regular backslash in our program,
        # so we encode it as double backslash.
        return [BACKSLASH, BACKSLASH]
    elif 32 <= byte_value < 127:
        # Printable ASCII
        return [byte_value]
    else:
        if not escape_non_printable:
            return [byte_value]
        # Non-printable -> hex escape like '\xHH'
        return [ord(ch) for ch in f'\\x{byte_value:02x}']

def _is_digit(c: int) -> bool:
    """Return True if character is a digit."""
    return ord('0') <= c <= ord('9')

def ints_to_str(int_list: list[int]) -> str:
    """Convert a list of integers into a string with the ASCII encoding"""
    return ''.join(chr(i) for i in int_list)
    
def endswith_list(lst, sub):
    """Does the list end with the sub-list?"""
    if not sub:
        return True
    if len(sub) > len(lst):
        return False
    return lst[-len(sub):] == sub

def list_of_ascii_bytes(s: str) -> list[bytes]:
    """Convert a string into a list of integers"""
    return list(bytes(s.encode("ascii")))

def round_trip_works(line: list, new_bit: list, expected_ending: list, next_char: str = None):
    """'line' extended with 'new_bit' is an ASCII string supplied as a list 
    of integer values. It represents the BASIC line we are tokenizing. We 
    tokenise it to see if it matches the expected_ending."""
    new_line = line.copy()
    new_line.extend(new_bit)
    reader = bbt.Reader(BytesIO(bytes(new_line)), contains_escaped_characters=True)
    writer = bbt.Writer()
    bbt.tokenize_line_contents(reader, writer)
    result = list(writer.data())
    if endswith_list(result, expected_ending):
        # if the ending is a keyword of type C, then it must not have a letter of number immediately following
        if (next_char is not None) and (bbt._is_alpha_digit(next_char)):
            for keyword in bbt._keyword_list:
                if expected_ending[0] == keyword.token:
                    if keyword.flags & bbt.KeywordFlags.C:
                        return False
        return True
    return False

def decode_basic(file_data: bytes, output_file_should_escape_chars: bool = True, start_index: int = 0) -> tuple[list, int, bool]:
    """
    Decode a BBC BASIC tokenized program.

    Args:
        file_data: The raw bytes of the tokenized BASIC program.
        start_index: Start byte to read from the data

    Returns:
        A tuple of (listing, index, success) where listing is the decoded program
        as a string, index is the byte index where the BASIC program ends,
        and success indicates whether decoding completed without errors.
    """

    file_length = len(file_data)

    listing = []
    i = start_index

    while i < file_length:
        # Each line starts with CR (13)
        if file_data[i] != LINE_START_BYTE:
            listing.append("Bad Program (expected ^M at start of line).")
            return listing, i, False
        i += 1

        if i == file_length:
            listing.append("Bad Program (expected FF terminator).")
            return listing, i, False

        # Line number high byte. 0xFF marks end of program
        if file_data[i] == END_OF_PROGRAM:
            i += 1
            return listing, i, True

        if i > (file_length - 3):
            listing.append("Bad Program (Line finishes before metadata).")
            return listing, i, False

        # Line number (big-endian)
        line_number = file_data[i] * 256 + file_data[i + 1]
        i += 2

        # Line length (includes the 4-byte header: CR, line_hi, line_lo, length)
        line_len = file_data[i] - 4
        i += 1

        if line_len < 0:
            listing.append("Bad Program (Line length too short)")
            return listing, i, False

        line_end = i + line_len
        if line_end > file_length:
            listing.append("Bad Program (Line truncated)")
            return listing, i, False

        # Decode the line content
        in_quotes = False
        in_rem_or_data = False
        start_of_line = True
        decoded = []

        while i < line_end:
            byte = file_data[i]

            if in_quotes or in_rem_or_data:
                # Inside quotes, output characters literally
                #
                # We also choose not to detokenize inside a REM or DATA statement.
                # This is an unusual case. If entered at the BASIC prompt, anything
                # after REM or DATA doesn't get tokenized. So 10REMPRINT has
                # a token for REM, but the letters of PRINT are encoded as five ASCII
                # characters.
                #
                # So when we detokenize, if we find a BASIC program with a token byte
                # inside a REM or DATA it was put there by alternative means, such as
                # poking memory. We preserve these token bytes as bytes so that if it
                # gets re-tokenized again, the original bytes are restored. This
                # occurs in games sometimes where a REM statement has a short amount
                # of machine code or data in it. (See file '$.HEADER' in the game
                # 'Rat Catcher' for an example, https://bbcmicro.co.uk/game.php?id=4332 ).
                decoded.extend(escape(byte, output_file_should_escape_chars))
            elif byte == ENCODED_LINE_NUMBER:
                # Encoded line number token
                # Decode using algorithm from "The BASIC ROM User Guide" page 41
                if (i + 3) >= line_end:
                    break
                n1 = file_data[i + 1]
                n2 = file_data[i + 2]
                n3 = file_data[i + 3]
                i += 3

                n1  = (n1 * 4) & 0xFF
                low = (n1 & 0xC0) ^ n2
                n1  = (n1 * 4) & 0xFF
                high = n1 ^ n3
                line_ref = high * 256 + low
                decoded.extend(list(bytes(str(line_ref), encoding="ascii")))
            elif byte in TOKENS:
                # We have found a token. The normal thing to do is to just output 
                # the text of the token. This results in a text file that will get
                # tokenized just as if it were typed at the BASIC command prompt.
                #
                # However, in the case of some games the tokenized BASIC has been 
                # manipulated by means other than typing lines at the BASIC prompt. 
                # For example, by poking directly into memory, spaces can be removed
                # that could not be removed when typing lines at the BASIC prompt.
                # 
                # This results in a slight faster and smaller program but 
                # one that cannot be typed in the regular way at the BASIC prompt.
                #
                # To handle these BASIC programs, we encode with extra markup. In 
                # particular e.g. \{TAB} forces the tokenizer to tokenize the TAB 
                # keyword even if the regular tokenizer wouldn't. For 
                # pseudo-variables we can force the LHS token with \{PAGE-LHS} if 
                # needed.
                token_string = list_of_ascii_bytes(TOKENS[byte])
                token_string_marked_up = list_of_ascii_bytes('\\{' + TOKENS[byte] + '}')
                token_string_marked_up_lhs = list_of_ascii_bytes('\\{' + TOKENS[byte] + '-LHS}')
                
                next_char = chr(file_data[i+1]) if (i+1) < line_end else None
                if round_trip_works(decoded, token_string, [byte], next_char):
                    decoded.extend(token_string)
                elif round_trip_works(decoded, token_string_marked_up, [byte]):
                    decoded.extend(token_string_marked_up)
                elif (byte in PSEUDO_VARIABLES_LHS) and round_trip_works(decoded, token_string_marked_up_lhs, [byte]):
                    decoded.extend(token_string_marked_up_lhs)
                else:
                    # Error out
                    listing.append(f"ERROR: Could not detokenize {byte} and get a valid round trip")
                    return listing, i, False
            else:
                # Not a token, just ASCII
                
                # Acornsoft Reversi (https://bbcmicro.co.uk/game.php?id=4463) has 
                # a BASIC variable named 'IF'. This is not normally possible when 
                # typing lines of BASIC code at the BASIC command prompt, since 
                # 'IF' would get tokenized as a keyword.
                #
                # So if we find the letters that happen match a keyword, we check 
                # that we can round trip the detokenize and tokenize. If it doesn't 
                # round trip correctly, then we can mark it up as e.g. \{"IF"} 
                # to avoid any tokenization.
                #
                # We also check for abbreviations of keywords too, such as "RET." 
                # which appears in e.g. Land of Chark (https://bbcmicro.co.uk/game.php?id=1657)
                # even though it looks to be erroneous BASIC code.

                # Check if there is the text of a keyword present here
                match = next((s.decode("ascii") for s in TOKENS_REV if file_data[i:].startswith(s)), None)
                if match:
                    # Check the round trip works as expected when we record the token as a single byte
                    word = list_of_ascii_bytes(match)
                    if round_trip_works(decoded, word, word):
                        decoded.extend(word)
                        i += len(word)-1
                    else:
                        # If no round trip to the byte we want, then mark it explicitly 
                        # as the string of letters, e.g. \{"IF"}
                        token_string_quoted_marked_up = list_of_ascii_bytes('\\{"' + match + '"}')
                        if round_trip_works(decoded, token_string_quoted_marked_up, list_of_ascii_bytes(match)):
                            decoded.extend(token_string_quoted_marked_up)
                            i += len(match)-1
                        else:
                            # Error out
                            decoded.extend(token_string_quoted_marked_up)
                            i += len(match)-1
                            if output_file_should_escape_chars:
                                decoded = ints_to_str(decoded)
                                listing.append(f"{line_number:6d}{decoded}\n")
                            else:
                                decoded = bytes(f"{line_number:6d}", encoding='ascii') + bytes(decoded) + bytes("\n", encoding='ascii')
                                listing.append(decoded)
                            listing.append(f"ERROR: Could not detokenize {byte} and get a valid round trip with possible keyword '{match}'")
                            return listing, i, False
                else:
                    # No potential keyword found. Output a regular character.
                    
                    # We check for a digit at the start of the line. If so it should 
                    # be marked up in quotes to separate it from the line number.
                    # This is seen in Minefield (Graphic Research Ltd) (https://bbcmicro.co.uk/game.php?id=1900)
                    # even though that code looks to be erroneous BASIC code.
                    if start_of_line and _is_digit(byte):
                        decoded.extend(list_of_ascii_bytes('\\{"' + chr(byte) + '"}'))
                    else:
                        decoded.extend(escape(byte, output_file_should_escape_chars))

            # Toggle quote state
            if chr(byte) == '"':
                in_quotes = not in_quotes

            # Set boolean true if starting a REM or DATA statement
            if ((byte == TOKEN_REM) or (byte == TOKEN_DATA)) and not in_quotes:
                in_rem_or_data = True

            i += 1
            start_of_line = False

        if output_file_should_escape_chars:
            decoded = ints_to_str(decoded)
            listing.append(f"{line_number:6d}{decoded}\n")
        else:
            decoded = bytes(f"{line_number:6d}", encoding='ascii') + bytes(decoded) + bytes("\n", encoding='ascii')
            listing.append(decoded)

    listing.append("Bad program (file ends without FF terminator)")
    return listing, i, False

def decode_basic_file(filepath: str, output_file_should_escape_chars: bool) -> tuple[list, bool]:
    """
    Decode a BBC BASIC tokenized program from a file.

    Args:
        filepath: Path to the tokenized BASIC file.
        output_file_should_escape_chars:  When True, converts unprintable characters to ASCII with markup
                                          Rather than 8 bit characters. This also allows the file
                                          to be re-tokenized preserving the original binary.

    Returns:
        A tuple of (listing, success).
    """
    with open(filepath, 'rb') as f:
        file_data = f.read()

    return decode_basic(file_data, output_file_should_escape_chars)


def main(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Converts tokenized BASIC file into detokenized ASCII BASIC format."
    )
    parser.add_argument("input_file",  help="Input tokenized BASIC file")
    parser.add_argument("output_file", help="Output detokenized ASCII file")
    parser.add_argument(
        "--no_escape",
        action="store_true",
        help='Disable conversion of non-printables to escaped strings like "\\x07"'
    )

    parsed = parser.parse_args(args)

    output_file_should_escape_chars = not parsed.no_escape

    listing, end_index, success = decode_basic_file(parsed.input_file, output_file_should_escape_chars)

    # Output result as text or binary file as needed
    if output_file_should_escape_chars:
        # Text file
        listing = "".join(listing)
        with open(parsed.output_file, "w") as f:
            f.write(listing)
    else:
        # Binary file
        listing = b"".join(listing)
        with open(parsed.output_file, "wb") as f:
            f.write(listing)

    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main(sys.argv[1:])
