#!/usr/bin/env python3

"""
BBC BASIC II detokenizer.

Converts a tokenized BBC BASIC II format file into an ASCII BASIC text file.

Unprintable characters are by default converted to "\x07" style strings to give a pure ASCII result.
To override this behaviour, add the "--no_escape" argument. This allows non-printable characters to be output.

Based on the PD JavaScript version at https://github.com/shawty/BBCB_DFS_Catalog/blob/master/dfscat.js
which was based on the original list.pl code from MMB_Utils https://github.com/sweharris/MMB_Utils
"""
import sys

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

def convert_to_string(int_list) -> str:
    result = []
    for number in int_list:
        if number == 92:  # ASCII code for backslash
            result.append('\\x5c')
        if 32 <= number < 127:  # Printable ASCII range
            result.append(chr(number))
        else:
            result.append(f'\\x{number:02x}')  # Non-printable character
    return ''.join(result)

def listing_append(listing, data_to_add):
    listing.append(data_to_add)


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
        if file_data[i] != 13:
            listing_append(listing, "Bad Program (expected ^M at start of line).")
            return listing, i, False
        i += 1

        if i == file_length:
            listing_append(listing, "Bad Program (expected FF terminator).")
            return listing, i, False

        # Line number high byte. 0xFF marks end of program
        if file_data[i] == 0xFF:
            i += 1
            return listing, i, True

        if i > (file_length - 3):
            listing_append(listing, "Bad Program (Line finishes before metadata).")
            return listing, i, False

        # Line number (big-endian)
        line_number = file_data[i] * 256 + file_data[i + 1]
        i += 2

        # Line length (includes the 4-byte header: CR, line_hi, line_lo, length)
        line_len = file_data[i] - 4
        i += 1

        if line_len < 0:
            listing_append(listing, "Bad Program (Line length too short)")
            return listing, i, False

        line_end = i + line_len
        if line_end > file_length:
            listing_append(listing, "Bad Program (Line truncated)")
            return listing, i, False

        # Decode the line content
        in_quotes = False
        in_rem_or_data = False
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
                decoded.append(byte)
            elif byte == 0x8D:
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
                decoded.extend(list(bytes(TOKENS[byte], encoding="ascii")))
            else:
                decoded.append(byte)

            # Toggle quote state
            if chr(byte) == '"':
                in_quotes = not in_quotes

            # Set boolean true if starting a REM or DATA statement
            if (byte == 244) or (byte == 220) and not in_quotes:
                in_rem_or_data = True

            i += 1

        if output_file_should_escape_chars:
            decoded = convert_to_string(decoded)
            listing_append(listing, f"{line_number:6d}{decoded}\n")
        else:
            decoded = bytes(f"{line_number:6d}", encoding='ascii') + bytes(decoded) + bytes("\n", encoding='ascii')
            listing_append(listing, decoded)

    listing_append(listing, "Bad program (file ends without FF terminator)")
    return listing, i, False

def decode_basic_file(filepath: str, output_file_should_escape_chars: bool) -> tuple[list, bool]:
    """
    Decode a BBC BASIC tokenized program from a file.

    Args:
        filepath: Path to the tokenized BASIC file.

    Returns:
        A tuple of (listing, success).
    """
    with open(filepath, 'rb') as f:
        file_data = f.read()

    return decode_basic(file_data, output_file_should_escape_chars)


def main(args: list[str]) -> None:
    """Main entry point for command-line tokenization."""
    if len(args) < 2:
        print('BBC BASIC II detokenizer.')
        print('')
        print('Converts a tokenized BBC BASIC II file into detokenized ASCII BASIC source code.')
        print('')
        print('By default, unprintable characters are converted to "\\x07" style strings to give a pure ASCII result.')
        print('To override this behaviour, add the "--no_escape" argument. In this case, non-printable characters will be output as raw binary.')
        print('')
        print("Usage: python3 bbc_basic_detokenizer.py <input_tokenized_file> <output_text_file> {--no_escape}", file=sys.stderr)
        sys.exit(1)

    output_file_should_escape_chars = True
    if "--no_escape" in args:
        args.remove("--no_escape")
        output_file_should_escape_chars = False

    listing, end_index, success = decode_basic_file(args[0], output_file_should_escape_chars)

    # Output result as text or binary file as needed
    if output_file_should_escape_chars:
        # Text file
        listing = "".join(listing)
        with open(args[1], "w") as f:
            f.write(listing)
    else:
        # Binary file
        listing = b"".join(listing)
        with open(args[1], "wb") as f:
            f.write(listing)

    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
