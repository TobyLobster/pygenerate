#!/usr/bin/env python3
"""
Byte-level syntax checker for tokenised BBC BASIC II.

Purpose: decide whether bytes that *look* like a BASIC program (correct $0D / line number /
length structure) actually contain plausible BASIC, so that coincidental byte patterns inside
binary files can be rejected.

The rules follow the BASIC II ROM (see basic2_acme.asm). Labels from the ROM are quoted in
comments so each rule can be traced back. Only *syntax* is checked, i.e. errors the ROM would
raise purely from parsing a statement:

    Syntax error, Mistake, Missing ',', Missing ')', Missing '"', Missing '#',
    Type mismatch (string vs number), No such variable (for things that can't be a name).

Deliberately NOT checked (these are runtime/dynamic matters and real programs break them):
    FOR/NEXT and REPEAT/UNTIL pairing, GOTO/GOSUB targets existing, value ranges,
    whether variables/PROCs/FNs exist.

Public API:
    check_line(body, in_assembler=False) -> LineResult         strict: would the ROM accept it?
    is_valid_line(body, in_assembler=False) -> bool
    check_program(data, start=0) -> ProgramResult              strict, every line
    assess_program(data, start=0, at_start_of_file=None) -> Assessment
        'likely BASIC': weighs up valid BASIC and assembler lines, partial credit for corrupted
        lines and increasing line numbers, for finding BASIC fragments in binary files

'body' is the bytes of one line *after* the 4-byte header ($0D, line hi, line lo, length) and
not including the next $0D.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------------------------
# Token values (BASIC II)
# ---------------------------------------------------------------------------------------------

CR = 0x0D

T_AND, T_DIV, T_EOR, T_MOD, T_OR = 0x80, 0x81, 0x82, 0x83, 0x84
T_ERROR, T_LINE, T_OFF, T_STEP, T_SPC, T_TAB = 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A
T_ELSE, T_THEN, T_LINE_NUMBER = 0x8B, 0x8C, 0x8D

# Right-hand-side (function) tokens: $8E..$C5  (token_openin .. token_eof)
T_OPENIN, T_PTR_R, T_PAGE_R, T_TIME_R, T_LOMEM_R, T_HIMEM_R = 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93
T_ABS, T_ACS, T_ADVAL, T_ASC, T_ASN, T_ATN, T_BGET, T_COS = 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B
T_COUNT, T_DEG, T_ERL, T_ERR, T_EVAL, T_EXP, T_EXT, T_FALSE = 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3
T_FN, T_GET, T_INKEY, T_INSTR, T_INT, T_LEN, T_LN, T_LOG = 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB
T_NOT, T_OPENUP, T_OPENOUT, T_PI, T_POINT, T_POS, T_RAD, T_RND = 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3
T_SGN, T_SIN, T_SQR, T_TAN, T_TO, T_TRUE, T_USR, T_VAL = 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB
T_VPOS, T_CHR, T_GET_S, T_INKEY_S, T_LEFT, T_MID, T_RIGHT, T_STR = 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3
T_STRING, T_EOF = 0xC4, 0xC5

TOKEN_FIRST_FUNCTION = T_OPENIN       # $8E
TOKEN_FIRST_LHS_COMMAND = 0xC6        # first 'command' token; not valid inside an expression
TOKEN_FIRST_PROGRAM_STATEMENT = 0xCF  # skip_spaces_then_execute_statement: cmp #token_ptr_left_hand_side

# Statement tokens $CF..$FF
T_PTR_L, T_PAGE_L, T_TIME_L, T_LOMEM_L, T_HIMEM_L = 0xCF, 0xD0, 0xD1, 0xD2, 0xD3
T_SOUND, T_BPUT, T_CALL, T_CHAIN, T_CLEAR, T_CLOSE, T_CLG, T_CLS = 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB
T_DATA, T_DEF, T_DIM, T_DRAW, T_END, T_ENDPROC, T_ENVELOPE, T_FOR = 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3
T_GOSUB, T_GOTO, T_GCOL, T_IF, T_INPUT, T_LET, T_LOCAL, T_MODE = 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB
T_MOVE, T_NEXT, T_ON, T_VDU, T_PLOT, T_PRINT, T_PROC, T_READ = 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3
T_REM, T_REPEAT, T_REPORT, T_RESTORE, T_RETURN, T_RUN, T_STOP, T_COLOUR = 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB
T_TRACE, T_UNTIL, T_WIDTH, T_OSCLI = 0xFC, 0xFD, 0xFE, 0xFF

TOKEN_NAMES = {
    0x80: 'AND', 0x81: 'DIV', 0x82: 'EOR', 0x83: 'MOD', 0x84: 'OR', 0x85: 'ERROR', 0x86: 'LINE',
    0x87: 'OFF', 0x88: 'STEP', 0x89: 'SPC', 0x8A: 'TAB(', 0x8B: 'ELSE', 0x8C: 'THEN', 0x8D: '<line>',
    0x8E: 'OPENIN', 0x8F: 'PTR', 0x90: 'PAGE', 0x91: 'TIME', 0x92: 'LOMEM', 0x93: 'HIMEM', 0x94: 'ABS',
    0x95: 'ACS', 0x96: 'ADVAL', 0x97: 'ASC', 0x98: 'ASN', 0x99: 'ATN', 0x9A: 'BGET', 0x9B: 'COS',
    0x9C: 'COUNT', 0x9D: 'DEG', 0x9E: 'ERL', 0x9F: 'ERR', 0xA0: 'EVAL', 0xA1: 'EXP', 0xA2: 'EXT',
    0xA3: 'FALSE', 0xA4: 'FN', 0xA5: 'GET', 0xA6: 'INKEY', 0xA7: 'INSTR(', 0xA8: 'INT', 0xA9: 'LEN',
    0xAA: 'LN', 0xAB: 'LOG', 0xAC: 'NOT', 0xAD: 'OPENUP', 0xAE: 'OPENOUT', 0xAF: 'PI', 0xB0: 'POINT(',
    0xB1: 'POS', 0xB2: 'RAD', 0xB3: 'RND', 0xB4: 'SGN', 0xB5: 'SIN', 0xB6: 'SQR', 0xB7: 'TAN',
    0xB8: 'TO', 0xB9: 'TRUE', 0xBA: 'USR', 0xBB: 'VAL', 0xBC: 'VPOS', 0xBD: 'CHR$', 0xBE: 'GET$',
    0xBF: 'INKEY$', 0xC0: 'LEFT$(', 0xC1: 'MID$(', 0xC2: 'RIGHT$(', 0xC3: 'STR$', 0xC4: 'STRING$(',
    0xC5: 'EOF', 0xC6: 'AUTO', 0xC7: 'DELETE', 0xC8: 'LOAD', 0xC9: 'LIST', 0xCA: 'NEW', 0xCB: 'OLD',
    0xCC: 'RENUMBER', 0xCD: 'SAVE', 0xCE: '<unused>', 0xCF: 'PTR', 0xD0: 'PAGE', 0xD1: 'TIME',
    0xD2: 'LOMEM', 0xD3: 'HIMEM', 0xD4: 'SOUND', 0xD5: 'BPUT', 0xD6: 'CALL', 0xD7: 'CHAIN',
    0xD8: 'CLEAR', 0xD9: 'CLOSE', 0xDA: 'CLG', 0xDB: 'CLS', 0xDC: 'DATA', 0xDD: 'DEF', 0xDE: 'DIM',
    0xDF: 'DRAW', 0xE0: 'END', 0xE1: 'ENDPROC', 0xE2: 'ENVELOPE', 0xE3: 'FOR', 0xE4: 'GOSUB',
    0xE5: 'GOTO', 0xE6: 'GCOL', 0xE7: 'IF', 0xE8: 'INPUT', 0xE9: 'LET', 0xEA: 'LOCAL', 0xEB: 'MODE',
    0xEC: 'MOVE', 0xED: 'NEXT', 0xEE: 'ON', 0xEF: 'VDU', 0xF0: 'PLOT', 0xF1: 'PRINT', 0xF2: 'PROC',
    0xF3: 'READ', 0xF4: 'REM', 0xF5: 'REPEAT', 0xF6: 'REPORT', 0xF7: 'RESTORE', 0xF8: 'RETURN',
    0xF9: 'RUN', 0xFA: 'STOP', 0xFB: 'COLOUR', 0xFC: 'TRACE', 0xFD: 'UNTIL', 0xFE: 'WIDTH',
    0xFF: 'OSCLI',
}

# Expression types
NUM = 'number'
STR = 'string'
ANY = 'any'        # FN and EVAL can return either


def _is_name_char(c: int) -> bool:
    """is_legal_char_in_variable_name: A-Z, a-z, 0-9, '_' and '£' (shown as '`' in ASCII)."""
    return (0x30 <= c <= 0x39) or (0x41 <= c <= 0x5A) or (0x5F <= c <= 0x7A)


def _is_proc_name_char(c: int) -> bool:
    """get_array_or_proc_or_fn_name_loop: '0'-'9', '@'-'Z', '_'-'z'. PROC/FN names may start
    with a digit (e.g. PROC0, PROC@ are both valid)."""
    return (0x30 <= c <= 0x39) or (0x40 <= c <= 0x5A) or (0x5F <= c <= 0x7A)


def _is_hex_digit(c: int) -> bool:
    """parse_hex_number: only '0'-'9' and upper case 'A'-'F' are accepted."""
    return (0x30 <= c <= 0x39) or (0x41 <= c <= 0x46)


# Assembler mnemonics (BASIC II), compared using the bottom five bits of each character as the
# ROM does (so upper and lower case both work).
# Mnemonic groups, in the order of the ROM's mnemonic table (mnemonics_low_bytes). Each group
# shares a set of addressing modes.
_MNEMONIC_GROUPS = {
    'implied':  ('BRK', 'CLC', 'CLD', 'CLI', 'CLV', 'DEX', 'DEY', 'INX', 'INY', 'NOP', 'PHA', 'PHP',
                 'PLA', 'PLP', 'RTI', 'RTS', 'SEC', 'SED', 'SEI', 'TAX', 'TAY', 'TSX', 'TXA', 'TXS',
                 'TYA'),
    'branch':   ('BCC', 'BCS', 'BEQ', 'BMI', 'BNE', 'BPL', 'BVC', 'BVS'),
    'alu':      ('AND', 'EOR', 'ORA', 'ADC', 'CMP', 'LDA', 'SBC'),
    'shift':    ('ASL', 'LSR', 'ROL', 'ROR'),
    'incdec':   ('DEC', 'INC'),
    'cpxy':     ('CPX', 'CPY'),
    'bit':      ('BIT',),
    'jmp':      ('JMP',),
    'jsr':      ('JSR',),
    'ldx':      ('LDX',),
    'ldy':      ('LDY',),
    'sta':      ('STA',),
    'stx':      ('STX',),
    'sty':      ('STY',),
    'opt':      ('OPT',),
    'equ':      ('EQU',),
}
# The ROM compares only the bottom five bits of each letter, so case doesn't matter.
_MNEMONIC_KEYS = {tuple(ord(ch) & 0x1F for ch in m): (m, group)
                  for group, names in _MNEMONIC_GROUPS.items() for m in names}


# ---------------------------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------------------------

@dataclass
class LineResult:
    ok: bool
    message: str = ''
    offset: int = -1               # offset within the line body where the problem was found
    in_assembler: bool = False     # True if the line ends inside an assembler block '[ ...'
    # Set (with ok=True) when the line is valid up to an END/GOTO/RETURN etc. but is followed by
    # bytes that would be a syntax error if they were ever executed. They can't be reached, and
    # protected programs often put junk there (e.g. ':\x15\x06' to disable LIST).
    unreachable_junk: bool = False
    # Set (with ok=True) when the line is only valid because part of it is never checked, and
    # that part looks like data rather than text: e.g. 'REM' or '*' followed by control codes,
    # assembler text after an instruction that isn't a '\' comment, or unreachable junk.
    # Such lines are valid but are weak evidence that the bytes are BASIC.
    weak: bool = False

    def __bool__(self) -> bool:
        return self.ok


@dataclass
class BadLine:
    line_number: int
    offset: int                    # offset of the line's $0D within the data
    message: str
    body: bytes

    def __str__(self) -> str:
        return f"line {self.line_number} (at &{self.offset:X}): {self.message}: {describe(self.body)}"


@dataclass
class ProgramResult:
    structure_ok: bool             # $0D / length bytes form a properly terminated program
    length: int = 0                # bytes from start up to and including the $0D $FF terminator
    lines: int = 0
    bad_lines: list[BadLine] = field(default_factory=list)
    message: str = ''              # explanation if structure_ok is False
    junk_lines: list[BadLine] = field(default_factory=list)   # valid but with unreachable junk
    hidden_bytes_lines: int = 0    # lines whose length byte spans past a $0D (protection tricks)

    @property
    def good_lines(self) -> int:
        return self.lines - len(self.bad_lines)

    @property
    def ok(self) -> bool:
        """Structurally sound and every line passes the syntax check."""
        return self.structure_ok and not self.bad_lines

    def fraction_good(self) -> float:
        return self.good_lines / self.lines if self.lines else 0.0


class _Fail(Exception):
    def __init__(self, message: str, offset: int):
        super().__init__(message)
        self.message = message
        self.offset = offset


# ---------------------------------------------------------------------------------------------
# Line parser
# ---------------------------------------------------------------------------------------------

class _LineParser:
    def __init__(self, body: bytes, in_assembler: bool = False):
        # Execution stops at the first $0D, even if the line's length byte says the line is longer
        # (protected programs hide lines, or machine code in REMs, this way).
        if CR in body:
            body = body[:body.index(CR)]
        # Append a $0D sentinel so peeking at the end of the line always sees the line end,
        # exactly as the ROM does.
        self.b = bytes(body) + b'\r'
        self.end = len(body)
        self.pos = 0
        self.in_assembler = in_assembler
        self.terminal_at = -1          # offset just after an END/GOTO/RETURN... statement
        # Recovery mode (used by assess_program): instead of stopping at the first error, skip
        # to the next ':' or ELSE and carry on, counting good and bad statements.
        self.recover = False
        self.good = 0
        self.bad = 0
        self.junk = False              # stopped at unreachable junk after END/GOTO etc
        self.weak = False              # see LineResult.weak

    # -- low level ----------------------------------------------------------------------------

    def fail(self, message: str, at: Optional[int] = None):
        raise _Fail(message, self.pos if at is None else at)

    def peek(self, ahead: int = 0) -> int:
        i = self.pos + ahead
        return self.b[i] if i <= self.end else CR

    def advance(self, n: int = 1):
        self.pos = min(self.pos + n, self.end)

    def skip_spaces(self) -> int:
        """Skip spaces and return (but don't consume) the next character."""
        while self.b[self.pos] == 0x20:
            self.pos += 1
        return self.b[self.pos]

    def expect(self, ch: int, message: str):
        if self.skip_spaces() != ch:
            self.fail(message)
        self.advance()

    def comma(self):
        self.expect(ord(','), "Missing ,")

    def close_bracket(self):
        self.expect(ord(')'), "Missing )")

    def at_end_of_statement(self) -> bool:
        """check_end_of_statement: ':' or $0D or ELSE."""
        return self.skip_spaces() in (ord(':'), CR, T_ELSE)

    def rest_of_line(self):
        self.note_unchecked(self.pos, self.end)
        self.pos = self.end

    def note_unchecked(self, start: int, end: int, assembler_tail: bool = False,
                       star_command: bool = False):
        """Bytes the ROM skips without checking (REM, DATA, '*' commands, the rest of an assembler
        statement). Note whether they look like data rather than text."""
        content = self.b[start:end]
        if any(c < 0x20 or c == 0x7F for c in content):
            self.weak = True
        elif star_command and any(c >= 0x80 for c in content):
            self.weak = True
        elif assembler_tail and content.strip(b' ') and not content.lstrip(b' ').startswith(b'\\'):
            self.weak = True

    # -- types ----------------------------------------------------------------------------------

    def need_num(self, t: str, at: Optional[int] = None):
        if t == STR:
            self.fail("Type mismatch: number expected", at)

    def need_str(self, t: str, at: Optional[int] = None):
        if t == NUM:
            self.fail("Type mismatch: string expected", at)

    # -- line ---------------------------------------------------------------------------------

    def parse_line(self):
        # 'chain' means the next statement starts right here, without needing a ':' first.
        chain = self.assembler() if self.in_assembler else True
        while True:
            resume_from = self.pos
            try:
                if not chain:
                    # end_of_statement_skip_colon_and_else
                    c = self.skip_spaces()
                    resume_from = self.pos
                    if c == CR:
                        return
                    if c == ord(':'):
                        self.advance()
                    elif c == T_ELSE:
                        self.advance()
                        self.terminal_at = -1   # code after ELSE is reachable
                        if not self.then_clause():
                            continue            # ELSE <line number>: still need an end of statement
                    else:
                        self.fail("Syntax error: expected end of statement")
                c = self.skip_spaces()
                resume_from = self.pos
                chain = self.statement()
                if c in _TERMINAL_STATEMENTS:
                    self.terminal_at = self.pos
                if self.pos > resume_from and c != ord('['):
                    self.good += 1
            except _Fail as e:
                if not self.recover:
                    raise
                if 0 <= self.terminal_at <= e.offset and T_ELSE not in self.b[self.terminal_at:self.end]:
                    self.junk = True        # the rest can never be executed
                    return
                self.bad += 1
                if not self.resync(resume_from):
                    return
                chain = False

    def resync(self, start: int) -> bool:
        """Recovery: move to the next ':' or ELSE after 'start' that isn't inside a string.
        Returns False if there isn't one."""
        in_string = False
        for i in range(start, self.end):
            c = self.b[i]
            if c == ord('"'):
                in_string = not in_string
            elif not in_string and i > start and c in (ord(':'), T_ELSE):
                self.pos = i
                return True
        self.pos = self.end
        return False

    def then_clause(self) -> bool:
        """After THEN or ELSE: either a tokenised line number or more statements.
        Returns True if statements follow directly (chain), False if a line number was consumed."""
        if self.skip_spaces() == T_LINE_NUMBER:
            self.line_number()
            self.terminal_at = self.pos     # THEN/ELSE <line> jumps, so nothing after is reached
            return False
        return True

    def line_number(self):
        """Tokenised line number: $8D followed by three encoded bytes.

        parse_line_number decodes with ASL/EOR so *any* three bytes are accepted by the ROM.
        (The tokeniser only produces bytes in $40-$7F, but protected programs such as Puff
        use other values deliberately, so we don't insist on that.)"""
        start = self.pos
        if self.pos + 4 > self.end:
            self.fail("truncated line number", start)
        self.advance(4)

    def line_number_or_expression(self):
        if self.skip_spaces() == T_LINE_NUMBER:
            self.line_number()
        else:
            self.need_num(self.expression())

    # -- statements -------------------------------------------------------------------------

    def statement(self) -> bool:
        """Parse one statement starting at self.pos.

        Returns True if the next statement starts immediately (no ':' needed), e.g. after
        REPEAT, THEN, ']' etc. Returns False when the caller must find the end of the statement.
        """
        c = self.skip_spaces()
        start = self.pos

        if c >= TOKEN_FIRST_PROGRAM_STATEMENT:
            self.advance()
            handler = _STATEMENTS.get(c)
            if handler is None:
                self.fail(f"Syntax error: {TOKEN_NAMES.get(c, hex(c))}", start)
            return handler(self)

        # lhs_command_token_not_found: an l-value assignment, '=', '*', '[' or empty statement.
        if c == ord('='):
            # found_fn_return_equals
            self.advance()
            self.expression()
            return False
        if c == ord('*'):
            # star_command: rest of line is passed to OSCLI. The tokeniser never tokenises a
            # '*' command, so keyword tokens in one suggest data rather than BASIC.
            self.note_unchecked(self.pos, self.end, star_command=True)
            self.pos = self.end
            return False
        if c == ord('['):
            self.advance()
            return self.assembler()
        if c in (ord(':'), CR, T_ELSE):
            return False            # empty statement

        t = self.lvalue()
        if t is None:
            if c >= 0x80:
                self.fail(f"Syntax error: {TOKEN_NAMES.get(c, hex(c))} cannot start a statement", start)
            self.fail("Syntax error", start)
        self.assignment(t)
        return False

    def assignment(self, t: str):
        # verify_equals_expression_at_ptr2: missing '=' is a 'Mistake'
        if self.skip_spaces() != ord('='):
            self.fail("Mistake: '=' expected")
        self.advance()
        at = self.pos
        e = self.expression()
        if t == STR:
            self.need_str(e, at)
        else:
            self.need_num(e, at)

    # Individual statements. Each returns the 'chain' flag described in statement().

    def st_nothing(self) -> bool:
        return False

    def st_rest_of_line(self) -> bool:
        self.rest_of_line()
        return False

    def st_pseudo_variable(self) -> bool:
        # PAGE= TIME= LOMEM= HIMEM=
        self.expect(ord('='), "Mistake: '=' expected")
        self.need_num(self.expression())
        return False

    def st_ptr(self) -> bool:
        # PTR#operand = expression
        self.hash_channel()
        self.expect(ord('='), "Mistake: '=' expected")
        self.need_num(self.expression())
        return False

    def numeric_args(self, count: int) -> bool:
        for i in range(count):
            if i:
                self.comma()
            self.need_num(self.expression())
        return False

    def st_one_num(self) -> bool:
        return self.numeric_args(1)

    def st_two_nums(self) -> bool:
        return self.numeric_args(2)

    def st_three_nums(self) -> bool:
        return self.numeric_args(3)

    def st_sound(self) -> bool:
        return self.numeric_args(4)

    def st_envelope(self) -> bool:
        return self.numeric_args(14)

    def st_string_expression(self) -> bool:
        # CHAIN, OSCLI
        self.need_str(self.expression())
        return False

    def st_bput(self) -> bool:
        self.hash_channel()
        self.comma()
        self.need_num(self.expression())
        return False

    def st_close(self) -> bool:
        self.hash_channel()
        return False

    def st_call(self) -> bool:
        self.need_num(self.expression())
        while self.skip_spaces() == ord(','):
            self.advance()
            self.required_lvalue()
        return False

    def st_def(self) -> bool:
        # DEF [FN|PROC] name {(lvalue {, lvalue})}
        # The ROM skips DEF lines when executing them in sequence, but when the PROC/FN is called
        # execution continues straight after the parameter list, so the rest is real code.
        c = self.skip_spaces()
        if c not in (T_FN, T_PROC):
            self.fail("DEF must be followed by FN or PROC")
        self.advance()
        self.proc_or_fn_name()
        if self.skip_spaces() == ord('('):
            self.advance()
            self.required_lvalue()
            while self.skip_spaces() == ord(','):
                self.advance()
                self.required_lvalue()
            self.close_bracket()
        return True

    def st_dim(self) -> bool:
        while True:
            self.skip_spaces()
            start = self.pos
            n, suffix = self.name()
            if n == 0:
                self.fail("Bad DIM", start)
            if self.peek() == ord('('):
                # dim_with_brackets
                self.advance()
                self.need_num(self.expression())
                while self.skip_spaces() == ord(','):
                    self.advance()
                    self.need_num(self.expression())
                self.close_bracket()
            else:
                # DIM name size  (reserve bytes); must be a numeric variable
                if suffix == ord('$'):
                    self.fail("Bad DIM", start)
                self.need_num(self.expression())
            if self.skip_spaces() != ord(','):
                return False
            self.advance()

    def st_for(self) -> bool:
        at = self.pos
        t = self.lvalue()
        if t is None:
            self.fail("Syntax error: FOR variable expected", at)
        if t == STR:
            self.fail("Type mismatch: FOR variable", at)
        self.expect(ord('='), "Mistake: '=' expected")
        self.need_num(self.expression())
        self.expect(T_TO, "No TO")
        self.need_num(self.expression())
        if self.skip_spaces() == T_STEP:
            self.advance()
            self.need_num(self.expression())
        return False

    def st_goto(self) -> bool:
        self.line_number_or_expression()
        return False

    def st_if(self) -> bool:
        at = self.pos
        self.need_num(self.expression(), at)
        if self.skip_spaces() == T_THEN:
            self.advance()
        return self.then_clause()

    def print_or_input_formatting(self, c: int) -> bool:
        """Handle TAB( and SPC items. Returns True if one was consumed."""
        if c == T_TAB:
            self.advance()
            self.need_num(self.expression())
            if self.skip_spaces() == ord(','):
                self.advance()
                self.need_num(self.expression())
            self.close_bracket()
            return True
        if c == T_SPC:
            self.advance()
            self.need_num(self.operand())
            return True
        return False

    def st_input(self) -> bool:
        c = self.skip_spaces()
        if c == ord('#'):
            self.advance()
            self.need_num(self.operand())
            while self.skip_spaces() == ord(','):
                self.advance()
                self.required_lvalue()
            return False
        if c == T_LINE:
            self.advance()
        while True:
            c = self.skip_spaces()
            if c in (ord(':'), CR, T_ELSE):
                return False
            if c in (ord(','), ord(';'), ord("'")):
                self.advance()
                continue
            if self.print_or_input_formatting(c):
                continue
            if c == ord('"'):
                self.string_literal()
                continue
            self.required_lvalue()

    def st_let(self) -> bool:
        t = self.required_lvalue()
        self.assignment(t)
        return False

    def st_lvalue_list(self) -> bool:
        # LOCAL: optional list of l-values
        if self.at_end_of_statement():
            return False
        self.required_lvalue()
        while self.skip_spaces() == ord(','):
            self.advance()
            self.required_lvalue()
        return False

    def st_next(self) -> bool:
        # next_command: the variable is optional, and ',' continues with another NEXT,
        # so 'NEXT,' and 'NEXT I,J' and 'NEXT ,,' are all valid.
        while True:
            c = self.skip_spaces()
            if c not in (ord(','), ord(':'), CR, T_ELSE):
                at = self.pos
                if self.required_lvalue() == STR:
                    self.fail("Syntax error: NEXT with string variable", at)
            if self.skip_spaces() != ord(','):
                return False
            self.advance()

    def st_read(self) -> bool:
        while True:
            c = self.skip_spaces()
            if c in (ord(':'), CR, T_ELSE):
                return False
            if c == ord(','):
                self.advance()
                continue
            self.required_lvalue()

    def st_on(self) -> bool:
        c = self.skip_spaces()
        if c == T_ERROR:
            self.advance()
            if self.skip_spaces() == T_OFF:
                self.advance()
                return False
            return True                 # ON ERROR statements
        self.need_num(self.expression())
        c = self.skip_spaces()
        if c not in (T_GOTO, T_GOSUB):
            self.fail("ON syntax")
        self.advance()
        # on_goto_or_gosub_command only counts commas to find the chosen entry, so empty
        # entries such as 'ON X GOTO ,,100' are valid.
        while True:
            if self.skip_spaces() not in (ord(','), ord(':'), CR, T_ELSE):
                self.line_number_or_expression()
            if self.skip_spaces() != ord(','):
                return False            # an ELSE may follow; parse_line handles it
            self.advance()

    def st_vdu(self) -> bool:
        # vdu_command: expression, then an optional single ',' or ';', repeated. Separators are
        # optional ('VDU 22 7' and 'VDU23&EE&00' are valid) but two in a row are not.
        while True:
            if self.at_end_of_statement():
                return False
            self.need_num(self.expression())
            if self.skip_spaces() in (ord(','), ord(';')):
                self.advance()

    def st_print(self) -> bool:
        c = self.skip_spaces()
        if c == ord('#'):
            self.advance()
            self.need_num(self.operand())
            while self.skip_spaces() == ord(','):
                self.advance()
                self.expression()
            return False
        while True:
            c = self.skip_spaces()
            if c in (ord(':'), CR, T_ELSE):
                return False
            if c in (ord('~'), ord(','), ord(';'), ord("'")):
                self.advance()
                continue
            if self.print_or_input_formatting(c):
                continue
            self.expression()

    def st_proc(self) -> bool:
        self.proc_or_fn_name()
        self.optional_arguments()
        return False

    def st_restore(self) -> bool:
        if self.at_end_of_statement():
            return False
        self.line_number_or_expression()
        return False

    def st_chain_on(self) -> bool:
        # REPEAT: execution continues with the next statement directly
        return True

    def st_trace(self) -> bool:
        c = self.skip_spaces()
        if c in (T_ON, T_OFF):
            self.advance()
            return False
        self.line_number_or_expression()
        return False

    def st_until(self) -> bool:
        at = self.pos
        self.need_num(self.expression(), at)
        return False

    # -- assembler ----------------------------------------------------------------------------

    def assembler(self) -> bool:
        """Parse inline assembler until ']' (returns True: BASIC statements follow directly)
        or the end of the line (returns False with in_assembler set)."""
        self.in_assembler = True
        while True:
            c = self.skip_spaces()
            if c == ord(']'):
                # assembler_exit_point -> skip_spaces_then_execute_statement
                self.advance()
                self.in_assembler = False
                return True
            if c == CR:
                return False
            if self.recover:
                start = self.pos
                try:
                    self.assembler_instruction()
                    self.good += 1
                except _Fail:
                    self.bad += 1
                    self.pos = start
            else:
                self.assembler_instruction()
            # find_end_of_statement_loop: anything after the instruction up to ':' or $0D is
            # ignored, so 'LDA &1234 read a byte' is legal. (Strings for EQUS have already been
            # consumed by the operand, so a ':' inside one doesn't end the statement.)
            tail = self.pos
            while True:
                c = self.peek()
                if c == CR:
                    self.note_unchecked(tail, self.pos, assembler_tail=True)
                    break
                self.advance()
                if c == ord(':'):
                    self.note_unchecked(tail, self.pos - 1, assembler_tail=True)
                    break

    def assembler_instruction(self):
        """assemble_single_instruction: optional labels, then a mnemonic and its operand."""
        c = self.skip_spaces()
        while c == ord('.'):
            # assemble_label: must be a numeric l-value; falls back into
            # assemble_single_instruction, so several labels can follow each other.
            self.advance()
            at = self.pos
            t = self.lvalue()
            if t is None or t == STR:
                self.fail("Syntax error: bad assembler label", at)
            c = self.skip_spaces()
        if c in (ord(':'), CR, ord('\\')):
            return
        mnemonic, group = self.mnemonic()
        getattr(self, 'asm_' + group)(mnemonic)

    def mnemonic(self) -> tuple[str, str]:
        """get_mnemonic_letters_loop: up to three characters, compared on their bottom five bits.
        A token anywhere in the three is handled by token_starts_a_mnemonic (AND, EOR, OR+'A')."""
        start = self.pos
        key = []
        while len(key) < 3:
            ch = self.peek()
            if ch >= 0x80:
                self.advance()
                if ch == T_AND:
                    return 'AND', 'alu'
                if ch == T_EOR:
                    return 'EOR', 'alu'
                if ch == T_OR and self.peek() == ord('A'):
                    self.advance()
                    return 'ORA', 'alu'
                self.fail("Syntax error: bad mnemonic", start)
            if ch in (0x20, CR):
                break                       # found_space: fewer than three letters won't match
            key.append(ch & 0x1F)
            self.advance()
        found = _MNEMONIC_KEYS.get(tuple(key))
        if found is None:
            self.fail("Syntax error: bad mnemonic", start)
        return found

    # Operand helpers. 'get_char_from_ptr1_skipping_spaces' becomes skip_spaces() + advance().

    def asm_integer(self):
        """evaluate_integer_expression_at_ptr1"""
        at = self.pos
        self.need_num(self.expression(), at)

    def asm_char(self) -> int:
        c = self.skip_spaces()
        self.advance()
        return c

    def asm_require(self, want: int):
        """The X, Y, A and brackets in operands must match exactly (upper case)."""
        at = self.pos
        if self.asm_char() != want:
            self.fail("Index", at)

    def asm_optional_index(self, registers: str):
        """Optional ',X' / ',Y' after an address."""
        if self.skip_spaces() == ord(','):
            self.advance()
            at = self.pos
            if chr(self.asm_char()) not in registers:
                self.fail("Index", at)

    def asm_implied(self, m):
        pass                                # anything after it is ignored

    def asm_branch(self, m):
        self.asm_integer()

    def asm_alu(self, m):
        # non_branching_instruction: '#' immediate, then the modes shared with STA
        if self.skip_spaces() == ord('#'):
            self.advance()
            self.asm_integer()
            return
        self.asm_sta(m)

    def asm_sta(self, m):
        # not_immediate_addressing_mode3: (zp),Y  (zp,X)  addr  addr,X  addr,Y
        if self.skip_spaces() == ord('('):
            self.advance()
            self.asm_integer()
            at = self.pos
            c = self.asm_char()
            if c == ord(')'):
                self.asm_require(ord(','))
                self.asm_require(ord('Y'))
            elif c == ord(','):
                self.asm_require(ord('X'))
                self.asm_require(ord(')'))
            else:
                self.fail("Index", at)
            return
        self.asm_integer()
        self.asm_optional_index('XY')

    def asm_shift(self, m):
        # 'A' (upper case only) is the accumulator; anything after it is ignored, so the ROM
        # reads 'ROL ADDR' as 'ROL A'.
        if self.skip_spaces() == ord('A'):
            self.advance()
            return
        self.asm_incdec(m)

    def asm_incdec(self, m):
        self.asm_integer()
        self.asm_optional_index('X')

    def asm_cpxy(self, m):
        if self.skip_spaces() == ord('#'):
            self.advance()
        self.asm_integer()

    def asm_bit(self, m):
        self.asm_integer()

    asm_jsr = asm_bit
    asm_opt = asm_bit

    def asm_jmp(self, m):
        if self.skip_spaces() == ord('('):
            self.advance()
            self.asm_integer()
            self.asm_require(ord(')'))
            return
        self.asm_integer()

    def asm_index_register(self, register: str):
        """ldx_or_ldy_comma: only the bottom five bits of the index character are compared, so
        e.g. 'LDX 0,y' and even 'LDX 0,RUN' are accepted."""
        if self.skip_spaces() == ord(','):
            self.advance()
            at = self.pos
            if (self.asm_char() & 0x1F) != (ord(register) & 0x1F):
                self.fail("Index", at)

    def asm_ldx(self, m):
        if self.skip_spaces() == ord('#'):
            self.advance()
            self.asm_integer()
            return
        self.asm_stx(m)

    def asm_stx(self, m):
        self.asm_integer()
        self.asm_index_register('Y')

    def asm_ldy(self, m):
        if self.skip_spaces() == ord('#'):
            self.advance()
            self.asm_integer()
            return
        self.asm_sty(m)

    def asm_sty(self, m):
        self.asm_integer()
        self.asm_index_register('X')

    def asm_equ(self, m):
        # assemble_equ: the very next character (no spaces, upper case) selects the size
        at = self.pos
        c = self.peek()
        self.advance()
        if c in (ord('B'), ord('W'), ord('D')):
            self.asm_integer()
        elif c == ord('S'):
            at = self.pos
            self.need_str(self.expression(), at)
        else:
            self.fail("Syntax error: bad EQU", at)

    # -- l-values -----------------------------------------------------------------------------

    def name(self) -> tuple[int, int]:
        """Read a variable name at pos. Returns (length, suffix) where suffix is '$', '%' or 0.
        The name length does not include the suffix."""
        start = self.pos
        while _is_name_char(self.peek()):
            self.advance()
        n = self.pos - start
        if n == 0:
            return 0, 0
        c = self.peek()
        if c in (ord('$'), ord('%')):
            self.advance()
            return n, c
        return n, 0

    def proc_or_fn_name(self):
        start = self.pos
        while _is_proc_name_char(self.peek()):
            self.advance()
        if self.pos == start:
            self.fail("Bad call: missing PROC/FN name", start)

    def optional_arguments(self):
        # evaluate_parameters: spaces are skipped before '(' so 'PROCx (1)' is valid
        if self.skip_spaces() == ord('('):
            self.advance()
            self.expression()
            while self.skip_spaces() == ord(','):
                self.advance()
                self.expression()
            self.close_bracket()

    def binary_indirection(self) -> bool:
        """check_for_binary_memory_access_operators: name?expr or name!expr (no spaces)."""
        if self.peek() in (ord('?'), ord('!')):
            self.advance()
            self.need_num(self.operand())
            return True
        return False

    def lvalue(self) -> Optional[str]:
        """find_lvalue_details_at_ptr2. Returns NUM/STR, or None if there's no possible l-value
        here (in which case pos is unchanged)."""
        c = self.skip_spaces()
        start = self.pos
        if c < ord('@'):
            # check_for_unary_memory_accessor
            if c in (ord('!'), ord('?')):
                self.advance()
                self.need_num(self.operand())
                return NUM
            if c == ord('$'):
                self.advance()
                self.need_num(self.operand())
                return STR
            return None
        if c <= ord('Z') and self.peek(1) == ord('%') and self.peek(2) != ord('('):
            # Resident integer variable @% to Z%
            self.advance(2)
            self.binary_indirection()
            return NUM
        n, suffix = self.name()
        if n == 0:
            self.pos = start
            return None
        t = STR if suffix == ord('$') else NUM
        if self.peek() == ord('('):
            # array element
            self.advance()
            self.need_num(self.expression())
            while self.skip_spaces() == ord(','):
                self.advance()
                self.need_num(self.expression())
            self.close_bracket()
        if t == NUM:
            self.binary_indirection()
        return t

    def required_lvalue(self) -> str:
        at = self.pos
        t = self.lvalue()
        if t is None:
            self.fail("Syntax error: variable expected", at)
        return t

    def hash_channel(self):
        # parse_hash_file_handle: '#' then a numeric operand
        if self.skip_spaces() != ord('#'):
            self.fail("Missing #")
        self.advance()
        self.need_num(self.operand())

    # -- expressions --------------------------------------------------------------------------

    def expression(self) -> str:
        """evaluate_expression: OR / EOR (lowest precedence)."""
        t = self.expr_and()
        while self.skip_spaces() in (T_OR, T_EOR):
            at = self.pos
            self.need_num(t, at)
            self.advance()
            self.need_num(self.expr_and(), at)
            t = NUM
        return t

    def expr_and(self) -> str:
        t = self.expr_compare()
        while self.skip_spaces() == T_AND:
            at = self.pos
            self.need_num(t, at)
            self.advance()
            self.need_num(self.expr_compare(), at)
            t = NUM
        return t

    def expr_compare(self) -> str:
        # evaluate_expression_group_5: at most ONE comparison (no loop in the ROM)
        t = self.expr_add()
        c = self.skip_spaces()
        if c in (ord('<'), ord('='), ord('>')):
            at = self.pos
            self.advance()
            n = self.peek()
            if (c == ord('<') and n in (ord('='), ord('>'))) or (c == ord('>') and n == ord('=')):
                self.advance()
            t2 = self.expr_add()
            if (t == STR and t2 == NUM) or (t == NUM and t2 == STR):
                self.fail("Type mismatch in comparison", at)
            return NUM
        return t

    def expr_add(self) -> str:
        t = self.expr_mul()
        while True:
            c = self.skip_spaces()
            if c == ord('+'):
                at = self.pos
                self.advance()
                t2 = self.expr_mul()
                if (t == STR and t2 == NUM) or (t == NUM and t2 == STR):
                    self.fail("Type mismatch in +", at)
                t = STR if STR in (t, t2) else (ANY if ANY in (t, t2) else NUM)
            elif c == ord('-'):
                at = self.pos
                self.need_num(t, at)
                self.advance()
                self.need_num(self.expr_mul(), at)
                t = NUM
            else:
                return t

    def expr_mul(self) -> str:
        t = self.expr_power()
        while self.skip_spaces() in (ord('*'), ord('/'), T_MOD, T_DIV):
            at = self.pos
            self.need_num(t, at)
            self.advance()
            self.need_num(self.expr_power(), at)
            t = NUM
        return t

    def expr_power(self) -> str:
        t = self.operand()
        while self.skip_spaces() == ord('^'):
            at = self.pos
            self.need_num(t, at)
            self.advance()
            self.need_num(self.operand(), at)
            t = NUM
        return t

    def operand(self) -> str:
        """evaluate_operand (expression group 1)."""
        c = self.skip_spaces()
        start = self.pos
        if c == ord('-'):
            self.advance()
            self.need_num(self.operand(), start)
            return NUM
        if c == ord('"'):
            self.string_literal()
            return STR
        if c == ord('+'):
            self.advance()
            c = self.skip_spaces()
            start = self.pos

        # evaluate_operand_without_initial_sign / skipping_plus
        if c >= TOKEN_FIRST_FUNCTION:
            if c >= TOKEN_FIRST_LHS_COMMAND:
                self.fail(f"No such variable: {TOKEN_NAMES.get(c, hex(c))} in expression", start)
            self.advance()
            return self.function(c, start)
        if c >= ord('?'):
            t = self.lvalue()
            if t is None:
                self.fail("No such variable", start)
            return t
        if c >= ord('.'):
            self.number(start)
            return NUM
        if c == ord('&'):
            self.advance()
            if not _is_hex_digit(self.peek()):
                self.fail("Bad HEX", start)
            while _is_hex_digit(self.peek()):
                self.advance()
            return NUM
        if c == ord('('):
            self.advance()
            t = self.expression()
            self.close_bracket()
            return t
        # '!' and '$' (and anything else) go via find_lvalue
        t = self.lvalue()
        if t is None:
            self.fail("No such variable", start)
        return t

    def number(self, start: int):
        """ascii_to_float8A_or_iac. First char is one of './0123456789:;<=>'."""
        c = self.peek()
        if not (c == ord('.') or 0x30 <= c <= 0x39):
            self.fail("No such variable", start)
        seen_point = False
        while True:
            c = self.peek()
            if 0x30 <= c <= 0x39:
                self.advance()
            elif c == ord('.') and not seen_point:
                seen_point = True
                self.advance()
            else:
                break
        if self.peek() == ord('E'):
            self.advance()
            if self.peek() in (ord('+'), ord('-')):
                self.advance()
            while 0x30 <= self.peek() <= 0x39:
                self.advance()

    def string_literal(self):
        start = self.pos
        self.advance()
        while True:
            c = self.peek()
            if c == CR:
                self.fail('Missing "', start)
            self.advance()
            if c == ord('"'):
                if self.peek() == ord('"'):     # "" is an embedded quote
                    self.advance()
                    continue
                return

    def function(self, tok: int, start: int) -> str:
        """A right hand side function token ($8E-$C5) has been consumed."""
        if tok in _NUM_OPERAND_FUNCTIONS:
            self.need_num(self.operand(), start)
            return NUM
        if tok in _STRING_OPERAND_TO_NUM_FUNCTIONS:
            self.need_str(self.operand(), start)
            return NUM
        if tok in _NO_ARG_NUM_FUNCTIONS:
            return NUM
        if tok in _HASH_FUNCTIONS:
            self.hash_channel()
            return NUM
        if tok == T_EVAL:
            self.need_str(self.operand(), start)
            return ANY
        if tok in (T_CHR, T_INKEY_S):
            self.need_num(self.operand(), start)
            return STR
        if tok == T_STR:
            if self.skip_spaces() == ord('~'):
                self.advance()
            self.need_num(self.operand(), start)
            return STR
        if tok == T_GET_S:
            return STR
        if tok == T_TO:
            # TOP is tokenised as TO followed by 'P'
            if self.peek() != ord('P'):
                self.fail("No such variable: TO in expression", start)
            self.advance()
            return NUM
        if tok == T_RND:
            if self.peek() == ord('('):
                self.advance()
                self.need_num(self.expression())
                self.close_bracket()
            return NUM
        if tok == T_POINT:
            self.need_num(self.expression())
            self.comma()
            self.need_num(self.expression())
            self.close_bracket()
            return NUM
        if tok == T_INSTR:
            self.need_str(self.expression())
            self.comma()
            self.need_str(self.expression())
            if self.skip_spaces() == ord(','):
                self.advance()
                self.need_num(self.expression())
            self.close_bracket()
            return NUM
        if tok in (T_LEFT, T_RIGHT):
            self.need_str(self.expression())
            self.comma()
            self.need_num(self.expression())
            self.close_bracket()
            return STR
        if tok == T_MID:
            self.need_str(self.expression())
            self.comma()
            self.need_num(self.expression())
            if self.skip_spaces() == ord(','):
                self.advance()
                self.need_num(self.expression())
            self.close_bracket()
            return STR
        if tok == T_STRING:
            self.need_num(self.expression())
            self.comma()
            self.need_str(self.expression())
            self.close_bracket()
            return STR
        if tok == T_FN:
            self.proc_or_fn_name()
            self.optional_arguments()
            return ANY
        self.fail(f"Syntax error: unexpected {TOKEN_NAMES.get(tok, hex(tok))}", start)


# Statements after which the rest of the line can never be reached (unless an ELSE follows).
# '=' is the FN return.
_TERMINAL_STATEMENTS = {T_END, T_STOP, T_RETURN, T_ENDPROC, T_GOTO, T_RUN, T_CHAIN, ord('=')}

_NUM_OPERAND_FUNCTIONS = {
    T_ABS, T_ACS, T_ASN, T_ATN, T_COS, T_DEG, T_EXP, T_INT, T_LN, T_LOG, T_RAD, T_SGN, T_SIN,
    T_SQR, T_TAN, T_ADVAL, T_USR, T_NOT, T_INKEY,
}
_STRING_OPERAND_TO_NUM_FUNCTIONS = {T_ASC, T_LEN, T_VAL, T_OPENIN, T_OPENOUT, T_OPENUP}
_NO_ARG_NUM_FUNCTIONS = {
    T_COUNT, T_ERL, T_ERR, T_FALSE, T_TRUE, T_GET, T_PI, T_POS, T_VPOS,
    T_PAGE_R, T_TIME_R, T_LOMEM_R, T_HIMEM_R,
}
_HASH_FUNCTIONS = {T_PTR_R, T_EXT, T_BGET, T_EOF}

P = _LineParser
_STATEMENTS = {
    T_PTR_L: P.st_ptr,
    T_PAGE_L: P.st_pseudo_variable, T_TIME_L: P.st_pseudo_variable,
    T_LOMEM_L: P.st_pseudo_variable, T_HIMEM_L: P.st_pseudo_variable,
    T_SOUND: P.st_sound, T_BPUT: P.st_bput, T_CALL: P.st_call, T_CHAIN: P.st_string_expression,
    T_CLEAR: P.st_nothing, T_CLOSE: P.st_close, T_CLG: P.st_nothing, T_CLS: P.st_nothing,
    T_DATA: P.st_rest_of_line, T_DEF: P.st_def, T_DIM: P.st_dim, T_DRAW: P.st_two_nums,
    T_END: P.st_nothing, T_ENDPROC: P.st_nothing, T_ENVELOPE: P.st_envelope, T_FOR: P.st_for,
    T_GOSUB: P.st_goto, T_GOTO: P.st_goto, T_GCOL: P.st_two_nums, T_IF: P.st_if,
    T_INPUT: P.st_input, T_LET: P.st_let, T_LOCAL: P.st_lvalue_list, T_MODE: P.st_one_num,
    T_MOVE: P.st_two_nums, T_NEXT: P.st_next, T_ON: P.st_on, T_VDU: P.st_vdu,
    T_PLOT: P.st_three_nums, T_PRINT: P.st_print, T_PROC: P.st_proc, T_READ: P.st_read,
    T_REM: P.st_rest_of_line, T_REPEAT: P.st_chain_on, T_REPORT: P.st_nothing,
    T_RESTORE: P.st_restore, T_RETURN: P.st_nothing, T_RUN: P.st_nothing, T_STOP: P.st_nothing,
    T_COLOUR: P.st_one_num, T_TRACE: P.st_trace, T_UNTIL: P.st_until, T_WIDTH: P.st_one_num,
    T_OSCLI: P.st_string_expression,
}
del P


# ---------------------------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------------------------

def check_line(body: bytes, in_assembler: bool = False) -> LineResult:
    """Check the syntax of one line body (bytes after the 4 byte line header)."""
    p = None
    try:
        p = _LineParser(body, in_assembler)
        p.parse_line()
        return LineResult(True, in_assembler=p.in_assembler, weak=p.weak)
    except _Fail as e:
        if p is None:
            return LineResult(False, e.message, e.offset, in_assembler)
        state = p.in_assembler
        if state and _assembler_exit_later(body, e.offset):
            state = False
        if 0 <= p.terminal_at <= e.offset and T_ELSE not in body[p.terminal_at:]:
            return LineResult(True, f"unreachable: {e.message}", e.offset, state,
                              unreachable_junk=True, weak=True)
        # Keep whatever assembler state was reached, e.g. a bad statement after ']' should
        # not leave the following lines being treated as assembler.
        return LineResult(False, e.message, e.offset, state)
    except RecursionError:
        return LineResult(False, "expression nested too deeply", -1, in_assembler)


def _assembler_exit_later(body: bytes, offset: int) -> bool:
    """After a failure inside assembler, does a later statement on the line start with ']'?
    (Used only to keep track of the assembler state for the following lines.)"""
    in_string = False
    for i in range(max(offset, 0), len(body)):
        c = body[i]
        if c == ord('"'):
            in_string = not in_string
        elif c == ord(':') and not in_string:
            j = i + 1
            while j < len(body) and body[j] == 0x20:
                j += 1
            if j < len(body) and body[j] == ord(']'):
                return True
    return False


def is_valid_line(body: bytes, in_assembler: bool = False) -> bool:
    return check_line(body, in_assembler).ok


def check_program(data: bytes, start: int = 0, max_bad_lines: Optional[int] = None) -> ProgramResult:
    """Walk a tokenised program starting at data[start] (which should be $0D), checking the
    structure and every line's syntax.

    If max_bad_lines is given, stop early once more than that many bad lines are found.
    """
    pos = start
    n = len(data)
    result = ProgramResult(structure_ok=False)
    in_assembler = False
    while True:
        if pos >= n or data[pos] != CR:
            result.message = f"expected $0D at &{pos:X}"
            return result
        if pos + 1 >= n:
            result.message = "truncated before end of program marker"
            return result
        if data[pos + 1] & 0x80:
            result.structure_ok = True
            result.length = pos + 2 - start
            return result
        if pos + 3 >= n:
            result.message = "truncated line header"
            return result
        line_number = (data[pos + 1] << 8) | data[pos + 2]
        length = data[pos + 3]
        if length < 4 or pos + length >= n:
            result.message = f"bad line length {length} at &{pos:X}"
            return result
        body = bytes(data[pos + 4: pos + length])
        # The ROM steps through lines using the length byte (for LIST, GOTO etc) but executes up
        # to the first $0D. Protected programs use this to hide lines from LIST, or put machine
        # code containing $0D bytes in a REM. Only the part up to the first $0D is executed, so
        # that's what we check.
        if CR in body:
            result.hidden_bytes_lines += 1
        result.lines += 1
        r = check_line(body, in_assembler)
        in_assembler = r.in_assembler
        if r.unreachable_junk:
            result.junk_lines.append(BadLine(line_number, pos, f"{r.message} (col {r.offset})", body))
        if not r.ok:
            result.bad_lines.append(BadLine(line_number, pos, f"{r.message} (col {r.offset})", body))
            if max_bad_lines is not None and len(result.bad_lines) > max_bad_lines:
                result.message = "too many bad lines"
                return result
        pos += length


# ---------------------------------------------------------------------------------------------
# 'Likely BASIC' assessment
# ---------------------------------------------------------------------------------------------
#
# check_program() answers "would the ROM accept every line?". assess_program() answers a looser
# question: "is this most likely (a fragment of) a BASIC program?", which is what matters when
# looking for BASIC inside binary files and memory dumps. It weighs up evidence:
#
#  - Lines that are valid BASIC, or valid inline assembler. A fragment found part way through a
#    file may start inside an assembler block whose '[' is missing, so until the context is known
#    each line may be either; ']' or a fall in line numbers (a new program) resets the context.
#  - Corrupted lines get partial credit for the statements that still parse, e.g. a line of five
#    statements with one corrupted byte in the fourth scores 0.8 rather than 0.
#  - Line numbers that increase from one line to the next are strong evidence, since bytes that
#    only happen to look like BASIC have line numbers in no particular order.

BASIC, ASSEMBLER, UNKNOWN = 'basic', 'assembler', 'unknown'


@dataclass
class LineAssessment:
    line_number: int
    offset: int                    # offset of the line's $0D within the data
    credit: float                  # 1.0 = valid, 0 = nothing recognisable, in between = partly valid
    kind: str                      # 'basic', 'assembler', 'weak', 'partial', 'bad', 'blank' or 'empty'
    message: str                   # for lines that aren't fully valid: the strict check's error
    body: bytes


@dataclass
class Assessment:
    likely: bool
    structure_ok: bool
    length: int = 0                # bytes up to and including the $0D $FF terminator
    lines: list[LineAssessment] = field(default_factory=list)
    score: float = 0.0             # mean credit per line
    order: float = 1.0             # fraction of consecutive line numbers that increase
    reason: str = ''               # why it was (or wasn't) judged likely
    message: str = ''              # structure problem, if any

    @property
    def valid_lines(self) -> int:
        return sum(1 for l in self.lines if l.credit == 1.0)

    @property
    def scored_lines(self) -> list[LineAssessment]:
        return [l for l in self.lines if l.kind != 'blank']


def _partial_credit(body: bytes, in_assembler: bool) -> tuple[float, bool]:
    """Recovery parse: the fraction of statements that parse, and the assembler state after."""
    p = _LineParser(body, in_assembler)
    p.recover = True
    try:
        p.parse_line()
    except (_Fail, RecursionError):
        return 0.0, in_assembler
    total = p.good + p.bad
    if p.bad == 0 or total < 2:
        return 0.0, p.in_assembler
    return p.good / total, p.in_assembler


# Thresholds for assess_program, calibrated on the pygenerate test discs (18,924 files):
#  - 47 hand-labelled fragments from memory dumps (43 BASIC, 4 not): all classified correctly.
#  - 2,500 real programs assessed as if found part way through a file: 2,496 judged likely (the
#    others are 1-2 line programs, which are accepted at the start of a file).
#  - 36,000 line structures forged from binary data, 1-10 lines, with random or increasing line
#    numbers: at most 0.3% judged likely for any size, none at 6 lines or more.
LIKELY_MIN_SCORE_UNORDERED = 0.9   # any fragment: nearly every line valid
LIKELY_MIN_SCORE = 0.5             # with mostly increasing line numbers and at least 3 lines
LIKELY_MIN_ORDER = 0.75
LIKELY_MIN_LINES_ORDERED = 3
LIKELY_MIN_VALID_ANY_ORDER = 3     # at least this many fully valid lines and ...
LIKELY_MIN_SCORE_ANY_ORDER = 0.75  # ... this score, whatever the line order (e.g. jumbled numbers)
LIKELY_MIN_SCORE_AT_START = 0.2    # a program at the start of a file is almost always real


def assess_program(data: bytes, start: int = 0, at_start_of_file: Optional[bool] = None) -> Assessment:
    """Decide whether the tokenised program structure at data[start] is likely to be BASIC.

    at_start_of_file: if False (the default when start > 0) the first lines may be inside an
    assembler block whose '[' isn't part of the fragment.
    """
    if at_start_of_file is None:
        at_start_of_file = (start == 0)
    result = Assessment(likely=False, structure_ok=False)
    pos = start
    n = len(data)
    state = BASIC if at_start_of_file else UNKNOWN
    previous_number = None
    increases = pairs = 0
    while True:
        if pos >= n or data[pos] != CR:
            result.message = f"expected $0D at &{pos:X}"
            return result
        if pos + 1 >= n:
            result.message = "truncated before end of program marker"
            return result
        if data[pos + 1] & 0x80:
            result.structure_ok = True
            result.length = pos + 2 - start
            break
        if pos + 3 >= n:
            result.message = "truncated line header"
            return result
        number = (data[pos + 1] << 8) | data[pos + 2]
        length = data[pos + 3]
        if length < 4 or pos + length >= n:
            result.message = f"bad line length {length} at &{pos:X}"
            return result
        body = bytes(data[pos + 4: pos + length])

        if previous_number is not None:
            pairs += 1
            if number > previous_number:
                increases += 1
            else:
                state = UNKNOWN             # probably the start of another program
        previous_number = number

        executed = body[:body.index(CR)] if CR in body else body
        if body and not executed:
            # Only bytes hidden after a $0D: nothing that would ever execute.
            result.lines.append(LineAssessment(number, pos, 0.0, 'empty', 'nothing executable', body))
            pos += length
            continue
        if not executed.strip(b' '):
            # A blank line is valid but says nothing either way, so it isn't scored.
            result.lines.append(LineAssessment(number, pos, 1.0, 'blank', '', body))
            pos += length
            continue

        # Which readings are possible: assembler without a '[' only when the context is unknown
        # (start of a fragment, a new program, or after a line too damaged to read).
        order = {BASIC: [False], ASSEMBLER: [True, False], UNKNOWN: [False, True]}[state]
        best = None
        for in_asm in order:
            r = check_line(body, in_asm)
            if r.ok and not r.weak:
                best = (1.0, BASIC if not in_asm else ASSEMBLER, r.in_assembler, '')
                break
            if r.ok and best is None:
                best = (0.5, 'weak', r.in_assembler, r.message or 'only valid because unchecked bytes follow')
        if best is None:
            first = check_line(body, order[0])
            credits = [(_partial_credit(body, a), a) for a in order]
            (credit, after), in_asm = max(credits, key=lambda c: c[0][0])
            best = (credit, 'partial' if credit > 0 else 'bad', after, first.message)
        credit, kind, in_asm_after, message = best
        result.lines.append(LineAssessment(number, pos, credit, kind, message, body))
        if credit > 0:
            state = ASSEMBLER if in_asm_after else BASIC
        else:
            state = UNKNOWN                 # context lost (e.g. a corrupted '[' line)
        pos += length

    lines = result.scored_lines
    if not lines:
        result.reason = 'no lines with any content'
        result.likely = at_start_of_file     # e.g. a program of blank lines
        return result
    result.score = sum(l.credit for l in lines) / len(lines)
    result.order = increases / pairs if pairs else 1.0
    if at_start_of_file:
        result.likely = result.score >= LIKELY_MIN_SCORE_AT_START
        result.reason = f'{result.score:.0%} valid at the start of the file'
    elif result.valid_lines == 0:
        result.reason = 'no line is fully valid'
    elif result.score >= LIKELY_MIN_SCORE_UNORDERED:
        result.likely = True
        result.reason = f'{result.score:.0%} valid'
    elif (len(lines) >= LIKELY_MIN_LINES_ORDERED and result.order >= LIKELY_MIN_ORDER
          and result.score >= LIKELY_MIN_SCORE):
        result.likely = True
        result.reason = f'{result.score:.0%} valid with {result.order:.0%} of line numbers increasing'
    elif result.valid_lines >= LIKELY_MIN_VALID_ANY_ORDER and result.score >= LIKELY_MIN_SCORE_ANY_ORDER:
        result.likely = True
        result.reason = f'{result.score:.0%} valid with {result.valid_lines} fully valid lines'
    else:
        result.reason = f'only {result.score:.0%} valid' + (f', {result.order:.0%} of line numbers increasing' if pairs else '')
    return result


def describe(body: bytes) -> str:
    """A rough human readable listing of a line body, for error messages."""
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == T_LINE_NUMBER and i + 3 < len(body):
            b1, b2, b3 = body[i + 1:i + 4]
            lo = ((b1 << 2) & 0xC0) ^ b2            # parse_line_number
            hi = ((b1 << 4) & 0xFF) ^ b3
            out.append(str(hi * 256 + lo))
            i += 4
            continue
        if c >= 0x80:
            out.append(TOKEN_NAMES.get(c, f'\\x{c:02x}'))
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            out.append(f'\\x{c:02x}')
        i += 1
    return ''.join(out)


def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: bbc_basic_syntax.py <tokenised BASIC file> [start offset]")
        return 2
    with open(argv[0], 'rb') as f:
        data = f.read()
    start = int(argv[1], 0) if len(argv) > 1 else 0
    r = check_program(data, start)
    if not r.structure_ok:
        print(f"Structure: {r.message}")
    for bad in r.bad_lines:
        print(bad)
    print(f"{r.good_lines}/{r.lines} lines OK")
    return 0 if r.ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
