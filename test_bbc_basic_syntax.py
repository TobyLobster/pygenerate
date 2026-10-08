#!/usr/bin/env python3
"""Tests for bbc_basic_syntax.py.  Run with:  python3 -m unittest test_bbc_basic_syntax -v"""

import io
import unittest

import bbc_basic_syntax as s
import bbc_basic_tokenizer as bt


def tokenise(source: str) -> bytes:
    """Tokenise BASIC source text (lines separated by newlines) to program bytes."""
    return bytes(bt.tokenize_file(io.BytesIO(source.encode('latin-1')), True))


def line_body(text: str) -> bytes:
    """Tokenise a single line of BASIC (without line number) and return the line body bytes."""
    data = tokenise('10 ' + text)
    return data[4:data[3]]


class LineTestCase(unittest.TestCase):
    def assertValid(self, *lines):
        for text in lines:
            with self.subTest(text=text):
                r = s.check_line(line_body(text))
                self.assertTrue(r.ok, f"{text!r} rejected: {r.message} at col {r.offset}")
                self.assertFalse(r.unreachable_junk, f"{text!r} flagged as junk: {r.message}")

    def assertInvalid(self, *lines, contains=None):
        for text in lines:
            with self.subTest(text=text):
                r = s.check_line(line_body(text))
                self.assertFalse(r.ok, f"{text!r} accepted")
                if contains:
                    self.assertIn(contains, r.message)


class TestStatementStart(LineTestCase):
    def test_motivating_examples(self):
        self.assertInvalid('OSCLI OSCLI', 'PRINT PRINT', 'COLOUR COLOUR', ')(*&^')

    def test_immediate_only_commands_are_invalid_in_programs(self):
        # skip_spaces_then_execute_statement only executes tokens >= &CF
        self.assertInvalid('LIST', 'SAVE "X"', 'NEW', 'OLD', 'RENUMBER', 'AUTO', 'LOAD "X"')

    def test_functions_cannot_start_a_statement(self):
        self.assertInvalid('ABS 3', 'CHR$65', 'MID$(A$,1)', 'THEN PRINT')

    def test_empty_statements(self):
        self.assertValid('', ':', '::PRINT', ' : : ')

    def test_star_command_takes_rest_of_line(self):
        self.assertValid('*FX 200,3', '*.', '*L. ZEUS 1E00')

    def test_fn_return(self):
        self.assertValid('=X*2', '=A$+"!"')


class TestAssignment(LineTestCase):
    def test_valid(self):
        self.assertValid('A=1', 'A%=1', 'A$="X"', 'LET A=1', 'LET A$=B$', 'A(1,2)=3', 'A$(3)="X"',
                         '?&70=1', '!&70=0', '$&900="HI"', 'A%?3=4', 'A%!4=0', 'P%=P%+1', '@%=10',
                         'PAGE=&1900', 'TIME=0', 'HIMEM=&3000', 'LOMEM=TOP', 'PTR#F=0',
                         'A=B=C', 'X=Y<>Z', 'snake_case=1', 'A`=1')

    def test_mistake(self):
        self.assertInvalid('A', 'A+1', 'X)', 'PRNT', contains='Mistake')

    def test_type_mismatch(self):
        self.assertInvalid('A$=1', 'A=""', 'A%="X"', '$&900=1', contains='Type mismatch')

    def test_comparisons_do_not_chain(self):
        # evaluate_expression_group_5 performs at most one comparison
        self.assertInvalid('A=B=C=D', 'PRINT 1<2<3')


class TestExpressions(LineTestCase):
    def test_operators_and_precedence(self):
        self.assertValid('X=(1+2)*3^2 DIV 4 MOD 3', 'X=NOT A AND B OR C EOR D', 'X=-Y', 'X=+Y',
                         'X=1E3+.5+&FF+1.5E-3', 'X=A<=B', 'X=A>=B', 'X=A<>B', 'X=--1')

    def test_string_operations(self):
        self.assertValid('A$=B$+"X"+CHR$65', 'X=A$<B$', 'X=A$=""')
        self.assertInvalid('A$=B$-C$', 'X=A$*2', 'X=A$=1', 'X=1+"A"', 'X=NOT A$', 'X=-A$')

    def test_functions(self):
        self.assertValid('X=SIN COS 3', 'X=ABS(-1)+INT RND(10)+RND', 'X=LEN A$+ASC"A"+VAL"3"',
                         'A$=STR$~X+STR$X+MID$(A$,2)+MID$(A$,2,3)+LEFT$(A$,1)+RIGHT$(A$,1)',
                         'A$=STRING$(3,"*")+GET$+INKEY$10', 'X=INSTR(A$,"X")+INSTR(A$,"X",2)',
                         'X=POINT(1,2)+POS+VPOS+COUNT+ERR+ERL+GET+INKEY-99+ADVAL1+USR&FFF4',
                         'X=PTR#F+EXT#F+BGET#F+EOF#F+OPENIN"F"+OPENOUT A$+OPENUP"G"',
                         'X=TRUE+FALSE+PI+DEG1+RAD1+LN2+LOG2+EXP1+SQR4+SGN-1+TAN1+ATN1+ACS1+ASN1',
                         'X=TOP-PAGE+HIMEM+LOMEM+TIME', 'X=EVAL"1+2"', 'A$=EVAL("A$")',
                         'X=FNfoo+FNbar(1,"A")+FN@+FN0', 'X=FNx (1)')

    def test_bad_function_use(self):
        self.assertInvalid('X=LEN 3', 'X=SIN"A"', 'X=PTR F', 'X=INSTR(1,2)', 'X=LEFT$(A$)',
                           'X=MID$(A$', 'X=TO', 'X=FN')

    def test_operand_errors(self):
        self.assertInvalid('X=&', 'X=&g', contains='Bad HEX')
        self.assertInvalid('X=(1', contains='Missing )')
        self.assertInvalid('X="ABC', 'PRINT"', contains='Missing "')
        self.assertInvalid('X=1+', 'X=*2', 'X=#3')

    def test_statement_tokens_in_expressions(self):
        self.assertInvalid('X=PRINT', 'X=1+GOTO', 'PRINT LIST')

    def test_quotes_inside_strings(self):
        self.assertValid('PRINT "He said ""Hi"""', 'A$=""""')


class TestStatements(LineTestCase):
    def test_print(self):
        self.assertValid('PRINT', 'PRINT "A";B,C\'D', 'PRINT TAB(3)"X"TAB(1,2);SPC 3;~X',
                         'PRINT"A"A$B', 'PRINT#F,A,B$', 'PRINT;', "PRINT''")

    def test_input(self):
        self.assertValid('INPUT A', 'INPUT "Name? " N$', 'INPUT LINE A$', 'INPUT#F,A,B$',
                         'INPUT TAB(3)"X",A,B', 'INPUT A,B$')
        self.assertInvalid('INPUT 3')

    def test_graphics_and_sound(self):
        self.assertValid('MODE 7', 'MODE X%', 'CLS', 'CLG', 'COLOUR 3', 'GCOL 0,1', 'MOVE 0,0',
                         'DRAW X,Y', 'PLOT 85,1,2', 'SOUND 1,-15,53,20', 'WIDTH 40',
                         'ENVELOPE 1,1,0,0,0,0,0,0,126,-4,0,-1,126,0')
        self.assertInvalid('MOVE 1', 'PLOT 1,2', 'SOUND 1,2,3', 'SOUND 1,2,3,4,5', 'GCOL 0',
                           'ENVELOPE 1,2,3')

    def test_vdu(self):
        # Separators are optional in vdu_command; two in a row are not.
        self.assertValid('VDU 23,1,0;0;0;0;', 'VDU', 'VDU 22 7', 'VDU23&EE&00&C1', 'VDU 1;')
        self.assertInvalid('VDU 1,,2', 'VDU 76;;18')

    def test_for_next(self):
        self.assertValid('FOR I=1 TO 10', 'FOR I%=1 TO 10 STEP -1', 'NEXT', 'NEXT I', 'NEXT I,J',
                         'NEXT,', 'NEXT ,,', 'FOR A(1)=0 TO 3')
        self.assertInvalid('FOR I=1', 'FOR A$=1 TO 2', 'FOR 1 TO 2', 'NEXT A$')

    def test_if(self):
        self.assertValid('IF A THEN PRINT', 'IF A PRINT', 'IF A=1 THEN 100', 'IF A THEN 100 ELSE 200',
                         'IF A THEN PRINT ELSE PRINT', 'IF A$="Y" THEN 100', 'IF A GOTO 100',
                         'IF A THEN', 'IF A THEN ELSE 20', 'IF X THEN IF Y THEN PRINT')
        self.assertInvalid('IF', 'IF A$ THEN 10', 'IF A THEN X')

    def test_goto_gosub_restore_trace(self):
        self.assertValid('GOTO 100', 'GOSUB 100', 'GOTO X*10', 'RETURN', 'RESTORE', 'RESTORE 100',
                         'TRACE ON', 'TRACE OFF', 'TRACE 100', 'TRACE X')
        self.assertInvalid('GOTO', 'GOTO A$', 'GOSUB "X"')

    def test_on(self):
        self.assertValid('ON X GOTO 10,20,30', 'ON X GOSUB 10,20 ELSE PRINT', 'ON X GOTO ,,9010,,',
                         'ON ERROR OFF', 'ON ERROR REPORT:PRINT ERL:END', 'ON ERROR GOTO 100')
        self.assertInvalid('ON X PRINT', 'ON A$ GOTO 10')

    def test_procedures(self):
        self.assertValid('PROCfoo', 'PROCfoo(1,"A",X)', 'PROC@(1)', 'PROC0', 'PROCx (1,2)',
                         'DEF PROCfoo', 'DEF PROCfoo(A,B$):LOCAL X:X=A', 'DEF FNsq(X)=X*X',
                         'DEFFN@:=1', 'LOCAL A,B$,C%', 'ENDPROC', 'DEF PROCa PRINT')
        self.assertInvalid('PROC', 'PROC(1)', 'DEF X', 'DEF PROC', 'PROCfoo(1')

    def test_dim(self):
        self.assertValid('DIM A(10)', 'DIM A%(10),B 20,C$(3,4)', 'DIM P% 100', 'DIM M% -1')
        self.assertInvalid('DIM', 'DIM 3', 'DIM A$ 10', 'DIM A(10')

    def test_files(self):
        self.assertValid('CLOSE#0', 'BPUT#F,65', 'CHAIN "PROG"', 'CHAIN A$', 'OSCLI "CAT"',
                         'OSCLI A$+"X"')
        self.assertInvalid('CLOSE 0', 'BPUT#F', 'CHAIN 3', 'OSCLI 1')

    def test_misc(self):
        self.assertValid('REM anything at all ][":', 'DATA 1,2,"x:y",anything', 'END', 'STOP',
                         'REPEAT', 'REPEAT UNTIL INKEY(0)=32', 'UNTIL X', 'CLEAR', 'REPORT', 'RUN',
                         'CALL &FFEE', 'CALL &FFEE,A%,B$', 'READ A,B$', 'READ A,,B')
        self.assertInvalid('UNTIL', 'UNTIL A$', 'CALL', 'REPORT X', 'CLS 1')
        # Anything after END can't be reached, so it is accepted but flagged
        self.assertTrue(s.check_line(line_body('END X')).unreachable_junk)

    def test_unused_token(self):
        self.assertInvalid('Î')     # token &CE has no statement


class TestLineNumbers(unittest.TestCase):
    def test_round_trip(self):
        for n in (0, 10, 255, 256, 1000, 32767):
            body = line_body(f'GOTO {n}')
            self.assertTrue(s.check_line(body).ok)
            self.assertEqual(s.describe(body).strip(), f'GOTO {n}')

    def test_any_three_bytes_accepted(self):
        # parse_line_number decodes with ASL/EOR, so unusual encodings (used by protected
        # programs) are accepted by the ROM.
        self.assertTrue(s.check_line(bytes([s.T_GOTO, 0x8D, 0x5C, 0x6C, 0xD0])).ok)

    def test_truncated(self):
        self.assertFalse(s.check_line(bytes([s.T_GOTO, 0x8D, 0x54])).ok)


class TestAssembler(unittest.TestCase):
    def program(self, source):
        return s.check_program(tokenise(source))

    def test_inline_assembler_on_one_line(self):
        r = s.check_line(line_body('[OPT 2:.loop LDA #0:STA &70:BNE loop:]:NEXT'))
        self.assertTrue(r.ok, r.message)
        self.assertFalse(r.in_assembler)

    def test_assembler_spanning_lines(self):
        r = self.program('10 FOR I%=0 TO 3 STEP 3\n20 P%=&900\n30 [OPT I%\n40 .start LDA #65\n'
                         '50 JSR &FFEE \\ print it\n60 lda #0:ORA #1:AND #2:EOR #3\n'
                         '70 .a .b EQUB 0:EQUW 1:EQUD 2:EQUS "a:b"\n80 RTS\n90 ]:NEXT\n100 CALL &900')
        self.assertTrue(r.ok, [str(b) for b in r.bad_lines])

    def test_bad_mnemonic(self):
        r = self.program('10 [OPT 2\n20 LDQ #0\n30 ]\n40 PRINT')
        self.assertEqual([b.line_number for b in r.bad_lines], [20])

    def test_assembler_state_recovers_after_bad_line(self):
        # A 65C02 instruction (not BASIC II) fails, but the ']' later on the line must still end
        # the assembler so the following BASIC lines are checked as BASIC.
        r = self.program('10 [OPT 2\n20 TSB &70:]:PRINT\n30 PRINT "OK"')
        self.assertEqual([b.line_number for b in r.bad_lines], [20])

    def test_basic_lines_are_not_assembler(self):
        r = self.program('10 PRINT\n20 LDA #0')
        self.assertEqual([b.line_number for b in r.bad_lines], [20])


class TestAssemblerOperands(unittest.TestCase):
    """Operand checks, following the ROM's assembler (assemble_single_instruction onwards)."""

    def check(self, instruction):
        return s.check_line(line_body('[OPT 2:' + instruction + ':]'))

    def assertValid(self, *instructions):
        for ins in instructions:
            with self.subTest(ins=ins):
                r = self.check(ins)
                self.assertTrue(r.ok, f"{ins!r} rejected: {r.message} at col {r.offset}")

    def assertInvalid(self, *instructions):
        for ins in instructions:
            with self.subTest(ins=ins):
                self.assertFalse(self.check(ins).ok, f"{ins!r} accepted")

    def test_implied(self):
        # anything after the instruction is ignored, like a comment
        self.assertValid('CLC', 'RTS', 'rts', 'NOP anything here', 'TXA \\ comment')

    def test_branches(self):
        self.assertValid('BNE loop', 'BEQ P%+2', 'bcc &2000')
        self.assertInvalid('BNE', 'BNE "X"', 'BNE #3')

    def test_alu_group(self):
        self.assertValid('LDA #0', 'LDA #ASC"A"', 'LDA &70', 'LDA &70,X', 'LDA &1234,Y', 'LDA (&70),Y',
                         'LDA (&70,X)', 'ORA #1', 'AND #2', 'EOR #3', 'ADC zp%', 'CMP(pt%),Y',
                         'SBC &70 ,X', 'LDA &1234 read a byte', 'LDA#V%MOD256')
        self.assertInvalid('LDA', 'LDA (&70),X', 'LDA (&70)', 'LDA (&70,Y)', 'LDA &70,Z',
                           'LDA &70,x', 'LDA (&70),y', 'LDA #"A"', 'LDA (&70,X')

    def test_sta(self):
        self.assertValid('STA &70', 'STA &70,X', 'STA &1234,Y', 'STA (&70),Y', 'STA (&70,X)')
        self.assertInvalid('STA #3', 'STA', 'STA &70,A')

    def test_shifts_and_inc_dec(self):
        self.assertValid('ASL A', 'ROR A', 'LSR &70', 'ROL &70,X', 'INC &70', 'DEC &70,X',
                         'INC A', 'ROL ADDR')   # 'ROL ADDR' is read as 'ROL A' by the ROM
        self.assertInvalid('ASL', 'ASL &70,Y', 'INC #3', 'DEC &70,Y', 'INC')

    def test_compare_bit_jumps(self):
        self.assertValid('CPX #3', 'CPY &70', 'BIT &70', 'JMP &2000', 'JMP (&20E)', 'JSR &FFEE',
                         'CPX (&3000),X')       # the ROM ignores everything after '(&3000)'
        self.assertInvalid('BIT #3', 'JMP (&20E', 'JMP (&20E,X)', 'JSR', 'JSR #3')

    def test_index_register_instructions(self):
        self.assertValid('LDX #0', 'LDX &70', 'LDX &70,Y', 'LDX 0,y', 'LDY #0', 'LDY &70,X',
                         'STX &70', 'STX &70,Y', 'STY &70,X')
        self.assertInvalid('LDX &70,X', 'LDY &70,Y', 'STX #3', 'STY &70,Y', 'STX &70,X')

    def test_index_register_quirk(self):
        # ldx_or_ldy_comma only compares the bottom five bits of the index character
        body = line_body('[LDX 0,') + bytes([s.T_RUN]) + b':]'
        self.assertTrue(s.check_line(body).ok)

    def test_directives(self):
        self.assertValid('OPT 3', 'opt I%', 'EQUB 1', 'EQUW &1234', 'EQUD 0', 'EQUS "a:b"',
                         'EQUS STRING$(3,"x")', 'equB 0')
        # The size letter must follow immediately and be upper case (assemble_equ: cmp #'B')
        self.assertInvalid('OPT', 'EQUB "A"', 'EQUS 3', 'EQUQ 1', 'EQUb 0', 'equb 0', 'EQU B 1',
                           'OPT "X"')

    def test_tokens_as_mnemonics(self):
        # AND, EOR and OR are tokenised but still work as mnemonics (OR followed by 'A' is ORA)
        self.assertValid('AND &70', 'EOR #&FF', 'ORA (&70),Y')
        self.assertInvalid('OR #1')

    def test_labels(self):
        self.assertValid('.loop', '.loop LDA #0', '.a .b EQUB 0', '.P%')
        self.assertInvalid('.', '.A$', '.loop LDQ')

    def test_string_with_colon_does_not_end_statement(self):
        r = s.check_line(line_body('[EQUS "a:LDQ":RTS:]:PRINT'))
        self.assertTrue(r.ok, r.message)


class TestUnreachableJunk(unittest.TestCase):
    def test_junk_after_terminal_statements(self):
        for prefix in (bytes([s.T_END]), bytes([s.T_RETURN]) + b':', bytes([s.T_ENDPROC]) + b':',
                       line_body('GOTO 100') + b':', line_body('IF A THEN END') + b':',
                       line_body('IF A THEN 100') + b' '):
            with self.subTest(prefix=prefix):
                r = s.check_line(prefix + b'\x15\x06')
                self.assertTrue(r.ok, r.message)
                self.assertTrue(r.unreachable_junk)

    def test_junk_reachable_via_else(self):
        r = s.check_line(line_body('IF A THEN END ELSE') + b'\x15')
        self.assertFalse(r.ok)

    def test_junk_without_terminal_statement(self):
        r = s.check_line(line_body('PRINT') + b':\x15\x06')
        self.assertFalse(r.ok)


class TestProgram(unittest.TestCase):
    def test_valid_program(self):
        r = s.check_program(tokenise('10 MODE 7\n20 PRINT "HELLO"\n30 GOTO 20'))
        self.assertTrue(r.ok)
        self.assertEqual(r.lines, 3)
        self.assertEqual(r.fraction_good(), 1.0)

    def test_bad_lines_reported(self):
        r = s.check_program(tokenise('10 PRINT\n20 OSCLI OSCLI\n30 END'))
        self.assertTrue(r.structure_ok)
        self.assertFalse(r.ok)
        self.assertEqual([b.line_number for b in r.bad_lines], [20])

    def test_offset_and_length(self):
        prog = tokenise('10 PRINT\n20 END')
        data = b'\x00\x01\x02' + prog + b'\xaa\xbb'
        r = s.check_program(data, 3)
        self.assertTrue(r.ok)
        self.assertEqual(r.length, len(prog))

    def test_empty_program(self):
        r = s.check_program(b'\r\xff')
        self.assertTrue(r.structure_ok)
        self.assertEqual(r.lines, 0)

    def test_structure_errors(self):
        prog = tokenise('10 PRINT\n20 END')
        for data in (b'', b'\x00', prog[:-1], prog[:5], b'\r\x00\x0a\x02\r\xff',
                     b'\r\x00\x0a\x09AB\rC\r\xff'):
            with self.subTest(data=data):
                self.assertFalse(s.check_program(data).structure_ok)

    def test_length_byte_spanning_a_cr(self):
        # Line 80's length byte covers a hidden line 85 (a protection trick). The ROM executes
        # line 80 up to the first $0D, so only that part is checked.
        hidden = tokenise('85 PRINT "HIDDEN"')[:-2]
        line80 = tokenise('80 PRINT')[:-2]
        data = line80[:3] + bytes([len(line80) + len(hidden)]) + line80[4:] + hidden + b'\r\xff'
        r = s.check_program(data)
        self.assertTrue(r.ok, r.message)
        self.assertEqual(r.lines, 1)
        self.assertEqual(r.hidden_bytes_lines, 1)
        # Machine code in a REM, containing $0D
        data = b'\r\x00\x14\x0a\xf4\x0d\x0d\x0d\x0d\x0d\r\xff'
        r = s.check_program(data)
        self.assertTrue(r.ok, r.message)

    def test_cr_in_line_body(self):
        self.assertTrue(s.check_line(b'\xf1"A"\r\x00\x00garbage').ok)
        self.assertFalse(s.check_line(b'AB\rC').ok)

    def test_max_bad_lines(self):
        r = s.check_program(tokenise('10 X\n20 Y\n30 Z\n40 PRINT'), max_bad_lines=0)
        self.assertFalse(r.structure_ok)
        self.assertEqual(len(r.bad_lines), 1)

    def test_rom_like_binary_is_rejected(self):
        # Bytes with a valid line structure but machine code content.
        body = bytes([0xA9, 0x00, 0x8D, 0x00, 0x70, 0x60])
        data = b'\r\x00\x0a' + bytes([len(body) + 4]) + body + b'\r\xff'
        r = s.check_program(data)
        self.assertTrue(r.structure_ok)
        self.assertFalse(r.ok)



def program(lines) -> bytes:
    """Build program bytes from (line number, body bytes) pairs, so tests can use any numbering
    and any content (the tokeniser insists on increasing line numbers and valid text)."""
    out = bytearray()
    for number, body in lines:
        out += bytes([13, number >> 8, number & 0xFF, len(body) + 4]) + body
    return bytes(out) + b'\r\xff'


def body(text: str) -> bytes:
    return line_body(text)


class TestLikelyBasic(unittest.TestCase):
    """assess_program: is this fragment most likely BASIC?"""

    def mid(self, lines):
        return s.assess_program(b'\x00' + program(lines), 1)

    def test_fragment_starting_inside_assembler(self):
        # No '[' in the fragment: the strict check fails, but it is a BASIC program fragment.
        lines = [(10, body('LDA #0:STA &70')), (20, body('.loop DEX:BNE loop')), (30, body('RTS')),
                 (40, body(']:NEXT')), (50, body('CALL code%'))]
        self.assertFalse(s.check_program(b'\x00' + program(lines), 1).ok)
        a = self.mid(lines)
        self.assertTrue(a.likely, a.reason)
        self.assertEqual([l.kind for l in a.lines], ['assembler'] * 4 + ['basic'])

    def test_assembler_start_only_assumed_mid_file(self):
        # At the start of a file the first line can't be inside an assembler block. (After an
        # unreadable line the context is unknown again, so later lines may be.)
        lines = [(10, body('LDA #0')), (20, body('PRINT'))]
        a = s.assess_program(program(lines), 0)
        self.assertEqual([l.kind for l in a.lines], ['bad', 'basic'])
        a = s.assess_program(b'\x00' + program(lines), 1)
        self.assertEqual([l.kind for l in a.lines], ['assembler', 'basic'])

    def test_new_program_resets_context(self):
        # assembler, a corrupted line, then a new program whose line numbers start again
        lines = [(400, body('LDX#0:JSR&FFEE')), (410, body('LDA#1:JMP&FF') + b'\x00\x0e'),
                 (30, body('*TV0,1')), (40, body('MODE5')), (50, body('CALL&1E00'))]
        a = self.mid(lines)
        self.assertTrue(a.likely, a.reason)
        self.assertEqual(a.lines[0].kind, 'assembler')
        self.assertEqual(a.lines[2].kind, 'basic')

    def test_partial_credit(self):
        # One corrupted byte in the fourth of five statements
        corrupt = body('CLS:VDU19,0,7,0,0,0:COLOUR3:PRINTTAB(') + b'\x10' + body(',8)"X":G=GET')
        a = self.mid([(170, body('REPEATG=GET:UNTILG=32')), (180, corrupt), (190, body('CHAIN"MAIN"'))])
        self.assertEqual(a.lines[1].kind, 'partial')
        self.assertAlmostEqual(a.lines[1].credit, 0.8)
        self.assertTrue(a.likely)

    def test_on_error_a_loader(self):
        a = self.mid([(10, body('ONERRORA')), (20, body('VDU28,0,20,0,20')), (30, body('*L.CITY')),
                      (40, body('CALL&C30'))])
        self.assertTrue(a.likely, a.reason)

    def test_jumbled_line_numbers_with_valid_lines(self):
        a = self.mid([(1983, body('BPUT#N% Q%')), (1973, body('PRINT"X"')),
                      (1987, body('PRINT EOF#A%')), (1987, body('CLOSE#0'))])
        self.assertLess(a.order, 0.5)
        self.assertTrue(a.likely, a.reason)

    def test_binary_data_is_not_likely(self):
        for lines in ([(3341, b'\r\r\r\r'), (3341, b'\r\r\r\r'), (3341, b'\x00\x00\x00')],
                      [(12832, b' 01000.....\x85R H SOFTWARE'), (13088, b' 01000.....\x85R H SOFTWARE')],
                      [(0, b'\x00\x00\x00\x00'), (0, b'\x00\x00\x00')]):
            with self.subTest(lines=lines):
                self.assertFalse(self.mid(lines).likely)

    def test_short_fragments_need_every_line_valid(self):
        two = [(10, body('RETURN')), (20, b'\x12\x0ay\xd8t')]
        self.assertFalse(self.mid(two).likely)
        self.assertTrue(s.assess_program(program(two), 0).likely)      # fine at the start of a file

    def test_blank_lines_are_not_scored(self):
        a = self.mid([(10, b'   '), (20, b'')])
        self.assertFalse(a.likely)
        a = self.mid([(10, body('PRINT')), (20, b'   '), (30, body('END'))])
        self.assertTrue(a.likely)
        self.assertEqual(a.score, 1.0)

    def test_weak_lines(self):
        # Valid, but only because bytes that look like data are never checked
        for b in (body('REM') + b'\x17\x00\x00', b'*' + bytes([s.T_CLEAR, s.T_CHAIN]),
                  body('END') + b'\x15\x06'):
            with self.subTest(b=b):
                r = s.check_line(b)
                self.assertTrue(r.ok)
                self.assertTrue(r.weak)
        self.assertTrue(s.check_line(line_body('[STA R  some text:]')).weak)
        for b in (body('REM a comment'), body('*FX 200,3'), body('DATA 1,2,3')):
            with self.subTest(b=b):
                self.assertFalse(s.check_line(b).weak)
        # (built from bytes: the tokeniser helper treats a backslash as an escape)
        self.assertFalse(s.check_line(b'[LDA #0 \\ comment:]').weak)

    def test_real_program_is_likely_anywhere(self):
        prog = tokenise('10 MODE 7\n20 FOR I=1 TO 10\n30 PRINT I\n40 NEXT')
        self.assertTrue(s.assess_program(prog).likely)
        self.assertTrue(s.assess_program(b'\x00\x01' + prog, 2).likely)

    def test_structure_errors(self):
        a = s.assess_program(b'\r\x00\x0a\x02\r\xff')
        self.assertFalse(a.structure_ok)
        self.assertFalse(a.likely)


if __name__ == '__main__':
    unittest.main()
