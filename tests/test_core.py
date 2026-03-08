"""
Unit tests for Gr0gu3270 core library (PR1-PR4).
No network, no GUI — tests pure logic only.

Run: python3 -m pytest tests/ -v
"""
import pytest
from libGr0gu3270 import Gr0gu3270, e2a


# ---- Helpers: build EBCDIC bytes from ASCII ----

def ascii_to_ebcdic(text):
    """Convert ASCII string to EBCDIC bytes using the e2a table."""
    result = bytearray()
    for ch in text:
        for i, mapped in enumerate(e2a):
            if mapped == ch:
                result.append(i)
                break
    return bytes(result)


# ---- PR1: ABEND Detection ----

class TestDetectAbend:
    def test_finds_asra(self, h3270):
        """EBCDIC bytes containing 'ASRA' → detects ABEND."""
        # Build server data with ASRA in EBCDIC
        padding = ascii_to_ebcdic("  DFHAC2001 ASRA IN PROGRAM  ")
        detections = h3270.detect_abend(padding)
        abend_codes = [d['code'] for d in detections]
        assert 'ASRA' in abend_codes
        assert any(d['type'] == 'ABEND' for d in detections)

    def test_no_false_positive(self, h3270):
        """Normal screen data → no detections."""
        # Typical CICS welcome screen text in EBCDIC
        normal_data = ascii_to_ebcdic("WELCOME TO CICS REGION PLEASE LOGON")
        detections = h3270.detect_abend(normal_data)
        assert detections == []


# ---- PR2: Screen Map Parsing ----

class TestDecodeBufferAddress:
    def test_12bit_addressing(self, h3270):
        """12-bit: (0x5B, 0x60) → address 0, position (0,0)."""
        # 0x5B = 0b01011011, 0x60 = 0b01100000
        # 12-bit: ((0x5B & 0x3F) << 6) | (0x60 & 0x3F) = (0x1B << 6) | 0x20 = 1728 + 32 = 1760
        row, col = h3270.decode_buffer_address(0x5B, 0x60)
        # 1760 / 80 = 22, 1760 % 80 = 0
        assert row == 22
        assert col == 0

    def test_14bit_addressing(self, h3270):
        """14-bit: (0x00, 0x50) → address 80, position (1,0)."""
        # 0x00 & 0xC0 == 0x00 → 14-bit
        # address = ((0x00 & 0x3F) << 8) | 0x50 = 0x50 = 80
        row, col = h3270.decode_buffer_address(0x00, 0x50)
        assert row == 1
        assert col == 0


class TestDecodeFieldAttribute:
    def test_protected_field(self, h3270):
        """0x60 → protected=True, numeric=False, hidden=False."""
        attr = h3270.decode_field_attribute(0x60)
        assert attr['protected'] is True
        assert attr['numeric'] is False
        assert attr['hidden'] is False

    def test_hidden_field(self, h3270):
        """0x0C → hidden=True (intensity bits = 11)."""
        attr = h3270.decode_field_attribute(0x0C)
        assert attr['hidden'] is True
        assert attr['intensity'] == 'hidden'


class TestParseScreenMap:
    def test_basic_screen(self, h3270):
        """Write + WCC + SBA + SF + data → extracts 1 field."""
        # Build: EW(0xF5) + WCC(0xC0) + SBA(0x11) + addr + SF(0x1D) + attr + data
        data = bytearray()
        data.append(0xF5)  # Erase/Write
        data.append(0xC0)  # WCC
        data.append(0x11)  # SBA
        data.append(0x00)  # addr byte 1 (14-bit, row 0)
        data.append(0x00)  # addr byte 2 (col 0)
        data.append(0x1D)  # SF
        data.append(0x60)  # attr: protected
        # Append "USERID" in EBCDIC
        data.extend(ascii_to_ebcdic("USERID"))

        fields = h3270.parse_screen_map(bytes(data))
        assert len(fields) == 1
        assert fields[0]['protected'] is True
        assert 'USERID' in fields[0]['content']


# ---- PR3: Transaction Correlation ----

class TestDetectTransactionCode:
    def test_cemt_transaction(self, h3270):
        """AID(ENTER) + cursor + SBA + 'CEMT' EBCDIC → 'CEMT'."""
        data = bytearray()
        data.append(0x7D)  # AID: ENTER
        data.append(0x5B)  # cursor addr byte 1
        data.append(0x60)  # cursor addr byte 2
        data.append(0x11)  # SBA
        data.append(0x5B)  # buffer addr byte 1
        data.append(0x60)  # buffer addr byte 2
        data.extend(ascii_to_ebcdic("CEMT"))

        txn = h3270.detect_transaction_code(bytes(data))
        assert txn == "CEMT"

    def test_clear_aid_returns_none(self, h3270):
        """AID(CLEAR) → None (short-read, no transaction)."""
        data = bytearray()
        data.append(0x6D)  # AID: CLEAR
        data.append(0xFF)  # EOR marker
        data.append(0xEF)

        txn = h3270.detect_transaction_code(bytes(data))
        assert txn is None


# ---- PR4: Security Audit ----

class TestClassifyResponse:
    def test_denied_response(self, h3270):
        """Server data containing 'NOT AUTHORIZED' → 'DENIED'."""
        data = ascii_to_ebcdic("DFHAC2002 NOT AUTHORIZED FOR TRANSACTION")
        status = h3270.classify_response(data)
        assert status == 'DENIED'

    def test_accessible_response(self, h3270):
        """Normal server data without violation patterns → 'ACCESSIBLE'."""
        data = ascii_to_ebcdic("ENTER TRANSACTION CODE OR PRESS CLEAR")
        status = h3270.classify_response(data)
        assert status == 'ACCESSIBLE'


# ---- PR4 refactored: Pure payload builders ----

class TestBuildPayloads:
    def test_build_clear_payload_tn3270e(self, h3270):
        """TN3270E CLEAR payload has 5-byte header."""
        payload = h3270.build_clear_payload(is_tn3270e=True)
        assert payload == b'\x00\x00\x00\x00\x01\x6d\xff\xef'

    def test_build_clear_payload_plain(self, h3270):
        """Plain TN3270 CLEAR payload — no header."""
        payload = h3270.build_clear_payload(is_tn3270e=False)
        assert payload == b'\x6d\xff\xef'

    def test_build_txn_payload_plain(self, h3270):
        """Plain TN3270 txn payload contains ENTER AID + SBA + EBCDIC txn code."""
        payload = h3270.build_txn_payload("CEMT", is_tn3270e=False)
        assert payload[:3] == b'\x7d\x5b\x60'  # ENTER + cursor addr
        assert payload.endswith(b'\xff\xef')     # EOR
        # CEMT in EBCDIC: C=0xC3, E=0xC5, M=0xD4, T=0xE3
        assert b'\xc3\xc5\xd4\xe3' in payload


# ---- Single Transaction Scan ----

class TestFingerprintEsm:
    def test_racf(self, h3270):
        """Response with ICH408I → RACF."""
        data = ascii_to_ebcdic("ICH408I USER NOT AUTHORIZED")
        result = h3270.fingerprint_esm(data)
        assert result['esm'] == 'RACF'
        assert 'ICH408I' in result['evidence']

    def test_acf2(self, h3270):
        """Response with ACF2 → ACF2."""
        data = ascii_to_ebcdic("ACF2 VIOLATION DETECTED")
        result = h3270.fingerprint_esm(data)
        assert result['esm'] == 'ACF2'

    def test_unknown(self, h3270):
        """Normal response → UNKNOWN."""
        data = ascii_to_ebcdic("WELCOME TO CICS")
        result = h3270.fingerprint_esm(data)
        assert result['esm'] == 'UNKNOWN'
        assert result['evidence'] == []


class TestAnalyzeScreenFields:
    def test_counts(self, h3270):
        """Mock screen_map → correct counts."""
        screen_map = [
            {'type': 'protected', 'protected': True, 'hidden': False, 'numeric': False, 'content': 'LABEL', 'row': 0, 'col': 0},
            {'type': 'input', 'protected': False, 'hidden': False, 'numeric': False, 'content': '', 'row': 0, 'col': 10},
            {'type': 'input', 'protected': False, 'hidden': True, 'numeric': True, 'content': 'SECRET', 'row': 1, 'col': 10},
        ]
        result = h3270.analyze_screen_fields(screen_map)
        assert result['total'] == 3
        assert result['input'] == 2
        assert result['protected'] == 1
        assert result['hidden'] == 1
        assert result['numeric'] == 1

    def test_hidden_fields_detail(self, h3270):
        """Hidden fields are listed with position/content."""
        screen_map = [
            {'type': 'input', 'protected': False, 'hidden': True, 'numeric': False, 'content': 'PASS', 'row': 5, 'col': 20},
        ]
        result = h3270.analyze_screen_fields(screen_map)
        assert len(result['hidden_fields']) == 1
        assert result['hidden_fields'][0]['row'] == 5
        assert result['hidden_fields'][0]['content'] == 'PASS'


# ---- SPOOL/RCE Detection ----

class TestSpoolConstants:
    def test_spool_patterns_exist(self):
        """SPOOL_SUCCESS_PATTERNS and SPOOL_FAIL_PATTERNS are defined."""
        from libGr0gu3270 import SPOOL_SUCCESS_PATTERNS, SPOOL_FAIL_PATTERNS
        assert 'NORMAL' in SPOOL_SUCCESS_PATTERNS
        assert 'INVREQ' in SPOOL_FAIL_PATTERNS
        assert 'NOTAUTH' in SPOOL_FAIL_PATTERNS


class TestBuildCeciPayload:
    def test_ceci_payload_tn3270(self, h3270):
        """CECI payload in TN3270 mode starts with AID ENTER + SBA."""
        payload = h3270.build_ceci_payload('CECI SPOOLOPEN OUTPUT TOKEN(H3TK)', False)
        # Should be same as build_txn_payload
        expected = h3270.build_txn_payload('CECI SPOOLOPEN OUTPUT TOKEN(H3TK)', False)
        assert payload == expected

    def test_ceci_payload_tn3270e(self, h3270):
        """CECI payload in TN3270E mode has 5-byte header."""
        payload = h3270.build_ceci_payload('CECI SPOOLOPEN OUTPUT TOKEN(H3TK)', True)
        assert payload[:5] == b'\x00\x00\x00\x00\x01'
        assert payload.endswith(b'\xff\xef')

    def test_ceci_payload_contains_ebcdic(self, h3270):
        """CECI payload contains EBCDIC encoding of the command."""
        payload = h3270.build_ceci_payload('CECI', False)
        ebcdic_ceci = h3270.get_ebcdic('CECI')
        assert ebcdic_ceci in payload


class TestSpoolClassifyResponse:
    def test_spool_open_classified_accessible(self, h3270):
        """A SPOOLOPEN NORMAL response contains NORMAL in ASCII."""
        # Simulate: classify_response sees a normal CICS screen
        data = ascii_to_ebcdic("RESPONSE: NORMAL         EXEC CICS SPOOLOPEN")
        status = h3270.classify_response(data)
        assert status == 'ACCESSIBLE'

    def test_spool_denied_classified(self, h3270):
        """NOTAUTH response → DENIED."""
        data = ascii_to_ebcdic("DFHAC2008 NOT AUTHORIZED TO USE TRANSACTION")
        status = h3270.classify_response(data)
        assert status == 'DENIED'


# ---- PR5: AID Scan ----

class TestScreenSimilarity:
    def test_identical_screens(self, h3270):
        """Identical data → similarity 1.0."""
        data = ascii_to_ebcdic("WELCOME TO CICS MENU")
        assert h3270.screen_similarity(data, data) == 1.0

    def test_different_screens(self, h3270):
        """Completely different data → low similarity."""
        a = ascii_to_ebcdic("WELCOME TO CICS MENU PLEASE SELECT")
        b = ascii_to_ebcdic("NOT AUTHORIZED ICH408I SECURITY FAIL")
        sim = h3270.screen_similarity(a, b)
        assert sim < 0.5

    def test_similar_screens(self, h3270):
        """Screens with minor changes (timestamp) → high similarity."""
        a = ascii_to_ebcdic("CICS MENU  16:42:03  SELECT OPTION")
        b = ascii_to_ebcdic("CICS MENU  16:42:05  SELECT OPTION")
        sim = h3270.screen_similarity(a, b)
        assert sim > 0.8

    def test_none_input(self, h3270):
        """None input → 0.0."""
        data = ascii_to_ebcdic("HELLO")
        assert h3270.screen_similarity(None, data) == 0.0
        assert h3270.screen_similarity(data, None) == 0.0


class TestScreenDiff:
    def test_identical_no_diff(self, h3270):
        """Identical screens produce empty diff."""
        data = ascii_to_ebcdic("HELLO WORLD MENU")
        assert h3270.screen_diff(data, data) == []

    def test_different_content(self, h3270):
        """Screens with different parsed fields produce diff entries."""
        # Build minimal 3270 streams with SBA + SF + text
        # WCC + SBA(0,0) + SF(unprotected) + "FOO"
        import struct
        def make_screen(text):
            # F1=W, C0=WCC, 11=SBA, 40 00=addr(0,0), 1D=SF, 40=attr(unprotected)
            return b'\xf1\xc0\x11\x40\x40\x1d\x40' + bytes([0xc1 + i if i < 9 else 0xd1 + i - 9 for i, c in enumerate(text.encode()) for _ in [None]][:0]) + h3270.get_ebcdic(text) + b'\xff\xef'
        ref = make_screen("FOO")
        got = make_screen("BAR")
        diffs = h3270.screen_diff(ref, got)
        assert len(diffs) >= 1
        assert any('FOO' in d.get('ref', '') or 'BAR' in d.get('got', '') for d in diffs)

    def test_none_input(self, h3270):
        """None input produces empty diff."""
        data = ascii_to_ebcdic("HELLO")
        assert h3270.screen_diff(None, data) == []
        assert h3270.screen_diff(data, None) == []


class TestAidScanCategorize:
    def test_violation(self, h3270):
        """Response with security violation → VIOLATION."""
        data = ascii_to_ebcdic("ICH408I NOT AUTHORIZED FOR RESOURCE")
        cat, status, sim = h3270.aid_scan_categorize(data, data)
        assert cat == 'VIOLATION'
        assert status == 'DENIED'

    def test_same_screen(self, h3270):
        """Response identical to ref → SAME_SCREEN."""
        ref = ascii_to_ebcdic("CICS MENU SELECT OPTION 1-9")
        cat, status, sim = h3270.aid_scan_categorize(ref, ref)
        assert cat == 'SAME_SCREEN'
        assert sim > 0.8

    def test_new_screen(self, h3270):
        """Response different from ref → NEW_SCREEN."""
        ref = ascii_to_ebcdic("CICS MENU SELECT OPTION 1-9 PF KEYS")
        resp = ascii_to_ebcdic("ORDER MANAGEMENT ENTER ORDER NUMBER")
        cat, status, sim = h3270.aid_scan_categorize(resp, ref)
        assert cat == 'NEW_SCREEN'
        assert sim < 0.8


class TestBuildAidPayload:
    def test_enter_plain(self, h3270):
        """ENTER AID payload (plain TN3270)."""
        payload = h3270.build_aid_payload('ENTER', is_tn3270e=False)
        assert payload[0:1] == b'\x7d'  # ENTER AID
        assert payload.endswith(b'\xff\xef')

    def test_clear_plain(self, h3270):
        """CLEAR is a short-read AID (no cursor address)."""
        payload = h3270.build_aid_payload('CLEAR', is_tn3270e=False)
        assert payload == b'\x6d\xff\xef'

    def test_pf3_tn3270e(self, h3270):
        """PF3 in TN3270E has 5-byte header."""
        payload = h3270.build_aid_payload('PF3', is_tn3270e=True)
        assert payload[:5] == b'\x00\x00\x00\x00\x01'
        assert payload[5:6] == b'\xf3'  # PF3 AID
        assert payload.endswith(b'\xff\xef')

    def test_pa1_short_read(self, h3270):
        """PA1 is a short-read AID."""
        payload = h3270.build_aid_payload('PA1', is_tn3270e=False)
        assert payload == b'\x6c\xff\xef'


class TestExtractReplayPath:
    def test_empty_logs(self, h3270):
        """No logs → empty path."""
        path = h3270.extract_replay_path()
        assert path == []

    def test_path_from_clear(self, h3270):
        """Logs with CLEAR + follow-up → path includes both."""
        # Insert some client logs
        clear_payload = b'\x6d\xff\xef'  # CLEAR
        txn_payload = b'\x7d\x5b\x60\xc3\xe2\xc7\xd4\xff\xef'  # ENTER+SBA+CSGM
        h3270.write_database_log('C', 'clear', clear_payload)
        h3270.write_database_log('S', 'response', ascii_to_ebcdic("OK"))
        h3270.write_database_log('C', 'txn', txn_payload)
        path = h3270.extract_replay_path()
        assert len(path) == 2
        assert path[0] == clear_payload
        assert path[1] == txn_payload

    def test_skips_negotiations(self, h3270):
        """TN3270 negotiation packets (0xFF) are skipped."""
        h3270.write_database_log('C', 'neg', b'\xff\xfd\x28')
        h3270.write_database_log('C', 'clear', b'\x6d\xff\xef')
        path = h3270.extract_replay_path()
        assert len(path) == 1  # Only CLEAR, no negotiation


class TestAidScanState:
    def test_start_sets_state(self, h3270):
        """aid_scan_start initializes all state."""
        # Insert a reference screen in logs
        h3270.write_database_log('C', 'clear', b'\x6d\xff\xef')
        h3270.write_database_log('S', 'ref', ascii_to_ebcdic("MENU SCREEN"))
        h3270.aid_scan_start()
        assert h3270.aid_scan_running is True
        assert len(h3270.aid_scan_keys) == 22
        assert h3270.aid_scan_index == 0
        assert h3270.aid_scan_ref_screen is not None
        assert len(h3270.aid_scan_replay_path) >= 1

    def test_stop_clears_state(self, h3270):
        """aid_scan_stop sets running to False."""
        h3270.aid_scan_running = True
        h3270.aid_scan_stop()
        assert h3270.aid_scan_running is False

    def test_get_aid_scan_running(self, h3270):
        """get_aid_scan_running returns current state."""
        assert h3270.get_aid_scan_running() is False
        h3270.aid_scan_running = True
        assert h3270.get_aid_scan_running() is True

    def test_timeout_default(self, h3270):
        """Default AID scan timeout is 1.0s."""
        assert h3270.aid_scan_timeout == 1.0

    def test_set_timeout(self, h3270):
        """set_aid_scan_timeout sets and clamps value."""
        h3270.set_aid_scan_timeout(3.0)
        assert h3270.aid_scan_timeout == 3.0

    def test_set_timeout_clamp_low(self, h3270):
        """Timeout clamped to 0.5 minimum."""
        h3270.set_aid_scan_timeout(0.1)
        assert h3270.aid_scan_timeout == 0.5

    def test_set_timeout_clamp_high(self, h3270):
        """Timeout clamped to 10.0 maximum."""
        h3270.set_aid_scan_timeout(99)
        assert h3270.aid_scan_timeout == 10.0


class TestAidScanDB:
    def test_write_read_aid_scan(self, h3270):
        """Write + read AID scan result round-trip."""
        import time
        result = {
            'aid_key': 'PF5',
            'category': 'NEW_SCREEN',
            'status': 'ACCESSIBLE',
            'similarity': 0.234,
            'response_preview': 'ADMIN MENU',
            'response_len': 500,
            'timestamp': time.time(),
        }
        h3270.write_aid_scan_log(result)
        rows = h3270.all_aid_scan_results()
        assert len(rows) == 1
        assert rows[0][2] == 'PF5'
        assert rows[0][3] == 'NEW_SCREEN'
        assert rows[0][4] == 'ACCESSIBLE'
        assert abs(rows[0][5] - 0.234) < 0.001

    def test_read_since(self, h3270):
        """all_aid_scan_results(since) filters by ID."""
        import time
        for key in ['PF1', 'PF2', 'PF3']:
            h3270.write_aid_scan_log({
                'aid_key': key, 'category': 'SAME_SCREEN', 'status': 'ACCESSIBLE',
                'similarity': 0.9, 'response_preview': '', 'response_len': 100,
                'timestamp': time.time(),
            })
        all_rows = h3270.all_aid_scan_results()
        assert len(all_rows) == 3
        since_rows = h3270.all_aid_scan_results(start=1)
        assert len(since_rows) == 2


# ---- AID Scan: DVCA Benchmark ----

class MockSocket:
    """Fake socket that records sends and returns nothing."""
    def __init__(self):
        self.sent = []
    def send(self, data):
        self.sent.append(data)
    def flush(self):
        pass

class TestAidScanDVCA:
    """Benchmark aid_scan_next() against simulated DVCA scenarios."""

    def _setup_scan(self, h3270, ref_text="MCMM MAIN MENU OPTION ==>"):
        """Prepare h3270 for AID scan with mocked sockets and ref screen."""
        ref_screen = ascii_to_ebcdic(ref_text)
        h3270.write_database_log('C', 'clear', b'\x6d\xff\xef')
        h3270.write_database_log('S', 'ref', ref_screen)
        h3270.aid_scan_start()
        h3270.client = MockSocket()
        h3270.server = MockSocket()
        return ref_screen

    def test_same_screen_green(self, h3270):
        """DVCA: PF7 on MCMM — same screen returned, replay OK."""
        ref = self._setup_scan(h3270)
        # AID key returns same screen, replay returns same screen
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: ref
        h3270.aid_scan_replay = lambda: ref
        result = h3270.aid_scan_next()
        assert result['category'] == 'SAME_SCREEN'
        assert result['replay_ok'] is True

    def test_new_screen_replay_ok(self, h3270):
        """DVCA: ENTER with option 1 — navigates to MCOR, replay returns to MCMM."""
        ref = self._setup_scan(h3270)
        mcor_screen = ascii_to_ebcdic("MCOR ORDER SUPPLY ITEM NAME PRICE")
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: mcor_screen
        h3270.aid_scan_replay = lambda: ref
        result = h3270.aid_scan_next()
        assert result['category'] == 'NEW_SCREEN'
        assert result['replay_ok'] is True

    def test_unmapped_replay_ok(self, h3270):
        """DVCA: PA3 ignored — no response, replay still works."""
        ref = self._setup_scan(h3270)
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: None
        h3270.aid_scan_replay = lambda: ref
        result = h3270.aid_scan_next()
        assert result['category'] == 'UNMAPPED'
        assert result['replay_ok'] is True

    def test_violation_abend_replay_ok(self, h3270):
        """DVCA: key triggers ABEND, but replay recovers."""
        ref = self._setup_scan(h3270)
        abend_screen = ascii_to_ebcdic("DFHAC2001 ASRA IN PROGRAM TESTPGM")
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: abend_screen
        h3270.aid_scan_replay = lambda: ref
        result = h3270.aid_scan_next()
        assert result['category'] == 'VIOLATION'
        assert result['replay_ok'] is True

    def test_session_kill_recovery_continues(self, h3270):
        """DVCA: PF3 kills KICKS session — replay fails, but scan continues with per-key recovery."""
        ref = self._setup_scan(h3270)
        dead_screen = ascii_to_ebcdic("TSO READY")
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: dead_screen
        h3270.aid_scan_replay = lambda: dead_screen  # always returns wrong screen
        result = h3270.aid_scan_next()
        # First key: tested, red dot
        assert result['replay_ok'] is False
        # Scan continues (no abort)
        assert h3270.aid_scan_running is True
        assert h3270.aid_scan_needs_recovery is True
        # Next key: pre-recovery fails → SKIPPED, but scan still runs
        r2 = h3270.aid_scan_next()
        assert r2['category'] == 'SKIPPED'
        assert h3270.aid_scan_running is True

    def test_transient_fail_recovery_succeeds(self, h3270):
        """DVCA: slow mainframe — first replay fails, recovery succeeds, scan continues."""
        ref = self._setup_scan(h3270)
        bad_screen = ascii_to_ebcdic("LOADING PLEASE WAIT")
        # Track replay calls: first 2 return bad screen (initial try_replay),
        # next 2 return ref screen (recovery try_replay)
        call_count = [0]
        def mock_replay():
            call_count[0] += 1
            return bad_screen if call_count[0] <= 2 else ref
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: ref
        h3270.aid_scan_replay = mock_replay
        result = h3270.aid_scan_next()
        assert result['replay_ok'] is False  # initial replay failed
        assert h3270.aid_scan_running is True  # but scan continues (recovered)
        # No SKIPPED results
        skipped = [r for r in h3270.aid_scan_results if r['category'] == 'SKIPPED']
        assert len(skipped) == 0

    def test_replay_none_continues(self, h3270):
        """DVCA: server completely dead — replay returns None, scan continues per-key."""
        ref = self._setup_scan(h3270)
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: None
        h3270.aid_scan_replay = lambda: None  # dead
        result = h3270.aid_scan_next()
        assert result['category'] == 'UNMAPPED'
        assert result['replay_ok'] is False
        assert h3270.aid_scan_running is True
        assert h3270.aid_scan_needs_recovery is True

    def test_dynamic_content_still_matches(self, h3270):
        """DVCA: timestamp changes between ref and replay — similarity still > 0.8."""
        ref = self._setup_scan(h3270, "MCMM MAIN MENU OPTION ==> TIME 10:30:00")
        # Same screen but timestamp changed (5 chars diff out of 39)
        replay_screen = ascii_to_ebcdic("MCMM MAIN MENU OPTION ==> TIME 10:31:15")
        h3270._aid_scan_send_and_read = lambda payload, timeout=2: ref
        h3270.aid_scan_replay = lambda: replay_screen
        result = h3270.aid_scan_next()
        assert result['replay_ok'] is True

    def test_multiple_keys_sequence(self, h3270):
        """DVCA: scan 3 keys — 2 OK then session kill — scan continues, key 4 SKIPPED."""
        ref = self._setup_scan(h3270)
        dead_screen = ascii_to_ebcdic("TSO READY")
        call_count = [0]
        def mock_send(payload, timeout=2):
            call_count[0] += 1
            if call_count[0] <= 2:
                return ref  # first 2 keys: same screen
            return dead_screen  # 3rd key: session dies
        h3270._aid_scan_send_and_read = mock_send
        # Replay: works for first 2, fails after 3rd
        def mock_replay():
            if call_count[0] <= 2:
                return ref
            return dead_screen
        h3270.aid_scan_replay = mock_replay

        r1 = h3270.aid_scan_next()
        assert r1['replay_ok'] is True
        assert h3270.aid_scan_running is True

        r2 = h3270.aid_scan_next()
        assert r2['replay_ok'] is True
        assert h3270.aid_scan_running is True

        r3 = h3270.aid_scan_next()
        assert r3['replay_ok'] is False
        assert h3270.aid_scan_running is True  # continues, no abort
        assert h3270.aid_scan_needs_recovery is True

        # Key 4: pre-recovery fails → SKIPPED
        r4 = h3270.aid_scan_next()
        assert r4['category'] == 'SKIPPED'
        assert len(h3270.aid_scan_results) == 4


class TestAidScanFastRecovery:
    """Tests for CLEAR+txn fast recovery in AID scan."""

    def test_start_captures_txn_code(self, h3270):
        """aid_scan_start() captures txn code from last client log entry."""
        # Write a client payload with a detectable txn code
        is_tn3270e = h3270.check_inject_3270e()
        txn_payload = h3270.build_txn_payload('MCMM', is_tn3270e)
        h3270.write_database_log('C', 'txn', txn_payload)
        h3270.write_database_log('S', 'ref', ascii_to_ebcdic("MCMM MENU"))
        h3270.aid_scan_start()
        assert h3270.aid_scan_txn_code == 'MCMM'

    def test_fast_recovery_skips_full_replay(self, h3270):
        """CLEAR+txn succeeds → full replay is never called."""
        ref = ascii_to_ebcdic("MCMM MAIN MENU OPTION ==>")
        h3270.write_database_log('C', 'clear', b'\x6d\xff\xef')
        h3270.write_database_log('S', 'ref', ref)
        h3270.aid_scan_start()
        h3270.aid_scan_txn_code = 'MCMM'
        h3270.client = MockSocket()
        h3270.server = MockSocket()
        # _aid_scan_send_and_read returns ref screen (fast path works)
        h3270._aid_scan_send_and_read = lambda payload, timeout=1.0: ref
        # aid_scan_replay should NOT be called — make it fail loudly
        replay_called = [False]
        def bad_replay():
            replay_called[0] = True
            return None
        h3270.aid_scan_replay = bad_replay
        ok = h3270._aid_scan_try_replay('PF1')
        assert ok is True
        assert replay_called[0] is False

    def test_fast_recovery_fallback_to_full_replay(self, h3270):
        """CLEAR+txn gives low similarity → falls back to full replay."""
        ref = ascii_to_ebcdic("MCMM MAIN MENU OPTION ==>")
        wrong = ascii_to_ebcdic("COMPLETELY DIFFERENT SCREEN HERE")
        h3270.write_database_log('C', 'clear', b'\x6d\xff\xef')
        h3270.write_database_log('S', 'ref', ref)
        h3270.aid_scan_start()
        h3270.aid_scan_txn_code = 'MCMM'
        h3270.client = MockSocket()
        h3270.server = MockSocket()
        # Fast path returns wrong screen, full replay returns ref
        call_count = [0]
        def mock_send(payload, timeout=1.0):
            call_count[0] += 1
            if call_count[0] <= 2:  # CLEAR + txn (fast path)
                return wrong
            return ref  # shouldn't be called in send_and_read for replay
        h3270._aid_scan_send_and_read = mock_send
        h3270.aid_scan_replay = lambda: ref
        ok = h3270._aid_scan_try_replay('PF1')
        assert ok is True  # recovered via full replay


# ---- PR6: Multi-Field Payload ----

class TestBuildMultiFieldPayload:
    def test_two_fields(self, h3270):
        """Payload with 2 fields: AID + cursor + 2x SBA + EOR."""
        fields = [('AB', 1, 10), ('CD', 3, 20)]
        payload = h3270.build_multi_field_payload(fields, is_tn3270e=False)
        # AID = ENTER (0x7d)
        assert payload[0:1] == b'\x7d'
        # Cursor address = encode(1, 10)
        cursor = h3270.encode_buffer_address(1, 10)
        assert payload[1:3] == cursor
        # First SBA order
        assert payload[3:4] == b'\x11'
        sba1 = h3270.encode_buffer_address(1, 10)
        assert payload[4:6] == sba1
        # Second SBA order somewhere after
        sba2 = h3270.encode_buffer_address(3, 20)
        assert b'\x11' + sba2 in payload
        # Ends with IAC EOR
        assert payload.endswith(b'\xff\xef')

    def test_tn3270e_prefix(self, h3270):
        """TN3270E mode adds 5-byte header."""
        fields = [('X', 0, 0)]
        payload = h3270.build_multi_field_payload(fields, is_tn3270e=True)
        assert payload[:5] == b'\x00\x00\x00\x00\x01'
        assert payload.endswith(b'\xff\xef')

    def test_empty_fields(self, h3270):
        """Empty fields list returns empty bytes."""
        payload = h3270.build_multi_field_payload([], is_tn3270e=False)
        assert payload == b''


# ---- Macro Engine ----

class TestMacroParser:

    def test_parse_macro_valid(self, h3270, tmp_path):
        """Valid macro JSON loads successfully."""
        macro = {"name": "test", "steps": [
            {"action": "CLEAR"},
            {"action": "SEND", "text": "LOGON", "aid": "ENTER"},
            {"action": "WAIT", "text": "READY"},
            {"action": "AID", "key": "PF1"},
        ]}
        f = tmp_path / "test.json"
        import json
        f.write_text(json.dumps(macro))
        steps, err = h3270.parse_macro(str(f))
        assert err is None
        assert len(steps) == 4

    def test_parse_macro_invalid_action(self, h3270, tmp_path):
        """Rejects unknown action."""
        macro = {"steps": [{"action": "JUMP"}]}
        f = tmp_path / "bad.json"
        import json
        f.write_text(json.dumps(macro))
        steps, err = h3270.parse_macro(str(f))
        assert steps is None
        assert 'Unknown action' in err

    def test_validate_step_send_missing_text(self, h3270):
        """SEND without text is invalid."""
        ok, err = h3270.validate_macro_step({"action": "SEND"})
        assert not ok
        assert 'text' in err.lower()

    def test_build_macro_step_clear(self, h3270):
        """CLEAR step produces correct payload."""
        payload = h3270.build_macro_step_payload({"action": "CLEAR"}, is_tn3270e=False)
        assert payload == b'\x6d\xff\xef'

    def test_build_macro_step_send(self, h3270):
        """SEND step with AID produces ENTER + cursor + EBCDIC text."""
        payload = h3270.build_macro_step_payload(
            {"action": "SEND", "text": "CSGM", "aid": "ENTER"}, is_tn3270e=False)
        assert payload[0:1] == b'\x7d'  # ENTER AID
        assert payload.endswith(b'\xff\xef')

    def test_build_macro_step_aid(self, h3270):
        """AID step for PF8 produces bare key payload."""
        payload = h3270.build_macro_step_payload(
            {"action": "AID", "key": "PF8"}, is_tn3270e=False)
        assert payload[0:1] == b'\xf8'  # PF8
        assert payload.endswith(b'\xff\xef')


# ---- F-0003: Injection files path ----

class TestListInjectionFiles:
    def test_list_injection_files_from_any_cwd(self, h3270, tmp_path, monkeypatch):
        """list_injection_files() works even when cwd is not the project root."""
        monkeypatch.chdir(tmp_path)
        files = h3270.list_injection_files()
        assert len(files) > 0
        assert all(f.endswith('.txt') for f in files)


# ---- F-0007: ABEND regex fallback ----

class TestAbendRegexFallback:
    def test_detect_abend_regex_fallback(self, h3270):
        """Unknown ABEND code AZZZ detected via regex fallback."""
        data = ascii_to_ebcdic("Abend Code AZZZ")
        detections = h3270.detect_abend(data)
        codes = [d['code'] for d in detections]
        assert 'AZZZ' in codes
        assert any(d['description'] == 'Unknown ABEND (not in catalog)' for d in detections)

    def test_detect_abend_regex_no_duplicate(self, h3270):
        """Known ABEND ASRA found by dict should not be duplicated by regex."""
        data = ascii_to_ebcdic("ABEND ASRA in program")
        detections = h3270.detect_abend(data)
        asra_count = sum(1 for d in detections if d['code'] == 'ASRA')
        assert asra_count == 1


# ---- Findings ----

class TestFindings:
    def test_findings_table_exists(self, h3270):
        """Findings table is created at init."""
        h3270.sql_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Findings'")
        assert h3270.sql_cur.fetchone() is not None

    def test_emit_finding_basic(self, h3270):
        """emit_finding inserts and retrieves a finding."""
        result = h3270.emit_finding('HIGH', 'ABEND', 'ASRA detected', txn_code='CECI')
        assert result is True
        rows = h3270.all_findings()
        assert len(rows) == 1
        assert rows[0][2] == 'HIGH'
        assert rows[0][3] == 'ABEND'
        assert rows[0][4] == 'CECI'
        assert rows[0][5] == 'ASRA detected'

    def test_emit_finding_dedup(self, h3270):
        """Same dedup_key inserts only one row."""
        h3270.emit_finding('HIGH', 'ABEND', 'ASRA detected', dedup_key='ABEND:ASRA:CECI')
        h3270.emit_finding('HIGH', 'ABEND', 'ASRA detected again', dedup_key='ABEND:ASRA:CECI')
        rows = h3270.all_findings()
        assert len(rows) == 1

    def test_emit_finding_different_keys(self, h3270):
        """Different dedup_keys create separate rows."""
        h3270.emit_finding('HIGH', 'ABEND', 'ASRA', dedup_key='key1')
        h3270.emit_finding('MEDIUM', 'FUZZER', 'denied', dedup_key='key2')
        rows = h3270.all_findings()
        assert len(rows) == 2

    def test_emit_finding_with_txn(self, h3270):
        """txn_code is properly stored."""
        h3270.emit_finding('INFO', 'AID_SCAN', 'PF5 new screen', txn_code='MCMM')
        rows = h3270.all_findings()
        assert rows[0][4] == 'MCMM'

    def test_all_findings_since(self, h3270):
        """Incremental retrieval via start parameter."""
        h3270.emit_finding('HIGH', 'ABEND', 'first', dedup_key='k1')
        h3270.emit_finding('MEDIUM', 'FUZZER', 'second', dedup_key='k2')
        rows = h3270.all_findings()
        first_id = rows[0][0]
        rows_since = h3270.all_findings(start=first_id)
        assert len(rows_since) == 1
        assert rows_since[0][5] == 'second'

    def test_all_findings_txn_filter(self, h3270):
        """Filtering by transaction code."""
        h3270.emit_finding('HIGH', 'ABEND', 'on CECI', txn_code='CECI', dedup_key='k1')
        h3270.emit_finding('MEDIUM', 'FUZZER', 'on MCMM', txn_code='MCMM', dedup_key='k2')
        h3270.emit_finding('INFO', 'AID_SCAN', 'no txn', dedup_key='k3')
        rows = h3270.all_findings(txn_code='CECI')
        assert len(rows) == 1
        assert rows[0][5] == 'on CECI'

    def test_finding_status_default(self, h3270):
        """New findings have STATUS='NEW' by default."""
        h3270.emit_finding('HIGH', 'ABEND', 'test', dedup_key='status1')
        row = h3270.all_findings()[0]
        assert row[7] == 'NEW'

    def test_get_finding_by_id(self, h3270):
        """get_finding returns a single row by ID."""
        h3270.emit_finding('HIGH', 'ABEND', 'test find', dedup_key='get1')
        rows = h3270.all_findings()
        row = h3270.get_finding(rows[0][0])
        assert row is not None
        assert row[5] == 'test find'

    def test_update_finding_status(self, h3270):
        """update_finding changes status in DB."""
        h3270.emit_finding('HIGH', 'ABEND', 'update test', dedup_key='upd1')
        fid = h3270.all_findings()[0][0]
        ok = h3270.update_finding(fid, status='CONFIRMED')
        assert ok is True
        row = h3270.get_finding(fid)
        assert row[7] == 'CONFIRMED'

    def test_update_finding_invalid_status(self, h3270):
        """update_finding rejects invalid status values."""
        h3270.emit_finding('HIGH', 'ABEND', 'bad status', dedup_key='bad1')
        fid = h3270.all_findings()[0][0]
        ok = h3270.update_finding(fid, status='INVALID')
        assert ok is False

    def test_update_finding_remediation(self, h3270):
        """update_finding stores remediation text."""
        h3270.emit_finding('HIGH', 'ABEND', 'remed test', dedup_key='rem1')
        fid = h3270.all_findings()[0][0]
        h3270.update_finding(fid, remediation='Fix the COBOL program')
        row = h3270.get_finding(fid)
        assert row[8] == 'Fix the COBOL program'

    def test_finding_classes_dict(self, h3270):
        """FINDING_CLASSES has all 6 sources with description and remediation."""
        from libGr0gu3270 import FINDING_CLASSES
        expected = ['ABEND', 'SCREEN_MAP', 'AID_SCAN', 'SPOOL', 'FUZZER', 'SECURITY_AUDIT']
        for src in expected:
            assert src in FINDING_CLASSES, '{} missing from FINDING_CLASSES'.format(src)
            assert 'description' in FINDING_CLASSES[src]
            assert 'remediation' in FINDING_CLASSES[src]

    def test_abend_severity_mapping(self, h3270):
        """ABEND_SEVERITY maps known codes correctly."""
        from libGr0gu3270 import ABEND_SEVERITY
        assert ABEND_SEVERITY.get('ASRA') == 'CRIT'
        assert ABEND_SEVERITY.get('AEY7') == 'HIGH'
        assert ABEND_SEVERITY.get('APCT') == 'INFO'
        assert ABEND_SEVERITY.get('XXXX', 'MEDIUM') == 'MEDIUM'
