"""
Unit tests for hack3270 core library (PR1-PR4).
No network, no GUI — tests pure logic only.

Run: python3 -m pytest tests/ -v
"""
import pytest
from libhack3270 import hack3270, e2a


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


class TestScanAnalyze:
    def test_structure(self, h3270):
        """scan_analyze returns dict with all expected keys."""
        data = ascii_to_ebcdic("ENTER TRANSACTION CODE")
        # Wrap in valid 3270 stream: EW + WCC
        stream = bytes([0xF5, 0xC0]) + data
        result = h3270.scan_analyze(stream, 'TEST', 42.5)
        assert result['txn_code'] == 'TEST'
        assert result['status'] == 'ACCESSIBLE'
        assert isinstance(result['abends'], list)
        assert isinstance(result['field_analysis'], dict)
        assert isinstance(result['pf_keys'], list)
        assert isinstance(result['esm'], dict)
        assert result['duration_ms'] == 42.5
        assert result['response_len'] == len(stream)


class TestScanDB:
    def test_write_read_scan_result(self, h3270):
        """Write + read scan result round-trip."""
        import json
        report = {
            'txn_code': 'CEMT',
            'timestamp': 1234567890.0,
            'status': 'ACCESSIBLE',
            'abends': [],
            'field_analysis': {'total': 2, 'input': 1, 'protected': 1, 'hidden': 0, 'numeric': 0, 'hidden_fields': []},
            'pf_keys': ['PF3', 'PF7'],
            'esm': {'esm': 'UNKNOWN', 'evidence': []},
            'response_len': 100,
            'duration_ms': 25.5,
            'response_preview': 'CEMT INQUIRY',
        }
        row_id = h3270.write_scan_result(report)
        assert row_id is not None
        results = h3270.all_scan_results()
        assert len(results) == 1
        assert results[0][2] == 'CEMT'
        assert results[0][3] == 'ACCESSIBLE'
        assert results[0][7] == 'UNKNOWN'
        # Verify JSON fields
        stored_report = json.loads(results[0][11])
        assert stored_report['txn_code'] == 'CEMT'


# ---- SPOOL/RCE Detection ----

class TestSpoolConstants:
    def test_spool_status_codes_exist(self):
        """AUDIT_STATUS includes SPOOL_OPEN and SPOOL_CLOSED."""
        from libhack3270 import AUDIT_STATUS
        assert 'SPOOL_OPEN' in AUDIT_STATUS
        assert 'SPOOL_CLOSED' in AUDIT_STATUS

    def test_spool_patterns_exist(self):
        """SPOOL_SUCCESS_PATTERNS and SPOOL_FAIL_PATTERNS are defined."""
        from libhack3270 import SPOOL_SUCCESS_PATTERNS, SPOOL_FAIL_PATTERNS
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
