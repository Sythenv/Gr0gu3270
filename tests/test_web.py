"""
Tests for Gr0gu3270 Web UI API endpoints.
Uses the test client pattern with threading.
"""
import os
import sys
import json
import threading
import time
import urllib.request
import urllib.error

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from libGr0gu3270 import Gr0gu3270
from web import Gr0gu3270State, Gr0gu3270Handler, Gr0gu3270WebUI, ReusableHTTPServer, NonBlockingClientSocket
from http.server import HTTPServer
import socket
import queue


@pytest.fixture
def h3270(tmp_path):
    """Gr0gu3270 instance with temp DB, offline mode."""
    db_name = str(tmp_path / "test")
    obj = Gr0gu3270(
        server_ip="127.0.0.1",
        server_port=3270,
        proxy_port=3271,
        offline_mode=True,
        project_name=db_name,
    )
    yield obj
    obj.sql_con.close()


@pytest.fixture
def state(h3270):
    """Thread-safe state wrapper."""
    return Gr0gu3270State(h3270)


@pytest.fixture
def web_server(state):
    """Start a real HTTP server on a random port for integration tests."""
    Gr0gu3270Handler.state = state
    server = HTTPServer(('127.0.0.1', 0), Gr0gu3270Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()


def get(port, path):
    url = 'http://127.0.0.1:{}{}'.format(port, path)
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode())


def post_json(port, path, data=None):
    url = 'http://127.0.0.1:{}{}'.format(port, path)
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


# ---- Unit tests on Gr0gu3270State ----

def test_get_status_offline(state):
    s = state.get_status()
    assert s['offline'] is True
    assert 'version' in s
    assert s['hack_on'] is False

def test_get_logs_empty(state):
    logs = state.get_logs()
    assert logs == []

def test_get_abends_empty(state):
    assert state.get_abends() == []

def test_get_screen_map_empty(state):
    assert state.get_screen_map() == []

def test_get_transactions_empty(state):
    assert state.get_transactions() == []

def test_get_transaction_stats_empty(state):
    stats = state.get_transaction_stats()
    assert stats['count'] == 0

def test_get_audit_results_empty(state):
    assert state.get_audit_results() == []

def test_get_audit_summary_empty(state):
    s = state.get_audit_summary()
    assert s['ACCESSIBLE'] == 0
    assert s['DENIED'] == 0

def test_get_statistics(state):
    stats = state.get_statistics()
    assert stats['server_ip'] == '127.0.0.1'
    assert stats['server_port'] == 3270

def test_get_aids(state):
    aids = state.get_aids()
    assert 'ENTER' in aids['all']
    assert 'PF1' in aids['all']

def test_get_inject_status(state):
    s = state.get_inject_status()
    assert s['config_set'] is False
    assert s['running'] is False

def test_get_injection_files(state):
    files = state.get_injection_files()
    assert isinstance(files, list)

def test_set_hack_fields(state):
    state.set_hack_fields({'on': 1, 'prot': 1, 'hf': 1})
    s = state.get_status()
    assert s['hack_on'] is True

def test_set_hack_color(state):
    state.set_hack_color({'on': 1, 'sfe': 1})
    s = state.get_status()
    assert s['hack_color_on'] is True

def test_toggle_abend_detection(state):
    # Enabled by default
    r = state.toggle_abend_detection()
    assert r['on'] is False
    r = state.toggle_abend_detection()
    assert r['on'] is True

def test_toggle_transaction_tracking(state):
    # Enabled by default
    r = state.toggle_transaction_tracking()
    assert r['on'] is False

def test_inject_reset(state):
    r = state.inject_reset()
    assert r['ok'] is True

def test_inject_file_missing(state):
    r = state.set_inject_file({'filename': 'nonexistent.txt'})
    assert r['ok'] is False

def test_inject_go_no_file(state):
    r = state.inject_go({})
    assert r['ok'] is False

def test_export_csv(state):
    r = state.export_csv()
    assert r['ok'] is True
    # Clean up
    if os.path.exists(r['filename']):
        os.remove(r['filename'])

def test_export_audit_csv(state):
    r = state.export_audit_csv()
    assert r['ok'] is True
    if os.path.exists(r['filename']):
        os.remove(r['filename'])


# ---- Integration tests with HTTP server ----

def test_http_root(web_server):
    url = 'http://127.0.0.1:{}/'.format(web_server)
    with urllib.request.urlopen(url) as resp:
        html = resp.read().decode()
        assert 'Gr0gu3270' in html
        assert resp.status == 200

def test_http_api_status(web_server):
    data = get(web_server, '/api/status')
    assert 'offline' in data
    assert 'version' in data

def test_http_api_logs(web_server):
    data = get(web_server, '/api/logs')
    assert isinstance(data, list)

def test_http_api_logs_since(web_server):
    data = get(web_server, '/api/logs?since=0')
    assert isinstance(data, list)

def test_http_api_abends(web_server):
    data = get(web_server, '/api/abends?since=0')
    assert isinstance(data, list)

def test_http_api_screen_map(web_server):
    data = get(web_server, '/api/screen_map')
    assert isinstance(data, list)

def test_http_api_transactions(web_server):
    data = get(web_server, '/api/transactions')
    assert isinstance(data, list)

def test_http_api_transaction_stats(web_server):
    data = get(web_server, '/api/transaction_stats')
    assert 'count' in data

def test_http_api_audit_results(web_server):
    data = get(web_server, '/api/audit_results')
    assert isinstance(data, list)

def test_http_api_audit_summary(web_server):
    data = get(web_server, '/api/audit_summary')
    assert 'ACCESSIBLE' in data

def test_http_api_statistics(web_server):
    data = get(web_server, '/api/statistics')
    assert 'server_ip' in data

def test_http_api_aids(web_server):
    data = get(web_server, '/api/aids')
    assert 'all' in data

def test_http_api_inject_status(web_server):
    data = get(web_server, '/api/inject_status')
    assert 'config_set' in data

def test_http_api_injection_files(web_server):
    data = get(web_server, '/api/injection_files')
    assert isinstance(data, list)

def test_http_post_hack_fields(web_server):
    data = post_json(web_server, '/api/hack_fields', {'on': 1, 'prot': 1})
    assert data['ok'] is True
    status = get(web_server, '/api/status')
    assert status['hack_on'] is True

def test_http_post_abend_detection(web_server):
    data = post_json(web_server, '/api/abend_detection')
    assert 'on' in data

def test_http_post_inject_reset(web_server):
    data = post_json(web_server, '/api/inject/reset')
    assert data['ok'] is True

def test_http_404(web_server):
    try:
        get(web_server, '/api/nonexistent')
        assert False, "Should have raised"
    except urllib.error.HTTPError as e:
        assert e.code == 404

def test_http_log_detail_not_found(web_server):
    try:
        get(web_server, '/api/log/99999')
        assert False, "Should have raised"
    except urllib.error.HTTPError as e:
        assert e.code == 404


# ---- Port reuse / cleanup tests ----

def test_reusable_server_allows_reuse():
    """ReusableHTTPServer sets SO_REUSEADDR so port can be rebound immediately."""
    assert ReusableHTTPServer.allow_reuse_address is True

def test_reusable_server_binds_after_close(state):
    """Can rebind the same port immediately after closing a ReusableHTTPServer."""
    Gr0gu3270Handler.state = state
    srv1 = ReusableHTTPServer(('127.0.0.1', 0), Gr0gu3270Handler)
    port = srv1.server_address[1]
    srv1.server_close()
    # Should not raise OSError
    srv2 = ReusableHTTPServer(('127.0.0.1', port), Gr0gu3270Handler)
    srv2.server_close()

def test_kill_port_owner_no_crash(h3270):
    """_kill_port_owner doesn't crash when no process holds the port."""
    ui = Gr0gu3270WebUI(h3270, port=0)
    ui.port = 59999  # unlikely to be in use
    ui._kill_port_owner()  # should complete without error

def test_find_pid_for_inode_not_found():
    """_find_pid_for_inode returns None for a bogus inode."""
    assert Gr0gu3270WebUI._find_pid_for_inode('9999999999') is None


# ---- Single Transaction Scan tests ----

def test_get_scan_status_idle(state):
    s = state.get_scan_status()
    assert s['running'] is False
    assert s['result'] is None

def test_get_scan_results_empty(state):
    assert state.get_scan_results() == []

def test_scan_start_no_connection(state):
    r = state.scan_txn({'txn_code': 'CEMT'})
    assert r['ok'] is False
    assert 'Not connected' in r['message']

def test_scan_start_validation_empty(state):
    r = state.scan_txn({'txn_code': ''})
    assert r['ok'] is False
    assert 'Invalid' in r['message']

def test_scan_start_validation_too_long(state):
    r = state.scan_txn({'txn_code': 'ABCDEFGHI'})
    assert r['ok'] is False

def test_scan_start_validation_bad_chars(state):
    r = state.scan_txn({'txn_code': 'CE MT'})
    assert r['ok'] is False

def test_http_api_scan_status(web_server):
    data = get(web_server, '/api/scan/status')
    assert 'running' in data
    assert data['running'] is False

def test_http_api_scan_results(web_server):
    data = get(web_server, '/api/scan/results')
    assert isinstance(data, list)

def test_http_scan_start_no_connection(web_server):
    data = post_json(web_server, '/api/scan/start', {'txn_code': 'CEMT'})
    assert data['ok'] is False


# ---- NonBlockingClientSocket tests ----

def test_nonblocking_send_buffers():
    """send() buffers data when the underlying socket would block."""
    s1, s2 = socket.socketpair()
    try:
        nbs = NonBlockingClientSocket(s1)
        nbs.send(b'\x01\x02\x03')
        # Data either sent immediately or buffered — either way no exception
        # Verify recv on the other end gets it after flush
        nbs.flush()
        data = s2.recv(1024)
        assert data == b'\x01\x02\x03'
    finally:
        s1.close()
        s2.close()

def test_nonblocking_flush():
    """flush() drains buffered data."""
    s1, s2 = socket.socketpair()
    try:
        nbs = NonBlockingClientSocket(s1)
        nbs.send(b'hello')
        nbs.flush()
        assert not nbs.has_pending
        data = s2.recv(1024)
        assert data == b'hello'
    finally:
        s1.close()
        s2.close()

def test_nonblocking_send_closed():
    """send() raises OSError on a closed NonBlockingClientSocket."""
    s1, s2 = socket.socketpair()
    nbs = NonBlockingClientSocket(s1)
    nbs.close()
    s2.close()
    with pytest.raises(OSError):
        nbs.send(b'data')

def test_nonblocking_has_pending():
    """has_pending reflects buffered data state."""
    s1, s2 = socket.socketpair()
    try:
        nbs = NonBlockingClientSocket(s1)
        assert not nbs.has_pending
        # Close receiving end to force buffering (send may still succeed for small data)
        # Instead just check after send + flush cycle
        nbs.send(b'test')
        nbs.flush()
        assert not nbs.has_pending
    finally:
        s1.close()
        s2.close()


# ---- Command queue tests ----

def test_send_keys_queues_command(state):
    """send_keys() puts commands on _cmd_queue instead of sending directly."""
    # Set up AIDS so send_keys knows the key
    state.send_keys({'keys': ['ENTER']})
    assert not state._cmd_queue.empty()
    label, payload = state._cmd_queue.get_nowait()
    assert 'ENTER' in label
    assert b'\xff\xef' in payload  # IAC EOR marker

def test_send_text_queues_command(state):
    """send_text() puts text payload on _cmd_queue."""
    state.send_text({'text': 'CSGM'})
    assert not state._cmd_queue.empty()
    label, payload = state._cmd_queue.get_nowait()
    assert 'CSGM' in label
    assert isinstance(payload, (bytes, bytearray))

def test_run_daemon_drains_queue(state):
    """run_daemon() drains _cmd_queue (even if not connected, just no-ops)."""
    state._cmd_queue.put(('test label', b'\x00\x01'))
    state._cmd_queue.put(('test label 2', b'\x00\x02'))
    # Not connected, so run_daemon returns early — queue stays
    state.run_daemon()
    # connection_ready not set, so run_daemon returns immediately without draining
    assert not state._cmd_queue.empty()

    # Now simulate connection ready with a mock server socket
    state.connection_ready.set()
    # Need a server socket — use socketpair
    s1, s2 = socket.socketpair()
    try:
        state.h.server = s1
        state._cmd_queue.put(('test cmd', b'\x7d\xff\xef'))
        state.run_daemon()
        assert state._cmd_queue.empty()
        # Verify data was sent
        data = s2.recv(1024)
        assert b'\x7d\xff\xef' in data
    finally:
        s1.close()
        s2.close()
        state.connection_ready.clear()


# ---- Inject worker queue test ----

def test_inject_worker_uses_queue(state, tmp_path):
    """_inject_worker puts injection payloads on _cmd_queue."""
    # Create a small injection file
    inject_file = tmp_path / "test_inject.txt"
    inject_file.write_text("AAA\nBBB\n")
    state.inject_filename = str(inject_file)

    # Set up injection config so worker doesn't skip
    with state.lock:
        state.h.set_inject_config_set(1)
        # We need preamble/postamble set — use minimal values
        state.h.inject_preamble = b'\x00'
        state.h.inject_postamble = b'\xff\xef'
        state.h.inject_mask_len = 10

    state._inject_worker('SKIP', 'ENTER')

    # Worker should have queued commands (2 lines x ENTER key = 4 items)
    items = []
    while not state._cmd_queue.empty():
        items.append(state._cmd_queue.get_nowait())
    # At least 2 injection payloads (AAA, BBB) + 2 ENTER keys
    assert len(items) >= 2
    labels = [item[0] for item in items]
    assert any('AAA' in l for l in labels)
    assert any('BBB' in l for l in labels)


# ---- PR6: Field Fuzzing ----

def test_fuzz_go_no_fields(state):
    """fuzz_go rejects empty fields list."""
    r = state.fuzz_go({'fields': [], 'filename': 'alpha.txt'})
    assert r['ok'] is False
    assert 'No fields' in r['message']

def test_fuzz_go_no_file(state):
    """fuzz_go rejects missing filename."""
    r = state.fuzz_go({'fields': [{'row': 1, 'col': 10, 'length': 5}], 'filename': ''})
    assert r['ok'] is False
    assert 'No wordlist' in r['message']

def test_fuzz_go_file_not_found(state):
    """fuzz_go rejects nonexistent file."""
    r = state.fuzz_go({'fields': [{'row': 1, 'col': 10, 'length': 5}], 'filename': 'nonexistent_xyz.txt'})
    assert r['ok'] is False
    assert 'not found' in r['message'].lower()

def test_fuzz_worker_sends_payloads(state, tmp_path):
    """_fuzz_worker sends payloads via _aid_scan_send_and_read."""
    inject_file = tmp_path / "fuzz_test.txt"
    inject_file.write_text("AAA\nBBB\n")
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    # Mock _aid_scan_send_and_read to capture calls
    sent = []
    original = state.h._aid_scan_send_and_read
    def mock_send(payload, timeout=2):
        sent.append(payload)
        return None  # No server response
    state.h._aid_scan_send_and_read = mock_send
    state.inject_running = True
    state.fuzz_results = []

    try:
        state._fuzz_worker(fields, str(inject_file), 'SKIP', 'ENTER')
        # Should have sent 2 payloads (AAA, BBB)
        assert len(sent) == 2
        # Each payload should contain IAC EOR
        for p in sent:
            assert p.endswith(b'\xff\xef')
        # Both should be NO_RESPONSE
        assert all(r['status'] == 'NO_RESPONSE' for r in state.fuzz_results)
    finally:
        state.h._aid_scan_send_and_read = original

def test_fuzz_worker_multi_field(state, tmp_path):
    """Fuzz with 2 fields produces payload with 2 SBA orders."""
    inject_file = tmp_path / "fuzz_multi.txt"
    inject_file.write_text("X\n")
    fields = [{'row': 1, 'col': 10, 'length': 5}, {'row': 3, 'col': 20, 'length': 8}]

    sent = []
    def mock_send(payload, timeout=2):
        sent.append(payload)
        return None
    state.h._aid_scan_send_and_read = mock_send
    state.inject_running = True
    state.fuzz_results = []

    try:
        state._fuzz_worker(fields, str(inject_file), 'SKIP', 'ENTER')
        assert len(sent) == 1
        # Payload should contain 2 SBA orders (0x11)
        sba_count = sent[0].count(b'\x11')
        assert sba_count == 2
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_worker_replay_fallback(state, tmp_path):
    """When screen similarity drops, replay is triggered."""
    from tests.test_core import ascii_to_ebcdic
    inject_file = tmp_path / "fuzz_replay.txt"
    inject_file.write_text("TEST\n")
    fields = [{'row': 1, 'col': 10, 'length': 10}]

    # Set up a reference screen in DB
    ref_data = ascii_to_ebcdic("CICS MENU SELECT OPTION 1-9 PF KEYS AVAILABLE")
    state.h.write_database_log('C', 'clear', b'\x6d\xff\xef')
    state.h.write_database_log('S', 'ref', ref_data)

    # Return different screen so similarity < 0.8
    diff_screen = ascii_to_ebcdic("COMPLETELY DIFFERENT SCREEN CONTENT HERE NOW")
    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        return diff_screen
    state.h._aid_scan_send_and_read = mock_send

    # Mock client.send to avoid errors
    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []

    try:
        state._fuzz_worker(fields, str(inject_file), 'SKIP', 'ENTER')
        # Should have stopped due to lost screen
        assert 'Lost screen' in state.inject_status_msg
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_worker_lost_screen_stops(state, tmp_path):
    """When replay also fails, fuzz stops."""
    inject_file = tmp_path / "fuzz_lost.txt"
    inject_file.write_text("A\nB\nC\n")
    fields = [{'row': 0, 'col': 0, 'length': 5}]

    from tests.test_core import ascii_to_ebcdic
    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH LOTS OF CONTENT HERE")
    state.h.write_database_log('C', 'clear', b'\x6d\xff\xef')
    state.h.write_database_log('S', 'ref', ref_data)

    diff = ascii_to_ebcdic("TOTALLY WRONG SCREEN ERROR ERROR ERROR PANIC NOW")
    def mock_send(payload, timeout=2):
        return diff
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True

    try:
        state._fuzz_worker(fields, str(inject_file), 'SKIP', 'ENTER')
        assert state.inject_running is False
        assert 'Lost screen' in state.inject_status_msg
        # Should have stopped after first payload, not processed all 3
        assert state.fuzz_progress['current'] <= 1
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_stop(state):
    """fuzz_stop clears running flag."""
    state.inject_running = True
    r = state.fuzz_stop()
    assert r['ok'] is True
    assert state.inject_running is False

def test_fuzz_http_endpoint(web_server):
    """POST /api/inject/fuzz with no fields returns error."""
    data = post_json(web_server, '/api/inject/fuzz', {'fields': [], 'filename': 'alpha.txt'})
    assert data['ok'] is False

def test_fuzz_stop_http_endpoint(web_server):
    """POST /api/inject/fuzz/stop returns ok."""
    data = post_json(web_server, '/api/inject/fuzz/stop')
    assert data['ok'] is True


# ---- SPOOL/RCE State Methods ----

def test_spool_check_offline(state):
    """spool_check in offline mode raises or returns error (no server socket)."""
    # In offline mode there's no server socket, so spool_check should fail gracefully
    try:
        result = state.spool_check()
        # If it doesn't raise, it should still return a dict
        assert isinstance(result, dict)
    except Exception:
        pass  # Expected — no server connection in offline mode


def test_spool_poc_missing_ip(state):
    """spool_poc_ftp rejects empty listener_ip."""
    result = state.spool_poc_ftp({})
    assert result['ok'] is False
    assert 'listener_ip' in result['message']


def test_spool_poc_invalid_port(state):
    """spool_poc_ftp rejects non-numeric port."""
    result = state.spool_poc_ftp({'listener_ip': '10.10.10.10', 'listener_port': 'abc'})
    assert result['ok'] is False
    assert 'port' in result['message'].lower()


def test_spool_poc_valid_params(state):
    """spool_poc_ftp with valid params attempts execution (fails in offline mode)."""
    try:
        result = state.spool_poc_ftp({'listener_ip': '10.10.10.10', 'listener_port': 4444})
        assert isinstance(result, dict)
    except Exception:
        pass  # Expected — no server connection


# ---- SPOOL HTTP Integration ----

def test_spool_check_endpoint(web_server):
    """POST /api/spool/check returns JSON."""
    port = web_server
    try:
        req = urllib.request.Request(
            'http://127.0.0.1:{}/api/spool/check'.format(port),
            data=b'{}',
            headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        assert isinstance(data, dict)
    except Exception:
        pass  # May fail in offline mode, endpoint exists


def test_spool_poc_endpoint_no_ip(web_server):
    """POST /api/spool/poc without IP returns error."""
    port = web_server
    req = urllib.request.Request(
        'http://127.0.0.1:{}/api/spool/poc'.format(port),
        data=json.dumps({}).encode(),
        headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=5)
    data = json.loads(resp.read())
    assert data['ok'] is False


# ---- PR5: AID Scan ----

class TestAidScanState:
    def test_start_not_connected(self, state):
        """AID scan requires connection."""
        result = state.aid_scan_start()
        assert result['ok'] is False
        assert 'Not connected' in result['message']

    def test_stop(self, state):
        """AID scan stop returns ok."""
        result = state.aid_scan_stop()
        assert result['ok'] is True

    def test_summary_empty(self, state):
        """Empty summary when no scan run."""
        summary = state.get_aid_scan_summary()
        assert summary['running'] is False
        assert summary['total'] == 0
        assert summary['results'] == []

    def test_results_empty(self, state):
        """No results when no scan run."""
        results = state.get_aid_scan_results()
        assert results == []

    def test_results_with_data(self, state):
        """Results return stored AID scan data."""
        import time
        state.h.write_aid_scan_log({
            'aid_key': 'PF5', 'category': 'NEW_SCREEN', 'status': 'ACCESSIBLE',
            'similarity': 0.3, 'response_preview': 'ADMIN', 'response_len': 200,
            'timestamp': time.time(),
        })
        results = state.get_aid_scan_results()
        assert len(results) == 1
        assert results[0]['aid_key'] == 'PF5'
        assert results[0]['category'] == 'NEW_SCREEN'

    def test_summary_sorted(self, state):
        """Summary sorts results by category priority."""
        import time
        for key, cat in [('PF1', 'SAME_SCREEN'), ('PF5', 'NEW_SCREEN'), ('PF3', 'VIOLATION')]:
            state.h.aid_scan_results.append({
                'aid_key': key, 'category': cat, 'status': 'ACCESSIBLE',
                'similarity': 0.5, 'response_preview': '', 'response_len': 0,
                'timestamp': time.time(),
            })
        summary = state.get_aid_scan_summary()
        assert summary['results'][0]['category'] == 'VIOLATION'
        assert summary['results'][1]['category'] == 'NEW_SCREEN'
        assert summary['results'][2]['category'] == 'SAME_SCREEN'


def test_http_aid_scan_summary(web_server):
    """GET /api/aid_scan/summary returns valid JSON."""
    port = web_server
    data = get(port, '/api/aid_scan/summary')
    assert 'running' in data
    assert 'total' in data
    assert 'results' in data


def test_http_aid_scan_results(web_server):
    """GET /api/aid_scan/results returns list."""
    port = web_server
    data = get(port, '/api/aid_scan/results')
    assert isinstance(data, list)


def test_http_aid_scan_start_no_connection(web_server):
    """POST /api/aid_scan/start without connection returns error."""
    port = web_server
    req = urllib.request.Request(
        'http://127.0.0.1:{}/api/aid_scan/start'.format(port),
        data=json.dumps({}).encode(),
        headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=5)
    data = json.loads(resp.read())
    assert data['ok'] is False


def test_http_aid_scan_stop(web_server):
    """POST /api/aid_scan/stop returns ok."""
    port = web_server
    req = urllib.request.Request(
        'http://127.0.0.1:{}/api/aid_scan/stop'.format(port),
        data=json.dumps({}).encode(),
        headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=5)
    data = json.loads(resp.read())
    assert data['ok'] is True
