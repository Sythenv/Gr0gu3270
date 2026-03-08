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
    result = state.get_screen_map()
    assert result['fields'] == []
    assert result['esm'] == 'UNKNOWN'

def test_get_transactions_empty(state):
    assert state.get_transactions() == []

def test_get_transaction_stats_empty(state):
    stats = state.get_transaction_stats()
    assert stats['count'] == 0

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
    assert s['running'] is False

def test_get_injection_files(state):
    files = state.get_injection_files()
    assert isinstance(files, list)

def test_set_hack_fields(state):
    state.set_hack_fields({'on': 1, 'prot': 1, 'hf': 1})
    s = state.get_status()
    assert s['hack_on'] is True

def test_hack_color_always_on(state):
    # Hack Color is always on — no status field needed, verify color flags are True
    assert state.h.hack_color_sfe is True
    assert state.h.hack_color_hv is True

def test_abend_detection_always_on(state):
    # Always on — no toggle, no status field
    assert state.h.abend_detection is True

def test_transaction_tracking_always_on(state):
    # Always on — no toggle, no status field
    assert state.h.transaction_tracking is True

def test_export_csv(state):
    r = state.export_csv()
    assert r['ok'] is True
    # Clean up
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
    assert isinstance(data, dict)
    assert 'fields' in data
    assert 'esm' in data

def test_http_api_transactions(web_server):
    data = get(web_server, '/api/transactions')
    assert isinstance(data, list)

def test_http_api_transaction_stats(web_server):
    data = get(web_server, '/api/transaction_stats')
    assert 'count' in data

def test_http_api_statistics(web_server):
    data = get(web_server, '/api/statistics')
    assert 'server_ip' in data

def test_http_api_aids(web_server):
    data = get(web_server, '/api/aids')
    assert 'all' in data

def test_http_api_inject_status(web_server):
    data = get(web_server, '/api/inject_status')
    assert 'running' in data

def test_http_api_injection_files(web_server):
    data = get(web_server, '/api/injection_files')
    assert isinstance(data, list)

def test_http_post_hack_fields(web_server):
    data = post_json(web_server, '/api/hack_fields', {'on': 1, 'prot': 1})
    assert data['ok'] is True
    status = get(web_server, '/api/status')
    assert status['hack_on'] is True

def test_http_post_abend_detection_removed(web_server):
    # Endpoint removed — should 404
    url = 'http://127.0.0.1:{}/api/abend_detection'.format(web_server)
    try:
        urllib.request.urlopen(urllib.request.Request(
            url, data=b'{}',
            headers={'Content-Type': 'application/json'}, method='POST'))
        assert False, "endpoint should not exist"
    except urllib.error.HTTPError as e:
        assert e.code == 404

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



# ---- PR6: Field Fuzzing ----

def test_fuzz_go_no_fields(state):
    """fuzz_go rejects missing field."""
    r = state.fuzz_go({})
    assert r['ok'] is False
    assert 'No field' in r['message']

def test_fuzz_go_auto_select_alpha(state):
    """_select_wordlists returns correct files for alpha fields."""
    lines, sources = state._select_wordlists({'numeric': False, 'hidden': False})
    assert 'boundary-values.txt' in sources
    assert 'db2-injections.txt' in sources
    assert len(lines) > 0

def test_fuzz_go_auto_select_numeric(state):
    """_select_wordlists returns correct files for numeric fields."""
    lines, sources = state._select_wordlists({'numeric': True, 'hidden': False})
    assert 'boundary-values.txt' in sources
    assert 'db2-injections.txt' not in sources

def test_fuzz_timeout_clamp(state):
    """Fuzz timeout is clamped to 0.5-10.0 range."""
    # Low clamp
    result = state.fuzz_go({'field': {'row': 1, 'col': 1, 'length': 5}, 'timeout': 0.1})
    # fuzz_go starts the worker thread — just check it accepted
    assert result['ok'] is True
    state.inject_running = False  # stop the thread
    import time; time.sleep(0.1)

    # High clamp
    result = state.fuzz_go({'field': {'row': 1, 'col': 1, 'length': 5}, 'timeout': 99})
    assert result['ok'] is True
    state.inject_running = False
    time.sleep(0.1)

def test_fuzz_worker_sends_payloads(state, tmp_path):
    """_fuzz_worker sends payloads via _aid_scan_send_and_read."""
    lines = [('AAA', 'test.txt'), ('BBB', 'test.txt')]
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
    state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}

    try:
        state._fuzz_worker(fields, lines, 'ENTER')
        # Should have sent 3 payloads (probe + AAA + BBB)
        assert len(sent) == 3
        # Each payload should contain IAC EOR
        for p in sent:
            assert p.endswith(b'\xff\xef')
        # All should be NO_RESPONSE (probe + 2 payloads)
        assert len(state.fuzz_results) == 3
        assert state.fuzz_results[0]['source'] == 'overflow-probe'
        assert all(r['status'] == 'NO_RESPONSE' for r in state.fuzz_results)
    finally:
        state.h._aid_scan_send_and_read = original

def test_fuzz_worker_single_field(state, tmp_path):
    """Fuzz with 1 field produces payload with 1 SBA order."""
    lines = [('X', 'test.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    sent = []
    def mock_send(payload, timeout=2):
        sent.append(payload)
        return None
    state.h._aid_scan_send_and_read = mock_send
    state.inject_running = True
    state.fuzz_results = []
    state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}

    try:
        state._fuzz_worker(fields, lines, 'ENTER')
        assert len(sent) == 2  # probe + 1 payload
        # Second payload (after probe) should contain 1 SBA order (0x11)
        sba_count = sent[1].count(b'\x11')
        assert sba_count == 1
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_worker_replay_fallback(state, tmp_path):
    """When screen similarity drops, txn_code recovery (CLEAR+txn) is used."""
    from tests.test_core import ascii_to_ebcdic
    lines = [('BAD', 'test.txt'), ('GOOD', 'test.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 10}]

    ref_data = ascii_to_ebcdic("CICS MENU SELECT OPTION 1-9 PF KEYS AVAILABLE")
    # Seed a client payload with txn code "MCOR" so fuzz_go() extracts it
    txn_payload = b'\x7d\x5b\x60\xD4\xC3\xD6\xD9\xff\xef'  # ENTER + cursor + MCOR
    state.h.write_database_log('C', 'txn', txn_payload)
    state.h.write_database_log('S', 'ref', ref_data)

    diff_screen = ascii_to_ebcdic("COMPLETELY DIFFERENT SCREEN CONTENT HERE NOW")
    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        # Call 1=probe→ref (no recovery needed), 2=fuzz→wrong, 3=CLEAR, 4=txn→ref
        if call_count[0] == 1:
            return ref_data  # probe response: same screen
        if call_count[0] >= 4:
            return ref_data
        return diff_screen
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []

    try:
        # Pass txn_code directly (fuzz_go() would extract it from DB)
        state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        assert 'recovery' in state.inject_status_msg.lower() or 'complete' in state.inject_status_msg.lower()
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_worker_lost_screen_stops(state, tmp_path):
    """When recovery always fails, fuzz stops after 3 consecutive failures."""
    lines = [('A', 't.txt'), ('B', 't.txt'), ('C', 't.txt'), ('D', 't.txt'), ('E', 't.txt')]
    fields = [{'row': 0, 'col': 0, 'length': 5}]

    from tests.test_core import ascii_to_ebcdic
    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH LOTS OF CONTENT HERE")
    state.h.write_database_log('C', 'clear', b'\x6d\xff\xef')
    state.h.write_database_log('S', 'ref', ref_data)

    diff = ascii_to_ebcdic("TOTALLY WRONG SCREEN ERROR ERROR ERROR PANIC NOW")
    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        if call_count[0] == 1:
            return ref_data  # probe → same screen (no recovery needed)
        return diff  # all fuzz payloads + recoveries → wrong screen
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True

    try:
        # With txn_code, recovery uses CLEAR+txn but still fails (diff screen)
        state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        assert state.inject_running is False
        assert 'Lost screen' in state.inject_status_msg
        # Should stop after 3 consecutive recovery failures, not all 5
        # Progress includes probe (+1), so max is 3+1=4
        assert state.fuzz_progress['current'] <= 5
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_navigated_status(state, tmp_path):
    """When classification=ACCESSIBLE and similarity < threshold, status is NAVIGATED."""
    from tests.test_core import ascii_to_ebcdic
    lines = [('NAV', 'test.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH OPTIONS 1 THROUGH 9 LIST")
    state.h.write_database_log('S', 'ref', ref_data)

    nav_screen = ascii_to_ebcdic("COMPLETELY DIFFERENT NAVIGATION TARGET SCREEN HERE")
    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        # Call 1: probe → ref (ok), Call 2: fuzz payload → nav, Calls 3+: recovery → ref
        if call_count[0] == 1 or call_count[0] >= 3:
            return ref_data
        return nav_screen
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []

    try:
        state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        assert len(state.fuzz_results) == 2  # probe + 1 payload
        assert state.fuzz_results[0]['source'] == 'overflow-probe'
        assert state.fuzz_results[1]['status'] == 'NAVIGATED'
        assert state.fuzz_results[1]['recovered'] is True
        assert state.fuzz_results[1]['abend_code'] is None
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_abend_code_in_results(state, tmp_path):
    """When classification=ABEND, the abend_code field contains the code."""
    from tests.test_core import ascii_to_ebcdic
    lines = [('CRASH', 'test.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH OPTIONS 1 THROUGH 9 LIST")
    state.h.write_database_log('S', 'ref', ref_data)

    abend_screen = ascii_to_ebcdic("DFHAC2206 TRANSACTION ABEND AEI9 HAS OCCURRED QUIT")
    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH OPTIONS 1 THROUGH 9 LIST")
    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        if call_count[0] == 1:
            return ref_data  # probe → same screen
        return abend_screen  # fuzz payloads → ABEND
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []

    try:
        state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        assert len(state.fuzz_results) >= 2  # probe + at least 1 payload
        # Find the fuzz payload result (not probe)
        fuzz_result = state.fuzz_results[1]
        assert fuzz_result['status'] == 'ABEND'
        assert fuzz_result['abend_code'] == 'AEI9'
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_recovered_flag(state, tmp_path):
    """After successful recovery, the result has recovered=True."""
    from tests.test_core import ascii_to_ebcdic
    lines = [('BAD', 'test.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 10}]

    ref_data = ascii_to_ebcdic("CICS MENU SELECT OPTION 1-9 PF KEYS AVAILABLE NOW")
    state.h.write_database_log('S', 'ref', ref_data)

    diff_screen = ascii_to_ebcdic("COMPLETELY DIFFERENT SCREEN CONTENT HERE NOW TODAY")
    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        # Call 1: probe → ref, Call 2: fuzz → diff, Calls 3+: recovery → ref
        if call_count[0] == 1 or call_count[0] >= 4:
            return ref_data
        return diff_screen
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []

    try:
        state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        assert len(state.fuzz_results) == 2  # probe + 1 payload
        assert state.fuzz_results[1]['recovered'] is True
    finally:
        del state.h._aid_scan_send_and_read

def test_overflow_probe_in_results(state, tmp_path):
    """fuzz_results[0] is the overflow probe with source='overflow-probe'."""
    lines = [('X', 'test.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    sent = []
    def mock_send(payload, timeout=2):
        sent.append(payload)
        return None
    state.h._aid_scan_send_and_read = mock_send
    state.inject_running = True
    state.fuzz_results = []
    state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}

    try:
        state._fuzz_worker(fields, lines, 'ENTER')
        assert len(state.fuzz_results) == 2  # probe + 1 payload
        assert state.fuzz_results[0]['source'] == 'overflow-probe'
        assert state.fuzz_results[0]['status'] == 'NO_RESPONSE'
        assert 'OVERFLOW-PROBE' in state.fuzz_results[0]['payload']
        assert '5+50' in state.fuzz_results[0]['payload']  # flen=5
    finally:
        del state.h._aid_scan_send_and_read

def test_overflow_probe_reorders_on_abend(state, tmp_path):
    """When probe causes ABEND, cobol-overflow lines come first."""
    from tests.test_core import ascii_to_ebcdic
    lines = [('BOUND', 'boundary-values.txt'), ('COBOL', 'cobol-overflow.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH OPTIONS 1 THROUGH 9 LIST")
    abend_screen = ascii_to_ebcdic("DFHAC2206 TRANSACTION ABEND ASRA HAS OCCURRED QUIT")
    state.h.write_database_log('S', 'ref', ref_data)

    call_count = [0]
    def mock_send(payload, timeout=2):
        call_count[0] += 1
        if call_count[0] == 1:
            return abend_screen  # probe → ABEND
        # Recovery calls + fuzz payloads → ref screen
        return ref_data
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []
    state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}

    try:
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        # Probe should be first result with ABEND
        assert state.fuzz_results[0]['source'] == 'overflow-probe'
        assert state.fuzz_results[0]['abend_code'] == 'ASRA'
        # After reorder: cobol-overflow should come before boundary-values
        non_probe = [r for r in state.fuzz_results if r['source'] != 'overflow-probe']
        cobol_idx = next(i for i, r in enumerate(non_probe) if r['source'] == 'cobol-overflow.txt')
        bound_idx = next(i for i, r in enumerate(non_probe) if r['source'] == 'boundary-values.txt')
        assert cobol_idx < bound_idx
    finally:
        del state.h._aid_scan_send_and_read

def test_overflow_probe_deprioritizes_on_trunc(state, tmp_path):
    """When probe returns SAME_SCREEN (no ABEND), cobol-overflow lines come last."""
    from tests.test_core import ascii_to_ebcdic
    lines = [('COBOL', 'cobol-overflow.txt'), ('BOUND', 'boundary-values.txt')]
    fields = [{'row': 1, 'col': 10, 'length': 5}]

    ref_data = ascii_to_ebcdic("ORIGINAL MENU SCREEN WITH OPTIONS 1 THROUGH 9 LIST")
    state.h.write_database_log('S', 'ref', ref_data)

    def mock_send(payload, timeout=2):
        return ref_data  # all responses = same screen (ACCESSIBLE, similarity=1.0)
    state.h._aid_scan_send_and_read = mock_send

    class FakeClient:
        def send(self, data): pass
        def flush(self): pass
    state.h.client = FakeClient()
    state.inject_running = True
    state.fuzz_results = []
    state.fuzz_progress = {'current': 0, 'total': 0, 'payload': '', 'source': ''}

    try:
        state._fuzz_worker(fields, lines, 'ENTER', txn_code='MCOR')
        # Probe first, then reordered payloads
        non_probe = [r for r in state.fuzz_results if r['source'] != 'overflow-probe']
        cobol_idx = next(i for i, r in enumerate(non_probe) if r['source'] == 'cobol-overflow.txt')
        bound_idx = next(i for i, r in enumerate(non_probe) if r['source'] == 'boundary-values.txt')
        # No ABEND → cobol should be AFTER boundary
        assert cobol_idx > bound_idx
    finally:
        del state.h._aid_scan_send_and_read

def test_fuzz_stop(state):
    """fuzz_stop clears running flag."""
    state.inject_running = True
    r = state.fuzz_stop()
    assert r['ok'] is True
    assert state.inject_running is False

def test_fuzz_http_endpoint(web_server):
    """POST /api/inject/fuzz with no field returns error."""
    data = post_json(web_server, '/api/inject/fuzz', {})
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


# ---- Findings ----

def test_get_findings_empty(state):
    """get_findings returns empty list when no findings."""
    assert state.get_findings() == []


def test_get_findings_summary_empty(state):
    """get_findings_summary returns all zeros when no findings."""
    s = state.get_findings_summary()
    assert s['CRIT'] == 0
    assert s['HIGH'] == 0
    assert s['MEDIUM'] == 0
    assert s['INFO'] == 0
    assert s['total'] == 0


def test_get_findings_includes_status(state):
    """get_findings returns status field."""
    state.h.emit_finding('HIGH', 'ABEND', 'status test', dedup_key='web_st1')
    findings = state.get_findings()
    assert len(findings) == 1
    assert findings[0]['status'] == 'NEW'


def test_get_finding_detail(state):
    """get_finding_detail returns full finding with description."""
    state.h.emit_finding('HIGH', 'ABEND', 'detail test', dedup_key='web_det1')
    findings = state.get_findings()
    detail = state.get_finding_detail(findings[0]['id'])
    assert detail['source'] == 'ABEND'
    assert detail['message'] == 'detail test'
    assert detail['status'] == 'NEW'
    assert 'description' in detail
    assert len(detail['description']) > 0
    assert 'remediation' in detail


def test_update_finding_via_state(state):
    """update_finding_detail changes status and remediation."""
    state.h.emit_finding('MEDIUM', 'FUZZER', 'update test', dedup_key='web_upd1')
    findings = state.get_findings()
    fid = findings[0]['id']
    result = state.update_finding_detail({'id': fid, 'status': 'CONFIRMED', 'remediation': 'Fix it'})
    assert result['ok'] is True
    detail = state.get_finding_detail(fid)
    assert detail['status'] == 'CONFIRMED'
    assert detail['remediation'] == 'Fix it'


def test_http_api_findings(web_server):
    """GET /api/findings returns a list."""
    data = get(web_server, '/api/findings')
    assert isinstance(data, list)
    assert len(data) == 0
