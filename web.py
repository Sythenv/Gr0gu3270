"""
Gr0gu3270 Web UI
~~~~~~~~~~~~~~~
Web-based interface for Gr0gu3270 using stdlib http.server.
Replaces Tkinter GUI for WSL/remote usage.
Accessible at http://localhost:8080
"""

import json
import threading
import signal
import sys
import time
import select
import logging
import datetime
import re
import os
import queue
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# ---- Debug trace (no sensitive data) ----
_DTRACE = os.environ.get('GR0GU_DEBUG')
_dtrace_fh = None

def _dt(msg):
    """Append a timestamped line to the debug trace file."""
    global _dtrace_fh
    if not _DTRACE:
        return
    if _dtrace_fh is None:
        _dtrace_fh = open(_DTRACE, 'a', buffering=1)
    _dtrace_fh.write('{} {}\n'.format(
        datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3], msg))


class ReusableHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
from urllib.parse import urlparse, parse_qs

import libGr0gu3270


class NonBlockingClientSocket:
    """Wraps a client socket so send() never blocks.

    Sends are attempted immediately in non-blocking mode.
    If the kernel buffer is full, data is queued internally.
    Call flush() periodically (from the daemon loop) to drain the buffer.
    recv() and fileno() are delegated directly to the underlying socket.
    """

    def __init__(self, sock):
        self._sock = sock
        self._buf = bytearray()
        self._sock.setblocking(False)
        self._closed = False

    # --- send path (non-blocking + buffered) ---

    def send(self, data):
        if self._closed:
            raise OSError("socket closed")
        self._buf.extend(data)
        self._flush_once()
        return len(data)

    def sendall(self, data):
        return self.send(data)

    def flush(self):
        """Try to send all buffered data. Safe to call from daemon loop."""
        while self._buf and not self._closed:
            if not self._flush_once():
                break

    def _flush_once(self):
        """Attempt a single non-blocking send. Returns True if progress made."""
        if not self._buf:
            return False
        try:
            n = self._sock.send(bytes(self._buf[:8192]))
            if n > 0:
                del self._buf[:n]
                return True
            return False
        except BlockingIOError:
            return False
        except OSError:
            self._closed = True
            return False

    @property
    def has_pending(self):
        return len(self._buf) > 0

    # --- recv path (non-blocking, but only called after select) ---

    def recv(self, bufsize):
        return self._sock.recv(bufsize)

    # --- delegation ---

    def fileno(self):
        return self._sock.fileno()

    def getpeername(self):
        return self._sock.getpeername()

    def close(self):
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass

    def setsockopt(self, *args):
        self._sock.setsockopt(*args)

    def settimeout(self, t):
        pass  # We manage blocking ourselves

# ---- Thread-safe wrapper around Gr0gu3270 ----

class Gr0gu3270State:
    """Thread-safe wrapper around the Gr0gu3270 object."""

    def __init__(self, Gr0gu3270):
        self.h = Gr0gu3270
        self.lock = threading.Lock()
        self.last_log_id = 0
        self.last_abend_id = 0
        self.last_txn_id = 0
        self.inject_running = False
        self.inject_status_msg = "Not Ready."
        self.inject_thread = None
        self.shutdown_flag = threading.Event()
        self.connection_ready = threading.Event()
        _dt('STATE_INIT')
        self.aid_scan_thread = None
        self.last_aid_scan_id = 0
        # Command queue: HTTP threads queue (label, payload) tuples,
        # daemon thread sends them to the server socket.
        self._cmd_queue = queue.Queue()
        self.fuzz_progress = {'current': 0, 'total': 0, 'payload': ''}
        self.fuzz_results = []
        self.macro_running = False
        self.macro_thread = None
        self.macro_progress = {'current': 0, 'total': 0, 'step': ''}
        self.macro_error = None

    def get_status(self):
        with self.lock:
            return {
                'connected': self.connection_ready.is_set(),
                'offline': self.h.is_offline(),
                'hack_on': bool(self.h.hack_on),
                'aid_scan_running': bool(self.h.aid_scan_running),
                'version': libGr0gu3270.__version__,
                'project_name': self.h.project_name,
            }

    def get_logs(self, since=0):
        with self.lock:
            rows = self.h.all_logs(since)
            result = []
            for row in rows:
                result.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(row[1]))),
                    'direction': self.h.expand_CS(row[2]),
                    'data_len': row[4],
                    'notes': row[3],
                })
            return result

    def get_log_detail(self, record_id):
        with self.lock:
            rows = self.h.get_log(record_id)
            if not rows:
                return None
            row = rows[0]
            ebcdic_data = self.h.get_ascii(row[5])
            if re.search("^tn3270 ", row[3]):
                parsed = self.h.parse_telnet(ebcdic_data)
            else:
                parsed = self.h.parse_3270(ebcdic_data)
            return {
                'id': row[0],
                'timestamp': row[1],
                'direction': self.h.expand_CS(row[2]),
                'notes': row[3],
                'data_len': row[4],
                'parsed': parsed,
            }

    def get_abends(self, since=0):
        with self.lock:
            rows = self.h.all_abends(since)
            result = []
            for row in rows:
                result.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(row[1]))),
                    'type': row[2],
                    'code': row[3],
                    'description': row[4],
                })
            return result

    def get_screen_map(self):
        with self.lock:
            fields = self.h.get_screen_map()
            result = []
            for f in fields:
                content = f.get('content', '').replace('\n', ' ')
                result.append({
                    'row': f['row'],
                    'col': f['col'],
                    'type': f['type'],
                    'protected': f['protected'],
                    'hidden': f['hidden'],
                    'numeric': f['numeric'],
                    'length': f['length'],
                    'content': content,
                    'bms': f.get('bms', False),
                })
            esm = 'UNKNOWN'
            if self.h.last_server_data:
                esm_info = self.h.fingerprint_esm(self.h.last_server_data)
                esm = esm_info.get('esm', 'UNKNOWN')
            return {'fields': result, 'esm': esm}

    def get_transactions(self, since=0):
        with self.lock:
            rows = self.h.all_transactions(since)
            result = []
            for row in rows:
                result.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(row[1]))),
                    'txn_code': row[3],
                    'duration_ms': row[4],
                    'response_len': row[5],
                    'status': row[6],
                })
            return result

    def get_transaction_stats(self):
        with self.lock:
            return self.h.get_transaction_stats()

    def get_statistics(self):
        with self.lock:
            ip, port = self.h.get_ip_port()
            tls = self.h.get_tls()
            total_connections = 0
            total_time = 0.0
            last_timestamp = 0.0
            start_timestamp = 0.0
            total_injections = 0
            total_hacks = 0
            server_messages = 0
            server_bytes = 0
            client_messages = 0
            client_bytes = 0

            for record in self.h.all_logs():
                curr_timestamp = float(record[1])
                if record[2] == 'C':
                    client_messages += 1
                    client_bytes += record[4]
                else:
                    server_messages += 1
                    server_bytes += record[4]
                if record[2] == 'C' and "Send" in record[3]:
                    total_injections += 1
                if record[2] == 'S' and "ENABLED" in record[3]:
                    total_hacks += 1
                if record[2] == 'S' and record[4] == 3:
                    total_connections += 1
                    start_timestamp = curr_timestamp
                    if last_timestamp > 0:
                        total_time += start_timestamp - last_timestamp
                else:
                    last_timestamp = curr_timestamp
            if start_timestamp > 0 and last_timestamp > 0:
                total_time += start_timestamp - last_timestamp

            return {
                'server_ip': ip,
                'server_port': port,
                'tls_enabled': bool(tls),
                'total_connections': total_connections,
                'server_messages': server_messages,
                'client_messages': client_messages,
                'server_bytes': server_bytes,
                'client_bytes': client_bytes,
                'total_hacks': total_hacks,
                'total_injections': total_injections,
                'total_time': total_time,
            }

    def get_aids(self):
        with self.lock:
            found = self.h.current_aids()
            all_aids = list(self.h.AIDS.keys())
            return {'all': all_aids, 'found': found}

    def get_inject_status(self):
        with self.lock:
            return {
                'running': self.inject_running,
                'message': self.inject_status_msg,
                'progress': self.fuzz_progress,
            }

    def get_injection_files(self):
        with self.lock:
            return self.h.list_injection_files()

    # ---- POST actions ----

    def set_hack_fields(self, data):
        with self.lock:
            if 'prot' in data: self.h.set_hack_prot(int(data['prot']))
            if 'hf' in data: self.h.set_hack_hf(int(data['hf']))
            if 'rnr' in data: self.h.set_hack_rnr(int(data['rnr']))
            if 'sf' in data: self.h.set_hack_sf(int(data['sf']))
            if 'sfe' in data: self.h.set_hack_sfe(int(data['sfe']))
            if 'mf' in data: self.h.set_hack_mf(int(data['mf']))
            if 'ei' in data: self.h.set_hack_ei(int(data['ei']))
            if 'hv' in data: self.h.set_hack_hv(int(data['hv']))
            if 'on' in data:
                self.h.set_hack_on(int(data['on']))
                self.h.set_hack_toggled()

    def _select_wordlists(self, field):
        """Auto-select wordlists based on field attributes."""
        inj_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'injections')
        is_hidden = field.get('hidden', False)
        is_numeric = field.get('numeric', False)
        is_short = field.get('length', 0) <= 8

        if is_short:
            if is_numeric:
                order = ['short-numeric.txt', 'short-alpha.txt']
            else:
                order = ['short-alpha.txt', 'short-numeric.txt']
        elif is_hidden:
            order = ['hidden-tampering.txt', 'boundary-values.txt', 'cobol-overflow.txt']
        elif is_numeric:
            order = ['boundary-values.txt', 'cobol-overflow.txt']
        else:
            order = ['boundary-values.txt', 'cobol-overflow.txt', 'db2-injections.txt']

        lines = []
        sources = []
        for fname in order:
            fpath = os.path.join(inj_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, 'r') as f:
                    file_lines = [l.rstrip() for l in f if l.strip() and not l.startswith('#')]
                for l in file_lines:
                    lines.append((l, fname))
                sources.append(fname)
        return lines, sources

    def fuzz_go(self, data):
        if self.inject_running:
            return {'ok': False, 'message': 'Injection already running.'}

        field = data.get('field')
        if not field:
            return {'ok': False, 'message': 'No field specified.'}

        lines, sources = self._select_wordlists(field)
        if not lines:
            return {'ok': False, 'message': 'No wordlist files found.'}

        key_mode = data.get('key', 'ENTER')
        timeout = max(0.5, min(float(data.get('timeout', 1)), 10.0))
        delay = float(data.get('delay', 0.1))

        # Load replay macro if specified
        replay_macro = None
        macro_file = data.get('macro', '')
        if macro_file:
            macro_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'macros', macro_file)
            if not os.path.isfile(macro_path):
                return {'ok': False, 'message': 'Replay macro not found: {}'.format(macro_file)}
            with self.lock:
                steps, err = self.h.parse_macro(macro_path)
            if err:
                return {'ok': False, 'message': 'Replay macro error: {}'.format(err)}
            replay_macro = steps

        # Capture txn code from last client payload for simplified recovery
        txn_code = None
        try:
            self.h.sql_cur.execute(
                "SELECT RAW_DATA FROM Logs WHERE C_S='C' ORDER BY ID DESC LIMIT 1")
            row = self.h.sql_cur.fetchone()
            if row:
                txn_code = self.h.detect_transaction_code(bytes(row[0]))
        except Exception:
            pass

        self.inject_running = True
        self.fuzz_progress = {'current': 0, 'total': len(lines) + 1, 'payload': '', 'source': ''}
        self.fuzz_results = []
        macro_label = ' + macro {}'.format(macro_file) if macro_file else ''
        self.inject_status_msg = 'Fuzz starting ({} payloads + 1 probe from {}{})...'.format(
            len(lines), ', '.join(sources), macro_label)
        self.inject_thread = threading.Thread(
            target=self._fuzz_worker,
            args=([field], lines, key_mode, timeout, delay, txn_code, replay_macro),
            daemon=True)
        self.inject_thread.start()
        return {'ok': True, 'message': 'Fuzz started: {} payloads + 1 probe from {}{}'.format(
            len(lines), ', '.join(sources), macro_label)}

    def _fuzz_replay_macro(self, steps, is_tn3270e, timeout):
        """Replay a macro sequence (CLEAR + all steps). Returns last server response."""
        # CLEAR first to reset state
        clear_p = self.h.build_clear_payload(is_tn3270e)
        self.h._aid_scan_send_and_read(clear_p, timeout=timeout)
        last_resp = None
        pending_fields = []
        for step in steps:
            action = step['action']
            if action == 'WAIT':
                wait_text = step.get('text', '')
                wait_timeout = step.get('timeout', 10)
                deadline = time.time() + wait_timeout
                while time.time() < deadline and self.inject_running:
                    with self.lock:
                        ref = self.h.extract_ref_screen()
                    if ref:
                        screen_text = self.h.get_ascii(ref)
                        if wait_text.lower() in screen_text.lower():
                            break
                    time.sleep(0.3)
            elif action == 'FIELD':
                row = int(step['row']) if step.get('row') is not None else None
                col = int(step['col']) if step.get('col') is not None else None
                pending_fields.append((step['text'], row, col))
            else:
                if pending_fields:
                    pending_fields = self._resolve_field_positions(pending_fields)
                with self.lock:
                    payload = self.h.build_macro_step_payload(step, is_tn3270e, pending_fields)
                pending_fields = []
                if not payload:
                    continue
                last_resp = self.h._aid_scan_send_and_read(payload, timeout=timeout)
                if last_resp:
                    try:
                        self.h.client.send(last_resp)
                        self.h.client.flush()
                    except Exception:
                        pass
                time.sleep(0.3)
        return last_resp

    def _fuzz_recover(self, replay_macro, txn_code, replay_path, is_tn3270e, timeout):
        """Try to recover the target screen. Macro > txn_code > replay_path."""
        if replay_macro:
            last_resp = self._fuzz_replay_macro(replay_macro, is_tn3270e, timeout)
            if last_resp:
                return last_resp
        if txn_code:
            clear_p = self.h.build_clear_payload(is_tn3270e)
            txn_p = self.h.build_txn_payload(txn_code, is_tn3270e)
            self.h._aid_scan_send_and_read(clear_p, timeout=timeout)
            last_resp = self.h._aid_scan_send_and_read(txn_p, timeout=timeout)
            if last_resp:
                try:
                    self.h.client.send(last_resp)
                    self.h.client.flush()
                except Exception:
                    pass
                return last_resp
        # Fallback: replay path from logs
        with self.lock:
            self.h.aid_scan_replay_path = replay_path
            return self.h.aid_scan_replay()

    def _fuzz_worker(self, fields, lines_with_source, key_mode, timeout=1, delay=0.1, txn_code=None, replay_macro=None):
        _dt('FUZZ_WORKER_START payloads={} macro={} txn={}'.format(
            len(lines_with_source), bool(replay_macro), txn_code))
        try:
            self.fuzz_progress['total'] = len(lines_with_source)

            with self.lock:
                ref_screen = self.h.extract_ref_screen()
                replay_path = self.h.extract_replay_path()
                is_tn3270e = self.h.check_inject_3270e()

            aid_byte = 0x7d  # ENTER
            aid_name = key_mode.split('+')[0] if '+' in key_mode else key_mode
            if aid_name in self.h.AIDS:
                aid_byte = self.h.AIDS[aid_name][0]

            sim_threshold = 0.8
            recovery_count = 0
            consecutive_fails = 0

            # --- Overflow probe: send one non-truncated payload ---
            flen = fields[0].get('length', 0)
            probe_len = (flen + 50) if flen > 0 else 50
            probe_text = 'A' * probe_len
            field_loc = 'R{},C{}'.format(fields[0]['row'], fields[0]['col'])
            field_label = fields[0].get('label', '')

            probe_fields = [(probe_text, fields[0]['row'], fields[0]['col'])]
            with self.lock:
                probe_payload = self.h.build_multi_field_payload(
                    probe_fields, is_tn3270e, aid=aid_byte)
                self.h.write_database_log('C', 'Fuzz: OVERFLOW-PROBE', probe_payload)

            self.inject_status_msg = "Sending probe: OVERFLOW-PROBE ({} chars)".format(probe_len)
            self.fuzz_progress['current'] = 1
            self.fuzz_progress['payload'] = 'OVERFLOW-PROBE'
            self.fuzz_progress['source'] = 'overflow-probe'

            _dt('FUZZ_PROBE_SEND field={} len={}'.format(field_loc, probe_len))
            probe_data = self.h._aid_scan_send_and_read(probe_payload, timeout=timeout)
            _dt('FUZZ_PROBE_RECV bytes={}'.format(len(probe_data) if probe_data else 0))
            probe_status = 'NO_RESPONSE'
            probe_abend = None
            probe_similarity = -1
            probe_diff = []

            if probe_data:
                with self.lock:
                    self.h.write_database_log('S', 'Fuzz resp: OVERFLOW-PROBE', probe_data)
                    probe_class = self.h.classify_response(probe_data)
                    probe_similarity = self.h.screen_similarity(probe_data, ref_screen) if ref_screen else -1
                    probe_diff = self.h.screen_diff(ref_screen, probe_data) if ref_screen else []
                    if probe_class == 'ABEND':
                        abends = self.h.detect_abend(probe_data)
                        if abends:
                            probe_abend = abends[0]['code']
                if probe_class == 'ACCESSIBLE' and probe_similarity >= 0 and probe_similarity <= sim_threshold:
                    probe_status = 'NAVIGATED'
                elif probe_class == 'ACCESSIBLE':
                    probe_status = 'SAME_SCREEN'
                else:
                    probe_status = probe_class
                try:
                    self.h.client.send(probe_data)
                    self.h.client.flush()
                except Exception:
                    pass
            else:
                probe_status = 'NO_RESPONSE'

            self.fuzz_results.append({
                'payload': 'OVERFLOW-PROBE ({}+50 chars)'.format(flen),
                'source': 'overflow-probe',
                'status': probe_status,
                'abend_code': probe_abend,
                'size': len(probe_data) if probe_data else 0,
                'similarity': round(probe_similarity, 3),
                'diff': probe_diff,
                'recovered': False,
            })

            # Emit finding if probe caused ABEND
            if probe_abend:
                with self.lock:
                    constat = "Overflow probe on field '{}' {} (len={}): sent {} chars, caused ABEND {} on transaction {}.".format(
                        field_label, field_loc, flen, probe_len, probe_abend, txn_code or 'unknown')
                    self.h.emit_finding('HIGH', 'FUZZER',
                                        'Overflow probe ({}+50 chars) caused ABEND {} on field {} — buffer overflow confirmed'.format(
                                            flen, probe_abend, field_loc),
                                        txn_code=txn_code,
                                        dedup_key='FUZZER:OVERFLOW:{}:{}'.format(probe_abend, field_loc),
                                        constat=constat)

            # Recovery after probe (same pattern as main loop)
            if ref_screen and probe_data:
                sim = self.h.screen_similarity(probe_data, ref_screen)
                if sim <= sim_threshold:
                    recovered = False
                    for attempt in range(2):
                        time.sleep(0.3 * (attempt + 1))
                        last_resp = self._fuzz_recover(
                            replay_macro, txn_code, replay_path, is_tn3270e, timeout)
                        if last_resp:
                            sim2 = self.h.screen_similarity(last_resp, ref_screen)
                            if sim2 > sim_threshold:
                                recovered = True
                                recovery_count += 1
                                break
                    if not recovered:
                        self.inject_status_msg = "Lost screen after overflow probe — recovery failed."
                        self.inject_running = False
                        return
                    else:
                        self.fuzz_results[-1]['recovered'] = True

            # Reorder wordlists based on overflow signal
            overflow_signal = (probe_abend is not None)
            cobol = [(l, s) for l, s in lines_with_source if s == 'cobol-overflow.txt']
            rest = [(l, s) for l, s in lines_with_source if s != 'cobol-overflow.txt']
            if overflow_signal:
                lines_with_source = cobol + rest    # overflow → cobol first
            else:
                lines_with_source = rest + cobol    # no overflow → cobol last

            for idx, (line, source_file) in enumerate(lines_with_source):
                if self.shutdown_flag.is_set() or not self.inject_running:
                    break

                # Build field payloads — truncate per field length
                fields_with_text = []
                for field in fields:
                    flen = field.get('length', 0)
                    text = line
                    if flen > 0 and len(text) > flen:
                        text = text[:flen]
                    fields_with_text.append((text, field['row'], field['col']))

                with self.lock:
                    payload = self.h.build_multi_field_payload(
                        fields_with_text, is_tn3270e, aid=aid_byte)
                    self.h.write_database_log('C', 'Fuzz: ' + line, payload)

                self.inject_status_msg = "Sending {}/{}: {} [{}]".format(
                    idx + 2, len(lines_with_source) + 1, line, source_file)
                self.fuzz_progress['current'] = idx + 2
                self.fuzz_progress['payload'] = line
                self.fuzz_progress['source'] = source_file

                # Send payload and read response (I/O outside lock)
                server_data = self.h._aid_scan_send_and_read(payload, timeout=timeout)

                if server_data:
                    with self.lock:
                        self.h.write_database_log('S', 'Fuzz resp: ' + line, server_data)
                        classification = self.h.classify_response(server_data)
                        self.h.detect_transaction_code(payload)
                        similarity = self.h.screen_similarity(server_data, ref_screen) if ref_screen else -1
                        diff = self.h.screen_diff(ref_screen, server_data) if ref_screen else []
                        # Extract ABEND code when classification is ABEND
                        abend_code = None
                        if classification == 'ABEND':
                            abends = self.h.detect_abend(server_data)
                            if abends:
                                abend_code = abends[0]['code']
                    # Map to fuzzer-specific statuses (clearer than classify_response labels)
                    if classification == 'ACCESSIBLE' and similarity >= 0 and similarity <= sim_threshold:
                        classification = 'NAVIGATED'
                    elif classification == 'ACCESSIBLE':
                        classification = 'SAME_SCREEN'
                    try:
                        self.h.client.send(server_data)
                        self.h.client.flush()
                    except Exception:
                        pass
                    self.fuzz_results.append({
                        'payload': line,
                        'source': source_file,
                        'status': classification,
                        'abend_code': abend_code,
                        'size': len(server_data),
                        'similarity': round(similarity, 3),
                        'diff': diff,
                        'recovered': False,
                    })
                    # Emit finding for interesting fuzz results
                    field_loc = 'R{},C{}'.format(fields[0]['row'], fields[0]['col'])
                    if classification == 'ABEND':
                        with self.lock:
                            constat = 'Payload "{}" ({}) on field \'{}\' {} caused ABEND {} on transaction {}.'.format(
                                line[:60], source_file, field_label, field_loc, abend_code or '?', txn_code or 'unknown')
                            self.h.emit_finding('HIGH', 'FUZZER',
                                                'Payload "{}" ({}) caused ABEND {} on field {}'.format(
                                                    line[:60], source_file, abend_code or '?', field_loc),
                                                txn_code=txn_code,
                                                dedup_key='FUZZER:ABEND:{}:{}'.format(abend_code or '?', line[:60]),
                                                constat=constat)
                    elif classification == 'DENIED':
                        with self.lock:
                            constat = 'Payload "{}" ({}) on field \'{}\' {} denied by ESM on transaction {}.'.format(
                                line[:60], source_file, field_label, field_loc, txn_code or 'unknown')
                            self.h.emit_finding('MEDIUM', 'FUZZER',
                                                'Payload "{}" ({}) denied by ESM on field {}'.format(
                                                    line[:60], source_file, field_loc),
                                                txn_code=txn_code,
                                                dedup_key='FUZZER:DENIED:{}'.format(line[:60]),
                                                constat=constat)
                    elif classification == 'NAVIGATED':
                        with self.lock:
                            constat = 'Payload "{}" ({}) on field \'{}\' {} on transaction {} caused navigation to different screen.'.format(
                                line[:60], source_file, field_label, field_loc, txn_code or 'unknown')
                            self.h.emit_finding('MEDIUM', 'FUZZER',
                                                'Payload "{}" ({}) changed screen on field {}'.format(
                                                    line[:60], source_file, field_loc),
                                                txn_code=txn_code,
                                                dedup_key='FUZZER:NAVIGATED:{}'.format(line[:60]),
                                                constat=constat)
                else:
                    self.fuzz_results.append({
                        'payload': line,
                        'source': source_file,
                        'status': 'NO_RESPONSE',
                        'abend_code': None,
                        'size': 0,
                        'similarity': -1,
                        'diff': [],
                        'recovered': False,
                    })

                # Send follow-up keys
                followup_keys = []
                if key_mode == 'ENTER+CLEAR':
                    followup_keys = ['CLEAR']
                elif key_mode == 'ENTER+PF3':
                    followup_keys = ['PF3']
                elif key_mode == 'ENTER+PF3+CLEAR':
                    followup_keys = ['PF3', 'CLEAR']

                for fk in followup_keys:
                    with self.lock:
                        fk_payload = self.h.build_aid_payload(fk, is_tn3270e)
                    fk_response = self.h._aid_scan_send_and_read(fk_payload, timeout=timeout)
                    if fk_response:
                        try:
                            self.h.client.send(fk_response)
                            self.h.client.flush()
                        except Exception:
                            pass

                # Check if we're still on the right screen
                if ref_screen and server_data:
                    sim = self.h.screen_similarity(server_data, ref_screen)
                    if sim <= sim_threshold:
                        recovered = False
                        for attempt in range(2):
                            time.sleep(0.3 * (attempt + 1))
                            last_resp = self._fuzz_recover(
                                replay_macro, txn_code, replay_path, is_tn3270e, timeout)
                            if last_resp:
                                sim2 = self.h.screen_similarity(last_resp, ref_screen)
                                if sim2 > sim_threshold:
                                    recovered = True
                                    recovery_count += 1
                                    break
                        if not recovered:
                            consecutive_fails += 1
                            if consecutive_fails >= 3:
                                self.inject_status_msg = "Lost screen — {} consecutive recovery failures.".format(consecutive_fails)
                                break
                        else:
                            consecutive_fails = 0
                            # Mark the last result as recovered
                            if self.fuzz_results:
                                self.fuzz_results[-1]['recovered'] = True

                time.sleep(delay)

        except Exception as e:
            _dt('FUZZ_WORKER_ERR {}: {}'.format(type(e).__name__, e))
            self.inject_status_msg = "Fuzz error: {}".format(e)
        finally:
            self.inject_running = False
            if 'Lost screen' not in self.inject_status_msg and 'error' not in self.inject_status_msg.lower():
                msg = "Fuzz complete ({} payloads).".format(self.fuzz_progress['current'])
                if recovery_count > 0:
                    msg += " {} recovery(s).".format(recovery_count)
                self.inject_status_msg = msg

    def fuzz_stop(self):
        self.inject_running = False
        self.inject_status_msg = "Fuzz stopped by user."
        return {'ok': True, 'message': 'Fuzz stopped.'}

    def get_fuzz_results(self):
        results = getattr(self, 'fuzz_results', [])
        summary = {}
        for r in results:
            s = r['status']
            summary[s] = summary.get(s, 0) + 1
        return {
            'results': results,
            'summary': summary,
            'running': self.inject_running,
            'progress': getattr(self, 'fuzz_progress', {}),
        }

    # ---- Findings ----

    def get_findings(self, since=0, txn_code=None):
        with self.lock:
            rows = self.h.all_findings(since, txn_code)
            return [{'id': r[0], 'timestamp': r[1],
                     'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(r[1]))),
                     'severity': r[2], 'source': r[3],
                     'txn_code': r[4], 'message': r[5],
                     'status': r[7] if len(r) > 7 and r[7] else 'NEW',
                     'constat': r[9] if len(r) > 9 else None} for r in rows]

    def get_findings_summary(self):
        with self.lock:
            self.h.sql_cur.execute("SELECT SEVERITY, COUNT(*) FROM Findings GROUP BY SEVERITY")
            counts = {r[0]: r[1] for r in self.h.sql_cur.fetchall()}
            return {'CRIT': counts.get('CRIT', 0), 'HIGH': counts.get('HIGH', 0),
                    'MEDIUM': counts.get('MEDIUM', 0), 'INFO': counts.get('INFO', 0),
                    'total': sum(counts.values())}

    def get_finding_detail(self, finding_id):
        with self.lock:
            from libGr0gu3270 import FINDING_CLASSES
            row = self.h.get_finding(finding_id)
            if not row:
                return {'error': 'not found'}
            cls = FINDING_CLASSES.get(row[3], {})
            return {
                'id': row[0], 'timestamp': row[1],
                'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(row[1]))),
                'severity': row[2], 'source': row[3],
                'txn_code': row[4], 'message': row[5],
                'status': row[7] if len(row) > 7 and row[7] else 'NEW',
                'remediation': row[8] if len(row) > 8 and row[8] else cls.get('remediation', ''),
                'constat': row[9] if len(row) > 9 else None,
                'description': cls.get('description', ''),
            }

    def update_finding_detail(self, data):
        with self.lock:
            fid = data.get('id')
            if not fid:
                return {'ok': False, 'message': 'Missing id'}
            status = data.get('status')
            remediation = data.get('remediation')
            constat = data.get('constat')
            ok = self.h.update_finding(fid, status=status, remediation=remediation, constat=constat)
            return {'ok': ok}

    # ---- Macro Engine ----

    def macro_run(self, data):
        """Start macro execution in a daemon thread."""
        if self.macro_running:
            return {'ok': False, 'message': 'Macro already running.'}
        if not self.connection_ready.is_set():
            return {'ok': False, 'message': 'Not connected.'}
        filename = data.get('file', '')
        if not filename:
            return {'ok': False, 'message': 'No macro file specified.'}
        macro_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'macros', filename)
        if not os.path.isfile(macro_path):
            return {'ok': False, 'message': 'Macro file not found: {}'.format(filename)}
        with self.lock:
            steps, err = self.h.parse_macro(macro_path)
        if err:
            return {'ok': False, 'message': err}
        self.macro_running = True
        self.macro_error = None
        self.macro_progress = {'current': 0, 'total': len(steps), 'step': ''}
        self.macro_thread = threading.Thread(
            target=self._macro_worker, args=(steps,), daemon=True)
        self.macro_thread.start()
        return {'ok': True, 'message': 'Macro started ({} steps).'.format(len(steps))}

    def _resolve_field_positions(self, pending_fields):
        """Resolve FIELD steps without row/col from current screen map.
        Fields with (text, None, None) get assigned to input fields in tab order."""
        needs_resolve = any(r is None or c is None for _, r, c in pending_fields)
        if not needs_resolve:
            return pending_fields
        # Get input fields from screen map in tab order (row, col)
        with self.lock:
            screen_fields = [f for f in self.h.current_screen_map
                             if not f.get('protected') or f.get('hidden')]
        resolved = []
        auto_idx = 0
        for text, row, col in pending_fields:
            if row is not None and col is not None:
                resolved.append((text, row, col))
            elif auto_idx < len(screen_fields):
                sf = screen_fields[auto_idx]
                resolved.append((text, sf['row'], sf['col']))
                auto_idx += 1
                _dt('FIELD_RESOLVE idx={} -> R{},C{}'.format(auto_idx - 1, sf['row'], sf['col']))
            else:
                _dt('FIELD_RESOLVE idx={} -> no more input fields'.format(auto_idx))
                resolved.append((text, 0, 0))
        return resolved

    def _macro_worker(self, steps):
        try:
            with self.lock:
                is_tn3270e = self.h.check_inject_3270e()
            pending_fields = []
            for i, step in enumerate(steps):
                if not self.macro_running:
                    break
                action = step['action']
                self.macro_progress = {
                    'current': i + 1, 'total': len(steps),
                    'step': '{} {}'.format(action, step.get('text', step.get('key', '')))
                }
                if action == 'WAIT':
                    ok = self._macro_wait(step['text'], step.get('timeout', 10))
                    if not ok:
                        self.macro_error = 'Timeout waiting for "{}".'.format(step['text'])
                        break
                elif action == 'FIELD':
                    row = int(step['row']) if step.get('row') is not None else None
                    col = int(step['col']) if step.get('col') is not None else None
                    pending_fields.append((step['text'], row, col))
                else:
                    if pending_fields:
                        pending_fields = self._resolve_field_positions(pending_fields)
                    with self.lock:
                        payload = self.h.build_macro_step_payload(step, is_tn3270e, pending_fields)
                    pending_fields = []
                    if not payload:
                        continue
                    chunks = self._macro_send_and_drain(payload)
                    for chunk in chunks:
                        with self.lock:
                            self.h.client.send(chunk)
                            self.h.client.flush()
                            self.h.write_database_log('S', 'macro', chunk)
                    # Update internal state (screen map, ABEND, etc.) from last response
                    if chunks:
                        with self.lock:
                            self.h.last_server_data = chunks[-1]
                            self.h.parse_screen_map(chunks[-1])
                            self.h.refresh_aids(chunks[-1])
                    with self.lock:
                        self.h.write_database_log('C', 'macro', payload)
        except Exception as e:
            self.macro_error = 'Macro error: {}'.format(e)
        finally:
            self.macro_running = False

    def _macro_send_and_drain(self, payload, timeout=5, settle=0.5):
        '''Send payload and drain all server data until quiet for settle seconds.'''
        self.h.server.send(payload)
        chunks = []
        # Wait for first response (up to timeout)
        rlist, _, _ = select.select([self.h.server], [], [], timeout)
        if self.h.server not in rlist:
            return chunks
        data = self.h.server.recv(libGr0gu3270.BUFFER_MAX)
        if not data:
            return chunks
        chunks.append(data)
        # Drain: keep reading until server is quiet for settle seconds
        while True:
            rlist, _, _ = select.select([self.h.server], [], [], settle)
            if self.h.server not in rlist:
                break
            data = self.h.server.recv(libGr0gu3270.BUFFER_MAX)
            if not data:
                break
            chunks.append(data)
        return chunks

    def _macro_wait(self, text, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline and self.macro_running:
            with self.lock:
                ref = self.h.extract_ref_screen()
            if ref:
                screen_text = self.h.get_ascii(ref)
                if text.lower() in screen_text.lower():
                    return True
            time.sleep(0.3)
        return False

    def macro_stop(self):
        self.macro_running = False
        return {'ok': True, 'message': 'Macro stopped.'}

    def get_macro_status(self):
        return {
            'running': self.macro_running,
            'progress': self.macro_progress,
            'error': self.macro_error,
        }

    def get_macro_list(self):
        macro_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'macros')
        if not os.path.isdir(macro_dir):
            return {'files': []}
        files = [f for f in sorted(os.listdir(macro_dir)) if f.endswith('.json')]
        return {'files': files}

    def macro_save(self, data):
        """Save a macro to the macros/ directory."""
        name = data.get('name', '').strip()
        steps = data.get('steps', [])
        if not name:
            return {'ok': False, 'message': 'Macro name is required.'}
        if not steps:
            return {'ok': False, 'message': 'Macro must have at least one step.'}
        # Validate steps
        with self.lock:
            for i, step in enumerate(steps):
                ok, err = self.h.validate_macro_step(step)
                if not ok:
                    return {'ok': False, 'message': 'Step {}: {}'.format(i + 1, err)}
        # Sanitize filename
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '', name)
        if not safe_name:
            return {'ok': False, 'message': 'Invalid macro name.'}
        filename = safe_name + '.json'
        macro_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'macros')
        os.makedirs(macro_dir, exist_ok=True)
        macro_path = os.path.join(macro_dir, filename)
        with open(macro_path, 'w') as f:
            json.dump({'name': name, 'steps': steps}, f, indent=2)
        return {'ok': True, 'message': 'Macro saved: {}'.format(filename), 'file': filename}

    def macro_load(self, data):
        """Load a macro file for editing."""
        filename = data.get('file', '')
        if not filename:
            return {'ok': False, 'message': 'No file specified.'}
        macro_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'macros')
        macro_path = os.path.join(macro_dir, filename)
        if not os.path.isfile(macro_path):
            return {'ok': False, 'message': 'File not found.'}
        try:
            with open(macro_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return {'ok': False, 'message': str(e)}
        steps = data if isinstance(data, list) else data.get('steps', [])
        name = data.get('name', filename.replace('.json', '')) if isinstance(data, dict) else filename.replace('.json', '')
        return {'ok': True, 'name': name, 'steps': steps}

    def send_keys(self, data):
        """Queue AID keys for the daemon thread to send to the server."""
        keys = data.get('keys', [])
        with self.lock:
            is_tn3270e = self.h.check_inject_3270e()
            aids = self.h.AIDS
        for key_name in keys:
            if key_name in aids:
                byte_code = aids[key_name]
                if is_tn3270e:
                    payload = b'\x00\x00\x00\x00\x01' + byte_code + b'\xff\xef'
                else:
                    payload = byte_code + b'\xff\xef'
                self._cmd_queue.put(('Sending key: ' + key_name, payload))
        return {'ok': True, 'message': 'Keys sent.'}

    def send_text(self, data):
        """Queue text for the daemon thread to send to the server."""
        text = data.get('text', '')
        if not text:
            return {'ok': False, 'message': 'No text provided.'}
        with self.lock:
            is_tn3270e = self.h.check_inject_3270e()
            row = data.get('row')
            col = data.get('col')
            if row is not None and col is not None:
                payload = self.h.build_input_payload(text, int(row), int(col), is_tn3270e)
            else:
                payload = self.h.build_txn_payload(text, is_tn3270e)
        self._cmd_queue.put(('Send text: ' + text, payload))
        return {'ok': True, 'message': 'Text sent: ' + text}

    def spool_check(self):
        with self.lock:
            result = self.h.spool_check()
            return {'ok': True, 'result': result}

    def spool_poc_ftp(self, data):
        listener_ip = data.get('listener_ip', '')
        listener_port = data.get('listener_port', 4444)
        if not listener_ip:
            return {'ok': False, 'message': 'listener_ip is required.'}
        try:
            listener_port = int(listener_port)
        except (ValueError, TypeError):
            return {'ok': False, 'message': 'Invalid port.'}
        with self.lock:
            result = self.h.spool_poc_ftp(listener_ip, listener_port)
            return {'ok': True, 'result': result}

    def export_csv(self):
        with self.lock:
            csv_file = self.h.export_csv()
            return {'ok': True, 'filename': csv_file}

    # ---- AID Scan (PR5) ----

    def aid_scan_start(self, data=None):
        if not self.connection_ready.is_set():
            return {'ok': False, 'message': 'Not connected.'}
        if self.h.aid_scan_running:
            return {'ok': False, 'message': 'AID scan already running.'}

        # Load replay macro if specified
        replay_macro = None
        macro_file = data.get('macro', '') if data else ''
        if macro_file:
            macro_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'macros', macro_file)
            if not os.path.isfile(macro_path):
                return {'ok': False, 'message': 'Replay macro not found: {}'.format(macro_file)}
            with self.lock:
                steps, err = self.h.parse_macro(macro_path)
            if err:
                return {'ok': False, 'message': 'Replay macro error: {}'.format(err)}
            replay_macro = steps

        with self.lock:
            if data and 'timeout' in data:
                self.h.set_aid_scan_timeout(data['timeout'])
            self.h.aid_scan_start()

        self.aid_scan_replay_macro = replay_macro
        self.aid_scan_thread = threading.Thread(
            target=self._aid_scan_worker, daemon=True)
        self.aid_scan_thread.start()
        macro_label = ' + macro {}'.format(macro_file) if macro_file else ''
        return {'ok': True, 'message': 'AID scan started ({} keys{})...'.format(
            len(self.h.aid_scan_keys), macro_label)}

    def _aid_scan_worker(self):
        try:
            macro = getattr(self, 'aid_scan_replay_macro', None)
            if macro:
                # Monkey-patch replay method to use macro
                is_tn3270e = self.h.check_inject_3270e()
                original_replay = self.h.aid_scan_replay
                self.h.aid_scan_replay = lambda: self._fuzz_replay_macro(
                    macro, is_tn3270e, self.h.aid_scan_timeout)

            _dt('AID_SCAN_WORKER_START macro={}'.format(bool(macro)))
            key_count = 0
            while True:
                if self.shutdown_flag.is_set():
                    _dt('AID_SCAN_WORKER shutdown_flag')
                    break

                with self.lock:
                    running = self.h.get_aid_scan_running()
                    idx = self.h.aid_scan_index
                if not running:
                    _dt('AID_SCAN_WORKER not_running after {} keys'.format(key_count))
                    break

                # Run aid_scan_next() OUTSIDE the lock — daemon loop already
                # skips when aid_scan_running=True, and the monkey-patched
                # _fuzz_replay_macro needs to acquire the lock internally.
                _dt('AID_SCAN_NEXT key_index={}'.format(idx))
                result = self.h.aid_scan_next()
                if result is None:
                    _dt('AID_SCAN_WORKER done after {} keys'.format(key_count))
                    break
                key_count += 1
                _dt('AID_SCAN_RESULT key={} cat={} replay={}'.format(
                    result.get('aid_key'), result.get('category'), result.get('replay_ok')))

                # Pause between tests to let mainframe settle
                time.sleep(0.3)

        except Exception as e:
            _dt('AID_SCAN_WORKER_ERR {}: {}'.format(type(e).__name__, e))
            logging.getLogger(__name__).error("AID scan error: {}".format(e))
        finally:
            with self.lock:
                self.h.aid_scan_stop()
            if macro:
                self.h.aid_scan_replay = original_replay
            _dt('AID_SCAN_WORKER_STOP')

    def aid_scan_stop(self):
        with self.lock:
            self.h.aid_scan_stop()
            return {'ok': True, 'message': 'AID scan stopped.'}

    def get_aid_scan_results(self, since=0):
        with self.lock:
            rows = self.h.all_aid_scan_results(since)
            results = []
            for row in rows:
                results.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'aid_key': row[2],
                    'category': row[3],
                    'status': row[4],
                    'similarity': row[5],
                    'response_preview': row[6],
                    'response_len': row[7],
                    'replay_ok': bool(row[8]) if len(row) > 8 else True,
                })
            return results

    def get_aid_scan_summary(self):
        with self.lock:
            results = self.h.aid_scan_results
            summary = {'VIOLATION': [], 'NEW_SCREEN': [], 'SAME_SCREEN': [], 'UNMAPPED': [], 'SKIPPED': []}
            for r in results:
                cat = r.get('category', 'UNMAPPED')
                if cat in summary:
                    summary[cat].append(r)
                else:
                    summary[cat] = [r]
            return {
                'running': self.h.aid_scan_running,
                'progress': self.h.aid_scan_index,
                'total': len(self.h.aid_scan_keys),
                'summary': {k: len(v) for k, v in summary.items()},
                'results': sorted(results,
                    key=lambda r: {'VIOLATION': 0, 'NEW_SCREEN': 1, 'UNMAPPED': 2, 'SAME_SCREEN': 3, 'SKIPPED': 4}.get(r.get('category', ''), 5))
            }

    def run_daemon(self):
        """Called from daemon thread to process proxy traffic.

        Architecture:
        - Queued commands (from HTTP threads) are sent to the server OUTSIDE
          the lock so HTTP requests never block on socket I/O.
        - The client socket is wrapped in NonBlockingClientSocket so
          client.send() in handle_server() / daemon() never blocks.
        - The lock is held only during daemon() for state access.
        """
        if not self.connection_ready.is_set():
            return

        # 1. Drain the command queue → send to server (no lock needed)
        drained = 0
        while True:
            try:
                label, payload = self._cmd_queue.get_nowait()
                drained += 1
            except queue.Empty:
                break
            try:
                with self.lock:
                    self.h.write_database_log('C', label, payload)
                self.h.server.send(payload)
            except OSError as e:
                _dt('CMD_SEND_ERR type={}'.format(type(e).__name__))
        if drained:
            _dt('CMD_DRAINED count={}'.format(drained))

        # 2. Flush any pending client send buffer
        client = self.h.client
        if hasattr(client, 'flush'):
            client.flush()

        # 3. Run proxy loop (reads both sockets, processes data)
        with self.lock:
            if self.h.is_offline():
                _dt('DAEMON_SKIP reason=offline')
                return
            if self.h.aid_scan_running:
                _dt('DAEMON_SKIP reason=aid_scan')
                return
            if self.inject_running:
                _dt('DAEMON_SKIP reason=inject')
                return
            try:
                sm_before = len(self.h.current_screen_map)
                last_sd_before = len(self.h.last_server_data) if self.h.last_server_data else 0
                self.h.daemon()
                sm_after = len(self.h.current_screen_map)
                last_sd_after = len(self.h.last_server_data) if self.h.last_server_data else 0
                if last_sd_after != last_sd_before:
                    sd = self.h.last_server_data
                    hdr = ' '.join('{:02X}'.format(b) for b in sd[:8])
                    _dt('DAEMON_IO server_bytes={} screen_fields={} hdr=[{}]'.format(
                        last_sd_after, sm_after, hdr))
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                _dt('DAEMON_ERR type={}'.format(type(e).__name__))
            except Exception as e:
                _dt('DAEMON_ERR type={} msg={}'.format(type(e).__name__, e))


# ---- HTTP Handler ----

class Gr0gu3270Handler(BaseHTTPRequestHandler):
    """HTTP request handler for Gr0gu3270 Web UI."""

    state = None  # Set by Gr0gu3270WebUI

    def log_message(self, format, *args):
        # Suppress default request logging
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            return json.loads(body.decode('utf-8'))
        return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == '/':
            self._send_html(HTML_PAGE)
        elif path == '/api/status':
            self._send_json(self.state.get_status())
        elif path == '/api/logs':
            since = int(params.get('since', ['0'])[0])
            data = self.state.get_logs(since)
            if data:
                _dt('API_LOGS count={} since={}'.format(len(data), since))
            self._send_json(data)
        elif path.startswith('/api/log/'):
            try:
                record_id = int(path.split('/')[-1])
                detail = self.state.get_log_detail(record_id)
                if detail:
                    self._send_json(detail)
                else:
                    self._send_json({'error': 'not found'}, 404)
            except ValueError:
                self._send_json({'error': 'invalid id'}, 400)
        elif path == '/api/abends':
            since = int(params.get('since', ['0'])[0])
            self._send_json(self.state.get_abends(since))
        elif path == '/api/screen_map':
            data = self.state.get_screen_map()
            _dt('API_SCREEN_MAP fields={} esm={}'.format(len(data.get('fields', [])), data.get('esm', '?')))
            self._send_json(data)
        elif path == '/api/transactions':
            since = int(params.get('since', ['0'])[0])
            self._send_json(self.state.get_transactions(since))
        elif path == '/api/transaction_stats':
            self._send_json(self.state.get_transaction_stats())
        elif path == '/api/statistics':
            self._send_json(self.state.get_statistics())
        elif path == '/api/aids':
            self._send_json(self.state.get_aids())
        elif path == '/api/inject_status':
            self._send_json(self.state.get_inject_status())
        elif path == '/api/injection_files':
            self._send_json(self.state.get_injection_files())
        elif path == '/api/aid_scan/results':
            since = int(params.get('since', ['0'])[0])
            self._send_json(self.state.get_aid_scan_results(since))
        elif path == '/api/aid_scan/summary':
            self._send_json(self.state.get_aid_scan_summary())
        elif path == '/api/inject/fuzz/results':
            self._send_json(self.state.get_fuzz_results())
        elif path == '/api/macro/list':
            self._send_json(self.state.get_macro_list())
        elif path == '/api/macro/status':
            self._send_json(self.state.get_macro_status())
        elif path == '/api/findings':
            since = int(params.get('since', ['0'])[0])
            txn = params.get('txn', [None])[0]
            self._send_json(self.state.get_findings(since, txn))
        elif path == '/api/findings/summary':
            self._send_json(self.state.get_findings_summary())
        elif path.startswith('/api/findings/') and path.count('/') == 3:
            try:
                fid = int(path.split('/')[-1])
                self._send_json(self.state.get_finding_detail(fid))
            except (ValueError, IndexError):
                self._send_json({'error': 'invalid id'}, 400)
        else:
            self._send_json({'error': 'not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_body()

        if path == '/api/hack_fields':
            self.state.set_hack_fields(data)
            self._send_json({'ok': True})
        elif path == '/api/send_keys':
            result = self.state.send_keys(data)
            self._send_json(result)
        elif path == '/api/send_text':
            result = self.state.send_text(data)
            self._send_json(result)
        elif path == '/api/export_csv':
            result = self.state.export_csv()
            self._send_json(result)
        elif path == '/api/aid_scan/start':
            result = self.state.aid_scan_start(data)
            self._send_json(result)
        elif path == '/api/aid_scan/stop':
            result = self.state.aid_scan_stop()
            self._send_json(result)
        elif path == '/api/inject/fuzz':
            result = self.state.fuzz_go(data)
            self._send_json(result)
        elif path == '/api/inject/fuzz/stop':
            result = self.state.fuzz_stop()
            self._send_json(result)
        elif path == '/api/macro/run':
            result = self.state.macro_run(data)
            self._send_json(result)
        elif path == '/api/macro/stop':
            result = self.state.macro_stop()
            self._send_json(result)
        elif path == '/api/macro/save':
            result = self.state.macro_save(data)
            self._send_json(result)
        elif path == '/api/macro/load':
            result = self.state.macro_load(data)
            self._send_json(result)
        elif path == '/api/spool/check':
            result = self.state.spool_check()
            self._send_json(result)
        elif path == '/api/spool/poc':
            result = self.state.spool_poc_ftp(data)
            self._send_json(result)
        elif path == '/api/findings/update':
            result = self.state.update_finding_detail(data)
            self._send_json(result)
        else:
            self._send_json({'error': 'not found'}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


# ---- Orchestrator ----

class Gr0gu3270WebUI:
    """Main orchestrator: launches HTTP server + daemon thread."""

    def __init__(self, Gr0gu3270_obj, port=8080):
        self.Gr0gu3270 = Gr0gu3270_obj
        self.port = port
        self.state = Gr0gu3270State(Gr0gu3270_obj)
        self.logger = logging.getLogger(__name__)

    def _kill_port_owner(self):
        """Kill any orphan process holding our web port (best-effort, stdlib only)."""
        killed = False
        try:
            # Parse /proc/net/tcp to find the PID holding our port
            port_hex = '{:04X}'.format(self.port)
            with open('/proc/net/tcp', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    local = parts[1]
                    if local.endswith(':' + port_hex):
                        inode = parts[9] if len(parts) > 9 else None
                        if inode and inode != '0':
                            # Find PID owning this inode
                            pid = self._find_pid_for_inode(inode)
                            if pid and pid != os.getpid():
                                os.kill(pid, signal.SIGTERM)
                                print("Killed orphan PID {} on port {}".format(pid, self.port))
                                killed = True
        except (OSError, IOError, ValueError):
            pass
        if killed:
            time.sleep(0.5)

    @staticmethod
    def _find_pid_for_inode(inode):
        """Find PID that owns a socket inode by scanning /proc/*/fd/."""
        target = 'socket:[{}]'.format(inode)
        try:
            for entry in os.listdir('/proc'):
                if not entry.isdigit():
                    continue
                fd_dir = '/proc/{}/fd'.format(entry)
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            if os.readlink('{}/{}'.format(fd_dir, fd)) == target:
                                return int(entry)
                        except OSError:
                            continue
                except OSError:
                    continue
        except OSError:
            pass
        return None

    def start(self):
        # Set up signal handler
        signal.signal(signal.SIGINT, self._sigint_handler)

        # Kill orphan process on port before anything else
        self._kill_port_owner()

        # Start daemon thread
        daemon_thread = threading.Thread(target=self._daemon_loop, daemon=True)
        daemon_thread.start()

        # Set handler state
        Gr0gu3270Handler.state = self.state

        # Start HTTP server
        self.httpd = ReusableHTTPServer(('0.0.0.0', self.port), Gr0gu3270Handler)
        print("Web UI at http://localhost:{}".format(self.port))
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    def _daemon_loop(self):
        _dt('DAEMON_LOOP_START')
        _logged_waiting = False
        _logged_running = False
        while not self.state.shutdown_flag.is_set():
            if not self.state.connection_ready.is_set():
                if not _logged_waiting:
                    _dt('DAEMON_LOOP waiting_for_connection')
                    _logged_waiting = True
            else:
                if not _logged_running:
                    _dt('DAEMON_LOOP connection_ready, entering run_daemon')
                    _logged_running = True
            self.state.run_daemon()
            time.sleep(0.01)
        _dt('DAEMON_LOOP_STOP')

    def _sigint_handler(self, signum, frame):
        print("\nShutting down...")
        self.state.shutdown_flag.set()
        # shutdown() must be called from a DIFFERENT thread than serve_forever()
        threading.Thread(target=self.httpd.shutdown, daemon=True).start()

    def _shutdown(self):
        if getattr(self, '_shutdown_done', False):
            return
        self._shutdown_done = True
        self.state.shutdown_flag.set()
        self.Gr0gu3270.on_closing()


# ---- HTML SPA ----

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gr0gu3270</title>
<style>
:root {
  --bg: #0a0a0a;
  --text: #00969a;
  --head: #006c4d;
  --alert: #ff151f;
  --border: #004d40;
  --input-bg: #050a05;
  --dim: #004d3a;
  --glow: rgba(0,108,77,0.4);
}
* { box-sizing: border-box; margin: 0; padding: 0; scrollbar-width: thin; scrollbar-color: var(--border) var(--bg); }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--dim); }
body { font-family: 'Consolas','Monaco','Courier New',monospace; background: var(--bg); color: var(--text); font-size: 22px; display: flex; flex-direction: column; height: 100vh; overflow: hidden; text-shadow: 0 0 5px var(--glow); padding: 0 20px; align-items: center; }
.container { max-width: 1200px; width: 100%; margin: 0 auto; display: flex; flex-direction: column; flex: 1; min-height: 0; overflow: hidden; }
body::after { content:''; position:fixed; top:0; left:0; width:100%; height:100%; pointer-events:none; z-index:9998; background: repeating-linear-gradient(0deg, rgba(0,0,0,0.06) 0px, rgba(0,0,0,0.06) 1px, transparent 1px, transparent 3px); }

/* Header */
.header { background: var(--bg); padding: 0; display: flex; align-items: stretch; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.header-left { display: flex; flex-direction: column; flex: 1; min-width: 0; justify-content: flex-end; }
.header .h-title { background: var(--head); color: var(--bg); padding: 5px 10px; font-size: 22px; font-weight: bold; display: flex; flex-direction: column; align-items: center; }
.header .status { font-size: 17px; color: var(--dim); padding: 0 10px; white-space: nowrap; }
.header .status .online { color: var(--text); }
.header .status .offline { color: var(--alert); }
.header .toggles { display: flex; gap: 4px; margin-left: auto; padding-right: 4px; }
.header-bottom { display: flex; align-items: center; gap: 0; }
.header-bottom .header-toolbar { display: flex; gap: 0; }
.toggle-pill { display: flex; align-items: center; justify-content: center; width: 28px; height: 22px; font-size: 17px; font-weight: bold; cursor: pointer; border: 1px solid var(--border); background: var(--bg); color: var(--dim); transition: all 0.15s; user-select: none; }
.toggle-pill.on { background: var(--head); border-color: var(--head); color: var(--bg); }
.toggle-pill .dot-indicator { display: none; }

/* Main vertical stack */
.main { display: flex; flex-direction: column; flex: 1; min-height: 0; overflow: hidden; }

/* Collapsible panels */
.panel-screen { max-height: 25vh; flex-shrink: 0; border-bottom: 1px solid var(--border); display: flex; flex-direction: column; overflow: hidden; transition: max-height 0.2s; }
.panel-screen.collapsed { max-height: 26px; }
.panel-findings { flex:1; min-height:120px; border-bottom:1px solid var(--border); display:flex; flex-direction:column; overflow:hidden; }
.panel-findings .panel-body { overflow-y:auto; flex:1; min-height:0; }
.panel-header { display: flex; align-items: center; gap: 8px; padding: 4px 10px; background: var(--head); color: var(--bg); cursor: pointer; flex-shrink: 0; font-weight: bold; font-size: 18px; text-transform: uppercase; letter-spacing: 0.5px; text-shadow: none; }
.panel-header:hover { opacity: 0.9; }
.panel-title { color: var(--bg); font-size: 18px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
.badge { background: var(--alert); color: var(--bg); font-size: 15px; padding: 1px 6px; min-width: 16px; text-align: center; font-weight: bold; }
.badge.zero { background: var(--border); color: var(--dim); }
.panel-body { flex: 1; overflow-y: auto; min-height: 0; }

/* Findings severity badges */
.fcnt { font-size:13px; font-weight:bold; padding:1px 6px; min-width:16px; text-align:center; }
.fcnt-crit { background:#ff1521; color:#fff; }
.fcnt-high { background:#ff8c00; color:#000; }
.fcnt-med { background:#ffd700; color:#000; }
.fcnt-info { background:var(--border); color:var(--dim); }
.sev-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; vertical-align:middle; }
.sev-crit { background:#ff1521; }
.sev-high { background:#ff8c00; }
.sev-med { background:#ffd700; }
.sev-info { background:var(--dim); }
.finding-src { font-size:11px; font-weight:bold; padding:1px 4px; background:var(--border); color:var(--text); }

/* Tool footer bar */
.tool-footer { flex-shrink:0; display:flex; gap:0; border-top:1px solid var(--border); }
.tool-footer button { background:var(--bg); color:var(--dim); border:none; border-right:1px solid var(--border); padding:5px 14px; font-family:inherit; font-size:17px; font-weight:bold; text-transform:uppercase; letter-spacing:0.5px; cursor:pointer; transition:all 0.15s; }
.tool-footer button:hover { color:var(--text); }
.tool-footer button.active { background:var(--head); color:var(--bg); text-shadow:none; }
.accordion-tabs { display: flex; background: var(--bg); border-bottom: 1px solid var(--border); }
.accordion-tabs button { background: transparent; color: var(--dim); border: none; padding: 4px 10px; cursor: pointer; font-family: inherit; font-size: 15px; text-transform: uppercase; transition: all 0.15s; }
.accordion-tabs button:hover { color: var(--text); }
.accordion-tabs button.active { color: var(--bg); background: var(--head); }
.action-panel { display: none; padding: 8px 12px; background: var(--bg); max-height: 220px; overflow-y: auto; scrollbar-width: none; }
.action-panel::-webkit-scrollbar { display: none; }
.action-panel.tall { max-height: min(55vh, calc(100vh - 160px)); }
.action-panel.active { display: block; }

/* Hide old tab bar */
.action-tabs { display: none; }

/* Shared styles */
.controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; padding: 6px 8px; background: #050a05; border: 1px solid var(--border); }
.controls label { display: flex; align-items: center; gap: 4px; cursor: pointer; font-size: 17px; color: var(--text); }
.controls input[type="checkbox"] { accent-color: var(--head); }
.fuzz-diff { cursor: help; color: #f90; font-weight: bold; }
.fuzz-overlay { position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:1000;display:flex;align-items:center;justify-content:center; }
.fuzz-popup { background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:16px;width:min(700px,90vw);max-height:80vh;overflow-y:auto;font-size:15px; }
.fuzz-popup h3 { margin:0 0 8px 0;font-size:17px;color:var(--head); }
.fuzz-popup .fuzz-field-info { color:var(--dim);margin-bottom:8px; }
.fuzz-popup .fuzz-controls { display:flex;gap:8px;align-items:center;margin-bottom:8px; }
.fuzz-popup .fuzz-progress { height:4px;background:var(--border);border-radius:2px;margin-bottom:8px; }
.fuzz-popup .fuzz-progress-fill { height:100%;background:var(--head);border-radius:2px;width:0%;transition:width 0.3s; }
.fuzz-popup table { width:100%;table-layout:fixed; }
.fuzz-popup td { overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
.fuzz-popup .fuzz-summary { margin-top:4px;color:var(--dim);font-size:12px; }
.field-input:hover { background: rgba(0,150,154,0.2); }
.btn { background: var(--bg); color: var(--text); border: 1px solid var(--border); padding: 4px 12px; cursor: pointer; font-family: inherit; font-size: 17px; transition: all 0.15s; }
.btn:hover { border-color: var(--head); color: var(--head); }
.btn.on { background: var(--head); border-color: var(--head); color: var(--bg); }
.btn.danger { border-color: var(--alert); color: var(--alert); }
.btn.danger:hover { background: var(--alert); color: var(--bg); }
.section-title { font-size: 18px; color: var(--head); margin: 6px 0 4px; border-bottom: 1px solid var(--border); padding-bottom: 2px; }
table { width: 100%; border-collapse: collapse; }
table th { background: var(--head); color: var(--bg); text-align: left; padding: 4px 8px; font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; z-index: 1; cursor: pointer; user-select: none; text-shadow: none; }
table th:hover { opacity: 0.85; }
table td { padding: 3px 8px; border-bottom: 1px solid var(--border); font-size: 17px; }
table tr:hover { background: rgba(0,150,154,0.08); }
table tr.selected { background: rgba(0,150,154,0.15); }
.detail-box { background: var(--input-bg); border: 1px solid var(--border); padding: 8px; font-size: 17px; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; margin-top: 4px; }
select { background: var(--input-bg); color: var(--text); border: 1px solid var(--border); padding: 3px 6px; font-family: inherit; font-size: 17px; }
.stat-row { display: flex; gap: 8px; padding: 3px 0; font-size: 18px; }
.stat-label { color: var(--dim); min-width: 180px; }
.stat-value { color: var(--text); }
.summary-bar { display: flex; gap: 12px; flex-wrap: wrap; padding: 6px 10px; background: var(--input-bg); border: 1px solid var(--border); margin-bottom: 6px; font-size: 17px; }
.summary-bar span { display: flex; align-items: center; gap: 3px; }
.dot { width: 8px; height: 8px; display: inline-block; }
.checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 2px; }
.help-content { background: var(--input-bg); border: 1px solid var(--border); padding: 12px; white-space: pre-wrap; line-height: 1.5; font-size: 17px; }

/* Screen map: highlight hidden/protected */
.field-hidden { color: var(--alert); font-weight: bold; }
.field-input { color: var(--text); }
.field-label { color: var(--dim); }

/* Toast notifications */
.toast-container { position: fixed; top: 8px; right: 8px; z-index: 10000; display: flex; flex-direction: column; gap: 4px; pointer-events: none; }
.toast { padding: 6px 14px; font-size: 17px; font-family: inherit; pointer-events: auto; animation: toast-in 0.2s ease, toast-out 0.3s ease 2.6s forwards; max-width: 320px; border: 1px solid; }
.toast-error { background: var(--bg); border-color: var(--alert); color: var(--alert); }
.toast-success { background: var(--bg); border-color: var(--text); color: var(--text); }
.toast-info { background: var(--bg); border-color: var(--head); color: var(--head); }
.toast-warn { background: var(--bg); border-color: #ff8c00; color: #ff8c00; }
@keyframes toast-in { from { opacity: 0; transform: translateX(30px); } to { opacity: 1; transform: translateX(0); } }
@keyframes toast-out { from { opacity: 1; } to { opacity: 0; } }

/* Keyboard hint */
.kb-hint { font-size: 15px; color: var(--dim); }

/* Methodology */
.method-phases { display: flex; align-items: stretch; gap: 0; padding: 0 0 8px; flex-wrap: wrap; }
.method-phase { padding: 5px 14px; font-size: 17px; font-weight: bold; cursor: pointer; border: 1px solid var(--border); border-right: none; background: var(--bg); color: var(--dim); transition: all 0.15s; }
.method-phase:last-of-type { border-right: 1px solid var(--border); }
.method-phase:hover { color: var(--text); }
.method-phase.active { background: var(--head); color: var(--bg); border-color: var(--head); }
.method-arrow { display: none; }
.method-steps { font-size: 17px; color: var(--text); margin-bottom: 8px; padding: 8px 12px; background: var(--input-bg); border: 1px solid var(--border); }
.method-steps ol { margin: 0; padding-left: 20px; }
.method-steps li { margin: 3px 0; }
.method-cards { display: grid; grid-template-columns: 1fr; gap: 6px; margin-bottom: 8px; }
.method-card { background: var(--input-bg); border: 1px solid var(--border); padding: 8px 12px; }
.card-term { color: var(--head); font-weight: bold; font-size: 18px; margin-bottom: 2px; }
.card-explain { font-size: 17px; color: var(--text); margin-bottom: 2px; }
.card-analogy { font-size: 15px; color: var(--head); font-style: italic; margin-bottom: 2px; }
.card-action { font-size: 15px; color: var(--text); border-top: 1px solid var(--border); padding-top: 4px; margin-top: 4px; }
.method-decision { padding: 8px 12px; background: var(--input-bg); border: 1px solid var(--border); }
.node-q { color: var(--head); font-size: 17px; font-weight: bold; margin-bottom: 2px; }
.node-a { font-size: 17px; color: var(--text); padding-left: 16px; margin-bottom: 8px; }
.node-a:last-child { margin-bottom: 0; }
.abend-ref-table { margin-top: 8px; }
.abend-ref-table td { font-size: 17px; }
.abend-ref-detected { background: rgba(255,21,31,0.15); font-weight: bold; }

/* OIA Bar */
.oia-bar { flex-shrink: 0; display: flex; align-items: center; gap: 16px; padding: 3px 12px; background: var(--bg); border-top: 1px solid var(--border); font-size: 15px; color: var(--dim); }
.oia-bar .oia-conn { color: var(--text); }
.oia-bar .oia-conn.off { color: var(--alert); }
.oia-bar .oia-right { margin-left: auto; }

/* Splash screen */
#splash { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: var(--bg); z-index: 9999; display: flex; flex-direction: column; align-items: center; justify-content: center; transition: opacity 0.5s; }
#splash.hidden { opacity: 0; pointer-events: none; }
#splash .splash-title { background: var(--head); color: var(--bg); padding: 12px 24px 4px; font-size: 30px; font-weight: bold; margin-bottom: 12px; text-shadow: none; display: flex; flex-direction: column; align-items: center; }
.grogu-art { display: grid; grid-template-columns: repeat(20, var(--gs, 14px)); gap: 0; margin-bottom: 4px; }
.grogu-art .gp { width: var(--gs, 14px); height: var(--gs, 14px); }
.grogu-art .g1 { background: #22482c; } .grogu-art .g2 { background: #3c9d30; }
.grogu-art .g3 { background: #000; } .grogu-art .g4 { background: #e9a3c0; }
.grogu-art .g5 { background: #bf1864; } .grogu-art .g6 { background: #643800; }
.grogu-art .g7 { background: #fdc98d; }
#splash .grogu-art { --gs: 18px; }
.header .h-title .grogu-art { --gs: 3px; margin-bottom: 1px; }
#splash .splash-status { color: var(--text); font-size: 20px; }
@keyframes blink { 0%,49% { opacity: 1; } 50%,100% { opacity: 0; } }
#splash .splash-cursor { animation: blink 1s step-end infinite; }
</style>
</head>
<body>
<!-- SPLASH SCREEN -->
<div id="splash">
  <div class="splash-title"><div class="grogu-art" id="grogu-splash"></div>Gr0gu3270</div>
  <div class="splash-status" id="splash-status"><span class="splash-cursor">_</span> CONNECTING...</div>
</div>

<div class="toast-container" id="toast-container"></div>

<div class="container">
<!-- HEADER -->
<div class="header">
  <div class="header-left">
    <div class="header-bottom">
      <div class="h-title"><div class="grogu-art" id="grogu-header"></div>Gr0gu3270</div>
      <div class="status">
        <span id="conn-status">...</span>
        <span id="project-name" style="margin-left:6px"></span>
      </div>
      <div class="header-toolbar" id="toolbar">
        <div class="macro-bar" style="display:inline-flex;align-items:center;gap:6px;margin-right:10px">
          <select id="macro-select" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:2px 6px;font-family:inherit;font-size:15px"><option value="">-- Macro --</option></select>
          <button class="btn" id="macro-run-btn" onclick="macroRun()" style="font-size:15px;padding:2px 8px">RUN</button>
          <button class="btn danger" id="macro-stop-btn" onclick="macroStop()" style="display:none;font-size:15px;padding:2px 8px">STOP</button>
          <span id="macro-status" style="font-size:13px;color:var(--dim)"></span>
        </div>
        <button class="btn" onclick="openAidScanPopup()" style="font-size:15px;padding:2px 8px">AID SCAN</button>
      </div>
      <div class="toggles">
        <div class="toggle-pill" id="tgl-hack" onclick="toggleHackFields()" title="Hack Fields">H</div>
        <div class="toggle-pill" onclick="toggleHelpModal()" title="Method &amp; Help" style="font-weight:bold">?</div>
      </div>
    </div>
  </div>
</div>

<!-- MAIN: vertical stack -->
<div class="main">
  <!-- Screen Map (top, collapsible) -->
  <div class="panel-screen" id="panel-screen">
    <div class="panel-header" onclick="togglePanel('panel-screen')">
      <span class="panel-title">Screen Map</span>
      <span id="smap-esm" style="font-size:13px;color:var(--dim);margin-left:8px"></span>
      <button class="btn" id="smap-filter-btn" onclick="event.stopPropagation();toggleSmapFilter()" style="margin-left:auto;font-size:15px;padding:2px 8px">SHOW ALL</button>
    </div>
    <div class="panel-body">
      <table><thead><tr id="smap-thead">
        <th style="text-align:center">H</th><th style="text-align:center">N</th><th>Len</th><th>Content</th>
      </tr></thead><tbody id="smap-table"></tbody></table>
    </div>
  </div>

  <!-- Findings (always visible, top) -->
  <div class="panel-findings" id="panel-findings">
    <div class="panel-header">
      <span class="panel-title">Findings</span>
      <span class="fcnt fcnt-crit" id="cnt-crit">0</span>
      <span class="fcnt fcnt-high" id="cnt-high">0</span>
      <span class="fcnt fcnt-med" id="cnt-med">0</span>
      <span class="fcnt fcnt-info" id="cnt-info">0</span>
      <div style="margin-left:auto;display:flex;align-items:center;gap:4px">
        <span id="finding-txn-label" style="color:var(--bg);font-size:13px">ALL</span>
        <button class="btn" id="finding-filter-btn" onclick="toggleFindingFilter()" style="font-size:12px;padding:1px 6px">ALL</button>
      </div>
    </div>
    <div class="panel-body">
      <table><thead><tr>
        <th style="width:16px"></th><th>Source</th><th>TXN</th><th>Finding</th><th>Status</th>
      </tr></thead><tbody id="findings-table"></tbody></table>
    </div>
  </div>
</div>

<!-- Hidden legacy containers for buildActionPanels compat -->
<div style="display:none">
  <div id="action-tabs"></div>
  <div id="action-panels"></div>
</div>

<!-- TOOL FOOTER -->
<div class="tool-footer" id="tool-footer"></div>

<!-- OIA BAR -->
<div class="oia-bar">
  <span class="oia-conn" id="oia-conn">DISCONNECTED</span>
  <span id="oia-target"></span>
  <span>F:<b id="oia-findings">0</b> C:<b id="oia-crit">0</b> H:<b id="oia-high">0</b></span>
  <span class="oia-right" id="oia-version"></span>
</div>
</div><!-- /container -->

<script>
// ---- Grogu pixel art ----
(function(){
const D='00000001111110000000000000122222210000001112112222222211211111222133322333122211445222330223302225440441223332233322144000441122222222114400000366666666666630000003777666666777300000003766666666730000000037767667677300000000237676676732000000000376766767300000000003667667663000000000003776677300000000000003333330000000';
const C=['','g1','g2','g3','g4','g5','g6','g7'];
document.querySelectorAll('.grogu-art').forEach(g=>{
  for(let i=0;i<D.length;i++){const v=+D[i];const d=document.createElement('div');d.className='gp'+(v?' '+C[v]:'');g.appendChild(d);}
});
})();
// ---- CSS variable bridge ----
const CS = getComputedStyle(document.documentElement);
const C = {text:CS.getPropertyValue('--text').trim(), head:CS.getPropertyValue('--head').trim(), dim:CS.getPropertyValue('--dim').trim(), alert:CS.getPropertyValue('--alert').trim()};
// ---- Action tabs config ----
const ACTIONS = [
  {id:'hack-fields', label:'Hack Fields', group:0},
  {id:'inject-keys', label:'Send Keys', group:0},
  {id:'spool', label:'SPOOL/RCE', group:1},
  {id:'logs', label:'Logs', group:2, tall:true},
  {id:'statistics', label:'Stats', group:2},
];

const GROUPS = [
  {id:'grp-hacks', label:'HACKS', items:['hack-fields','inject-keys']},
  {id:'grp-system', label:'SYSTEM', items:['spool']},
  {id:'grp-data', label:'DATA', items:['logs','statistics']},
];

let activeAction = null;
let activeGroup = null;
let pollers = {};
let logSince = 0, abendSince = 0, txnSince = 0;

// ---- Findings data layer ----
let rawAbends = [];
let rawTxns = [];
let findingSince = 0;
let findingsData = [];
let findingFilterTxn = null; // null = ALL

async function loadFindings() {
  let url = '/api/findings?since=' + findingSince;
  if (findingFilterTxn) url += '&txn=' + encodeURIComponent(findingFilterTxn);
  try {
    const data = await api(url);
    if (data.length === 0) return;
    data.forEach(r => { findingSince = Math.max(findingSince, r.id); findingsData.push(r); });
    renderFindings();
    loadFindingsSummary();
  } catch(e) {}
}

function renderFindings() {
  const tbody = document.getElementById('findings-table');
  if (!tbody) return;
  tbody.innerHTML = '';
  [...findingsData].reverse().forEach(f => {
    const tr = document.createElement('tr');
    const s = f.severity.toLowerCase();
    const stColor = f.status==='CONFIRMED' ? 'var(--head)' : f.status==='FALSE_POSITIVE' ? 'var(--alert)' : 'var(--dim)';
    const stLabel = f.status==='FALSE_POSITIVE' ? 'FP' : f.status||'NEW';
    tr.innerHTML = '<td><span class="sev-dot sev-'+s+'"></span></td>'
      +'<td><span class="finding-src">'+esc(f.source)+'</span></td>'
      +'<td>'+esc(f.txn_code||'')+'</td>'
      +'<td>'+esc(f.message)+'</td>'
      +'<td style="color:'+stColor+'">'+stLabel+'</td>';
    tr.style.cursor = 'pointer';
    if (f.status==='FALSE_POSITIVE') tr.style.opacity = '0.5';
    tr.onclick = () => openFindingPopup(f.id);
    tbody.appendChild(tr);
  });
}

async function loadFindingsSummary() {
  try {
    const s = await api('/api/findings/summary');
    document.getElementById('cnt-crit').textContent = s.CRIT||0;
    document.getElementById('cnt-high').textContent = s.HIGH||0;
    document.getElementById('cnt-med').textContent = s.MEDIUM||0;
    document.getElementById('cnt-info').textContent = s.INFO||0;
    // OIA bar
    const of = document.getElementById('oia-findings'); if (of) of.textContent = s.total||0;
    const oc = document.getElementById('oia-crit'); if (oc) oc.textContent = s.CRIT||0;
    const oh = document.getElementById('oia-high'); if (oh) oh.textContent = s.HIGH||0;
  } catch(e) {}
}

function toggleFindingFilter() {
  if (findingFilterTxn) {
    findingFilterTxn = null;
  } else if (rawTxns.length > 0) {
    findingFilterTxn = rawTxns[rawTxns.length-1].txn_code;
  }
  document.getElementById('finding-filter-btn').textContent = findingFilterTxn || 'ALL';
  document.getElementById('finding-txn-label').textContent = findingFilterTxn || 'ALL';
  findingSince = 0; findingsData = [];
  loadFindings();
}

// ---- Finding Popup ----
let findingPopupId = null;

async function openFindingPopup(id) {
  const existing = document.getElementById('finding-overlay');
  if (existing) existing.remove();
  findingPopupId = id;
  const f = await api('/api/findings/' + id);
  if (f.error) { toast(f.error, 'error'); return; }
  findingStatus = f.status || 'NEW';
  const overlay = document.createElement('div');
  overlay.id = 'finding-overlay';
  overlay.className = 'fuzz-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeFindingPopup(); };
  const s = f.severity.toLowerCase();
  const statusBtns = ['NEW','CONFIRMED','FALSE_POSITIVE'].map(st => {
    const active = f.status===st;
    const colors = {NEW:'var(--dim)',CONFIRMED:'var(--head)',FALSE_POSITIVE:'var(--alert)'};
    const label = st.replace(/_/g,' ');
    return '<button class="btn" data-status="'+st+'" onclick="setFindingStatus(\''+st+'\')" style="'
      +(active?'background:'+colors[st]+';color:var(--bg);border-color:'+colors[st]:'')
      +'">'+label+'</button>';
  }).join('');
  overlay.innerHTML = `<div class="fuzz-popup" style="width:min(700px,90vw)">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
      <button class="btn" onclick="findingNav(-1)">\u25C0</button>
      <h3 style="flex:1;margin:0"><span class="sev-dot sev-${s}"></span> ${esc(f.source)} #${f.id}</h3>
      <button class="btn" onclick="findingNav(1)">\u25B6</button>
      <button class="btn" onclick="closeFindingPopup()">\u2715</button>
    </div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <span id="finding-status-btns" style="display:flex;gap:4px">${statusBtns}</span>
      <span style="color:var(--dim);font-size:13px">${esc(f.timestamp_fmt)}</span>
      ${f.txn_code ? '<span class="finding-src">'+esc(f.txn_code)+'</span>' : ''}
    </div>
    <div style="margin-bottom:12px">
      <label style="color:var(--dim);font-size:12px;display:block;margin-bottom:4px">DESCRIPTION</label>
      <div style="color:var(--text);font-size:14px;white-space:pre-wrap;background:var(--input-bg);border:1px solid var(--border);padding:8px">${esc(f.description||'No description available.')}</div>
    </div>
    <div style="margin-bottom:12px">
      <label style="color:var(--dim);font-size:12px;display:block;margin-bottom:4px">CONSTAT</label>
      <textarea id="finding-constat" rows="4" style="width:100%;box-sizing:border-box;background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:8px;font-family:inherit;font-size:14px;resize:vertical">${esc(f.constat||f.message)}</textarea>
    </div>
    <div style="margin-bottom:8px">
      <label style="color:var(--dim);font-size:12px;display:block;margin-bottom:4px">REMEDIATION</label>
      <textarea id="finding-remed" rows="4" style="width:100%;box-sizing:border-box;background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:8px;font-family:inherit;font-size:14px;resize:vertical">${esc(f.remediation||'')}</textarea>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn" onclick="saveFinding()">SAVE</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
}

function closeFindingPopup() {
  const el = document.getElementById('finding-overlay');
  if (el) el.remove();
  findingPopupId = null;
}

let findingStatus = 'NEW';

function setFindingStatus(st) {
  findingStatus = st;
  const colors = {NEW:'var(--dim)',CONFIRMED:'var(--head)',FALSE_POSITIVE:'var(--alert)'};
  document.querySelectorAll('#finding-status-btns button').forEach(btn => {
    const s = btn.dataset.status;
    if (s === st) { btn.style.background = colors[s]; btn.style.color = 'var(--bg)'; btn.style.borderColor = colors[s]; }
    else { btn.style.background = ''; btn.style.color = ''; btn.style.borderColor = ''; }
  });
}

async function saveFinding() {
  if (!findingPopupId) return;
  const status = findingStatus;
  const remediation = document.getElementById('finding-remed')?.value;
  const constat = document.getElementById('finding-constat')?.value;
  const r = await post('/api/findings/update', {id: findingPopupId, status, remediation, constat});
  if (r.ok) {
    toast('Finding updated', 'success');
    findingSince = 0; findingsData = [];
    loadFindings();
  } else {
    toast(r.message || 'Update failed', 'error');
  }
}

function findingNav(dir) {
  const idx = findingsData.findIndex(f => f.id === findingPopupId);
  if (idx < 0) return;
  const newIdx = idx + dir;
  if (newIdx < 0 || newIdx >= findingsData.length) { toast('No more findings', 'info'); return; }
  openFindingPopup(findingsData[newIdx].id);
}

// ---- Toast ----
function toast(msg, type='info') {
  const c = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ---- API ----
async function api(path) {
  try {
    const r = await fetch(path);
    if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
    return r.json();
  } catch(e) { toast('API: ' + e.message, 'error'); throw e; }
}
async function post(path, data={}) {
  try {
    const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
    return r.json();
  } catch(e) { toast('API: ' + e.message, 'error'); throw e; }
}

// ---- Build footer + popups ----
function buildActionBar() {
  // Create hidden legacy panels for buildActionPanels compat
  const legacyPanels = document.getElementById('action-panels');
  ACTIONS.forEach(a => {
    const panel = document.createElement('div');
    panel.className = 'action-panel' + (a.tall ? ' tall' : '');
    panel.id = 'apanel-' + a.id;
    legacyPanels.appendChild(panel);
  });

  // Build footer buttons
  const footer = document.getElementById('tool-footer');
  GROUPS.forEach(g => {
    const btn = document.createElement('button');
    btn.id = 'ft-' + g.id;
    btn.textContent = g.label;
    btn.onclick = () => openToolPopup(g.id);
    footer.appendChild(btn);
  });

  buildActionPanels();
}

function openToolPopup(gid) {
  closeToolPopup();
  const g = GROUPS.find(x => x.id === gid);
  if (!g) return;
  // Highlight footer button
  document.querySelectorAll('.tool-footer button').forEach(b => b.classList.remove('active'));
  document.getElementById('ft-' + gid).classList.add('active');

  const overlay = document.createElement('div');
  overlay.id = 'tool-popup-overlay';
  overlay.className = 'fuzz-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeToolPopup(); };

  // Build inner HTML: tabs (if >1 item) + panels
  let tabsHtml = '';
  if (g.items.length > 1) {
    tabsHtml = '<div class="accordion-tabs" style="margin-bottom:8px">';
    g.items.forEach((aid, i) => {
      const a = ACTIONS.find(x => x.id === aid);
      tabsHtml += '<button id="subtab-' + aid + '" class="' + (i===0?'active':'') + '" onclick="showToolInPopup(\'' + gid + '\',\'' + aid + '\')">' + a.label + '</button>';
    });
    tabsHtml += '</div>';
  }
  let panelsHtml = '';
  g.items.forEach((aid, i) => {
    const a = ACTIONS.find(x => x.id === aid);
    const src = document.getElementById('apanel-' + aid);
    const cls = (a && a.tall) ? ' tall' : '';
    panelsHtml += '<div id="acc-panel-' + aid + '" class="action-panel' + cls + (i===0?' active':'') + '">' + (src ? src.innerHTML : '') + '</div>';
  });

  overlay.innerHTML = '<div class="fuzz-popup" style="width:min(800px,90vw)">' +
    '<div style="display:flex;align-items:center;margin-bottom:8px">' +
    '<h3 style="flex:1">' + g.label + '</h3>' +
    '<button class="btn" onclick="closeToolPopup()">\u00d7</button>' +
    '</div>' +
    tabsHtml +
    panelsHtml +
    '</div>';
  document.body.appendChild(overlay);

  activeGroup = gid;
  activeAction = g.items[0];
  startActionPollers(g.items[0]);
}

function closeToolPopup() {
  stopActionPollers();
  const el = document.getElementById('tool-popup-overlay');
  if (el) el.remove();
  document.querySelectorAll('.tool-footer button').forEach(b => b.classList.remove('active'));
  activeGroup = null;
  activeAction = null;
}

function showToolInPopup(gid, aid) {
  const g = GROUPS.find(x => x.id === gid);
  if (!g) return;
  g.items.forEach(id => {
    const tb = document.getElementById('subtab-' + id);
    if (tb) tb.className = id === aid ? 'active' : '';
    const p = document.getElementById('acc-panel-' + id);
    if (p) {
      const a = ACTIONS.find(x => x.id === id);
      p.className = id === aid ? 'action-panel' + (a && a.tall ? ' tall' : '') + ' active' : 'action-panel' + (a && a.tall ? ' tall' : '');
    }
  });
  stopActionPollers();
  activeAction = aid;
  startActionPollers(aid);
}

function stopActionPollers() {
  if (pollers.aids) { clearInterval(pollers.aids); delete pollers.aids; }
  if (pollers.actionLogs) { clearInterval(pollers.actionLogs); delete pollers.actionLogs; }
}

function startActionPollers(id) {
  if (id === 'inject-keys') { loadAids(); pollers.aids = setInterval(loadAids, 1000); }
  if (id === 'logs') { loadLogs(); pollers.actionLogs = setInterval(loadLogs, 1000); }
  if (id === 'statistics') loadStatistics();
}

function buildActionPanels() {
  // Hack Fields
  document.getElementById('apanel-hack-fields').innerHTML = `
    <div class="controls">
      <label><input type="checkbox" id="hf-prot" checked> Disable Protection</label>
      <label><input type="checkbox" id="hf-hf" checked> Show Hidden</label>
      <label><input type="checkbox" id="hf-rnr" checked> Remove Numeric</label>
      <label><input type="checkbox" id="hf-sf" checked> SF</label>
      <label><input type="checkbox" id="hf-sfe" checked> SFE</label>
      <label><input type="checkbox" id="hf-mf" checked> MF</label>
      <label><input type="checkbox" id="hf-ei" checked> Intensity</label>
      <label><input type="checkbox" id="hf-hv" checked> High Vis</label>
    </div>`;

  // Send Keys
  document.getElementById('apanel-inject-keys').innerHTML = `
    <div class="controls">
      <button class="btn" onclick="sendSelectedKeys()">Send Keys</button>
      <span id="send-keys-status" style="font-size:17px;color:var(--dim)">Ready.</span>
    </div>
    <div class="controls checkbox-grid" id="aid-checkboxes"></div>`;

  // AID Scan — moved to popup (openAidScanPopup)

  // SPOOL/RCE
  document.getElementById('apanel-spool').innerHTML = `
    <div class="controls">
      <button class="btn" onclick="spoolCheck()">CHECK SPOOL</button>
      <span style="margin-left:12px;color:var(--border);font-size:17px">|</span>
      <input type="text" id="spool-ip" placeholder="Listener IP" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:17px;width:120px">
      <input type="number" id="spool-port" placeholder="Port" value="4444" min="1" max="65535" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:17px;width:70px">
      <button class="btn danger" onclick="spoolPoc()">FTP PoC</button>
      <span id="spool-status-msg" style="font-size:17px;color:var(--dim)">Ready.</span>
    </div>
    <div id="spool-result" style="margin-top:6px;background:var(--input-bg);border:1px solid var(--border);padding:8px;font-size:17px;max-height:200px;overflow-y:auto;display:none"></div>`;

  // Logs
  document.getElementById('apanel-logs').innerHTML = `
    <div class="controls">
      <button class="btn" onclick="exportCsv()">Export CSV</button>
      <span id="export-status" style="font-size:15px;color:var(--dim)"></span>
    </div>
    <table><thead><tr>
      <th onclick="sortTable('logs-table',0,'num')">ID</th>
      <th onclick="sortTable('logs-table',1,'str')">Time</th>
      <th onclick="sortTable('logs-table',2,'str')">Dir</th>
      <th onclick="sortTable('logs-table',3,'num')">Len</th>
      <th onclick="sortTable('logs-table',4,'str')">Notes</th>
    </tr></thead><tbody id="logs-table"></tbody></table>
    <div class="detail-box" id="log-detail">Click a log entry for details.</div>`;

  // Statistics
  document.getElementById('apanel-statistics').innerHTML = '<div id="stats-content" style="padding:4px"></div>';

}

// ---- Always-on pollers for dashboard panels ----
function startDashboardPollers() {
  pollers.findings = setInterval(loadFindings, 2000);
  pollers.txns = setInterval(loadTransactions, 2000);
  pollers.abends = setInterval(loadAbends, 5000);
  pollers.screenMap = setInterval(loadScreenMap, 5000);
  // Initial loads
  loadFindings(); loadTransactions(); loadAbends(); loadScreenMap();
}

// ---- Splash screen ----
let splashDismissed = false;
function dismissSplash() {
  if (splashDismissed) return;
  splashDismissed = true;
  const el = document.getElementById('splash');
  el.classList.add('hidden');
  setTimeout(() => el.style.display = 'none', 600);
}

// ---- Panel collapse ----
function togglePanel(id) {
  document.getElementById(id).classList.toggle('collapsed');
}

// ---- Status polling ----
async function pollStatus() {
  try {
    const s = await api('/api/status');
    const el = document.getElementById('conn-status');
    const oiaConn = document.getElementById('oia-conn');
    if (s.offline) {
      el.innerHTML = '<span class="offline">OFFLINE</span>';
      oiaConn.textContent = 'OFFLINE';
      oiaConn.className = 'oia-conn off';
      // Dismiss splash immediately in offline mode
      if (!splashDismissed) {
        document.getElementById('splash-status').innerHTML = 'OFFLINE MODE';
        setTimeout(dismissSplash, 800);
      }
    } else {
      el.innerHTML = '<span class="online">CONNECTED</span>';
      oiaConn.textContent = 'CONNECTED';
      oiaConn.className = 'oia-conn';
      if (!splashDismissed) dismissSplash();
    }
    document.getElementById('project-name').textContent = s.project_name || '';
    document.getElementById('oia-version').textContent = 'v' + (s.version || '');
    document.getElementById('oia-target').textContent = (s.server_ip || '') + (s.server_port ? ':'+s.server_port : '');


    // Update header toggle pills
    const hackPill = document.getElementById('tgl-hack');
    hackPill.className = s.hack_on ? 'toggle-pill on' : 'toggle-pill';
  } catch(e) { /* non-critical */ }
}
setInterval(pollStatus, 1000);
pollStatus();

// ---- Data loaders ----
async function loadLogs() {
  try {
    const data = await api('/api/logs?since=' + logSince);
    const tbody = document.getElementById('logs-table');
    if (!tbody) return;
    data.forEach(r => {
      logSince = Math.max(logSince, r.id);
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      tr.onclick = () => loadLogDetail(r.id);
      tr.innerHTML = '<td>'+r.id+'</td><td>'+esc(r.timestamp_fmt)+'</td><td>'+esc(r.direction)+'</td><td>'+r.data_len+'</td><td>'+esc(r.notes)+'</td>';
      tbody.appendChild(tr);
    });
  } catch(e) {}
}

async function loadLogDetail(id) {
  try {
    const data = await api('/api/log/' + id);
    const el = document.getElementById('log-detail');
    if (!el) return;
    if (data.error) { el.textContent = 'Error: ' + data.error; return; }
    el.textContent = data.parsed || '(no data)';
  } catch(e) {}
}

async function loadAbends() {
  try {
    const data = await api('/api/abends?since=' + abendSince);
    if (data.length === 0) return;
    data.forEach(r => {
      abendSince = Math.max(abendSince, r.id);
      rawAbends.push(r);
    });
  } catch(e) {}
}

let smapShowAll = false;
let smapData = [];

async function loadScreenMap() {
  try {
    const resp = await api('/api/screen_map');
    smapData = Array.isArray(resp) ? resp : (resp.fields || []);
    const esmEl = document.getElementById('smap-esm');
    const esm = resp && resp.esm;
    if (esmEl && esm && esm !== 'UNKNOWN') {
      esmEl.textContent = 'ESM: ' + esm;
      esmEl.style.color = 'var(--head)';
    } else if (esmEl) {
      esmEl.textContent = '';
    }
    renderScreenMap();
  } catch(e) { console.error('loadScreenMap error:', e); }
}

function renderScreenMap() {
  const thead = document.getElementById('smap-thead');
  const tbody = document.getElementById('smap-table');
  thead.innerHTML = smapShowAll
    ? '<th>Pos</th><th style="text-align:center">H</th><th style="text-align:center">N</th><th>Len</th><th>Content</th>'
    : '<th style="text-align:center">H</th><th style="text-align:center">N</th><th>Len</th><th>Content</th>';
  tbody.innerHTML = '';
  const dot = '<span style="display:block;margin:auto;width:8px;height:8px;border-radius:50%;background:var(--text)"></span>';
  smapData.forEach((f, i) => {
    const isInput = !f.protected;
    const isHidden = f.hidden;
    const isBms = f.bms;
    if (!smapShowAll && isBms) return;
    if (!smapShowAll && !isInput && !isHidden) return;
    const tr = document.createElement('tr');
    if (isBms) { tr.className = 'field-label'; tr.style.opacity = '0.4'; }
    else if (isHidden) tr.className = 'field-hidden';
    else if (isInput) tr.className = 'field-input';
    else tr.className = 'field-label';
    if ((isInput || isHidden) && !isBms) {
      tr.style.cursor = 'pointer';
      tr.ondblclick = () => openFuzzPopup(f);
    }
    const pos = smapShowAll ? '<td>'+f.row+','+f.col+'</td>' : '';
    const bmsTag = isBms ? ' <span style="color:var(--dim);font-size:11px">BMS</span>' : '';
    tr.innerHTML = pos+'<td>'+(f.hidden?dot:'')+'</td><td>'+(f.numeric?dot:'')+'</td><td>'+f.length+'</td><td>'+esc(f.content)+bmsTag+'</td>';
    tbody.appendChild(tr);
  });
}

function toggleSmapFilter() {
  smapShowAll = !smapShowAll;
  document.getElementById('smap-filter-btn').textContent = smapShowAll ? 'FILTER' : 'SHOW ALL';
  renderScreenMap();
}

const FUZZ_STATUS_COLORS = {
  SAME_SCREEN:'#4ec9b0',ACCESSIBLE:'#4ec9b0',NEW_SCREEN:'#4ec9b0',NAVIGATED:'#569cd6',ABEND:'#f44',DENIED:'#f90',
  NOT_FOUND:'var(--dim)',ERROR:'#f90',SAME_SCREEN:'var(--dim)',NO_RESPONSE:'#f44',UNKNOWN:'var(--dim)'
};

async function loadTransactions() {
  try {
    const data = await api('/api/transactions?since=' + txnSince);
    if (data.length === 0) return;
    data.forEach(r => {
      txnSince = Math.max(txnSince, r.id);
      rawTxns.push(r);
    });
    // Auto-follow: update finding filter to latest transaction
    if (findingFilterTxn && rawTxns.length > 0) {
      const latest = rawTxns[rawTxns.length-1].txn_code;
      if (latest !== findingFilterTxn) {
        findingFilterTxn = latest;
        document.getElementById('finding-filter-btn').textContent = latest;
        document.getElementById('finding-txn-label').textContent = latest;
        findingSince = 0; findingsData = [];
        loadFindings();
      }
    }
  } catch(e) {}
}

async function loadStatistics() {
  try {
    const s = await api('/api/statistics');
    const el = document.getElementById('stats-content');
    if (!el) return;
    el.innerHTML = `
      <div class="stat-row"><span class="stat-label">Server:</span><span class="stat-value">${esc(s.server_ip)}:${s.server_port} ${s.tls_enabled ? '(TLS)' : ''}</span></div>
      <div class="stat-row"><span class="stat-label">Connections:</span><span class="stat-value">${s.total_connections}</span></div>
      <div class="stat-row"><span class="stat-label">Server msgs/bytes:</span><span class="stat-value">${s.server_messages} / ${s.server_bytes}</span></div>
      <div class="stat-row"><span class="stat-label">Client msgs/bytes:</span><span class="stat-value">${s.client_messages} / ${s.client_bytes}</span></div>
      <div class="stat-row"><span class="stat-label">Hacks / Injections:</span><span class="stat-value">${s.total_hacks} / ${s.total_injections}</span></div>
      <div class="stat-row"><span class="stat-label">Connect time:</span><span class="stat-value">${Math.round(s.total_time)}s</span></div>`;
  } catch(e) {}
}

async function loadAids() {
  try {
    const data = await api('/api/aids');
    const container = document.getElementById('aid-checkboxes');
    if (container.children.length > 0) return;
    const defaults_unchecked = ['ENTER', 'CLEAR'];
    data.all.forEach(name => {
      const checked = !defaults_unchecked.includes(name) ? 'checked' : '';
      const found = data.found.includes(name);
      const label = document.createElement('label');
      label.innerHTML = '<input type="checkbox" data-aid="'+name+'" '+checked+'> '+name + (found ? ' *' : '');
      container.appendChild(label);
    });
  } catch(e) {}
}

// ---- Badge helper ----
// ---- Actions ----
async function toggleHackFields() {
  const pill = document.getElementById('tgl-hack');
  const on = !pill.classList.contains('on');
  const g = id => { const e = document.getElementById(id); return e ? (e.checked ? 1 : 0) : 1; };
  await post('/api/hack_fields', { on: on?1:0, prot:g('hf-prot'), hf:g('hf-hf'), rnr:g('hf-rnr'), sf:g('hf-sf'), sfe:g('hf-sfe'), mf:g('hf-mf'), ei:g('hf-ei'), hv:g('hf-hv') });
  toast('Hack Fields ' + (on ? 'ON' : 'OFF'), on ? 'success' : 'info');
}


async function sendSelectedKeys() {
  const checks = document.querySelectorAll('#aid-checkboxes input[type=checkbox]:checked');
  const keys = Array.from(checks).map(c => c.dataset.aid);
  const r = await post('/api/send_keys', {keys: keys});
  document.getElementById('send-keys-status').textContent = r.message || 'Sent.';
}

async function exportCsv() {
  const r = await post('/api/export_csv');
  document.getElementById('export-status').textContent = r.ok ? 'Exported: '+r.filename : 'Failed.';
}

// ---- AID Scan (popup) ----
let aidScanPoller = null;
const CAT_COLORS = {VIOLATION:C.alert,NEW_SCREEN:C.text,SAME_SCREEN:C.dim,UNMAPPED:C.dim,SKIPPED:C.dim};

async function openAidScanPopup() {
  if (document.getElementById('aid-scan-overlay')) return;
  const macroList = await api('/api/macro/list').catch(()=>({files:[]}));
  let macroOpts = '<option value="">No replay macro</option>';
  (macroList.files||[]).forEach(f => { macroOpts += '<option value="'+esc(f)+'">'+esc(f.replace('.json',''))+'</option>'; });
  const overlay = document.createElement('div');
  overlay.id = 'aid-scan-overlay';
  overlay.className = 'fuzz-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeAidScanPopup(); };
  overlay.innerHTML = `<div class="fuzz-popup" style="width:80vw">
    <h3>AID Scan</h3>
    <p style="font-size:14px;color:var(--dim);margin:0 0 8px 0">Tests 22 keys (PF2, PF4-24) on current screen with auto-replay.</p>
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
      <button class="btn" id="aid-scan-btn" onclick="aidScanStart()">START</button>
      <button class="btn danger" id="aid-scan-stop-btn" onclick="aidScanStop()" style="display:none">STOP</button>
      <input type="number" id="aid-timeout" value="1" min="0.5" max="10" step="0.5" style="width:70px;background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:17px;margin-left:12px"> <label style="color:var(--dim);font-size:15px">s timeout</label>
      <button class="btn" onclick="closeAidScanPopup()" style="margin-left:auto">\u2715</button>
    </div>
    <div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
      <label style="color:var(--dim);font-size:13px">Replay macro:</label>
      <select id="aid-scan-macro" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:14px">${macroOpts}</select>
      <button class="btn" onclick="openMacroEditor()" style="font-size:12px;padding:2px 8px" title="Create/Edit macro">EDIT</button>
    </div>
    <div id="aid-scan-status" style="color:var(--dim);margin-bottom:4px"></div>
    <div class="fuzz-progress" id="aid-scan-progress-bar" style="display:none"><div class="fuzz-progress-fill" id="aid-scan-progress-fill"></div></div>
    <div id="aid-scan-summary" style="display:none;margin-bottom:8px;gap:12px;font-size:16px">
      <span style="color:var(--alert)"><b id="as-violation">0</b> VIOLATION</span>
      <span style="color:var(--head)"><b id="as-new">0</b> NEW</span>
      <span style="color:var(--dim)"><b id="as-same">0</b> SAME</span>
      <span style="color:var(--dim)"><b id="as-unmapped">0</b> UNMAPPED</span>
      <span style="color:var(--dim)"><b id="as-skipped">0</b> SKIP</span>
    </div>
    <div style="max-height:400px;overflow-y:auto;">
      <table style="table-layout:fixed;width:100%"><thead><tr>
        <th style="width:70px">Key</th><th style="width:100px">Category</th><th style="width:50px">Sim</th><th>Preview</th>
      </tr></thead><tbody id="aid-scan-table"></tbody></table>
    </div>
  </div>`;
  document.body.appendChild(overlay);
}

function closeAidScanPopup() {
  const el = document.getElementById('aid-scan-overlay');
  if (el) el.remove();
  // don't stop poller — scan continues in background, popup can be reopened
}

async function aidScanStart() {
  const t = parseFloat(document.getElementById('aid-timeout').value) || 1;
  const macro = document.getElementById('aid-scan-macro').value || '';
  const r = await post('/api/aid_scan/start', {timeout: t, macro: macro});
  if (!r.ok) { toast(r.message, 'error'); return; }
  toast(r.message, 'success');
  document.getElementById('aid-scan-btn').style.display = 'none';
  document.getElementById('aid-scan-stop-btn').style.display = '';
  document.getElementById('aid-scan-table').innerHTML = '';
  const pb = document.getElementById('aid-scan-progress-bar');
  if (pb) pb.style.display = '';
  const sum = document.getElementById('aid-scan-summary');
  if (sum) sum.style.display = 'flex';
  aidScanPoller = setInterval(aidScanPoll, 1000);
}

async function aidScanStop() {
  await post('/api/aid_scan/stop');
  if (aidScanPoller) { clearInterval(aidScanPoller); aidScanPoller = null; }
  const btn = document.getElementById('aid-scan-btn');
  const stop = document.getElementById('aid-scan-stop-btn');
  const st = document.getElementById('aid-scan-status');
  if (btn) btn.style.display = '';
  if (stop) stop.style.display = 'none';
  if (st) st.textContent = 'Stopped';
}

async function aidScanPoll() {
  const r = await fetch('/api/aid_scan/summary').then(r=>r.json());
  const s = r.summary || {};
  const el = id => document.getElementById(id);
  if (el('as-violation')) el('as-violation').textContent = s.VIOLATION||0;
  if (el('as-new')) el('as-new').textContent = s.NEW_SCREEN||0;
  if (el('as-same')) el('as-same').textContent = s.SAME_SCREEN||0;
  if (el('as-unmapped')) el('as-unmapped').textContent = s.UNMAPPED||0;
  if (el('as-skipped')) el('as-skipped').textContent = s.SKIPPED||0;
  const st = el('aid-scan-status');
  if (st) st.textContent = r.progress+'/'+r.total;
  const fill = el('aid-scan-progress-fill');
  if (fill && r.total > 0) fill.style.width = Math.round(r.progress/r.total*100)+'%';
  const tb = el('aid-scan-table');
  if (tb) {
    tb.innerHTML = '';
    (r.results||[]).forEach(row => {
      const c = CAT_COLORS[row.category]||C.dim;
      const sim = row.similarity != null ? Math.round(row.similarity*100) : '';
      const simColor = sim==='' ? '' : sim>=90 ? 'var(--text)' : sim>=80 ? '#ffd700' : 'var(--alert)';
      const preview = (row.response_preview||'').replace(/</g,'&lt;');
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      tr.ondblclick = () => { post('/api/inject/keys', {keys:[row.aid_key]}); toast('Sent '+row.aid_key, 'success'); };
      tr.innerHTML = '<td>'+row.aid_key+'</td>'+
        '<td style="color:'+c+';font-weight:bold">'+row.category+'</td>'+
        '<td style="text-align:center;color:'+simColor+'">'+(sim!==''?sim+'%':'')+'</td>'+
        '<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dim);font-size:14px">'+preview+'</td>';
      tb.appendChild(tr);
    });
  }
  if (!r.running) {
    if (aidScanPoller) { clearInterval(aidScanPoller); aidScanPoller = null; }
    const btn = el('aid-scan-btn');
    const stop = el('aid-scan-stop-btn');
    if (btn) btn.style.display = '';
    if (stop) stop.style.display = 'none';
    const nSkipped = s.SKIPPED||0;
    const nFailed = (r.results||[]).filter(x => x.replay_ok===false && x.category!=='SKIPPED').length;
    if (nSkipped > 0) {
      if (st) st.textContent = 'Interrupted — '+nSkipped+' skipped';
      toast('Session lost — '+nSkipped+' keys skipped', 'warn');
    } else if (nFailed > 0) {
      if (st) st.textContent = 'Done ('+r.total+' keys, '+nFailed+' recovered)';
      toast('AID Scan complete — '+nFailed+' key(s) needed recovery', 'warn');
    } else {
      if (st) st.textContent = 'Done ('+r.total+' keys)';
      toast('AID Scan complete', 'success');
    }
  }
}

// ---- SPOOL/RCE ----
async function spoolCheck() {
  document.getElementById('spool-status-msg').textContent = 'Checking SPOOL API...';
  const r = await post('/api/spool/check');
  const div = document.getElementById('spool-result');
  if (r.ok && r.result) {
    const res = r.result;
    const color = res.status === 'SPOOL_OPEN' ? 'var(--alert)' : 'var(--text)';
    div.innerHTML = '<b style="color:'+color+'">'+res.status+'</b><br>'+
      '<b>Detail:</b> '+res.detail+'<br>'+
      '<b>Response:</b> <pre style="white-space:pre-wrap;margin:4px 0;color:var(--dim)">'+res.response_preview+'</pre>';
    div.style.display = 'block';
    document.getElementById('spool-status-msg').textContent = res.status;
    toast('SPOOL Check: ' + res.status, res.status === 'SPOOL_OPEN' ? 'error' : 'success');
  } else {
    document.getElementById('spool-status-msg').textContent = 'Error';
  }
}
async function spoolPoc() {
  const ip = document.getElementById('spool-ip').value.trim();
  const port = document.getElementById('spool-port').value.trim();
  if (!ip) { toast('Enter listener IP', 'error'); return; }
  if (!port) { toast('Enter listener port', 'error'); return; }
  if (!confirm('This will submit a FTP job on the mainframe that connects back to '+ip+':'+port+'. Proceed?')) return;
  document.getElementById('spool-status-msg').textContent = 'Submitting FTP PoC...';
  const r = await post('/api/spool/poc', {listener_ip: ip, listener_port: parseInt(port)});
  const div = document.getElementById('spool-result');
  if (r.ok && r.result) {
    const res = r.result;
    const color = res.status === 'SPOOL_OPEN' ? 'var(--alert)' : 'var(--head)';
    let html = '<b style="color:'+color+'">'+res.status+'</b><br>'+
      '<b>Detail:</b> '+res.detail+'<br>'+
      '<b>Lines written:</b> '+res.lines_written+'/'+res.jcl_lines+'<br>';
    if (res.results) {
      html += '<table style="margin-top:4px;font-size:15px"><tr><th>Line</th><th>OK</th></tr>';
      res.results.forEach(l => {
        html += '<tr><td><code>'+l.line+'</code></td><td>'+(l.ok?'Y':'N')+'</td></tr>';
      });
      html += '</table>';
    }
    div.innerHTML = html;
    div.style.display = 'block';
    document.getElementById('spool-status-msg').textContent = res.status;
  } else {
    document.getElementById('spool-status-msg').textContent = r.message || 'Error';
  }
}

// ---- Table sorting ----
function sortTable(tbodyId, colIdx, type) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const dir = tbody.dataset.sortDir === 'asc' ? 'desc' : 'asc';
  tbody.dataset.sortDir = dir;
  rows.sort((a, b) => {
    let va = a.children[colIdx]?.textContent || '';
    let vb = b.children[colIdx]?.textContent || '';
    if (type === 'num') { va = parseFloat(va)||0; vb = parseFloat(vb)||0; }
    return dir === 'asc' ? (va > vb ? 1 : va < vb ? -1 : 0) : (va < vb ? 1 : va > vb ? -1 : 0);
  });
  rows.forEach(r => tbody.appendChild(r));
}

// ---- Utility ----
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---- Methodology ----
const ABEND_REF = [
  {code:'ASRA', desc:'Program check (possible injection vulnerability)', analogy:'Segfault'},
  {code:'ASRB', desc:'Operating system abend', analogy:'Kernel panic'},
  {code:'AICA', desc:'Runaway task (infinite loop)', analogy:'Timeout/DoS'},
  {code:'AEY7', desc:'Not authorized (security violation)', analogy:'403 Forbidden'},
  {code:'AEY9', desc:'CICS unable to process', analogy:'503 Unavailable'},
  {code:'AEYD', desc:'Transaction not found', analogy:'404 endpoint'},
  {code:'AEYF', desc:'Resource security check failure', analogy:'403 resource'},
  {code:'APCT', desc:'Program not found (enumeration opportunity)', analogy:'404 Not Found'},
  {code:'AFCA', desc:'DATASET not found', analogy:'File not found'},
  {code:'AFCR', desc:'DATASET read error', analogy:'I/O error'},
  {code:'AKCS', desc:'Temp storage queue not found', analogy:'Cache miss'},
  {code:'AKCT', desc:'Transient data queue not found', analogy:'Queue missing'},
  {code:'ASP1', desc:'Supervisor call', analogy:'Syscall error'},
  {code:'ATNI', desc:'Task abend due to node error', analogy:'Network error'},
  {code:'AEXL', desc:'EXEC interface program not found', analogy:'Library missing'},
  {code:'ABMB', desc:'BMS map not found', analogy:'Template 404'},
  {code:'ADTC', desc:'DL/I call error', analogy:'DB query error'},
  {code:'AEIP', desc:'EXEC CICS command error', analogy:'Bad API call'},
  {code:'AEZD', desc:'CICS security violation', analogy:'Auth violation'},
  {code:'AQRD', desc:'Queue read error', analogy:'Queue I/O error'},
];

const METHOD_DATA = {
  recon: {
    label: '1. RECON',
    steps: ['Connect via proxy and observe initial screen', 'Enable ABEND detection + Transaction tracking', 'Map all fields with Screen Map', 'Identify hidden, protected, and numeric fields', 'Note transaction codes visible on screen'],
    cards: [
      {term:'Transaction Code', explain:'4-char identifier that launches a CICS program (like a URL path).', analogy:'Like typing a URL path in a browser to reach a specific page.', action:'Look at top-left of screen or use Scan tab to probe codes.'},
      {term:'Screen Map', explain:'Parsed layout of all fields on the current 3270 screen with attributes.', analogy:'Like browser DevTools showing all form fields and their properties.', action:'Check Screen Map panel above. Look for hidden (yellow) and input (green) fields.'},
      {term:'Hidden Fields', explain:'Fields with the hidden attribute set — invisible to user but contain data.', analogy:'Like hidden HTML form fields (<input type="hidden">).', action:'Enable Hack Fields to reveal them. Often contain menu options or admin commands.'},
      {term:'Protected Fields', explain:'Fields marked read-only by the server. Cannot be typed into normally.', analogy:'Like disabled or readonly form inputs in a web form.', action:'Hack Fields disables protection, allowing you to type in any field.'},
      {term:'Numeric Fields', explain:'Fields restricted to numeric input only.', analogy:'Like <input type="number"> that rejects letters.', action:'Hack Fields removes the numeric constraint, allowing any character.'},
      {term:'Field Attributes', explain:'Byte before each field encoding protection, visibility, numeric, intensity.', analogy:'Like CSS properties (display:none, readonly, input type) combined into one byte.', action:'Screen Map decodes these. SF/SFE/MF are the 3270 orders that set them.'},
    ],
    decision: [
      {q:'Do you see hidden fields?', a:'Yes -> Phase 2 (modify fields). No -> Try Scan to enumerate transactions.'},
      {q:'Do you see transaction codes on screen?', a:'Yes -> Note them for Phase 3. No -> Use injections/cics_transactions.txt.'},
    ]
  },
  fields: {
    label: '2. FIELDS',
    steps: ['Enable Hack Fields (Ctrl+H) to unlock all protections', 'Hidden fields with black color are automatically revealed in yellow', 'Modify hidden field values and submit', 'Try typing in protected fields after hack'],
    cards: [
      {term:'Hack Fields', explain:'Rewrites field attribute bytes in proxy traffic to remove protection, reveal hidden, remove numeric lock.', analogy:'Like a browser extension that removes "disabled" and "readonly" from all form inputs.', action:'Toggle via Ctrl+H or header pill. Configure options in Hack Fields action tab.'},
      {term:'Hack Color', explain:'Always active. Replaces black-on-black color attributes (SFE/SA/MF) with yellow so hidden text is visible on the emulator.', analogy:'Like a CSS rule that forces visibility:visible on all hidden elements.', action:'Automatic — no toggle needed.'},
      {term:'EBCDIC', explain:'Character encoding used by mainframes. All 3270 data is EBCDIC, converted by proxy.', analogy:'Like UTF-8 vs ASCII — different byte values for the same characters.', action:'The proxy handles conversion transparently. Injection payloads are auto-converted.'},
      {term:'3270 Protocol', explain:'Telnet-based protocol with structured fields, orders (SF/SFE/SBA), and AID keys.', analogy:'Like HTTP with form fields, but binary and stateful — think WebSocket + HTML forms.', action:'The proxy intercepts and modifies the binary stream. No manual protocol work needed.'},
    ],
    decision: [
      {q:'Did hidden fields reveal new menu options?', a:'Yes -> Try them! Often admin/debug functions. No -> Move to Phase 3 injection.'},
      {q:'Can you now type in protected fields?', a:'Yes -> Try modifying values and submitting. Check for ABENDs.'},
    ]
  },
  inject: {
    label: '3. INJECT',
    steps: ['Load a wordlist in the Inject tab', 'Setup mask and truncation mode', 'Choose key sequence (ENTER, ENTER+CLEAR, etc.)', 'Run injection and monitor Events for ABENDs', 'Use Scan for targeted single-transaction probes'],
    cards: [
      {term:'AID Keys', explain:'Attention Identifier keys (ENTER, PF1-24, PA1-3, CLEAR) that trigger server processing.', analogy:'Like different HTTP methods (GET, POST, PUT, DELETE) — each triggers different server behavior.', action:'Use Keys tab to send specific AID keys. Some functions only respond to specific PF keys.'},
      {term:'Field Fuzzing', explain:'Injecting wordlist values into input fields to trigger errors or unexpected behavior.', analogy:'Like web fuzzing with Burp Intruder — trying many payloads to find vulnerabilities.', action:'Load a file in Inject tab, setup mask, and run. Monitor Events panel for ABENDs.'},
      {term:'Transaction Enumeration', explain:'Trying known CICS transaction codes to discover accessible functions.', analogy:'Like directory bruteforcing (gobuster/ffuf) to find hidden endpoints.', action:'Use cics_transactions.txt wordlist or Bulk Audit for systematic testing.'},
      {term:'Mask & Truncation', explain:'Mask char fills remaining field space. Truncation mode skips or truncates long payloads.', analogy:'Like padding/truncation in web parameter fuzzing — handling size mismatches.', action:'Configure in Inject tab. * is default mask. SKIP skips oversized payloads, TRUNC truncates.'},
    ],
    decision: [
      {q:'Are you getting ABENDs?', a:'Yes -> Great! Check ABEND codes in Phase 4. ASRA = possible injection.'},
      {q:'Getting DENIED responses?', a:'Yes -> Note the transaction. Try with different AID keys or from different screens.'},
    ]
  },
  analyze: {
    label: '4. ANALYZE',
    steps: ['Review Events timeline for patterns', 'Check ABEND codes against reference table below', 'Look for security violations (AEY7, AEYF, AEZD)', 'Analyze timing differences between transactions', 'Classify responses: ACCESSIBLE, DENIED, ABEND, NOT_FOUND'],
    cards: [
      {term:'ABEND Codes', explain:'4-char codes indicating how a CICS transaction crashed. Each reveals different info.', analogy:'Like HTTP status codes (404, 403, 500) but for mainframe programs.', action:'See ABEND Reference table below. Cross-referenced with your session data.'},
      {term:'ESM Detection', explain:'External Security Manager identification — RACF, ACF2, or Top Secret.', analogy:'Like fingerprinting the WAF/auth system (detecting Cloudflare, AWS WAF, etc.).', action:'Scan results show ESM detection. 25 patterns matched against responses.'},
      {term:'Security Violations', explain:'RACF/ACF2/TSS messages indicating access control enforcement.', analogy:'Like 403 Forbidden responses with WAF signatures.', action:'Look for DENY events in the timeline. These confirm ESM is blocking access.'},
      {term:'Timing Analysis', explain:'Response time differences can reveal processing depth before rejection.', analogy:'Like timing-based user enumeration in web apps.', action:'Check ms column in Events. Slow denials may mean the txn exists but is blocked.'},
      {term:'Response Classification', explain:'Categorizing responses as ACCESSIBLE/DENIED/ABEND/NOT_FOUND/ERROR.', analogy:'Like categorizing HTTP responses by status code families (2xx, 4xx, 5xx).', action:'Bulk Audit auto-classifies. Event counters show distribution.'},
      {term:'ABEND Reference', explain:'Complete reference of 20 CICS ABEND codes with pentest implications.', analogy:'Like an HTTP status code reference card for mainframe testing.', action:'See table below — codes detected in this session are highlighted.'},
    ],
    decision: [
      {q:'Is ASRA showing up?', a:'Yes -> The program crashed on your input. This is a potential injection point.'},
      {q:'Is AEY7/AEYF/AEZD showing?', a:'Yes -> Security is blocking you. Try different user context or escalation paths.'},
      {q:'Is APCT showing up?', a:'The program does not exist. But the transaction IS defined — enumeration success.'},
    ]
  },
  report: {
    label: '5. REPORT',
    steps: ['Export logs and audit results via CSV', 'Document accessible transactions', 'Document hidden fields and their contents', 'Document ABENDs and their implications', 'Assign severity based on impact'],
    cards: [
      {term:'Findings', explain:'Documented security issues discovered during the assessment.', analogy:'Like Burp Scanner findings or OWASP ZAP alerts.', action:'Use research/FINDINGS.md format: F-XXXX with severity and evidence.'},
      {term:'Evidence', explain:'Screenshots, logs, and data proving the vulnerability exists.', analogy:'Like HTTP request/response pairs proving an XSS or SQLi.', action:'Export CSV from Logs tab. Include ABEND codes and screen contents.'},
      {term:'Impact', explain:'What an attacker could achieve by exploiting the finding.', analogy:'Like CVSS impact scoring — confidentiality, integrity, availability.', action:'ASRA = code execution potential. AEY7 bypass = privilege escalation.'},
      {term:'Remediation', explain:'Recommended fixes for the security team.', analogy:'Like fix recommendations in a pentest report.', action:'Common fixes: input validation, RACF rules, transaction security, program checks.'},
      {term:'Severity', explain:'Rating from INFO to CRITICAL based on exploitability and impact.', analogy:'Like CVSS scores: INFO/LOW/MEDIUM/HIGH/CRITICAL.', action:'Hidden fields with admin access = HIGH. ASRA on user input = HIGH. Denied txn = INFO.'},
    ],
    decision: [
      {q:'Did you find accessible admin transactions?', a:'CRITICAL/HIGH — unauthorized access to admin functions.'},
      {q:'Did you find hidden fields revealing sensitive data?', a:'MEDIUM/HIGH — information disclosure through UI bypass.'},
      {q:'Did you trigger ABENDs with crafted input?', a:'HIGH — potential for code execution or denial of service.'},
    ]
  }
};

let activePhase = 'recon';

function showPhase(pid) {
  activePhase = pid;
  // Update active class on phase buttons
  document.querySelectorAll('.method-phase').forEach(el => {
    el.className = 'method-phase' + (el.textContent.trim() === METHOD_DATA[pid].label ? ' active' : '');
  });
  renderPhaseContent();
}

function renderPhaseContent() {
  const area = document.getElementById('method-content-area');
  if (!area) return;
  const phase = METHOD_DATA[activePhase];
  let h = '';
  // Steps
  h += '<div class="method-steps"><ol>';
  phase.steps.forEach(s => { h += '<li>' + esc(s) + '</li>'; });
  h += '</ol></div>';
  // Cards
  h += '<div class="method-cards">';
  phase.cards.forEach(c => {
    h += '<div class="method-card">';
    h += '<div class="card-term">' + esc(c.term) + '</div>';
    h += '<div class="card-explain">' + esc(c.explain) + '</div>';
    h += '<div class="card-analogy">' + esc(c.analogy) + '</div>';
    h += '<div class="card-action">' + esc(c.action) + '</div>';
    h += '</div>';
  });
  h += '</div>';
  // Decision tree
  if (phase.decision && phase.decision.length) {
    h += '<div class="method-decision">';
    h += '<div style="color:var(--head);font-size:17px;font-weight:bold;margin-bottom:6px">DECISION TREE</div>';
    phase.decision.forEach(d => {
      h += '<div class="node-q">' + esc(d.q) + '</div>';
      h += '<div class="node-a">' + esc(d.a) + '</div>';
    });
    h += '</div>';
  }
  // ABEND reference table for analyze phase
  if (activePhase === 'analyze') {
    h += renderAbendRefTable();
  }
  area.innerHTML = h;
}

function renderAbendRefTable() {
  const detectedCodes = new Set(rawAbends.map(a => a.code));
  let h = '<div class="abend-ref-table"><div class="section-title">ABEND Reference (' + detectedCodes.size + ' detected in session)</div>';
  h += '<table><thead><tr><th>Code</th><th>Description</th><th>Web Analogy</th><th style="text-align:center;width:16px"></th></tr></thead><tbody>';
  ABEND_REF.forEach(a => {
    const detected = detectedCodes.has(a.code);
    h += '<tr class="' + (detected ? 'abend-ref-detected' : '') + '">';
    h += '<td>' + esc(a.code) + '</td><td>' + esc(a.desc) + '</td><td>' + esc(a.analogy) + '</td>';
    h += '<td style="text-align:center">' + (detected ? '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--text)"></span>' : '') + '</td>';
    h += '</tr>';
  });
  h += '</tbody></table></div>';
  return h;
}

// ---- Keyboard shortcuts ----
document.addEventListener('keydown', function(e) {
  if (e.ctrlKey && !e.altKey && !e.shiftKey) {
    const k = e.key.toLowerCase();
    if (k === 'h') { e.preventDefault(); toggleHackFields(); return; }
  }
  if (e.key === 'Escape' && activeGroup) {
    toggleGroup(activeGroup);
  }
});

// ---- Macro Engine ----
let macroPoller = null;
async function loadMacroList() {
  const r = await api('/api/macro/list');
  const sel = document.getElementById('macro-select');
  const old = sel.value;
  sel.innerHTML = '<option value="">-- Macro --</option>';
  (r.files||[]).forEach(f => {
    const o = document.createElement('option');
    o.value = f; o.textContent = f.replace('.json','');
    sel.appendChild(o);
  });
  if (old) sel.value = old;
}
async function macroRun() {
  const file = document.getElementById('macro-select').value;
  if (!file) { toast('Select a macro file', 'error'); return; }
  const r = await post('/api/macro/run', {file: file});
  if (!r.ok) { toast(r.message, 'error'); return; }
  toast(r.message, 'info');
  document.getElementById('macro-run-btn').style.display = 'none';
  document.getElementById('macro-stop-btn').style.display = '';
  macroPoller = setInterval(macroPoll, 500);
}
async function macroStop() {
  await post('/api/macro/stop');
  if (macroPoller) { clearInterval(macroPoller); macroPoller = null; }
  document.getElementById('macro-run-btn').style.display = '';
  document.getElementById('macro-stop-btn').style.display = 'none';
  document.getElementById('macro-status').textContent = 'Stopped';
  toast('Macro stopped', 'warn');
}
async function macroPoll() {
  try {
    const s = await api('/api/macro/status');
    const p = s.progress || {};
    document.getElementById('macro-status').textContent = p.current+'/'+p.total+' '+p.step;
    if (!s.running) {
      clearInterval(macroPoller); macroPoller = null;
      document.getElementById('macro-run-btn').style.display = '';
      document.getElementById('macro-stop-btn').style.display = 'none';
      if (s.error) {
        document.getElementById('macro-status').textContent = s.error;
        toast('Macro failed: ' + s.error, 'error');
      } else {
        document.getElementById('macro-status').textContent = 'Done ('+p.total+' steps)';
        toast('Macro complete', 'success');
      }
    }
  } catch(e) { clearInterval(macroPoller); macroPoller = null; }
}
loadMacroList();

// ---- Help/Method modal ----
function toggleHelpModal() {
  let overlay = document.getElementById('help-overlay');
  if (overlay) { overlay.remove(); return; }
  overlay = document.createElement('div');
  overlay.id = 'help-overlay';
  overlay.className = 'fuzz-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  overlay.innerHTML = '<div class="fuzz-popup" style="max-width:800px;max-height:80vh;overflow-y:auto">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">' +
    '<h3 style="margin:0">Method &amp; Help</h3>' +
    '<button class="btn" onclick="document.getElementById(\'help-overlay\').remove()" style="font-size:18px">\u2715</button></div>' +
    '<div id="help-method-root"></div>' +
    '<hr style="border-color:var(--border);margin:12px 0">' +
    '<div id="help-content-area" style="white-space:pre-wrap;font-size:15px;color:var(--dim)"></div></div>';
  document.body.appendChild(overlay);
  // Build methodology in modal
  const root = document.getElementById('help-method-root');
  if (root) {
    let h = '<div class="method-phases">';
    const phases = Object.keys(METHOD_DATA);
    phases.forEach((pid, i) => {
      if (i > 0) h += '<span class="method-arrow">&#9654;</span>';
      h += '<div class="method-phase' + (pid === activePhase ? ' active' : '') + '" onclick="showPhase(\''+pid+'\')">' + esc(METHOD_DATA[pid].label) + '</div>';
    });
    h += '</div><div id="method-content-area"></div>';
    root.innerHTML = h;
    renderPhaseContent();
  }
  // Help text
  document.getElementById('help-content-area').textContent = 'Gr0gu3270 - TN3270 Penetration Testing Toolkit\n\nMain view: Screen Map (top) + Findings (bottom)\nAction bar: click group headers to expand tools\n\nAlways active: Hack Color, ABEND Detection, Transaction Tracking\n\nKeyboard Shortcuts:\n  Ctrl+H  Toggle Hack Fields\n  Esc     Close action panel\n  ?       Open this help modal';
}

// ---- Init ----
buildActionBar();
startDashboardPollers();
// ---- Fuzz popup (double-click on field) ----
let fuzzPoller = null;
let fuzzField = null;

async function openFuzzPopup(field) {
  if (document.getElementById('fuzz-overlay')) return; // already open
  fuzzField = field;
  const type = field.hidden ? 'Hidden' : field.numeric ? 'Numeric' : 'Input';
  // Load macro list for dropdown
  const macroList = await api('/api/macro/list').catch(()=>({files:[]}));
  let macroOpts = '<option value="">No replay macro</option>';
  (macroList.files||[]).forEach(f => { macroOpts += '<option value="'+esc(f)+'">'+esc(f.replace('.json',''))+'</option>'; });
  const overlay = document.createElement('div');
  overlay.id = 'fuzz-overlay';
  overlay.className = 'fuzz-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeFuzzPopup(); };
  overlay.innerHTML = `<div class="fuzz-popup">
    <h3>Fuzz Field</h3>
    <div class="fuzz-field-info">R${field.row},C${field.col} | ${type} | Len ${field.length} | "${esc(field.content || '')}"</div>
    <div class="fuzz-controls">
      <button class="btn" id="fp-start" onclick="fuzzPopupStart()">START</button>
      <button class="btn danger" id="fp-stop" onclick="fuzzPopupStop()" style="display:none">STOP</button>
      <input type="number" id="fp-timeout" value="1" min="0.5" max="10" step="0.5" style="width:70px;background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:17px;margin-left:12px"> <label style="color:var(--dim);font-size:15px">s timeout</label>
      <button class="btn" onclick="closeFuzzPopup()" style="margin-left:auto">\u2715</button>
    </div>
    <div style="margin-bottom:8px;display:flex;align-items:center;gap:8px">
      <label style="color:var(--dim);font-size:13px">Replay macro:</label>
      <select id="fp-macro" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:14px">${macroOpts}</select>
      <button class="btn" onclick="openMacroEditor()" style="font-size:12px;padding:2px 8px" title="Create/Edit macro">EDIT</button>
    </div>
    <div id="fp-status" style="color:var(--dim);margin-bottom:4px"></div>
    <div class="fuzz-progress" id="fp-progress" style="display:none"><div class="fuzz-progress-fill" id="fp-progress-fill"></div></div>
    <div id="fp-results" style="max-height:400px;overflow-y:auto">
      <table style="table-layout:fixed;width:100%"><thead><tr><th style="width:45%">Payload</th><th style="width:20%">Wordlist</th><th style="width:25%">Status</th><th style="width:10%">Diff</th></tr></thead>
      <tbody id="fp-results-table"></tbody></table>
      <div class="fuzz-summary" id="fp-summary"></div>
    </div>
  </div>`;
  document.body.appendChild(overlay);
}

function closeFuzzPopup() {
  fuzzPopupStop();
  const el = document.getElementById('fuzz-overlay');
  if (el) el.remove();
  fuzzField = null;
}

async function fuzzPopupStart() {
  if (!fuzzField) return;
  const key = 'ENTER';
  const t = parseFloat(document.getElementById('fp-timeout').value) || 1;
  const macro = document.getElementById('fp-macro').value || '';
  const r = await post('/api/inject/fuzz', {
    field: {row: fuzzField.row, col: fuzzField.col, length: fuzzField.length,
            hidden: !!fuzzField.hidden, numeric: !!fuzzField.numeric},
    key: key, timeout: t, macro: macro
  });
  if (!r.ok) { toast(r.message, 'error'); return; }
  document.getElementById('fp-status').textContent = r.message;
  document.getElementById('fp-start').style.display = 'none';
  document.getElementById('fp-stop').style.display = '';
  document.getElementById('fp-progress').style.display = 'block';
  fuzzPoller = setInterval(fuzzPopupPoll, 800);
}

async function fuzzPopupStop() {
  if (fuzzPoller) { clearInterval(fuzzPoller); fuzzPoller = null; }
  await post('/api/inject/fuzz/stop').catch(()=>{});
  const startBtn = document.getElementById('fp-start');
  const stopBtn = document.getElementById('fp-stop');
  if (startBtn) startBtn.style.display = '';
  if (stopBtn) stopBtn.style.display = 'none';
}

async function fuzzPopupPoll() {
  try {
    const s = await api('/api/inject_status');
    const statusEl = document.getElementById('fp-status');
    if (statusEl) statusEl.textContent = s.message;
    if (s.progress && s.progress.total > 0) {
      const pct = Math.round(s.progress.current / s.progress.total * 100);
      const fill = document.getElementById('fp-progress-fill');
      if (fill) fill.style.width = pct + '%';
    }
    // Load results
    const d = await api('/api/inject/fuzz/results');
    const tbody = document.getElementById('fp-results-table');
    const sumEl = document.getElementById('fp-summary');
    if (tbody && d.results) {
      tbody.innerHTML = '';
      for (const r of d.results) {
        const tr = document.createElement('tr');
        const col = FUZZ_STATUS_COLORS[r.status] || 'var(--fg)';
        const diffHtml = r.diff && r.diff.length > 0
          ? '<span class="fuzz-diff" title="'+r.diff.map(d=>'R'+d.row+': '+esc(d.got)).join('&#10;')+'">\u0394'+r.diff.length+'</span>'
          : '';
        const statusText = r.abend_code ? r.status+' ('+r.abend_code+')' : r.status;
        const recIcon = r.recovered ? ' <span title="Recovery needed" style="color:#4ec9b0">\u21bb</span>' : '';
        const src = (r.source||'').replace('.txt','');
        tr.innerHTML = '<td title="'+esc(r.payload)+'">'+esc(r.payload)+'</td><td style="color:var(--dim)" title="'+src+'">'+src+'</td><td style="color:'+col+'">'+statusText+recIcon+'</td><td>'+diffHtml+'</td>';
        tbody.appendChild(tr);
      }
      if (sumEl) {
        const parts = Object.entries(d.summary).map(([k,v]) => k+':'+v);
        sumEl.textContent = d.results.length + ' payloads — ' + parts.join(', ');
      }
    }
    if (!s.running) {
      if (fuzzPoller) { clearInterval(fuzzPoller); fuzzPoller = null; }
      const startBtn = document.getElementById('fp-start');
      const stopBtn = document.getElementById('fp-stop');
      const progEl = document.getElementById('fp-progress');
      if (startBtn) startBtn.style.display = '';
      if (stopBtn) stopBtn.style.display = 'none';
      if (progEl) progEl.style.display = 'none';
      toast('Fuzz complete', 'success');
    }
  } catch(e) {}
}

// ---- Macro Editor ----
const MACRO_ACTIONS = ['SEND', 'FIELD', 'WAIT', 'AID', 'CLEAR'];
const AID_KEYS = ['ENTER','CLEAR','PF1','PF2','PF3','PF4','PF5','PF6','PF7','PF8','PF9','PF10','PF11','PF12','PF13','PF14','PF15','PF16','PF17','PF18','PF19','PF20','PF21','PF22','PF23','PF24','PA1','PA2','PA3'];

function openMacroEditor(file) {
  if (document.getElementById('macro-editor-overlay')) return;
  const overlay = document.createElement('div');
  overlay.id = 'macro-editor-overlay';
  overlay.className = 'fuzz-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) closeMacroEditor(); };
  overlay.innerHTML = `<div class="fuzz-popup" style="width:min(600px,90vw)">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <h3 style="margin:0">Macro Editor</h3>
      <button class="btn" onclick="closeMacroEditor()">\u2715</button>
    </div>
    <div style="margin-bottom:8px;display:flex;gap:8px;align-items:center">
      <label style="color:var(--dim);font-size:13px">Name:</label>
      <input type="text" id="me-name" value="" placeholder="my-navigation" style="flex:1;background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:14px">
      <label style="color:var(--dim);font-size:13px">Load:</label>
      <select id="me-load" onchange="macroEditorLoad()" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:14px">
        <option value="">-- New --</option>
      </select>
    </div>
    <div id="me-steps" style="max-height:400px;overflow-y:auto"></div>
    <div style="margin-top:8px;display:flex;gap:8px">
      <button class="btn" onclick="macroEditorAddStep()">+ Step</button>
      <button class="btn" onclick="macroEditorSave()" style="margin-left:auto">SAVE</button>
    </div>
    <div id="me-status" style="color:var(--dim);margin-top:4px;font-size:13px"></div>
  </div>`;
  document.body.appendChild(overlay);
  macroEditorLoadList();
  if (file) {
    document.getElementById('me-load').value = file;
    macroEditorLoad();
  } else {
    macroEditorAddStep();
  }
}

function closeMacroEditor() {
  const el = document.getElementById('macro-editor-overlay');
  if (el) el.remove();
}

async function macroEditorLoadList() {
  const r = await api('/api/macro/list').catch(()=>({files:[]}));
  const sel = document.getElementById('me-load');
  if (!sel) return;
  const old = sel.value;
  sel.innerHTML = '<option value="">-- New --</option>';
  (r.files||[]).forEach(f => {
    const o = document.createElement('option');
    o.value = f; o.textContent = f.replace('.json','');
    sel.appendChild(o);
  });
  if (old) sel.value = old;
}

async function macroEditorLoad() {
  const file = document.getElementById('me-load').value;
  if (!file) { document.getElementById('me-steps').innerHTML = ''; macroEditorAddStep(); return; }
  const r = await post('/api/macro/load', {file: file}).catch(()=>({ok:false}));
  if (!r.ok) { toast('Failed to load macro', 'error'); return; }
  document.getElementById('me-name').value = r.name || file.replace('.json','');
  const container = document.getElementById('me-steps');
  container.innerHTML = '';
  (r.steps||[]).forEach(s => macroEditorAddStep(s));
}

function macroEditorAddStep(step) {
  const container = document.getElementById('me-steps');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'me-step';
  div.style.cssText = 'display:flex;gap:6px;align-items:center;margin-bottom:4px;padding:4px;border:1px solid var(--border);border-radius:4px';
  const action = (step && step.action) || 'SEND';
  let actOpts = MACRO_ACTIONS.map(a => '<option value="'+a+'"'+(a===action?' selected':'')+'>'+a+'</option>').join('');
  let aidOpts = AID_KEYS.map(k => '<option value="'+k+'"'+(step && step.key===k?' selected':'')+'>'+k+'</option>').join('');
  const text = step ? esc(step.text||'') : '';
  const aid = step ? (step.aid||'ENTER') : 'ENTER';
  let aidSendOpts = AID_KEYS.map(k => '<option value="'+k+'"'+(k===aid?' selected':'')+'>'+k+'</option>').join('');
  const timeout = step ? (step.timeout||3) : 3;
  const inputStyle = 'background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:2px 4px;font-family:inherit;font-size:13px';
  div.innerHTML = `
    <select class="me-action" onchange="macroEditorUpdateFields(this)" style="${inputStyle};width:70px">${actOpts}</select>
    <input class="me-text" placeholder="text" value="${text}" style="flex:1;${inputStyle};padding:2px 6px">
    <select class="me-aid-send" style="${inputStyle};width:75px">${aidSendOpts}</select>
    <select class="me-aid-key" style="${inputStyle};width:75px;display:none">${aidOpts}</select>
    <input class="me-timeout" type="number" value="${timeout}" min="1" max="30" style="width:45px;${inputStyle};display:none" title="Timeout (s)">
    <button class="btn" onclick="this.parentElement.remove()" style="font-size:11px;padding:1px 6px;color:var(--alert)">\u2715</button>`;
  container.appendChild(div);
  macroEditorUpdateFields(div.querySelector('.me-action'));
}

function macroEditorUpdateFields(sel) {
  const row = sel.parentElement;
  const action = sel.value;
  const textEl = row.querySelector('.me-text');
  const aidSendEl = row.querySelector('.me-aid-send');
  const aidKeyEl = row.querySelector('.me-aid-key');
  const timeoutEl = row.querySelector('.me-timeout');
  const needsText = (action === 'SEND' || action === 'WAIT' || action === 'FIELD');
  textEl.style.display = needsText ? '' : 'none';
  aidSendEl.style.display = action === 'SEND' ? '' : 'none';
  aidKeyEl.style.display = action === 'AID' ? '' : 'none';
  timeoutEl.style.display = action === 'WAIT' ? '' : 'none';
  if (action === 'SEND') textEl.placeholder = 'text to send';
  if (action === 'WAIT') textEl.placeholder = 'text to wait for';
  if (action === 'FIELD') textEl.placeholder = 'value (auto-fills next input field)';
}

async function macroEditorSave() {
  const name = document.getElementById('me-name').value.trim();
  if (!name) { toast('Macro name required', 'error'); return; }
  const steps = [];
  document.querySelectorAll('#me-steps .me-step').forEach(row => {
    const action = row.querySelector('.me-action').value;
    const step = {action: action};
    if (action === 'SEND') {
      step.text = row.querySelector('.me-text').value;
      step.aid = row.querySelector('.me-aid-send').value;
    } else if (action === 'FIELD') {
      step.text = row.querySelector('.me-text').value;
    } else if (action === 'WAIT') {
      step.text = row.querySelector('.me-text').value;
      step.timeout = parseInt(row.querySelector('.me-timeout').value) || 3;
    } else if (action === 'AID') {
      step.key = row.querySelector('.me-aid-key').value;
    }
    steps.push(step);
  });
  if (steps.length === 0) { toast('Add at least one step', 'error'); return; }
  const r = await post('/api/macro/save', {name: name, steps: steps});
  if (r.ok) {
    toast(r.message, 'success');
    document.getElementById('me-status').textContent = r.message;
    // Refresh macro dropdowns
    macroEditorLoadList();
    loadMacroList();
    // Refresh fuzz popup dropdown if open
    const fpMacro = document.getElementById('fp-macro');
    if (fpMacro) {
      const ml = await api('/api/macro/list').catch(()=>({files:[]}));
      fpMacro.innerHTML = '<option value="">No replay macro</option>';
      (ml.files||[]).forEach(f => { fpMacro.innerHTML += '<option value="'+esc(f)+'">'+esc(f.replace('.json',''))+'</option>'; });
      if (r.file) fpMacro.value = r.file;
    }
  } else {
    toast(r.message, 'error');
    document.getElementById('me-status').textContent = r.message;
  }
}

</script>
</body>
</html>
"""
