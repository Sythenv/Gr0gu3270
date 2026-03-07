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
        self.disabled_tabs = []
        self.shutdown_flag = threading.Event()
        self.connection_ready = threading.Event()
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
                'hack_color_on': bool(self.h.hack_color_on),
                'abend_detection': bool(self.h.abend_detection),
                'transaction_tracking': bool(self.h.transaction_tracking),
                'aid_scan_running': bool(self.h.aid_scan_running),
                'disabled_tabs': self.disabled_tabs,
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

    def set_hack_color(self, data):
        with self.lock:
            if 'sfe' in data: self.h.set_hack_color_sfe(int(data['sfe']))
            if 'mf' in data: self.h.set_hack_color_mf(int(data['mf']))
            if 'sa' in data: self.h.set_hack_color_sa(int(data['sa']))
            if 'hv' in data: self.h.set_hack_color_hv(int(data['hv']))
            if 'on' in data:
                self.h.set_hack_color_on(int(data['on']))
                self.h.set_hack_color_toggled()

    def _select_wordlists(self, field):
        """Auto-select wordlists based on field attributes."""
        inj_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'injections')
        is_hidden = field.get('hidden', False)
        is_numeric = field.get('numeric', False)

        if is_hidden:
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
        timeout = float(data.get('timeout', 1))
        delay = float(data.get('delay', 0.1))

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
        self.fuzz_progress = {'current': 0, 'total': len(lines), 'payload': '', 'source': ''}
        self.fuzz_results = []
        self.inject_status_msg = 'Fuzz starting ({} payloads from {})...'.format(
            len(lines), ', '.join(sources))
        self.inject_thread = threading.Thread(
            target=self._fuzz_worker,
            args=([field], lines, key_mode, timeout, delay, txn_code),
            daemon=True)
        self.inject_thread.start()
        return {'ok': True, 'message': 'Fuzz started: {} payloads from {}'.format(
            len(lines), ', '.join(sources))}

    def _fuzz_worker(self, fields, lines_with_source, key_mode, timeout=1, delay=0.1, txn_code=None):
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
                    idx + 1, len(lines_with_source), line, source_file)
                self.fuzz_progress['current'] = idx + 1
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
                    # Distinguish navigation from same-screen acceptance
                    if classification == 'ACCESSIBLE' and similarity >= 0 and similarity <= sim_threshold:
                        classification = 'NAVIGATED'
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
                            self.h.emit_finding('HIGH', 'FUZZER',
                                                'Payload "{}" ({}) caused ABEND {} on field {}'.format(
                                                    line[:60], source_file, abend_code or '?', field_loc),
                                                txn_code=txn_code,
                                                dedup_key='FUZZER:ABEND:{}:{}'.format(abend_code or '?', line[:60]))
                    elif classification == 'DENIED':
                        with self.lock:
                            self.h.emit_finding('MEDIUM', 'FUZZER',
                                                'Payload "{}" ({}) denied by ESM on field {}'.format(
                                                    line[:60], source_file, field_loc),
                                                txn_code=txn_code,
                                                dedup_key='FUZZER:DENIED:{}'.format(line[:60]))
                    elif classification == 'NAVIGATED':
                        with self.lock:
                            self.h.emit_finding('MEDIUM', 'FUZZER',
                                                'Payload "{}" ({}) changed screen on field {}'.format(
                                                    line[:60], source_file, field_loc),
                                                txn_code=txn_code,
                                                dedup_key='FUZZER:NAVIGATED:{}'.format(line[:60]))
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
                    fk_response = self.h._aid_scan_send_and_read(fk_payload, timeout=1)
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
                            if txn_code:
                                # Simple recovery: CLEAR + re-send txn code
                                clear_p = self.h.build_clear_payload(is_tn3270e)
                                txn_p = self.h.build_txn_payload(txn_code, is_tn3270e)
                                self.h._aid_scan_send_and_read(clear_p, timeout=1)
                                last_resp = self.h._aid_scan_send_and_read(txn_p, timeout=2)
                            else:
                                # Fallback: full replay if no txn code
                                with self.lock:
                                    self.h.aid_scan_replay_path = replay_path
                                    last_resp = self.h.aid_scan_replay()
                            if last_resp:
                                sim2 = self.h.screen_similarity(last_resp, ref_screen)
                                if sim2 > sim_threshold:
                                    recovered = True
                                    recovery_count += 1
                                    try:
                                        self.h.client.send(last_resp)
                                        self.h.client.flush()
                                    except Exception:
                                        pass
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
                     'txn_code': r[4], 'message': r[5]} for r in rows]

    def get_findings_summary(self):
        with self.lock:
            self.h.sql_cur.execute("SELECT SEVERITY, COUNT(*) FROM Findings GROUP BY SEVERITY")
            counts = {r[0]: r[1] for r in self.h.sql_cur.fetchall()}
            return {'CRIT': counts.get('CRIT', 0), 'HIGH': counts.get('HIGH', 0),
                    'MEDIUM': counts.get('MEDIUM', 0), 'INFO': counts.get('INFO', 0),
                    'total': sum(counts.values())}

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

    def _macro_worker(self, steps):
        try:
            with self.lock:
                is_tn3270e = self.h.check_inject_3270e()
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
                else:
                    with self.lock:
                        payload = self.h.build_macro_step_payload(step, is_tn3270e)
                    server_data = self.h._aid_scan_send_and_read(payload, timeout=5)
                    if server_data:
                        with self.lock:
                            self.h.client.send(server_data)
                            self.h.client.flush()
                            self.h.write_database_log('S', 'macro', server_data)
                    with self.lock:
                        self.h.write_database_log('C', 'macro', payload)
                    time.sleep(0.3)
        except Exception as e:
            self.macro_error = 'Macro error: {}'.format(e)
        finally:
            self.macro_running = False

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

    def toggle_abend_detection(self):
        with self.lock:
            current = self.h.get_abend_detection()
            self.h.set_abend_detection(0 if current else 1)
            return {'on': bool(self.h.get_abend_detection())}

    def toggle_transaction_tracking(self):
        with self.lock:
            current = self.h.get_transaction_tracking()
            self.h.set_transaction_tracking(0 if current else 1)
            return {'on': bool(self.h.get_transaction_tracking())}

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

    def aid_scan_start(self):
        if not self.connection_ready.is_set():
            return {'ok': False, 'message': 'Not connected.'}
        if self.h.aid_scan_running:
            return {'ok': False, 'message': 'AID scan already running.'}

        with self.lock:
            self.h.aid_scan_start()

        self.aid_scan_thread = threading.Thread(
            target=self._aid_scan_worker, daemon=True)
        self.aid_scan_thread.start()
        return {'ok': True, 'message': 'AID scan started ({} keys)...'.format(
            len(self.h.aid_scan_keys))}

    def _aid_scan_worker(self):
        try:
            while True:
                if self.shutdown_flag.is_set():
                    break

                with self.lock:
                    if not self.h.get_aid_scan_running():
                        break
                    result = self.h.aid_scan_next()
                    if result is None:
                        break

                # Pause between tests to let mainframe settle
                time.sleep(0.3)

        except Exception as e:
            logging.getLogger(__name__).error("AID scan error: {}".format(e))
        finally:
            with self.lock:
                self.h.aid_scan_stop()

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
            summary = {'VIOLATION': [], 'NEW_SCREEN': [], 'SAME_SCREEN': [], 'TIMEOUT': [], 'SKIPPED': []}
            for r in results:
                cat = r.get('category', 'TIMEOUT')
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
                    key=lambda r: {'VIOLATION': 0, 'NEW_SCREEN': 1, 'TIMEOUT': 2, 'SAME_SCREEN': 3, 'SKIPPED': 4}.get(r.get('category', ''), 5))
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
        while True:
            try:
                label, payload = self._cmd_queue.get_nowait()
            except queue.Empty:
                break
            try:
                with self.lock:
                    self.h.write_database_log('C', label, payload)
                self.h.server.send(payload)
            except OSError:
                pass

        # 2. Flush any pending client send buffer
        client = self.h.client
        if hasattr(client, 'flush'):
            client.flush()

        # 3. Run proxy loop (reads both sockets, processes data)
        with self.lock:
            if self.h.is_offline():
                return
            if self.h.aid_scan_running:
                return
            if self.inject_running:
                return
            try:
                self.h.daemon()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            except Exception:
                pass


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
            self._send_json(self.state.get_logs(since))
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
            self._send_json(self.state.get_screen_map())
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
        else:
            self._send_json({'error': 'not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_body()

        if path == '/api/hack_fields':
            self.state.set_hack_fields(data)
            self._send_json({'ok': True})
        elif path == '/api/hack_color':
            self.state.set_hack_color(data)
            self._send_json({'ok': True})
        elif path == '/api/send_keys':
            result = self.state.send_keys(data)
            self._send_json(result)
        elif path == '/api/send_text':
            result = self.state.send_text(data)
            self._send_json(result)
        elif path == '/api/abend_detection':
            result = self.state.toggle_abend_detection()
            self._send_json(result)
        elif path == '/api/transaction_tracking':
            result = self.state.toggle_transaction_tracking()
            self._send_json(result)
        elif path == '/api/export_csv':
            result = self.state.export_csv()
            self._send_json(result)
        elif path == '/api/aid_scan/start':
            result = self.state.aid_scan_start()
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
        elif path == '/api/spool/check':
            result = self.state.spool_check()
            self._send_json(result)
        elif path == '/api/spool/poc':
            result = self.state.spool_poc_ftp(data)
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
        while not self.state.shutdown_flag.is_set():
            self.state.run_daemon()
            time.sleep(0.01)

    def _sigint_handler(self, signum, frame):
        print("\nShutting down...")
        self._shutdown()
        sys.exit(0)

    def _shutdown(self):
        self.state.shutdown_flag.set()
        try:
            self.httpd.shutdown()
        except Exception:
            pass
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
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Consolas','Monaco','Courier New',monospace; background: var(--bg); color: var(--text); font-size: 22px; display: flex; flex-direction: column; height: 100vh; overflow: hidden; text-shadow: 0 0 5px var(--glow); padding: 0 20px; align-items: center; }
.container { max-width: 1200px; width: 100%; margin: 0 auto; display: flex; flex-direction: column; flex: 1; min-height: 0; overflow: hidden; }
body::after { content:''; position:fixed; top:0; left:0; width:100%; height:100%; pointer-events:none; z-index:9998; background: repeating-linear-gradient(0deg, rgba(0,0,0,0.06) 0px, rgba(0,0,0,0.06) 1px, transparent 1px, transparent 3px); }

/* Header */
.header { background: var(--bg); padding: 0; display: flex; align-items: stretch; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.header-grogu { color: #00969a; font-size: 5px; line-height: 1.1; white-space: pre; padding: 2px 8px; display: flex; align-items: center; text-shadow: 0 0 6px #00969a; opacity: 0.8; border-right: 1px solid var(--border); }
.header-left { display: flex; flex-direction: column; flex: 1; min-width: 0; justify-content: flex-end; }
.header .h-title { background: var(--head); color: var(--bg); padding: 5px 10px; font-size: 22px; font-weight: bold; }
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
.panel-findings { flex-shrink:0; max-height:140px; border-bottom:1px solid var(--border); display:flex; flex-direction:column; overflow:hidden; }
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

/* Accordion tool bar */
/* Toolbar (top groups) */
.toolbar-btn { background: var(--bg); color: var(--dim); border: none; border-right: 1px solid var(--border); padding: 5px 14px; font-family: inherit; font-size: 17px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer; transition: all 0.15s; }
.toolbar-btn:hover { color: var(--text); }
.toolbar-btn.active { background: var(--head); color: var(--bg); text-shadow: none; }
.toolbar-panel { flex-shrink: 0; display: none; border-bottom: 1px solid var(--border); }
.toolbar-panel.open { display: block; }
.toolbar-panel .accordion-tabs { border-bottom: 1px solid var(--border); }

/* Bottom accordion (GUIDE) */
.action-bar { flex-shrink: 0; border-top: 1px solid var(--border); display: flex; flex-direction: column; overflow-y: auto; max-height: 50vh; scrollbar-width: none; }
.action-bar::-webkit-scrollbar { display: none; }
.accordion-group { border-bottom: 1px solid var(--border); }
.accordion-header { display: flex; align-items: center; gap: 8px; padding: 5px 10px; background: var(--bg); color: var(--text); cursor: pointer; font-size: 18px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; border: none; width: 100%; text-align: left; font-family: inherit; user-select: none; }
.accordion-header:hover { background: #0f1a0f; }
.accordion-header .arrow { color: var(--dim); font-size: 15px; transition: transform 0.15s; }
.accordion-header.open .arrow { transform: rotate(90deg); }
.accordion-header.open { background: var(--head); color: var(--bg); text-shadow: none; }
.accordion-body { display: none; border-top: 1px solid var(--border); }
.accordion-body.open { display: block; }
.accordion-tabs { display: flex; background: var(--bg); border-bottom: 1px solid var(--border); }
.accordion-tabs button { background: transparent; color: var(--dim); border: none; padding: 4px 10px; cursor: pointer; font-family: inherit; font-size: 15px; text-transform: uppercase; transition: all 0.15s; }
.accordion-tabs button:hover { color: var(--text); }
.accordion-tabs button.active { color: var(--bg); background: var(--head); }
.action-panel { display: none; padding: 8px 12px; background: var(--bg); max-height: 220px; overflow-y: auto; scrollbar-width: none; }
.action-panel::-webkit-scrollbar { display: none; }
.action-panel.tall { max-height: min(55vh, calc(100vh - 160px)); }
.action-panel.active { display: block; }

/* Hide old tab bar — we use accordion now */
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
.fuzz-popup table { width:100%; }
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
.status-accessible { background: rgba(0,108,77,0.15); }
.status-denied { background: rgba(255,21,31,0.1); }
.status-abend { background: rgba(255,21,31,0.06); }
.status-not_found { background: rgba(0,77,64,0.1); }
.status-error { background: rgba(255,21,31,0.08); }
.summary-bar { display: flex; gap: 12px; flex-wrap: wrap; padding: 6px 10px; background: var(--input-bg); border: 1px solid var(--border); margin-bottom: 6px; font-size: 17px; }
.summary-bar span { display: flex; align-items: center; gap: 3px; }
.dot { width: 8px; height: 8px; display: inline-block; }
.dot-accessible { background: var(--text); }
.dot-denied { background: var(--alert); }
.dot-abend { background: var(--alert); opacity: 0.6; }
.dot-not_found { background: var(--dim); }
.dot-error { background: var(--alert); opacity: 0.4; }
.checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 2px; }
.inject-status { padding: 6px 10px; background: var(--input-bg); border: 1px solid var(--border); margin-top: 4px; font-size: 17px; min-height: 24px; }
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
#splash .splash-title { background: var(--head); color: var(--bg); padding: 4px 24px; font-size: 30px; font-weight: bold; margin-bottom: 12px; text-shadow: none; }
#splash .splash-status { color: var(--text); font-size: 20px; }
@keyframes blink { 0%,49% { opacity: 1; } 50%,100% { opacity: 0; } }
#splash .splash-cursor { animation: blink 1s step-end infinite; }
</style>
</head>
<body>
<!-- SPLASH SCREEN -->
<div id="splash">
  <div class="splash-title">Gr0gu3270</div>
  <div class="splash-status" id="splash-status"><span class="splash-cursor">_</span> CONNECTING...</div>
</div>

<div class="toast-container" id="toast-container"></div>

<div class="container">
<!-- HEADER -->
<div class="header">
  <pre class="header-grogu">
⠀⢀⣠⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⡾⠿⠿⠿⠿⢷⣶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⡟⠛⠛⠛⠻⠿⠿⢿⣶⣶⣦⣤⣤⣀⣀⡀⣀⣴⣾⡿⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⢿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⡀
⠀⠻⣿⣦⡀⠀⠉⠓⠶⢦⣄⣀⠉⠉⠛⠛⠻⠿⠟⠋⠁⠀⠀⠀⣤⡀⠀⠀⢠⠀⠀⠀⣠⠀⠀⠀⠀⠈⠙⠻⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠛⢻⣿
⠀⠀⠈⠻⣿⣦⠀⠀⠀⠀⠈⠙⠻⢷⣶⣤⡀⠀⠀⠀⠀⢀⣀⡀⠀⠙⢷⡀⠸⡇⠀⣰⠇⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⡶⠶⠶⠒⠂⠀⠀⣠⣾⠟
⠀⠀⠀⠀⠈⢿⣷⡀⠀⠀⠀⠀⠀⠀⠈⢻⣿⡄⣠⣴⣿⣯⣭⣽⣷⣆⠀⠁⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣦⡀⠀⣠⣾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⣠⣾⡟⠁⠀
⠀⠀⠀⠀⠀⠈⢻⣷⣄⠀⠀⠀⠀⠀⠀⠀⣿⡗⢻⣿⣧⣽⣿⣿⣿⣧⠀⠀⣀⣀⠀⢠⣿⣧⣼⣿⣿⣿⣿⠗⠰⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⡿⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⢿⣶⣄⡀⠀⠀⠀⠀⠸⠃⠈⠻⣿⣿⣿⣿⣿⡿⠃⠾⣥⡬⠗⠸⣿⣿⣿⣿⣿⡿⠛⠀⢀⡟⠀⠀⠀⠀⠀⠀⣀⣠⣾⡿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣷⣶⣤⣤⣄⣰⣄⠀⠀⠉⠉⠉⠁⠀⢀⣀⣠⣄⣀⡀⠀⠉⠉⠉⠀⠀⢀⣠⣾⣥⣤⣤⣤⣶⣶⡿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢻⣿⠛⢿⣷⣦⣤⣴⣶⣶⣦⣤⣤⣤⣤⣬⣥⡴⠶⠾⠿⠿⠿⠿⠛⢛⣿⣿⣿⣯⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣧⡀⠈⠉⠀⠈⠁⣾⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⠟⠉⣹⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣸⣿⣿⣦⣀⠀⠀⠀⢻⡀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⠋⣿⠛⠃⠀⣈⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡿⢿⡀⠈⢹⡿⠶⣶⣼⡇⠀⢀⣀⣀⣤⣴⣾⠟⠋⣡⣿⡟⠀⢻⣶⠶⣿⣿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣷⡈⢿⣦⣸⠇⢀⡿⠿⠿⡿⠿⠿⣿⠛⠋⠁⠀⣴⠟⣿⣧⡀⠈⢁⣰⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢻⣦⣈⣽⣀⣾⠃⠀⢸⡇⠀⢸⡇⠀⢀⣠⡾⠋⢰⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⢿⣿⣿⡟⠛⠃⠀⠀⣾⠀⠀⢸⡇⠐⠿⠋⠀⠀⣿⢻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠁⢀⡴⠋⠀⣿⠀⠀⢸⠇⠀⠀⠀⠀⠀⠁⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠟⠋⠀⠀⠀⣿⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣁⣀⠀⠀⠀⠀⣿⡀⠀⣿⠀⠀⠀⠀⠀⠀⢀⣈⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
  </pre>
  <div class="header-left">
    <div class="header-bottom">
      <span class="h-title">Gr0gu3270</span>
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
      </div>
      <div class="toggles">
        <div class="toggle-pill" id="tgl-hack" onclick="toggleHackFields()" title="Hack Fields">H</div>
        <div class="toggle-pill" id="tgl-color" onclick="toggleHackColor()" title="Hack Color">C</div>
        <div class="toggle-pill on" id="tgl-abend" style="display:none">A</div>
        <div class="toggle-pill on" id="tgl-txn" style="display:none">T</div>
        <div class="toggle-pill" onclick="toggleHelpModal()" title="Method &amp; Help" style="font-weight:bold">?</div>
      </div>
    </div>
  </div>
</div>
<div class="toolbar-panel" id="toolbar-panel"></div>

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
        <th style="width:16px"></th><th>Source</th><th>TXN</th><th>Finding</th><th>Time</th>
      </tr></thead><tbody id="findings-table"></tbody></table>
    </div>
  </div>
</div>

<!-- TOOL ACCORDION -->
<div class="action-bar" id="tool-accordion"></div>

<!-- Hidden legacy containers for buildActionBar compat -->
<div style="display:none">
  <div id="action-tabs"></div>
  <div id="action-panels"></div>
</div>

<!-- OIA BAR -->
<div class="oia-bar">
  <span class="oia-conn" id="oia-conn">DISCONNECTED</span>
  <span id="oia-target"></span>
  <span>F:<b id="oia-findings">0</b> C:<b id="oia-crit">0</b> H:<b id="oia-high">0</b></span>
  <span class="oia-right" id="oia-version"></span>
</div>
</div><!-- /container -->

<script>
// ---- CSS variable bridge ----
const CS = getComputedStyle(document.documentElement);
const C = {text:CS.getPropertyValue('--text').trim(), head:CS.getPropertyValue('--head').trim(), dim:CS.getPropertyValue('--dim').trim(), alert:CS.getPropertyValue('--alert').trim()};
// ---- Action tabs config ----
const ACTIONS = [
  {id:'hack-fields', label:'Hack Fields', group:0},
  {id:'hack-color', label:'Hack Color', group:0},
  {id:'inject-keys', label:'Send Keys', group:0},
  {id:'aid-scan', label:'AID Scan', group:0},
  {id:'spool', label:'SPOOL/RCE', group:1},
  {id:'logs', label:'Logs', group:2, tall:true},
  {id:'statistics', label:'Stats', group:2},
];

const GROUPS = [
  {id:'grp-hacks', label:'HACKS', items:['hack-fields','hack-color','inject-keys','aid-scan'], location:'top'},
  {id:'grp-system', label:'SYSTEM', items:['spool'], location:'top'},
  {id:'grp-data', label:'DATA', items:['logs','statistics'], location:'top'},
];

let activeAction = null;
let activeGroup = null;
let pollers = {};
let disabledTabs = [];
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
    tr.innerHTML = '<td><span class="sev-dot sev-'+s+'"></span></td>'
      +'<td><span class="finding-src">'+esc(f.source)+'</span></td>'
      +'<td>'+esc(f.txn_code||'')+'</td>'
      +'<td>'+esc(f.message)+'</td>'
      +'<td>'+esc((f.timestamp_fmt||'').split(' ')[1]||'')+'</td>';
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

// ---- Build toolbar + accordion ----
function buildActionBar() {
  const toolbar = document.getElementById('toolbar');
  const tbPanel = document.getElementById('toolbar-panel');
  const acc = document.getElementById('tool-accordion');
  // Also create hidden legacy panels for buildActionPanels compat
  const legacyPanels = document.getElementById('action-panels');
  ACTIONS.forEach(a => {
    const panel = document.createElement('div');
    panel.className = 'action-panel' + (a.tall ? ' tall' : '');
    panel.id = 'apanel-' + a.id;
    legacyPanels.appendChild(panel);
    const btn = document.createElement('button');
    btn.id = 'atab-btn-' + a.id;
    btn.style.display = 'none';
    legacyPanels.appendChild(btn);
  });

  GROUPS.forEach(g => {
    if (g.location === 'top') {
      // Toolbar button
      const btn = document.createElement('button');
      btn.className = 'toolbar-btn';
      btn.id = 'tb-' + g.id;
      btn.textContent = g.label;
      btn.onclick = () => toggleGroup(g.id);
      toolbar.appendChild(btn);
      // Panel content inside shared toolbar-panel
      const wrapper = document.createElement('div');
      wrapper.id = g.id + '-wrapper';
      wrapper.style.display = 'none';
      if (g.items.length > 1) {
        const tabs = document.createElement('div');
        tabs.className = 'accordion-tabs';
        tabs.id = g.id + '-tabs';
        g.items.forEach(aid => {
          const a = ACTIONS.find(x => x.id === aid);
          const tb = document.createElement('button');
          tb.textContent = a.label;
          tb.id = 'subtab-' + aid;
          tb.onclick = () => showTool(g.id, aid);
          tabs.appendChild(tb);
        });
        wrapper.appendChild(tabs);
      }
      const pc = document.createElement('div');
      pc.id = g.id + '-panels';
      g.items.forEach(aid => {
        const a = ACTIONS.find(x => x.id === aid);
        const p = document.createElement('div');
        p.className = 'action-panel' + (a.tall ? ' tall' : '');
        p.id = 'acc-panel-' + aid;
        pc.appendChild(p);
      });
      wrapper.appendChild(pc);
      tbPanel.appendChild(wrapper);
    } else {
      // Bottom accordion (GUIDE)
      const group = document.createElement('div');
      group.className = 'accordion-group';
      group.id = g.id;
      const hdr = document.createElement('button');
      hdr.className = 'accordion-header';
      hdr.innerHTML = '<span class="arrow">&#9654;</span> ' + g.label;
      hdr.onclick = () => toggleGroup(g.id);
      group.appendChild(hdr);
      const body = document.createElement('div');
      body.className = 'accordion-body';
      body.id = g.id + '-body';
      if (g.items.length > 1) {
        const tabs = document.createElement('div');
        tabs.className = 'accordion-tabs';
        tabs.id = g.id + '-tabs';
        g.items.forEach(aid => {
          const a = ACTIONS.find(x => x.id === aid);
          const tb = document.createElement('button');
          tb.textContent = a.label;
          tb.id = 'subtab-' + aid;
          tb.onclick = (e) => { e.stopPropagation(); showTool(g.id, aid); };
          tabs.appendChild(tb);
        });
        body.appendChild(tabs);
      }
      const pc = document.createElement('div');
      pc.id = g.id + '-panels';
      g.items.forEach(aid => {
        const a = ACTIONS.find(x => x.id === aid);
        const p = document.createElement('div');
        p.className = 'action-panel' + (a.tall ? ' tall' : '');
        p.id = 'acc-panel-' + aid;
        pc.appendChild(p);
      });
      body.appendChild(pc);
      group.appendChild(body);
      acc.appendChild(group);
    }
  });
  buildActionPanels();
  ACTIONS.forEach(a => {
    const src = document.getElementById('apanel-' + a.id);
    const dst = document.getElementById('acc-panel-' + a.id);
    if (src && dst) { dst.innerHTML = src.innerHTML; }
  });
}

function toggleGroup(gid) {
  const g = GROUPS.find(x => x.id === gid);
  if (!g) return;
  const isTop = g.location === 'top';
  const tbPanel = document.getElementById('toolbar-panel');

  if (activeGroup === gid) {
    // Close
    if (isTop) {
      document.getElementById('tb-' + gid).classList.remove('active');
      document.getElementById(gid + '-wrapper').style.display = 'none';
      tbPanel.classList.remove('open');
    } else {
      document.querySelector('#' + gid + ' .accordion-header').classList.remove('open');
      document.getElementById(gid + '-body').classList.remove('open');
    }
    activeGroup = null;
    activeAction = null;
    stopActionPollers();
    return;
  }
  // Close previous
  if (activeGroup) {
    const prev = GROUPS.find(x => x.id === activeGroup);
    if (prev && prev.location === 'top') {
      document.getElementById('tb-' + prev.id).classList.remove('active');
      document.getElementById(prev.id + '-wrapper').style.display = 'none';
    } else if (prev) {
      document.querySelector('#' + prev.id + ' .accordion-header').classList.remove('open');
      document.getElementById(prev.id + '-body').classList.remove('open');
    }
  }
  // Open this
  if (isTop) {
    document.getElementById('tb-' + gid).classList.add('active');
    document.getElementById(gid + '-wrapper').style.display = 'block';
    tbPanel.classList.add('open');
  } else {
    document.querySelector('#' + gid + ' .accordion-header').classList.add('open');
    document.getElementById(gid + '-body').classList.add('open');
  }
  activeGroup = gid;
  showTool(gid, g.items[0]);
}

function showTool(gid, aid) {
  const g = GROUPS.find(x => x.id === gid);
  if (!g) return;
  // Update sub-tabs
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

function toggleAction(id) {
  // Legacy compat — find group and open it
  const g = GROUPS.find(gr => gr.items.includes(id));
  if (!g) return;
  if (activeGroup !== g.id) toggleGroup(g.id);
  showTool(g.id, id);
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

  // Hack Color
  document.getElementById('apanel-hack-color').innerHTML = `
    <div class="controls">
      <label><input type="checkbox" id="hc-sfe" checked> SFE</label>
      <label><input type="checkbox" id="hc-mf" checked> MF</label>
      <label><input type="checkbox" id="hc-sa" checked> SA</label>
      <label><input type="checkbox" id="hc-hv" checked> High Vis</label>
    </div>`;

  // Send Keys
  document.getElementById('apanel-inject-keys').innerHTML = `
    <div class="controls">
      <button class="btn" onclick="sendSelectedKeys()">Send Keys</button>
      <span id="send-keys-status" style="font-size:17px;color:var(--dim)">Ready.</span>
    </div>
    <div class="controls checkbox-grid" id="aid-checkboxes"></div>`;

  // AID Scan
  document.getElementById('apanel-aid-scan').innerHTML = `
    <div class="controls">
      <button class="btn" id="aid-scan-btn" onclick="aidScanStart()">AID SCAN</button>
      <button class="btn danger" id="aid-scan-stop-btn" onclick="aidScanStop()" style="display:none">STOP</button>
      <span id="aid-scan-progress" style="font-size:17px;color:var(--dim);margin-left:8px"></span>
    </div>
    <p style="font-size:15px;color:var(--dim);margin:4px 0 8px 0">Navigate to a screen in your emulator, then click AID SCAN. Tests 24 keys (ENTER, PF1-2, PF4-24) and auto-returns to screen.</p>
    <div id="aid-scan-summary" style="display:none;margin-bottom:8px;gap:12px;font-size:18px">
      <span style="color:var(--alert)"><b id="as-violation">0</b> VIOLATION</span>
      <span style="color:var(--head)"><b id="as-new">0</b> NEW SCREEN</span>
      <span style="color:var(--dim)"><b id="as-same">0</b> SAME</span>
      <span style="color:var(--dim)"><b id="as-timeout">0</b> TIMEOUT</span>
      <span style="color:var(--dim)"><b id="as-skipped">0</b> SKIPPED</span>
    </div>
    <table style="margin-top:4px"><thead><tr>
      <th style="text-align:center">R</th><th>Key</th><th>Category</th>
    </tr></thead><tbody id="aid-scan-table"></tbody></table>`;

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

    disabledTabs = s.disabled_tabs || [];

    // Update header toggle pills
    const hackPill = document.getElementById('tgl-hack');
    hackPill.className = s.hack_on ? 'toggle-pill on' : 'toggle-pill';
    const colorPill = document.getElementById('tgl-color');
    colorPill.className = s.hack_color_on ? 'toggle-pill on' : 'toggle-pill';
    const abendPill = document.getElementById('tgl-abend');
    abendPill.className = s.abend_detection ? 'toggle-pill on' : 'toggle-pill';
    const txnPill = document.getElementById('tgl-txn');
    txnPill.className = s.transaction_tracking ? 'toggle-pill on' : 'toggle-pill';
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
    if (!smapShowAll && !isInput && !isHidden) return;
    const tr = document.createElement('tr');
    if (isHidden) tr.className = 'field-hidden';
    else if (isInput) tr.className = 'field-input';
    else tr.className = 'field-label';
    if (isInput || isHidden) {
      tr.style.cursor = 'pointer';
      tr.ondblclick = () => openFuzzPopup(f);
    }
    const pos = smapShowAll ? '<td>'+f.row+','+f.col+'</td>' : '';
    tr.innerHTML = pos+'<td>'+(f.hidden?dot:'')+'</td><td>'+(f.numeric?dot:'')+'</td><td>'+f.length+'</td><td>'+esc(f.content)+'</td>';
    tbody.appendChild(tr);
  });
}

function toggleSmapFilter() {
  smapShowAll = !smapShowAll;
  document.getElementById('smap-filter-btn').textContent = smapShowAll ? 'FILTER' : 'SHOW ALL';
  renderScreenMap();
}

const FUZZ_STATUS_COLORS = {
  ACCESSIBLE:'#4ec9b0',NEW_SCREEN:'#4ec9b0',NAVIGATED:'#569cd6',ABEND:'#f44',DENIED:'#f90',
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
function updateBadge(name, count) {
  const el = document.getElementById('badge-' + name);
  if (!el) return;
  el.textContent = count > 99 ? '99+' : count;
  el.className = count > 0 ? 'badge' : 'badge zero';
}

// ---- Actions ----
async function toggleHackFields() {
  const pill = document.getElementById('tgl-hack');
  const on = !pill.classList.contains('on');
  const g = id => { const e = document.getElementById(id); return e ? (e.checked ? 1 : 0) : 1; };
  await post('/api/hack_fields', { on: on?1:0, prot:g('hf-prot'), hf:g('hf-hf'), rnr:g('hf-rnr'), sf:g('hf-sf'), sfe:g('hf-sfe'), mf:g('hf-mf'), ei:g('hf-ei'), hv:g('hf-hv') });
  toast('Hack Fields ' + (on ? 'ON' : 'OFF'), on ? 'success' : 'info');
}

async function toggleHackColor() {
  const pill = document.getElementById('tgl-color');
  const on = !pill.classList.contains('on');
  const g = id => { const e = document.getElementById(id); return e ? (e.checked ? 1 : 0) : 1; };
  await post('/api/hack_color', { on: on?1:0, sfe:g('hc-sfe'), mf:g('hc-mf'), sa:g('hc-sa'), hv:g('hc-hv') });
  toast('Hack Color ' + (on ? 'ON' : 'OFF'), on ? 'success' : 'info');
}

async function toggleAbend() { await post('/api/abend_detection'); toast('ABEND detection toggled', 'info'); }
async function toggleTxnTracking() { await post('/api/transaction_tracking'); toast('Transaction tracking toggled', 'info'); }

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

// ---- AID Scan ----
let aidScanPoller = null;
async function aidScanStart() {
  const r = await post('/api/aid_scan/start');
  if (!r.ok) { toast(r.message, 'error'); return; }
  toast(r.message, 'success');
  document.getElementById('aid-scan-btn').style.display = 'none';
  document.getElementById('aid-scan-stop-btn').style.display = '';
  document.getElementById('aid-scan-table').innerHTML = '';
  aidScanPoller = setInterval(aidScanPoll, 1000);
}
async function aidScanStop() {
  await post('/api/aid_scan/stop');
  if (aidScanPoller) { clearInterval(aidScanPoller); aidScanPoller = null; }
  document.getElementById('aid-scan-btn').style.display = '';
  document.getElementById('aid-scan-stop-btn').style.display = 'none';
  document.getElementById('aid-scan-progress').textContent = 'Stopped';
}
const CAT_COLORS = {VIOLATION:C.alert,NEW_SCREEN:C.text,SAME_SCREEN:C.dim,TIMEOUT:C.dim,SKIPPED:C.dim};
const CAT_ORDER = {VIOLATION:0,NEW_SCREEN:1,TIMEOUT:2,SAME_SCREEN:3,SKIPPED:4};
async function aidScanPoll() {
  const r = await fetch('/api/aid_scan/summary').then(r=>r.json());
  const s = r.summary || {};
  document.getElementById('as-violation').textContent = s.VIOLATION||0;
  document.getElementById('as-new').textContent = s.NEW_SCREEN||0;
  document.getElementById('as-same').textContent = s.SAME_SCREEN||0;
  document.getElementById('as-timeout').textContent = s.TIMEOUT||0;
  document.getElementById('as-skipped').textContent = s.SKIPPED||0;
  document.getElementById('aid-scan-progress').textContent = r.progress+'/'+r.total;
  const tb = document.getElementById('aid-scan-table');
  tb.innerHTML = '';
  (r.results||[]).forEach(row => {
    const c = CAT_COLORS[row.category]||C.dim;
    const rdot = row.replay_ok===false ? 'var(--alert)' : 'var(--text)';
    const tr = document.createElement('tr');
    const preview = (row.response_preview||'').replace(/"/g,'&quot;');
    tr.setAttribute('title', preview);
    tr.innerHTML = '<td style="text-align:center"><span style="display:block;margin:auto;width:8px;height:8px;border-radius:50%;background:'+rdot+'"></span></td>'+
      '<td>'+row.aid_key+'</td>'+
      '<td style="color:'+c+';font-weight:bold">'+row.category+'</td>';
    tb.appendChild(tr);
  });
  if (!r.running) {
    if (aidScanPoller) { clearInterval(aidScanPoller); aidScanPoller = null; }
    document.getElementById('aid-scan-btn').style.display = '';
    document.getElementById('aid-scan-stop-btn').style.display = 'none';
    const nSkipped = s.SKIPPED||0;
    const nFailed = (r.results||[]).filter(x => x.replay_ok===false && x.category!=='SKIPPED').length;
    if (nSkipped > 0) {
      document.getElementById('aid-scan-progress').textContent = 'Interrupted — '+nSkipped+' skipped';
      toast('Session lost — '+nSkipped+' keys skipped (double fail)', 'warn');
    } else if (nFailed > 0) {
      document.getElementById('aid-scan-progress').textContent = 'Done ('+r.total+' keys, '+nFailed+' recovered)';
      toast('AID Scan complete — '+nFailed+' key(s) needed recovery', 'warn');
    } else {
      document.getElementById('aid-scan-progress').textContent = 'Done ('+r.total+' keys)';
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
    steps: ['Enable Hack Fields (Ctrl+H) to unlock all protections', 'Enable Hack Color (Ctrl+G) to visually distinguish field types', 'Modify hidden field values and submit', 'Try typing in protected fields after hack'],
    cards: [
      {term:'Hack Fields', explain:'Rewrites field attribute bytes in proxy traffic to remove protection, reveal hidden, remove numeric lock.', analogy:'Like a browser extension that removes "disabled" and "readonly" from all form inputs.', action:'Toggle via Ctrl+H or header pill. Configure options in Hack Fields action tab.'},
      {term:'Hack Color', explain:'Injects color attributes (SFE/SA) to make different field types visually distinct.', analogy:'Like a CSS injection that highlights hidden elements with bright colors.', action:'Toggle via Ctrl+G. Useful to visually spot field boundaries on the emulator.'},
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

function buildMethodology() {
  const root = document.getElementById('method-root');
  if (!root) return;
  // Build phase navigation bar
  let h = '<div class="method-phases">';
  const phases = Object.keys(METHOD_DATA);
  phases.forEach((pid, i) => {
    if (i > 0) h += '<span class="method-arrow">&#9654;</span>';
    h += '<div class="method-phase' + (pid === activePhase ? ' active' : '') + '" onclick="showPhase(\''+pid+'\')">' + esc(METHOD_DATA[pid].label) + '</div>';
  });
  h += '</div>';
  h += '<div id="method-content-area"></div>';
  root.innerHTML = h;
  renderPhaseContent();
}

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
    if (k === 'g') { e.preventDefault(); toggleHackColor(); return; }
    if (k === 'b') { e.preventDefault(); toggleAbend(); return; }
    if (k === 't') { e.preventDefault(); toggleTxnTracking(); return; }
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
  document.getElementById('help-content-area').textContent = 'Gr0gu3270 - TN3270 Penetration Testing Toolkit\n\nMain view: Screen Map (top) + Findings (bottom)\nAction bar: click group headers to expand tools\n\nKeyboard Shortcuts:\n  Ctrl+H  Toggle Hack Fields\n  Ctrl+G  Toggle Hack Color\n  Ctrl+B  Toggle ABEND Detection\n  Ctrl+T  Toggle Transaction Tracking\n  Esc     Close action panel\n  ?       Open this help modal';
}

// ---- Init ----
buildActionBar();
startDashboardPollers();
// ---- Fuzz popup (double-click on field) ----
let fuzzPoller = null;
let fuzzField = null;

function openFuzzPopup(field) {
  if (document.getElementById('fuzz-overlay')) return; // already open
  fuzzField = field;
  const type = field.hidden ? 'Hidden' : field.numeric ? 'Numeric' : 'Input';
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
      <button class="btn" onclick="closeFuzzPopup()" style="margin-left:auto">\u2715</button>
    </div>
    <div id="fp-status" style="color:var(--dim);margin-bottom:4px"></div>
    <div class="fuzz-progress" id="fp-progress" style="display:none"><div class="fuzz-progress-fill" id="fp-progress-fill"></div></div>
    <div id="fp-results" style="max-height:400px;overflow-y:auto">
      <table><thead><tr><th>Payload</th><th>Source</th><th>Status</th><th>Diff</th></tr></thead>
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
  const r = await post('/api/inject/fuzz', {
    field: {row: fuzzField.row, col: fuzzField.col, length: fuzzField.length,
            hidden: !!fuzzField.hidden, numeric: !!fuzzField.numeric},
    key: key
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
        tr.innerHTML = '<td>'+esc(r.payload)+'</td><td style="color:var(--dim)">'+src+'</td><td style="color:'+col+'">'+statusText+recIcon+'</td><td>'+diffHtml+'</td>';
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

</script>
</body>
</html>
"""
