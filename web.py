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


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True
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
        self.last_audit_id = 0
        self.inject_filename = ""
        self.inject_running = False
        self.inject_status_msg = "Not Ready."
        self.audit_thread = None
        self.inject_thread = None
        self.disabled_tabs = []
        self.shutdown_flag = threading.Event()
        self.connection_ready = threading.Event()
        self.scan_running = False
        self.scan_result = None
        self.scan_thread = None
        self.aid_scan_thread = None
        self.last_aid_scan_id = 0
        # Command queue: HTTP threads queue (label, payload) tuples,
        # daemon thread sends them to the server socket.
        self._cmd_queue = queue.Queue()
        self.last_scan_id = 0

    def get_status(self):
        with self.lock:
            return {
                'connected': self.connection_ready.is_set(),
                'offline': self.h.is_offline(),
                'hack_on': bool(self.h.hack_on),
                'hack_color_on': bool(self.h.hack_color_on),
                'abend_detection': bool(self.h.abend_detection),
                'transaction_tracking': bool(self.h.transaction_tracking),
                'audit_running': bool(self.h.audit_running),
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
            return result

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

    def get_audit_results(self, since=0):
        with self.lock:
            rows = self.h.all_audit_results(since)
            result = []
            for row in rows:
                preview = row[4][:80] if row[4] else ''
                result.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(row[1]))),
                    'txn_code': row[2],
                    'status': row[3],
                    'preview': preview,
                    'response_len': row[5],
                })
            return result

    def get_audit_summary(self):
        with self.lock:
            results = self.h.audit_results
            counts = {'ACCESSIBLE': 0, 'DENIED': 0, 'ABEND': 0, 'NOT_FOUND': 0, 'ERROR': 0, 'UNKNOWN': 0}
            for r in results:
                s = r.get('status', 'UNKNOWN')
                if s in counts:
                    counts[s] += 1
            return counts

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
                'config_set': bool(self.h.get_inject_config_set()),
                'running': self.inject_running,
                'filename': self.inject_filename,
                'message': self.inject_status_msg,
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

    def set_inject_file(self, data):
        filename = data.get('filename', '')
        with self.lock:
            if filename:
                full_path = os.path.join('injections', filename)
                if os.path.isfile(full_path):
                    self.inject_filename = full_path
                    self.inject_status_msg = "Filename set to: " + full_path
                    return {'ok': True, 'message': self.inject_status_msg}
            self.inject_status_msg = "Error: file not set."
            return {'ok': False, 'message': self.inject_status_msg}

    def inject_setup(self):
        with self.lock:
            mask = '*'
            self.h.set_inject_mask(mask)
            self.h.set_inject_setup_capture()
            self.inject_status_msg = "Submit data using mask character of '{}' to setup injection.".format(mask)
            return {'ok': True, 'message': self.inject_status_msg}

    def inject_setup_with_mask(self, data):
        with self.lock:
            mask = data.get('mask', '*')
            self.h.set_inject_mask(mask)
            self.h.set_inject_setup_capture()
            self.inject_status_msg = "Submit data using mask character of '{}' to setup injection.".format(mask)
            return {'ok': True, 'message': self.inject_status_msg}

    def inject_go(self, data):
        if self.inject_running:
            return {'ok': False, 'message': 'Injection already running.'}

        with self.lock:
            if not self.inject_filename:
                self.inject_status_msg = "Injection file not set. Select a file first."
                return {'ok': False, 'message': self.inject_status_msg}
            if not self.h.get_inject_config_set():
                self.inject_status_msg = "Field for injection hasn't been setup. Click SETUP."
                return {'ok': False, 'message': self.inject_status_msg}

        trunc_mode = data.get('trunc', 'SKIP')
        key_mode = data.get('key', 'ENTER')

        self.inject_running = True
        self.inject_thread = threading.Thread(
            target=self._inject_worker, args=(trunc_mode, key_mode), daemon=True)
        self.inject_thread.start()
        return {'ok': True, 'message': 'Injection started.'}

    def _inject_worker(self, trunc_mode, key_mode):
        try:
            with open(self.inject_filename, 'r') as f:
                lines = f.readlines()

            for line in lines:
                if self.shutdown_flag.is_set():
                    break
                line = line.rstrip()
                if not line:
                    continue

                # Build payload under lock (fast, no I/O)
                with self.lock:
                    mask_len = self.h.get_inject_mask_len()
                    if trunc_mode == 'TRUNC':
                        line = line[:mask_len]
                    if len(line) <= mask_len:
                        injection_ebcdic = self.h.get_ebcdic(line)
                        bytes_ebcdic = self.h.get_inject_preamble() + injection_ebcdic + self.h.get_inject_postamble()
                        is_tn3270e = self.h.check_inject_3270e()
                    else:
                        continue
                    self.inject_status_msg = "Sending: " + line

                # Queue the injection payload + follow-up keys via command queue
                # The daemon thread handles all socket I/O
                self._cmd_queue.put(('Sending: ' + line, bytes_ebcdic))

                if key_mode == 'ENTER+CLEAR':
                    aid = b'\x6d'
                    payload = (b'\x00\x00\x00\x00\x01' + aid + b'\xff\xef') if is_tn3270e else (aid + b'\xff\xef')
                    self._cmd_queue.put(('Sending key: CLEAR', payload))
                elif key_mode == 'ENTER+PF3':
                    aid = b'\xf3'
                    payload = (b'\x00\x00\x00\x00\x01' + aid + b'\xff\xef') if is_tn3270e else (aid + b'\xff\xef')
                    self._cmd_queue.put(('Sending key: PF3', payload))
                elif key_mode == 'ENTER+PF3+CLEAR':
                    for name, aid in [('PF3', b'\xf3'), ('CLEAR', b'\x6d')]:
                        payload = (b'\x00\x00\x00\x00\x01' + aid + b'\xff\xef') if is_tn3270e else (aid + b'\xff\xef')
                        self._cmd_queue.put(('Sending key: ' + name, payload))

                # Let daemon thread drain the queue and process responses
                time.sleep(0.3)

        except Exception as e:
            self.inject_status_msg = "Injection error: {}".format(e)
        finally:
            self.inject_running = False
            self.inject_status_msg = "Injection complete."

    def inject_reset(self):
        with self.lock:
            self.h.set_inject_config_set(0)
            self.inject_status_msg = "Configuration cleared."
            return {'ok': True, 'message': self.inject_status_msg}

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

    def audit_start(self, data):
        filename = data.get('filename', '')
        if not filename:
            return {'ok': False, 'message': 'No file specified.'}

        full_path = os.path.join('injections', filename)
        if not os.path.isfile(full_path):
            return {'ok': False, 'message': 'File not found.'}

        with open(full_path, 'r') as f:
            txn_list = [line.strip() for line in f if line.strip()]

        if not txn_list:
            return {'ok': False, 'message': 'Transaction list is empty.'}

        with self.lock:
            self.h.audit_start(txn_list)

        self.audit_thread = threading.Thread(
            target=self._audit_worker, daemon=True)
        self.audit_thread.start()
        return {'ok': True, 'message': 'Auditing {} transactions...'.format(len(txn_list))}

    def _audit_worker(self):
        try:
            while True:
                if self.shutdown_flag.is_set():
                    break

                with self.lock:
                    if not self.h.get_audit_running():
                        break
                    txn = self.h.audit_next()
                    if txn is None:
                        break
                    server_sock = self.h.server

                # Wait for response — select OUTSIDE lock so HTTP stays responsive
                time.sleep(0.1)
                try:
                    rlist, _, _ = select.select([server_sock], [], [], 2)
                    if server_sock in rlist:
                        server_data = server_sock.recv(libGr0gu3270.BUFFER_MAX)
                        if len(server_data) > 0:
                            with self.lock:
                                self.h.handle_server(server_data)
                except Exception:
                    pass

                time.sleep(0.3)

        except Exception as e:
            logging.getLogger(__name__).error("Audit error: {}".format(e))
        finally:
            with self.lock:
                self.h.audit_stop()

    def audit_stop(self):
        with self.lock:
            self.h.audit_stop()
            return {'ok': True, 'message': 'Audit stopped.'}

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

    def export_audit_csv(self):
        with self.lock:
            csv_file = self.h.export_audit_csv()
            return {'ok': True, 'filename': csv_file}

    def get_scan_status(self):
        return {'running': self.scan_running, 'result': self.scan_result}

    def get_scan_results(self, since=0):
        with self.lock:
            rows = self.h.all_scan_results(since)
            result = []
            for row in rows:
                result.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'timestamp_fmt': str(datetime.datetime.fromtimestamp(float(row[1]))),
                    'txn_code': row[2],
                    'status': row[3],
                    'abends': row[4],
                    'field_analysis': row[5],
                    'pf_keys': row[6],
                    'esm_type': row[7],
                    'response_len': row[8],
                    'duration_ms': row[9],
                    'response_preview': row[10],
                    'full_report': row[11],
                })
            return result

    def scan_txn(self, data):
        txn_code = data.get('txn_code', '').strip().upper()
        if not txn_code or len(txn_code) > 8 or not re.match(r'^[A-Z0-9@#$]+$', txn_code):
            return {'ok': False, 'message': 'Invalid transaction code (1-8 chars, A-Z0-9@#$).'}
        if not self.connection_ready.is_set():
            return {'ok': False, 'message': 'Not connected.'}
        if self.h.audit_running:
            return {'ok': False, 'message': 'Audit is running.'}
        if self.scan_running:
            return {'ok': False, 'message': 'Scan already running.'}

        self.scan_running = True
        self.scan_result = None
        self.scan_thread = threading.Thread(
            target=self._scan_worker, args=(txn_code,), daemon=True)
        self.scan_thread.start()
        return {'ok': True, 'message': 'Scanning {}...'.format(txn_code)}

    def _scan_worker(self, txn_code):
        try:
            with self.lock:
                server_data, duration_ms = self.h.scan_send_txn(txn_code)

            if server_data is None:
                self.scan_result = {'txn_code': txn_code, 'status': 'ERROR',
                                    'error': 'No response from server'}
                return

            with self.lock:
                report = self.h.scan_analyze(server_data, txn_code, duration_ms)
                self.h.write_scan_result(report)

            self.scan_result = report
        except Exception as e:
            self.scan_result = {'txn_code': txn_code, 'status': 'ERROR',
                                'error': str(e)}
        finally:
            self.scan_running = False

    def export_scan_csv(self):
        with self.lock:
            csv_file = self.h.export_scan_csv()
            return {'ok': True, 'filename': csv_file}

    # ---- AID Scan (PR5) ----

    def aid_scan_start(self):
        if not self.connection_ready.is_set():
            return {'ok': False, 'message': 'Not connected.'}
        if self.h.audit_running:
            return {'ok': False, 'message': 'Audit is running.'}
        if self.scan_running:
            return {'ok': False, 'message': 'Scan is running.'}
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
                })
            return results

    def get_aid_scan_summary(self):
        with self.lock:
            results = self.h.aid_scan_results
            summary = {'VIOLATION': [], 'NEW_SCREEN': [], 'SAME_SCREEN': [], 'TIMEOUT': []}
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
                    key=lambda r: {'VIOLATION': 0, 'NEW_SCREEN': 1, 'TIMEOUT': 2, 'SAME_SCREEN': 3}.get(r.get('category', ''), 4))
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
            if self.h.audit_running:
                return
            if self.scan_running:
                return
            if self.h.aid_scan_running:
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
        elif path == '/api/audit_results':
            since = int(params.get('since', ['0'])[0])
            self._send_json(self.state.get_audit_results(since))
        elif path == '/api/audit_summary':
            self._send_json(self.state.get_audit_summary())
        elif path == '/api/statistics':
            self._send_json(self.state.get_statistics())
        elif path == '/api/aids':
            self._send_json(self.state.get_aids())
        elif path == '/api/inject_status':
            self._send_json(self.state.get_inject_status())
        elif path == '/api/injection_files':
            self._send_json(self.state.get_injection_files())
        elif path == '/api/scan/status':
            self._send_json(self.state.get_scan_status())
        elif path == '/api/scan/results':
            since = int(params.get('since', ['0'])[0])
            self._send_json(self.state.get_scan_results(since))
        elif path == '/api/aid_scan/results':
            since = int(params.get('since', ['0'])[0])
            self._send_json(self.state.get_aid_scan_results(since))
        elif path == '/api/aid_scan/summary':
            self._send_json(self.state.get_aid_scan_summary())
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
        elif path == '/api/inject/file':
            result = self.state.set_inject_file(data)
            self._send_json(result)
        elif path == '/api/inject/setup':
            result = self.state.inject_setup_with_mask(data)
            self._send_json(result)
        elif path == '/api/inject/go':
            result = self.state.inject_go(data)
            self._send_json(result)
        elif path == '/api/inject/reset':
            result = self.state.inject_reset()
            self._send_json(result)
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
        elif path == '/api/audit/start':
            result = self.state.audit_start(data)
            self._send_json(result)
        elif path == '/api/audit/stop':
            result = self.state.audit_stop()
            self._send_json(result)
        elif path == '/api/export_csv':
            result = self.state.export_csv()
            self._send_json(result)
        elif path == '/api/audit/export':
            result = self.state.export_audit_csv()
            self._send_json(result)
        elif path == '/api/scan/start':
            result = self.state.scan_txn(data)
            self._send_json(result)
        elif path == '/api/scan/export':
            result = self.state.export_scan_csv()
            self._send_json(result)
        elif path == '/api/aid_scan/start':
            result = self.state.aid_scan_start()
            self._send_json(result)
        elif path == '/api/aid_scan/stop':
            result = self.state.aid_scan_stop()
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

/* Reverse video helper */
.rv { background: var(--head); color: var(--bg); padding: 1px 8px; font-weight: bold; }

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
.panel-events { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.panel-events.collapsed { flex: 0; max-height: 26px; overflow: hidden; }
.panel-header { display: flex; align-items: center; gap: 8px; padding: 4px 10px; background: var(--head); color: var(--bg); cursor: pointer; flex-shrink: 0; font-weight: bold; font-size: 18px; text-transform: uppercase; letter-spacing: 0.5px; text-shadow: none; }
.panel-header:hover { opacity: 0.9; }
.panel-title { color: var(--bg); font-size: 18px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
.badge { background: var(--alert); color: var(--bg); font-size: 15px; padding: 1px 6px; min-width: 16px; text-align: center; font-weight: bold; }
.badge.zero { background: var(--border); color: var(--dim); }
.panel-body { flex: 1; overflow-y: auto; min-height: 0; }

/* Event row colors */
.ev-abnd { background: rgba(255,21,31,0.06); }
.ev-txn { background: transparent; }
.ev-deny { background: rgba(255,21,31,0.1); }
.ev-type { display: inline-block; font-size: 14px; font-weight: bold; padding: 1px 5px; letter-spacing: 0.5px; }
.ev-type-abnd { background: var(--alert); color: var(--bg); }
.ev-type-txn { background: var(--border); color: var(--text); }
.ev-type-deny { background: var(--alert); color: var(--bg); }

/* Event counters in header */
.event-counters { display: flex; gap: 10px; margin-left: auto; font-size: 15px; color: var(--bg); }
.event-counters span { display: flex; align-items: center; gap: 3px; }

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

/* Toast notifications */
.toast-container { position: fixed; top: 8px; right: 8px; z-index: 10000; display: flex; flex-direction: column; gap: 4px; pointer-events: none; }
.toast { padding: 6px 14px; font-size: 17px; font-family: inherit; pointer-events: auto; animation: toast-in 0.2s ease, toast-out 0.3s ease 2.6s forwards; max-width: 320px; border: 1px solid; }
.toast-error { background: var(--bg); border-color: var(--alert); color: var(--alert); }
.toast-success { background: var(--bg); border-color: var(--text); color: var(--text); }
.toast-info { background: var(--bg); border-color: var(--head); color: var(--head); }
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
      <div class="header-toolbar" id="toolbar"></div>
      <div class="toggles">
        <div class="toggle-pill" id="tgl-hack" onclick="toggleHackFields()" title="Hack Fields">H</div>
        <div class="toggle-pill" id="tgl-color" onclick="toggleHackColor()" title="Hack Color">C</div>
        <div class="toggle-pill on" id="tgl-abend" style="display:none">A</div>
        <div class="toggle-pill on" id="tgl-txn" style="display:none">T</div>
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
      <button class="btn" onclick="event.stopPropagation();loadScreenMap()" style="margin-left:auto;font-size:15px;padding:2px 8px">REFRESH</button>
    </div>
    <div class="panel-body">
      <table><thead><tr>
        <th>Pos</th><th>Type</th><th>P</th><th>H</th><th>N</th><th>Len</th><th>Content</th>
      </tr></thead><tbody id="smap-table"></tbody></table>
    </div>
  </div>

  <!-- Events (flex:1, collapsible) -->
  <div class="panel-events" id="panel-events">
    <div class="panel-header" onclick="togglePanel('panel-events')">
      <span class="panel-title">Events</span>
      <span class="badge zero" id="badge-events">0</span>
      <div class="event-counters">
        <span><span class="ev-type ev-type-abnd">ABND</span> <b id="cnt-abnd">0</b></span>
        <span><span class="ev-type ev-type-txn">TXN</span> <b id="cnt-txn">0</b></span>
        <span><span class="ev-type ev-type-deny">DENY</span> <b id="cnt-deny">0</b></span>
      </div>
    </div>
    <div class="panel-body">
      <table><thead><tr>
        <th onclick="sortTable('events-table',0,'num')">ID</th>
        <th onclick="sortTable('events-table',1,'str')">Time</th>
        <th>Type</th>
        <th>Code</th>
        <th>Detail</th>
        <th>ms</th>
      </tr></thead><tbody id="events-table"></tbody></table>
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
  <span>A:<b id="oia-abnd">0</b> T:<b id="oia-txn">0</b> D:<b id="oia-deny">0</b></span>
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
  {id:'inject-fields', label:'Inject', group:1},
  {id:'inject-keys', label:'Keys', group:1},
  {id:'scan', label:'Scan', group:2},
  {id:'audit', label:'Bulk Audit', group:2},
  {id:'aid-scan', label:'AID Scan', group:2},
  {id:'spool', label:'SPOOL/RCE', group:2},
  {id:'logs', label:'Logs', group:3, tall:true},
  {id:'statistics', label:'Stats', group:3},
  {id:'methodology', label:'Method', group:4, tall:true},
  {id:'help', label:'Help', group:4},
];

const GROUPS = [
  {id:'grp-info', label:'GUIDE', items:['methodology','help'], location:'bottom'},
  {id:'grp-hacks', label:'HACKS', items:['hack-fields','hack-color'], location:'top'},
  {id:'grp-inject', label:'INJECTION', items:['inject-fields','inject-keys'], location:'top'},
  {id:'grp-scan', label:'SCANNING', items:['scan','audit','aid-scan','spool'], location:'top'},
  {id:'grp-data', label:'DATA', items:['logs','statistics'], location:'top'},
];

let activeAction = null;
let activeGroup = null;
let pollers = {};
let disabledTabs = [];
let logSince = 0, abendSince = 0, txnSince = 0, auditSince = 0;

// ---- Events data layer ----
let rawAbends = [];
let rawTxns = [];
let eventsList = [];

function rebuildEvents() {
  eventsList = [];
  rawAbends.forEach(r => {
    const isDeny = (r.code === 'AEY7' || r.code === 'AEYF' || r.code === 'AEZD');
    eventsList.push({
      id: 'A' + r.id,
      sortKey: r.id * 1000,
      time: r.timestamp_fmt,
      type: isDeny ? 'DENY' : 'ABND',
      code: r.code,
      detail: r.description || r.type,
      ms: '',
      raw: r
    });
  });
  rawTxns.forEach(r => {
    const isDeny = r.status && r.status.toLowerCase() === 'denied';
    eventsList.push({
      id: 'T' + r.id,
      sortKey: r.id * 1000 + 1,
      time: r.timestamp_fmt,
      type: isDeny ? 'DENY' : 'TXN',
      code: r.txn_code,
      detail: r.status || '',
      ms: r.duration_ms || '',
      raw: r
    });
  });
  eventsList.sort((a, b) => b.sortKey - a.sortKey);
  renderEvents();
  updateEventCounters();
}

function renderEvents() {
  const tbody = document.getElementById('events-table');
  if (!tbody) return;
  tbody.innerHTML = '';
  eventsList.forEach(ev => {
    const tr = document.createElement('tr');
    const typeClass = ev.type === 'ABND' ? 'ev-abnd' : ev.type === 'DENY' ? 'ev-deny' : 'ev-txn';
    const badgeClass = ev.type === 'ABND' ? 'ev-type-abnd' : ev.type === 'DENY' ? 'ev-type-deny' : 'ev-type-txn';
    tr.className = typeClass;
    tr.innerHTML = '<td>'+esc(ev.id)+'</td><td>'+esc(ev.time)+'</td><td><span class="ev-type '+badgeClass+'">'+ev.type+'</span></td><td>'+esc(ev.code)+'</td><td>'+esc(ev.detail)+'</td><td>'+esc(String(ev.ms))+'</td>';
    tbody.appendChild(tr);
  });
}

function updateEventCounters() {
  let abnd = 0, txn = 0, deny = 0;
  eventsList.forEach(ev => {
    if (ev.type === 'ABND') abnd++;
    else if (ev.type === 'DENY') deny++;
    else txn++;
  });
  document.getElementById('cnt-abnd').textContent = abnd;
  document.getElementById('cnt-txn').textContent = txn;
  document.getElementById('cnt-deny').textContent = deny;
  // OIA bar counters
  const oa = document.getElementById('oia-abnd'); if (oa) oa.textContent = abnd;
  const ot = document.getElementById('oia-txn'); if (ot) ot.textContent = txn;
  const od = document.getElementById('oia-deny'); if (od) od.textContent = deny;
  const total = eventsList.length;
  const el = document.getElementById('badge-events');
  el.textContent = total > 99 ? '99+' : total;
  el.className = total > 0 ? 'badge' : 'badge zero';
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
  if (pollers.injectStatus) { clearInterval(pollers.injectStatus); delete pollers.injectStatus; }
  if (pollers.aids) { clearInterval(pollers.aids); delete pollers.aids; }
  if (pollers.actionLogs) { clearInterval(pollers.actionLogs); delete pollers.actionLogs; }
  if (pollers.actionAudit) { clearInterval(pollers.actionAudit); delete pollers.actionAudit; }
  if (pollers.actionAuditSummary) { clearInterval(pollers.actionAuditSummary); delete pollers.actionAuditSummary; }
}

function startActionPollers(id) {
  if (id === 'inject-fields') pollers.injectStatus = setInterval(loadInjectStatus, 1000);
  if (id === 'inject-keys') { loadAids(); pollers.aids = setInterval(loadAids, 1000); }
  if (id === 'logs') { loadLogs(); pollers.actionLogs = setInterval(loadLogs, 1000); }
  if (id === 'audit') { loadAuditResults(); loadAuditSummary(); pollers.actionAudit = setInterval(loadAuditResults, 2000); pollers.actionAuditSummary = setInterval(loadAuditSummary, 3000); }
  if (id === 'statistics') loadStatistics();
  if (id === 'methodology') { buildMethodology(); }
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

  // Inject Fields
  document.getElementById('apanel-inject-fields').innerHTML = `
    <div class="controls">
      <select id="inject-file-select"><option value="">-- File --</option></select>
      <button class="btn" onclick="injectSetFile()">LOAD</button>
      <span>Mask:</span>
      <select id="inject-mask">
        <option value="*">*</option><option value="@">@</option><option value="#">#</option>
        <option value="$">$</option><option value="%">%</option><option value="^">^</option><option value="&">&</option>
      </select>
      <button class="btn" onclick="injectSetup()">SETUP</button>
      <span>Mode:</span>
      <select id="inject-trunc"><option value="SKIP">SKIP</option><option value="TRUNC">TRUNC</option></select>
      <span>Keys:</span>
      <select id="inject-key">
        <option value="ENTER">ENTER</option><option value="ENTER+CLEAR">ENTER+CLEAR</option>
        <option value="ENTER+PF3">ENTER+PF3</option><option value="ENTER+PF3+CLEAR">ENTER+PF3+CLEAR</option>
      </select>
      <button class="btn" onclick="injectGo()">INJECT</button>
      <button class="btn danger" onclick="injectReset()">RESET</button>
    </div>
    <div class="inject-status" id="inject-status-msg">Not Ready.</div>`;

  // Inject Keys
  document.getElementById('apanel-inject-keys').innerHTML = `
    <div class="controls">
      <button class="btn" onclick="sendSelectedKeys()">Send Keys</button>
      <span id="send-keys-status" style="font-size:17px;color:var(--dim)">Ready.</span>
    </div>
    <div class="controls checkbox-grid" id="aid-checkboxes"></div>`;

  // Scan
  document.getElementById('apanel-scan').innerHTML = `
    <div class="controls">
      <input type="text" id="scan-txn-input" maxlength="8" placeholder="e.g. CEMT" style="background:var(--input-bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:17px;width:100px;text-transform:uppercase">
      <button class="btn" onclick="scanStart()">SCAN</button>
      <button class="btn" onclick="scanExport()">EXPORT</button>
      <span id="scan-status-msg" style="font-size:17px;color:var(--dim)"></span>
    </div>
    <div id="scan-report" style="display:none;background:var(--input-bg);border:1px solid var(--border);padding:8px;font-size:17px;max-height:140px;overflow-y:auto"></div>`;

  // Bulk Audit
  document.getElementById('apanel-audit').innerHTML = `
    <div class="controls">
      <select id="audit-file-select"><option value="">-- File --</option></select>
      <button class="btn" onclick="auditStart()">START</button>
      <button class="btn danger" onclick="auditStop()">STOP</button>
      <button class="btn" onclick="auditExport()">EXPORT</button>
      <span id="audit-status-msg" style="font-size:17px;color:var(--dim)">Ready.</span>
    </div>
    <div class="summary-bar" id="audit-summary" style="margin-top:6px">
      <span><span class="dot dot-accessible"></span><b id="sum-accessible">0</b></span>
      <span><span class="dot dot-denied"></span><b id="sum-denied">0</b></span>
      <span><span class="dot dot-abend"></span><b id="sum-abend">0</b></span>
      <span><span class="dot dot-not_found"></span><b id="sum-not_found">0</b></span>
      <span><span class="dot dot-error"></span><b id="sum-error">0</b></span>
    </div>
    <table style="margin-top:6px"><thead><tr>
      <th>ID</th><th>Time</th><th>Txn</th><th>Status</th><th>Preview</th>
    </tr></thead><tbody id="audit-table"></tbody></table>`;

  // AID Scan
  document.getElementById('apanel-aid-scan').innerHTML = `
    <div class="controls">
      <button class="btn" id="aid-scan-btn" onclick="aidScanStart()">AID SCAN</button>
      <button class="btn danger" id="aid-scan-stop-btn" onclick="aidScanStop()" style="display:none">STOP</button>
      <span id="aid-scan-progress" style="font-size:17px;color:var(--dim);margin-left:8px"></span>
    </div>
    <p style="font-size:15px;color:var(--dim);margin:4px 0 8px 0">Navigate to a screen in your emulator, then click AID SCAN. Tests all 28 keys (PF1-24, PA1-3, ENTER) and auto-returns to screen.</p>
    <div id="aid-scan-summary" style="display:none;margin-bottom:8px;gap:12px;font-size:18px">
      <span style="color:var(--alert)"><b id="as-violation">0</b> VIOLATION</span>
      <span style="color:var(--head)"><b id="as-new">0</b> NEW SCREEN</span>
      <span style="color:var(--dim)"><b id="as-same">0</b> SAME</span>
      <span style="color:var(--dim)"><b id="as-timeout">0</b> TIMEOUT</span>
    </div>
    <table style="margin-top:4px"><thead><tr>
      <th>Key</th><th>Category</th><th>Status</th><th>Similarity</th><th>Preview</th>
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

  // Methodology
  document.getElementById('apanel-methodology').innerHTML = '<div id="method-root"></div>';

  // Help
  document.getElementById('apanel-help').innerHTML = '<div class="help-content" id="help-content"></div>';
  loadHelp();

  loadInjectionFiles();
}

// ---- Always-on pollers for dashboard panels ----
function startDashboardPollers() {
  pollers.abends = setInterval(loadAbends, 2000);
  pollers.txns = setInterval(loadTransactions, 2000);
  pollers.screenMap = setInterval(loadScreenMap, 5000);
  // Initial loads
  loadAbends(); loadTransactions(); loadScreenMap();
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
    rebuildEvents();
  } catch(e) {}
}

async function loadScreenMap() {
  try {
    const data = await api('/api/screen_map');
    const tbody = document.getElementById('smap-table');
    tbody.innerHTML = '';
    data.forEach(f => {
      const tr = document.createElement('tr');
      if (f.hidden) tr.className = 'field-hidden';
      else if (!f.protected) tr.className = 'field-input';
      tr.innerHTML = '<td>'+f.row+','+f.col+'</td><td>'+esc(f.type)+'</td><td>'+(f.protected?'Y':'')+'</td><td>'+(f.hidden?'Y':'')+'</td><td>'+(f.numeric?'Y':'')+'</td><td>'+f.length+'</td><td>'+esc(f.content)+'</td>';
      tbody.appendChild(tr);
    });
  } catch(e) {}
}

async function loadTransactions() {
  try {
    const data = await api('/api/transactions?since=' + txnSince);
    if (data.length === 0) return;
    data.forEach(r => {
      txnSince = Math.max(txnSince, r.id);
      rawTxns.push(r);
    });
    rebuildEvents();
  } catch(e) {}
}

async function loadAuditResults() {
  try {
    const data = await api('/api/audit_results?since=' + auditSince);
    const tbody = document.getElementById('audit-table');
    if (!tbody) return;
    data.forEach(r => {
      auditSince = Math.max(auditSince, r.id);
      const tr = document.createElement('tr');
      tr.className = 'status-' + r.status.toLowerCase();
      tr.innerHTML = '<td>'+r.id+'</td><td>'+esc(r.timestamp_fmt)+'</td><td>'+esc(r.txn_code)+'</td><td>'+esc(r.status)+'</td><td>'+esc(r.preview)+'</td>';
      tbody.appendChild(tr);
    });
  } catch(e) {}
}

async function loadAuditSummary() {
  try {
    const s = await api('/api/audit_summary');
    const el = document.getElementById('sum-accessible');
    if (!el) return;
    el.textContent = s.ACCESSIBLE || 0;
    document.getElementById('sum-denied').textContent = s.DENIED || 0;
    document.getElementById('sum-abend').textContent = s.ABEND || 0;
    document.getElementById('sum-not_found').textContent = s.NOT_FOUND || 0;
    document.getElementById('sum-error').textContent = s.ERROR || 0;
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

async function loadHelp() {
  document.getElementById('help-content').textContent = 'Gr0gu3270 - TN3270 Penetration Testing Toolkit\n\nMain view: Screen Map (top) + Events timeline (bottom)\nAction bar: click tabs to expand tools\nLogs & Audit moved to action bar (on-demand)\n\nKeyboard Shortcuts:\n  Ctrl+H  Toggle Hack Fields\n  Ctrl+G  Toggle Hack Color\n  Ctrl+B  Toggle ABEND Detection\n  Ctrl+T  Toggle Transaction Tracking\n  Esc     Close action panel';
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

async function loadInjectStatus() {
  try {
    const s = await api('/api/inject_status');
    document.getElementById('inject-status-msg').textContent = s.message;
  } catch(e) {}
}

async function loadInjectionFiles() {
  try {
    const files = await api('/api/injection_files');
    ['inject-file-select', 'audit-file-select'].forEach(id => {
      const sel = document.getElementById(id);
      if (!sel) return;
      files.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f; opt.textContent = f;
        sel.appendChild(opt);
      });
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

async function injectSetFile() {
  const sel = document.getElementById('inject-file-select');
  const r = await post('/api/inject/file', {filename: sel.value});
  document.getElementById('inject-status-msg').textContent = r.message;
}
async function injectSetup() {
  const mask = document.getElementById('inject-mask').value;
  const r = await post('/api/inject/setup', {mask: mask});
  document.getElementById('inject-status-msg').textContent = r.message;
}
async function injectGo() {
  const trunc = document.getElementById('inject-trunc').value;
  const key = document.getElementById('inject-key').value;
  const r = await post('/api/inject/go', {trunc: trunc, key: key});
  document.getElementById('inject-status-msg').textContent = r.message;
  toast('Injection started', 'success');
}
async function injectReset() {
  const r = await post('/api/inject/reset');
  document.getElementById('inject-status-msg').textContent = r.message;
}
async function sendSelectedKeys() {
  const checks = document.querySelectorAll('#aid-checkboxes input[type=checkbox]:checked');
  const keys = Array.from(checks).map(c => c.dataset.aid);
  const r = await post('/api/send_keys', {keys: keys});
  document.getElementById('send-keys-status').textContent = r.message || 'Sent.';
}

async function auditStart() {
  const sel = document.getElementById('audit-file-select');
  if (!sel.value) { toast('Select an audit file first', 'error'); return; }
  const r = await post('/api/audit/start', {filename: sel.value});
  document.getElementById('audit-status-msg').textContent = r.message;
  toast('Audit started', 'success');
}
async function auditStop() {
  const r = await post('/api/audit/stop');
  document.getElementById('audit-status-msg').textContent = r.message;
}
async function auditExport() {
  const r = await post('/api/audit/export');
  document.getElementById('audit-status-msg').textContent = r.ok ? 'Exported: '+r.filename : 'Failed.';
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
const CAT_COLORS = {VIOLATION:C.alert,NEW_SCREEN:C.text,SAME_SCREEN:C.dim,TIMEOUT:C.dim};
const CAT_ORDER = {VIOLATION:0,NEW_SCREEN:1,TIMEOUT:2,SAME_SCREEN:3};
async function aidScanPoll() {
  const r = await fetch('/api/aid_scan/summary').then(r=>r.json());
  const s = r.summary || {};
  document.getElementById('as-violation').textContent = s.VIOLATION||0;
  document.getElementById('as-new').textContent = s.NEW_SCREEN||0;
  document.getElementById('as-same').textContent = s.SAME_SCREEN||0;
  document.getElementById('as-timeout').textContent = s.TIMEOUT||0;
  document.getElementById('aid-scan-progress').textContent = r.progress+'/'+r.total;
  const tb = document.getElementById('aid-scan-table');
  tb.innerHTML = '';
  (r.results||[]).forEach(row => {
    const c = CAT_COLORS[row.category]||C.dim;
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>'+row.aid_key+'</td>'+
      '<td style="color:'+c+';font-weight:bold">'+row.category+'</td>'+
      '<td>'+row.status+'</td>'+
      '<td>'+(row.similarity*100).toFixed(0)+'%</td>'+
      '<td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:15px;color:var(--dim)" title="'+
        (row.response_preview||'').replace(/"/g,'&quot;')+'">'+
        (row.response_preview||'').substring(0,100)+'</td>';
    tb.appendChild(tr);
  });
  if (!r.running) {
    if (aidScanPoller) { clearInterval(aidScanPoller); aidScanPoller = null; }
    document.getElementById('aid-scan-btn').style.display = '';
    document.getElementById('aid-scan-stop-btn').style.display = 'none';
    document.getElementById('aid-scan-progress').textContent = 'Done ('+r.total+' keys)';
    toast('AID Scan complete', 'success');
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

// ---- Scan ----
let scanPoller = null;
async function scanStart() {
  const txn = document.getElementById('scan-txn-input').value.trim().toUpperCase();
  if (!txn) { toast('Enter a transaction code', 'error'); return; }
  document.getElementById('scan-status-msg').textContent = 'Scanning ' + txn + '...';
  document.getElementById('scan-report').style.display = 'none';
  const r = await post('/api/scan/start', {txn_code: txn});
  if (!r.ok) { document.getElementById('scan-status-msg').textContent = r.message; return; }
  scanPoller = setInterval(scanPoll, 500);
}
async function scanPoll() {
  try {
    const s = await api('/api/scan/status');
    if (!s.running && s.result) {
      clearInterval(scanPoller); scanPoller = null;
      document.getElementById('scan-status-msg').textContent = 'Done.';
      renderScanReport(s.result);
    }
  } catch(e) { clearInterval(scanPoller); scanPoller = null; }
}
function renderScanReport(r) {
  const el = document.getElementById('scan-report');
  el.style.display = 'block';
  const sc = {ACCESSIBLE:C.text,DENIED:C.alert,ABEND:C.alert,NOT_FOUND:C.dim,ERROR:C.alert}[r.status]||C.dim;
  let h = '<span style="font-weight:bold">'+esc(r.txn_code)+'</span> ';
  h += '<span style="background:'+sc+';color:var(--bg);padding:1px 8px;font-weight:bold">'+esc(r.status)+'</span> ';
  h += '<span style="color:var(--dim)">'+((r.duration_ms||0).toFixed(1))+'ms | '+(r.response_len||0)+'B</span>';
  if (r.error) { h += '<div style="color:var(--alert);margin-top:4px">'+esc(r.error)+'</div>'; el.innerHTML=h; return; }
  const esm = r.esm||{};
  h += '<div style="margin-top:4px">ESM: '+esc(esm.esm||'?');
  if (esm.evidence&&esm.evidence.length) h += ' ('+esm.evidence.map(esc).join(', ')+')';
  h += '</div>';
  const fa = r.field_analysis||{};
  h += '<div>Fields: '+fa.total+' total, '+fa.input+' input, '+fa.hidden+' hidden</div>';
  if (fa.hidden_fields&&fa.hidden_fields.length) {
    h += '<div style="color:var(--alert)">Hidden: ';
    h += fa.hidden_fields.map(f=>'['+f.row+','+f.col+'] '+esc(f.content)).join('; ');
    h += '</div>';
  }
  if (r.response_preview) h += '<div style="margin-top:4px;padding:4px;background:var(--input-bg);border:1px solid var(--border);white-space:pre-wrap;max-height:60px;overflow-y:auto">'+esc(r.response_preview)+'</div>';
  el.innerHTML = h;
}
async function scanExport() {
  const r = await post('/api/scan/export');
  document.getElementById('scan-status-msg').textContent = r.ok ? 'Exported: '+r.filename : 'Failed.';
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
  h += '<table><thead><tr><th>Code</th><th>Description</th><th>Web Analogy</th><th>Seen</th></tr></thead><tbody>';
  ABEND_REF.forEach(a => {
    const detected = detectedCodes.has(a.code);
    h += '<tr class="' + (detected ? 'abend-ref-detected' : '') + '">';
    h += '<td>' + esc(a.code) + '</td><td>' + esc(a.desc) + '</td><td>' + esc(a.analogy) + '</td>';
    h += '<td>' + (detected ? '<span style="color:var(--alert)">YES</span>' : '') + '</td>';
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

// ---- Init ----
buildActionBar();
toggleGroup('grp-info');
startDashboardPollers();
</script>
</body>
</html>
"""
