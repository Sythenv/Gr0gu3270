#!/usr/bin/env python3
"""
Wordlist Benchmark against DVCA.

Connects to DVCA, navigates to each transaction (MCMM, MCOR, MCSH),
sends every payload from all 4 wordlists on every input/hidden field,
records the response classification, ABEND codes, and screen similarity.

Produces a CSV report + equivalence class analysis + recommendations.

Usage: python3 bench_wordlists.py
"""
import socket
import select
import time
import sys
import os
import csv
import io
import re
import subprocess
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from libGr0gu3270 import Gr0gu3270, BUFFER_MAX

DVCA_HOST = '127.0.0.1'
DVCA_PORT = 3270
IS_TN3270E = False  # DVCA = plain TN3270

# Transactions to benchmark (via MCMM menu option number)
# MCSH gives APCT on current DVCA — excluded
TRANSACTIONS = [
    {'code': 'MCOR', 'menu_option': '1', 'description': 'Office Supplies / Orders'},
]


# ---- Infra (from test_aid_scan_live.py) ----

def create_hack(name):
    """Create a Gr0gu3270 instance with fresh temp DB."""
    import tempfile
    db = os.path.join(tempfile.mkdtemp(), name)
    h = Gr0gu3270(
        server_ip=DVCA_HOST,
        server_port=DVCA_PORT,
        proxy_port=13271,
        offline_mode=False,
        project_name=db,
    )
    return h


def connect_direct(h):
    """Connect directly to DVCA (no client socketpair needed in bench mode)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((DVCA_HOST, DVCA_PORT))
    sock.settimeout(None)
    h.server = sock
    h.connected = True
    return sock


def read_response(sock, timeout=3):
    """Read all available data from socket."""
    data = b''
    while True:
        rlist, _, _ = select.select([sock], [], [], timeout)
        if sock not in rlist:
            break
        chunk = sock.recv(BUFFER_MAX)
        if not chunk:
            break
        data += chunk
        timeout = 0.3
    return data


def negotiate_tn3270(sock):
    """Handle TN3270 negotiation."""
    data = read_response(sock, timeout=3)
    negotiations = []
    i = 0
    while i < len(data):
        if data[i] == 0xFF:
            if i + 2 < len(data):
                cmd = data[i + 1]
                opt = data[i + 2]
                if cmd == 0xFD:
                    negotiations.append(bytes([0xFF, 0xFB, opt]))
                elif cmd == 0xFB:
                    negotiations.append(bytes([0xFF, 0xFD, opt]))
                i += 3
            else:
                i += 1
        else:
            i += 1
    for neg in negotiations:
        sock.send(neg)
    time.sleep(0.3)
    data2 = read_response(sock, timeout=1)
    if data2 and b'\xff\xfa\x18\x01\xff\xf0' in data2:
        sock.send(b'\xff\xfa\x18\x00IBM-3278-2-E\xff\xf0')
    time.sleep(0.5)
    return read_response(sock, timeout=2)


def send_and_read(h, payload, timeout=1):
    """Send payload and read response. Raises on dead socket.

    NOTE: Does NOT call h.handle_server() — that forwards to h.client
    which has no reader in bench mode, causing socketpair buffer overflow
    and eventual BrokenPipeError.
    """
    try:
        h.server.settimeout(3)
        h.server.send(payload)
        h.server.settimeout(None)
    except (socket.timeout, BrokenPipeError, OSError) as e:
        raise ConnectionError("Socket dead: {}".format(e))
    time.sleep(0.1)
    data = read_response(h.server, timeout=timeout)
    return data


# ---- Login & Navigation ----

def login_dvca(h):
    """CLEAR -> LOGON -> PF3 -> DVCA (uid) -> DVCA (pw) -> KICKS -> ready."""
    print("[*] Logging in to DVCA...")

    # CLEAR + LOGON
    send_and_read(h, h.build_clear_payload(IS_TN3270E))
    time.sleep(0.5)
    send_and_read(h, h.build_txn_payload('LOGON', IS_TN3270E))
    time.sleep(1)

    # PF3 to exit IKTXLOG → "ENTER USERID"
    send_and_read(h, b'\xf3\x40\x40\xff\xef')
    time.sleep(1)

    # DVCA as userid
    resp = send_and_read(h, h.build_txn_payload('DVCA', IS_TN3270E))
    time.sleep(1)

    if resp:
        ascii_text = h.get_ascii(resp)
        if 'PASSWORD' in ascii_text:
            # DVCA as password
            resp = send_and_read(h, h.build_txn_payload('DVCA', IS_TN3270E))
            time.sleep(2)
        elif 'IN USE' in ascii_text or 'REJECTED' in ascii_text:
            print("    [!] USERID IN USE — DVCA container needs restart")
            return False

    # CLEAR + KICKS → starts CICS/KICKS (auto-starts CSGM)
    send_and_read(h, h.build_clear_payload(IS_TN3270E))
    time.sleep(0.5)
    resp = send_and_read(h, h.build_txn_payload('KICKS', IS_TN3270E))
    time.sleep(2)

    if resp:
        ascii_text = h.get_ascii(resp)
        if 'DVCAPROD' in ascii_text or 'PRODUCTION' in ascii_text:
            print("[+] Login OK — at DVCA (KICKS)")
            return True

    # Fallback: CLEAR + CSGM
    send_and_read(h, h.build_clear_payload(IS_TN3270E))
    time.sleep(0.5)
    resp = send_and_read(h, h.build_txn_payload('CSGM', IS_TN3270E))
    time.sleep(1)
    if resp:
        ascii_text = h.get_ascii(resp)
        if 'DVCAPROD' in ascii_text:
            print("[+] Login OK — at DVCA (CSGM)")
            return True

    print("[-] Login failed")
    return False


def find_option_field(h, screen_data):
    """Find the non-hidden input field (the 'Option ==>' field) on a menu screen."""
    fields = h.parse_screen_map(screen_data)
    for f in fields:
        if f['type'] == 'input' and not f.get('hidden'):
            return f
    return None


def navigate_to_txn(h, txn):
    """From anywhere, CLEAR + MCMM + menu option to reach sub-screen."""
    # CLEAR to reset
    send_and_read(h, h.build_clear_payload(IS_TN3270E))
    time.sleep(0.3)

    # Go to MCMM main menu
    resp = send_and_read(h, h.build_txn_payload('MCMM', IS_TN3270E))
    time.sleep(0.3)

    if not resp:
        return None

    # Find the option field and type the menu option
    # NOTE: parse_screen_map returns col = attribute byte position,
    # but data starts at col+1 (after the attribute byte)
    opt = find_option_field(h, resp)
    if opt:
        data_col = opt['col'] + 1
        fields_with_text = [(txn['menu_option'], opt['row'], data_col)]
        resp = send_and_read(h, h.build_multi_field_payload(
            fields_with_text, IS_TN3270E))
    else:
        # Fallback: send as transaction text at cursor
        resp = send_and_read(h, h.build_multi_field_payload(
            [(txn['menu_option'], 0, 0)], IS_TN3270E))

    time.sleep(0.3)
    return resp


def reconnect_and_login(h):
    """Full reconnect: restart DVCA + new socket + TN3270 + login."""
    print("\n    [!] Reconnecting (restarting DVCA)...")
    try:
        h.server.close()
    except Exception:
        pass
    # Restart DVCA to clear stale sessions
    subprocess.run(['docker', 'rm', '-f', 'dvca'], capture_output=True, timeout=10)
    subprocess.run(['docker', 'run', '-d', '--name', 'dvca',
                    '-p', '3270:3270', 'mainframed767/dvca'],
                   capture_output=True, timeout=30)
    time.sleep(25)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((DVCA_HOST, DVCA_PORT))
    sock.settimeout(None)
    h.server = sock
    negotiate_tn3270(sock)
    login_dvca(h)
    return sock


def recover_to_txn(h, txn):
    """Recovery: CLEAR + navigate back. Reconnects if socket dead."""
    for attempt in range(2):
        try:
            resp = navigate_to_txn(h, txn)
            if resp:
                return resp
        except ConnectionError:
            print("\n    [!] Socket dead — reconnecting (attempt {})".format(attempt + 1))
            try:
                reconnect_and_login(h)
            except Exception as e:
                print("    [!] Reconnect failed: {}".format(e))
                time.sleep(2)
                continue
            try:
                resp = navigate_to_txn(h, txn)
                if resp:
                    return resp
            except Exception:
                pass
        except Exception as e:
            print("    [!] Recovery attempt {} failed: {}".format(attempt + 1, e))
            time.sleep(1)
    return None


# ---- Wordlist Loading ----

def load_all_wordlists():
    """Load all wordlists. Returns [(payload_text, source_file), ...]"""
    injections_dir = Path(__file__).parent / 'injections'
    payloads = []
    seen = set()

    for wl_file in sorted(injections_dir.glob('*.txt')):
        source = wl_file.stem
        for line in wl_file.read_text().splitlines():
            # Skip comments and empty lines
            if line.startswith('#') or not line:
                continue
            # Deduplicate across files
            key = (line, source)
            if key not in seen:
                seen.add(key)
                payloads.append((line, source))

    return payloads


# ---- Field Discovery ----

def discover_fields(h, screen_data):
    """Parse screen and return input + hidden fields with capacity calculated."""
    all_fields = h.parse_screen_map(screen_data)
    targets = []
    for i, f in enumerate(all_fields):
        if f['type'] == 'input' or f.get('hidden'):
            # Calculate field capacity from distance to next field
            if f['length'] == 0 and i + 1 < len(all_fields):
                next_f = all_fields[i + 1]
                pos = f['row'] * 80 + f['col']
                next_pos = next_f['row'] * 80 + next_f['col']
                capacity = next_pos - pos - 1  # -1 for attr byte
                if capacity > 0:
                    f['length'] = capacity
            targets.append(f)
    return targets


def field_label(field):
    """Human-readable field identifier."""
    label = field.get('label', '')
    if label:
        return label[:20]
    return 'R{}C{}'.format(field['row'], field['col'])


# ---- Benchmark Engine ----

def benchmark_field(h, field, payloads, txn, ref_screen):
    """
    Send each payload to a single field, record results.
    Returns list of result dicts.
    """
    results = []
    consecutive_fails = 0
    field_row = field['row']
    field_col = field['col'] + 1  # data starts after attribute byte
    field_len = field['length'] if field['length'] > 0 else 1
    fl = field_label(field)

    send_count = 0
    for payload_text, source in payloads:
        # Truncate to field length
        truncated = payload_text[:field_len]
        if not truncated:
            continue

        # DVCA hangs after ~75 sends. Reconnect every 50 sends.
        send_count += 1
        if send_count % 50 == 0:
            print('R', end='', flush=True)
            try:
                reconnect_and_login(h)
                ref = navigate_to_txn(h, txn)
                if ref:
                    ref_screen = ref
            except Exception as e:
                print("\n    [!] Reconnect failed: {} — skipping rest".format(e))
                break

        # Build and send
        fields_with_text = [(truncated, field_row, field_col)]
        try:
            pkt = h.build_multi_field_payload(fields_with_text, IS_TN3270E)
            resp = send_and_read(h, pkt)
        except Exception as e:
            print("    [!] Send error: {}".format(e))
            consecutive_fails += 1
            if consecutive_fails >= 2:
                print("    [!] 2 consecutive failures on {} — skipping field".format(fl))
                break
            # Try recovery
            ref = recover_to_txn(h, txn)
            if ref:
                ref_screen = ref
                consecutive_fails = 0
            continue

        if not resp:
            # Empty response — server may be slow, wait and retry
            time.sleep(0.5)
            consecutive_fails += 1
            if consecutive_fails >= 3:
                print("\n    [!] 3 consecutive empty responses on {} — skipping".format(fl))
                break
            ref = recover_to_txn(h, txn)
            if ref:
                ref_screen = ref
                consecutive_fails = 0
            continue

        # Classify
        status = h.classify_response(resp)
        abends = h.detect_abend(resp)
        abend_codes = ','.join(a['code'] for a in abends if a['type'] == 'ABEND')
        sim = h.screen_similarity(ref_screen, resp)

        result = {
            'txn': txn['code'],
            'field': fl,
            'hidden': 'H' if field.get('hidden') else '',
            'numeric': 'N' if field.get('numeric') else '',
            'field_len': field_len,
            'payload': payload_text,
            'truncated': truncated,
            'source': source,
            'status': status,
            'abend': abend_codes,
            'similarity': round(sim, 2),
        }
        results.append(result)
        consecutive_fails = 0

        # Status indicator
        marker = '.'
        if status == 'ABEND':
            marker = '!'
        elif status == 'DENIED':
            marker = 'X'
        elif status == 'ERROR':
            marker = 'E'
        elif sim < 0.5:
            marker = '>'  # significant screen change
        print(marker, end='', flush=True)

        # Pace sends to avoid overwhelming DVCA
        time.sleep(0.3)

        # Recovery if screen changed significantly
        if sim < 0.5 or status in ('ABEND', 'ERROR', 'NOT_FOUND'):
            ref = recover_to_txn(h, txn)
            if ref:
                ref_screen = ref
            else:
                consecutive_fails += 1
                if consecutive_fails >= 2:
                    print("\n    [!] Cannot recover to {} — skipping field".format(txn['code']))
                    break

    return results, ref_screen


# ---- Report Generation ----

def write_csv_report(all_results, filename='bench_results.csv'):
    """Write raw CSV results."""
    if not all_results:
        print("\n[-] No results to write")
        return

    fieldnames = ['txn', 'field', 'hidden', 'numeric', 'field_len',
                  'payload', 'truncated', 'source', 'status', 'abend', 'similarity']

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter='|')
        writer.writeheader()
        for r in all_results:
            writer.writerow(r)

    print("[+] CSV report: {}".format(filename))


def analyze_equivalence_classes(all_results):
    """Group results into equivalence classes and print analysis."""
    print("\n" + "=" * 70)
    print("EQUIVALENCE CLASS ANALYSIS")
    print("=" * 70)

    # Group by (txn, field, status, similarity_bucket)
    classes = defaultdict(list)
    for r in all_results:
        sim_bucket = round(r['similarity'] * 10) / 10  # bucket by 0.1
        key = (r['txn'], r['field'], r['status'], sim_bucket, r['abend'])
        classes[key].append(r)

    # Print classes with >1 member (duplicates)
    print("\n--- Duplicate Groups (same observable) ---")
    dup_count = 0
    for key, members in sorted(classes.items()):
        if len(members) > 1:
            dup_count += 1
            txn, field, status, sim, abend = key
            payloads = ['{} [{}]'.format(m['truncated'][:20], m['source'][:10]) for m in members]
            print("\n  Group: {} / {} -> {} (sim={}, abend={})".format(
                txn, field, status, sim, abend or '-'))
            print("  {} equivalent payloads:".format(len(members)))
            for p in payloads:
                print("    - {}".format(p))
            print("  -> KEEP: {}".format(payloads[0]))

    if dup_count == 0:
        print("  (no duplicates found)")

    print("\n  Total equivalence classes: {}".format(len(classes)))
    print("  Classes with duplicates: {}".format(dup_count))

    return classes


def print_recommendations(all_results, classes):
    """Print actionable recommendations."""
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)

    # 1. Payloads that always produce ACCESSIBLE (never interesting)
    payload_stats = defaultdict(lambda: defaultdict(int))
    for r in all_results:
        payload_stats[r['payload']][r['status']] += 1

    boring = []
    for payload, stats in payload_stats.items():
        if len(stats) == 1 and 'ACCESSIBLE' in stats:
            boring.append(payload)

    if boring:
        print("\n[REMOVE] Always ACCESSIBLE (no observable effect):")
        for p in sorted(boring):
            print("  - {!r}".format(p[:60]))
    else:
        print("\n[OK] All payloads produced at least one non-ACCESSIBLE response")

    # 2. Payloads that cause ABENDs (keepers!)
    abend_payloads = set()
    for r in all_results:
        if r['abend']:
            abend_payloads.add((r['payload'], r['source'], r['abend']))

    if abend_payloads:
        print("\n[KEEP] Payloads that trigger ABENDs:")
        for payload, source, abend in sorted(abend_payloads):
            print("  - {!r} [{}] -> {}".format(payload[:60], source, abend))
    else:
        print("\n[INFO] No ABENDs triggered by any payload")

    # 3. Overflow payloads that truncate to same thing
    overflow_truncs = defaultdict(list)
    for r in all_results:
        if r['source'] == 'cobol-overflow' and r['payload'] != r['truncated']:
            key = (r['txn'], r['field'], r['truncated'])
            overflow_truncs[key].append(r['payload'])

    if overflow_truncs:
        print("\n[DEDUP] Overflow payloads truncated to same value:")
        for (txn, field, trunc), originals in overflow_truncs.items():
            if len(originals) > 1:
                print("  {} / {}: {} payloads all truncated to {!r}".format(
                    txn, field, len(originals), trunc[:20]))

    # 4. Cross-file duplicates (same payload in multiple wordlists)
    payload_sources = defaultdict(set)
    for r in all_results:
        payload_sources[r['payload']].add(r['source'])

    cross_dupes = {p: srcs for p, srcs in payload_sources.items() if len(srcs) > 1}
    if cross_dupes:
        print("\n[DEDUP] Payloads present in multiple wordlists:")
        for payload, sources in sorted(cross_dupes.items()):
            print("  - {!r} in: {}".format(payload[:40], ', '.join(sorted(sources))))

    # 5. Security violations
    violations = [r for r in all_results if r['status'] == 'DENIED']
    if violations:
        print("\n[KEEP] Payloads that trigger security violations:")
        for r in violations:
            print("  - {!r} [{}] on {} / {}".format(
                r['payload'][:60], r['source'], r['txn'], r['field']))

    # 6. Significant screen changes (sim < 0.5, not ABEND/DENIED)
    navigated = [r for r in all_results
                 if r['similarity'] < 0.5 and r['status'] == 'ACCESSIBLE']
    if navigated:
        print("\n[INVESTIGATE] Significant screen changes (sim < 0.5):")
        for r in navigated:
            print("  - {!r} [{}] on {} / {} (sim={})".format(
                r['payload'][:60], r['source'], r['txn'], r['field'], r['similarity']))


def print_summary(all_results):
    """Print high-level summary."""
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total = len(all_results)
    by_status = defaultdict(int)
    by_source = defaultdict(int)
    for r in all_results:
        by_status[r['status']] += 1
        by_source[r['source']] += 1

    print("\n  Total sends: {}".format(total))
    print("\n  By status:")
    for status, count in sorted(by_status.items()):
        pct = 100 * count / total if total else 0
        print("    {:12s} {:4d}  ({:.1f}%)".format(status, count, pct))

    print("\n  By wordlist source:")
    for source, count in sorted(by_source.items()):
        print("    {:20s} {:4d}".format(source, count))

    # ABEND summary
    abend_codes = defaultdict(int)
    for r in all_results:
        if r['abend']:
            for code in r['abend'].split(','):
                abend_codes[code] += 1
    if abend_codes:
        print("\n  ABEND codes triggered:")
        for code, count in sorted(abend_codes.items(), key=lambda x: -x[1]):
            print("    {:6s} x{}".format(code, count))


# ---- Main ----

def main():
    print("=" * 70)
    print("WORDLIST BENCHMARK — DVCA")
    print("=" * 70)

    # Restart DVCA container for clean session state
    print("[*] Restarting DVCA container...")
    subprocess.run(['docker', 'rm', '-f', 'dvca'],
                   capture_output=True, timeout=10)
    subprocess.run(['docker', 'run', '-d', '--name', 'dvca',
                    '-p', '3270:3270', 'mainframed767/dvca'],
                   capture_output=True, timeout=30)
    print("[*] Waiting 25s for MVS boot...")
    time.sleep(25)

    # Load wordlists
    payloads = load_all_wordlists()
    print("[+] Loaded {} payloads from wordlists".format(len(payloads)))
    sources = set(s for _, s in payloads)
    for s in sorted(sources):
        count = sum(1 for _, src in payloads if src == s)
        print("    {} ({})".format(s, count))

    # Connect to DVCA (with retry)
    h = None
    for attempt in range(3):
        try:
            h = create_hack("bench_wl")
            sock = connect_direct(h)
            print("[+] Connected to DVCA")
            break
        except Exception as e:
            print("[-] Connection attempt {}: {}".format(attempt + 1, e))
            if attempt < 2:
                print("    Retrying in 5s...")
                time.sleep(5)
            else:
                print("[-] DVCA not reachable. Start it first.")
                sys.exit(1)

    # Negotiate TN3270
    negotiate_tn3270(sock)
    print("[+] TN3270 negotiation done")

    # Login
    if not login_dvca(h):
        print("[-] Login failed")
        sys.exit(1)

    # Benchmark each transaction
    all_results = []
    start_time = time.time()

    for txn in TRANSACTIONS:
        print("\n" + "-" * 70)
        print("[*] Transaction: {} ({})".format(txn['code'], txn['description']))
        print("-" * 70)

        # Navigate to transaction
        screen_data = navigate_to_txn(h, txn)
        if not screen_data:
            print("[-] Could not reach {} — skipping".format(txn['code']))
            continue

        # Verify we're on the right screen
        ascii_text = h.get_ascii(screen_data)
        if txn['code'] not in ascii_text and 'Abend' in ascii_text:
            print("[-] Got ABEND instead of {} — skipping".format(txn['code']))
            continue

        ref_screen = screen_data

        # Discover fields
        fields = discover_fields(h, screen_data)
        input_fields = [f for f in fields if f['type'] == 'input']
        hidden_fields = [f for f in fields if f.get('hidden')]
        print("[+] Fields: {} input, {} hidden".format(len(input_fields), len(hidden_fields)))

        for f in fields:
            fl = field_label(f)
            flags = ''
            if f.get('hidden'):
                flags += 'H'
            if f.get('numeric'):
                flags += 'N'
            print("    {} (len={}{})".format(
                fl, f['length'], ' ' + flags if flags else ''))

        if not fields:
            print("[-] No target fields — skipping")
            continue

        # Benchmark each field (skip len=0 — no content to inject)
        fields = [f for f in fields if f['length'] > 0]
        if not fields:
            print("[-] No fields with length > 0 — skipping")
            continue

        for f in fields:
            fl = field_label(f)
            print("\n  [*] Field: {} (len={})  ".format(fl, f['length']), end='')

            results, ref_screen = benchmark_field(h, f, payloads, txn, ref_screen)
            all_results.extend(results)

            # Stats for this field
            statuses = defaultdict(int)
            for r in results:
                statuses[r['status']] += 1
            print("\n      -> {} sends: {}".format(
                len(results),
                ', '.join('{}={}'.format(s, c) for s, c in sorted(statuses.items()))))

    elapsed = time.time() - start_time
    print("\n\n" + "=" * 70)
    print("Benchmark complete in {:.0f}s ({} sends)".format(elapsed, len(all_results)))
    print("=" * 70)

    # Cleanup
    try:
        sock.close()
        h.sql_con.close()
    except Exception:
        pass

    # Reports
    write_csv_report(all_results)
    print_summary(all_results)
    classes = analyze_equivalence_classes(all_results)
    print_recommendations(all_results, classes)


if __name__ == '__main__':
    main()
