#!/usr/bin/env python3
"""Benchmark AID scan across DVCA transactions via Gr0gu3270 API.

Prerequisite: Gr0gu3270 proxy running + wx3270 connected + logged into DVCA.
Drives the existing AID scan through the web API — no direct socket, no login.

Usage:
    python3 bench_aid_scan.py [--port 1337] [--txn MCMM,MCOR] [--timeout 2]

Dev-only script, do NOT commit.
"""

import time, json, sys, argparse
from urllib.request import urlopen, Request
from urllib.error import URLError

TRANSACTIONS = ['MCMM', 'MCOR']
POLL_INTERVAL = 1.0   # seconds between status polls
SETTLE_DELAY = 1.5    # seconds to wait after each navigation step
NAV_RETRIES = 3       # max navigation attempts before giving up
NAV_VERIFY_DELAY = 0.5  # extra wait before screen verification


def api_get(base, path):
    """GET JSON from API."""
    resp = urlopen(f'{base}{path}', timeout=10)
    return json.loads(resp.read())


def api_post(base, path, data=None):
    """POST JSON to API."""
    body = json.dumps(data or {}).encode()
    req = Request(f'{base}{path}', data=body,
                  headers={'Content-Type': 'application/json'})
    resp = urlopen(req, timeout=10)
    return json.loads(resp.read())


def check_connection(base):
    """Verify proxy is running and emulator connected."""
    try:
        status = api_get(base, '/api/inject_status')
        return status
    except URLError as e:
        print(f"Cannot reach Gr0gu3270 API at {base}: {e}", file=sys.stderr)
        sys.exit(1)


def get_screen_text(base):
    """Get concatenated text content from current screen fields."""
    screen = api_get(base, '/api/screen_map')
    fields = screen.get('fields', [])
    text = ' '.join(f.get('content', '') for f in fields).strip()
    # Clean control chars
    text = ' '.join(text.split())
    return text, fields


def verify_screen(base, txn_code):
    """Check that the current screen looks like the expected transaction.
    Returns (ok, screen_text, fields)."""
    text, fields = get_screen_text(base)

    # Screen must have content (not blank)
    if not text or len(text) < 10:
        return False, text, fields

    # Must not be an error/recovery screen
    error_markers = ['HIKT00405I', 'SCREEN ERASURE', 'NOT RECOGNIZED',
                     'INVALID TRANSACTION', 'UNKNOWN TRANSACTION']
    text_upper = text.upper()
    for marker in error_markers:
        if marker in text_upper:
            return False, text, fields

    # Must have at least one input field (transaction screens have inputs)
    has_input = any(not f.get('protected') for f in fields)
    if not has_input:
        # Some txn screens might be display-only — still OK if content present
        pass

    return True, text, fields


def navigate_to_txn(base, txn_code):
    """CLEAR → type txn → ENTER, then verify screen.
    Retries up to NAV_RETRIES times. Returns (ok, screen_text, fields)."""
    for attempt in range(1, NAV_RETRIES + 1):
        # CLEAR
        api_post(base, '/api/send_keys', {'keys': ['CLEAR']})
        time.sleep(SETTLE_DELAY)

        # Send transaction code
        api_post(base, '/api/send_text', {'text': txn_code})
        time.sleep(SETTLE_DELAY + NAV_VERIFY_DELAY)

        # Verify
        ok, text, fields = verify_screen(base, txn_code)
        if ok:
            return True, text, fields

        print(f"  [!] Attempt {attempt}/{NAV_RETRIES}: bad screen "
              f"({len(fields)} fields, text={text[:60]}...)", file=sys.stderr)

        # Extra settle before retry
        time.sleep(1.0)

    return False, text, fields


def run_aid_scan(base, timeout=1.0):
    """Start AID scan, poll until done. Returns summary dict."""
    result = api_post(base, '/api/aid_scan/start', {'timeout': timeout})
    if not result.get('ok'):
        return None, result.get('message', 'unknown error')

    # Poll until done
    while True:
        time.sleep(POLL_INTERVAL)
        summary = api_get(base, '/api/aid_scan/summary')
        if not summary.get('running'):
            break
        progress = summary.get('progress', 0)
        total = summary.get('total', 0)
        print(f"  ... {progress}/{total}", end='\r', flush=True)

    print(f"  ... done       ")
    return summary, None


def scan_transaction(base, txn_code, timeout=1.0):
    """Navigate to txn, verify screen, run AID scan, collect results."""
    t_start = time.time()

    # Reset: CLEAR before navigation to ensure clean state
    api_post(base, '/api/send_keys', {'keys': ['CLEAR']})
    time.sleep(SETTLE_DELAY)

    # Navigate + verify
    ok, ref_text, ref_fields = navigate_to_txn(base, txn_code)
    if not ok:
        print(f"  [!] SKIPPED {txn_code}: could not navigate to transaction screen",
              file=sys.stderr)
        print(f"      Last screen: {ref_text[:100]}", file=sys.stderr)
        return None

    n_input = sum(1 for f in ref_fields if not f.get('protected'))
    n_hidden = sum(1 for f in ref_fields if f.get('hidden'))
    print(f"  Screen OK: {len(ref_fields)} fields ({n_input} input, {n_hidden} hidden)")

    # Run scan
    summary, error = run_aid_scan(base, timeout=timeout)
    if error:
        print(f"  [!] AID scan failed for {txn_code}: {error}", file=sys.stderr)
        return None

    duration_s = round(time.time() - t_start, 1)

    # Post-scan check: verify session is usable
    post_scan_ok = True
    time.sleep(0.5)
    post_text, _ = get_screen_text(base)
    post_upper = post_text.upper()
    error_markers = ['HIKT', 'SCREEN ERASURE', 'NOT RECOGNIZED']
    for marker in error_markers:
        if marker in post_upper:
            print(f"  [!] Post-scan error detected: {marker}", file=sys.stderr)
            post_scan_ok = False
            break
    if not post_scan_ok:
        api_post(base, '/api/send_keys', {'keys': ['CLEAR']})
        time.sleep(SETTLE_DELAY)

    # Clean up: CLEAR after scan to leave session in known state
    api_post(base, '/api/send_keys', {'keys': ['CLEAR']})
    time.sleep(SETTLE_DELAY)

    # Extract counts
    counts = summary.get('summary', {})
    results = summary.get('results', [])

    # Add screen snippet for non-trivial results
    for r in results:
        if r.get('category') not in ('SAME_SCREEN',):
            r['screen'] = r.get('response_preview', '')[:200]
        else:
            r['screen'] = ''

    return {
        'keys_tested': summary.get('total', 0),
        'duration_s': duration_s,
        'post_scan_ok': post_scan_ok,
        'ref_screen': ref_text[:200],
        'ref_fields_count': len(ref_fields),
        'ref_input_count': n_input,
        'ref_hidden_count': n_hidden,
        'results': results,
        'summary': {
            'SAME_SCREEN': counts.get('SAME_SCREEN', 0),
            'NEW_SCREEN': counts.get('NEW_SCREEN', 0),
            'VIOLATION': counts.get('VIOLATION', 0),
            'UNMAPPED': counts.get('UNMAPPED', 0),
            'SKIPPED': counts.get('SKIPPED', 0),
        }
    }


def print_summary(all_results):
    """Print console summary table."""
    print()
    print(f"{'TXN':<9}{'SAME':>5}{'NEW':>5}{'VIOL':>5}{'UNMAP':>6}{'SKIP':>5}{'TIME':>8}")
    print('-' * 43)

    totals = {'SAME_SCREEN': 0, 'NEW_SCREEN': 0, 'VIOLATION': 0, 'UNMAPPED': 0, 'SKIPPED': 0}
    total_time = 0.0

    for txn, data in all_results.items():
        if data is None:
            print(f"{txn:<9}  FAILED")
            continue
        s = data['summary']
        t = data['duration_s']
        print(f"{txn:<9}{s['SAME_SCREEN']:>5}{s['NEW_SCREEN']:>5}"
              f"{s['VIOLATION']:>5}{s['UNMAPPED']:>6}{s['SKIPPED']:>5}{t:>7.1f}s")
        for k in totals:
            totals[k] += s[k]
        total_time += t

    print('-' * 43)
    print(f"{'TOTAL':<9}{totals['SAME_SCREEN']:>5}{totals['NEW_SCREEN']:>5}"
          f"{totals['VIOLATION']:>5}{totals['UNMAPPED']:>6}{totals['SKIPPED']:>5}"
          f"{total_time:>7.1f}s")
    print()


def main():
    parser = argparse.ArgumentParser(description='Benchmark AID scan via Gr0gu3270 API')
    parser.add_argument('--port', type=int, default=1337, help='Web UI port (default: 1337)')
    parser.add_argument('--txn', type=str, default=None,
                        help='Comma-separated transaction list (default: all)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='AID scan response timeout in seconds (default: 1.0)')
    args = parser.parse_args()

    base = f'http://localhost:{args.port}'
    transactions = args.txn.split(',') if args.txn else TRANSACTIONS

    # Preflight
    print(f"Connecting to Gr0gu3270 API at {base}...")
    status = check_connection(base)
    print(f"  Connected. Status: {status}")

    all_results = {}
    total_start = time.time()

    for txn in transactions:
        print(f"Scanning {txn}...")
        result = scan_transaction(base, txn, timeout=args.timeout)
        all_results[txn] = result
        if result:
            s = result['summary']
            ok_tag = '' if result.get('post_scan_ok', True) else ' [POST-SCAN ERROR]'
            print(f"  Done: SAME={s['SAME_SCREEN']} NEW={s['NEW_SCREEN']} "
                  f"VIOL={s['VIOLATION']} UNMAP={s['UNMAPPED']} SKIP={s['SKIPPED']} "
                  f"({result['duration_s']}s){ok_tag}")

    # Final CLEAR to leave session usable
    api_post(base, '/api/send_keys', {'keys': ['CLEAR']})

    total_duration = round(time.time() - total_start, 1)

    # Build output
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'target': f'localhost:{args.port}',
        'transactions': all_results,
        'totals': {
            'keys_tested': sum(r['keys_tested'] for r in all_results.values() if r),
            'duration_s': total_duration
        }
    }

    # Write JSON
    json_path = 'bench_aid_scan_results.json'
    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Results written to {json_path}")

    # Console summary
    print_summary(all_results)


if __name__ == '__main__':
    main()
