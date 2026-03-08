Gr0gu3270
========

TN3270 Penetration Testing Toolkit — MitM proxy between a TN3270 emulator and a mainframe for CICS security auditing.

```
usage: Gr0gu3270.py [options] IP PORT

Gr0gu3270 - The TN3270 Penetration Testing Toolkit

positional arguments:
  IP                    TN3270 server IP address
  PORT                  TN3270 server port

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Project name (default: pentest)
  -p PROXY_PORT, --proxy_port PROXY_PORT
                        Local TN3270 proxy port (default: 3271)
  --proxy_ip PROXY_IP   Local TN3270 proxy IP (default: 127.0.0.1)
  --web-port WEB_PORT   Web UI port (default: 8080)
  -t, --tls             Enable TLS encryption for server connection
  -o, --offline         Offline log analysis mode
  --macro MACRO         Auto-run macro JSON file on connect
  -d, --debug           Print debugging statements

Example:
    Gr0gu3270.py -n myproject 10.10.10.10 3270
    Gr0gu3270.py -t --web-port 1337 10.10.10.10 992
    Gr0gu3270.py --macro macros/dvca-login.json 10.10.10.10 3270
    Gr0gu3270.py -o
```

Requirements
------------

Python 3.11+. Zero external dependencies.

Data Flow
---------

```
TN3270 Emulator <-> Local Proxy (Gr0gu3270) <-> TN3270 Server (Mainframe)
                          |
                    SQLite3 DB (project_name.db)
                          |
                    Web UI (HTTP :8080)
```

The proxy sits between your TN3270 emulator and the mainframe. All traffic is logged to a per-project SQLite database. A web UI provides real-time screen analysis, security findings, and attack tools.

Command Line Options
--------------------

The `-n` (or `--name`) option determines the name of the SQLite3 log database file.
By default this is `pentest` and will create `pentest.db`. Each penetration test
should have a different project name. If you restart with the same project name,
logs will be appended to the existing database.

The `IP` and `PORT` options configure the connection to the mainframe. This is
the same IP and port you would normally use in your TN3270 emulator.

The `-p` (or `--proxy_port`) option sets the local listening port. Connections
to this port are NOT encrypted. This allows tools like Wireshark to capture
network traffic. When the mainframe connection uses TLS, only connect to
localhost (127.0.0.1) to avoid unencrypted application data traversing the
network.

The `--proxy_ip` option sets the local IP address to listen on. Default is
127.0.0.1.

The `--web-port` option sets the web UI port (default: 8080).

The `-t` (or `--tls`) option enables TLS for the mainframe connection. The
local proxy connection is intentionally unencrypted.

The `-o` (or `--offline`) option enables offline log analysis. No connection to
the mainframe is made. Connect a TN3270 emulator to the local port to replay
previously logged server data.

The `--macro` option auto-runs a JSON macro file after the emulator connects
(e.g., automated login sequences).

Web UI Features
---------------

The web UI (accessible at `http://127.0.0.1:<web-port>`) provides:

* **Screen Map** — real-time field parsing with input/hidden field detection, ESM fingerprint
* **Hack Fields** — toggle field attribute manipulation (Ctrl+H)
* **AID Scan** — automated testing of 24 function keys with replay verification
* **Field Fuzzer** — double-click any field to fuzz with auto-selected wordlists
* **Findings Panel** — deduplicated security findings with severity, constat, and remediation
* **Macro Engine** — JSON-based automated navigation replay
* **SPOOL/RCE** — passive SPOOL API detection + active FTP PoC
* **Logs, Transactions, ABENDs** — full audit trail

Recommendations
---------------

* Use x3270 or c3270 (Linux) or wx3270 (Windows) as your TN3270 emulator
* Select Options→Screen Size→Model 5
* Keep your screen size constant to ensure proper log replay

Getting Started with DVCA
--------------------------

[DVCA](https://github.com/mainframed/DVCA) is a deliberately vulnerable CICS
application for testing:

```bash
# Start DVCA
docker run -d --name dvca -p 3270:3270 mainframed767/dvca

# Wait ~15s for MVS to boot, then start Gr0gu3270
python3 Gr0gu3270.py -n dvca 127.0.0.1 3270 --web-port 1337

# Connect your TN3270 emulator to 127.0.0.1:3271
# Open http://127.0.0.1:1337 in your browser
```

Login: type `DVCA` + Enter (userid), then `DVCA` + Enter (password), PF5 for
main menu, CLEAR to access transactions (MCMM, MCOR, MCSH, MCAD, etc.).

License
-------

GPL-3.0
