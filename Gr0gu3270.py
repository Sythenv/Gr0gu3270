#!/usr/bin/env python3

import libGr0gu3270
import argparse
import logging

def main():

    desc = 'Gr0gu3270 - The TN3270 Penetration Testing Toolkit'
    epilog = '''Example:
    %(prog)s -n prod_lpar3 10.10.10.10 992 -l 31337 --proxy_ip 0.0.0.0 --debug
    %(prog)s -o'''
    arg_parser = argparse.ArgumentParser(description=desc,
                        usage='%(prog)s [options] IP PORT',
                        formatter_class=argparse.RawTextHelpFormatter,
                        epilog=epilog)
    arg_parser.add_argument('-n', '--name', help='Project name (default: %(default)s)', default="pentest")
    arg_parser.add_argument('-p', '--proxy_port', type=int, help='Local TN3270 proxy port (default: %(default)s)', default=3271)
    arg_parser.add_argument('--proxy_ip', help="Local TN3270 proxy IP (default: %(default)s)", default="127.0.0.1")
    arg_parser.add_argument('-t', '--tls', help="Enable TLS encryption for server connection (default: %(default)s)", action="store_true", default=False)
    arg_parser.add_argument('-o', '--offline', help="Offline log analysis mode (default: %(default)s)", action="store_true", default=False)
    arg_parser.add_argument('-d', '--debug', help="Print debugging statements (default: %(default)s)", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.WARNING)
    arg_parser.add_argument('--web-port', type=int, default=8080, help="Web UI port (default: %(default)s)")
    arg_parser.add_argument('--macro', help="Macro file to run on startup (from macros/ dir)", default=None)
    arg_parser.add_argument("IP", help="TN3270 server IP address")
    arg_parser.add_argument("PORT", help="TN3270 server port")

    args = arg_parser.parse_args()

    Gr0gu3270 = libGr0gu3270.Gr0gu3270(
                 server_ip = args.IP,
                 server_port = args.PORT,
                 proxy_port=args.proxy_port,
                 proxy_ip=args.proxy_ip,
                 offline_mode = args.offline,
                 project_name = args.name,
                 loglevel=args.loglevel,
                 tls_enabled = args.tls,
                 logfile=None
    )

    # CLI proxy_port always wins over stale DB value
    Gr0gu3270.proxy_port = args.proxy_port

    import web
    import threading

    ui = web.Gr0gu3270WebUI(Gr0gu3270, port=args.web_port)

    if not Gr0gu3270.is_offline():
        def connect_proxy():
            print("Waiting for TN3270 connection on {}:{}...".format(
                Gr0gu3270.proxy_ip, Gr0gu3270.proxy_port))
            Gr0gu3270.client_connect()
            print("Client connected.")
            # Wrap client socket for non-blocking sends
            Gr0gu3270.client = web.NonBlockingClientSocket(Gr0gu3270.client)
            Gr0gu3270.server_connect()
            print("Server connected.")
            Gr0gu3270.check_inject_3270e()
            ui.state.connection_ready.set()
            from web import _dt
            _dt('CONNECTION_READY client+server connected')
            if args.macro:
                import time
                time.sleep(0.5)
                ui.state.macro_run({'file': args.macro})

        t = threading.Thread(target=connect_proxy, daemon=True)
        t.start()
    else:
        ui.state.connection_ready.set()

    ui.start()

main()
