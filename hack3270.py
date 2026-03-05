#!/usr/bin/env python3

import libhack3270
import argparse
import logging

def main():

    desc = 'Hack3270 - The TN3270 Penetration Testing Toolkit'
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
    arg_parser.add_argument('--ui', choices=['web', 'tk'], default='web', help="UI mode: web (default) or tk")
    arg_parser.add_argument('--web-port', type=int, default=8080, help="Web UI port (default: %(default)s)")
    arg_parser.add_argument("IP", help="TN3270 server IP address")
    arg_parser.add_argument("PORT", help="TN3270 server port")

    args = arg_parser.parse_args()

    hack3270 = libhack3270.hack3270(
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
    hack3270.proxy_port = args.proxy_port

    if args.ui == 'tk':
        import tk
        from tkinter import Tk
        from tkinter import ttk

        root = Tk()
        style = ttk.Style()
        style.theme_create( "hackallthethings", parent="alt", settings={
                "TButton": {"configure": {"background": "light grey" , "anchor": "center", "relief": "solid"} },
                "Treeview": {"configure": {"background": "white" } },
                "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0] } },
                "TNotebook.Tab": {
                    "configure": {"padding": [5, 1], "background": "dark grey" },
                    "map":       {"background": [("selected", "light grey"), ('disabled','grey')],
                                "expand": [("selected", [1, 1, 1, 0])] } } } )
        style.theme_use("hackallthethings")
        my_gui = tk.tkhack3270(root, style, hack3270, logfile=None,loglevel=args.loglevel)
    else:
        import web
        import threading

        ui = web.Hack3270WebUI(hack3270, port=args.web_port)

        if not hack3270.is_offline():
            def connect_proxy():
                print("Waiting for TN3270 connection on {}:{}...".format(
                    hack3270.proxy_ip, hack3270.proxy_port))
                hack3270.client_connect()
                print("Client connected.")
                # Wrap client socket for non-blocking sends
                hack3270.client = web.NonBlockingClientSocket(hack3270.client)
                hack3270.server_connect()
                print("Server connected.")
                hack3270.check_inject_3270e()
                ui.state.connection_ready.set()

            t = threading.Thread(target=connect_proxy, daemon=True)
            t.start()
        else:
            ui.state.connection_ready.set()

        ui.start()

main()
