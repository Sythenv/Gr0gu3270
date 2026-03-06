import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import tkinter.scrolledtext as tkk
import libGr0gu3270
import sys, signal, platform, logging, datetime, re, select

class tkGr0gu3270:
    def __init__(self, master, style, Gr0gu3270, logfile=None,loglevel=logging.WARNING):

        self.root = master  # Tk root
        self.style = style  # Tk Style
        self.Gr0gu3270 = Gr0gu3270 #Initialized Gr0gu3270 object
        self.last_db_id = 0

        # Create the Loggers (file and stderr)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        if logfile is not None:
            logger_formatter = logging.Formatter(
                '%(levelname)s :: {} :: %(funcName)s'
                ' :: %(message)s'.format(self.filename))
        else:
            logger_formatter = logging.Formatter(
                '%(module)s :: %(levelname)s :: %(funcName)s :: %(lineno)d :: %(message)s')
        # Log to stderr
        ch = logging.StreamHandler()
        ch.setFormatter(logger_formatter)
        ch.setLevel(loglevel)
        if not self.logger.hasHandlers():
            self.logger.addHandler(ch)

        self.style.theme_use("hackallthethings")
        self.tabControl = ttk.Notebook(self.root)

        self.tk_vars_init()

        self.root_height = 100
        self.exit_loop = False

        # handle ctrl-c
        self.logger.debug("Setting up SIGINT handler")
        signal.signal(signal.SIGINT, self.sigint_handler)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.frame = tk.Frame(self.root)
        self.frame.pack(side="top", expand=True, fill="both")

        self.root.title("{} v{}".format(libGr0gu3270.__name__ ,libGr0gu3270.__version__))

        self.darwin_resize()

        self.initial_window()

        if self.Gr0gu3270.is_offline():
            status = tk.Label(self.frame, text="OFFLINE LOG ANALYSIS MODE", bg='light grey').pack()
        else:
            self.Gr0gu3270.server_connect()


        if self.Gr0gu3270.is_offline():
            self.logger.debug("Offline mode enabled.")
            self.offline_init()
        else:
            self.Gr0gu3270.check_inject_3270e()

        self.tabs_init()

        if self.Gr0gu3270.is_offline():
            self.tabControl.tab(0, state="disabled")
            self.tabControl.tab(1, state="disabled")
            self.tabControl.tab(2, state="disabled")
            self.tabControl.tab(3, state="disabled")
            self.tabControl.tab(10, state="disabled")  # Security Audit needs live connection

        self.lastTab = 0
        self.tabNum = -1
        self.tabControl.bind("<<NotebookTabChanged>>", self.resize_window)

        self.root.after(10, self.run_it)
        self.root.mainloop()

    def run_it(self):

        if self.Gr0gu3270.is_offline():
            self.lastTab = self.tabNum
            self.root.update()
            return

        self.Gr0gu3270.daemon()
        if self.tabNum == 2: # Inject Keys
            self.aid_refresh()
        self.lastTab = self.tabNum
        self.root.update_idletasks()
        self.root.after(10, self.run_it)

    def tk_vars_init(self):
        self.logger.debug("Initializing Tk variables")
        self.tab1 = tk.Frame(self.tabControl, background="light grey")
        self.tab2 = tk.Frame(self.tabControl, background="light grey")
        self.tab3 = tk.Frame(self.tabControl, background="light grey")
        self.tab4 = tk.Frame(self.tabControl, background="light grey")
        self.tab5 = tk.Frame(self.tabControl, background="light grey")
        self.tab6 = tk.Frame(self.tabControl, background="light grey")
        self.tab7 = tk.Frame(self.tabControl, background="light grey")
        self.tab8 = tk.Frame(self.tabControl, background="light grey")   # ABEND Detection
        self.tab9 = tk.Frame(self.tabControl, background="light grey")   # Screen Map
        self.tab10 = tk.Frame(self.tabControl, background="light grey")  # Transactions
        self.tab11 = tk.Frame(self.tabControl, background="light grey")  # Security Audit
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.hack_prot = tk.IntVar(value = 1)
        self.auto_server = tk.IntVar(value = 1)
        self.auto_client = tk.IntVar(value = 0)
        self.hack_sf = tk.IntVar(value = 1)
        self.hack_sfe = tk.IntVar(value = 1)
        self.hack_mf = tk.IntVar(value = 1)
        self.hack_hf = tk.IntVar(value = 1)
        self.hack_rnr = tk.IntVar(value = 1)
        self.hack_ei = tk.IntVar(value = 1)
        self.hack_hv = tk.IntVar(value = 1)
        self.hack_color_sfe = tk.IntVar(value = 1)
        self.hack_color_mf = tk.IntVar(value = 1)
        self.hack_color_sa = tk.IntVar(value = 1)
        self.hack_color_hv = tk.IntVar(value = 1)
        self.aid_no = tk.IntVar(value = 1)
        self.aid_qreply = tk.IntVar(value = 1)
        self.aid_enter = tk.IntVar(value = 0)
        self.aid_pf1 = tk.IntVar(value = 1)
        self.aid_pf2 = tk.IntVar(value = 1)
        self.aid_pf3 = tk.IntVar(value = 1)
        self.aid_pf4 = tk.IntVar(value = 1)
        self.aid_pf5 = tk.IntVar(value = 1)
        self.aid_pf6 = tk.IntVar(value = 1)
        self.aid_pf7 = tk.IntVar(value = 1)
        self.aid_pf8 = tk.IntVar(value = 1)
        self.aid_pf9 = tk.IntVar(value = 1)
        self.aid_pf10 = tk.IntVar(value = 1)
        self.aid_pf11 = tk.IntVar(value = 1)
        self.aid_pf12 = tk.IntVar(value = 1)
        self.aid_pf13 = tk.IntVar(value = 1)
        self.aid_pf14 = tk.IntVar(value = 1)
        self.aid_pf15 = tk.IntVar(value = 1)
        self.aid_pf16 = tk.IntVar(value = 1)
        self.aid_pf17 = tk.IntVar(value = 1)
        self.aid_pf18 = tk.IntVar(value = 1)
        self.aid_pf19 = tk.IntVar(value = 1)
        self.aid_pf20 = tk.IntVar(value = 1)
        self.aid_pf21 = tk.IntVar(value = 1)
        self.aid_pf22 = tk.IntVar(value = 1)
        self.aid_pf23 = tk.IntVar(value = 1)
        self.aid_pf24 = tk.IntVar(value = 1)
        self.aid_oicr = tk.IntVar(value = 1)
        self.aid_msr_mhs = tk.IntVar(value = 1)
        self.aid_select = tk.IntVar(value = 1)
        self.aid_pa1 = tk.IntVar(value = 1)
        self.aid_pa2 = tk.IntVar(value = 1)
        self.aid_pa3 = tk.IntVar(value = 1)
        self.aid_clear = tk.IntVar(value = 0)
        self.aid_sysreq = tk.IntVar(value = 1)
        self.inject_enter = tk.IntVar(value = 1)
        self.inject_clear = tk.IntVar(value = 0)
        self.inject_mask = tk.StringVar(value = '*')
        self.inject_key = tk.StringVar(value = 'ENTER')
        self.inject_trunc = tk.StringVar(value = 'SKIP')
        self.abend_detection_var = tk.IntVar(value = 0)
        self.transaction_tracking_var = tk.IntVar(value = 0)
        self.last_abend_id = 0
        self.last_txn_id = 0
        self.last_audit_id = 0

    def tabs_init(self):
        # Tabs---
        self.logger.debug("Setting up Tabs")
        self.tabControl.add(self.tab1, text ='Hack Field Attributes')
        self.tabControl.add(self.tab2, text ='Hack Text Color')
        self.tabControl.add(self.tab3, text ='Inject Into Fields')
        self.tabControl.add(self.tab4, text ='Inject Key Presses')
        self.tabControl.add(self.tab5, text ='Logs')
        self.tabControl.add(self.tab6, text ='Statistics')
        self.tabControl.add(self.tab7, text ='Help')
        self.tabControl.add(self.tab8, text ='ABEND Detection')
        self.tabControl.add(self.tab9, text ='Screen Map')
        self.tabControl.add(self.tab10, text ='Transactions')
        self.tabControl.add(self.tab11, text ='Security Audit')
        self.tabControl.pack(expand = 1, fill ="both")

        self.hack_field_tabs()
        self.hack_color_tabs()
        self.inject_fields_tab()
        self.inject_aids_tab()
        self.logs_tab()
        self.statistic_tab()
        self.help_tab()
        self.abend_detection_tab()
        self.screen_map_tab()
        self.transactions_tab()
        self.security_audit_tab()

    def hack_field_tabs(self):
        # Tab : Hack Field Attributes---
        self.logger.debug("Setting up Hack Field Attributes tab")
        self.a1 = tk.Label(self.tab1, text='Hack Fields:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=10)
        self.hack_button = ttk.Button(self.tab1, text='OFF', width=8, command=self.hack_button_pressed)
        self.hack_button.place(x=20,y=33)
        a2 = tk.Checkbutton(self.tab1, text='Disable Field Protection', bg='light grey', variable=self.hack_prot, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=150, y=0)
        a3 = tk.Checkbutton(self.tab1, text='Enable Hidden Fields', bg='light grey', variable=self.hack_hf, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=150, y=25)
        a4 = tk.Checkbutton(self.tab1, text='Remove Numeric Only Restrictions', bg='light grey', variable=self.hack_rnr, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=150, y=50)
        a6 = tk.Checkbutton(self.tab1, text='Start Field', bg='light grey', variable=self.hack_sf, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=420, y=2)
        a7 = tk.Checkbutton(self.tab1, text='Start Field Extended', bg='light grey', variable=self.hack_sfe, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=420, y=25)
        a9 = tk.Checkbutton(self.tab1, text='Modify Field', bg='light grey', variable=self.hack_mf, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=420, y=50)
        a10 = tk.Label(self.tab1, text='Hidden Field Highlighting:', font="TkDefaultFont 12 underline", bg='light grey').place(x=600, y=2)
        a11 = tk.Checkbutton(self.tab1, text='Enable Intensity', bg='light grey', variable=self.hack_ei, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=600, y=25)
        a12 = tk.Checkbutton(self.tab1, text='High Visibility', bg='light grey', variable=self.hack_hv, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=600, y=50)

    def hack_color_tabs(self):
        # Tab : Hack Text Color
        self.logger.debug("Setting up Hack Text Color tab")
        d1 = tk.Label(self.tab2, text='Hack Color:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=10)
        self.hack_color_button = ttk.Button(self.tab2, text='OFF', width=8, command=self.hack_color_button_pressed)
        self.hack_color_button.place(x=20,y=33)
        d2 = tk.Checkbutton(self.tab2, text='Start Field Extended', bg='light grey', variable=self.hack_color_sfe, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=150, y=2)
        d3 = tk.Checkbutton(self.tab2, text='Modify Field', bg='light grey', variable=self.hack_color_mf, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=150, y=25)
        d4 = tk.Checkbutton(self.tab2, text='Set Attribute', bg='light grey', variable=self.hack_color_sa, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=150, y=50)
        d5 = tk.Label(self.tab2, text='Hidden Color Highlighting:', font="TkDefaultFont 12 underline", bg='light grey').place(x=330, y=2)
        d6 = tk.Checkbutton(self.tab2, text='High Visibility', bg='light grey', variable=self.hack_color_hv, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=330, y=25)

    def inject_fields_tab(self):
        # Tab : Inject Into Fields---
        self.logger.debug("Setting up Inject Into Fields tab")
        b0 = tk.Label(self.tab3, text='Status:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=12)
        self.inject_status = tk.Label(self.tab3, text = 'Not Ready.', bg='light grey')
        self.inject_status.place(x=23, y=40)
        inject_file_button = ttk.Button(self.tab3, text='FILE', width=8, command=self.browse_files).place(x=125, y=2)
        inject_setup_button = ttk.Button(self.tab3, text='SETUP', width=8, command=self.inject_setup).place(x=200, y=2)
        inject_button = ttk.Button(self.tab3, text='INJECT', width=8, command=self.inject_go).place(x=275, y=2)
        inject_reset_button = ttk.Button(self.tab3, text='RESET', width=8, command=self.inject_reset).place(x=350, y=2)
        b1 = tk.Label(self.tab3, text='Mask:', font="TkDefaultFont 12 underline", bg='light grey').place(x=475, y=9)
        b2options = ["@", "#", "$", "%", "^", "&", "*"]
        b2 =ttk.OptionMenu(self.tab3, self.inject_mask, b2options[6], *b2options).place(x=525, y=8)
        b3 = tk.Label(self.tab3, text='Mode:', font="TkDefaultFont 12 underline", bg='light grey').place(x=600, y=9)
        b4options = ["SKIP", "TRUNC"]
        b4 =ttk.OptionMenu(self.tab3, self.inject_trunc, b4options[0], *b4options).place(x=650, y=8)
        b5 = tk.Label(self.tab3, text='Keys:', font="TkDefaultFont 12 underline", bg='light grey').place(x=750, y=9)
        b6options = ["ENTER", "ENTER+CLEAR", "ENTER+PF3", "ENTER+PF3+CLEAR"]
        b6 =ttk.OptionMenu(self.tab3, self.inject_key, b6options[0], *b6options).place(x=800, y=8)
    
    def inject_aids_tab(self):
        # Tab : Inject Key Presses---
        self.logger.debug("Setting up Inject Key Presses tab")
        send_button = ttk.Button(self.tab4, text = 'Send Keys', command=self.send_keys, width=10).place(x=25, y=12)
        self.send_label = tk.Label(self.tab4, text = 'Ready.', bg='light grey')
        self.send_label.place(x=25, y=50)
        c1 = tk.Checkbutton(self.tab4, text='NO',variable=self.aid_no, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=0)
        c2 = tk.Checkbutton(self.tab4, text='QREPLY',variable=self.aid_qreply, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=0)
        c3 = tk.Checkbutton(self.tab4, text='ENTER',variable=self.aid_enter, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=0)
        c4 = tk.Checkbutton(self.tab4, text='PF1',variable=self.aid_pf1, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=0)
        c5 = tk.Checkbutton(self.tab4, text='PF2',variable=self.aid_pf2, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=0)
        c6 = tk.Checkbutton(self.tab4, text='PF3',variable=self.aid_pf3, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=0)
        c7 = tk.Checkbutton(self.tab4, text='PF4',variable=self.aid_pf4, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=0)
        c8 = tk.Checkbutton(self.tab4, text='PF5',variable=self.aid_pf5, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=0)
        c9 = tk.Checkbutton(self.tab4, text='PF6',variable=self.aid_pf6, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=0)
        c10 = tk.Checkbutton(self.tab4, text='PF7',variable=self.aid_pf7, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=0)
        c11 = tk.Checkbutton(self.tab4, text='PF8',variable=self.aid_pf8, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=0)
        c12 = tk.Checkbutton(self.tab4, text='PF9',variable=self.aid_pf9, onvalue=1, offvalue=0, bg='light grey').place(x=1250, y=0)
        c13 = tk.Checkbutton(self.tab4, text='PF10',variable=self.aid_pf10, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=25)
        c14 = tk.Checkbutton(self.tab4, text='PF11',variable=self.aid_pf11, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=25)
        c15 = tk.Checkbutton(self.tab4, text='PF12',variable=self.aid_pf12, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=25)
        c16 = tk.Checkbutton(self.tab4, text='PF13',variable=self.aid_pf13, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=25)
        c17 = tk.Checkbutton(self.tab4, text='PF14',variable=self.aid_pf14, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=25)
        c18 = tk.Checkbutton(self.tab4, text='PF15',variable=self.aid_pf15, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=25)
        c19 = tk.Checkbutton(self.tab4, text='PF16',variable=self.aid_pf16, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=25)
        c20 = tk.Checkbutton(self.tab4, text='PF17',variable=self.aid_pf17, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=25)
        c21 = tk.Checkbutton(self.tab4, text='PF18',variable=self.aid_pf18, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=25)
        c22 = tk.Checkbutton(self.tab4, text='PF19',variable=self.aid_pf19, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=25)
        c23 = tk.Checkbutton(self.tab4, text='PF20',variable=self.aid_pf20, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=25)
        c24 = tk.Checkbutton(self.tab4, text='PF21',variable=self.aid_pf21, onvalue=1, offvalue=0, bg='light grey').place(x=1250, y=25)
        c25 = tk.Checkbutton(self.tab4, text='PF22',variable=self.aid_pf22, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=50)
        c26 = tk.Checkbutton(self.tab4, text='PF23',variable=self.aid_pf23, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=50)
        c27 = tk.Checkbutton(self.tab4, text='PF24',variable=self.aid_pf24, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=50)
        c28 = tk.Checkbutton(self.tab4, text='OICR',variable=self.aid_oicr, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=50)
        c29 = tk.Checkbutton(self.tab4, text='MSR_MHS',variable=self.aid_msr_mhs, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=50)
        c30 = tk.Checkbutton(self.tab4, text='SELECT',variable=self.aid_select, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=50)
        c31 = tk.Checkbutton(self.tab4, text='PA1',variable=self.aid_pa1, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=50)
        c32 = tk.Checkbutton(self.tab4, text='PA2',variable=self.aid_pa2, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=50)
        c33 = tk.Checkbutton(self.tab4, text='PA3',variable=self.aid_pa3, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=50)
        c34 = tk.Checkbutton(self.tab4, text='CLEAR',variable=self.aid_clear, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=50)
        c35 = tk.Checkbutton(self.tab4, text='SYSREQ',variable=self.aid_sysreq, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=50)

    def logs_tab(self):
        self.logger.debug("Setting up Logs tab")
        # Tab : Logs---
        self.treev = ttk.Treeview(self.tab5, selectmode="browse")
        self.treev.place(x=25, y=10, height=220, relwidth=0.985)
        verscrlbar = ttk.Scrollbar(self.tab5, orient ="vertical", command = self.treev.yview)
        self.treev.configure(yscrollcommand = verscrlbar.set)
        verscrlbar.place(x=5, y=10, height=220)
        self.treev["columns"] = ("1", "2", "3", "4", "5")
        self.treev['show'] = 'headings'
        self.treev.column("1", width = int(self.screen_width * 0.05), anchor ='center')
        self.treev.column("2", width = int(self.screen_width * 0.15), anchor ='center')
        self.treev.column("3", width = int(self.screen_width * 0.05), anchor ='center')
        self.treev.column("4", width = int(self.screen_width * 0.05), anchor ='center')
        self.treev.column("5", width = int(self.screen_width * 0.66), anchor ='sw')
        self.treev.heading("1", text ="ID", command=lambda:self.sort_numeric_column(self.treev, "1", False))
        self.treev.heading("2", text ="Timestamp", command=lambda:self.sort_column(self.treev, "2", False))
        self.treev.heading("3", text ="Sender", command=lambda:self.sort_column(self.treev, "3", False))
        self.treev.heading("4", text ="Length", command=lambda:self.sort_numeric_column(self.treev, "4", False))
        self.treev.heading("5", text ="Notes", command=lambda:self.sort_column(self.treev, "5", False))   

        self.update_logs_tab()

        self.treev.bind('<<TreeviewSelect>>', self.fetch_item)
        self.d1 = tkk.ScrolledText(master = self.tab5, wrap = tk.CHAR, height=12)
        if platform.system()=="Darwin":
        #    self.d1.place(x=25, y=235, width=screen_width - 105, height=220)
            self.d1.place(x=25, y=235, relwidth=0.985, height=220)
        else:
            self.d1.place(x=25, y=235, width=self.screen_width - 60, height=220)
        self.d1.config(state = "disabled")
        d2 = tk.Checkbutton(self.tab5, text='Auto Send Server', bg='light grey', variable=self.auto_server, onvalue=1, offvalue=0).place(x=25, y=465)
        d2 = tk.Checkbutton(self.tab5, text='Auto Send Client', bg='light grey', variable=self.auto_client, onvalue=1, offvalue=0).place(x=175, y=465)
        export_button = ttk.Button(self.tab5, text = 'Export to CSV', command=self.export_csv, width=10).place(x=345, y=465)
        self.export_label = tk.Label(self.tab5, text = 'Ready.', font="TkDefaultFont 12", bg='light grey')
        self.export_label.place(x=450, y=465)     

    def statistic_tab(self):
        self.logger.debug("Setting up Statistics tab")
        ip_label = tk.Label(self.tab6, text = 'Server IP Address: {}'.format(self.Gr0gu3270.get_ip_port()[0]),  font="TkDefaultFont 14", bg='light grey')
        ip_label.place(x=25, y=20)
        port_label = tk.Label(self.tab6, text = 'Server TCP Port: {}'.format(self.Gr0gu3270.get_ip_port()[1]), font="TkDefaultFont 14", bg='light grey')
        port_label.place(x=25, y=40)

        port_label = tk.Label(self.tab6, text = 'TLS Enabled: {}'.format(self.Gr0gu3270.get_tls()), font="TkDefaultFont 14", bg='light grey')
        port_label.place(x=25, y=60)
        
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


        for record in self.Gr0gu3270.all_logs():
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
        total_time += start_timestamp - last_timestamp

        connections_label = tk.Label(self.tab6, text = 'Total Numer of TCP Connections: ' + str(total_connections), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=90)
        connections_label = tk.Label(self.tab6, text = 'Total Server Messages: ' + str(server_messages), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=110)
        connections_label = tk.Label(self.tab6, text = 'Total Client Messages: ' + str(client_messages), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=130)
        connections_label = tk.Label(self.tab6, text = 'Total Server Bytes: ' + str(server_bytes), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=150)
        connections_label = tk.Label(self.tab6, text = 'Total Client Bytes: ' + str(client_bytes), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=170)
        connections_label = tk.Label(self.tab6, text = 'Total Numer of Hacks: ' + str(total_hacks), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=190)
        connections_label = tk.Label(self.tab6, text = 'Total Numer of Injections: ' + str(total_injections), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=210)
        connections_label = tk.Label(self.tab6, text = 'Total Connect Time: ' + self.get_elapsed_time(total_time), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=230)

    def help_tab(self):
        e1 = tkk.ScrolledText(master = self.tab7, wrap = tk.WORD, width = 20, height = 20)

        with open("README.MD", "r") as readme_file:
            e1.insert(tk.INSERT, readme_file.read())

        e1.pack(padx = 10, pady = 10, fill=tk.BOTH, expand=True)
        e1.config(state = "disabled")

    def update_logs_tab(self):
        for row in self.Gr0gu3270.all_logs(self.last_db_id):
            self.treev.insert('', 'end',text="",values=(row[0], datetime.datetime.fromtimestamp(float(row[1])), self.Gr0gu3270.expand_CS(row[2]), row[4], row[3]))
            self.last_db_id = int(row[0])

    def offline_init(self):
            my_record_num = 1
            while self.Gr0gu3270.check_record(my_record_num):
                if self.Gr0gu3270.check_server(my_record_num):
                    self.logger.debug("Playing server message: " + str(my_record_num))
                    self.Gr0gu3270.play_record(my_record_num)
                else:
                    self.logger.debug("Waiting for message from client.")
                    self.Gr0gu3270.recv()
                my_record_num = my_record_num + 1
            self.logger.debug("Telnet negotiation complete.")
            self.logger.debug("Displaying splash screen.")
            while self.Gr0gu3270.check_server(my_record_num):
                self.logger.debug("Playing server message: " + str(my_record_num))
                self.Gr0gu3270.play_record(my_record_num)
                my_record_num = my_record_num + 1

    def initial_window(self):
        ip, port = self.Gr0gu3270.get_proxy_ip_port()
        status = tk.Label(self.frame, text = "Waiting for TN3270 connection on  {}:{}".format(ip,port))
        status.pack()
        self.frame.update()
        self.Gr0gu3270.client_connect()
        status = tk.Label(self.frame, text = "Connection received.")
        status.pack()
        self.frame.update()

        self.logger.debug("Waiting for button press after inital connection")

        B = tk.Button(self.frame, text ="Click to Continue", command = self.continue_func)
        B.pack()
        while True:
            self.root.update()
            if self.exit_loop:
                break

    def continue_func(self):
        self.frame.destroy()
        self.root.update()
        self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
        self.exit_loop = True
        return

    def darwin_resize(self):
        if platform.system()=="Darwin":
            self.logger.debug("Darwin detected")
            self.root.geometry(str(int(self.screen_width / 2))+'x120+'+str(int((self.screen_width / 4)))+'+0')
        else:
            self.root.geometry(str(int(self.screen_width / 2))+'x100+'+str(int((self.screen_width / 4)))+'+0')
    
    def on_closing(self):

        self.root.protocol("WM_DELETE_WINDOW")
        self.Gr0gu3270.on_closing()
        self.tabControl.tab(0, state="disabled")
        self.tabControl.tab(1, state="disabled")
        self.tabControl.tab(3, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.root.destroy()
        self.logger.debug("Exiting.")
        sys.exit(0)

    def sigint_handler(self, signum, frame):
        self.logger.debug("Shutting Down")
        self.Gr0gu3270.on_closing()
        self.tabControl.tab(0, state="disabled")
        self.tabControl.tab(1, state="disabled")
        self.tabControl.tab(3, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.root.destroy()
        sys.exit(0)

    def hack_button_pressed(self):

        self.set_checkbox_values()
        if self.Gr0gu3270.get_hack_on():
            self.Gr0gu3270.set_hack_on(0)
            self.hack_button["text"] = 'OFF'
            self.root.update()
            self.Gr0gu3270.set_hack_toggled()
        else:
            self.Gr0gu3270.set_hack_on(1)
            self.hack_button["text"] = 'ON'
            self.root.update()
            self.Gr0gu3270.set_hack_toggled()
        return

    def hack_color_button_pressed(self):
        self.set_checkbox_values()

        if self.Gr0gu3270.get_hack_color_on():
            self.Gr0gu3270.set_hack_color_on(0)
            self.hack_color_button["text"] = 'OFF'
            self.root.update()
            self.Gr0gu3270.set_hack_color_toggled()
        else:
            self.Gr0gu3270.set_hack_color_on(1)
            self.hack_color_button["text"] = 'ON'
            self.root.update()
            self.Gr0gu3270.set_hack_color_toggled()
        return

    def hack_toggle(self):
        self.set_checkbox_values()
        self.Gr0gu3270.set_hack_toggled(1)
        return
    
    def hack_color_toggle(self):
        self.set_checkbox_values()
        self.Gr0gu3270.set_hack_color_toggled(1)
        return

    def set_checkbox_values(self):
        self.Gr0gu3270.set_hack_prot(self.hack_prot.get())
        self.Gr0gu3270.set_hack_hf(self.hack_hf.get())
        self.Gr0gu3270.set_hack_rnr(self.hack_rnr.get())
        self.Gr0gu3270.set_hack_sf(self.hack_sf.get())
        self.Gr0gu3270.set_hack_sfe(self.hack_sfe.get())
        self.Gr0gu3270.set_hack_mf(self.hack_mf.get())
        self.Gr0gu3270.set_hack_ei(self.hack_ei.get())
        self.Gr0gu3270.set_hack_hv(self.hack_hv.get())
        self.Gr0gu3270.set_hack_color_sfe(self.hack_color_sfe.get())
        self.Gr0gu3270.set_hack_color_mf(self.hack_color_mf.get())
        self.Gr0gu3270.set_hack_color_sa(self.hack_color_sa.get())
        self.Gr0gu3270.set_hack_color_hv(self.hack_color_hv.get())
        
    
    def browse_files(self):
        self.logger.debug("Opening browse file dialogue")
        self.inject_filename = filedialog.askopenfilename(initialdir = "injections", title = "Select file for injections", filetypes = (("Text Files", "*.txt"), ("All Files", "*")))
        if self.inject_filename:
            self.inject_status["text"] = "Filename set to: " + self.inject_filename
            self.logger.debug("Inject Filename: {}".format(self.inject_filename))
        else:
            self.inject_status["text"] = "Error: file not set."
            self.inject_filename = ""
        self.root.update()
        return
    
    def inject_setup(self):
        self.inject_status["text"] = "Submit data using mask character of '{}' to setup injection.".format(self.inject_mask.get())
        self.Gr0gu3270.set_inject_mask(self.inject_mask.get())
        self.root.update()
        self.Gr0gu3270.set_inject_setup_capture()
        return
    
    def inject_go(self):

        if (not self.inject_filename) and (not self.Gr0gu3270.get_inject_config_set()):
            self.inject_status["text"] = "First select a file for injection, then click SETUP."
            self.root.update()
            return
        
        if not self.inject_filename:
            self.logger.debug("Injection file not setup.")
            self.inject_status["text"] = "Injection file not set.  Click FILE."
            self.root.update()
            return
        
        if not self.Gr0gu3270.get_inject_config_set():
            self.logger.debug("Field for injection hasn't been setup.")
            self.inject_status["text"] = "Field for injection hasn't been setup.  Click SETUP."
            self.root.update()
            return

        self.logger.debug("All setup conditions met... injecting")
        self.disable_tabs(2)

        injections = open(self.inject_filename, 'r')
        while True:
            injection_line = injections.readline()

            if not injection_line:
                break

            injection_line = injection_line.rstrip()

            if self.inject_trunc.get() == 'TRUNC':
                injection_line = injection_line[:self.Gr0gu3270.get_inject_mask_len()]

            if len(injection_line) <= self.Gr0gu3270.get_inject_mask_len():
                injection_ebcdic = self.Gr0gu3270.get_ebcdic(injection_line)
                bytes_ebcdic = self.Gr0gu3270.get_inject_preamble() + injection_ebcdic + self.Gr0gu3270.get_inject_postamble()
                self.Gr0gu3270.write_log('C', 'Sending: ' + injection_line, bytes_ebcdic)
                self.Gr0gu3270.send_server(bytes_ebcdic)
                self.inject_status["text"] = "Sending: " + injection_line
                self.root.update()
                self.Gr0gu3270.tend_server()
            if self.inject_key.get() == 'ENTER+CLEAR':
                self.Gr0gu3270.send_key('CLEAR', b'\x6d')
            elif self.inject_key.get() == 'ENTER+PF3':
                self.Gr0gu3270.send_key('PF3', b'\xf3')
            elif self.inject_key.get() == 'ENTER+PF3+CLEAR':
                self.Gr0gu3270.send_key('PF3', b'\xf3')
                self.Gr0gu3270.send_key('CLEAR', b'\x6d')

        injections.close()
        self.enable_tabs()

        return

    def disable_tabs(self,skip=-1):
        '''
        disables all tabs except the skip (int) tab
        '''
        
        tabs = (num for num in range(0,11) if num != skip)
        for tab in tabs:
            self.logger.debug("Disabling Tab{}".format(tab))
            self.tabControl.tab(tab, state="disabled")

    def enable_tabs(self):
        for tab in range(0,11):
            self.logger.debug("Enabling Tab{}".format(tab))
            self.tabControl.tab(tab, state="normal")
            

    def inject_reset(self):
        self.Gr0gu3270.set_inject_config_set(0)
        self.inject_status["text"] = "Configuration cleared."
        self.root.update()
        return
    
    def send_keys(self):

        self.disable_tabs(3)


        # TODO: Rewrite this function to use a loop
        if self.aid_no.get(): self.Gr0gu3270.send_key('NO', b'\x60')
        if self.aid_qreply.get(): self.Gr0gu3270.send_key('QREPLY', b'\x61')
        if self.aid_enter.get(): self.Gr0gu3270.send_key('ENTER', b'\x7d')
        if self.aid_pf1.get(): self.Gr0gu3270.send_key('PF1', b'\xf1')
        if self.aid_pf2.get(): self.Gr0gu3270.send_key('PF2', b'\xf2')
        if self.aid_pf3.get(): self.Gr0gu3270.send_key('PF3', b'\xf3')
        if self.aid_pf4.get(): self.Gr0gu3270.send_key('PF4', b'\xf4')
        if self.aid_pf5.get(): self.Gr0gu3270.send_key('PF5', b'\xf5')
        if self.aid_pf6.get(): self.Gr0gu3270.send_key('PF6', b'\xf6')
        if self.aid_pf7.get(): self.Gr0gu3270.send_key('PF7', b'\xf7')
        if self.aid_pf8.get(): self.Gr0gu3270.send_key('PF8', b'\xf8')
        if self.aid_pf9.get(): self.Gr0gu3270.send_key('PF9', b'\xf9')
        if self.aid_pf10.get(): self.Gr0gu3270.send_key('PF10', b'\x7a')
        if self.aid_pf11.get(): self.Gr0gu3270.send_key('PF11', b'\x7b')
        if self.aid_pf12.get(): self.Gr0gu3270.send_key('PF12', b'\x7c')
        if self.aid_pf13.get(): self.Gr0gu3270.send_key('PF13', b'\xc1')
        if self.aid_pf14.get(): self.Gr0gu3270.send_key('PF14', b'\xc2')
        if self.aid_pf15.get(): self.Gr0gu3270.send_key('PF15', b'\xc3')
        if self.aid_pf16.get(): self.Gr0gu3270.send_key('PF16', b'\xc4')
        if self.aid_pf17.get(): self.Gr0gu3270.send_key('PF17', b'\xc5')
        if self.aid_pf18.get(): self.Gr0gu3270.send_key('PF18', b'\xc6')
        if self.aid_pf19.get(): self.Gr0gu3270.send_key('PF19', b'\xc7')
        if self.aid_pf20.get(): self.Gr0gu3270.send_key('PF20', b'\xc8')
        if self.aid_pf21.get(): self.Gr0gu3270.send_key('PF21', b'\xc9')
        if self.aid_pf22.get(): self.Gr0gu3270.send_key('PF22', b'\x4a')
        if self.aid_pf23.get(): self.Gr0gu3270.send_key('PF23', b'\x4b')
        if self.aid_pf24.get(): self.Gr0gu3270.send_key('PF24', b'\x4c')
        if self.aid_oicr.get(): self.Gr0gu3270.send_key('OICR', b'\xe6')
        if self.aid_msr_mhs.get(): self.Gr0gu3270.send_key('MSR_MHS', b'\xe7')
        if self.aid_select.get(): self.Gr0gu3270.send_key('SELECT', b'\x7e')
        if self.aid_pa1.get(): self.Gr0gu3270.send_key('PA1', b'\x6c')
        if self.aid_pa2.get(): self.Gr0gu3270.send_key('PA2', b'\x6e')
        if self.aid_pa3.get(): self.Gr0gu3270.send_key('PA3', b'\x6b')
        if self.aid_clear.get(): self.Gr0gu3270.send_key('CLEAR', b'\x6d')
        if self.aid_sysreq.get(): self.Gr0gu3270.send_key('SYSREQ', b'\xf0')
        self.send_label["text"] = 'Ready.'

        self.enable_tabs()
        return
    
    def sort_column(self, tree, col, reverse):
        data = [(tree.set(child, col), child) for child in tree.get_children('')]
        data.sort(reverse=reverse)
        for i, (_, child) in enumerate(data):
            tree.move(child, '', i)
        tree.heading(col, command=lambda:self.sort_column(tree, col, not reverse))

    def sort_numeric_column(self, tree, col, reverse):
        data = [(float(tree.set(child, col)), child) for child in tree.get_children('')]
        data.sort(reverse=reverse)
        for i, (_, child) in enumerate(data):
            tree.move(child, '', i)
        tree.heading(col, command=lambda:self.sort_numeric_column(tree, col, not reverse))

    def fetch_item(self,unused):

        style = ttk.Style()
        style.map('Treeview', foreground=[('focus', 'black')], background=[('focus', 'light blue')])
        current_item = self.treev.focus()
            
        dict_item = self.treev.item(current_item)
        record_id = dict_item['values'][0]
        record_cs = dict_item['values'][2]

        for row in self.Gr0gu3270.get_log(record_id):
            ebcdic_data = self.Gr0gu3270.get_ascii(row[5])
            self.d1.config(state='normal')
            self.d1.delete('1.0', tk.END)
            if re.search("^tn3270 ", row[3]):
                parsed_3270 = self.Gr0gu3270.parse_telnet(ebcdic_data)
            else:
                parsed_3270 = self.Gr0gu3270.parse_3270(ebcdic_data)
            self.d1.insert(tk.INSERT, parsed_3270)
            self.d1.config(state='disabled')
            self.root.update()
            if record_cs == "Server" and self.auto_server.get() == 1:
                self.Gr0gu3270.send_client(row[5])
            if record_cs == "Client" and self.auto_client.get() == 1:
                self.Gr0gu3270.send_server(row[5])
        return
    
    def export_csv(self):
        self.export_label["text"] = 'Starting export.'
        self.root.update()
        csv_filename = self.Gr0gu3270.export_csv()
        self.export_label["text"] = 'Export finished, filename is: ' + csv_filename
        self.root.update()
        return
    
    def get_elapsed_time(self, elapsed):
        if elapsed < 60:
            seconds = int(elapsed)
            return f"{seconds} seconds"
        elif elapsed < 3600:
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            return f"{minutes} minutes and {seconds} seconds"
        elif elapsed < 86400:
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{hours} hours, {minutes} minutes and {seconds} seconds"
        else:
            days = int(elapsed // 86400)
            hours = int((elapsed % 86400) // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{days} days, {hours} hours, {minutes} minutes and {seconds} seconds"
        
    def resize_window(self, event): 
        self.tabNum = self.tabControl.index(self.tabControl.select())
        self.logger.debug("Tab Changed to: {}".format(self.tabNum))
        if self.tabNum != self.lastTab:
            if self.tabNum == 0: # Hack Fields
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 1: # Hack Colors
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 2: # Inject
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 3: # Inject Key Presses
                self.aid_refresh()
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 4: # Logs
                self.update_logs_tab()
                self.export_label["text"] = 'Ready.'
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 5: # Statistics
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 6: # Help
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 7: # ABEND Detection
                self.update_abend_tab()
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 8: # Screen Map
                self.update_screen_map_tab()
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 9: # Transactions
                self.update_transactions_tab()
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 10: # Security Audit
                self.update_audit_tab()
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
    
    # ---- PR1: ABEND Detection Tab ----

    def abend_detection_tab(self):
        self.logger.debug("Setting up ABEND Detection tab")
        # Toggle button
        self.abend_toggle_btn = ttk.Button(self.tab8, text='OFF', width=8, command=self.abend_toggle_pressed)
        self.abend_toggle_btn.place(x=20, y=10)
        tk.Label(self.tab8, text='ABEND Detection:', font="TkDefaultFont 12 underline", bg='light grey').place(x=110, y=12)
        self.abend_count_label = tk.Label(self.tab8, text='ABENDs detected: 0', font="TkDefaultFont 12", bg='light grey')
        self.abend_count_label.place(x=300, y=12)

        # Treeview
        self.abend_treev = ttk.Treeview(self.tab8, selectmode="browse")
        self.abend_treev.place(x=25, y=45, height=400, relwidth=0.985)
        abend_scroll = ttk.Scrollbar(self.tab8, orient="vertical", command=self.abend_treev.yview)
        self.abend_treev.configure(yscrollcommand=abend_scroll.set)
        abend_scroll.place(x=5, y=45, height=400)
        self.abend_treev["columns"] = ("1", "2", "3", "4", "5")
        self.abend_treev['show'] = 'headings'
        self.abend_treev.column("1", width=50, anchor='center')
        self.abend_treev.column("2", width=180, anchor='center')
        self.abend_treev.column("3", width=100, anchor='center')
        self.abend_treev.column("4", width=80, anchor='center')
        self.abend_treev.column("5", width=400, anchor='sw')
        self.abend_treev.heading("1", text="ID")
        self.abend_treev.heading("2", text="Timestamp")
        self.abend_treev.heading("3", text="Type")
        self.abend_treev.heading("4", text="Code")
        self.abend_treev.heading("5", text="Description")

    def abend_toggle_pressed(self):
        if self.Gr0gu3270.get_abend_detection():
            self.Gr0gu3270.set_abend_detection(0)
            self.abend_toggle_btn["text"] = 'OFF'
        else:
            self.Gr0gu3270.set_abend_detection(1)
            self.abend_toggle_btn["text"] = 'ON'
        self.root.update()

    def update_abend_tab(self):
        for row in self.Gr0gu3270.all_abends(self.last_abend_id):
            self.abend_treev.insert('', 'end', text="", values=(
                row[0],
                datetime.datetime.fromtimestamp(float(row[1])),
                row[2], row[3], row[4]
            ))
            self.last_abend_id = int(row[0])
        self.abend_count_label["text"] = 'ABENDs detected: {}'.format(self.Gr0gu3270.get_abend_count())

    # ---- PR2: Screen Map Tab ----

    def screen_map_tab(self):
        self.logger.debug("Setting up Screen Map tab")
        tk.Label(self.tab9, text='Current Screen Map:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=10)
        refresh_btn = ttk.Button(self.tab9, text='REFRESH', width=8, command=self.update_screen_map_tab)
        refresh_btn.place(x=250, y=8)

        self.smap_treev = ttk.Treeview(self.tab9, selectmode="browse")
        self.smap_treev.place(x=25, y=40, height=420, relwidth=0.985)
        smap_scroll = ttk.Scrollbar(self.tab9, orient="vertical", command=self.smap_treev.yview)
        self.smap_treev.configure(yscrollcommand=smap_scroll.set)
        smap_scroll.place(x=5, y=40, height=420)
        self.smap_treev["columns"] = ("1", "2", "3", "4", "5", "6", "7", "8")
        self.smap_treev['show'] = 'headings'
        self.smap_treev.column("1", width=50, anchor='center')
        self.smap_treev.column("2", width=50, anchor='center')
        self.smap_treev.column("3", width=80, anchor='center')
        self.smap_treev.column("4", width=80, anchor='center')
        self.smap_treev.column("5", width=70, anchor='center')
        self.smap_treev.column("6", width=70, anchor='center')
        self.smap_treev.column("7", width=60, anchor='center')
        self.smap_treev.column("8", width=400, anchor='sw')
        self.smap_treev.heading("1", text="Row")
        self.smap_treev.heading("2", text="Col")
        self.smap_treev.heading("3", text="Type")
        self.smap_treev.heading("4", text="Protected")
        self.smap_treev.heading("5", text="Hidden")
        self.smap_treev.heading("6", text="Numeric")
        self.smap_treev.heading("7", text="Length")
        self.smap_treev.heading("8", text="Content")

    def update_screen_map_tab(self):
        # Clear existing items
        for item in self.smap_treev.get_children():
            self.smap_treev.delete(item)
        screen_map = self.Gr0gu3270.get_screen_map()
        for f in screen_map:
            content = f.get('content', '').replace('\n', ' ')
            self.smap_treev.insert('', 'end', text="", values=(
                f['row'], f['col'], f['type'],
                'Yes' if f['protected'] else 'No',
                'Yes' if f['hidden'] else 'No',
                'Yes' if f['numeric'] else 'No',
                f['length'], content
            ))

    # ---- PR3: Transactions Tab ----

    def transactions_tab(self):
        self.logger.debug("Setting up Transactions tab")
        # Toggle
        self.txn_toggle_btn = ttk.Button(self.tab10, text='OFF', width=8, command=self.txn_toggle_pressed)
        self.txn_toggle_btn.place(x=20, y=10)
        tk.Label(self.tab10, text='Transaction Tracking:', font="TkDefaultFont 12 underline", bg='light grey').place(x=110, y=12)
        self.txn_stats_label = tk.Label(self.tab10, text='Total: 0 | Avg: 0ms', font="TkDefaultFont 12", bg='light grey')
        self.txn_stats_label.place(x=320, y=12)

        # Treeview
        self.txn_treev = ttk.Treeview(self.tab10, selectmode="browse")
        self.txn_treev.place(x=25, y=45, height=400, relwidth=0.985)
        txn_scroll = ttk.Scrollbar(self.tab10, orient="vertical", command=self.txn_treev.yview)
        self.txn_treev.configure(yscrollcommand=txn_scroll.set)
        txn_scroll.place(x=5, y=45, height=400)
        self.txn_treev["columns"] = ("1", "2", "3", "4", "5", "6")
        self.txn_treev['show'] = 'headings'
        self.txn_treev.column("1", width=50, anchor='center')
        self.txn_treev.column("2", width=180, anchor='center')
        self.txn_treev.column("3", width=120, anchor='center')
        self.txn_treev.column("4", width=100, anchor='center')
        self.txn_treev.column("5", width=100, anchor='center')
        self.txn_treev.column("6", width=100, anchor='center')
        self.txn_treev.heading("1", text="ID")
        self.txn_treev.heading("2", text="Timestamp")
        self.txn_treev.heading("3", text="Transaction")
        self.txn_treev.heading("4", text="Duration (ms)")
        self.txn_treev.heading("5", text="Response Size")
        self.txn_treev.heading("6", text="Status")

    def txn_toggle_pressed(self):
        if self.Gr0gu3270.get_transaction_tracking():
            self.Gr0gu3270.set_transaction_tracking(0)
            self.txn_toggle_btn["text"] = 'OFF'
        else:
            self.Gr0gu3270.set_transaction_tracking(1)
            self.txn_toggle_btn["text"] = 'ON'
        self.root.update()

    def update_transactions_tab(self):
        for row in self.Gr0gu3270.all_transactions(self.last_txn_id):
            self.txn_treev.insert('', 'end', text="", values=(
                row[0],
                datetime.datetime.fromtimestamp(float(row[1])),
                row[3], row[4], row[5], row[6]
            ))
            self.last_txn_id = int(row[0])
        stats = self.Gr0gu3270.get_transaction_stats()
        self.txn_stats_label["text"] = 'Total: {} | Avg: {}ms | Min: {}ms | Max: {}ms'.format(
            stats['count'], stats['avg_ms'], stats['min_ms'], stats['max_ms'])

    # ---- PR4: Security Audit Tab ----

    def security_audit_tab(self):
        self.logger.debug("Setting up Security Audit tab")
        self.audit_filename = ""

        # Controls row
        audit_file_btn = ttk.Button(self.tab11, text='FILE', width=8, command=self.audit_browse_files)
        audit_file_btn.place(x=20, y=10)
        self.audit_start_btn = ttk.Button(self.tab11, text='START', width=8, command=self.audit_start)
        self.audit_start_btn.place(x=100, y=10)
        self.audit_stop_btn = ttk.Button(self.tab11, text='STOP', width=8, command=self.audit_stop)
        self.audit_stop_btn.place(x=180, y=10)
        audit_export_btn = ttk.Button(self.tab11, text='EXPORT CSV', width=10, command=self.audit_export)
        audit_export_btn.place(x=260, y=10)
        self.audit_status_label = tk.Label(self.tab11, text='Ready.', font="TkDefaultFont 12", bg='light grey')
        self.audit_status_label.place(x=380, y=12)

        # Summary labels
        self.audit_summary_label = tk.Label(self.tab11, text='Accessible: 0 | Denied: 0 | ABEND: 0 | Not Found: 0 | Error: 0',
                                            font="TkDefaultFont 10", bg='light grey')
        self.audit_summary_label.place(x=25, y=40)

        # Treeview with color tags
        self.audit_treev = ttk.Treeview(self.tab11, selectmode="browse")
        self.audit_treev.place(x=25, y=65, height=380, relwidth=0.985)
        audit_scroll = ttk.Scrollbar(self.tab11, orient="vertical", command=self.audit_treev.yview)
        self.audit_treev.configure(yscrollcommand=audit_scroll.set)
        audit_scroll.place(x=5, y=65, height=380)
        self.audit_treev["columns"] = ("1", "2", "3", "4", "5")
        self.audit_treev['show'] = 'headings'
        self.audit_treev.column("1", width=50, anchor='center')
        self.audit_treev.column("2", width=180, anchor='center')
        self.audit_treev.column("3", width=120, anchor='center')
        self.audit_treev.column("4", width=100, anchor='center')
        self.audit_treev.column("5", width=400, anchor='sw')
        self.audit_treev.heading("1", text="ID")
        self.audit_treev.heading("2", text="Timestamp")
        self.audit_treev.heading("3", text="Transaction")
        self.audit_treev.heading("4", text="Status")
        self.audit_treev.heading("5", text="Response Preview")

        # Color tags
        self.audit_treev.tag_configure('accessible', background='#90EE90')
        self.audit_treev.tag_configure('denied', background='#FFB6C1')
        self.audit_treev.tag_configure('abend', background='#FFFF99')
        self.audit_treev.tag_configure('not_found', background='#D3D3D3')
        self.audit_treev.tag_configure('error', background='#FFA500')
        self.audit_treev.tag_configure('spool_open', background='#FF6B6B')
        self.audit_treev.tag_configure('spool_closed', background='#90EE90')

        # SPOOL/RCE section
        tk.Label(self.tab11, text='SPOOL/RCE:', font="TkDefaultFont 10 underline", bg='light grey').place(x=650, y=12)
        spool_check_btn = ttk.Button(self.tab11, text='CHECK', width=8, command=self.spool_check)
        spool_check_btn.place(x=750, y=10)

        tk.Label(self.tab11, text='IP:', font="TkDefaultFont 9", bg='light grey').place(x=840, y=14)
        self.spool_ip_var = tk.StringVar(value='10.10.10.10')
        spool_ip_entry = tk.Entry(self.tab11, textvariable=self.spool_ip_var, width=15)
        spool_ip_entry.place(x=860, y=12)
        tk.Label(self.tab11, text='Port:', font="TkDefaultFont 9", bg='light grey').place(x=980, y=14)
        self.spool_port_var = tk.StringVar(value='4444')
        spool_port_entry = tk.Entry(self.tab11, textvariable=self.spool_port_var, width=6)
        spool_port_entry.place(x=1015, y=12)

        spool_poc_btn = ttk.Button(self.tab11, text='FTP PoC', width=8, command=self.spool_poc)
        spool_poc_btn.place(x=1070, y=10)

    def audit_browse_files(self):
        self.audit_filename = filedialog.askopenfilename(
            initialdir="injections", title="Select transaction list",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*")))
        if self.audit_filename:
            self.audit_status_label["text"] = "File: " + self.audit_filename
        else:
            self.audit_status_label["text"] = "Error: file not set."
            self.audit_filename = ""
        self.root.update()

    def audit_start(self):
        if not self.audit_filename:
            self.audit_status_label["text"] = "Select a transaction list file first."
            self.root.update()
            return

        with open(self.audit_filename, 'r') as f:
            txn_list = [line.strip() for line in f if line.strip()]

        if not txn_list:
            self.audit_status_label["text"] = "Transaction list is empty."
            self.root.update()
            return

        self.Gr0gu3270.audit_start(txn_list)
        self.audit_status_label["text"] = "Auditing {} transactions...".format(len(txn_list))
        self.disable_tabs(10)
        self.root.update()
        self.audit_step()

    def audit_step(self):
        if not self.Gr0gu3270.get_audit_running():
            self.audit_status_label["text"] = "Audit complete. {} results.".format(len(self.Gr0gu3270.audit_results))
            self.enable_tabs()
            if self.Gr0gu3270.is_offline():
                self.tabControl.tab(0, state="disabled")
                self.tabControl.tab(1, state="disabled")
                self.tabControl.tab(2, state="disabled")
                self.tabControl.tab(3, state="disabled")
                self.tabControl.tab(10, state="disabled")
            self.update_audit_tab()
            self.root.update()
            return

        txn = self.Gr0gu3270.audit_next()
        if txn is None:
            self.audit_status_label["text"] = "Audit complete."
            self.enable_tabs()
            self.update_audit_tab()
            self.root.update()
            return

        self.audit_status_label["text"] = "Testing: {} ({}/{})".format(
            txn, self.Gr0gu3270.audit_index, len(self.Gr0gu3270.audit_txn_list))
        self.root.update()

        # Wait for response
        try:
            rlist, _, _ = select.select([self.Gr0gu3270.server], [], [], 2)
            if self.Gr0gu3270.server in rlist:
                server_data = self.Gr0gu3270.server.recv(libGr0gu3270.BUFFER_MAX)
                if len(server_data) > 0:
                    self.Gr0gu3270.handle_server(server_data)
        except Exception as e:
            self.logger.debug("Audit recv error: {}".format(e))

        self.update_audit_tab()
        # Schedule next step with delay
        self.root.after(500, self.audit_step)

    def audit_stop(self):
        self.Gr0gu3270.audit_stop()
        self.audit_status_label["text"] = "Audit stopped."
        self.enable_tabs()
        self.root.update()

    def audit_export(self):
        csv_file = self.Gr0gu3270.export_audit_csv()
        self.audit_status_label["text"] = "Exported to: " + csv_file
        self.root.update()

    def update_audit_tab(self):
        for row in self.Gr0gu3270.all_audit_results(self.last_audit_id):
            status = row[3]
            tag_map = {
                'ACCESSIBLE': 'accessible',
                'DENIED': 'denied',
                'ABEND': 'abend',
                'NOT_FOUND': 'not_found',
                'ERROR': 'error',
            }
            tag_map['SPOOL_OPEN'] = 'spool_open'
            tag_map['SPOOL_CLOSED'] = 'spool_closed'
            tag = tag_map.get(status, '')
            preview = row[4][:80] if row[4] else ''
            self.audit_treev.insert('', 'end', text="", values=(
                row[0],
                datetime.datetime.fromtimestamp(float(row[1])),
                row[2], status, preview
            ), tags=(tag,))
            self.last_audit_id = int(row[0])

        # Update summary
        results = self.Gr0gu3270.audit_results
        counts = {'ACCESSIBLE': 0, 'DENIED': 0, 'ABEND': 0, 'NOT_FOUND': 0, 'ERROR': 0, 'UNKNOWN': 0}
        for r in results:
            s = r.get('status', 'UNKNOWN')
            if s in counts:
                counts[s] += 1
        self.audit_summary_label["text"] = 'Accessible: {} | Denied: {} | ABEND: {} | Not Found: {} | Error: {}'.format(
            counts['ACCESSIBLE'], counts['DENIED'], counts['ABEND'], counts['NOT_FOUND'], counts['ERROR'])

    def spool_check(self):
        self.audit_status_label["text"] = "Checking SPOOL API..."
        self.root.update()
        try:
            result = self.Gr0gu3270.spool_check()
            self.audit_status_label["text"] = "SPOOL: {}".format(result['status'])
            self.update_audit_tab()
            if result['status'] == 'SPOOL_OPEN':
                messagebox.showwarning("SPOOL/RCE", result['detail'])
            else:
                messagebox.showinfo("SPOOL/RCE", result['detail'])
        except Exception as e:
            self.audit_status_label["text"] = "SPOOL check error: {}".format(e)
        self.root.update()

    def spool_poc(self):
        ip = self.spool_ip_var.get().strip()
        port = self.spool_port_var.get().strip()
        if not ip:
            messagebox.showerror("SPOOL/RCE", "Enter a listener IP address.")
            return
        try:
            port_int = int(port)
        except ValueError:
            messagebox.showerror("SPOOL/RCE", "Invalid port number.")
            return
        if not messagebox.askyesno("SPOOL/RCE - FTP PoC",
                "This will submit a FTP job on the mainframe that connects to {}:{}.\n\nProceed?".format(ip, port_int)):
            return
        self.audit_status_label["text"] = "Submitting FTP PoC..."
        self.root.update()
        try:
            result = self.Gr0gu3270.spool_poc_ftp(ip, port_int)
            self.audit_status_label["text"] = "SPOOL PoC: {}".format(result['status'])
            self.update_audit_tab()
            messagebox.showinfo("SPOOL/RCE", result['detail'])
        except Exception as e:
            self.audit_status_label["text"] = "SPOOL PoC error: {}".format(e)
        self.root.update()

    def aid_refresh(self):
        aids = self.Gr0gu3270.current_aids()
        #self.logger.debug("Found aids: {}".format(aids))
        self.aid_setdef()
        if "PF1" in aids: self.aid_pf1.set(0)
        if "PF2" in aids: self.aid_pf2.set(0)
        if "PF3" in aids: self.aid_pf3.set(0)
        if "PF4" in aids: self.aid_pf4.set(0)
        if "PF5" in aids: self.aid_pf5.set(0)
        if "PF6" in aids: self.aid_pf6.set(0)
        if "PF7" in aids: self.aid_pf7.set(0)
        if "PF8" in aids: self.aid_pf8.set(0)
        if "PF9" in aids: self.aid_pf9.set(0)
        if "PF10" in aids: self.aid_pf10.set(0)
        if "PF11" in aids: self.aid_pf11.set(0)
        if "PF12" in aids: self.aid_pf12.set(0)
        if "PF13" in aids: self.aid_pf13.set(0)
        if "PF14" in aids: self.aid_pf14.set(0)
        if "PF15" in aids: self.aid_pf15.set(0)
        if "PF16" in aids: self.aid_pf16.set(0)
        if "PF17" in aids: self.aid_pf17.set(0)
        if "PF18" in aids: self.aid_pf18.set(0)
        if "PF19" in aids: self.aid_pf19.set(0)
        if "PF20" in aids: self.aid_pf20.set(0)
        if "PF21" in aids: self.aid_pf21.set(0)
        if "PF22" in aids: self.aid_pf22.set(0)
        if "PF23" in aids: self.aid_pf23.set(0)
        if "PF24" in aids: self.aid_pf24.set(0)
    
    def aid_setdef(self):
        #self.logger.debug("Resetting AID checkboxes")
        self.aid_no.set(1)
        self.aid_qreply.set(1)
        self.aid_enter.set(0)
        self.aid_pf1.set(1)
        self.aid_pf2.set(1)
        self.aid_pf3.set(1)
        self.aid_pf4.set(1)
        self.aid_pf5.set(1)
        self.aid_pf6.set(1)
        self.aid_pf7.set(1)
        self.aid_pf8.set(1)
        self.aid_pf9.set(1)
        self.aid_pf10.set(1)
        self.aid_pf11.set(1)
        self.aid_pf12.set(1)
        self.aid_pf13.set(1)
        self.aid_pf14.set(1)
        self.aid_pf15.set(1)
        self.aid_pf16.set(1)
        self.aid_pf17.set(1)
        self.aid_pf18.set(1)
        self.aid_pf19.set(1)
        self.aid_pf20.set(1)
        self.aid_pf21.set(1)
        self.aid_pf22.set(1)
        self.aid_pf23.set(1)
        self.aid_pf24.set(1)
        self.aid_oicr.set(1)
        self.aid_msr_mhs.set(1)
        self.aid_select.set(1)
        self.aid_pa1.set(1)
        self.aid_pa2.set(1)
        self.aid_pa3.set(1)
        self.aid_clear.set(0)
        self.aid_sysreq.set(1)
