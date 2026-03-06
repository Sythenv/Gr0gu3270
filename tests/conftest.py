"""
Pytest fixtures for Gr0gu3270 core library testing.
Instantiates Gr0gu3270 with a temp SQLite DB — no network, no GUI.
"""
import os
import tempfile
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from libGr0gu3270 import Gr0gu3270


@pytest.fixture
def h3270(tmp_path):
    """Gr0gu3270 instance with temp DB, offline mode, no network."""
    db_name = str(tmp_path / "test")
    obj = Gr0gu3270(
        server_ip="127.0.0.1",
        server_port=3270,
        proxy_port=3271,
        offline_mode=True,
        project_name=db_name,
    )
    yield obj
    obj.sql_con.close()
