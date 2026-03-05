"""
Pytest fixtures for hack3270 core library testing.
Instantiates hack3270 with a temp SQLite DB — no network, no GUI.
"""
import os
import tempfile
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from libhack3270 import hack3270


@pytest.fixture
def h3270(tmp_path):
    """hack3270 instance with temp DB, offline mode, no network."""
    db_name = str(tmp_path / "test")
    obj = hack3270(
        server_ip="127.0.0.1",
        server_port=3270,
        proxy_port=3271,
        offline_mode=True,
        project_name=db_name,
    )
    yield obj
    obj.sql_con.close()
