import tempfile
from pathlib import Path

import pytest

vaultblob = pytest.importorskip("vaultblob")


def test_put_and_read_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vault"
        session = vaultblob.VaultSession.open(path, "secret")
        file_id = session.put_file(b"hello")
        assert isinstance(file_id, str)
        assert session.read_file(file_id) == b"hello"


def test_wrong_password_on_existing() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vault"
        vaultblob.VaultSession.open(path, "right")
        with pytest.raises(vaultblob.VaultBlobError):
            vaultblob.VaultSession.open_existing(path, "wrong")
