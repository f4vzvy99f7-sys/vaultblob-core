from os import PathLike
from typing import overload

class VaultBlobError(Exception): ...

class VaultSession:
    @staticmethod
    def open(
        path: str | PathLike[str],
        password: str,
        *,
        max_chunk_size: int | None = None,
        max_blob_size: int | None = None,
        split: bool = False,
        stripe: bool = False,
        verbose: bool = False,
    ) -> VaultSession: ...
    @staticmethod
    def open_existing(
        path: str | PathLike[str],
        password: str,
        *,
        verbose: bool = False,
    ) -> VaultSession: ...
    @property
    def vault_id(self) -> str: ...
    def blob_ids(self) -> list[str]: ...
    @overload
    def put_file(self, data: bytes | bytearray, *, file_id: None = None) -> str: ...
    @overload
    def put_file(self, data: bytes | bytearray, *, file_id: str) -> str: ...
    def put_file(
        self, data: bytes | bytearray, *, file_id: str | None = None
    ) -> str: ...
    def read_file(self, file_id: str) -> bytes: ...
    def layout_stats(self) -> list[tuple[str, str]]: ...
    def __repr__(self) -> str: ...
