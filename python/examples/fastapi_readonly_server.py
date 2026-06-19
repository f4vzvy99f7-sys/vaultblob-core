#!/usr/bin/env python3
"""
Read-only FastAPI front-end for a vaultblob vault.

Serves GET /resource/<file-uuid> with optional Range support. Watches blob files on disk
and refreshes cached indexes when they change. No write endpoints.

VaultSession (PyO3) is unsendable: all vault calls must run on the thread that created
the session. This server uses async route handlers (no Starlette thread pool) and
schedules filesystem watcher callbacks onto the asyncio event-loop thread.

Requires: uv sync --extra server

Run:
  export VAULTBLOB_VAULT_PATH=/path/to/vault
  export VAULTBLOB_PASSWORD=          # optional; may be empty
  uv run --extra server python examples/fastapi_readonly_server.py
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from vaultblob import VaultBlobError, VaultSession
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


@dataclass(frozen=True)
class ByteRange:
    start: int
    end: int  # inclusive

    @property
    def length(self) -> int:
        return self.end - self.start + 1


def parse_range_header(header: str, file_size: int) -> ByteRange | None:
    if file_size == 0:
        return None
    match = RANGE_RE.match(header.strip())
    if not match:
        return None

    start_s, end_s = match.groups()
    if start_s and end_s:
        start, end = int(start_s), int(end_s)
    elif start_s:
        start, end = int(start_s), file_size - 1
    elif end_s:
        suffix = int(end_s)
        if suffix <= 0:
            return None
        start = max(file_size - suffix, 0)
        end = file_size - 1
    else:
        return None

    if start < 0 or end < start or start >= file_size:
        return None
    end = min(end, file_size - 1)
    return ByteRange(start=start, end=end)


class ReadonlyVaultStore:
    """Read-only vault access. Must be used from the thread that constructed it."""

    def __init__(
        self,
        vault_path: str,
        password: str,
        *,
        verbose: bool = False,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._loop = loop
        self._session = VaultSession.open_existing(vault_path, password, verbose=verbose)
        self._path_to_blob: dict[str, str] = {}
        self._rebuild_watch_map()

    def run_on_loop(self, fn: Callable[..., None], *args: Any, **kwargs: Any) -> None:
        """Schedule ``fn`` on the asyncio loop thread (required from watchdog threads)."""
        if self._loop is None:
            fn(*args, **kwargs)
            return
        self._loop.call_soon_threadsafe(lambda: fn(*args, **kwargs))

    def _rebuild_watch_map(self) -> None:
        self._path_to_blob = {
            os.path.normpath(path): blob_id
            for blob_id, path in self._session.blob_watch_targets()
        }
        logger.info("watching %d blob file(s)", len(self._path_to_blob))

    def reload_from_disk(self) -> None:
        self._session.reload_from_disk()
        self._rebuild_watch_map()

    def notify_blob_changed(self, blob_id: str) -> None:
        self._session.notify_blob_changed(blob_id)

    def file_size(self, file_id: str) -> int:
        return self._session.file_size(file_id)

    def read_range(self, file_id: str, offset: int, length: int) -> bytes:
        return self._session.read_file_range(file_id, offset, length)

    def resolve_blob_id(self, path: str) -> str | None:
        return self._path_to_blob.get(os.path.normpath(path))

    def handle_blob_path_event(self, path: str, event_type: str) -> None:
        """Process a blob file notification (must run on the vault session thread)."""
        if event_type == "created":
            logger.info("new blob file %s — reloading vault", path)
            try:
                self.reload_from_disk()
            except VaultBlobError as exc:
                logger.error("reload failed: %s", exc)
            return

        blob_id = self.resolve_blob_id(path)
        if blob_id is None:
            logger.info("change on unknown blob %s — reloading vault", path)
            try:
                self.reload_from_disk()
            except VaultBlobError as exc:
                logger.error("reload failed: %s", exc)
            return

        logger.info("blob %s changed (%s) — refreshing index", blob_id, event_type)
        try:
            self.notify_blob_changed(blob_id)
        except VaultBlobError as exc:
            logger.warning("notify_blob_changed failed, reloading: %s", exc)
            try:
                self.reload_from_disk()
            except VaultBlobError as reload_exc:
                logger.error("reload failed: %s", reload_exc)


class VaultBlobEventHandler(FileSystemEventHandler):
    def __init__(self, store: ReadonlyVaultStore) -> None:
        self._store = store

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = os.path.normpath(event.src_path)
        name = os.path.basename(path)
        if not name.startswith("blob-") or not name.endswith(".blob"):
            return
        self._store.run_on_loop(
            self._store.handle_blob_path_event,
            path,
            event.event_type,
        )


def create_app(store: ReadonlyVaultStore) -> FastAPI:
    app = FastAPI(
        title="vaultblob read-only",
        description="Read-only HTTP access to files stored in a vaultblob vault",
    )

    @app.get("/resource/{file_id}")
    async def get_resource(file_id: str, request: Request) -> Response:
        try:
            size = store.file_size(file_id)
        except VaultBlobError as exc:
            if "FileNotFound" in str(exc) or "IncompleteFile" in str(exc):
                raise HTTPException(status_code=404, detail="resource not found") from exc
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        if size == 0:
            return Response(
                content=b"",
                media_type="application/octet-stream",
                headers={"Accept-Ranges": "bytes"},
            )

        range_header = request.headers.get("range")
        if range_header is None:
            data = store.read_range(file_id, 0, size)
            return Response(
                content=data,
                media_type="application/octet-stream",
                headers={
                    "Accept-Ranges": "bytes",
                    "Content-Length": str(len(data)),
                },
            )

        parsed = parse_range_header(range_header, size)
        if parsed is None:
            raise HTTPException(
                status_code=416,
                detail="invalid range",
                headers={"Content-Range": f"bytes */{size}"},
            )

        data = store.read_range(file_id, parsed.start, parsed.length)
        return Response(
            content=data,
            status_code=HTTPStatus.PARTIAL_CONTENT,
            media_type="application/octet-stream",
            headers={
                "Accept-Ranges": "bytes",
                "Content-Range": f"bytes {parsed.start}-{parsed.end}/{size}",
                "Content-Length": str(len(data)),
            },
        )

    @app.head("/resource/{file_id}")
    async def head_resource(file_id: str) -> Response:
        try:
            size = store.file_size(file_id)
        except VaultBlobError as exc:
            if "FileNotFound" in str(exc) or "IncompleteFile" in str(exc):
                raise HTTPException(status_code=404, detail="resource not found") from exc
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return Response(
            status_code=HTTPStatus.OK,
            headers={
                "Accept-Ranges": "bytes",
                "Content-Length": str(size),
            },
        )

    @app.get("/health")
    async def health() -> dict[str, Literal["ok"]]:
        return {"status": "ok"}

    return app


async def _serve(
    store: ReadonlyVaultStore,
    app: FastAPI,
    vault_dir: str,
    host: str,
    port: int,
) -> None:
    import uvicorn

    observer = Observer()
    handler = VaultBlobEventHandler(store)
    observer.schedule(handler, vault_dir, recursive=False)
    observer.start()
    logger.info("watching vault directory %s", vault_dir)

    config = uvicorn.Config(app, host=host, port=port)
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        observer.stop()
        observer.join()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vault",
        default=os.environ.get("VAULTBLOB_VAULT_PATH"),
        help="vault directory (or VAULTBLOB_VAULT_PATH)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("VAULTBLOB_PASSWORD"),
        nargs="?",
        const="",
        help="vault passphrase (or VAULTBLOB_PASSWORD); empty string is valid",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if not args.vault:
        raise SystemExit("missing vault path: set --vault or VAULTBLOB_VAULT_PATH")

    password = "" if args.password is None else args.password

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        store = ReadonlyVaultStore(
            args.vault,
            password,
            verbose=args.verbose,
            loop=loop,
        )
        app = create_app(store)
        await _serve(store, app, args.vault, args.host, args.port)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
