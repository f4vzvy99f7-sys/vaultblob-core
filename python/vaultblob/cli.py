"""Command-line interface for vaultblob (Python implementation)."""

from __future__ import annotations

import argparse
import glob
import os
import sys
from getpass import getpass
from pathlib import Path

from vaultblob import VaultBlobError, VaultSession


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except VaultBlobError as exc:
        print(f"vault error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultblob",
        description="Store and retrieve files in an encrypted vault",
    )
    parser.add_argument(
        "vault_dir",
        type=Path,
        help="path to the vault directory",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log index walks and locator selection to stderr (also VAULTBLOB_DEBUG=1)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    put = sub.add_parser(
        "put", help="write files into the vault and print their file IDs"
    )
    put.add_argument(
        "--max-chunk-size",
        default="4mb",
        metavar="SIZE",
        help="maximum plaintext per chunk (e.g. 4mb, 512kb)",
    )
    put.add_argument(
        "--max-blob-size",
        default="1gb",
        metavar="SIZE",
        help="soft max estimated data bytes per blob before starting another",
    )
    put.add_argument(
        "--split",
        action="store_true",
        help="allow a single file's chunks to span multiple blobs",
    )
    put.add_argument(
        "--stripe",
        action="store_true",
        help="when splitting, rotate chunk placement across blobs round-robin",
    )
    put.add_argument(
        "files",
        nargs="*",
        help="files or glob patterns to ingest; omit to read from stdin",
    )
    put.set_defaults(func=cmd_put)

    get = sub.add_parser(
        "get", help="read a file from the vault and write it to stdout"
    )
    get.add_argument("file_id", help="file ID printed by a prior put")
    get.set_defaults(func=cmd_get)

    stat = sub.add_parser("stat", help="print per-blob layout breakdown")
    stat.set_defaults(func=cmd_stat)

    return parser


def cmd_put(args: argparse.Namespace) -> int:
    password = _prompt_password()
    max_chunk_size = parse_byte_size(args.max_chunk_size)
    if max_chunk_size > 2**63 - 1:
        raise SystemExit(f"size too large for this platform: {args.max_chunk_size}")
    max_blob_size = parse_byte_size(args.max_blob_size)

    vault = VaultSession.open(
        args.vault_dir,
        password,
        max_chunk_size=max_chunk_size,
        max_blob_size=max_blob_size,
        split=args.split,
        stripe=args.stripe,
        verbose=args.verbose,
    )

    if not args.files:
        data = sys.stdin.buffer.read()
        file_id = vault.put_file(data)
        print(file_id)
        return 0

    for path in expand_patterns(args.files):
        data = path.read_bytes()
        file_id = vault.put_file(data)
        print(f"{file_id}\t{path}")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    password = _prompt_password()
    vault = VaultSession.open_existing(args.vault_dir, password, verbose=args.verbose)
    try:
        data = vault.read_file(args.file_id)
    except VaultBlobError as exc:
        msg = str(exc)
        if "FileNotFound" in msg:
            raise SystemExit(f"file not found: {args.file_id}") from exc
        if "FileHashMismatch" in msg:
            raise SystemExit("file integrity check failed") from exc
        if "InvalidMasterKey" in msg:
            raise SystemExit("wrong password") from exc
        raise
    sys.stdout.buffer.write(data)
    return 0


def cmd_stat(args: argparse.Namespace) -> int:
    password = _prompt_password()
    vault = VaultSession.open_existing(args.vault_dir, password, verbose=args.verbose)
    for path, report in vault.layout_stats():
        print(f"=== {path} ===")
        print(report, end="" if report.endswith("\n") else "\n")
    return 0


def _prompt_password() -> str:
    return getpass("Vault password: ")


def parse_byte_size(value: str) -> int:
    """Parse a human-readable byte size (e.g. 4mb, 512kb)."""
    s = value.strip().replace("_", "")
    if not s:
        raise ValueError("size must not be empty")

    split = next((i for i, ch in enumerate(s) if not ch.isdigit()), len(s))
    number, suffix = s[:split], s[split:].strip().lower()
    if not number:
        raise ValueError("size must start with a number (examples: 4096, 4mb, 512kb)")

    n = int(number)
    multipliers = {
        "": 1,
        "b": 1,
        "byte": 1,
        "bytes": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "ki": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "mi": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
        "gi": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "tib": 1024**4,
        "ti": 1024**4,
    }
    try:
        multiplier = multipliers[suffix]
    except KeyError as exc:
        raise ValueError(
            f"unknown size suffix {suffix!r} (use b, kb, mb, or gb)"
        ) from exc

    result = n * multiplier
    if result < 0:
        raise ValueError(f"size overflow parsing {value!r}")
    return result


def expand_patterns(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        expanded = _expand_tilde(pattern)
        matches = [Path(p) for p in glob.glob(expanded, recursive=True)]
        if not matches:
            raise SystemExit(f"no files matched: {pattern}")
        for path in sorted(matches):
            if path.is_file():
                paths.append(path)
    return paths


def _expand_tilde(pattern: str) -> str:
    if pattern == "~":
        return os.path.expanduser("~")
    if pattern.startswith("~/"):
        return os.path.expanduser(pattern)
    return pattern


if __name__ == "__main__":
    raise SystemExit(main())
