"""Python compatibility layer over vaultblob-core."""

from vaultblob._native import VaultBlobError, VaultSession

__all__ = ["VaultBlobError", "VaultSession"]
