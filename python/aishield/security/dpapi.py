"""Windows DPAPI helpers for encrypting data at rest."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def is_available() -> bool:
    return os.name == "nt"


def protect(data: bytes, description: str = "AI Firewall") -> bytes:
    if not is_available():
        return data
    try:
        import win32crypt
        return win32crypt.CryptProtectData(data, description, None, None, None, 0)
    except Exception as e:
        logger.warning("DPAPI protect failed: %s", e)
        return data


def unprotect(data: bytes) -> bytes:
    if not is_available():
        return data
    try:
        import win32crypt
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
    except Exception as e:
        logger.warning("DPAPI unprotect failed: %s", e)
        raise


def encrypt_file(src: Path, dest: Path | None = None) -> Path:
    dest = dest or src.with_suffix(src.suffix + ".dpapi")
    raw = src.read_bytes()
    dest.write_bytes(protect(raw))
    return dest


def decrypt_file(src: Path, dest: Path) -> Path:
    dest.write_bytes(unprotect(src.read_bytes()))
    return dest


def load_or_decrypt_db(db_path: Path) -> None:
    """If only encrypted copy exists, decrypt to live db path."""
    enc = db_path.with_suffix(db_path.suffix + ".dpapi")
    if db_path.exists():
        return
    if enc.exists() and is_available():
        try:
            decrypt_file(enc, db_path)
            logger.info("Decrypted permissions database from DPAPI backup")
        except Exception as e:
            logger.error("Could not decrypt permissions db: %s", e)


def seal_db(db_path: Path, enabled: bool = True) -> None:
    if not enabled or not db_path.exists() or not is_available():
        return
    try:
        encrypt_file(db_path)
        logger.info("Sealed permissions database with DPAPI")
    except Exception as e:
        logger.warning("Could not seal permissions db: %s", e)
