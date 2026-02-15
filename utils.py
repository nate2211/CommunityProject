from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import hashlib
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any, Dict, Optional


def app_dir() -> Path:
    base = Path(os.getenv("APPDATA") or str(Path.home()))
    inst = os.getenv("COMMUNITY_INSTANCE", "default").strip() or "default"
    p = base / "p2p_community_app" / inst
    p.mkdir(parents=True, exist_ok=True)
    return p

def load_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256_bytes(b_: bytes) -> str:
    return hashlib.sha256(b_).hexdigest()


def sha256_text(s: str) -> str:
    return sha256_bytes(s.encode("utf-8"))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def human_bytes(n: int) -> str:
    f = float(n)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if f < 1024.0:
            return f"{f:.1f}{u}"
        f /= 1024.0
    return f"{f:.1f}PB"


# --- parse_extras: supports "group.key=val" and "key=val" (goes to "all") ---
_EXTRAS_SPLIT = re.compile(r"^([^=]+)=(.*)$")


def _coerce(v: str) -> Any:
    v = v.strip()
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    # int
    if re.fullmatch(r"-?\d+", v):
        try:
            return int(v)
        except Exception:
            pass
    # float
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        try:
            return float(v)
        except Exception:
            pass
    # json object/array
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        try:
            return json.loads(v)
        except Exception:
            pass
    # quoted
    if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
        return v[1:-1]
    return v


def parse_extras(items: list[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for it in items or []:
        m = _EXTRAS_SPLIT.match(it)
        if not m:
            continue
        k = m.group(1).strip()
        v = _coerce(m.group(2))
        if "." in k:
            group, key = k.split(".", 1)
        else:
            group, key = "all", k
        group = group.strip().lower()
        key = key.strip()
        out.setdefault(group, {})[key] = v
    return out


def ensure_parent_dir(path: str) -> None:
    Path(path).resolve().parent.mkdir(parents=True, exist_ok=True)
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes):
    buf = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob, buf


def _bytes_from_blob(blob: _DATA_BLOB) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def protect_for_local_user(plaintext: bytes) -> bytes:
    if not sys.platform.startswith("win"):
        raise RuntimeError("DPAPI protect is only available on Windows.")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CryptProtectData = crypt32.CryptProtectData
    CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    CryptProtectData.restype = wintypes.BOOL

    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [ctypes.c_void_p]
    LocalFree.restype = ctypes.c_void_p

    in_blob, _keepalive = _blob_from_bytes(plaintext)
    out_blob = _DATA_BLOB()

    ok = CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return _bytes_from_blob(out_blob)
    finally:
        LocalFree(out_blob.pbData)


def unprotect_for_local_user(ciphertext: bytes) -> bytes:
    if not sys.platform.startswith("win"):
        raise RuntimeError("DPAPI unprotect is only available on Windows.")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CryptUnprotectData = crypt32.CryptUnprotectData
    CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    CryptUnprotectData.restype = wintypes.BOOL

    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [ctypes.c_void_p]
    LocalFree.restype = ctypes.c_void_p

    in_blob, _keepalive = _blob_from_bytes(ciphertext)
    out_blob = _DATA_BLOB()
    descr = wintypes.LPWSTR()

    ok = CryptUnprotectData(ctypes.byref(in_blob), ctypes.byref(descr), None, None, None, 0, ctypes.byref(out_blob))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return _bytes_from_blob(out_blob)
    finally:
        if descr:
            LocalFree(descr)
        LocalFree(out_blob.pbData)