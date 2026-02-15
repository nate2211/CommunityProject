# state.py
from __future__ import annotations

import dataclasses
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from utils import (
    app_dir,
    load_json,
    save_json,
    sha256_text,
    sha256_bytes,          # <-- ADD THIS
    canonical_json,
    b64e,
    b64d,
    protect_for_local_user,
    unprotect_for_local_user,
)
from moderation import ModerationState, ChatProtectionConfig, FileProtectionConfig
from ledger import CoinConfig, Ledger, Wallet
from p2p import P2PService


# -------------------------
# Paths
# -------------------------
def user_path():
    # single file holding BOTH account + wallet
    return app_dir() / "user.json"


def settings_path():
    return app_dir() / "settings.json"

def ledger_path():
    return app_dir() / "ledger.json"
def moderation_path():
    return app_dir() / "moderation.json"


# Legacy paths (migration support)
def _legacy_account_path():
    return app_dir() / "account.json"


def _legacy_wallet_path():
    return app_dir() / "wallet.json"

# -------------------------
# Coin fingerprint (bind wallet to coin config)
# -------------------------
def coin_fingerprint() -> str:
    payload = {
        "network_id": str(STATE.coin.network_id),
        "symbol": str(STATE.coin.symbol),
        "name": str(STATE.coin.name),
    }
    cj = canonical_json(payload)
    if isinstance(cj, (bytes, bytearray)):
        return sha256_bytes(bytes(cj))
    return sha256_text(str(cj))

def load_ledger() -> bool:
    if STATE.miner_status.get("running"):
        return False
    obj = load_json(ledger_path(), None)
    if not obj or not isinstance(obj, dict):
        return False

    # bind ledger file to current coin config
    if str(obj.get("coin_fpr", "")) != coin_fingerprint():
        return False

    try:
        ok, _ = STATE.ledger.load_from_dict(obj.get("ledger") or {})
        return bool(ok)
    except Exception:
        return False


def save_ledger() -> None:
    try:
        snap = STATE.ledger.to_dict()
    except Exception:
        return

    save_json(
        ledger_path(),
        {
            "v": 1,
            "coin_fpr": coin_fingerprint(),
            "ledger": snap,
        },
    )


# -------------------------
# Runtime state
# -------------------------
@dataclass
class RuntimeState:
    coin: CoinConfig = field(default_factory=CoinConfig)
    moderation: ModerationState = field(default_factory=ModerationState)
    ledger: Ledger = field(default_factory=lambda: Ledger(CoinConfig()))
    p2p: P2PService = field(default_factory=lambda: P2PService(ModerationState()))
    wallet: Optional[Wallet] = None

    miner_thread: Optional[threading.Thread] = None
    miner_stop: threading.Event = field(default_factory=threading.Event)
    miner_status: Dict[str, Any] = field(default_factory=lambda: {"running": False})


STATE = RuntimeState()
STATE.ledger = Ledger(STATE.coin)
STATE.p2p = P2PService(STATE.moderation)

# try to restore chain/balances
load_ledger()


# -------------------------
# Internal helpers (user.json)
# -------------------------
def _try_parse_wallet_dict(d: dict) -> Optional[Wallet]:
    try:
        return Wallet(
            private_key_b64=str(d["private_key_b64"]),
            public_key_b64=str(d["public_key_b64"]),
            address=str(d["address"]),
        )
    except Exception:
        return None


def _encrypt_wallet_section(w: Wallet) -> dict:
    """
    Produces the encrypted wallet section stored inside user.json.
    - encryption: Windows DPAPI (current user)
    - coin binding: coin_fpr
    """
    inner = {
        "v": 1,
        "coin_fpr": coin_fingerprint(),
        "private_key_b64": w.private_key_b64,
        "public_key_b64": w.public_key_b64,
        "address": w.address,
    }
    raw = json.dumps(inner, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ct = protect_for_local_user(raw)

    return {
        "scheme": "dpapi",
        "v": 1,

        # UI convenience fields (NOT trusted)
        "address": w.address,
        "public_key_b64": w.public_key_b64,

        # encrypted payload
        "enc_b64": b64e(ct),
    }


def _load_user_obj() -> dict:
    """
    Loads user.json; if missing, migrates legacy account.json/wallet.json.
    Always returns a dict with keys: {"account": {...}, "wallet": {...}}.
    """
    obj = load_json(user_path(), None)

    # If user.json missing -> migrate legacy
    if not obj or not isinstance(obj, dict):
        legacy_account = load_json(_legacy_account_path(), {}) or {}
        legacy_wallet = load_json(_legacy_wallet_path(), {}) or {}

        obj = {
            "account": legacy_account if isinstance(legacy_account, dict) else {},
            "wallet": {},
        }

        # If legacy wallet exists, encrypt it into new format
        if isinstance(legacy_wallet, dict) and legacy_wallet:
            w = _try_parse_wallet_dict(legacy_wallet)
            if w is not None:
                obj["wallet"] = _encrypt_wallet_section(w)

        save_json(user_path(), obj)

    # Normalize
    if "account" not in obj or not isinstance(obj["account"], dict):
        obj["account"] = {}
    if "wallet" not in obj or not isinstance(obj["wallet"], dict):
        obj["wallet"] = {}

    # If wallet stored plaintext inside user.json (legacy), migrate to encrypted
    wobj = obj.get("wallet") or {}
    if isinstance(wobj, dict) and wobj and "scheme" not in wobj and "private_key_b64" in wobj:
        w = _try_parse_wallet_dict(wobj)
        if w is not None:
            obj["wallet"] = _encrypt_wallet_section(w)
            save_json(user_path(), obj)

    return obj


def _save_user_obj(obj: dict) -> None:
    if not isinstance(obj, dict):
        obj = {}
    if "account" not in obj or not isinstance(obj["account"], dict):
        obj["account"] = {}
    if "wallet" not in obj or not isinstance(obj["wallet"], dict):
        obj["wallet"] = {}
    save_json(user_path(), obj)


# -------------------------
# Account
# -------------------------
def load_account() -> dict:
    obj = _load_user_obj()
    cfg = obj.get("account", {}) or {}

    cfg.setdefault("user_id", "")
    cfg.setdefault("name", "anon")
    cfg.setdefault("avatar_path", "")

    return cfg


def save_account(cfg: dict) -> None:
    obj = _load_user_obj()
    obj["account"] = dict(cfg or {})
    _save_user_obj(obj)


# -------------------------
# Wallet (encrypted)
# -------------------------
def load_wallet() -> Optional[Wallet]:
    obj = _load_user_obj()
    wobj = obj.get("wallet") or {}
    if not isinstance(wobj, dict) or not wobj:
        return None

    # Encrypted format
    if wobj.get("scheme") == "dpapi" and wobj.get("enc_b64"):
        try:
            ct = b64d(str(wobj["enc_b64"]))
            pt = unprotect_for_local_user(ct)
            inner = json.loads(pt.decode("utf-8"))

            # bind to coin config (prevents coin-param tampering)
            if str(inner.get("coin_fpr", "")) != coin_fingerprint():
                return None

            # tamper-evidence: convenience fields must match decrypted payload
            if wobj.get("address") and str(wobj["address"]) != str(inner.get("address", "")):
                return None
            if wobj.get("public_key_b64") and str(wobj["public_key_b64"]) != str(inner.get("public_key_b64", "")):
                return None

            return Wallet(
                private_key_b64=str(inner["private_key_b64"]),
                public_key_b64=str(inner["public_key_b64"]),
                address=str(inner["address"]),
            )
        except Exception:
            return None

    # Unknown / unsupported wallet section
    return None

def save_wallet(w: Wallet) -> None:
    """
    Saves wallet to user.json safely:
      - wallet keys encrypted via Windows DPAPI
      - wallet bound to coin fingerprint
      - editing user.json breaks decryption / integrity checks
    """
    obj = _load_user_obj()
    obj["wallet"] = _encrypt_wallet_section(w)
    _save_user_obj(obj)


# -------------------------
# Moderation
# -------------------------
def load_moderation() -> None:
    obj = load_json(moderation_path(), None)
    if not obj:
        return
    try:
        if "chat_cfg" in obj:
            STATE.moderation.chat_cfg = ChatProtectionConfig(**obj["chat_cfg"])
        if "file_cfg" in obj:
            STATE.moderation.file_cfg = FileProtectionConfig(**obj["file_cfg"])
    except Exception:
        pass


def save_moderation() -> None:
    save_json(
        moderation_path(),
        {
            "chat_cfg": dataclasses.asdict(STATE.moderation.chat_cfg),
            "file_cfg": dataclasses.asdict(STATE.moderation.file_cfg),
        },
    )
