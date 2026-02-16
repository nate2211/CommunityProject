# state.py
from __future__ import annotations

import dataclasses
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, List

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
from p2p import P2PService, FileOffer


def _src_rank(src: str) -> int:
    # higher = stronger provenance
    src = str(src or "").strip().lower()
    if src == "static":
        return 3
    if src == "manual":
        return 2
    if src == "dynamic":
        return 1
    return 0

_LH_LOCK = threading.Lock()

# Always keep at least one bootstrap seed around
DEFAULT_LH_SEED = [
    "170.253.163.90:38888",
]

def lighthouses_registry_path() -> Path:
    return app_dir() / "lighthouses.json"

def _lh_now() -> float:
    return time.time()

def _normalize_lh_addr(raw: str) -> str:
    """
    Normalize to 'host:port'.
    Accepts:
      - host
      - host:port
      - scheme://host:port/path
    """
    s = str(raw or "").strip()
    if not s:
        return ""

    # strip scheme + path
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    s = s.strip()
    if not s:
        return ""

    host = s
    port = 38888

    if ":" in s:
        host, ps = s.rsplit(":", 1)
        host = host.strip()
        try:
            port = int(ps.strip())
        except Exception:
            return ""

    if not host:
        return ""
    if port <= 0 or port > 65535:
        return ""

    return f"{host}:{port}"

def _load_lh_file() -> Dict[str, Any]:
    p = lighthouses_registry_path()
    try:
        data = load_json(p)  # your utils.load_json
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"items": []}

def _save_lh_file(data: Dict[str, Any]) -> None:
    try:
        save_json(lighthouses_registry_path(), data)  # your utils.save_json
    except Exception:
        pass

def ensure_default_lighthouses() -> None:
    """
    Ensure DEFAULT_LH_SEED is present as 'static' (does NOT overwrite manual).
    """
    with _LH_LOCK:
        data = _load_lh_file()
        items = data.get("items")
        if not isinstance(items, list):
            items = []
            data["items"] = items

        by_addr: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if isinstance(it, dict):
                a = _normalize_lh_addr(it.get("addr") or "")
                if a:
                    by_addr[a] = it

        changed = False
        for raw in DEFAULT_LH_SEED:
            addr = _normalize_lh_addr(raw)
            if not addr:
                continue

            cur = by_addr.get(addr)
            if cur:
                # Keep manual if user set it; otherwise ensure static seed is labeled static
                if str(cur.get("source") or "").lower() != "manual":
                    if str(cur.get("source") or "").lower() != "static":
                        cur["source"] = "static"
                        changed = True
                continue

            items.append({
                "addr": addr,
                "source": "static",
                "ok": None,
                "last_seen": 0.0,
                "added_ts": _lh_now(),
            })
            changed = True

        if changed:
            _save_lh_file(data)

def register_lighthouse(addr: str, source: str = "dynamic", ok: Optional[bool] = None) -> None:
    """
    Add/update a lighthouse.
      source: 'static' | 'manual' | 'dynamic'
      ok: None/True/False (connection health)
    """
    a = _normalize_lh_addr(addr)
    if not a:
        return

    src = str(source or "dynamic").lower()
    if src not in ("static", "manual", "dynamic"):
        src = "dynamic"

    with _LH_LOCK:
        data = _load_lh_file()
        items = data.get("items")
        if not isinstance(items, list):
            items = []
            data["items"] = items

        existing: Optional[Dict[str, Any]] = None
        for it in items:
            if isinstance(it, dict) and _normalize_lh_addr(it.get("addr") or "") == a:
                existing = it
                break

        if existing is None:
            existing = {
                "addr": a,
                "source": src,
                "ok": ok,
                "last_seen": _lh_now(),
                "added_ts": _lh_now(),
            }
            items.append(existing)
        else:
            # manual should win over dynamic/static
            cur_src = str(existing.get("source") or "dynamic").lower()
            if cur_src != "manual":
                existing["source"] = "manual" if src == "manual" else src
            # update health + timestamps
            existing["last_seen"] = _lh_now()
            if ok is not None:
                existing["ok"] = bool(ok)

        _save_lh_file(data)

def list_lighthouses() -> List[Dict[str, Any]]:
    """
    Returns list of dicts: {addr, source, ok, last_seen, added_ts}
    """
    with _LH_LOCK:
        data = _load_lh_file()
        items = data.get("items")
        if not isinstance(items, list):
            return []

        out: List[Dict[str, Any]] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            a = _normalize_lh_addr(it.get("addr") or "")
            if not a:
                continue
            out.append({
                "addr": a,
                "source": str(it.get("source") or "dynamic"),
                "ok": it.get("ok", None),
                "last_seen": float(it.get("last_seen") or 0.0),
                "added_ts": float(it.get("added_ts") or 0.0),
            })

        # nice sorting: manual first, then static, then dynamic; newest last_seen first
        def _rank(x: Dict[str, Any]) -> tuple:
            src = str(x.get("source") or "dynamic").lower()
            pri = 0 if src == "manual" else (1 if src == "static" else 2)
            return (pri, -float(x.get("last_seen") or 0.0))

        out.sort(key=_rank)
        return out


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


# Add a helper function to sync ledger
def sync_ledger_from_offer(offer: FileOffer):
    from utils import app_dir

    tmp_path = app_dir() / f"sync_{offer.sha256[:8]}.json"

    try:
        # Download
        STATE.p2p.download_offer(offer, str(tmp_path))

        # Validate and Load
        obj = load_json(tmp_path)
        if isinstance(obj, dict) and str(obj.get("coin_fpr", "")) == coin_fingerprint():
            ok, reason = STATE.ledger.load_from_dict(obj.get("ledger") or {})
            if ok:
                save_ledger()
                print(f"Synced ledger to height {STATE.ledger.height()}")
    except Exception as e:
        print(f"Sync failed: {e}")
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except:
                pass
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
# Inject the callbacks (Monkey-patching since P2PService is already init)
STATE.p2p.get_current_height_func = lambda: STATE.ledger.height()
STATE.p2p.on_ledger_offer = lambda offer: threading.Thread(target=sync_ledger_from_offer, args=(offer,), daemon=True).start()
try:
    ensure_default_lighthouses()
except Exception:
    pass
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
