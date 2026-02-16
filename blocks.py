from __future__ import annotations

import base64
import dataclasses
import json
import os
import re
import threading
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Callable

from block import BaseBlock
from registry import Registry
from utils import sha256_file, sha256_text, canonical_json, human_bytes
from state import (
    STATE,
    load_account,
    save_account,
    load_wallet,
    save_wallet,
    load_moderation,
    save_moderation,
    load_ledger,
    save_ledger,
    coin_fingerprint,
    ledger_path,
)
from ledger import Wallet, Tx, Block
from p2p import FileOffer

from utils import app_dir


# =============================================================================
# Local echo buffers (so sender sees their own messages even if P2P only queues
# incoming messages). These are "drain-on-read" to avoid duplicates.
# =============================================================================
from collections import deque

_ECHO_LOCK = threading.Lock()
_ROOM_ECHO: deque[Dict[str, Any]] = deque(maxlen=2000)
_DM_ECHO: deque[Dict[str, Any]] = deque(maxlen=4000)

def _echo_add_room(m: Dict[str, Any]) -> None:
    m = dict(m or {})
    m["_echo"] = True
    with _ECHO_LOCK:
        _ROOM_ECHO.append(m)

def _echo_add_dm(m: Dict[str, Any]) -> None:
    m = dict(m or {})
    m["_echo"] = True
    with _ECHO_LOCK:
        _DM_ECHO.append(m)

def _echo_drain_room() -> List[Dict[str, Any]]:
    with _ECHO_LOCK:
        out = list(_ROOM_ECHO)
        _ROOM_ECHO.clear()
        return out

def _echo_drain_dm() -> List[Dict[str, Any]]:
    with _ECHO_LOCK:
        out = list(_DM_ECHO)
        _DM_ECHO.clear()
        return out


# =============================================================================
# Helpers / Safety
# =============================================================================

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._ -]+")
BLOCKS = Registry()

MINER_LOCK = app_dir() / "miner.lock"

def _short(s: str, keep: int = 8) -> str:
    s = str(s or "")
    if len(s) <= keep * 2 + 1:
        return s
    return f"{s[:keep]}…{s[-keep:]}"

def _safe_basename(name: str, max_len: int = 256) -> str:
    n = os.path.basename(str(name or "file")).replace("\x00", "")
    if len(n) > max_len:
        root, ext = os.path.splitext(n)
        keep = max(1, max_len - len(ext))
        n = root[:keep] + ext
    return n or "file"

def _decode_wire_dict(wire_b64: str) -> Optional[Dict[str, Any]]:
    try:
        raw = base64.urlsafe_b64decode(wire_b64.encode("ascii"))
        d = json.loads(raw.decode("utf-8"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None

def _validate_tx_wire_b64(wire_b64: str) -> str:
    s = (wire_b64 or "").strip()
    if not s:
        raise ValueError("empty_tx_wire")
    if len(s) > 200_000:
        raise ValueError("tx_wire_too_long")
    d = _decode_wire_dict(s)
    if not isinstance(d, dict):
        raise ValueError("invalid_tx_wire")
    if not str(d.get("tx_id") or "").strip():
        raise ValueError("invalid_tx_wire_no_tx_id")
    return s

def summarize_tx_wire(wire_b64: str) -> str:
    d = _decode_wire_dict(wire_b64)
    if not d:
        return "[TX] invalid"
    txid = str(d.get("tx_id") or "")
    fa = str(d.get("from_addr") or "")
    ta = str(d.get("to_addr") or "")
    amt = d.get("amount", 0)
    return f"[TX] id={_short(txid, 8)} {_short(fa, 6)}→{_short(ta, 6)} amt={amt}"

def _format_tx_text(
    tx: Dict[str, Any],
    *,
    confirmed: bool,
    confirm_reason: str = "",
    attachment_saved: str = "",
    attachment_bytes: int = 0,
    ledger_synced: bool = False,
) -> str:
    tx_id = str(tx.get("tx_id") or "")
    fa = str(tx.get("from_addr") or "")
    ta = str(tx.get("to_addr") or "")
    amt = tx.get("amount", 0)
    nonce = tx.get("nonce", 0)
    memo = str(tx.get("memo") or "")

    a = tx.get("attachment") if isinstance(tx.get("attachment"), dict) else None
    attach_lines = ""
    if isinstance(a, dict):
        attach_lines = (
            f"\nattachment.name={a.get('name','')}"
            f"\nattachment.size={a.get('size',0)}"
            f"\nattachment.sha256={_short(str(a.get('sha256') or ''), 10)}"
            f"\nattachment.ext={a.get('ext','')}"
            + (f"\nattachment.saved={attachment_saved} ({attachment_bytes} bytes)" if attachment_saved else "")
        )

    status = "CONFIRMED" if confirmed else "PENDING"
    sync = " (ledger synced)" if ledger_synced else ""
    cr = f" reason={confirm_reason}" if confirm_reason else ""

    return (
        f"[TX {status}{sync}] id={_short(tx_id, 10)}"
        f"\nfrom={fa}"
        f"\nto={ta}"
        f"\namount={amt}"
        f"\nnonce={nonce}"
        + (f"\nmemo={memo}" if memo else "")
        + attach_lines
        + cr
    )

def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def acquire_lock(path: Path, *, force: bool = False) -> bool:
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.close(fd)
        return True
    except FileExistsError:
        if not force:
            return False

        try:
            pid_txt = path.read_text("ascii", errors="ignore").strip()
            pid = int(pid_txt) if pid_txt.isdigit() else -1
        except Exception:
            pid = -1

        if pid != -1 and _pid_alive(pid):
            return False

        try:
            path.unlink()
        except Exception:
            pass

        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, str(os.getpid()).encode("ascii"))
            os.close(fd)
            return True
        except Exception:
            return False

def release_lock(path: Path) -> None:
    try:
        path.unlink()
    except Exception:
        pass


# =============================================================================
# P2P queue access (robust to naming differences in your P2P class)
# =============================================================================

def _call0(obj: Any, name: str) -> Optional[Any]:
    fn = getattr(obj, name, None)
    if callable(fn):
        try:
            return fn()
        except Exception:
            return None
    return None

def _p2p_pop_room_messages() -> List[Dict[str, Any]]:
    for nm in (
        "pop_room_messages",
        "pop_public_messages",
        "pop_room_msgs",
        "pop_public_msgs",
        "pop_room_chat",
    ):
        v = _call0(STATE.p2p, nm)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    return []

def _p2p_pop_dm_messages() -> List[Dict[str, Any]]:
    v = _call0(STATE.p2p, "pop_dm_messages")
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    return []

def _p2p_pop_tx_msgs() -> List[Dict[str, Any]]:
    for nm in (
        "pop_tx_msgs",
        "pop_tx_messages",
        "pop_transactions",
        "pop_tx",
    ):
        v = _call0(STATE.p2p, nm)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    return []

def _p2p_pop_dm_offers() -> List[Any]:
    v = _call0(STATE.p2p, "pop_dm_offers")
    if isinstance(v, list):
        return v
    return []

def _p2p_pop_room_offers() -> List[Any]:
    for nm in ("pop_room_offers", "pop_public_offers"):
        v = _call0(STATE.p2p, nm)
        if isinstance(v, list):
            return v
    return []

def _is_tx_like_msg(m: Dict[str, Any]) -> bool:
    t = str(m.get("t") or "").lower()
    k = str(m.get("kind") or "").lower()
    if t in ("tx", "tx_push", "tx_wire", "transaction"):
        return True
    if k in ("tx", "transaction"):
        return True
    if "tx_wire" in m and isinstance(m.get("tx_wire"), str):
        return True
    if "wire" in m and isinstance(m.get("wire"), str) and len(str(m.get("wire"))) > 40:
        return True
    return False

def _extract_tx_pushes_from_dm(dm_msgs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    keep: List[Dict[str, Any]] = []
    pushes: List[Dict[str, Any]] = []
    for m in dm_msgs:
        if not isinstance(m, dict):
            continue
        if _is_tx_like_msg(m):
            wire = str(m.get("tx_wire") or m.get("wire") or m.get("msg") or "")
            if wire:
                pushes.append({
                    "tx_wire": wire,
                    "from_user_id": str(m.get("from_user_id") or m.get("from") or ""),
                    "from_name": str(m.get("from_name") or m.get("from_display") or ""),
                    "_src_ip": str(m.get("_src_ip") or m.get("from_ip") or ""),
                    "from_tcp_port": int(m.get("from_tcp_port") or 0),
                    "_relay_via": str(m.get("_relay_via") or m.get("relay_via") or ""),
                    "ledger_tip": (m.get("ledger_tip") if isinstance(m.get("ledger_tip"), dict) else {}),
                    "ts": float(m.get("ts") or time.time()),
                })
            continue
        keep.append(m)
    return keep, pushes



# =============================================================================
# Blocks
# =============================================================================

@dataclass
class AccountBlock(BaseBlock):
    """
    account:
      - ensure (default)
      - set: name, avatar_path
      - get
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        action = str(params.get("action") or "ensure").strip().lower()
        cfg = load_account()

        if STATE.wallet is None:
            WalletBlock().execute("", params={"action": "load"})

        if not cfg.get("user_id"):
            cfg["user_id"] = uuid.uuid4().hex

        if action in ("set", "ensure"):
            name = str(params.get("name") or cfg.get("name") or "anon").strip()[:64]
            avatar_path = str(params.get("avatar_path") or cfg.get("avatar_path") or "").strip()
            cfg["name"] = name if name else "anon"
            cfg["avatar_path"] = avatar_path
            save_account(cfg)

        # keep P2P identity in sync
        wallet_addr = STATE.wallet.address if STATE.wallet else ""
        STATE.p2p.set_identity(cfg["user_id"], cfg.get("name", "anon"), cfg.get("avatar_path", ""), wallet_addr)
        return cfg, {"type": "account", "action": action}


@dataclass
class RoomsBlock(BaseBlock):
    """
    rooms:
      - join: room
      - peers
      - current
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        action = str(params.get("action") or "current").strip().lower()

        STATE.p2p.start()
        AccountBlock().execute("", params={"action": "ensure"})

        if action == "join":
            room = str(params.get("room") or payload or "").strip()[:64]
            if not room:
                raise ValueError("rooms.join requires rooms.room")
            STATE.p2p.set_room(room)
            # Presence must be broadcast AFTER room set
            STATE.p2p.broadcast_presence()
            return {"room": room}, {"type": "rooms", "action": "join"}

        if action == "peers":
            # Make sure we're visible before asking for the list
            try:
                STATE.p2p.broadcast_presence()
            except Exception:
                pass
            try:
                STATE.p2p.peers.prune()
            except Exception:
                pass
            peers = [dataclasses.asdict(p) for p in STATE.p2p.peers.list()]
            return {"count": len(peers), "peers": peers, "room": STATE.p2p.room}, {"type": "rooms", "action": "peers"}

        return {"room": STATE.p2p.room}, {"type": "rooms", "action": "current"}


@dataclass
class ChatProtectionBlock(BaseBlock):
    """
    chat_protection:
      - check: payload text
      - load / save
      - config_get / config_set (payload json)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        action = str(params.get("action") or "check").strip().lower()

        if action == "load":
            load_moderation()
            return {"ok": True}, {"type": "chat_protection", "action": "load"}

        if action == "save":
            save_moderation()
            return {"ok": True}, {"type": "chat_protection", "action": "save"}

        if action == "config_get":
            return dataclasses.asdict(STATE.moderation.chat_cfg), {"type": "chat_protection", "action": "config_get"}

        if action == "config_set":
            d = json.loads(str(payload or "{}"))
            for k, v in d.items():
                if hasattr(STATE.moderation.chat_cfg, k):
                    setattr(STATE.moderation.chat_cfg, k, v)
            return dataclasses.asdict(STATE.moderation.chat_cfg), {"type": "chat_protection", "action": "config_set"}

        uid = str(params.get("user_id") or "local")
        text = str(payload or "")
        ok, cleaned, reason = STATE.moderation.chat_check(user_id=uid, text=text)
        return {"ok": ok, "text": cleaned if ok else "", "reason": reason}, {"type": "chat_protection", "action": "check", "ok": ok}


@dataclass
class FileProtectionBlock(BaseBlock):
    """
    file_protection:
      - scan: payload path
      - load / save
      - config_get / config_set (payload json)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        action = str(params.get("action") or "scan").strip().lower()

        if action == "load":
            load_moderation()
            return {"ok": True}, {"type": "file_protection", "action": "load"}

        if action == "save":
            save_moderation()
            return {"ok": True}, {"type": "file_protection", "action": "save"}

        if action == "config_get":
            return dataclasses.asdict(STATE.moderation.file_cfg), {"type": "file_protection", "action": "config_get"}

        if action == "config_set":
            d = json.loads(str(payload or "{}"))
            for k, v in d.items():
                if hasattr(STATE.moderation.file_cfg, k):
                    setattr(STATE.moderation.file_cfg, k, v)
            return dataclasses.asdict(STATE.moderation.file_cfg), {"type": "file_protection", "action": "config_set"}

        path = str(payload or "").strip()
        ok, reason = STATE.moderation.file_check_path(path=path)
        info = {}
        if ok:
            info = {
                "path": path,
                "sha256": sha256_file(path),
                "size": os.path.getsize(path),
                "ext": Path(path).suffix.lower(),
            }
        return {"ok": ok, "reason": reason, "info": info}, {"type": "file_protection", "action": "scan", "ok": ok}


@dataclass
class PublicChatBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        STATE.p2p.start()
        AccountBlock().execute("", params={"action": "ensure"})
        STATE.p2p.broadcast_presence()

        action = str(params.get("action") or "send").strip().lower()

        if action == "send":
            text = str(payload or "")
            ok, cleaned, reason = STATE.moderation.chat_check(user_id=STATE.p2p.identity.user_id, text=text)
            if not ok:
                return {"ok": False, "reason": reason}, {"type": "public_chat", "action": "send", "ok": False}

            STATE.p2p.send_public_text(cleaned)

            _echo_add_room({
                "t": "public_chat",
                "ts": time.time(),
                "room": STATE.p2p.room,
                "from_user_id": STATE.p2p.identity.user_id,
                "from_name": STATE.p2p.identity.name,
                "text": cleaned,
                "direction": "out",
            })

            return {"ok": True, "room": STATE.p2p.room, "text": cleaned}, {"type": "public_chat", "action": "send",
                                                                           "ok": True}

        if action == "share_file":
            path = str(params.get("path") or "").strip()
            note = str(params.get("note") or "").strip()
            if not path:
                raise ValueError("public_chat.share_file requires public_chat.path")

            ok, reason = STATE.moderation.file_check_path(path=path)
            if not ok:
                return {"ok": False, "reason": reason}, {"type": "public_chat", "action": "share_file", "ok": False}

            offer = STATE.p2p.share_file_to_room(path, note=note, scope="room")

            _echo_add_room({
                "t": "room_file_offer",
                "ts": time.time(),
                "room": STATE.p2p.room,
                "from_user_id": STATE.p2p.identity.user_id,
                "from_name": STATE.p2p.identity.name,
                "offer": dataclasses.asdict(offer),
                "note": note,
                "direction": "out",
            })

            return dataclasses.asdict(offer), {"type": "public_chat", "action": "share_file", "ok": True}

        if action == "feed":
            room_msgs = _p2p_pop_room_messages()
            room_msgs.extend(_echo_drain_room())

            # --- FIX: Removed the fallback that stole DM offers ---
            offers_raw = _p2p_pop_room_offers()

            offers: List[Dict[str, Any]] = []
            for o in (offers_raw or []):
                try:
                    offers.append(dataclasses.asdict(o))
                except Exception:
                    if isinstance(o, dict):
                        offers.append(o)

            def _ts(m: Dict[str, Any]) -> float:
                try:
                    return float(m.get("ts") or 0.0)
                except Exception:
                    return 0.0

            room_msgs = [m for m in room_msgs if isinstance(m, dict)]
            room_msgs.sort(key=_ts)

            seen = set()
            dedup: List[Dict[str, Any]] = []
            for m in room_msgs:
                key = (m.get("t"), m.get("room"), m.get("from_user_id"), m.get("text"), m.get("offer_id"))
                if key in seen:
                    continue
                seen.add(key)
                dedup.append(m)
            room_msgs = dedup

            seen_o = set()
            offers2: List[Dict[str, Any]] = []
            for o in offers:
                oid = str(o.get("offer_id") or "")
                if oid and oid in seen_o:
                    continue
                if oid:
                    seen_o.add(oid)
                offers2.append(o)

            return {"room": STATE.p2p.room, "messages": room_msgs, "file_offers": offers2}, {"type": "public_chat",
                                                                                             "action": "feed"}

        if action == "download":
            d = json.loads(str(payload or "{}"))
            offer = FileOffer(**d)
            save_path = str(params.get("save_path") or offer.filename)
            n = STATE.p2p.download_offer(offer, save_path)
            return {"ok": True, "saved": save_path, "bytes": n}, {"type": "public_chat", "action": "download"}

        raise ValueError(f"Unknown public_chat.action={action}")



@dataclass
class PrivateChatBlock(BaseBlock):
    """
    private_chat:
      - send: to_user_id + payload text
      - feed
      - share_file: to_user_id + path + note
      - download: payload offer json
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        STATE.p2p.start()
        AccountBlock().execute("", params={"action": "ensure"})
        STATE.p2p.broadcast_presence()

        action = str(params.get("action") or "send").strip().lower()

        if action == "send":
            to_uid = str(params.get("to_user_id") or "").strip()
            if not to_uid:
                raise ValueError("private_chat.send requires private_chat.to_user_id")

            peer = STATE.p2p.peers.get(to_uid)
            if not peer:
                raise ValueError("peer_not_found")

            text = str(payload or "")
            ok, cleaned, reason = STATE.moderation.chat_check(user_id=STATE.p2p.identity.user_id, text=text)
            if not ok:
                return {"ok": False, "reason": reason}, {"type": "private_chat", "action": "send", "ok": False}

            STATE.p2p.send_dm_text(peer, cleaned)

            _echo_add_dm({
                "t": "dm",
                "ts": time.time(),
                "from_user_id": STATE.p2p.identity.user_id,
                "from_name": STATE.p2p.identity.name,
                "to_user_id": getattr(peer, "user_id", to_uid),
                "to_name": getattr(peer, "name", ""),
                "text": cleaned,
                "direction": "out",
            })

            return {"ok": True, "to": getattr(peer, "name", to_uid), "text": cleaned}, {"type": "private_chat", "action": "send", "ok": True}

        if action == "share_file":
            to_uid = str(params.get("to_user_id") or "").strip()
            path = str(params.get("path") or "").strip()
            note = str(params.get("note") or "").strip()
            if not to_uid or not path:
                raise ValueError("private_chat.share_file requires to_user_id + path")

            peer = STATE.p2p.peers.get(to_uid)
            if not peer:
                raise ValueError("peer_not_found")

            ok, reason = STATE.moderation.file_check_path(path=path)
            if not ok:
                return {"ok": False, "reason": reason}, {"type": "private_chat", "action": "share_file", "ok": False}

            offer = STATE.p2p.share_file_dm(peer, path, note=note, scope="dm")
            return dataclasses.asdict(offer), {"type": "private_chat", "action": "share_file", "ok": True}

        if action == "feed":
            dm_msgs = _p2p_pop_dm_messages()
            dm_msgs.extend(_echo_drain_dm())

            tx_pushes = _p2p_pop_tx_msgs()
            dm_msgs, tx_from_dm = _extract_tx_pushes_from_dm(dm_msgs)
            tx_pushes.extend(tx_from_dm)

            imported = 0
            seen_offer_ids: set[str] = set()

            out_msgs: List[Dict[str, Any]] = []
            out_msgs.extend(dm_msgs)

            for w in (tx_pushes or []):
                if not isinstance(w, dict):
                    continue
                wire = str(w.get("tx_wire") or "").strip()
                if not wire:
                    continue

                from_uid = str(w.get("from_user_id") or "")
                from_name = str(w.get("from_name") or "")
                from_ip = str(w.get("_src_ip") or "")
                from_tcp_port = int(w.get("from_tcp_port") or 0)
                relay_via = str(w.get("_relay_via") or "")
                tip = w.get("ledger_tip") if isinstance(w.get("ledger_tip"), dict) else {}

                txd = _decode_wire_dict(wire) or {}

                prefer_sync = bool(tip.get("file_id")) and bool(tip.get("sha256")) and int(tip.get("size") or 0) > 0
                auto_confirm = "false" if prefer_sync else "true"

                res: Dict[str, Any] = {}
                try:
                    res, _meta = TransactionBlock().execute(
                        wire,
                        params={
                            "action": "import_wire",
                            "from_user_id": from_uid,
                            "from_name": from_name,
                            "from_ip": from_ip,
                            "from_tcp_port": from_tcp_port,
                            "auto_download": "false",
                            "auto_confirm": auto_confirm,
                            "relay_via": relay_via,
                        },
                    )
                    if isinstance(res, dict) and res.get("tx"):
                        txd = res.get("tx") or txd
                        if res.get("ok"):
                            imported += 1

                    ao = (res.get("attachment_offer") if isinstance(res, dict) else None) or {}
                    if isinstance(ao, dict) and ao:
                        off = FileOffer(**ao)
                        if off.offer_id and off.offer_id not in seen_offer_ids:
                            seen_offer_ids.add(off.offer_id)
                            try:
                                STATE.p2p._q_dm_offers.put(off)  # type: ignore[attr-defined]
                            except Exception:
                                pass
                except Exception:
                    res = {"ok": False}

                ledger_synced = False
                try:
                    if prefer_sync and from_uid and (from_ip == "relay" or (from_ip and from_tcp_port > 0)):
                        if int(tip.get("height") or 0) > int(STATE.ledger.height()):
                            tmp_path = app_dir() / f"tx_ledg_{_short(str(tip.get('sha256') or ''), 10)}.json"

                            offer = FileOffer(
                                offer_id=sha256_text(f"tx_ledg|{from_uid}|{tip.get('sha256')}"),
                                scope="ledger",
                                room=STATE.p2p.room,
                                from_user_id=from_uid,
                                from_name=from_name,
                                from_ip=("relay" if from_ip == "relay" else from_ip),
                                from_tcp_port=(0 if from_ip == "relay" else from_tcp_port),
                                file_id=str(tip.get("file_id") or ""),
                                filename=str(tip.get("filename") or "ledger.json"),
                                size=int(tip.get("size") or 0),
                                sha256=str(tip.get("sha256") or ""),
                                note="tx_ledger_tip",
                                relay_via=relay_via,
                            )

                            STATE.p2p.download_offer(offer, str(tmp_path))

                            obj = json.loads(tmp_path.read_text("utf-8", errors="ignore") or "{}")
                            if isinstance(obj, dict) and str(obj.get("coin_fpr", "")) == coin_fingerprint():
                                okL, _ = STATE.ledger.load_from_dict(obj.get("ledger") or {})
                                if okL:
                                    save_ledger()
                                    ledger_synced = True

                            if tmp_path.exists():
                                tmp_path.unlink()
                except Exception:
                    pass

                try:
                    confirmed = bool(res.get("confirmed")) if isinstance(res, dict) else False
                    confirm_reason = str(res.get("confirm_reason") or "") if isinstance(res, dict) else ""
                    attachment_saved = str(res.get("attachment_saved") or "") if isinstance(res, dict) else ""
                    attachment_bytes = int(res.get("attachment_bytes") or 0) if isinstance(res, dict) else 0

                    dm_text = _format_tx_text(
                        txd,
                        confirmed=(confirmed or ledger_synced),
                        confirm_reason=confirm_reason,
                        attachment_saved=attachment_saved,
                        attachment_bytes=attachment_bytes,
                        ledger_synced=ledger_synced,
                    )

                    out_msgs.append({
                        "t": "tx",
                        "ts": float(w.get("ts") or time.time()),
                        "from_user_id": from_uid,
                        "from_name": from_name,
                        "text": dm_text,
                        "tx": txd,
                        "confirmed": bool(confirmed or ledger_synced),
                        "ledger_synced": bool(ledger_synced),
                        "attachment_saved": attachment_saved,
                        "attachment_bytes": attachment_bytes,
                        "attachment_offer": (res.get("attachment_offer") if isinstance(res, dict) else {}) or {},
                    })
                except Exception:
                    pass

            offers_raw = _p2p_pop_dm_offers()
            offers: List[Dict[str, Any]] = []
            for o in (offers_raw or []):
                try:
                    offers.append(dataclasses.asdict(o))
                except Exception:
                    if isinstance(o, dict):
                        offers.append(o)

            def _ts(m: Dict[str, Any]) -> float:
                try:
                    return float(m.get("ts") or 0.0)
                except Exception:
                    return 0.0

            out_msgs = [m for m in out_msgs if isinstance(m, dict)]
            out_msgs.sort(key=_ts)

            def _norm_text(v: Any) -> str:
                return str(v or "").replace("\r\n", "\n").strip()

            WINDOW_S = 2.0
            pos: Dict[Tuple[Any, ...], int] = {}
            deduped: List[Dict[str, Any]] = []

            for m in out_msgs:
                try:
                    ts = float(m.get("ts") or 0.0)
                except Exception:
                    ts = 0.0
                bucket = int(ts // WINDOW_S) if ts > 0 else 0

                from_key = str(
                    m.get("from_user_id")
                    or m.get("from")
                    or m.get("sender_id")
                    or m.get("from_name")
                    or ""
                ).strip()

                text = _norm_text(m.get("text") or m.get("msg") or m.get("message") or "")

                if isinstance(m.get("tx"), dict):
                    txid = str(m["tx"].get("tx_id") or "").strip()
                    k = ("tx", txid or text, bucket)
                else:
                    k = ("dm", from_key, text, bucket)

                if k in pos:
                    i = pos[k]
                    if deduped[i].get("_echo") and not m.get("_echo"):
                        deduped[i] = m
                    continue

                pos[k] = len(deduped)
                deduped.append(m)

            return {"dms": deduped, "file_offers": offers, "tx_imported": imported}, {"type": "private_chat", "action": "feed"}

        if action == "download":
            d = json.loads(str(payload or "{}"))
            offer = FileOffer(**d)
            save_path = str(params.get("save_path") or offer.filename)
            n = STATE.p2p.download_offer(offer, save_path)
            return {"ok": True, "saved": save_path, "bytes": n}, {"type": "private_chat", "action": "download"}

        raise ValueError(f"Unknown private_chat.action={action}")


@dataclass
class WalletBlock(BaseBlock):
    """
    wallet:
      - init
      - load
      - address
      - balance
      - export
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        action = str(params.get("action") or "load").strip().lower()

        if action == "init":
            w = Wallet.generate()
            STATE.wallet = w
            save_wallet(w)
            STATE.ledger.state.ensure_addr(w.address)
            return {"address": w.address}, {"type": "wallet", "action": "init"}

        if action == "load":
            w = load_wallet()
            if not w:
                w = Wallet.generate()
                STATE.wallet = w
                save_wallet(w)
                STATE.ledger.state.ensure_addr(w.address)
                return {"address": w.address}, {"type": "wallet", "action": "init"}
            STATE.wallet = w
            STATE.ledger.state.ensure_addr(w.address)
            return {"address": w.address}, {"type": "wallet", "action": "load"}

        if action == "address":
            if STATE.wallet is None:
                WalletBlock().execute("", params={"action": "load"})
            return {"address": STATE.wallet.address}, {"type": "wallet", "action": "address"}

        if action == "balance":
            if STATE.wallet is None:
                WalletBlock().execute("", params={"action": "load"})
            addr = STATE.wallet.address
            confirmed = STATE.ledger.get_balance(addr)
            available = STATE.ledger.available_balance(addr)
            pend = STATE.ledger.pending_for(addr)
            return {
                "balance": confirmed,
                "confirmed": confirmed,
                "available": available,
                **pend,
            }, {"type": "wallet", "action": "balance"}

        if action == "export":
            if STATE.wallet is None:
                WalletBlock().execute("", params={"action": "load"})
            return dataclasses.asdict(STATE.wallet), {"type": "wallet", "action": "export"}

        raise ValueError(f"Unknown wallet.action={action}")


@dataclass
class TransactionBlock(BaseBlock):
    """
    transaction:
      - create: to_addr/to_user_id, amount, memo, optional file_path
      - submit: payload tx json
      - wire: payload tx json -> base64 wire
      - import_wire: payload wire -> submit
      - pending
      - push_to_peer: to_user_id + payload wire
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        action = str(params.get("action") or "create").strip().lower()

        if action == "create":
            if STATE.wallet is None:
                WalletBlock().execute("", params={"action": "load"})
            assert STATE.wallet is not None

            to_addr = str(params.get("to_addr") or "").strip()
            to_user_id = str(params.get("to_user_id") or "").strip()
            if (not to_addr) and to_user_id:
                peer = STATE.p2p.peers.get(to_user_id)
                if not peer or not getattr(peer, "wallet_addr", ""):
                    raise ValueError("peer_wallet_not_found")
                to_addr = str(peer.wallet_addr).strip()

            amount = int(params.get("amount") or 0)
            memo = str(params.get("memo") or "").strip()

            if not to_addr or amount <= 0:
                raise ValueError("transaction.create requires to_addr and amount>0")

            attachment = None
            file_path = str(params.get("file_path") or "").strip()
            if file_path:
                ok, reason = STATE.moderation.file_check_path(path=file_path)
                if not ok:
                    raise ValueError(f"attachment_blocked:{reason}")

                STATE.p2p.start()

                digest = sha256_file(file_path)
                size = int(os.path.getsize(file_path))
                name = _safe_basename(file_path)
                file_id = f"{digest}:{size}:{name}"
                STATE.p2p.register_shared_file(file_id, file_path)

                attachment = {
                    "sha256": digest,
                    "name": name,
                    "size": size,
                    "ext": Path(file_path).suffix.lower(),
                    "file_id": file_id,
                }

            from_addr = STATE.wallet.address
            STATE.ledger.state.ensure_addr(from_addr)
            nonce = int(STATE.ledger.expected_nonce(from_addr))

            tx = Tx(
                tx_id="",
                ts=time.time(),
                from_addr=from_addr,
                from_pub=STATE.wallet.public_key_b64,
                to_addr=to_addr,
                amount=amount,
                nonce=nonce,
                memo=memo,
                attachment=attachment,
                sig="",
            )
            unsigned = tx.unsigned_dict()
            tx.tx_id = sha256_text(json.dumps(unsigned, sort_keys=True))
            tx.sig = STATE.wallet.sign(canonical_json(unsigned))

            ok2, reason2 = STATE.ledger.verify_tx(tx)
            if not ok2:
                raise ValueError(f"tx_invalid:{reason2}")

            auto_submit = str(params.get("auto_submit") or "true").lower() == "true"
            if auto_submit:
                ok3, reason3 = STATE.ledger.add_tx_to_mempool(tx)
                if not ok3:
                    raise ValueError(f"mempool_reject:{reason3}")
                save_ledger()

            return tx.to_dict(), {"type": "transaction", "action": "create", "tx_id": tx.tx_id}

        if action == "submit":
            d = json.loads(str(payload or "{}"))
            tx = Tx.from_dict(d)
            ok, reason = STATE.ledger.add_tx_to_mempool(tx)
            if ok:
                save_ledger()
            return {"ok": ok, "reason": reason, "tx_id": tx.tx_id}, {"type": "transaction", "action": "submit", "ok": ok}

        if action == "wire":
            d = json.loads(str(payload or "{}"))
            raw = json.dumps(d, separators=(",", ":"), sort_keys=True).encode("utf-8")
            w = base64.urlsafe_b64encode(raw).decode("ascii")
            return {"wire": w}, {"type": "transaction", "action": "wire"}

        if action == "import_wire":
            s = str(payload or "").strip()

            try:
                raw = base64.urlsafe_b64decode(s.encode("ascii"))
                d = json.loads(raw.decode("utf-8"))
                if not isinstance(d, dict):
                    return {"ok": False, "reason": "bad_wire_format", "tx": {}}, {"type": "transaction", "action": "import_wire", "ok": False}
            except Exception:
                return {"ok": False, "reason": "bad_wire_decode", "tx": {}}, {"type": "transaction", "action": "import_wire", "ok": False}

            tx = Tx.from_dict(d)

            if STATE.wallet is None:
                try:
                    WalletBlock().execute("", params={"action": "load"})
                except Exception:
                    pass

            ok, reason = STATE.ledger.add_tx_to_mempool(tx)

            attachment_offer = None
            attachment_saved = ""
            attachment_bytes = 0
            confirmed = False
            confirm_reason = ""

            if ok:
                save_ledger()

                # Attachment offer (including relay peers)
                if isinstance(tx.attachment, dict):
                    a = tx.attachment
                    sha = str(a.get("sha256") or "")
                    name_safe = _safe_basename(str(a.get("name") or "file"))
                    size = int(a.get("size") or 0)
                    file_id = str(a.get("file_id") or "").strip()

                    if not file_id and sha and size > 0:
                        file_id = f"{sha}:{size}:{name_safe}"

                    if sha and size > 0 and file_id:
                        from_ip = str(params.get("from_ip") or "").strip()
                        from_tcp_port = int(params.get("from_tcp_port") or 0)
                        from_user_id = str(params.get("from_user_id") or "").strip()
                        relay_via = str(params.get("relay_via") or "").strip()

                        # Try to find a route if missing
                        if (not from_ip or from_tcp_port <= 0) and from_user_id:
                            peer = STATE.p2p.peers.get(from_user_id)
                            if peer:
                                from_ip = from_ip or peer.ip
                                from_tcp_port = int(peer.tcp_port or 0)
                                # If we still need a relay path, check the peer record
                                if not relay_via and getattr(peer, "relay_via", []):
                                    relay_via = peer.relay_via[0]

                        # Create offer if we have a path (Direct OR Relay)
                        if (from_ip == "relay") or (relay_via) or (from_ip and from_tcp_port > 0):
                            final_ip = "relay" if (from_ip == "relay" or relay_via) else from_ip
                            final_port = 0 if (from_ip == "relay" or relay_via) else from_tcp_port

                            attachment_offer = FileOffer(
                                offer_id=sha256_text(f"tx_attach|{tx.tx_id}|{from_user_id}|{file_id}"),
                                scope="tx",
                                room="",
                                from_user_id=from_user_id,
                                from_name=str(params.get("from_name") or ""),
                                from_ip=final_ip,
                                from_tcp_port=final_port,
                                relay_via=relay_via,
                                file_id=file_id,
                                filename=name_safe,
                                size=size,
                                sha256=sha,
                                note="tx_attachment",
                            )

                            if str(params.get("auto_download") or "true").lower() == "true":
                                try:
                                    save_dir = Path(str(params.get("save_dir") or (app_dir() / "incoming"))).resolve()
                                    save_dir.mkdir(parents=True, exist_ok=True)
                                    save_path = save_dir / f"{tx.tx_id[:10]}_{name_safe}"
                                    attachment_bytes = STATE.p2p.download_offer(attachment_offer, str(save_path))
                                    attachment_saved = str(save_path)
                                except Exception:
                                    pass

            return {
                "ok": ok,
                "reason": reason,
                "tx_id": tx.tx_id,
                "tx": tx.to_dict(),
                "attachment_saved": attachment_saved,
                "attachment_bytes": int(attachment_bytes),
                "attachment_offer": dataclasses.asdict(attachment_offer) if attachment_offer else {},
                "confirmed": confirmed,
                "confirm_reason": confirm_reason,
            }, {"type": "transaction", "action": "import_wire", "ok": ok}

        if action == "pending":
            addr = str(params.get("addr") or (STATE.wallet.address if STATE.wallet else "")).strip()
            txs = [t.to_dict() for t in STATE.ledger.mempool if (not addr or t.from_addr == addr or t.to_addr == addr)]
            return {"count": len(txs), "txs": txs}, {"type": "transaction", "action": "pending"}

        if action == "push_to_peer":
            to_uid = str(params.get("to_user_id") or "").strip()
            wire_in = str(payload or "").strip()
            if not to_uid or not wire_in:
                raise ValueError("transaction.push_to_peer requires to_user_id + payload wire")

            peer = STATE.p2p.peers.get(to_uid)
            if not peer:
                raise ValueError("peer_not_found")

            cleaned = _validate_tx_wire_b64(wire_in)

            ledger_tip: Dict[str, Any] = {}
            try:
                STATE.p2p.start()
                lp = ledger_path()
                if lp.exists():
                    digest = sha256_file(str(lp))
                    size2 = int(os.path.getsize(lp))
                    file_id2 = f"{digest}:{size2}:{lp.name}"
                    STATE.p2p.register_shared_file(file_id2, str(lp))
                    ledger_tip = {
                        "file_id": file_id2,
                        "sha256": digest,
                        "size": size2,
                        "filename": lp.name,
                        "height": STATE.ledger.height(),
                        "tip_hash": STATE.ledger.tip_hash(),
                    }
            except Exception:
                ledger_tip = {}

            STATE.p2p.push_tx_to_peer(peer, cleaned, ledger_tip=ledger_tip)

            frame = {
                "t": "tx_push",
                "ts": time.time(),
                "from_user_id": STATE.p2p.identity.user_id,
                "from_name": STATE.p2p.identity.name,
                "tx_wire": cleaned,
                "ledger_tip": ledger_tip,
            }

            for nm in ("send_dm_frame", "send_dm_json", "send_dm_dict", "send_dm_message"):
                fn = getattr(STATE.p2p, nm, None)
                if callable(fn):
                    try:
                        fn(peer, frame)
                        break
                    except Exception:
                        pass

            txd = _decode_wire_dict(cleaned) or {}
            _echo_add_dm({
                "t": "tx",
                "ts": time.time(),
                "from_user_id": STATE.p2p.identity.user_id,
                "from_name": STATE.p2p.identity.name,
                "to_user_id": getattr(peer, "user_id", to_uid),
                "to_name": getattr(peer, "name", ""),
                "text": _format_tx_text(txd, confirmed=False),
                "tx": txd,
                "direction": "out",
                "ledger_tip": ledger_tip,
            })

            return {"ok": True, "ledger_tip": ledger_tip}, {"type": "transaction", "action": "push_to_peer", "ok": True}

        raise ValueError(f"Unknown transaction.action={action}")

# --- Mining (kept as-is; only safety/robustness improvements were earlier) ----

class _MinerWorker(threading.Thread):
    def __init__(
        self,
        *,
        intensity: float,
        work_s: float,
        rest_s: float,
        cooldown_s: float,
        hps_cap: Optional[int],
        yield_every: int,
        out_q: "queue.Queue[Optional[Block]]",
        stop: threading.Event,
    ) -> None:
        super().__init__(daemon=True)
        self.intensity = float(intensity)
        self.work_s = float(work_s)
        self.rest_s = float(rest_s)
        self.cooldown_s = float(cooldown_s)
        self.hps_cap = hps_cap
        self.yield_every = int(yield_every)
        self.out_q = out_q
        self.stop = stop

    def run(self) -> None:
        while not self.stop.is_set():
            if STATE.wallet is None:
                try:
                    WalletBlock().execute("", params={"action": "load"})
                except Exception:
                    time.sleep(0.25)
                    continue
            assert STATE.wallet is not None

            b = STATE.ledger.mine_once(
                miner_addr=STATE.wallet.address,
                stop_event=self.stop,
                intensity=self.intensity,
                work_budget_s=self.work_s if self.work_s > 0 else None,
                hps_cap=self.hps_cap,
                yield_every=self.yield_every,
            )

            if self.stop.is_set():
                break

            if b is not None:
                self.out_q.put(b)
                if self.cooldown_s > 0:
                    time.sleep(self.cooldown_s)
            else:
                if self.rest_s > 0:
                    time.sleep(self.rest_s)


@dataclass
class MineBlock(BaseBlock):
    """
    mine:
      - start: threads, intensity, safe, work_s, rest_s, hps_cap, yield_every, max_runtime_s
      - stop
      - status
      - mine_one
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        import queue as _q

        action = str(params.get("action") or "status").strip().lower()
        force = str(params.get("force") or "false").lower() == "true"

        if action == "status":
            return STATE.miner_status, {"type": "mine", "action": "status"}

        if action == "stop":
            STATE.miner_stop.set()
            try:
                STATE.miner_status["running"] = False
            except Exception:
                STATE.miner_status = {"running": False}
            release_lock(MINER_LOCK)
            return {"running": False}, {"type": "mine", "action": "stop"}

        safe = str(params.get("safe") or "true").strip().lower() == "true"

        threads_in = int(params.get("threads") or (1 if safe else 1))
        intensity_in = float(params.get("intensity") or (0.18 if safe else 0.65))

        work_s = float(params.get("work_s") or (6.0 if safe else 0.0))
        rest_s = float(params.get("rest_s") or (3.0 if safe else 0.0))

        hps_cap_raw = int(params.get("hps_cap") or (25000 if safe else 0))
        hps_cap = hps_cap_raw if hps_cap_raw > 0 else None

        yield_every = int(params.get("yield_every") or (2000 if safe else 10000))
        cooldown_s = float(params.get("cooldown_s") or (0.35 if safe else 0.0))
        max_runtime_s = float(params.get("max_runtime_s") or (0.0))

        cpu_count = os.cpu_count() or 4
        max_threads = 1 if safe else max(1, cpu_count)
        threads = max(1, min(threads_in, max_threads))

        max_intensity = 0.25 if safe else 1.0
        intensity = max(0.02, min(float(intensity_in), float(max_intensity)))

        if action == "mine_one":
            if STATE.miner_status.get("running"):
                return {"ok": False, "reason": "miner_already_running"}, {"type": "mine", "action": "mine_one", "ok": False}

            if STATE.wallet is None:
                WalletBlock().execute("", params={"action": "load"})
            assert STATE.wallet is not None

            stop = threading.Event()
            b = STATE.ledger.mine_once(
                miner_addr=STATE.wallet.address,
                stop_event=stop,
                intensity=intensity,
                work_budget_s=work_s if work_s > 0 else None,
                hps_cap=hps_cap,
                yield_every=yield_every,
            )
            if b is None:
                return {"ok": False, "reason": "no_solution_in_budget"}, {"type": "mine", "action": "mine_one", "ok": False}

            ok, reason = STATE.ledger.accept_block(b)
            bal = STATE.ledger.get_balance(STATE.wallet.address)
            if ok:
                save_ledger()

            return {
                "ok": ok,
                "reason": reason,
                "height": b.height,
                "hash": b.block_hash,
                "miner": STATE.wallet.address,
                "balance": bal,
            }, {"type": "mine", "action": "mine_one", "ok": ok}

        if action == "start":
            if STATE.miner_status.get("running"):
                return {"running": True, "reason": "already_running", "status": STATE.miner_status}, {"type": "mine", "action": "start", "ok": True}

            if not acquire_lock(MINER_LOCK, force=force):
                return {
                    "running": False,
                    "reason": "miner_lock_busy",
                    "lock_path": str(MINER_LOCK),
                    "cwd": os.getcwd(),
                }, {"type": "mine", "action": "start", "ok": False}

            STATE.miner_stop.clear()
            out_q: "_q.Queue[Optional[Block]]" = _q.Queue()

            def coordinator() -> None:
                start_t = time.monotonic()
                workers: List[_MinerWorker] = []
                try:
                    STATE.miner_status = {
                        "running": True,
                        "safe": safe,
                        "threads": threads,
                        "intensity": intensity,
                        "work_s": work_s,
                        "rest_s": rest_s,
                        "hps_cap": hps_cap,
                        "yield_every": yield_every,
                        "accepted": 0,
                        "rejected": 0,
                    }

                    for _ in range(threads):
                        w = _MinerWorker(
                            intensity=intensity,
                            work_s=work_s,
                            rest_s=rest_s,
                            cooldown_s=cooldown_s,
                            hps_cap=hps_cap,
                            yield_every=yield_every,
                            out_q=out_q,
                            stop=STATE.miner_stop,
                        )
                        workers.append(w)
                        w.start()

                    while not STATE.miner_stop.is_set():
                        if max_runtime_s and (time.monotonic() - start_t) >= max_runtime_s:
                            break

                        try:
                            b = out_q.get(timeout=0.5)
                        except _q.Empty:
                            continue

                        if b is None:
                            continue

                        ok, reason = STATE.ledger.accept_block(b)
                        if ok:
                            STATE.miner_status["accepted"] = int(STATE.miner_status.get("accepted", 0)) + 1
                            save_ledger()

                            try:
                                STATE.p2p.start()
                                lp = ledger_path()
                                if lp.exists():
                                    digest = sha256_file(str(lp))
                                    size = int(os.path.getsize(lp))
                                    file_id = f"{digest}:{size}:{lp.name}"
                                    STATE.p2p.register_shared_file(file_id, str(lp))
                                    STATE.p2p.broadcast_ledger_tip(
                                        file_id=file_id,
                                        sha256hex=digest,
                                        size=size,
                                        filename=lp.name,
                                        height=STATE.ledger.height(),
                                        tip_hash=STATE.ledger.tip_hash(),
                                    )
                            except Exception:
                                pass
                        else:
                            STATE.miner_status["rejected"] = int(STATE.miner_status.get("rejected", 0)) + 1
                            STATE.miner_status["last_reject"] = reason

                except Exception:
                    STATE.miner_status["last_error"] = traceback.format_exc()
                finally:
                    try:
                        STATE.miner_status["running"] = False
                    except Exception:
                        STATE.miner_status = {"running": False}
                    release_lock(MINER_LOCK)

            t = threading.Thread(target=coordinator, daemon=True)
            STATE.miner_thread = t
            t.start()
            return {"running": True, "safe": safe, "threads": threads, "intensity": intensity}, {"type": "mine", "action": "start", "ok": True}

        raise ValueError(f"Unknown mine.action={action}")


# ---------------- Register ----------------
BLOCKS.register("account", AccountBlock)
BLOCKS.register("rooms", RoomsBlock)
BLOCKS.register("chat_protection", ChatProtectionBlock)
BLOCKS.register("file_protection", FileProtectionBlock)
BLOCKS.register("public_chat", PublicChatBlock)
BLOCKS.register("private_chat", PrivateChatBlock)
BLOCKS.register("wallet", WalletBlock)
BLOCKS.register("transaction", TransactionBlock)
BLOCKS.register("mine", MineBlock)
