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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

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
    coin_fingerprint,     # <-- ADD
    ledger_path,          # <-- ADD
)
from ledger import Wallet, Tx, Block
from p2p import FileOffer, tcp_request_blob
from utils import app_dir
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


def _format_tx_text(tx: Dict[str, Any], *, confirmed: bool, confirm_reason: str = "",
                    attachment_saved: str = "", attachment_bytes: int = 0,
                    ledger_synced: bool = False) -> str:
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
def _decode_wire_dict(wire_b64: str) -> Optional[Dict[str, Any]]:
    try:
        raw = base64.urlsafe_b64decode(wire_b64.encode("ascii"))
        d = json.loads(raw.decode("utf-8"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None

def summarize_tx_wire(wire_b64: str) -> str:
    d = _decode_wire_dict(wire_b64)
    if not d:
        return "[TX] invalid"
    txid = str(d.get("tx_id") or "")
    fa = str(d.get("from_addr") or "")
    ta = str(d.get("to_addr") or "")
    amt = d.get("amount", 0)
    return f"[TX] id={_short(txid, 8)} {_short(fa, 6)}→{_short(ta, 6)} amt={amt}"
def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        # Windows/Linux: this is a common cheap check
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

        # force = true: only remove if PID inside is not alive
        try:
            pid_txt = path.read_text("ascii", errors="ignore").strip()
            pid = int(pid_txt) if pid_txt.isdigit() else -1
        except Exception:
            pid = -1

        if pid != -1 and _pid_alive(pid):
            return False  # another instance is really running

        try:
            path.unlink()
        except Exception:
            pass

        # retry once
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
# ---------------- Account ----------------
@dataclass
class AccountBlock(BaseBlock):
    """
    account:
      - ensure (default)
      - set: account.name, account.avatar_path
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


# ---------------- Rooms ----------------
@dataclass
class RoomsBlock(BaseBlock):
    """
    rooms:
      - join: rooms.room
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
            STATE.p2p.broadcast_presence()
            return {"room": room}, {"type": "rooms", "action": "join"}

        if action == "peers":
            STATE.p2p.peers.prune()
            peers = [dataclasses.asdict(p) for p in STATE.p2p.peers.list()]
            return {"count": len(peers), "peers": peers}, {"type": "rooms", "action": "peers"}

        return {"room": STATE.p2p.room}, {"type": "rooms", "action": "current"}


# ---------------- Chat Protection ----------------
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

        # check
        uid = str(params.get("user_id") or "local")
        text = str(payload or "")
        ok, cleaned, reason = STATE.moderation.chat_check(user_id=uid, text=text)
        return {"ok": ok, "text": cleaned if ok else "", "reason": reason}, {"type": "chat_protection", "action": "check", "ok": ok}


# ---------------- File Protection ----------------
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
            info = {"path": path, "sha256": sha256_file(path), "size": os.path.getsize(path), "ext": Path(path).suffix.lower()}
        return {"ok": ok, "reason": reason, "info": info}, {"type": "file_protection", "action": "scan", "ok": ok}


# ---------------- Public Chat ----------------
@dataclass
class PublicChatBlock(BaseBlock):
    """
    public_chat:
      - send (default): payload text
      - feed
      - share_file: public_chat.path, public_chat.note
      - download: payload offer json
    """
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
            return {"ok": True, "room": STATE.p2p.room, "text": cleaned}, {"type": "public_chat", "action": "send", "ok": True}

        if action == "share_file":
            path = str(params.get("path") or "").strip()
            note = str(params.get("note") or "").strip()
            if not path:
                raise ValueError("public_chat.share_file requires public_chat.path")
            ok, reason = STATE.moderation.file_check_path(path=path)
            if not ok:
                return {"ok": False, "reason": reason}, {"type": "public_chat", "action": "share_file", "ok": False}
            offer = STATE.p2p.share_file_to_room(path, note=note, scope="room")
            return dataclasses.asdict(offer), {"type": "public_chat", "action": "share_file", "ok": True}

        if action == "feed":
            # 1) normal room messages (FILTER OUT legacy [LEDGER] spam)
            raw_msgs = STATE.p2p.pop_room_messages()
            visible_msgs: List[Dict[str, Any]] = []
            legacy_imported = 0

            for m in (raw_msgs or []):
                try:
                    text = str(m.get("text", "") or "")
                    if text.startswith("[LEDGER]"):
                        # legacy support: try import but DO NOT show in UI
                        wire = text[len("[LEDGER]"):].strip()
                        d = _decode_wire_dict(wire)
                        if isinstance(d, dict):
                            ok, _reason = STATE.ledger.load_from_dict(d)
                            if ok:
                                save_ledger()
                                legacy_imported += 1
                        continue
                except Exception:
                    # if anything goes wrong, just hide it (still prevents room annoyance)
                    continue

                visible_msgs.append(m)

            # 2) ledger_tip sync (preferred; also silent)
            tips = STATE.p2p.pop_ledger_tips()
            tips_seen = len(tips or [])
            tips_imported = 0

            for tip in (tips or []):
                try:
                    # only bother if peer claims a higher height
                    if int(tip.get("height", 0)) <= int(STATE.ledger.height()):
                        continue

                    ip = str(tip.get("_src_ip") or "")
                    port = int(tip.get("tcp_port") or 0)
                    file_id = str(tip.get("file_id") or "")
                    sha = str(tip.get("sha256") or "")

                    if not ip or port <= 0 or not file_id or not sha:
                        continue

                    tmp_path = app_dir() / f"ledger_tip_{_short(sha, 10).replace('…', '')}.json"

                    # fetch over TCP file_get with sha verification
                    tcp_request_blob(
                        ip, port,
                        {"t": "file_get", "file_id": file_id},
                        str(tmp_path),
                        expected_sha256=sha,
                    )

                    # ledger.json wrapper contains {"coin_fpr":..., "ledger":{...}}
                    obj = json.loads(tmp_path.read_text("utf-8", errors="ignore") or "{}")
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("coin_fpr", "")) != coin_fingerprint():
                        continue

                    ok, _reason = STATE.ledger.load_from_dict(obj.get("ledger") or {})
                    if ok:
                        save_ledger()
                        tips_imported += 1

                except Exception:
                    pass
                finally:
                    try:
                        if tmp_path.exists():
                            tmp_path.unlink()
                    except Exception:
                        pass

            offers = [dataclasses.asdict(o) for o in STATE.p2p.pop_room_offers()]
            return {
                "room": STATE.p2p.room,
                "messages": visible_msgs,
                "file_offers": offers,

                # optional debug counters (won't spam chat)
                "ledger_tip_seen": tips_seen,
                "ledger_tip_imported": tips_imported,
                "legacy_ledger_imported": legacy_imported,
            }, {"type": "public_chat", "action": "feed"}
        if action == "download":
            d = json.loads(str(payload or "{}"))
            offer = FileOffer(**d)
            save_path = str(params.get("save_path") or offer.filename)
            n = STATE.p2p.download_offer(offer, save_path)
            return {"ok": True, "saved": save_path, "bytes": n}, {"type": "public_chat", "action": "download"}

        raise ValueError(f"Unknown public_chat.action={action}")


# ---------------- Private Chat ----------------
@dataclass
class PrivateChatBlock(BaseBlock):
    """
    private_chat:
      - send: private_chat.to_user_id + payload text
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
            return {"ok": True, "to": peer.name, "text": cleaned}, {"type": "private_chat", "action": "send", "ok": True}

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
            msgs = STATE.p2p.pop_dm_messages()

            tx_pushes = STATE.p2p.pop_tx_msgs()
            imported = 0
            tx_pushes_view: List[Dict[str, Any]] = []

            # prevent dup offers within this feed call
            seen_offer_ids: set[str] = set()

            for w in (tx_pushes or []):
                try:
                    if not isinstance(w, dict):
                        continue

                    wire = str(w.get("tx_wire") or "").strip()
                    if not wire:
                        continue

                    from_uid = str(w.get("from_user_id") or "")
                    from_name = str(w.get("from_name") or "")
                    from_ip = str(w.get("_src_ip") or "")
                    from_tcp_port = int(w.get("from_tcp_port") or 0)
                    tip = w.get("ledger_tip") if isinstance(w.get("ledger_tip"), dict) else {}

                    prefer_sync = bool(tip.get("file_id")) and bool(tip.get("sha256")) and int(tip.get("size") or 0) > 0
                    auto_confirm = "false" if prefer_sync else "true"

                    res, _meta = TransactionBlock().execute(
                        wire,
                        params={
                            "action": "import_wire",
                            "from_user_id": from_uid,
                            "from_name": from_name,
                            "from_ip": from_ip,
                            "from_tcp_port": from_tcp_port,
                            "auto_download": "false",   # <-- OPTIONAL: show download button instead of auto-saving
                            "auto_confirm": auto_confirm,
                        },
                    )

                    # --- if tx import created an attachment_offer, enqueue it as a normal DM file offer ---
                    try:
                        ao = (res.get("attachment_offer") if isinstance(res, dict) else None) or {}
                        if isinstance(ao, dict) and ao:
                            off = FileOffer(**ao)
                            if off.offer_id and off.offer_id not in seen_offer_ids:
                                seen_offer_ids.add(off.offer_id)
                                # push into the same queue your UI already uses
                                STATE.p2p._q_dm_offers.put(off)  # yes, it's "private" — but it's your app
                    except Exception:
                        pass

                    # Sync ledger from sender immediately (no mining needed on receiver)
                    ledger_synced = False
                    if prefer_sync and from_ip and from_tcp_port > 0:
                        try:
                            if int(tip.get("height") or 0) > int(STATE.ledger.height()):
                                tmp_path = app_dir() / f"tx_ledg_{_short(str(tip.get('sha256') or ''), 10).replace('…', '')}.json"
                                tcp_request_blob(
                                    from_ip,
                                    from_tcp_port,
                                    {"t": "file_get", "file_id": str(tip.get("file_id") or "")},
                                    str(tmp_path),
                                    expected_sha256=str(tip.get("sha256") or ""),
                                )
                                obj = json.loads(tmp_path.read_text("utf-8", errors="ignore") or "{}")
                                if isinstance(obj, dict) and str(obj.get("coin_fpr", "")) == coin_fingerprint():
                                    okL, _rL = STATE.ledger.load_from_dict(obj.get("ledger") or {})
                                    if okL:
                                        save_ledger()
                                        ledger_synced = True
                        except Exception:
                            pass
                        finally:
                            try:
                                if "tmp_path" in locals() and tmp_path.exists():
                                    tmp_path.unlink()
                            except Exception:
                                pass

                    if isinstance(res, dict) and res.get("ok"):
                        imported += 1

                    txd = (res.get("tx") if isinstance(res, dict) else None) or {}
                    confirmed = bool(res.get("confirmed")) if isinstance(res, dict) else False
                    confirm_reason = str(res.get("confirm_reason") or "") if isinstance(res, dict) else ""
                    attachment_saved = str(res.get("attachment_saved") or "") if isinstance(res, dict) else ""
                    attachment_bytes = int(res.get("attachment_bytes") or 0) if isinstance(res, dict) else 0

                    dm_text = _format_tx_text(
                        txd if isinstance(txd, dict) else {},
                        confirmed=(confirmed or ledger_synced),
                        confirm_reason=confirm_reason,
                        attachment_saved=attachment_saved,
                        attachment_bytes=attachment_bytes,
                        ledger_synced=ledger_synced,
                    )

                    msgs.append({
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

                    tx_pushes_view.append({
                        "from_user_id": from_uid,
                        "from_name": from_name,
                        "from_ip": from_ip,
                        "from_tcp_port": from_tcp_port,
                        "wire": wire,
                        "summary": summarize_tx_wire(wire),
                        "ledger_tip": tip,
                        "ledger_synced": ledger_synced,
                        "import": res,
                    })
                except Exception:
                    continue

            # IMPORTANT: pop offers AFTER we possibly queued tx attachment offers
            offers = [dataclasses.asdict(o) for o in STATE.p2p.pop_dm_offers()]

            return {
                "dms": msgs,
                "file_offers": offers,
                "tx_pushes": tx_pushes_view,
                "tx_imported": imported,
            }, {"type": "private_chat", "action": "feed"}

        if action == "download":
            d = json.loads(str(payload or "{}"))
            offer = FileOffer(**d)
            save_path = str(params.get("save_path") or offer.filename)
            n = STATE.p2p.download_offer(offer, save_path)
            return {"ok": True, "saved": save_path, "bytes": n}, {"type": "private_chat", "action": "download"}

        raise ValueError(f"Unknown private_chat.action={action}")


# ---------------- Wallet / Coin / Tx / Mining ----------------
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
                "balance": confirmed,  # <-- ADD THIS
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
      - create: to_addr, amount, memo, optional file_path (attachment metadata)
      - submit: payload tx json
      - wire: payload tx json -> base64 wire
      - import_wire: payload wire -> submit
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

                # Make sure P2P is running so we can serve the attachment back to the receiver
                STATE.p2p.start()

                digest = sha256_file(file_path)
                size = int(os.path.getsize(file_path))
                name = os.path.basename(file_path)
                file_id = f"{digest}:{size}:{name}"

                # Register so peers can fetch via {"t":"file_get","file_id": ...}
                STATE.p2p.register_shared_file(file_id, file_path)

                attachment = {
                    "sha256": digest,
                    "name": name,
                    "size": size,
                    "ext": Path(file_path).suffix.lower(),
                    "file_id": file_id,  # NEW: receiver can fetch directly
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
                auto_confirm = str(params.get("auto_confirm") or "true").strip().lower() == "true"
                confirmed = False
                confirm_reason = ""

                if auto_confirm:
                    try:
                        stop = threading.Event()
                        b = STATE.ledger.mine_once(
                            miner_addr=STATE.wallet.address,
                            stop_event=stop,
                            intensity=1.0,
                            work_budget_s=0.25,  # tiny budget; with difficulty_zeros=0 it’s instant
                            hps_cap=None,
                            yield_every=500,
                        )
                        if b is not None:
                            okb, rb = STATE.ledger.accept_block(b)
                            confirmed = bool(okb)
                            confirm_reason = rb
                            if okb:
                                save_ledger()
                    except Exception:
                        pass

                out = tx.to_dict()
                out["_confirmed"] = bool(confirmed)
                out["_confirm_reason"] = confirm_reason
                return out, {"type": "transaction", "action": "create", "tx_id": tx.tx_id}
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

            # decode wire
            try:
                raw = base64.urlsafe_b64decode(s.encode("ascii"))
                d = json.loads(raw.decode("utf-8"))
                if not isinstance(d, dict):
                    return {"ok": False, "reason": "bad_wire_format"}, {"type": "transaction", "action": "import_wire",
                                                                        "ok": False}
            except Exception:
                return {"ok": False, "reason": "bad_wire_decode"}, {"type": "transaction", "action": "import_wire",
                                                                    "ok": False}

            tx = Tx.from_dict(d)

            # Ensure wallet exists (used if we auto-confirm by mining)
            if STATE.wallet is None:
                try:
                    WalletBlock().execute("", params={"action": "load"})
                except Exception:
                    pass

            ok, reason = STATE.ledger.add_tx_to_mempool(tx)
            if ok:
                save_ledger()

                # -------- Attachment offer + optional auto-download ----------
                attachment_offer = None
                attachment_saved = ""
                attachment_bytes = 0

                if ok and isinstance(tx.attachment, dict):
                    a = tx.attachment
                    sha = str(a.get("sha256") or "")
                    orig_name = str(a.get("name") or "file")
                    name_safe = _safe_basename(orig_name)
                    size = int(a.get("size") or 0)

                    # use EXACT file_id from sender metadata if present
                    file_id = str(a.get("file_id") or "").strip()
                    if not file_id and sha and size > 0:
                        # fallback only if sender didn't include file_id
                        file_id = f"{sha}:{size}:{os.path.basename(orig_name)}"

                    if sha and size > 0 and file_id:
                        from_ip = str(params.get("from_ip") or "").strip()
                        from_tcp_port = int(params.get("from_tcp_port") or 0)
                        from_user_id = str(params.get("from_user_id") or "").strip()

                        # fallback: peer directory by user_id
                        if (not from_ip or from_tcp_port <= 0) and from_user_id:
                            peer = STATE.p2p.peers.get(from_user_id)
                            if peer:
                                from_ip = from_ip or peer.ip
                                if from_tcp_port <= 0:
                                    from_tcp_port = int(peer.tcp_port or 0)

                        if from_ip and from_tcp_port > 0:
                            # Create an offer the UI can use later (download button)
                            attachment_offer = FileOffer(
                                offer_id=sha256_text(f"tx_attach|{tx.tx_id}|{from_ip}|{from_tcp_port}|{file_id}"),
                                scope="tx",
                                room="",
                                from_user_id=from_user_id,
                                from_name=str(params.get("from_name") or ""),
                                from_ip=from_ip,
                                from_tcp_port=from_tcp_port,

                                file_id=file_id,  # NEW: exact id to request
                                filename=os.path.basename(orig_name),  # keep original for display
                                size=size,
                                sha256=sha,
                                note="tx_attachment",
                            )

                            auto_download = str(params.get("auto_download") or "true").strip().lower() == "true"
                            if auto_download:
                                try:
                                    save_dir = Path(str(params.get("save_dir") or (app_dir() / "incoming"))).resolve()
                                    save_dir.mkdir(parents=True, exist_ok=True)
                                    save_path = save_dir / f"{tx.tx_id[:10]}_{name_safe}"

                                    attachment_bytes = STATE.p2p.download_offer(attachment_offer, str(save_path))
                                    attachment_saved = str(save_path)
                                except Exception:
                                    pass

            # -------- Optional: auto-confirm by mining a block ----------
            confirmed = False
            confirm_reason = ""
            auto_confirm = str(params.get("auto_confirm") or "true").strip().lower() == "true"

            if ok and auto_confirm and STATE.wallet is not None:
                try:
                    stop = threading.Event()
                    # safe defaults
                    intensity = float(params.get("confirm_intensity") or 0.18)
                    work_s = float(params.get("confirm_work_s") or 6.0)
                    hps_cap_raw = int(params.get("confirm_hps_cap") or 25000)
                    hps_cap = hps_cap_raw if hps_cap_raw > 0 else None
                    yield_every = int(params.get("confirm_yield_every") or 2000)

                    b = STATE.ledger.mine_once(
                        miner_addr=STATE.wallet.address,
                        stop_event=stop,
                        intensity=max(0.02, min(1.0, intensity)),
                        work_budget_s=work_s if work_s > 0 else None,
                        hps_cap=hps_cap,
                        yield_every=yield_every,
                    )
                    if b is not None:
                        okb, rb = STATE.ledger.accept_block(b)
                        confirmed = bool(okb)
                        confirm_reason = rb
                        if okb:
                            save_ledger()

                            # Broadcast ledger tip so sender (and others) can sync + clear pending
                            try:
                                STATE.p2p.start()
                                lp = ledger_path()
                                if lp.exists():
                                    digest = sha256_file(str(lp))
                                    size2 = int(os.path.getsize(lp))
                                    file_id2 = f"{digest}:{size2}:{lp.name}"
                                    STATE.p2p.register_shared_file(file_id2, str(lp))
                                    STATE.p2p.broadcast_ledger_tip(
                                        file_id=file_id2,
                                        sha256hex=digest,
                                        size=size2,
                                        filename=lp.name,
                                        height=STATE.ledger.height(),
                                        tip_hash=STATE.ledger.tip_hash(),
                                    )
                            except Exception:
                                pass
                except Exception:
                    pass

            return {
                "ok": ok,
                "reason": reason,
                "tx_id": tx.tx_id,
                "tx": tx.to_dict(),  # NEW: full decoded tx for UI
                "attachment_saved": attachment_saved,
                "attachment_bytes": int(attachment_bytes),
                "attachment_offer": dataclasses.asdict(attachment_offer) if attachment_offer else {},
                "confirmed": bool(confirmed),
                "confirm_reason": confirm_reason,
            }, {"type": "transaction", "action": "import_wire", "ok": ok}
        if action == "pending":
            addr = str(params.get("addr") or (STATE.wallet.address if STATE.wallet else "")).strip()
            txs = [t.to_dict() for t in STATE.ledger.mempool if (not addr or t.from_addr == addr or t.to_addr == addr)]
            return {"count": len(txs), "txs": txs}, {"type": "transaction", "action": "pending"}
        if action == "push_to_peer":
            to_uid = str(params.get("to_user_id") or "").strip()
            wire = str(payload or "").strip()
            if not to_uid or not wire:
                raise ValueError("transaction.push_to_peer requires to_user_id + payload wire")
            peer = STATE.p2p.peers.get(to_uid)
            if not peer:
                raise ValueError("peer_not_found")

            ok, cleaned, reason = STATE.moderation.chat_check(user_id=STATE.p2p.identity.user_id, text=wire)
            if not ok:
                return {"ok": False, "reason": reason}, {"type": "transaction", "action": "push_to_peer", "ok": False}

            # Make sure sender has confirmed this tx (so receiver can sync instantly)
            ensure_confirmed = str(params.get("ensure_confirmed") or "true").strip().lower() == "true"
            if ensure_confirmed:
                try:
                    d = _decode_wire_dict(cleaned)
                    txid = str(d.get("tx_id") or "") if isinstance(d, dict) else ""
                    if txid and any(t.tx_id == txid for t in (STATE.ledger.mempool or [])):
                        # confirm mempool once
                        if STATE.wallet is None:
                            WalletBlock().execute("", params={"action": "load"})
                        if STATE.wallet is not None:
                            stop = threading.Event()
                            b = STATE.ledger.mine_once(
                                miner_addr=STATE.wallet.address,
                                stop_event=stop,
                                intensity=1.0,
                                work_budget_s=0.25,
                                hps_cap=None,
                                yield_every=500,
                            )
                            if b is not None:
                                okb, _rb = STATE.ledger.accept_block(b)
                                if okb:
                                    save_ledger()
                except Exception:
                    pass

            # Build + serve a ledger tip over TCP so receiver can sync immediately (no mining needed)
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

            # Send tx + embedded ledger tip
            STATE.p2p.push_tx_to_peer(peer, cleaned, ledger_tip=ledger_tip)
            return {"ok": True, "ledger_tip": ledger_tip}, {"type": "transaction", "action": "push_to_peer", "ok": True}

        raise ValueError(f"Unknown transaction.action={action}")


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
                # work window expired (or nothing found) -> cool off
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

        # IMPORTANT: status/stop must NOT grab the lock
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

        # ---- Parse mining params (only for start/mine_one) ----
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

        # ---- mine_one (no background worker) ----
        if action == "mine_one":
            if STATE.miner_status.get("running"):
                return {"ok": False, "reason": "miner_already_running"}, {"type": "mine", "action": "mine_one",
                                                                          "ok": False}

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
                return {"ok": False, "reason": "no_solution_in_budget"}, {"type": "mine", "action": "mine_one",
                                                                          "ok": False}

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

        # ---- start (background miners) ----
        if action == "start":
            if STATE.miner_status.get("running"):
                return {"running": True, "reason": "already_running", "status": STATE.miner_status}, {"type": "mine",
                                                                                                      "action": "start",
                                                                                                      "ok": True}

            # Acquire lock ONLY here
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

                    # start workers
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

                    # coordinator loop
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

                            # broadcast ledger snapshot so others learn balances
                            try:
                                STATE.p2p.start()

                                lp = ledger_path()
                                if lp.exists():
                                    digest = sha256_file(str(lp))
                                    size = int(os.path.getsize(lp))
                                    file_id = f"{digest}:{size}:{lp.name}"

                                    # serve this file via file_get
                                    STATE.p2p.register_shared_file(file_id, str(lp))

                                    # multicast a tiny tip (NOT a chat message)
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
            return {"running": True, "safe": safe, "threads": threads, "intensity": intensity}, {"type": "mine",
                                                                                                 "action": "start",
                                                                                                 "ok": True}

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
