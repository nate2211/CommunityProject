# lighthouse_server.py
from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple, List

MAX_LINE = 256_000
STALE_S = 35.0
PEERLIST_INTERVAL_S = 2.0

# Safety cap for relayed files (keep your server safe)
MAX_RELAY_FILE_BYTES = int(os.environ.get("LIGHTHOUSE_MAX_FILE_MB", "150")) * 1024 * 1024
MAX_CHUNK_B64 = 160_000  # base64 chars per chunk (approx <=120KB raw)

TOKEN = (os.environ.get("LIGHTHOUSE_TOKEN") or os.environ.get("P2P_LIGHTHOUSE_TOKEN") or "").strip()


def now_ts() -> float:
    return time.time()


def _safe_str(v: Any, n: int = 256) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= n else s[:n]


def _safe_int(v: Any, lo: int, hi: int, default: int = 0) -> int:
    try:
        x = int(v)
    except Exception:
        return default
    return max(lo, min(hi, x))


def _read_json_line(conn: socket.socket, buf: bytearray) -> Optional[Dict[str, Any]]:
    """
    Returns:
      - dict: decoded JSON object
      - {}: timeout/no full line yet
      - None: disconnect / fatal error
    """
    while True:
        nl = buf.find(b"\n")
        if nl != -1:
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            if not line:
                return {}  # empty keepalive line -> ignore
            if len(line) > MAX_LINE:
                return None
            try:
                obj = json.loads(line.decode("utf-8"))
            except Exception:
                return None
            return obj if isinstance(obj, dict) else None

        if len(buf) > MAX_LINE:
            return None

        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            return {}  # no data this tick
        except OSError:
            return None

        if not chunk:
            return None  # peer disconnected
        buf.extend(chunk)


def _send_json(conn: socket.socket, obj: Dict[str, Any]) -> None:
    data = (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_LINE:
        return
    conn.sendall(data)


@dataclass
class PeerRecord:
    user_id: str
    name: str
    room: str
    avatar_sha: str
    wallet_addr: str
    last_seen: float
    # source IP seen by lighthouse
    ip: str = ""
    # client TCP port (LAN-only; still useful sometimes)
    tcp_port: int = 0

@dataclass
class LighthouseRecord:
    ip: str
    port: int
    user_id: str
    last_seen: float

class LighthouseState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.clients: Dict[str, "ClientSession"] = {}  # user_id -> session
        self.peers: Dict[str, PeerRecord] = {}  # user_id -> record
        self.lighthouses: Dict[str, LighthouseRecord] = {}  # "ip:port" -> record
        self._last_peerlist_bcast: float = 0.0

    def upsert_peer(self, rec: PeerRecord, sess: "ClientSession") -> None:
        with self.lock:
            self.clients[rec.user_id] = sess
            self.peers[rec.user_id] = rec

    def upsert_lighthouse(self, ip: str, port: int, user_id: str, ts: float) -> None:
        ip = _safe_str(ip, 128)
        port = _safe_int(port, 0, 65535, 0)
        user_id = _safe_str(user_id, 128)
        if not ip or port <= 0 or not user_id:
            return
        key = f"{ip}:{port}"
        with self.lock:
            self.lighthouses[key] = LighthouseRecord(ip=ip, port=port, user_id=user_id, last_seen=float(ts))

    def list_lighthouses(self) -> List[Dict[str, Any]]:
        t = now_ts()
        out: List[Dict[str, Any]] = []
        with self.lock:
            for k, rec in list(self.lighthouses.items()):
                if (t - float(rec.last_seen)) > STALE_S:
                    self.lighthouses.pop(k, None)
                    continue
                out.append({"ip": rec.ip, "port": int(rec.port), "user_id": rec.user_id})
        return out
    def remove(self, user_id: str) -> None:
        with self.lock:
            self.clients.pop(user_id, None)
            self.peers.pop(user_id, None)

    def get_session(self, user_id: str) -> Optional["ClientSession"]:
        with self.lock:
            return self.clients.get(user_id)

    def prune(self) -> None:
        t = now_ts()
        dead: List[str] = []
        with self.lock:
            for uid, rec in list(self.peers.items()):
                if (t - rec.last_seen) > STALE_S:
                    dead.append(uid)

            # prune lighthouses too
            for k, lh in list(self.lighthouses.items()):
                if (t - float(lh.last_seen)) > STALE_S:
                    self.lighthouses.pop(k, None)

        for uid in dead:
            sess = self.get_session(uid)
            if sess:
                try:
                    sess.close()
                except Exception:
                    pass
            self.remove(uid)

    def broadcast_peer_lists(self) -> None:
        """
        IMPORTANT:
        - Don't hold STATE.lock while doing socket I/O.
        - Avoid calling list_lighthouses() while holding a non-reentrant lock.
        """
        t = now_ts()

        with self.lock:
            if (t - self._last_peerlist_bcast) < PEERLIST_INTERVAL_S:
                return
            self._last_peerlist_bcast = t

            peers_snapshot = list(self.peers.values())
            clients_snapshot = list(self.clients.items())  # (uid, session)

        # Build room -> list[dict] outside the lock
        room_map: Dict[str, List[Dict[str, Any]]] = {}
        uid_to_room: Dict[str, str] = {}
        for rec in peers_snapshot:
            # Normalize to lower case for grouping keys
            room_key = rec.room.strip().lower()
            uid_to_room[rec.user_id] = room_key

            p_dict = asdict(rec)
            # We don't need to send relay_via internal field to clients usually,
            # but it doesn't hurt.
            room_map.setdefault(room_key, []).append(p_dict)

        # Safe: list_lighthouses() uses the lock internally
        lighthouses = self.list_lighthouses()

        sends: List[Tuple[str, "ClientSession", Dict[str, Any]]] = []
        for uid, sess in clients_snapshot:
            room = uid_to_room.get(uid)
            if not room:
                continue

            peers = [p for p in room_map.get(room, []) if str(p.get("user_id")) != uid]

            sends.append((
                uid,
                sess,
                {
                    "t": "peer_list",
                    "ts": t,
                    "room": room,
                    "peers": peers,
                    "lighthouses": lighthouses,
                },
            ))

        for uid, sess, payload in sends:
            try:
                sess.send(payload)
            except Exception:
                try:
                    sess.close()
                except Exception:
                    pass
                self.remove(uid)

    def broadcast_room(self, room: str, obj: Dict[str, Any], *, exclude_user_id: str = "") -> None:
        # Normalize room names to ensure matches
        room = _safe_str(room or "general", 64).lower()
        ex = _safe_str(exclude_user_id or "", 128)

        # 1. Gather targets safely under lock
        targets: List["ClientSession"] = []
        with self.lock:
            # Create a snapshot of items to iterate safely
            for uid, sess in list(self.clients.items()):
                if ex and uid == ex:
                    continue

                rec = self.peers.get(uid)
                # CRITICAL FIX: Ensure we compare lower() to lower()
                if rec and rec.room.lower() == room:
                    targets.append(sess)

        # 2. Send to targets (outside lock to prevent deadlocks)
        for sess in targets:
            try:
                sess.send(obj)
            except Exception:
                # If a client is dead, close it and clean up
                try:
                    sess.close()
                except Exception:
                    pass
                if sess.user_id:
                    self.remove(sess.user_id)


STATE = LighthouseState()


class ClientSession(threading.Thread):
    def __init__(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.conn.settimeout(1.0)
        self.buf = bytearray()
        self.user_id: str = ""
        self._send_lock = threading.Lock()
        self._closed = threading.Event()

        # relay file in-flight accounting (req_id -> bytes_forwarded)
        self._file_bytes: Dict[str, int] = {}

    def close(self) -> None:
        self._closed.set()
        try:
            self.conn.close()
        except Exception:
            pass

    def send(self, obj: Dict[str, Any]) -> None:
        with self._send_lock:
            _send_json(self.conn, obj)

    def run(self) -> None:
        try:
            while not self._closed.is_set():
                msg = _read_json_line(self.conn, self.buf)

                if msg is None:
                    break  # disconnect / fatal
                if not msg:
                    continue  # timeout / no full line yet

                t = msg.get("t")

                if t == "hello":
                    if TOKEN:
                        tok = _safe_str(msg.get("token") or "", 256)
                        if tok != TOKEN:
                            self.send({"t": "err", "code": "bad_token"})
                            self.close()
                            return

                    uid = _safe_str(msg.get("user_id") or "", 128)
                    if not uid:
                        self.send({"t": "err", "code": "missing_user_id"})
                        self.close()
                        return

                    self.user_id = uid
                    rec = PeerRecord(
                        user_id=uid,
                        name=_safe_str(msg.get("name") or "unknown", 64),
                        room=_safe_str(msg.get("room") or "general", 64),
                        avatar_sha=_safe_str(msg.get("avatar_sha") or "", 128),
                        wallet_addr=_safe_str(msg.get("wallet_addr") or "", 128),
                        last_seen=now_ts(),
                        ip=self.addr[0],
                        tcp_port=_safe_int(msg.get("tcp_port"), 0, 65535, 0),
                    )
                    STATE.upsert_peer(rec, self)
                    # --- NEW: if this client is advertising itself as a lighthouse, record its PUBLIC endpoint ---
                    lh_port = _safe_int(msg.get("lighthouse_port") or msg.get("lh_port") or 0, 0, 65535, 0)
                    is_lh = bool(msg.get("is_lighthouse")) or (
                                _safe_str(msg.get("role") or "", 32).lower() == "lighthouse")
                    if (is_lh or lh_port > 0) and lh_port > 0:
                        # addr[0] is the public IP as seen by this server (NAT external IP)
                        STATE.upsert_lighthouse(self.addr[0], lh_port, uid, now_ts())
                    continue

                if t == "room_broadcast":
                    if not self.user_id:
                        continue

                    inner = msg.get("msg")
                    if not isinstance(inner, dict):
                        continue

                    inner_t = _safe_str(inner.get("t") or "", 32)
                    if inner_t not in ("public_chat", "room_file_offer", "ledger_tip"):
                        continue

                    with STATE.lock:
                        rec = STATE.peers.get(self.user_id)
                    if not rec:
                        continue

                    room = rec.room
                    inner2 = dict(inner)
                    inner2["v"] = 1
                    inner2["room"] = room
                    inner2["from_user_id"] = self.user_id
                    inner2["from_name"] = rec.name
                    inner2["avatar_sha"] = rec.avatar_sha

                    mid = _safe_str(inner2.get("msg_id") or "", 128)
                    if not mid:
                        inner2["msg_id"] = uuid.uuid4().hex

                    try:
                        if len(json.dumps(inner2, ensure_ascii=False)) > 64_000:
                            continue
                    except Exception:
                        continue

                    payload = {
                        "t": "room_broadcast",
                        "from": self.user_id,
                        "room": room,
                        "msg": inner2,
                        "ts": now_ts(),
                    }
                    # NOTE: sender is excluded by design
                    STATE.broadcast_room(room, payload, exclude_user_id=self.user_id)
                    continue

                if t == "ping":
                    if self.user_id and self.user_id in STATE.peers:
                        with STATE.lock:
                            STATE.peers[self.user_id].last_seen = now_ts()
                    continue

                if t == "relay":
                    to_uid = _safe_str(msg.get("to") or "", 128)
                    kind = _safe_str(msg.get("kind") or "", 32)
                    payload = msg.get("msg")
                    if not to_uid or not kind or not isinstance(payload, dict):
                        continue

                    dst = STATE.get_session(to_uid)
                    if not dst:
                        self.send({"t": "relay_nack", "to": to_uid, "kind": kind, "code": "offline"})
                        continue

                    dst.send({"t": "relay", "kind": kind, "from": self.user_id, "msg": payload, "ts": now_ts()})
                    continue

                if t == "relay_file_get":
                    to_uid = _safe_str(msg.get("to") or "", 128)        # sender user_id
                    req_id = _safe_str(msg.get("req_id") or "", 64)
                    file_id = _safe_str(msg.get("file_id") or "", 1024)
                    if not to_uid or not req_id or not file_id:
                        continue

                    dst = STATE.get_session(to_uid)
                    if not dst:
                        self.send({"t": "relay_file_error", "req_id": req_id, "code": "offline"})
                        continue

                    dst.send({"t": "relay_file_get", "from": self.user_id, "req_id": req_id, "file_id": file_id, "ts": now_ts()})
                    continue

                if t in (
                "relay_file_begin", "relay_file_chunk", "relay_file_end", "relay_file_fail", "relay_file_error"):
                    to_uid = _safe_str(msg.get("to") or "", 128)
                    req_id = _safe_str(msg.get("req_id") or "", 64)
                    if not to_uid or not req_id:
                        continue

                    dst = STATE.get_session(to_uid)
                    if not dst:
                        continue

                    key = f"{req_id}|{to_uid}"

                    if t == "relay_file_begin":
                        self._file_bytes[key] = 0

                    if t == "relay_file_chunk":
                        b64 = msg.get("b64")
                        if not isinstance(b64, str):
                            continue
                        if len(b64) > MAX_CHUNK_B64:
                            continue

                        prev = self._file_bytes.get(key, 0)
                        approx = int(len(b64) * 3 / 4)
                        nxt = prev + approx
                        if nxt > MAX_RELAY_FILE_BYTES:
                            try:
                                dst.send({"t": "relay_file_error", "req_id": req_id, "code": "too_large"})
                            except Exception:
                                pass
                            self._file_bytes.pop(key, None)
                            continue
                        self._file_bytes[key] = nxt

                    if t in ("relay_file_end", "relay_file_fail", "relay_file_error"):
                        self._file_bytes.pop(key, None)

                    fwd = dict(msg)

                    # Normalize older naming so receivers always get relay_file_error
                    if t == "relay_file_fail":
                        fwd["t"] = "relay_file_error"
                        fwd.setdefault("code", _safe_str(msg.get("code") or msg.get("reason") or "fail", 64))

                    fwd["from"] = self.user_id
                    dst.send(fwd)
                    continue

                    if t in ("relay_file_end", "relay_file_fail"):
                        self._file_bytes.pop(req_id, None)

                    fwd = dict(msg)
                    # Normalize older names so receivers always get relay_file_error
                    if t in ("relay_file_fail",):
                        msg = dict(msg)
                        msg["t"] = "relay_file_error"
                        if "code" not in msg:
                            msg["code"] = _safe_str(msg.get("code") or msg.get("reason") or "fail", 64)
                    fwd["from"] = self.user_id
                    dst.send(fwd)
                    continue

        except Exception:
            pass
        finally:
            if self.user_id:
                STATE.remove(self.user_id)
            try:
                self.conn.close()
            except Exception:
                pass


class Housekeeper(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)

    def run(self) -> None:
        while True:
            try:
                STATE.prune()
                STATE.broadcast_peer_lists()
            except Exception:
                pass
            time.sleep(0.25)


class LighthouseServer(threading.Thread):
    def __init__(self, host: str = "0.0.0.0", port: int = 38888) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = int(port)
        self._stop_evt = threading.Event()
        self._srv: Optional[socket.socket] = None

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass

    def run(self) -> None:
        hk = Housekeeper()
        hk.start()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, int(self.port)))
        srv.listen(256)
        srv.settimeout(0.5)
        self._srv = srv

        print(
            f"[lighthouse] listening on {self.host}:{self.port} "
            f"token={'ON' if TOKEN else 'OFF'} "
            f"max_file_mb={MAX_RELAY_FILE_BYTES/1024/1024:.0f}"
        )

        while not self._stop_evt.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ClientSession(conn, addr).start()

        try:
            srv.close()
        except Exception:
            pass


def serve(host: str = "0.0.0.0", port: int = 38888) -> None:
    s = LighthouseServer(host, port)
    s.start()
    s.join()


if __name__ == "__main__":
    host = os.environ.get("LIGHTHOUSE_HOST", "0.0.0.0")
    port = int(os.environ.get("LIGHTHOUSE_PORT", "38888"))
    serve(host, port)
