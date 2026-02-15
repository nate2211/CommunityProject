from __future__ import annotations

"""
P2PService (LAN-only) — hardened for safety + multi-instance friendliness.

Key safety goals:
- Router/Wi-Fi friendly: throttle multicast presence; avoid accidental packet storms.
- CPU friendly: avoid 1-byte recv loops; cap inbound sizes; avoid “json bombs”.
- Safer file serving: cap max file bytes served; only serve explicitly shared file_ids.
- Multi-instance: supports multiple instances on same host; each instance binds TCP on port=0.

IMPORTANT REAL-WORLD SAFETY NOTE:
- This is NOT encrypted/authenticated. Treat it as "local LAN convenience", not a secure messenger.
- Do NOT expose the TCP port to the internet. Keep it behind your router/firewall.
"""

import dataclasses
import hashlib
import json
import os
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from moderation import ModerationState
from utils import sha256_text, sha256_file


# ---------------- Defaults ----------------
DEFAULT_GROUP = "239.7.7.7"
DEFAULT_PORT = 37777
DEFAULT_TTL = 1

# ---------------- Hard safety limits ----------------
MAX_UDP_BYTES = 64_000               # drop multicast packets larger than this
MAX_TCP_LINE_BYTES = 128_000         # max JSON line for dm/tx/offer requests
MAX_BLOB_SEND_BYTES = 256 * 1024**2  # 256MB max file/avatar served (safety)
TCP_CONNECT_TIMEOUT = 6.0
TCP_READ_TIMEOUT = 12.0
TCP_ACCEPT_TIMEOUT = 0.5

# ---------------- Rate limits (router friendly) ----------------
PRESENCE_MIN_INTERVAL_S = 5.0        # presence multicast at most every 5s per instance
PUBLIC_CHAT_MIN_INTERVAL_S = 0.10    # prevents accidental UI loops spamming multicast
LEDGER_TIP_MIN_INTERVAL_S = 2.0   # multicast at most every 2s (extra safe)
# Optional: allow disabling multicast entirely (DM still works if you know peer IP/port)
# Set env var: P2P_DISABLE_MCAST=1
DISABLE_MCAST = str(os.environ.get("P2P_DISABLE_MCAST") or "").strip().lower() in ("1", "true", "yes")


def now_ts() -> float:
    return time.time()


def _clamp_int(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        x = int(v)
    except Exception:
        return default
    return max(lo, min(hi, x))


def _safe_str(v: Any, max_len: int = 256) -> str:
    s = str(v) if v is not None else ""
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _safe_json_loads(raw: bytes, *, max_bytes: int) -> Optional[Dict[str, Any]]:
    if not raw or len(raw) > max_bytes:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def mcast_socket(group: str, port: int, ttl: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # best-effort reuseport for unix-likes (helps multi-instance listeners)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
    except Exception:
        pass

    # Bind: try wildcard first (most compatible), then group bind fallback.
    try:
        s.bind(("", int(port)))
    except OSError:
        s.bind((group, int(port)))

    # Join multicast group (LAN scope only)
    # Use "=4s4s" to avoid platform-dependent "long" size issues.
    mreq = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton("0.0.0.0"))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(ttl))
    return s


def mcast_send(group: str, port: int, ttl: int, msg: Dict[str, Any]) -> None:
    if DISABLE_MCAST:
        return
    data = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_UDP_BYTES:
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(ttl))
        s.sendto(data, (group, int(port)))
    finally:
        try:
            s.close()
        except Exception:
            pass


def tcp_send_json(ip: str, port: int, obj: Dict[str, Any], timeout: float = TCP_CONNECT_TIMEOUT) -> None:
    data = (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_TCP_LINE_BYTES:
        raise RuntimeError("tcp_send_json: message too large")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(float(timeout))
        sock.connect((ip, int(port)))
        sock.sendall(data)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def tcp_request_blob(ip: str, port: int, req: Dict[str, Any], save_path: str, expected_sha256: str = "") -> int:
    data = (json.dumps(req, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_TCP_LINE_BYTES:
        raise RuntimeError("tcp_request_blob: request too large")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(TCP_READ_TIMEOUT))
    sock.connect((ip, int(port)))
    sock.sendall(data)

    # Read 8-byte big-endian size header
    hdr = b""
    while len(hdr) < 8:
        chunk = sock.recv(8 - len(hdr))
        if not chunk:
            sock.close()
            raise RuntimeError("No header (connection closed).")
        hdr += chunk

    size = int.from_bytes(hdr, "big")
    if size <= 0:
        sock.close()
        raise RuntimeError("No data (size=0).")
    if size > MAX_BLOB_SEND_BYTES:
        sock.close()
        raise RuntimeError("Blob too large (safety cap).")

    h = hashlib.sha256()
    received = 0

    Path(save_path).resolve().parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f:
        while received < size:
            b = sock.recv(min(1024 * 1024, size - received))
            if not b:
                break
            f.write(b)
            h.update(b)
            received += len(b)

    sock.close()

    if received != size:
        raise RuntimeError(f"Incomplete download: {received}/{size}")

    got = h.hexdigest()
    if expected_sha256 and got.lower() != expected_sha256.lower():
        raise RuntimeError("SHA256 mismatch.")
    return received


# ---------------- Data Models ----------------
@dataclass
class PeerInfo:
    user_id: str
    name: str
    ip: str
    tcp_port: int
    room: str
    avatar_sha: str
    last_seen: float
    wallet_addr: str = ""   # NEW


class PeerDirectory:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._peers: Dict[str, PeerInfo] = {}

    def update(self, p: PeerInfo) -> None:
        # small sanity guards
        if not p.user_id or p.tcp_port <= 0 or p.tcp_port > 65535:
            return
        with self._lock:
            # cap number of peers (prevents growth from spam)
            if len(self._peers) > 2048:
                self._prune_locked(older_than_s=10.0)
                if len(self._peers) > 2048:
                    # drop update if still too large
                    return
            self._peers[p.user_id] = p

    def list(self) -> List[PeerInfo]:
        with self._lock:
            return list(self._peers.values())

    def get(self, user_id: str) -> Optional[PeerInfo]:
        with self._lock:
            return self._peers.get(user_id)

    def _prune_locked(self, older_than_s: float) -> None:
        t = now_ts()
        dead = [uid for uid, p in self._peers.items() if (t - p.last_seen) > older_than_s]
        for uid in dead:
            self._peers.pop(uid, None)

    def prune(self, older_than_s: float = 25.0) -> None:
        with self._lock:
            self._prune_locked(float(older_than_s))


@dataclass
class FileOffer:
    offer_id: str
    scope: str          # "room" or "dm" or "tx"
    room: str
    from_user_id: str
    from_name: str
    from_ip: str
    from_tcp_port: int

    # NEW: exact file_id registered on sender (do NOT reconstruct)
    file_id: str = ""

    filename: str = ""
    size: int = 0
    sha256: str = ""
    note: str = ""

# ---------------- TCP Server ----------------
class TcpServer(threading.Thread):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        on_dm: Callable[[Dict[str, Any], Tuple[str, int]], None],
        on_dm_file_offer: Callable[[Dict[str, Any], Tuple[str, int]], None],
        on_tx_push: Callable[[Dict[str, Any], Tuple[str, int]], None],
        get_file_path: Callable[[str], Optional[str]],
        get_avatar_path: Callable[[], Optional[str]],
    ) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = int(port)
        self.on_dm = on_dm
        self.on_dm_file_offer = on_dm_file_offer
        self.on_tx_push = on_tx_push
        self.get_file_path = get_file_path
        self.get_avatar_path = get_avatar_path
        self._stop = threading.Event()
        self.bound_port: Optional[int] = None
        self._sock: Optional[socket.socket] = None

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _read_json_line(self, conn: socket.socket) -> Optional[Dict[str, Any]]:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > MAX_TCP_LINE_BYTES:
                return None
        line = buf.split(b"\n", 1)[0]
        return _safe_json_loads(line, max_bytes=MAX_TCP_LINE_BYTES)

    def _send_blob_path(self, conn: socket.socket, path: str) -> None:
        if not path or not os.path.exists(path):
            conn.sendall((0).to_bytes(8, "big"))
            return
        size = int(os.path.getsize(path))
        if size <= 0 or size > MAX_BLOB_SEND_BYTES:
            conn.sendall((0).to_bytes(8, "big"))
            return

        conn.sendall(int(size).to_bytes(8, "big"))
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                conn.sendall(chunk)

    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind + listen
        srv.bind((self.host, self.port))
        srv.listen(16)
        srv.settimeout(float(TCP_ACCEPT_TIMEOUT))

        self._sock = srv
        self.bound_port = int(srv.getsockname()[1])

        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                conn.settimeout(8.0)
                msg = self._read_json_line(conn)
                if not msg:
                    conn.close()
                    continue

                t = msg.get("t")

                if t == "dm":
                    self.on_dm(msg, addr)
                    conn.close()
                    continue

                if t == "dm_file_offer":
                    self.on_dm_file_offer(msg, addr)
                    conn.close()
                    continue

                if t == "tx_push":
                    self.on_tx_push(msg, addr)
                    conn.close()
                    continue

                if t == "file_get":
                    file_id = _safe_str(msg.get("file_id"), 1024)
                    path = self.get_file_path(file_id)
                    self._send_blob_path(conn, path or "")
                    conn.close()
                    continue

                if t == "avatar_get":
                    ap = self.get_avatar_path()
                    self._send_blob_path(conn, ap or "")
                    conn.close()
                    continue

                conn.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass


# ---------------- UDP Listener ----------------
class UdpListener(threading.Thread):
    def __init__(self, group: str, port: int, ttl: int, *, on_message: Callable[[Dict[str, Any], str], None]) -> None:
        super().__init__(daemon=True)
        self.group = group
        self.port = int(port)
        self.ttl = int(ttl)
        self.on_message = on_message
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def run(self) -> None:
        s = mcast_socket(self.group, self.port, self.ttl)
        s.settimeout(0.5)
        self._sock = s
        while not self._stop.is_set():
            try:
                raw, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            if not raw or len(raw) > MAX_UDP_BYTES:
                continue

            ip = addr[0]
            msg = _safe_json_loads(raw, max_bytes=MAX_UDP_BYTES)
            if not msg:
                continue

            self.on_message(msg, ip)


# ---------------- Identity / Service ----------------
@dataclass
class Identity:
    user_id: str
    name: str
    avatar_path: str
    wallet_addr: str = ""   # NEW

class P2PService:
    def __init__(self, moderation: ModerationState) -> None:
        self.group = DEFAULT_GROUP
        self.port = DEFAULT_PORT
        self.ttl = DEFAULT_TTL

        self.moderation = moderation
        self.identity = Identity(user_id="", name="anon", avatar_path="")
        self.room = "general"

        self.peers = PeerDirectory()
        self._shared_files: Dict[str, str] = {}  # file_id -> path

        self._q_room_msgs: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._q_dm_msgs: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._q_room_offers: "queue.Queue[FileOffer]" = queue.Queue()
        self._q_dm_offers: "queue.Queue[FileOffer]" = queue.Queue()
        self._q_tx_msgs: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        self._udp: Optional[UdpListener] = None
        self._tcp: Optional[TcpServer] = None

        self._q_ledger_tips: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._last_ledger_tip_ts: float = 0.0
        self.ledger_tip_min_interval_s: float = LEDGER_TIP_MIN_INTERVAL_S

        # throttles
        self._last_presence_ts: float = 0.0
        self._last_public_ts: float = 0.0
        self.presence_min_interval_s: float = PRESENCE_MIN_INTERVAL_S
        self.public_chat_min_interval_s: float = PUBLIC_CHAT_MIN_INTERVAL_S

    def start(self) -> None:
        if self._tcp is None:
            self._tcp = TcpServer(
                host="0.0.0.0",
                port=0,
                on_dm=self._handle_dm,
                on_dm_file_offer=self._handle_dm_file_offer_tcp,
                on_tx_push=self._handle_tx_push_tcp,
                get_file_path=self._get_shared_file_path,
                get_avatar_path=self._get_avatar_path,
            )
            self._tcp.start()

            # wait briefly for bound_port
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if self._tcp.bound_port:
                    break
                time.sleep(0.01)

        if self._udp is None and not DISABLE_MCAST:
            self._udp = UdpListener(self.group, self.port, self.ttl, on_message=self._handle_udp)
            self._udp.start()

    def stop(self) -> None:
        if self._udp:
            self._udp.stop()
            self._udp = None
        if self._tcp:
            self._tcp.stop()
            self._tcp = None

    @property
    def tcp_port(self) -> int:
        return int(self._tcp.bound_port or 0) if self._tcp else 0

    def set_identity(self, user_id: str, name: str, avatar_path: str, wallet_addr: str = "") -> None:
        self.identity = Identity(user_id=user_id, name=name, avatar_path=avatar_path, wallet_addr=wallet_addr)

    def set_room(self, room: str) -> None:
        self.room = (_safe_str(room, 64) or "general")

    def avatar_sha(self) -> str:
        ap = self.identity.avatar_path
        if ap and os.path.exists(ap):
            try:
                return sha256_file(ap)
            except Exception:
                return ""
        return ""

    def broadcast_presence(self) -> None:
        if DISABLE_MCAST:
            return

        t = now_ts()
        if (t - self._last_presence_ts) < float(self.presence_min_interval_s):
            return
        self._last_presence_ts = t

        msg = {
            "v": 1,
            "t": "presence",
            "ts": t,
            "user_id": self.identity.user_id,
            "name": self.identity.name,
            "room": self.room,
            "tcp_port": self.tcp_port,
            "avatar_sha": self.avatar_sha(),
            "wallet_addr": self.identity.wallet_addr,
        }
        mcast_send(self.group, self.port, self.ttl, msg)

    def send_public_text(self, text: str) -> None:
        if DISABLE_MCAST:
            return

        # prevent accidental UI loops spamming multicast
        t = now_ts()
        if (t - self._last_public_ts) < float(self.public_chat_min_interval_s):
            return
        self._last_public_ts = t

        msg = {
            "v": 1,
            "t": "public_chat",
            "ts": t,
            "room": self.room,
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "avatar_sha": self.avatar_sha(),
            "text": _safe_str(text, 4000),
        }
        mcast_send(self.group, self.port, self.ttl, msg)

    def send_dm_text(self, peer: PeerInfo, text: str) -> None:
        obj = {
            "t": "dm",
            "ts": now_ts(),
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "avatar_sha": self.avatar_sha(),
            "text": _safe_str(text, 4000),
        }
        tcp_send_json(peer.ip, peer.tcp_port, obj)

    def push_tx_to_peer(self, peer: PeerInfo, tx_wire: str, *, ledger_tip: Optional[Dict[str, Any]] = None) -> None:
        obj: Dict[str, Any] = {
            "t": "tx_push",
            "ts": now_ts(),
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "from_tcp_port": self.tcp_port,  # lets receiver fetch attachments/ledger from sender
            "tx_wire": _safe_str(tx_wire, 120_000),
        }
        if isinstance(ledger_tip, dict) and ledger_tip:
            # keep it small + safe
            obj["ledger_tip"] = {
                "file_id": _safe_str(ledger_tip.get("file_id") or "", 1024),
                "sha256": _safe_str(ledger_tip.get("sha256") or "", 128),
                "size": _clamp_int(ledger_tip.get("size"), 0, MAX_BLOB_SEND_BYTES, 0),
                "filename": _safe_str(ledger_tip.get("filename") or "ledger.json", 256),
                "height": _clamp_int(ledger_tip.get("height"), 0, 10_000_000, 0),
                "tip_hash": _safe_str(ledger_tip.get("tip_hash") or "", 128),
            }

        tcp_send_json(peer.ip, peer.tcp_port, obj)

    def share_file_to_room(self, path: str, note: str = "", scope: str = "room") -> FileOffer:
        path = str(Path(path).resolve())
        size = int(os.path.getsize(path))
        if size <= 0 or size > MAX_BLOB_SEND_BYTES:
            raise RuntimeError("file_too_large_or_empty")

        digest = sha256_file(path)
        file_id = f"{digest}:{size}:{os.path.basename(path)}"
        self._shared_files[file_id] = path

        offer = FileOffer(
            offer_id=sha256_text(f"room_offer|{self.identity.user_id}|{now_ts():.6f}|{file_id}"),
            scope=_safe_str(scope, 16) or "room",
            room=self.room,
            from_user_id=self.identity.user_id,
            from_name=self.identity.name,
            from_ip="",
            from_tcp_port=self.tcp_port,
            file_id=file_id,  # IMPORTANT
            filename=os.path.basename(path),
            size=size,
            sha256=digest,
            note=_safe_str(note, 512),
        )

        msg = {
            "v": 1,
            "t": "room_file_offer",
            "ts": now_ts(),
            "room": self.room,
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "tcp_port": self.tcp_port,
            "avatar_sha": self.avatar_sha(),
            "scope": offer.scope,

            # IMPORTANT: include explicit file_id so receivers never guess
            "file_id": file_id,
            "file": {"name": offer.filename, "size": offer.size, "sha256": offer.sha256, "file_id": file_id},

            "note": offer.note,
        }
        mcast_send(self.group, self.port, self.ttl, msg)
        return offer

    def share_file_dm(self, peer: PeerInfo, path: str, note: str = "", scope: str = "dm") -> FileOffer:
        path = str(Path(path).resolve())
        size = int(os.path.getsize(path))
        if size <= 0 or size > MAX_BLOB_SEND_BYTES:
            raise RuntimeError("file_too_large_or_empty")

        digest = sha256_file(path)
        file_id = f"{digest}:{size}:{os.path.basename(path)}"
        self._shared_files[file_id] = path

        offer = FileOffer(
            offer_id=sha256_text(f"{scope}|{self.identity.user_id}|{peer.user_id}|{now_ts():.6f}|{file_id}"),
            scope=_safe_str(scope, 16) or "dm",
            room="",
            from_user_id=self.identity.user_id,
            from_name=self.identity.name,
            from_ip="",
            from_tcp_port=self.tcp_port,
            file_id=file_id,  # IMPORTANT
            filename=os.path.basename(path),
            size=size,
            sha256=digest,
            note=_safe_str(note, 512),
        )

        obj = {
            "t": "dm_file_offer",
            "ts": now_ts(),
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "from_tcp_port": self.tcp_port,
            "avatar_sha": self.avatar_sha(),
            "scope": offer.scope,

            # IMPORTANT
            "file_id": file_id,
            "file": {"name": offer.filename, "size": offer.size, "sha256": offer.sha256, "file_id": file_id},

            "note": offer.note,
        }
        tcp_send_json(peer.ip, peer.tcp_port, obj)
        return offer

    def download_offer(self, offer: FileOffer, save_path: str) -> int:
        ok, reason = self.moderation.file_check_metadata(
            filename=_safe_str(offer.filename, 512),
            size=int(offer.size),
            sha256hex=_safe_str(offer.sha256, 128),
        )
        if not ok:
            raise RuntimeError(f"blocked_before_download:{reason}")

        # IMPORTANT: use explicit file_id when provided (tx attachments / sanitized names)
        file_id = str(getattr(offer, "file_id", "") or "").strip()
        if not file_id:
            file_id = f"{offer.sha256}:{offer.size}:{offer.filename}"

        req = {"t": "file_get", "file_id": file_id}
        n = tcp_request_blob(offer.from_ip, offer.from_tcp_port, req, save_path, expected_sha256=offer.sha256)

        ok2, reason2 = self.moderation.file_check_path(path=save_path)
        if not ok2:
            try:
                os.unlink(save_path)
            except Exception:
                pass
            raise RuntimeError(f"blocked_after_download:{reason2}")

        return n

    def pop_room_messages(self, max_n: int = 200) -> List[Dict[str, Any]]:
        out = []
        for _ in range(int(max_n)):
            try:
                out.append(self._q_room_msgs.get_nowait())
            except queue.Empty:
                break
        return out

    def pop_dm_messages(self, max_n: int = 200) -> List[Dict[str, Any]]:
        out = []
        for _ in range(int(max_n)):
            try:
                out.append(self._q_dm_msgs.get_nowait())
            except queue.Empty:
                break
        return out

    def pop_room_offers(self, max_n: int = 200) -> List[FileOffer]:
        out: List[FileOffer] = []
        for _ in range(int(max_n)):
            try:
                out.append(self._q_room_offers.get_nowait())
            except queue.Empty:
                break
        return out

    def pop_dm_offers(self, max_n: int = 200) -> List[FileOffer]:
        out: List[FileOffer] = []
        for _ in range(int(max_n)):
            try:
                out.append(self._q_dm_offers.get_nowait())
            except queue.Empty:
                break
        return out

    def pop_tx_msgs(self, max_n: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(int(max_n)):
            try:
                out.append(self._q_tx_msgs.get_nowait())
            except queue.Empty:
                break
        return out

    # ---------------- internals ----------------
    def _get_avatar_path(self) -> Optional[str]:
        ap = self.identity.avatar_path
        return ap if ap and os.path.exists(ap) else None

    def _get_shared_file_path(self, file_id: str) -> Optional[str]:
        # Only serve files explicitly shared by THIS instance.
        p = self._shared_files.get(str(file_id))
        if not p:
            return None
        return p if os.path.exists(p) else None

    def _handle_dm(self, msg: Dict[str, Any], addr: Tuple[str, int]) -> None:
        from_uid = _safe_str(msg.get("from_user_id") or "remote", 128)
        text = _safe_str(msg.get("text") or "", 4000)
        ok, cleaned, _ = self.moderation.chat_check(user_id=from_uid, text=text)
        if not ok:
            return
        msg["from_user_id"] = from_uid
        msg["from_name"] = _safe_str(msg.get("from_name") or "unknown", 64)
        msg["text"] = cleaned
        msg["_src_ip"] = addr[0]
        self._q_dm_msgs.put(msg)

    def _handle_tx_push_tcp(self, msg: Dict[str, Any], addr: Tuple[str, int]) -> None:
        from_uid = _safe_str(msg.get("from_user_id") or "remote", 128)
        wire = _safe_str(msg.get("tx_wire") or "", 120_000)
        ok, cleaned, _ = self.moderation.chat_check(user_id=from_uid, text=wire)
        if not ok:
            return

        msg["from_user_id"] = from_uid
        msg["from_name"] = _safe_str(msg.get("from_name") or "unknown", 64)
        msg["from_tcp_port"] = _clamp_int(msg.get("from_tcp_port"), 1, 65535, 0)
        msg["tx_wire"] = cleaned
        msg["_src_ip"] = addr[0]

        tip = msg.get("ledger_tip")
        if isinstance(tip, dict):
            msg["ledger_tip"] = {
                "file_id": _safe_str(tip.get("file_id") or "", 1024),
                "sha256": _safe_str(tip.get("sha256") or "", 128),
                "size": _clamp_int(tip.get("size"), 0, MAX_BLOB_SEND_BYTES, 0),
                "filename": _safe_str(tip.get("filename") or "ledger.json", 256),
                "height": _clamp_int(tip.get("height"), 0, 10_000_000, 0),
                "tip_hash": _safe_str(tip.get("tip_hash") or "", 128),
            }

        self._q_tx_msgs.put(msg)

    def _handle_dm_file_offer_tcp(self, msg: Dict[str, Any], addr: Tuple[str, int]) -> None:
        ip = addr[0]
        f = msg.get("file") or {}
        name = _safe_str(f.get("name") or "file", 512)
        size = _clamp_int(f.get("size"), 0, MAX_BLOB_SEND_BYTES, 0)
        digest = _safe_str(f.get("sha256") or "", 128)
        note = _safe_str(msg.get("note") or "", 512)
        scope = _safe_str(msg.get("scope") or "dm", 16)

        if size <= 0 or not digest:
            return

        ok, _ = self.moderation.file_check_metadata(filename=name, size=size, sha256hex=digest)
        if not ok:
            return

        incoming_file_id = _safe_str(msg.get("file_id") or (f.get("file_id") if isinstance(f, dict) else "") or "",
                                     1024).strip()
        if not incoming_file_id:
            incoming_file_id = f"{digest}:{size}:{name}"

        offer = FileOffer(
            offer_id=sha256_text(f"dm_offer|{ip}|{msg.get('ts')}|{incoming_file_id}"),
            scope=scope,
            room="",
            from_user_id=_safe_str(msg.get("from_user_id") or "", 128),
            from_name=_safe_str(msg.get("from_name") or "unknown", 64),
            from_ip=ip,
            from_tcp_port=_clamp_int(msg.get("from_tcp_port"), 1, 65535, 0),

            file_id=incoming_file_id,  # IMPORTANT

            filename=name,
            size=size,
            sha256=digest,
            note=note,
        )
        if offer.from_tcp_port <= 0:
            return
        self._q_dm_offers.put(offer)

    def _handle_udp(self, msg: Dict[str, Any], src_ip: str) -> None:
        if msg.get("v") != 1:
            return

        t = msg.get("t")

        if t == "presence":
            p = PeerInfo(
                user_id=str(msg.get("user_id") or ""),
                name=str(msg.get("name") or "unknown"),
                ip=src_ip,
                tcp_port=int(msg.get("tcp_port") or 0),
                room=str(msg.get("room") or "general"),
                avatar_sha=str(msg.get("avatar_sha") or ""),
                last_seen=now_ts(),
                wallet_addr=str(msg.get("wallet_addr") or ""),  # NEW
            )
            if not p.user_id or p.user_id == self.identity.user_id or p.tcp_port <= 0:
                return
            self.peers.update(p)
            return

        if t == "public_chat":
            if _safe_str(msg.get("room") or "", 64) != self.room:
                return
            from_uid = _safe_str(msg.get("from_user_id") or "remote", 128)
            text = _safe_str(msg.get("text") or "", 4000)
            ok, cleaned, _ = self.moderation.chat_check(user_id=from_uid, text=text)
            if not ok:
                return
            msg["from_user_id"] = from_uid
            msg["from_name"] = _safe_str(msg.get("from_name") or "unknown", 64)
            msg["text"] = cleaned
            msg["_src_ip"] = src_ip
            self._q_room_msgs.put(msg)
            return
        if t == "ledger_tip":
            if _safe_str(msg.get("room") or "", 64) != self.room:
                return

            from_uid = _safe_str(msg.get("from_user_id") or "", 128)
            if not from_uid or from_uid == self.identity.user_id:
                return

            # Optional extra safety: only accept tips from known peers
            if self.peers.get(from_uid) is None:
                return

            tip = {
                "from_user_id": from_uid,
                "from_name": _safe_str(msg.get("from_name") or "unknown", 64),
                "tcp_port": _clamp_int(msg.get("tcp_port"), 1, 65535, 0),
                "height": _clamp_int(msg.get("height"), 0, 10_000_000, 0),
                "tip_hash": _safe_str(msg.get("tip_hash") or "", 128),

                "file_id": _safe_str(msg.get("file_id") or "", 1024),
                "sha256": _safe_str(msg.get("sha256") or "", 128),
                "size": _clamp_int(msg.get("size"), 0, MAX_BLOB_SEND_BYTES, 0),
                "filename": _safe_str(msg.get("filename") or "ledger.json", 256),

                "_src_ip": src_ip,
            }
            if tip["tcp_port"] <= 0 or not tip["file_id"] or tip["size"] <= 0 or not tip["sha256"]:
                return

            self._q_ledger_tips.put(tip)
            return
        if t == "room_file_offer":
            if _safe_str(msg.get("room") or "", 64) != self.room:
                return

            f = msg.get("file") or {}
            name = _safe_str(f.get("name") or "file", 512)
            size = _clamp_int(f.get("size"), 0, MAX_BLOB_SEND_BYTES, 0)
            digest = _safe_str(f.get("sha256") or "", 128)
            note = _safe_str(msg.get("note") or "", 512)
            scope = _safe_str(msg.get("scope") or "room", 16)

            if size <= 0 or not digest:
                return

            ok, _ = self.moderation.file_check_metadata(filename=name, size=size, sha256hex=digest)
            if not ok:
                return

            incoming_file_id = _safe_str(msg.get("file_id") or (f.get("file_id") if isinstance(f, dict) else "") or "",
                                         1024).strip()
            if not incoming_file_id:
                incoming_file_id = f"{digest}:{size}:{name}"

            offer = FileOffer(
                offer_id=sha256_text(f"room_offer|{src_ip}|{msg.get('ts')}|{incoming_file_id}"),
                scope=scope,
                room=_safe_str(msg.get("room") or "general", 64),
                from_user_id=_safe_str(msg.get("from_user_id") or "", 128),
                from_name=_safe_str(msg.get("from_name") or "unknown", 64),
                from_ip=src_ip,
                from_tcp_port=_clamp_int(msg.get("tcp_port"), 1, 65535, 0),

                file_id=incoming_file_id,  # IMPORTANT

                filename=name,
                size=size,
                sha256=digest,
                note=note,
            )
            if offer.from_tcp_port <= 0:
                return
            self._q_room_offers.put(offer)
            return

    def register_shared_file(self, file_id: str, path: str) -> None:
        """
        Safely register a path for file_get serving.
        Used for normal user shares AND internal ledger sync.
        """
        path = str(Path(path).resolve())
        if not path or not os.path.exists(path):
            raise RuntimeError("register_shared_file: missing path")
        size = int(os.path.getsize(path))
        if size <= 0 or size > MAX_BLOB_SEND_BYTES:
            raise RuntimeError("register_shared_file: bad size")
        self._shared_files[str(file_id)] = path

    def broadcast_ledger_tip(self, *, file_id: str, sha256hex: str, size: int, filename: str, height: int,
                             tip_hash: str) -> None:
        """
        Multicast only a tiny hint that a newer ledger exists.
        Actual bytes are fetched over TCP via file_get (sha-verified).
        """
        if DISABLE_MCAST:
            return

        t = now_ts()
        if (t - self._last_ledger_tip_ts) < float(self.ledger_tip_min_interval_s):
            return
        self._last_ledger_tip_ts = t

        msg = {
            "v": 1,
            "t": "ledger_tip",
            "ts": t,
            "room": self.room,

            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "tcp_port": self.tcp_port,

            "height": int(height),
            "tip_hash": _safe_str(tip_hash, 128),

            "file_id": _safe_str(file_id, 1024),
            "sha256": _safe_str(sha256hex, 128),
            "size": _clamp_int(size, 0, MAX_BLOB_SEND_BYTES, 0),
            "filename": _safe_str(filename, 256),
        }
        mcast_send(self.group, self.port, self.ttl, msg)

    def pop_ledger_tips(self, max_n: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(int(max_n)):
            try:
                out.append(self._q_ledger_tips.get_nowait())
            except queue.Empty:
                break
        return out
