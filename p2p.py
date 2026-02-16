from __future__ import annotations

import uuid
import base64  # <-- ADD (needed for relay file chunks)
from dataclasses import dataclass, field  # <-- change/ensure field is include
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
import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from moderation import ModerationState
from utils import sha256_text, sha256_file

from lighthouse_client import LighthouseClient

# Relay file chunk sizing (raw bytes -> base64 <= lighthouse MAX_CHUNK_B64)
RELAY_CHUNK_RAW = 120_000  # ~160k base64 chars

# Auto-discovered lighthouse sharing
MAX_AUTO_LIGHTHOUSES = 5
AUTO_CONNECT_DISCOVERED_LIGHTHOUSES = True  # set False if you only want to store, not connect
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

# ---- Lighthouse defaults (AUTOJOIN, no user input needed) ----
DEFAULT_BOOTSTRAP_LIGHTHOUSES = [
    "170.253.163.90:38888",  # default public seed
]
def now_ts() -> float:
    return time.time()

def _default_iface_ip() -> str:
    # best-effort: picks the interface used for default route
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"
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

    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
    except Exception:
        pass

    try:
        s.bind(("", int(port)))
    except OSError:
        s.bind((group, int(port)))

    iface = (os.environ.get("P2P_MCAST_IF") or "").strip() or _default_iface_ip()
    mreq = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton(iface))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(ttl))
    return s


def mcast_send(group: str, port: int, ttl: int, msg: Dict[str, Any]) -> None:
    if DISABLE_MCAST:
        return
    data = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_UDP_BYTES:
        return

    iface = (os.environ.get("P2P_MCAST_IF") or "").strip() or _default_iface_ip()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(ttl))
        # force correct NIC
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))
        s.sendto(data, (group, int(port)))
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(data, ("255.255.255.255", int(port)))
        except Exception:
            pass
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
    wallet_addr: str = ""
    relay_via: List[str] = field(default_factory=list)

class PeerDirectory:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._peers: Dict[str, PeerInfo] = {}

    def update(self, p: PeerInfo) -> None:
        if not p.user_id:
            return
        if p.tcp_port < 0 or p.tcp_port > 65535:
            return
        # allow relay-only peers to have tcp_port=0
        if p.tcp_port == 0 and p.ip != "relay":
            return

        with self._lock:
            if len(self._peers) > 2048:
                self._prune_locked(older_than_s=10.0)
                if len(self._peers) > 2048:
                    return

            old = self._peers.get(p.user_id)
            if old:
                old_via = set(getattr(old, "relay_via", []) or [])
                new_via = set(getattr(p, "relay_via", []) or [])
                merged_via = sorted(old_via | new_via)

                if old.ip != "relay" and p.ip == "relay":
                    p.ip = old.ip
                    p.tcp_port = old.tcp_port

                p.last_seen = max(float(old.last_seen), float(p.last_seen))

                if not p.avatar_sha:
                    p.avatar_sha = old.avatar_sha
                if not p.wallet_addr:
                    p.wallet_addr = old.wallet_addr
                if not p.name or p.name == "unknown":
                    p.name = old.name

                p.relay_via = merged_via

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
    scope: str
    room: str
    from_user_id: str
    from_name: str
    from_ip: str
    from_tcp_port: int

    file_id: str = ""
    filename: str = ""
    size: int = 0
    sha256: str = ""
    note: str = ""

    # NEW: which lighthouse delivered this offer (helps route relay downloads)
    relay_via: str = ""
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
        # ---- lighthouse (cross-router) ----
        self._lh_token: str = (os.environ.get("P2P_LIGHTHOUSE_TOKEN") or "").strip()
        self._lhs: Dict[str, LighthouseClient] = {}  # key "host:port" -> client
        self._lh_targets: List[str] = []  # normalized ["host:port", ...]
        # downloads in-flight via relay: req_id -> state
        self._relay_dl_lock = threading.Lock()
        self._relay_downloads: Dict[str, Dict[str, Any]] = {}
        # dedupe for room broadcasts (mcast + lighthouse can double-deliver)
        self._seen_room_ids: Dict[str, float] = {}
        self._seen_room_keep_s: float = 90.0
        self._seen_room_max: int = 4096
        # discovered lighthouses (addr strings like "ip:port")
        self._known_lighthouses_lock = threading.Lock()
        self.known_lighthouses: set[str] = set(self._normalize_lh_addrs(DEFAULT_BOOTSTRAP_LIGHTHOUSES))

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
            # ---- lighthouse connect (optional, multi) ----
            try:
                env_targets = self._parse_lighthouse_env_multi()
                if env_targets:
                    self.connect_lighthouses(env_targets, token=self._lh_token)
            except Exception:
                pass
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
        self._lh_refresh_hello(send_immediately=True)

    def set_room(self, room: str) -> None:
        self.room = (_safe_str(room, 64) or "general")
        self._lh_refresh_hello(send_immediately=True)
    def avatar_sha(self) -> str:
        ap = self.identity.avatar_path
        if ap and os.path.exists(ap):
            try:
                return sha256_file(ap)
            except Exception:
                return ""
        return ""


    def broadcast_presence(self) -> None:
        t = now_ts()
        if (t - self._last_presence_ts) < float(self.presence_min_interval_s):
            return
        self._last_presence_ts = t

        # multicast presence (LAN only)
        if not DISABLE_MCAST:
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

        # lighthouse hello (cross-router)
        if self._lhs:
            hp = dict(self._lh_hello_payload())
            if self._lh_token:
                hp["token"] = self._lh_token
            hp["t"] = "hello"
            hp["ts"] = t
            for cli in self._lhs.values():
                try:
                    cli.set_hello(self._lh_hello_payload())
                    if cli.is_connected:
                        cli.send(hp)
                except Exception:
                    pass

    def _room_seen_before(self, msg: Dict[str, Any]) -> bool:
        """Return True if msg_id was seen recently (drop duplicates)."""
        try:
            mid = str(msg.get("msg_id") or "").strip()
            if not mid:
                return False
            now = now_ts()
            last = self._seen_room_ids.get(mid)
            if last is not None and (now - float(last)) <= self._seen_room_keep_s:
                return True

            # prune occasionally
            if len(self._seen_room_ids) >= self._seen_room_max:
                cutoff = now - self._seen_room_keep_s
                self._seen_room_ids = {k: v for k, v in self._seen_room_ids.items() if float(v) >= cutoff}

            self._seen_room_ids[mid] = now
            return False
        except Exception:
            return False

    def _lh_room_broadcast(self, inner: Dict[str, Any]) -> None:
        """Send a UDP-style room message via lighthouse so cross-router peers see it."""
        if not self._lhs:
            return
        payload = {"t": "room_broadcast", "msg": inner}
        for cli in list(self._lhs.values()):
            try:
                if cli and cli.is_connected:
                    cli.send(payload)
            except Exception:
                pass

    def send_public_text(self, text: str) -> None:
        # prevent accidental UI loops spamming
        t = now_ts()
        if (t - self._last_public_ts) < float(self.public_chat_min_interval_s):
            return
        self._last_public_ts = t

        msg = {
            "v": 1,
            "t": "public_chat",
            "ts": t,
            "msg_id": uuid.uuid4().hex,
            "room": self.room,
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "avatar_sha": self.avatar_sha(),  # ✅ always computed from avatar_path
            "text": _safe_str(text, 4000),
        }

        # LAN multicast
        if not DISABLE_MCAST:
            try:
                mcast_send(self.group, self.port, self.ttl, msg)
            except Exception:
                pass

        # Lighthouse (cross-router)
        self._lh_room_broadcast(msg)

    def send_dm_text(self, peer: PeerInfo, text: str) -> None:
        obj = {
            "t": "dm",
            "ts": now_ts(),
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "to_user_id": peer.user_id,  # NEW
            "to_name": peer.name,  # NEW
            "avatar_sha": self.avatar_sha(),
            "text": _safe_str(text, 4000),
        }

        # relay-only peer
        if peer.ip == "relay" or peer.tcp_port <= 0:
            cli = self._lh_best_for_peer(peer)
            if cli:
                cli.send({"t": "relay", "kind": "dm", "to": peer.user_id, "msg": obj})
                return
            raise RuntimeError("no_lighthouse_connected")

        # direct LAN path
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
        if peer.ip == "relay" or peer.tcp_port <= 0:
            cli = self._lh_best_for_peer(peer)
            if not cli:
                raise RuntimeError("no_lighthouse_connected")
            cli.send({"t": "relay", "kind": "tx_push", "to": peer.user_id, "msg": obj})
            return
        tcp_send_json(peer.ip, peer.tcp_port, obj)

    def share_file_to_room(self, path: str, note: str = "", scope: str = "room") -> FileOffer:
        path = str(Path(path).resolve())
        size = int(os.path.getsize(path))
        if size <= 0 or size > MAX_BLOB_SEND_BYTES:
            raise RuntimeError("file_too_large_or_empty")

        digest = sha256_file(path)
        name = os.path.basename(path)
        file_id = f"{digest}:{size}:{name}"
        self._shared_files[file_id] = path

        offer = FileOffer(
            offer_id=sha256_text(f"room_offer|{self.identity.user_id}|{now_ts():.6f}|{file_id}"),
            scope=_safe_str(scope, 16) or "room",
            room=self.room,
            from_user_id=self.identity.user_id,
            from_name=self.identity.name,
            from_ip="",
            from_tcp_port=self.tcp_port,
            file_id=file_id,
            filename=name,
            size=size,
            sha256=digest,
            note=_safe_str(note, 512),
        )

        msg = {
            "v": 1,
            "t": "room_file_offer",
            "ts": now_ts(),
            "msg_id": uuid.uuid4().hex,
            "room": self.room,
            "from_user_id": self.identity.user_id,
            "from_name": self.identity.name,
            "tcp_port": self.tcp_port,
            "avatar_sha": self.avatar_sha(),  # ✅ always present
            "scope": offer.scope,
            "file_id": file_id,
            "file": {"name": offer.filename, "size": offer.size, "sha256": offer.sha256, "file_id": file_id},
            "note": offer.note,
        }

        # LAN multicast
        if not DISABLE_MCAST:
            try:
                mcast_send(self.group, self.port, self.ttl, msg)
            except Exception:
                pass

        # Lighthouse (cross-router)
        self._lh_room_broadcast(msg)

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
        if peer.ip == "relay" or peer.tcp_port <= 0:
            cli = self._lh_best_for_peer(peer)
            if not cli:
                raise RuntimeError("no_lighthouse_connected")
            cli.send({"t": "relay", "kind": "dm_file_offer", "to": peer.user_id, "msg": obj})
            return offer

        tcp_send_json(peer.ip, peer.tcp_port, obj)
        return offer

    def download_offer(self, offer: FileOffer, save_path: str) -> int:
        # --- FIX START: Allow ledger files to bypass moderation ---
        # If this is a ledger sync, we trust it (it is verified by coin_fingerprint later)
        is_system_file = (offer.scope == "ledger") or (offer.filename == "ledger.json")

        if not is_system_file:
            ok, reason = self.moderation.file_check_metadata(
                filename=_safe_str(offer.filename, 512),
                size=int(offer.size),
                sha256hex=_safe_str(offer.sha256, 128),
            )
            if not ok:
                raise RuntimeError(f"blocked_before_download:{reason}")
        # --- FIX END ---
        # file_id must be stable
        file_id = str(getattr(offer, "file_id", "") or "").strip()
        if not file_id:
            file_id = f"{offer.sha256}:{int(offer.size)}:{offer.filename}"

        received = 0
        # If offer is relay-origin, fetch via lighthouse
        if (offer.from_ip == "relay" or offer.from_tcp_port <= 0):
            if not self._lhs:
                raise RuntimeError("no_lighthouse_connected")

            req_id = uuid.uuid4().hex
            self._relay_download_register(req_id, save_path, int(offer.size), str(offer.sha256))

            file_id = str(getattr(offer, "file_id", "") or f"{offer.sha256}:{offer.size}:{offer.filename}")
            payload = {"t": "relay_file_get", "to": offer.from_user_id, "req_id": req_id, "file_id": file_id}

            cli: Optional[LighthouseClient] = None

            via = _safe_str(getattr(offer, "relay_via", "") or "", 256)
            if via:
                cli = self._lhs.get(via)
                if cli and not cli.is_connected:
                    cli = None

            if cli is None:
                sender = self.peers.get(offer.from_user_id)
                if sender:
                    cli = self._lh_best_for_peer(sender)

            if cli is None:
                for c in self._lhs.values():
                    if c.is_connected:
                        cli = c
                        break

            if cli is None:
                self._relay_download_finish(req_id, "no_lighthouse_connected")
                st = self._relay_download_pop(req_id)
                if st:
                    try:
                        st["f"].close()
                    except Exception:
                        pass
                raise RuntimeError("no_lighthouse_connected")

            cli.send(payload)

            # WAIT for completion
            with self._relay_dl_lock:
                st0 = self._relay_downloads.get(req_id)
            if not st0:
                raise RuntimeError("relay_state_missing")

            # simple timeout scale by size (clamped)
            exp = int(st0.get("expected_size") or int(offer.size) or 0)
            timeout_s = max(30.0, min(600.0, 30.0 + (exp / 200_000.0)))

            if not st0["done"].wait(timeout=timeout_s):
                self._relay_download_finish(req_id, "timeout")

            st = self._relay_download_pop(req_id)
            if not st:
                raise RuntimeError("relay_state_missing")

            err = str(st.get("err") or "")
            received = int(st.get("received") or 0)

            if err:
                try:
                    os.unlink(save_path)
                except Exception:
                    pass
                raise RuntimeError(f"relay_download_failed:{err}")

            # success
            received = int(received)
        else:
            req = {"t": "file_get", "file_id": file_id}
            received = tcp_request_blob(
                offer.from_ip,
                int(offer.from_tcp_port),
                req,
                save_path,
                expected_sha256=str(offer.sha256 or ""),
            )

        # --- FIX START: Bypass post-download check for ledger too ---
        if not is_system_file:
            ok2, reason2 = self.moderation.file_check_path(path=save_path)
            if not ok2:
                try:
                    os.unlink(save_path)
                except Exception:
                    pass
                raise RuntimeError(f"blocked_after_download:{reason2}")
        # --- FIX END ---

        return int(received) if 'received' in locals() else int(offer.size or 0)
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
        try:
            # Only accept if addressed to us (or if field missing, accept)
            to_uid = _safe_str(msg.get("to_user_id") or "", 128)
            if to_uid and to_uid != self.identity.user_id:
                return

            text = _safe_str(msg.get("text") or "", 4000)

            # Moderate inbound text (attribute to sender uid if available)
            sender_uid = _safe_str(msg.get("from_user_id") or addr[0], 128)
            ok, cleaned, _reason = self.moderation.chat_check(user_id=sender_uid, text=text)
            if not ok:
                return

            m = {
                "t": "dm",
                "ts": float(msg.get("ts") or now_ts()),
                "from_user_id": _safe_str(msg.get("from_user_id") or "", 128),
                "from_name": _safe_str(msg.get("from_name") or "unknown", 64),
                "to_user_id": to_uid or self.identity.user_id,
                "to_name": _safe_str(msg.get("to_name") or self.identity.name, 64),
                "avatar_sha": _safe_str(msg.get("avatar_sha") or "", 128),
                "text": cleaned,
                "direction": "in",
                "_src_ip": addr[0],
            }
            self._q_dm_msgs.put(m)
        except Exception:
            pass

    def _handle_tx_push_tcp(self, msg: Dict[str, Any], addr: Tuple[str, int]) -> None:
        from_uid = _safe_str(msg.get("from_user_id") or "remote", 128)

        wire = str(msg.get("tx_wire") or "").strip()
        if not wire:
            return
        if len(wire) > 200_000:
            return

        # ✅ Validate as tx wire (base64 urlsafe JSON), NOT as chat text
        try:
            raw = base64.urlsafe_b64decode(wire.encode("ascii"))
            d = json.loads(raw.decode("utf-8"))
            if not isinstance(d, dict) or not str(d.get("tx_id") or "").strip():
                return
        except Exception:
            return

        msg["from_user_id"] = from_uid
        msg["from_name"] = _safe_str(msg.get("from_name") or "unknown", 64)
        msg["from_tcp_port"] = _clamp_int(msg.get("from_tcp_port"), 0, 65535, 0)
        if addr[0] == "relay":
            msg["from_tcp_port"] = 0

        msg["tx_wire"] = wire
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
            from_tcp_port=_clamp_int(msg.get("from_tcp_port"), 0, 65535, 0),

            file_id=incoming_file_id,  # IMPORTANT

            filename=name,
            size=size,
            sha256=digest,
            note=note,
            relay_via=_safe_str(msg.get("_relay_via") or "", 256),
        )
        if offer.from_tcp_port <= 0 and offer.from_ip != "relay":
            return
        self._q_dm_offers.put(offer)

    def _handle_udp(self, msg: Dict[str, Any], src_ip: str) -> None:

        if msg.get("v") != 1:
            return

        t = msg.get("t")

        relay_via = _safe_str(msg.get("_relay_via") or "", 256)

        # --- FIX: Deduplication Check ---
        # If we have seen this unique msg_id before (via LAN or another Relay), drop it.
        # Applies to public_chat and room_file_offer.
        if t in ("public_chat", "room_file_offer"):
            if self._room_seen_before(msg):
                return

        if t == "presence":
            p = PeerInfo(
                user_id=str(msg.get("user_id") or ""),
                name=str(msg.get("name") or "unknown"),
                ip=src_ip,
                tcp_port=int(msg.get("tcp_port") or 0),
                room=str(msg.get("room") or "general"),
                avatar_sha=str(msg.get("avatar_sha") or ""),
                last_seen=now_ts(),
                wallet_addr=str(msg.get("wallet_addr") or ""),
                relay_via=[relay_via] if relay_via else [],
            )
            if not p.user_id or p.user_id == self.identity.user_id:
                return
            if p.tcp_port <= 0 and p.ip != "relay":
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
            msg["_relay_via"] = relay_via
            self._q_room_msgs.put(msg)
            return

        if t == "ledger_tip":
            if _safe_str(msg.get("room") or "", 64) != self.room:
                return

            from_uid = _safe_str(msg.get("from_user_id") or "", 128)
            # Don't listen to ourselves
            if not from_uid or from_uid == self.identity.user_id:
                return

            # ... (keep existing validation checks) ...

            # FIX STARTS HERE: Immediately trigger a sync if the tip is higher than our current height
            current_height = 0
            if hasattr(self, 'get_current_height_func') and self.get_current_height_func:
                current_height = self.get_current_height_func()

            tip_height = _clamp_int(msg.get("height"), 0, 10_000_000, 0)

            if tip_height > current_height:
                offer = FileOffer(
                    offer_id=sha256_text(f"ledger_sync|{from_uid}|{tip_height}"),
                    scope="ledger",
                    room=self.room,
                    from_user_id=from_uid,
                    from_name=_safe_str(msg.get("from_name") or "unknown", 64),
                    from_ip=src_ip,
                    from_tcp_port=_clamp_int(msg.get("tcp_port"), 0, 65535, 0),
                    file_id=_safe_str(msg.get("file_id") or "", 1024),
                    filename=_safe_str(msg.get("filename") or "ledger.json", 256),
                    size=_clamp_int(msg.get("size"), 0, MAX_BLOB_SEND_BYTES, 0),
                    sha256=_safe_str(msg.get("sha256") or "", 128),
                    note="auto_sync",
                    relay_via=relay_via,
                )

                # ✅ Always queue it so your blocks/GUI can see it
                try:
                    self._q_ledger_tips.put(dataclasses.asdict(offer))
                except Exception:
                    pass

                # Optional callback if you wired one
                cb = getattr(self, "on_ledger_offer", None)
                if callable(cb):
                    try:
                        cb(offer)
                    except Exception:
                        pass

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
                from_tcp_port=_clamp_int(msg.get("tcp_port"), 0, 65535, 0),
                file_id=incoming_file_id,
                filename=name,
                size=size,
                sha256=digest,
                note=note,
                relay_via=relay_via,
            )
            if offer.from_tcp_port <= 0 and offer.from_ip != "relay":
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

    def _parse_lighthouse_env(self) -> None:
        raw = (os.environ.get("P2P_LIGHTHOUSE") or "").strip()
        if not raw:
            self._lh_host, self._lh_port = "", 0
            return
        if "://" in raw:
            raw = raw.split("://", 1)[1]
        if "/" in raw:
            raw = raw.split("/", 1)[0]
        if ":" in raw:
            h, p = raw.rsplit(":", 1)
            self._lh_host = h.strip()
            try:
                self._lh_port = int(p.strip())
            except Exception:
                self._lh_port = 0
        else:
            self._lh_host = raw.strip()
            self._lh_port = 38888

    def _lh_hello_payload(self) -> Dict[str, Any]:
        if not self.identity.user_id:
            return {}

        # If this machine is ALSO running a lighthouse server, set env:
        #   P2P_ADVERTISE_LIGHTHOUSE_PORT=38888
        lh_port = _clamp_int(os.environ.get("P2P_ADVERTISE_LIGHTHOUSE_PORT") or 0, 0, 65535, 0)

        d = {
            "v": 1,
            "user_id": self.identity.user_id,
            "name": self.identity.name,
            "room": self.room,
            "tcp_port": self.tcp_port,
            "avatar_sha": self.avatar_sha(),
            "wallet_addr": self.identity.wallet_addr,
        }

        if lh_port > 0:
            d["is_lighthouse"] = True
            d["lighthouse_port"] = int(lh_port)

        return d

    def _lh_send(self, obj: Dict[str, Any]) -> None:
        # Back-compat shim: send to any connected lighthouse (best-effort).
        self._lh_send_any(obj)

    def _relay_peer_upsert(self, peer: Dict[str, Any], via_key: str) -> None:
        p = PeerInfo(
            user_id=str(peer.get("user_id") or ""),
            name=str(peer.get("name") or "unknown"),
            ip="relay",
            tcp_port=0,
            room=str(peer.get("room") or "general"),
            avatar_sha=str(peer.get("avatar_sha") or ""),

            # --- DELETE THIS LINE ---
            # last_seen=float(peer.get("last_seen") or now_ts()),

            # --- REPLACE WITH THIS ---
            # Use our OWN clock. If the server just sent us this peer,
            # they are alive right now. Ignore server clock skew.
            last_seen=now_ts(),
            # -------------------------

            wallet_addr=str(peer.get("wallet_addr") or ""),
            relay_via=[via_key],
        )
        if not p.user_id or p.user_id == self.identity.user_id:
            return
        self.peers.update(p)

    def _relay_download_register(self, req_id: str, save_path: str, expected_size: int, expected_sha256: str) -> None:
        Path(save_path).resolve().parent.mkdir(parents=True, exist_ok=True)
        st = {
            "req_id": req_id,
            "save_path": save_path,
            "expected_size": int(expected_size),
            "expected_sha256": (expected_sha256 or "").lower(),
            "received": 0,
            "h": hashlib.sha256(),
            "f": open(save_path, "wb"),
            "done": threading.Event(),
            "err": "",
        }
        with self._relay_dl_lock:
            self._relay_downloads[req_id] = st

    def _relay_download_finish(self, req_id: str, err: str = "") -> None:
        with self._relay_dl_lock:
            st = self._relay_downloads.get(req_id)
        if not st:
            return
        try:
            try:
                st["f"].close()
            except Exception:
                pass
            if err:
                st["err"] = err
            st["done"].set()
        finally:
            pass

    def _relay_download_pop(self, req_id: str) -> Optional[Dict[str, Any]]:
        with self._relay_dl_lock:
            return self._relay_downloads.pop(req_id, None)

    def _handle_lighthouse(self, msg: Dict[str, Any], via_key: str) -> None:
        t = msg.get("t")
        # --- DEBUG: Catch server errors ---
        if t == "err":
            code = msg.get("code")
            print(f"[LH Client] Server rejected connection: {code}")
            return
        if t == "peer_list":
            peers = msg.get("peers") or []
            if isinstance(peers, list):
                for p in peers:
                    if isinstance(p, dict):
                        self._relay_peer_upsert(p, via_key)
            return

        # ---- Room broadcast path (cross-router room traffic) ----
        if t == "room_broadcast":
            payload = msg.get("msg")
            if not isinstance(payload, dict):
                return
            inner = dict(payload)
            inner["_relay_via"] = via_key
            self._handle_udp(inner, "relay")
            return

        if t == "relay":
            kind = str(msg.get("kind") or "")
            payload = msg.get("msg")
            if not isinstance(payload, dict):
                return

            payload["_relay_via"] = via_key

            if kind == "dm":
                self._handle_dm(payload, ("relay", 0))
                return
            if kind == "dm_file_offer":
                self._handle_dm_file_offer_tcp(payload, ("relay", 0))
                return
            if kind == "tx_push":
                self._handle_tx_push_tcp(payload, ("relay", 0))
                return
            return

        # ---- relay file receive path ----
        if t == "relay_file_begin":
            req_id = str(msg.get("req_id") or "")
            size = int(msg.get("size") or 0)
            sha = str(msg.get("sha256") or "").lower()
            with self._relay_dl_lock:
                st = self._relay_downloads.get(req_id)
            if not st:
                return
            if size <= 0 or size > MAX_BLOB_SEND_BYTES:
                self._relay_download_finish(req_id, "bad_size")
                return
            st["expected_size"] = size
            st["expected_sha256"] = sha
            return

        if t == "relay_file_chunk":
            req_id = str(msg.get("req_id") or "")
            b64s = msg.get("b64")
            if not isinstance(b64s, str) or not req_id:
                return

            with self._relay_dl_lock:
                st = self._relay_downloads.get(req_id)
            if not st:
                return

            try:
                raw = base64.b64decode(b64s.encode("ascii"), validate=True)
            except Exception:
                self._relay_download_finish(req_id, "bad_b64")
                return

            if st["received"] + len(raw) > int(st["expected_size"]):
                self._relay_download_finish(req_id, "too_many_bytes")
                return

            try:
                st["f"].write(raw)
                st["h"].update(raw)
                st["received"] += len(raw)
            except Exception:
                self._relay_download_finish(req_id, "write_failed")
            return

        if t == "relay_file_get":
            req_id = _safe_str(msg.get("req_id") or "", 64)

            # ✅ Robust: different lighthouse servers use different keys for requester
            to_uid = _safe_str(
                msg.get("from")
                or msg.get("from_user_id")
                or msg.get("requester")
                or msg.get("src_user_id")
                or "",
                128
            )

            # ✅ Robust: sometimes file_id is nested
            fobj = msg.get("file") if isinstance(msg.get("file"), dict) else {}
            file_id = _safe_str(msg.get("file_id") or (fobj.get("file_id") if isinstance(fobj, dict) else "") or "",
                                1024)

            if not req_id or not to_uid or not file_id:
                return

            path = self._get_shared_file_path(file_id)
            if not path or not os.path.exists(path):
                self._lh_send_via(via_key,
                                  {"t": "relay_file_error", "to": to_uid, "req_id": req_id, "code": "not_found"})
                return

            try:
                size = int(os.path.getsize(path))
                if size <= 0 or size > MAX_BLOB_SEND_BYTES:
                    self._lh_send_via(via_key,
                                      {"t": "relay_file_error", "to": to_uid, "req_id": req_id, "code": "bad_size"})
                    return

                # Pull expected sha/name from file_id when possible, otherwise compute sha quickly
                # file_id format you use: "sha:size:filename"
                sha = ""
                name = os.path.basename(path)
                try:
                    parts = str(file_id).split(":", 2)
                    if len(parts) == 3:
                        sha = parts[0]
                        name = parts[2] or name
                except Exception:
                    pass
                if not sha:
                    sha = sha256_file(path)

                # begin
                self._lh_send_via(via_key, {
                    "t": "relay_file_begin",
                    "to": to_uid,
                    "req_id": req_id,
                    "size": size,
                    "sha256": sha,
                    "filename": _safe_str(name, 256),
                })

                # chunks
                with open(path, "rb") as f:
                    while True:
                        raw = f.read(RELAY_CHUNK_RAW)
                        if not raw:
                            break
                        b64s = base64.b64encode(raw).decode("ascii")
                        self._lh_send_via(via_key, {
                            "t": "relay_file_chunk",
                            "to": to_uid,
                            "req_id": req_id,
                            "b64": b64s,
                        })

                # end
                self._lh_send_via(via_key, {"t": "relay_file_end", "to": to_uid, "req_id": req_id})

            except Exception:
                self._lh_send_via(via_key,
                                  {"t": "relay_file_error", "to": to_uid, "req_id": req_id, "code": "send_failed"})

            return
        if t == "relay_file_end":
            req_id = str(msg.get("req_id") or "")
            with self._relay_dl_lock:
                st = self._relay_downloads.get(req_id)
            if not st:
                return

            try:
                st["f"].flush()
                st["f"].close()
            except Exception:
                pass

            got_sha = st["h"].hexdigest().lower()
            exp_sha = str(st.get("expected_sha256") or "").lower()
            if exp_sha and got_sha != exp_sha:
                self._relay_download_finish(req_id, "sha_mismatch")
                return

            self._relay_download_finish(req_id, "")
            return

        if t in ("relay_file_error", "relay_file_fail", "relay_file_nack"):
            req_id = str(msg.get("req_id") or "")
            code = msg.get("code") or msg.get("error") or msg.get("reason") or "error"
            self._relay_download_finish(req_id, _safe_str(code, 64))
            return
    def _normalize_lh_addrs(self, addrs: List[str]) -> List[str]:
        out: List[str] = []
        for raw in addrs:
            s = (raw or "").strip()
            if not s:
                continue
            if "://" in s:
                s = s.split("://", 1)[1]
            if "/" in s:
                s = s.split("/", 1)[0]
            host = s
            port = 38888
            if ":" in s:
                host, ps = s.rsplit(":", 1)
                try:
                    port = int(ps.strip())
                except Exception:
                    continue
            host = host.strip()
            if not host or port <= 0:
                continue
            out.append(f"{host}:{port}")
        # de-dupe, preserve order
        dedup: List[str] = []
        seen = set()
        for x in out:
            if x in seen:
                continue
            seen.add(x)
            dedup.append(x)
        return dedup

    def _parse_lighthouse_env_multi(self) -> List[str]:
        # NEW: supports P2P_LIGHTHOUSES="a:38888,b:38888" (comma-separated)
        raw = (os.environ.get("P2P_LIGHTHOUSES") or "").strip()
        if raw:
            targets = self._normalize_lh_addrs([x.strip() for x in raw.split(",")])
            if targets:
                return targets

        # Back-compat: old single env P2P_LIGHTHOUSE="host:port"
        one = (os.environ.get("P2P_LIGHTHOUSE") or "").strip()
        if one:
            targets = self._normalize_lh_addrs([one])
            if targets:
                return targets

        # BUILT-IN fallback (so users never type anything)
        return self._normalize_lh_addrs(DEFAULT_BOOTSTRAP_LIGHTHOUSES)

    def connect_lighthouses(self, addrs: List[str], *, token: str = "") -> None:
        """
        Connect to multiple lighthouses at once.
        Call anytime (GUI can call this) — it will add/remove connections as needed.
        """
        if token is not None and str(token).strip() != "":
            self._lh_token = str(token).strip()

        targets = self._normalize_lh_addrs(addrs)
        self._lh_targets = targets

        # Stop removed
        for key, cli in list(self._lhs.items()):
            if key not in targets:
                try:
                    cli.stop()
                except Exception:
                    pass
                self._lhs.pop(key, None)

        # Start/refresh existing
        for key in targets:
            host, ps = key.rsplit(":", 1)
            port = int(ps)

            if key in self._lhs:
                cli = self._lhs[key]
                cli.token = self._lh_token
                cli.set_hello(self._lh_hello_payload())
                continue

            cli = LighthouseClient(
                host,
                port,
                token=self._lh_token,
                on_message=(lambda m, k=key: self._handle_lighthouse(m, k)),
            )
            cli.set_hello(self._lh_hello_payload())
            cli.start()
            self._lhs[key] = cli

    def _lh_refresh_hello(self, *, send_immediately: bool = False) -> None:
        if not self._lhs:
            return

        hp = self._lh_hello_payload()
        for cli in self._lhs.values():
            try:
                cli.set_hello(hp)
            except Exception:
                pass

        if send_immediately and hp:
            t = now_ts()
            msg = dict(hp)
            if self._lh_token:
                msg["token"] = self._lh_token
            msg["t"] = "hello"
            msg["ts"] = t
            for cli in self._lhs.values():
                try:
                    if cli.is_connected:
                        cli.send(msg)
                except Exception:
                    pass
    def lighthouse_status(self) -> Dict[str, Any]:
        items = []
        connected = 0
        for key, cli in self._lhs.items():
            ok = bool(cli.is_connected)
            if ok:
                connected += 1
            items.append({"addr": key, "connected": ok})
        return {"total": len(items), "connected": connected, "items": items}

    def _lh_best_for_peer(self, peer: PeerInfo) -> Optional[LighthouseClient]:
        vias = getattr(peer, "relay_via", []) or []
        for k in vias:
            cli = self._lhs.get(k)
            if cli and cli.is_connected:
                return cli
        for cli in self._lhs.values():
            if cli.is_connected:
                return cli
        return None

    def _lh_send_via(self, key: str, obj: Dict[str, Any]) -> bool:
        cli = self._lhs.get(key)
        if cli and cli.is_connected:
            cli.send(obj)
            return True
        return False

    def _lh_send_any(self, obj: Dict[str, Any]) -> bool:
        for cli in self._lhs.values():
            if cli.is_connected:
                cli.send(obj)
                return True
        return False