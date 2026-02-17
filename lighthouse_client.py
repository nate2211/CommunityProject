# lighthouse_client.py
from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional

MAX_LINE = 256_000

def now_ts() -> float:
    return time.time()

def _safe_str(v: Any, n: int = 256) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= n else s[:n]

class LighthouseClient(threading.Thread):
    """
    Persistent TCP JSON-lines connection to lighthouse.
    - outbound only (NAT friendly)
    - reconnects automatically
    """
    def __init__(
        self,
        host: str,
        port: int,
        *,
        token: str = "",
        on_message: Callable[[Dict[str, Any]], None],
    ) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = int(port)
        self.token = token
        self.on_message = on_message

        self._stop_evt = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._buf = bytearray()
        self._send_lock = threading.Lock()
        self._connected = threading.Event()

        self._hello_payload: Dict[str, Any] = {}
        self._last_hello_ts = 0.0
        self._last_ping_ts = 0.0

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    def set_hello(self, payload: Dict[str, Any]) -> None:
        # payload should include: user_id,name,room,tcp_port,avatar_sha,wallet_addr
        self._hello_payload = dict(payload)

    def send(self, obj: Dict[str, Any]) -> None:
        s = self._sock
        if not s:
            return
        data = (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(data) > MAX_LINE:
            return
        with self._send_lock:
            try:
                s.sendall(data)
            except Exception:
                pass

    def _connect(self) -> Optional[socket.socket]:
        try:
            # --- FIX: Explicitly resolve IPv4 address ---
            # This handles the "localhost" vs "127.0.0.1" vs "::1" confusion
            addr_info = socket.getaddrinfo(
                self.host,
                self.port,
                socket.AF_INET,  # Force IPv4
                socket.SOCK_STREAM
            )

            if not addr_info:
                print(f"[LH Client] Could not resolve host: {self.host}")
                return None

            # Pick the first valid IPv4 address found
            family, socktype, proto, canonname, sockaddr = addr_info[0]

            s = socket.socket(family, socktype, proto)
            s.settimeout(5.0)
            s.connect(sockaddr)
            s.settimeout(1.0)

            print(f"[LH Client] Connected to {self.host}:{self.port}")
            return s

        except ConnectionRefusedError:
            # This is normal if the server isn't running yet
            return None
        except Exception as e:
            print(f"[LH Client] Connect error: {e}")
            return None

    def _recv_line(self, s: socket.socket) -> Optional[Dict[str, Any]]:
        # read until newline
        while True:
            nl = self._buf.find(b"\n")
            if nl != -1:
                line = bytes(self._buf[:nl])
                del self._buf[: nl + 1]
                if not line:
                    return {}
                if len(line) > MAX_LINE:
                    return None
                try:
                    obj = json.loads(line.decode("utf-8"))
                except Exception:
                    return None
                return obj if isinstance(obj, dict) else None

            if len(self._buf) > MAX_LINE:
                return None

            try:
                chunk = s.recv(4096)
            except socket.timeout:
                return {}
            except OSError:
                return None
            if not chunk:
                return None
            self._buf.extend(chunk)

    def run(self) -> None:
        backoff = 0.25
        while not self._stop_evt.is_set():
            s = self._connect()
            if not s:
                time.sleep(backoff)
                backoff = min(2.0, backoff * 1.4)
                continue

            self._sock = s
            self._connected.set()
            backoff = 0.25
            self._buf.clear()

            # send hello immediately
            if self._hello_payload:
                hp = dict(self._hello_payload)
                if self.token:
                    hp["token"] = self.token
                hp["t"] = "hello"
                hp["ts"] = now_ts()
                self.send(hp)
                self._last_hello_ts = now_ts()

            try:
                while not self._stop_evt.is_set():
                    # ping every ~8s
                    t = now_ts()
                    if (t - self._last_ping_ts) > 8.0:
                        self.send({"t": "ping", "ts": t})
                        self._last_ping_ts = t

                    # refresh hello every ~12s (keeps you listed even if packets drop)
                    if self._hello_payload and (t - self._last_hello_ts) > 12.0:
                        hp = dict(self._hello_payload)
                        if self.token:
                            hp["token"] = self.token
                        hp["t"] = "hello"
                        hp["ts"] = t
                        self.send(hp)
                        self._last_hello_ts = t

                    msg = self._recv_line(s)
                    if msg is None:
                        break
                    if msg == {}:
                        continue
                    self.on_message(msg)

            except Exception:
                pass
            finally:
                self._connected.clear()
                try:
                    s.close()
                except Exception:
                    pass
                self._sock = None
                time.sleep(backoff)
                backoff = min(2.0, backoff * 1.4)
