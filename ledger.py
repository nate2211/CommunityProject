from __future__ import annotations

import dataclasses
import threading
import time
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from utils import b64, unb64, sha256_bytes, canonical_json

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # type: ignore
    from cryptography.hazmat.primitives import serialization  # type: ignore
except Exception:
    Ed25519PrivateKey = None
    Ed25519PublicKey = None
    serialization = None


def now_ts() -> float:
    return time.time()


@dataclass
class CoinConfig:
    name: str = "CommunityCoin"
    symbol: str = "CC"
    network_id: str = "cc-main"
    difficulty_zeros: int = 1
    block_reward: int = 10
    max_mempool: int = 2000



@dataclass
class Wallet:
    private_key_b64: str
    public_key_b64: str
    address: str

    @staticmethod
    def generate() -> "Wallet":
        if Ed25519PrivateKey is None:
            raise RuntimeError("Missing dependency: cryptography (pip install cryptography)")
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        addr = sha256_bytes(pub_bytes)[:40]
        return Wallet(b64(priv_bytes), b64(pub_bytes), addr)

    def _priv(self) -> Any:
        if Ed25519PrivateKey is None:
            raise RuntimeError("cryptography not installed")
        return Ed25519PrivateKey.from_private_bytes(unb64(self.private_key_b64))

    def sign(self, msg: bytes) -> str:
        return b64(self._priv().sign(msg))

    @staticmethod
    def verify(pub_b64: str, msg: bytes, sig_b64: str) -> bool:
        if Ed25519PublicKey is None:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(unb64(pub_b64))
            pub.verify(unb64(sig_b64), msg)
            return True
        except Exception:
            return False


@dataclass
class Tx:
    tx_id: str
    ts: float
    from_addr: str
    from_pub: str
    to_addr: str
    amount: int
    nonce: int
    memo: str = ""
    attachment: Optional[Dict[str, Any]] = None  # {sha256,name,size,ext}
    sig: str = ""

    def unsigned_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "from_addr": self.from_addr,
            "from_pub": self.from_pub,
            "to_addr": self.to_addr,
            "amount": self.amount,
            "nonce": self.nonce,
            "memo": self.memo,
            "attachment": self.attachment,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.unsigned_dict()
        d["tx_id"] = self.tx_id
        d["sig"] = self.sig
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Tx":
        return Tx(
            tx_id=str(d.get("tx_id") or ""),
            ts=float(d.get("ts") or 0.0),
            from_addr=str(d.get("from_addr") or ""),
            from_pub=str(d.get("from_pub") or ""),
            to_addr=str(d.get("to_addr") or ""),
            amount=int(d.get("amount") or 0),
            nonce=int(d.get("nonce") or 0),
            memo=str(d.get("memo") or ""),
            attachment=d.get("attachment", None),
            sig=str(d.get("sig") or ""),
        )


@dataclass
class Block:
    height: int
    prev_hash: str
    ts: float
    nonce: int
    difficulty_zeros: int
    miner_addr: str
    txs: List[Dict[str, Any]]
    block_hash: str = ""

    def header_dict(self) -> Dict[str, Any]:
        return {
            "height": self.height,
            "prev_hash": self.prev_hash,
            "ts": self.ts,
            "nonce": self.nonce,
            "difficulty_zeros": self.difficulty_zeros,
            "miner_addr": self.miner_addr,
            "txs_hash": sha256_bytes(canonical_json(self.txs)),
        }

    def compute_hash(self) -> str:
        return sha256_bytes(canonical_json(self.header_dict()))

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Block":
        return Block(
            height=int(d.get("height") or 0),
            prev_hash=str(d.get("prev_hash") or ""),
            ts=float(d.get("ts") or 0.0),
            nonce=int(d.get("nonce") or 0),
            difficulty_zeros=int(d.get("difficulty_zeros") or 0),
            miner_addr=str(d.get("miner_addr") or ""),
            txs=list(d.get("txs") or []),
            block_hash=str(d.get("block_hash") or ""),
        )


@dataclass
class LedgerState:
    balances: Dict[str, int] = field(default_factory=dict)
    next_nonce: Dict[str, int] = field(default_factory=dict)

    def ensure_addr(self, addr: str) -> None:
        self.balances.setdefault(addr, 0)
        self.next_nonce.setdefault(addr, 1)


class Ledger:
    def __init__(self, coin: CoinConfig) -> None:
        self.coin = coin
        # RLock so verify_tx can safely be called from code paths that already hold the lock
        self._lock = threading.RLock()
        self.chain: List[Block] = []
        self.mempool: List[Tx] = []
        self.state = LedgerState()
        self._init_genesis()
    # ---------------- Genesis / chain helpers ----------------
    def _init_genesis(self) -> None:
        # reset to a clean chain + empty mempool + fresh state
        with self._lock:
            g = Block(
                height=0,
                prev_hash="0" * 64,
                ts=now_ts(),
                nonce=0,
                difficulty_zeros=int(self.coin.difficulty_zeros),
                miner_addr="GENESIS",
                txs=[],
            )
            g.block_hash = g.compute_hash()
            self.chain = [g]
            self.mempool = []
            self.state = LedgerState()

    def init_genesis(self) -> None:
        # public alias (so external code can call init_genesis safely)
        self._init_genesis()

    def tip_hash(self) -> str:
        with self._lock:
            return self.chain[-1].block_hash

    def height(self) -> int:
        with self._lock:
            return len(self.chain) - 1

    def get_balance(self, addr: str) -> int:
        with self._lock:
            self.state.ensure_addr(addr)
            return int(self.state.balances.get(addr, 0))
    # ---------- mempool-aware nonce + spend reservation ----------
    def _mempool_expected_nonce(self, from_addr: str) -> int:
        base = int(self.state.next_nonce.get(from_addr, 1))
        used = {int(t.nonce) for t in self.mempool if t.from_addr == from_addr and int(t.nonce) >= base}
        while base in used:
            base += 1
        return base

    def _mempool_reserved_spend(self, from_addr: str, up_to_nonce_exclusive: int) -> int:
        # sums amounts for pending txs that would be applied before the candidate nonce
        s = 0
        for t in self.mempool:
            if t.from_addr == from_addr and int(t.nonce) < int(up_to_nonce_exclusive):
                s += int(t.amount)
        return s

    # ---------- core tx checks (no chain state) ----------
    def _verify_tx_static(self, tx: Tx) -> Tuple[bool, str]:
        if tx.amount <= 0:
            return False, "bad_amount"
        if not tx.from_addr or not tx.to_addr:
            return False, "missing_addr"
        if not tx.from_pub or not tx.sig:
            return False, "missing_sig"
        if len(tx.memo) > 256:
            return False, "memo_too_large"

        try:
            derived = sha256_bytes(unb64(tx.from_pub))[:40]
            if derived != tx.from_addr:
                return False, "addr_pub_mismatch"
        except Exception:
            return False, "bad_pubkey"

        msg = canonical_json(tx.unsigned_dict())
        if not Wallet.verify(tx.from_pub, msg, tx.sig):
            return False, "bad_signature"

        if tx.attachment is not None:
            a = tx.attachment
            if not isinstance(a, dict):
                return False, "bad_attachment"
            for k in ("sha256", "size", "name", "ext"):
                if k not in a:
                    return False, "bad_attachment_fields"
            # small sanity caps (prevents “metadata bombs”)
            if len(str(a.get("name", ""))) > 256:
                return False, "bad_attachment_name"
            if int(a.get("size", 0)) < 0:
                return False, "bad_attachment_size"

        return True, "ok"

    def verify_tx(self, tx: Tx) -> Tuple[bool, str]:
        # Safe to call from anywhere (mining threads, UI thread, etc.)
        with self._lock:
            ok, reason = self._verify_tx_static(tx)
            if not ok:
                return False, reason

            self.state.ensure_addr(tx.from_addr)
            self.state.ensure_addr(tx.to_addr)

            # mempool-aware nonce reservation
            expected_nonce = self._mempool_expected_nonce(tx.from_addr)
            if int(tx.nonce) != int(expected_nonce):
                return False, "bad_nonce"

            # mempool-aware spend reservation (prevents overspending with multiple pending txs)
            bal = int(self.state.balances.get(tx.from_addr, 0))
            reserved = self._mempool_reserved_spend(tx.from_addr, expected_nonce)
            if (bal - reserved) < int(tx.amount):
                return False, "insufficient_funds"

            return True, "ok"

    def add_tx_to_mempool(self, tx: Tx) -> Tuple[bool, str]:
        with self._lock:
            if len(self.mempool) >= self.coin.max_mempool:
                return False, "mempool_full"
            ok, reason = self.verify_tx(tx)
            if not ok:
                return False, reason
            if any(t.tx_id == tx.tx_id for t in self.mempool):
                return False, "duplicate_tx"
            self.mempool.append(tx)
            return True, "ok"

    def expected_nonce(self, from_addr: str) -> int:
        with self._lock:
            self.state.ensure_addr(from_addr)
            return self._mempool_expected_nonce(from_addr)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "chain": [b.to_dict() for b in self.chain],
                "mempool": [t.to_dict() for t in self.mempool],
            }

    def load_from_dict(self, d: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Loads chain+mempool from a dict. Rebuilds balances by re-accepting blocks.
        Safe against tampering because accept_block() re-checks PoW + tx validity.
        """
        try:
            chain_raw = list(d.get("chain") or [])
            mempool_raw = list(d.get("mempool") or [])
        except Exception:
            return False, "bad_format"

        if not chain_raw:
            return False, "empty_chain"

        # Reset local state
        with self._lock:
            self.mempool = []
            self.state = LedgerState()

            # Load/validate genesis (height 0) from file
            g = Block.from_dict(chain_raw[0])
            if int(g.height) != 0:
                return False, "bad_genesis_height"
            if int(g.difficulty_zeros) != int(self.coin.difficulty_zeros):
                return False, "bad_genesis_difficulty"
            if not g.block_hash:
                g.block_hash = g.compute_hash()
            if g.block_hash != g.compute_hash():
                return False, "bad_genesis_hash"

            self.chain = [g]

        # Re-accept remaining blocks to rebuild balances/nonces
        for rawb in chain_raw[1:]:
            try:
                b = Block.from_dict(rawb)
            except Exception:
                return False, "bad_block_decode"
            ok, reason = self.accept_block(b)
            if not ok:
                return False, f"bad_block:{reason}"

        # Restore mempool (best-effort)
        for rawt in mempool_raw:
            try:
                tx = Tx.from_dict(rawt)
            except Exception:
                continue
            self.add_tx_to_mempool(tx)

        return True, "ok"
    # ---------- SAFE mining throttle controls ----------
    def mine_once(
        self,
        *,
        miner_addr: str,
        stop_event: threading.Event,
        intensity: float = 0.65,
        work_budget_s: Optional[float] = None,     # run at most this long, then return None (for duty-cycling)
        hps_cap: Optional[int] = None,             # approximate hashes/sec cap (safety)
        yield_every: int = 2000,                   # more frequent yielding = cooler/safer
    ) -> Optional[Block]:
        intensity = max(0.01, min(1.0, float(intensity)))
        yield_every = max(200, int(yield_every))

        with self._lock:
            prev = self.tip_hash()
            height = self.height() + 1
            txs = [t.to_dict() for t in self.mempool[:500]]

        b = Block(
            height=height,
            prev_hash=prev,
            ts=now_ts(),
            nonce=0,
            difficulty_zeros=self.coin.difficulty_zeros,
            miner_addr=miner_addr,
            txs=txs,
        )
        target = "0" * b.difficulty_zeros
        n = random.randint(0, 2**31 - 1)

        start = time.monotonic()
        hashes = 0

        while not stop_event.is_set():
            if work_budget_s is not None and (time.monotonic() - start) >= float(work_budget_s):
                return None

            b.nonce = n
            h = b.compute_hash()
            hashes += 1
            if h.startswith(target):
                b.block_hash = h
                return b

            n += 1

            # yield/throttle periodically (this is what keeps your machine from going nuclear)
            if (hashes % yield_every) == 0:
                # intensity behaves like “duty fraction”
                if intensity < 1.0:
                    time.sleep((1.0 - intensity) * 0.06)

                # optional hash-rate cap (extra safety)
                if hps_cap and hps_cap > 0:
                    elapsed = max(1e-6, time.monotonic() - start)
                    hps = hashes / elapsed
                    if hps > float(hps_cap):
                        # sleep a bit to drift under the cap
                        time.sleep(min(0.25, (hps / float(hps_cap) - 1.0) * 0.05))

        return None

    def accept_block(self, b: Block) -> Tuple[bool, str]:
        with self._lock:
            if b.height != self.height() + 1:
                return False, "bad_height"
            if b.prev_hash != self.tip_hash():
                return False, "bad_prev_hash"

            # never accept a block claiming an easier difficulty
            if int(b.difficulty_zeros) != int(self.coin.difficulty_zeros):
                return False, "bad_difficulty"

            if not b.block_hash:
                b.block_hash = b.compute_hash()
            if not b.block_hash.startswith("0" * int(b.difficulty_zeros)):
                return False, "bad_pow"

            # Validate + apply transactions FIRST on a temp snapshot.
            # (Fixes the bug where a failing block could still grant the miner reward.)
            tmp_bal = dict(self.state.balances)
            tmp_nonce = dict(self.state.next_nonce)

            def ensure_tmp(addr: str) -> None:
                tmp_bal.setdefault(addr, 0)
                tmp_nonce.setdefault(addr, 1)

            included: set[str] = set()

            for raw in b.txs:
                tx = Tx.from_dict(raw)

                ok, reason = self._verify_tx_static(tx)
                if not ok:
                    return False, f"bad_tx_in_block:{reason}"

                ensure_tmp(tx.from_addr)
                ensure_tmp(tx.to_addr)

                expected = int(tmp_nonce.get(tx.from_addr, 1))
                if int(tx.nonce) != expected:
                    return False, "bad_tx_in_block:bad_nonce"

                if int(tmp_bal.get(tx.from_addr, 0)) < int(tx.amount):
                    return False, "bad_tx_in_block:insufficient_funds"

                tmp_bal[tx.from_addr] -= int(tx.amount)
                tmp_bal[tx.to_addr] += int(tx.amount)
                tmp_nonce[tx.from_addr] = int(tx.nonce) + 1
                included.add(tx.tx_id)

            # Commit snapshot + reward only after everything checks out
            ensure_tmp(b.miner_addr)
            tmp_bal[b.miner_addr] += int(self.coin.block_reward)

            self.state.balances = tmp_bal
            self.state.next_nonce = tmp_nonce

            self.chain.append(b)
            self.mempool = [t for t in self.mempool if t.tx_id not in included]
            return True, "ok"
    def available_balance(self, addr: str) -> int:
        """
        confirmed_balance - sum(outgoing pending in mempool)
        (since you enforce contiguous nonces, reserving all outgoing is safe)
        """
        with self._lock:
            self.state.ensure_addr(addr)
            confirmed = int(self.state.balances.get(addr, 0))
            pending_out = sum(int(t.amount) for t in self.mempool if t.from_addr == addr)
            return confirmed - pending_out

    def pending_for(self, addr: str) -> Dict[str, int]:
        with self._lock:
            self.state.ensure_addr(addr)
            pending_out = sum(int(t.amount) for t in self.mempool if t.from_addr == addr)
            pending_in  = sum(int(t.amount) for t in self.mempool if t.to_addr == addr)
            return {"pending_out": pending_out, "pending_in": pending_in}