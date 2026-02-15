from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

from utils import sha256_text, sha256_file

try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None


TOKEN_RE = re.compile(r"[a-z0-9']+", re.IGNORECASE)

# SHA-256 hashes of banned slur tokens (lowercased)
# (Hashing avoids embedding the word itself in source.)
SLUR_HASHES = {
    "120f6e5b4ea32f65bda68452fcfaaef06b0136e1d0e4a6f60bc3771fa0936dd6",
    "08a841e996781e9e77d30a4e4420a8f501a280b00624e6d1224bf54aaff73eba",
    "341d56384afc0f47b34ca18273e793be555507a49444c30d3d0588688de46cb3",
    "5b3ae48be122f7ed19b4cc587649f41f9d2565df51cfa332f8e7806f4ebb9032",
    "7d2969e37aa4ff6030ee5b5b9e60f8689a5bab0a4a24b432d7ee4be157e5f6bd",
    "038c9ccdd226f5728bd0a945bdbb0a25c0f877f2f36f4092ee8c004e810aa300",
    "8c976cd4fdb52a4ebef8a5430df093e1d340c577ff373be3442da708aaac4592",
    "bbd1ebc6775b3e8afc43ae1e8983effa4c38d7101b51767e941f5ed27b556e54",
}


def now_ts() -> float:
    return time.time()


@dataclass
class ChatProtectionConfig:
    max_msgs_per_10s: int = 8
    max_chars_per_msg: int = 1200
    max_duplicate_window: int = 6
    max_links_per_msg: int = 4
    banned_words: List[str] = field(default_factory=list)
    banned_regex: List[str] = field(default_factory=list)


@dataclass
class FileProtectionConfig:
    max_size_mb: int = 75
    allow_ext: List[str] = field(default_factory=lambda: [
        # docs
        ".txt", ".pdf", ".zip",

        # images
        ".png", ".jpg", ".jpeg", ".webp", ".gif",

        # audio (includes WAV)
        ".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac",

        # video
        ".mp4", ".mov", ".mkv", ".webm",
    ])
    block_hashes: List[str] = field(default_factory=list)

    # very naive image scan (best-effort only)
    enable_naive_image_scan: bool = True
    naive_skin_pct_threshold: float = 0.38


@dataclass
class ModerationState:
    chat_cfg: ChatProtectionConfig = field(default_factory=ChatProtectionConfig)
    file_cfg: FileProtectionConfig = field(default_factory=FileProtectionConfig)

    # user_id -> [(ts, msg), ...]
    _recent_msgs: Dict[str, List[Tuple[float, str]]] = field(default_factory=dict)
    # user_id -> [hashes...]
    _recent_hashes: Dict[str, List[str]] = field(default_factory=dict)

    def chat_check(self, *, user_id: str, text: str) -> Tuple[bool, str, str]:
        text = (text or "").strip()
        if not text:
            return False, "", "empty_message"
        if len(text) > self.chat_cfg.max_chars_per_msg:
            return False, "", "too_long"

        t = now_ts()

        bucket = self._recent_msgs.setdefault(user_id, [])
        bucket = [(ts, s) for (ts, s) in bucket if (t - ts) <= 10.0]
        bucket.append((t, text))
        self._recent_msgs[user_id] = bucket
        if len(bucket) > self.chat_cfg.max_msgs_per_10s:
            return False, "", "rate_limited"

        # duplicate spam
        h = sha256_text(text.lower())
        hs = self._recent_hashes.setdefault(user_id, [])
        hs.append(h)
        if len(hs) > self.chat_cfg.max_duplicate_window:
            hs[:] = hs[-self.chat_cfg.max_duplicate_window:]
        if hs.count(h) >= 3:
            return False, "", "duplicate_spam"

        # link spam
        links = re.findall(r"https?://", text, flags=re.IGNORECASE)
        if len(links) >= self.chat_cfg.max_links_per_msg:
            return False, "", "link_spam"

        low = text.lower()

        # explicit banned words
        for w in self.chat_cfg.banned_words:
            ww = (w or "").strip().lower()
            if ww and ww in low:
                return False, "", "banned_word"

        # regex bans
        for pat in self.chat_cfg.banned_regex:
            try:
                if re.search(pat, text, flags=re.IGNORECASE):
                    return False, "", "banned_pattern"
            except Exception:
                continue

        # hashed slur tokens
        tokens = TOKEN_RE.findall(low)
        for tok in tokens:
            if sha256_text(tok) in SLUR_HASHES:
                return False, "", "hate_slur"

        return True, text, ""

    def file_check_metadata(self, *, filename: str, size: int, sha256hex: str) -> Tuple[bool, str]:
        ext = Path(filename).suffix.lower()
        if ext not in self.file_cfg.allow_ext:
            return False, "file_type_not_allowed"
        if size <= 0:
            return False, "empty_file"
        if size > self.file_cfg.max_size_mb * 1024 * 1024:
            return False, "file_too_large"
        if sha256hex and sha256hex.lower() in {h.lower() for h in self.file_cfg.block_hashes}:
            return False, "blocked_hash"
        return True, ""

    def file_check_path(self, *, path: str) -> Tuple[bool, str]:
        import os
        if not path or not os.path.exists(path):
            return False, "file_not_found"

        size = os.path.getsize(path)
        name = os.path.basename(path)
        try:
            digest = sha256_file(path)
        except Exception:
            return False, "hash_failed"

        ok, reason = self.file_check_metadata(filename=name, size=size, sha256hex=digest)
        if not ok:
            return False, reason

        ext = Path(path).suffix.lower()
        if self.file_cfg.enable_naive_image_scan and Image is not None and ext in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
            try:
                if naive_skin_pct(path) >= float(self.file_cfg.naive_skin_pct_threshold):
                    return False, "possible_nsfw_image"
            except Exception:
                pass

        return True, ""


def naive_skin_pct(path: str) -> float:
    if Image is None:
        return 0.0

    img = Image.open(path).convert("RGB")
    img.thumbnail((256, 256))
    px = img.load()
    w, h = img.size
    if w * h == 0:
        return 0.0

    skin = 0
    total = w * h
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]

            # crude YCbCr-ish heuristic
            Y  = 0.299 * r + 0.587 * g + 0.114 * b
            Cb = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b
            Cr = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b

            if (80 <= Cb <= 135) and (135 <= Cr <= 180) and (Y >= 50):
                skin += 1

    return skin / float(total)
