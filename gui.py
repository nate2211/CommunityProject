from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import Qt, QTimer, QUrl
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QSplitter, QTabWidget, QGroupBox, QFormLayout,
    QSpinBox, QDoubleSpinBox, QFrame, QSizePolicy
)
from PyQt5.QtGui import QDesktopServices

from blocks import BLOCKS
from state import STATE, load_account
from utils import human_bytes, sha256_file

# Optional: download peer avatars if your p2p.py exposes tcp_request_blob()
try:
    from p2p import tcp_request_blob  # type: ignore
except Exception:
    tcp_request_blob = None


# ---------------- helpers ----------------
def run_block(name: str, payload: Any = "", params: Optional[Dict[str, Any]] = None) -> Any:
    blk = BLOCKS.create(name)
    res, _meta = blk.execute(payload, params=params or {})
    return res


def is_image(path: str) -> bool:
    ext = Path(path).suffix.lower()
    return ext in (".png", ".jpg", ".jpeg", ".webp", ".gif")


def safe_text(s: Any, max_len: int = 2000) -> str:
    s2 = str(s or "")
    if len(s2) > max_len:
        s2 = s2[:max_len] + "…"
    return s2


def cache_dir() -> Path:
    p = Path.home() / ".p2p_community" / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


def downloads_dir() -> Path:
    p = Path.home() / "Downloads" / "p2p_community"
    p.mkdir(parents=True, exist_ok=True)
    return p


def sniff_image_ext(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png"
        if head.startswith(b"\xff\xd8"):
            return ".jpg"
        if head.startswith(b"GIF8"):
            return ".gif"
        if head.startswith(b"RIFF") and b"WEBP" in head:
            return ".webp"
    except Exception:
        pass
    return ".bin"


APP_STYLESHEET = """
QMainWindow { background: #0f1115; }
QWidget { color: #e7e7e7; font-size: 12px; }
QGroupBox {
  border: 1px solid #2b2f3a;
  border-radius: 10px;
  margin-top: 10px;
  padding: 10px;
  background: #151924;
}
QGroupBox::title {
  subcontrol-origin: margin;
  left: 10px;
  padding: 0 6px;
  color: #cfd6ff;
  font-weight: 600;
}
QLineEdit, QTextEdit, QListWidget {
  background: #0f1320;
  border: 1px solid #2b2f3a;
  border-radius: 8px;
  padding: 8px;
  selection-background-color: #2c4bff;
}
QPushButton {
  background: #2c4bff;
  border: 0px;
  padding: 8px 12px;
  border-radius: 8px;
  font-weight: 600;
}
QPushButton:hover { background: #3656ff; }
QPushButton:pressed { background: #1e36c9; }
QPushButton[secondary="true"] {
  background: #22283a;
}
QPushButton[secondary="true"]:hover {
  background: #2a3147;
}
QLabel[muted="true"] { color: #a8b0c2; }
QFrame#Divider {
  background: #2b2f3a;
  min-height: 1px;
  max-height: 1px;
}
"""


# ---------------- main window ----------------
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("P2P Community")
        self.resize(1120, 720)

        # Core state
        self._room_offers: List[Dict[str, Any]] = []
        self._dm_offers: List[Dict[str, Any]] = []
        self._peers: List[Dict[str, Any]] = []
        self._selected_peer: Optional[Dict[str, Any]] = None

        self._last_tx_json: Optional[dict] = None

        # Ensure account/p2p ready
        run_block("account", "", {"action": "ensure"})
        run_block("rooms", "", {"action": "join", "room": "general"})

        me = load_account()
        self._my_user_id = str(me.get("user_id", "") or "")
        self._my_name = str(me.get("name", "anon") or "anon")

        # Layout root
        root = QWidget()
        self.setCentralWidget(root)
        main = QHBoxLayout(root)
        main.setContentsMargins(12, 12, 12, 12)
        main.setSpacing(12)

        splitter = QSplitter(Qt.Horizontal)
        main.addWidget(splitter)

        # Sidebar
        sidebar = QWidget()
        sidebar.setMinimumWidth(320)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(0, 0, 0, 0)
        side_layout.setSpacing(12)

        side_layout.addWidget(self._build_profile_box())
        side_layout.addWidget(self._build_rooms_box())
        side_layout.addWidget(self._build_peers_box())
        side_layout.addWidget(self._build_selected_peer_box())
        side_layout.addStretch(1)

        splitter.addWidget(sidebar)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.room_tab = self._build_room_tab()
        self.dm_tab = self._build_dm_tab()
        self.wallet_tab = self._build_wallet_tab()

        self.tabs.addTab(self.room_tab, "Room")
        self.tabs.addTab(self.dm_tab, "Direct")
        self.tabs.addTab(self.wallet_tab, "Wallet")

        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 1)

        # Timers (slower = less CPU)
        self.timer_presence = QTimer(self)
        self.timer_presence.timeout.connect(self._tick_presence)
        self.timer_presence.start(4000)

        self.timer_peers = QTimer(self)
        self.timer_peers.timeout.connect(self._tick_peers)
        self.timer_peers.start(1500)

        self.timer_feed = QTimer(self)
        self.timer_feed.timeout.connect(self._tick_feed)
        self.timer_feed.start(700)

        self._refresh_profile_ui()
        self._refresh_wallet_ui()
        self._tick_peers()

    # ---------------- UI sections ----------------
    def _build_profile_box(self) -> QGroupBox:
        box = QGroupBox("You")
        lay = QVBoxLayout(box)

        top = QHBoxLayout()

        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(64, 64)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.avatar_label.setStyleSheet("border: 1px solid #2b2f3a; border-radius: 10px;")
        top.addWidget(self.avatar_label)

        right = QVBoxLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Display name")
        right.addWidget(self.name_edit)

        btns = QHBoxLayout()
        self.btn_pick_avatar = QPushButton("Avatar")
        self.btn_pick_avatar.setProperty("secondary", True)
        self.btn_save_profile = QPushButton("Save")
        btns.addWidget(self.btn_pick_avatar)
        btns.addWidget(self.btn_save_profile)
        right.addLayout(btns)

        top.addLayout(right, 1)
        lay.addLayout(top)

        self.btn_pick_avatar.clicked.connect(self._pick_avatar)
        self.btn_save_profile.clicked.connect(self._save_profile)
        return box

    def _build_rooms_box(self) -> QGroupBox:
        box = QGroupBox("Room")
        form = QFormLayout(box)
        form.setLabelAlignment(Qt.AlignLeft)

        self.room_edit = QLineEdit()
        self.room_edit.setPlaceholderText("general")
        self.btn_join_room = QPushButton("Join")
        self.btn_join_room.setProperty("secondary", True)

        row = QHBoxLayout()
        row.addWidget(self.room_edit, 1)
        row.addWidget(self.btn_join_room)
        form.addRow("Room name:", row)

        self.btn_join_room.clicked.connect(self._join_room)
        return box

    def _build_peers_box(self) -> QGroupBox:
        box = QGroupBox("Online peers")
        lay = QVBoxLayout(box)

        self.peers_list = QListWidget()
        self.peers_list.setUniformItemSizes(True)
        lay.addWidget(self.peers_list)

        row = QHBoxLayout()
        self.btn_refresh_peers = QPushButton("Refresh")
        self.btn_refresh_peers.setProperty("secondary", True)
        self.btn_dm_peer = QPushButton("Message")
        self.btn_dm_peer.setProperty("secondary", True)
        self.btn_dm_peer.setEnabled(False)
        row.addWidget(self.btn_refresh_peers)
        row.addWidget(self.btn_dm_peer)
        lay.addLayout(row)

        self.btn_refresh_peers.clicked.connect(self._tick_peers)
        self.peers_list.itemSelectionChanged.connect(self._on_peer_selected)
        self.btn_dm_peer.clicked.connect(self._jump_to_dm_tab)
        return box

    def _build_selected_peer_box(self) -> QGroupBox:
        box = QGroupBox("Selected peer")
        lay = QVBoxLayout(box)

        top = QHBoxLayout()

        self.peer_avatar = QLabel()
        self.peer_avatar.setFixedSize(56, 56)
        self.peer_avatar.setAlignment(Qt.AlignCenter)
        self.peer_avatar.setStyleSheet("border: 1px solid #2b2f3a; border-radius: 10px;")
        top.addWidget(self.peer_avatar)

        info = QVBoxLayout()
        self.peer_name_lbl = QLabel("No peer selected")
        self.peer_name_lbl.setStyleSheet("font-weight: 700; font-size: 13px;")
        self.peer_room_lbl = QLabel("")
        self.peer_room_lbl.setProperty("muted", True)
        info.addWidget(self.peer_name_lbl)
        info.addWidget(self.peer_room_lbl)

        top.addLayout(info, 1)
        lay.addLayout(top)

        div = QFrame()
        div.setObjectName("Divider")
        lay.addWidget(div)

        self.peer_wallet_lbl = QLabel("-")
        self.peer_wallet_lbl.setWordWrap(True)
        self.peer_wallet_lbl.setProperty("muted", True)
        lay.addWidget(QLabel("Wallet address:",))
        lay.addWidget(self.peer_wallet_lbl)

        row = QHBoxLayout()
        self.btn_copy_peer_addr = QPushButton("Copy address")
        self.btn_copy_peer_addr.setProperty("secondary", True)
        self.btn_use_peer_addr = QPushButton("Use for payment")
        self.btn_use_peer_addr.setProperty("secondary", True)
        self.btn_copy_peer_addr.setEnabled(False)
        self.btn_use_peer_addr.setEnabled(False)
        row.addWidget(self.btn_copy_peer_addr)
        row.addWidget(self.btn_use_peer_addr)
        lay.addLayout(row)

        self.btn_copy_peer_addr.clicked.connect(self._copy_peer_wallet)
        self.btn_use_peer_addr.clicked.connect(self._use_peer_wallet_in_tx)

        self._set_peer_card(None)
        return box

    def _build_room_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(12)

        self.room_log = QTextEdit()
        self.room_log.setReadOnly(True)
        self.room_log.setPlaceholderText("Room messages will appear here…")
        lay.addWidget(self.room_log, 2)

        offers_box = QGroupBox("File offers (room)")
        offers_lay = QVBoxLayout(offers_box)
        self.room_offers_list = QListWidget()
        offers_lay.addWidget(self.room_offers_list)

        row = QHBoxLayout()
        self.btn_room_download = QPushButton("Download")
        self.btn_room_download.setProperty("secondary", True)
        self.btn_open_downloads = QPushButton("Open downloads")
        self.btn_open_downloads.setProperty("secondary", True)
        row.addWidget(self.btn_room_download)
        row.addWidget(self.btn_open_downloads)
        offers_lay.addLayout(row)

        self.btn_room_download.clicked.connect(self._download_room_offer)
        self.btn_open_downloads.clicked.connect(self._open_downloads_folder)
        lay.addWidget(offers_box, 1)

        send_box = QGroupBox("Send message")
        send_lay = QVBoxLayout(send_box)

        row2 = QHBoxLayout()
        self.room_input = QLineEdit()
        self.room_input.setPlaceholderText("Type a message…")
        self.btn_room_send = QPushButton("Send")
        self.btn_room_send.setDefault(True)
        self.btn_room_file = QPushButton("Share file")
        self.btn_room_file.setProperty("secondary", True)
        row2.addWidget(self.room_input, 1)
        row2.addWidget(self.btn_room_send)
        row2.addWidget(self.btn_room_file)
        send_lay.addLayout(row2)

        self.btn_room_send.clicked.connect(self._send_room)
        self.btn_room_file.clicked.connect(self._send_room_file)
        self.room_input.returnPressed.connect(self._send_room)

        lay.addWidget(send_box)
        return w

    def _build_dm_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(12)

        self.dm_info = QLabel("Select a peer to start a direct message.")
        self.dm_info.setProperty("muted", True)
        lay.addWidget(self.dm_info)

        self.dm_log = QTextEdit()
        self.dm_log.setReadOnly(True)
        self.dm_log.setPlaceholderText("Direct messages will appear here…")
        lay.addWidget(self.dm_log, 2)

        offers_box = QGroupBox("File offers (direct)")
        offers_lay = QVBoxLayout(offers_box)
        self.dm_offers_list = QListWidget()
        offers_lay.addWidget(self.dm_offers_list)

        self.btn_dm_download = QPushButton("Download")
        self.btn_dm_download.setProperty("secondary", True)
        offers_lay.addWidget(self.btn_dm_download)
        self.btn_dm_download.clicked.connect(self._download_dm_offer)
        lay.addWidget(offers_box, 1)

        send_box = QGroupBox("Send DM")
        send_lay = QVBoxLayout(send_box)

        row = QHBoxLayout()
        self.dm_input = QLineEdit()
        self.dm_input.setPlaceholderText("Type a DM…")
        self.btn_dm_send = QPushButton("Send")
        self.btn_dm_file = QPushButton("Send file")
        self.btn_dm_file.setProperty("secondary", True)
        row.addWidget(self.dm_input, 1)
        row.addWidget(self.btn_dm_send)
        row.addWidget(self.btn_dm_file)
        send_lay.addLayout(row)

        self.btn_dm_send.clicked.connect(self._send_dm)
        self.btn_dm_file.clicked.connect(self._send_dm_file)
        self.dm_input.returnPressed.connect(self._send_dm)

        lay.addWidget(send_box)
        return w

    def _build_wallet_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(12)

        # Wallet
        wallet_box = QGroupBox("Wallet")
        f = QFormLayout(wallet_box)

        self.lbl_addr = QLabel("-")
        self.lbl_addr.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_balance = QLabel("-")

        row_btns = QHBoxLayout()
        self.btn_wallet_init = QPushButton("Create")
        self.btn_wallet_init.setProperty("secondary", True)
        self.btn_wallet_load = QPushButton("Load")
        self.btn_wallet_load.setProperty("secondary", True)
        self.btn_wallet_refresh = QPushButton("Refresh")
        self.btn_wallet_refresh.setProperty("secondary", True)
        self.btn_wallet_copy = QPushButton("Copy address")
        self.btn_wallet_copy.setProperty("secondary", True)

        row_btns.addWidget(self.btn_wallet_init)
        row_btns.addWidget(self.btn_wallet_load)
        row_btns.addWidget(self.btn_wallet_refresh)
        row_btns.addWidget(self.btn_wallet_copy)

        f.addRow("Address:", self.lbl_addr)
        f.addRow("Balance:", self.lbl_balance)
        f.addRow(row_btns)

        self.btn_wallet_init.clicked.connect(self._wallet_init)
        self.btn_wallet_load.clicked.connect(self._wallet_load)
        self.btn_wallet_refresh.clicked.connect(self._refresh_wallet_ui)
        self.btn_wallet_copy.clicked.connect(self._copy_my_wallet)

        lay.addWidget(wallet_box)

        # Send coins (simple)
        tx_box = QGroupBox("Send coins")
        tf = QFormLayout(tx_box)

        self.tx_to = QLineEdit()
        self.tx_to.setPlaceholderText("Recipient wallet address (or click ‘Use for payment’ on a peer)")
        self.tx_amount = QSpinBox()
        self.tx_amount.setRange(1, 1_000_000_000)
        self.tx_amount.setValue(1)
        self.tx_memo = QLineEdit()
        self.tx_memo.setPlaceholderText("(optional) memo")

        self.tx_file = QLineEdit()
        self.tx_file.setPlaceholderText("(optional) attach a file")
        self.btn_pick_tx_file = QPushButton("Pick file")
        self.btn_pick_tx_file.setProperty("secondary", True)

        attach_row = QHBoxLayout()
        attach_row.addWidget(self.tx_file, 1)
        attach_row.addWidget(self.btn_pick_tx_file)

        self.btn_make_tx = QPushButton("Send")
        self.btn_make_tx.setToolTip("Create + submit a transaction to your local mempool.")
        self.btn_make_tx.setProperty("secondary", True)

        self.tx_output = QTextEdit()
        self.tx_output.setReadOnly(True)
        self.tx_output.setPlaceholderText("Transaction output…")

        tf.addRow("To:", self.tx_to)
        tf.addRow("Amount:", self.tx_amount)
        tf.addRow("Memo:", self.tx_memo)
        tf.addRow("Attachment:", attach_row)
        tf.addRow(self.btn_make_tx)
        tf.addRow("Output:", self.tx_output)

        self.btn_pick_tx_file.clicked.connect(self._pick_tx_file)
        self.btn_make_tx.clicked.connect(self._make_tx)

        lay.addWidget(tx_box)

        # Mining (keep simple + safer defaults)
        mine_box = QGroupBox("Mining (safe)")
        mf = QFormLayout(mine_box)

        self.mine_threads = QSpinBox()
        self.mine_threads.setRange(1, max(1, (os.cpu_count() or 4)))
        self.mine_threads.setValue(1)

        self.mine_intensity = QDoubleSpinBox()
        self.mine_intensity.setRange(0.05, 0.35)  # keep “safe-ish” in UI
        self.mine_intensity.setSingleStep(0.05)
        self.mine_intensity.setValue(0.18)

        row = QHBoxLayout()
        self.btn_mine_start = QPushButton("Start")
        self.btn_mine_start.setProperty("secondary", True)
        self.btn_mine_stop = QPushButton("Stop")
        self.btn_mine_stop.setProperty("secondary", True)
        row.addWidget(self.btn_mine_start)
        row.addWidget(self.btn_mine_stop)

        self.lbl_mine_status = QLabel("Not running")
        self.lbl_mine_status.setProperty("muted", True)

        mf.addRow("Threads:", self.mine_threads)
        mf.addRow("Intensity:", self.mine_intensity)
        mf.addRow(row)
        mf.addRow("Status:", self.lbl_mine_status)

        self.btn_mine_start.clicked.connect(self._mine_start)
        self.btn_mine_stop.clicked.connect(self._mine_stop)

        lay.addWidget(mine_box)
        lay.addStretch(1)
        return w

    # ---------------- core ticks ----------------
    def _tick_presence(self) -> None:
        try:
            STATE.p2p.broadcast_presence()
        except Exception:
            pass

    def _tick_peers(self) -> None:
        try:
            res = run_block("rooms", "", {"action": "peers"})
            peers = res.get("peers", []) or []
            self._peers = peers

            self.peers_list.blockSignals(True)
            self.peers_list.clear()

            for p in peers:
                name = str(p.get("name", "?") or "?")
                room = str(p.get("room", "?") or "?")
                addr = str(p.get("wallet_addr", "") or "")
                # show a subtle indicator if wallet is available
                badge = " • wallet" if addr else ""
                item = QListWidgetItem(f"{name}  #{room}{badge}")
                item.setData(Qt.UserRole, p.get("user_id", ""))
                self.peers_list.addItem(item)

            self.peers_list.blockSignals(False)

            # Keep selection if possible
            if self._selected_peer:
                uid = self._selected_peer.get("user_id")
                if uid:
                    self._reselect_peer(uid)

        except Exception:
            pass

    def _tick_feed(self) -> None:
        # Room
        try:
            res = run_block("public_chat", "", {"action": "feed"})
            for m in res.get("messages", []):
                self._append_room_msg(m)

            offers = res.get("file_offers", []) or []
            if offers:
                self._room_offers.extend(offers)
                self._room_offers = self._room_offers[-200:]
                self._refresh_offer_lists()

        except Exception:
            pass

        # DM
        try:
            res = run_block("private_chat", "", {"action": "feed"})
            for m in res.get("dms", []):
                self._append_dm_msg(m)

            offers = res.get("file_offers", []) or []
            if offers:
                self._dm_offers.extend(offers)
                self._dm_offers = self._dm_offers[-200:]
                self._refresh_offer_lists()

            for txp in res.get("tx_pushes", []) or []:
                self._append_dm_msg({
                    "from_name": txp.get("from_name", "?"),
                    "text": f"[TX WIRE RECEIVED]\n{txp.get('tx_wire','')}",
                })
        except Exception:
            pass

        # Mining status (light)
        try:
            st = run_block("mine", "", {"action": "status"})
            running = bool(st.get("running"))
            if running:
                self.lbl_mine_status.setText(f"Running • threads={st.get('threads')} • intensity={st.get('intensity')}")
            else:
                self.lbl_mine_status.setText("Not running")
            st = run_block("mine", "", {"action": "status"})
            if st.get("running"):
                self.lbl_mine_status.setText(
                    f"Running • threads={st.get('threads')} • intensity={st.get('intensity')}")
            else:
                err = st.get("last_error")
                if err:
                    self.lbl_mine_status.setText("Crashed (see last_error)")
                    self.room_log.append(f"<pre>{safe_text(err, 8000)}</pre>")
                else:
                    self.lbl_mine_status.setText("Not running")
        except Exception:
            pass

    # ---------------- messages / offers ----------------
    def _append_room_msg(self, m: Dict[str, Any]) -> None:
        name = safe_text(m.get("from_name", "unknown"), 64)
        text = safe_text(m.get("text", ""), 4000)
        self.room_log.append(f"<b>{name}</b>: {text}")

    def _append_dm_msg(self, m: Dict[str, Any]) -> None:
        text = safe_text(m.get("text", ""), 4000)
        from_name = safe_text(m.get("from_name", "unknown"), 64)
        from_uid = str(m.get("from_user_id", "") or "")
        to_uid = str(m.get("to_user_id", "") or "")
        direction = str(m.get("direction", "") or "")

        if direction == "out" or (from_uid and from_uid == self._my_user_id):
            to_name = str(m.get("to_name", "") or "") or self._selected_peer_name()
            label = f"You → {safe_text(to_name, 64) or 'peer'}"
        elif direction == "in" or (to_uid and to_uid == self._my_user_id):
            label = f"{from_name} → You"
        else:
            label = from_name

        self.dm_log.append(f"<b>{label}</b>: {text}")

    def _refresh_offer_lists(self) -> None:
        self.room_offers_list.clear()
        for o in self._room_offers[-120:]:
            size = int(o.get("size", 0) or 0)
            self.room_offers_list.addItem(f"{o.get('from_name','?')}: {o.get('filename','file')} ({human_bytes(size)})")

        self.dm_offers_list.clear()
        for o in self._dm_offers[-120:]:
            size = int(o.get("size", 0) or 0)
            self.dm_offers_list.addItem(f"{o.get('from_name','?')}: {o.get('filename','file')} ({human_bytes(size)})")

    # ---------------- sidebar actions ----------------
    def _join_room(self) -> None:
        room = (self.room_edit.text() or "general").strip()
        if not room:
            room = "general"
        try:
            run_block("rooms", "", {"action": "join", "room": room})
            self.room_log.append(f"<i>Joined room #{room}</i>")
            self._room_offers.clear()
            self._refresh_offer_lists()
        except Exception as e:
            QMessageBox.warning(self, "Join failed", str(e))

    def _jump_to_dm_tab(self) -> None:
        self.tabs.setCurrentWidget(self.dm_tab)
        self.dm_input.setFocus()

    def _selected_peer_name(self) -> str:
        if self._selected_peer:
            return str(self._selected_peer.get("name", "peer") or "peer")
        return "peer"

    def _reselect_peer(self, uid: str) -> None:
        for i in range(self.peers_list.count()):
            it = self.peers_list.item(i)
            if it and it.data(Qt.UserRole) == uid:
                self.peers_list.setCurrentItem(it)
                break

    def _on_peer_selected(self) -> None:
        items = self.peers_list.selectedItems()
        if not items:
            self._selected_peer = None
            self._set_peer_card(None)
            self.btn_dm_peer.setEnabled(False)
            self.dm_info.setText("Select a peer to start a direct message.")
            return

        uid = str(items[0].data(Qt.UserRole) or "")
        peer = None
        for p in self._peers:
            if str(p.get("user_id", "")) == uid:
                peer = p
                break

        self._selected_peer = peer
        self._set_peer_card(peer)
        self.btn_dm_peer.setEnabled(bool(peer))
        self.dm_info.setText(f"DM with: {self._selected_peer_name()}")

    # ---------------- peer card / avatar ----------------
    def _set_peer_card(self, peer: Optional[Dict[str, Any]]) -> None:
        if not peer:
            self.peer_avatar.setText("—")
            self.peer_avatar.setPixmap(QPixmap())
            self.peer_name_lbl.setText("No peer selected")
            self.peer_room_lbl.setText("")
            self.peer_wallet_lbl.setText("-")
            self.btn_copy_peer_addr.setEnabled(False)
            self.btn_use_peer_addr.setEnabled(False)
            return

        name = str(peer.get("name", "peer") or "peer")
        room = str(peer.get("room", "") or "")
        wallet_addr = str(peer.get("wallet_addr", "") or "")

        self.peer_name_lbl.setText(name)
        self.peer_room_lbl.setText(f"#{room}" if room else "")
        self.peer_wallet_lbl.setText(wallet_addr if wallet_addr else "(not shared)")

        self.btn_copy_peer_addr.setEnabled(bool(wallet_addr))
        self.btn_use_peer_addr.setEnabled(bool(wallet_addr))

        # Try to show avatar if possible (optional)
        self._update_peer_avatar(peer)

    def _update_peer_avatar(self, peer: Dict[str, Any]) -> None:
        # If we can’t download avatars, just show placeholder.
        if tcp_request_blob is None:
            self.peer_avatar.setText("🙂")
            return

        avatar_sha = str(peer.get("avatar_sha", "") or "")
        ip = str(peer.get("ip", "") or "")
        tcp_port = int(peer.get("tcp_port", 0) or 0)
        uid = str(peer.get("user_id", "") or "")

        if not uid or not ip or tcp_port <= 0:
            self.peer_avatar.setText("🙂")
            return

        # If no avatar on peer, show placeholder.
        if not avatar_sha:
            self.peer_avatar.setText("🙂")
            return

        av_dir = cache_dir() / "avatars"
        av_dir.mkdir(parents=True, exist_ok=True)

        # Cached by uid+sha
        cached = av_dir / f"{uid}_{avatar_sha}"
        # If any file exists with that prefix, use it
        existing = None
        for ext in (".png", ".jpg", ".gif", ".webp", ".bin"):
            p = Path(str(cached) + ext)
            if p.exists():
                existing = p
                break

        if existing:
            self._set_pixmap_label(self.peer_avatar, str(existing), 56)
            return

        # Download once, quietly.
        try:
            tmp_path = av_dir / f"{uid}_{avatar_sha}.tmp"
            req = {"t": "avatar_get"}
            tcp_request_blob(ip, tcp_port, req, str(tmp_path), expected_sha256=avatar_sha)

            # Normalize extension for QPixmap and cache
            ext = sniff_image_ext(str(tmp_path))
            final_path = Path(str(cached) + ext)
            try:
                if final_path.exists():
                    final_path.unlink()
            except Exception:
                pass
            tmp_path.rename(final_path)

            # Verify sha (extra safety)
            try:
                got = sha256_file(str(final_path))
                if got.lower() != avatar_sha.lower():
                    final_path.unlink(missing_ok=True)  # type: ignore
                    self.peer_avatar.setText("🙂")
                    return
            except Exception:
                pass

            self._set_pixmap_label(self.peer_avatar, str(final_path), 56)
        except Exception:
            self.peer_avatar.setText("🙂")

    def _set_pixmap_label(self, lbl: QLabel, path: str, size: int) -> None:
        px = QPixmap(path)
        if px.isNull():
            lbl.setText("🙂")
            lbl.setPixmap(QPixmap())
            return
        px = px.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        lbl.setPixmap(px)
        lbl.setText("")

    def _copy_peer_wallet(self) -> None:
        if not self._selected_peer:
            return
        addr = str(self._selected_peer.get("wallet_addr", "") or "")
        if not addr:
            return
        QApplication.clipboard().setText(addr)
        QMessageBox.information(self, "Copied", "Peer wallet address copied to clipboard.")

    def _use_peer_wallet_in_tx(self) -> None:
        if not self._selected_peer:
            return
        addr = str(self._selected_peer.get("wallet_addr", "") or "")
        if not addr:
            return
        self.tx_to.setText(addr)
        self.tabs.setCurrentWidget(self.wallet_tab)

    # ---------------- room actions ----------------
    def _send_room(self) -> None:
        text = self.room_input.text().strip()
        if not text:
            return
        try:
            res = run_block("public_chat", text, {"action": "send"})
            if not res.get("ok"):
                QMessageBox.warning(self, "Blocked", res.get("reason", "blocked"))
                return
            self.room_input.clear()
        except Exception as e:
            QMessageBox.warning(self, "Send failed", str(e))

    def _send_room_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file to share",
            "",
            "Files (*.png *.jpg *.jpeg *.webp *.gif *.wav *.mp3 *.flac *.ogg *.m4a *.aac *.mp4 *.mov *.mkv *.webm *.txt *.pdf *.zip);;All files (*)",
        )
        if not path:
            return
        try:
            res = run_block("public_chat", "", {"action": "share_file", "path": path, "note": ""})
            self.room_log.append(f"<i>Shared file: {safe_text(res.get('filename','file'), 128)}</i>")
        except Exception as e:
            QMessageBox.warning(self, "File share blocked/failed", str(e))

    def _download_room_offer(self) -> None:
        idx = self.room_offers_list.currentRow()
        offer_slice = self._room_offers[-120:]
        if idx < 0 or idx >= len(offer_slice):
            return
        offer = offer_slice[idx]
        save_path = str(downloads_dir() / offer.get("filename", "file"))
        try:
            run_block("public_chat", json.dumps(offer), {"action": "download", "save_path": save_path})
            QMessageBox.information(self, "Downloaded", f"Saved to:\n{save_path}")
            if is_image(save_path):
                self._show_image_preview(save_path)
        except Exception as e:
            QMessageBox.warning(self, "Download failed", str(e))

    # ---------------- dm actions ----------------
    def _send_dm(self) -> None:
        if not self._selected_peer:
            QMessageBox.information(self, "Direct message", "Select a peer first.")
            return

        text = self.dm_input.text().strip()
        if not text:
            return

        to_user_id = str(self._selected_peer.get("user_id", "") or "")
        if not to_user_id:
            QMessageBox.warning(self, "Direct message", "Selected peer is missing user_id.")
            return

        try:
            res = run_block("private_chat", text, {"action": "send", "to_user_id": to_user_id})
            if not res.get("ok"):
                QMessageBox.warning(self, "Blocked", res.get("reason", "blocked"))
                return

            # show outgoing immediately
            self._append_dm_msg({
                "direction": "out",
                "from_user_id": self._my_user_id,
                "from_name": self._my_name,
                "to_user_id": to_user_id,
                "to_name": self._selected_peer_name(),
                "text": text,
            })

            self.dm_input.clear()
        except Exception as e:
            QMessageBox.warning(self, "DM failed", str(e))

    def _send_dm_file(self) -> None:
        if not self._selected_peer:
            QMessageBox.information(self, "Direct message", "Select a peer first.")
            return

        to_user_id = str(self._selected_peer.get("user_id", "") or "")
        if not to_user_id:
            QMessageBox.warning(self, "Direct message", "Selected peer is missing user_id.")
            return

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file to send",
            "",
            "Files (*.png *.jpg *.jpeg *.webp *.gif *.wav *.mp3 *.flac *.ogg *.m4a *.aac *.mp4 *.mov *.mkv *.webm *.txt *.pdf *.zip);;All files (*)",
        )
        if not path:
            return

        try:
            res = run_block("private_chat", "", {"action": "share_file", "to_user_id": to_user_id, "path": path, "note": ""})
            self._append_dm_msg({
                "direction": "out",
                "from_user_id": self._my_user_id,
                "from_name": self._my_name,
                "to_user_id": to_user_id,
                "to_name": self._selected_peer_name(),
                "text": f"[FILE OFFER SENT] {safe_text(res.get('filename','file'), 128)}",
            })
        except Exception as e:
            QMessageBox.warning(self, "File send blocked/failed", str(e))

    def _download_dm_offer(self) -> None:
        idx = self.dm_offers_list.currentRow()
        offer_slice = self._dm_offers[-120:]
        if idx < 0 or idx >= len(offer_slice):
            return
        offer = offer_slice[idx]
        save_path = str(downloads_dir() / offer.get("filename", "file"))
        try:
            run_block("private_chat", json.dumps(offer), {"action": "download", "save_path": save_path})
            QMessageBox.information(self, "Downloaded", f"Saved to:\n{save_path}")
            if is_image(save_path):
                self._show_image_preview(save_path)
        except Exception as e:
            QMessageBox.warning(self, "Download failed", str(e))

    def _open_downloads_folder(self) -> None:
        p = downloads_dir()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))

    # ---------------- profile ----------------
    def _pick_avatar(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Pick avatar", "", "Images (*.png *.jpg *.jpeg *.webp *.gif)")
        if not path:
            return
        self._pending_avatar = path
        self._set_avatar_preview(path)

    def _save_profile(self) -> None:
        name = (self.name_edit.text() or "anon").strip()[:64]
        avatar_path = getattr(self, "_pending_avatar", "")
        try:
            run_block("account", "", {"action": "set", "name": name, "avatar_path": avatar_path})
            self._pending_avatar = ""
            self._refresh_profile_ui()
            # presence may include avatar/wallet info; refresh it
            try:
                STATE.p2p.broadcast_presence()
            except Exception:
                pass
        except Exception as e:
            QMessageBox.warning(self, "Save failed", str(e))

    def _refresh_profile_ui(self) -> None:
        cfg = load_account()
        self.name_edit.setText(cfg.get("name", "anon"))
        ap = cfg.get("avatar_path", "")
        if ap and os.path.exists(ap):
            self._set_avatar_preview(ap)
        else:
            self.avatar_label.setText("No\nAvatar")
            self.avatar_label.setPixmap(QPixmap())

    def _set_avatar_preview(self, path: str) -> None:
        px = QPixmap(path)
        if px.isNull():
            self.avatar_label.setText("Bad\nImage")
            self.avatar_label.setPixmap(QPixmap())
            return
        px = px.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.avatar_label.setPixmap(px)
        self.avatar_label.setText("")

    def _show_image_preview(self, path: str) -> None:
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Image Preview")
        px = QPixmap(path)
        if not px.isNull():
            px = px.scaled(520, 520, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            dlg.setIconPixmap(px)
        dlg.setText(path)
        dlg.exec_()

    # ---------------- wallet / mining / tx ----------------
    def _wallet_init(self) -> None:
        try:
            run_block("wallet", "", {"action": "init"})
            # ensure identity/presence gets updated wallet addr
            run_block("account", "", {"action": "ensure"})
            self._refresh_wallet_ui()
            try:
                STATE.p2p.broadcast_presence()
            except Exception:
                pass
        except Exception as e:
            QMessageBox.warning(self, "Wallet create failed", str(e))

    def _wallet_load(self) -> None:
        try:
            run_block("wallet", "", {"action": "load"})
            run_block("account", "", {"action": "ensure"})
            self._refresh_wallet_ui()
            try:
                STATE.p2p.broadcast_presence()
            except Exception:
                pass
        except Exception as e:
            QMessageBox.warning(self, "Wallet load failed", str(e))

    def _refresh_wallet_ui(self) -> None:
        try:
            addr = run_block("wallet", "", {"action": "address"}).get("address", "-")
            b = run_block("wallet", "", {"action": "balance"})

            confirmed = int(b.get("confirmed", 0) or 0)
            available = int(b.get("available", confirmed) or 0)
            pin = int(b.get("pending_in", 0) or 0)
            pout = int(b.get("pending_out", 0) or 0)

            self.lbl_addr.setText(str(addr))
            self.lbl_balance.setText(f"{available} avail • {confirmed} conf • +{pin}/-{pout} pending")
        except Exception:
            self.lbl_addr.setText("(no wallet)")
            self.lbl_balance.setText("-")

    def _copy_my_wallet(self) -> None:
        addr = self.lbl_addr.text().strip()
        if not addr or addr.startswith("(") or addr == "-":
            return
        QApplication.clipboard().setText(addr)
        QMessageBox.information(self, "Copied", "Your wallet address copied to clipboard.")

    def _mine_start(self) -> None:
        try:
            res = run_block("mine", "", {
                "action": "start",
                "safe": True,
                "threads": int(self.mine_threads.value()),
                "intensity": float(self.mine_intensity.value()),
                "work_s": 6.0,
                "rest_s": 3.0,
                "hps_cap": 25000,
                "yield_every": 2000,
            })

            if not res.get("running"):
                # If lock busy, try force once (stale lock is common)
                if res.get("reason") == "miner_lock_busy":
                    res2 = run_block("mine", "", {
                        "action": "start",
                        "safe": True,
                        "force": True,
                        "threads": int(self.mine_threads.value()),
                        "intensity": float(self.mine_intensity.value()),
                        "work_s": 6.0,
                        "rest_s": 3.0,
                        "hps_cap": 25000,
                        "yield_every": 2000,
                    })
                    if not res2.get("running"):
                        QMessageBox.warning(self, "Mining", "Did not start:\n" + json.dumps(res2, indent=2))
                    return

                QMessageBox.warning(self, "Mining", "Did not start:\n" + json.dumps(res, indent=2))

        except Exception as e:
            QMessageBox.warning(self, "Mining start failed", str(e))

    def _mine_stop(self) -> None:
        try:
            run_block("mine", "", {"action": "stop"})
        except Exception as e:
            QMessageBox.warning(self, "Mining stop failed", str(e))

    def _pick_tx_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Pick attachment",
            "",
            "Files (*.png *.jpg *.jpeg *.webp *.gif *.wav *.mp3 *.flac *.ogg *.m4a *.aac *.mp4 *.mov *.mkv *.webm *.txt *.pdf *.zip);;All files (*)",
        )
        if not path:
            return
        self.tx_file.setText(path)

    def _make_tx(self) -> None:
        to_addr = self.tx_to.text().strip()
        if not to_addr:
            QMessageBox.information(self, "Send coins", "Enter a recipient wallet address (or select a peer and click ‘Use for payment’).")
            return

        try:
            params = {
                "action": "create",
                "to_addr": to_addr,
                "amount": int(self.tx_amount.value()),
                "memo": self.tx_memo.text().strip(),
                "file_path": self.tx_file.text().strip(),
                "auto_submit": True,
            }
            tx = run_block("transaction", "", params)
            try:
                if self._selected_peer:
                    peer_uid = str(self._selected_peer.get("user_id", "") or "")
                    peer_addr = str(self._selected_peer.get("wallet_addr", "") or "")
                    if peer_uid and peer_addr and peer_addr == to_addr:
                        wire = run_block("transaction", json.dumps(tx), {"action": "wire"}).get("wire", "")
                        if wire:
                            run_block("transaction", wire, {"action": "push_to_peer", "to_user_id": peer_uid})
            except Exception:
                pass
            self._last_tx_json = tx
            self.tx_output.setPlainText(json.dumps(tx, indent=2))
            # refresh balance quickly
            self._refresh_wallet_ui()

        except Exception as e:
            QMessageBox.warning(self, "Transaction failed", str(e))


def main() -> None:
    app = QApplication([])
    app.setStyleSheet(APP_STYLESHEET)
    w = MainWindow()
    w.show()
    app.exec_()


if __name__ == "__main__":
    main()
