# P2P Community App (Block-based)
<img width="1112" height="950" alt="Screenshot 2026-02-16 220227" src="https://github.com/user-attachments/assets/9cfe4389-67e8-4a2f-949b-3c81462dfb64" />

RUNNING SERVER!!! on IP: 170.253.163.90:38888

# P2P Community App (Block-based)

A small **LAN-first** community app that works **without a central server**, with an optional “Lighthouse” relay layer for harder networks (different routers / NAT).

It’s built around **Blocks** (each feature is a block) and ships with a **PyQt5 GUI**.

---

## What it does

### Presence + Discovery
- **LAN multicast discovery** (who’s online, name, avatar, current room)
- Peer “staleness” handling + periodic peerlist refresh (keeps the online list accurate)
- Multi-instance friendly: clients bind TCP on an **ephemeral port** so multiple copies can run on one machine

### Chat
- **Public room chat** (join/create rooms)
- **Private DMs**
  - UI-friendly message labeling (sender/receiver fields)
  - Local echo for outgoing items so you see what you sent immediately

### File sharing
- Share + download files via **File Offers**
- Supported types:
  - Images: `.png .jpg .jpeg .webp .gif`
  - Audio: `.wav .mp3 .flac .ogg .m4a .aac`
  - Video: `.mp4 .mov .mkv .webm`
  - Docs/Archives: `.txt .pdf .zip`
- Safe handling:
  - Allowlist extensions
  - Max-size enforcement
  - Hash blocklist
  - Optional simple image heuristics (best-effort)

### Coin / Ledger (local)
- **Local wallet**
- **Local ledger** with mining rewards
- **Transaction wire pushes** (share a tx to a peer over P2P)
- Transactions can include **optional attachment metadata**
  - Receiver UI can surface a “Download attachment” action when a tx includes an attachment
- Optional **ledger tip** included on pushes to help peers sync quickly

---

## Lighthouse (cross-router / relay support)

When direct peer-to-peer TCP is blocked (different routers, strict NAT, etc.), the app can use **Lighthouses**:

- A **Lighthouse Server** can relay:
  - presence/peer reachability help
  - **DMs**
  - **tx_push** messages
  - **file fetches** (via relay file get)
- Safety caps for relayed files (size limits + chunking)
- Optional **LAN bridge fallback**:
  - If you don’t have a lighthouse connected, a reachable LAN peer can act as a bridge relay for certain message types (best-effort)

> This keeps the app “no central server” by default, but gives you a practical path to connect across tougher networks.

---

## Protection / Safety notes
- **ChatProtection**: anti-spam, banned words/regex, slur-hash detection
- **FileProtection**: extension allowlist, size caps, hash blocklist
- Hard caps to avoid “json bombs”, runaway message sizes, and accidental packet storms
- **Important real-world note:** this is not a secure messenger. Treat it as **local-network convenience**, and don’t expose the TCP port to the public internet without adding real authentication/encryption.

---

## Install
```bash
pip install -r requirements.txt
