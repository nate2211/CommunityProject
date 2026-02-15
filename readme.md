# P2P Community App (Block-based)

A small community app that runs without a central server:
- LAN multicast discovery (who's online + which room)
- P2P TCP for:
  - Direct messages
  - File offers + downloads (images/audio/video/docs)
  - Transaction wire pushes

The app is block-based (each feature is a Block) and includes a PyQt5 GUI.

## Features
- Profile: name + avatar
- Rooms: join/create room names
- Public room chat
- Private DM chat
- File sharing:
  - Images: .png/.jpg/.jpeg/.webp/.gif
  - Audio: .wav/.mp3/.flac/.ogg/.m4a/.aac
  - Video: .mp4/.mov/.mkv/.webm
  - Docs: .txt/.pdf/.zip
- Protection:
  - ChatProtection: anti-spam + banned words/regex + slur hash detection
  - FileProtection: allowlist ext, max size, hash blocklist, optional naive image heuristic
- Coin:
  - Local wallet
  - Local ledger + mining rewards
  - Transactions support optional file attachment metadata
  - Tx wire can be pushed to a peer over P2P (for sharing)

## Install
```bash
pip install -r requirements.txt
