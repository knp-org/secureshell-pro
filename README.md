# 🛡️ SecureShell Pro

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Platform: Linux · Windows](https://img.shields.io/badge/Platform-Linux%20·%20Windows-informational)]()
[![Built with Tauri 2](https://img.shields.io/badge/Built%20with-Tauri%202-ffc131?logo=tauri&logoColor=white)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen)]()

A private, local-first desktop SSH workspace for managing remote hosts, private keys, reusable command snippets, terminal sessions, SFTP file transfers, and encrypted LAN sync — all without a cloud account.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Host Manager** | Organize SSH hosts with labels, groups, tags, color codes, and saved connection details. |
| **Encrypted Vault** | Store SSH keys and passwords in an AES-256-GCM encrypted vault, protected by a master password derived with Argon2id. |
| **Tabbed Terminal** | Open multiple interactive SSH sessions in a tabbed terminal powered by xterm.js with local shell support. |
| **Command Snippets** | Save reusable command snippets, organize them into folders, and execute them directly in terminal sessions. |
| **Snippet Variables** | Use runtime variables like `{{host}}` or `{{service}}` that prompt for values just before execution. |
| **SFTP File Browser** | Browse, upload, download, rename, and manage remote files through an integrated dual-pane SFTP interface. |
| **LAN Sync** | Pair with the Android companion app via QR code and sync hosts, keys, snippets, and groups over your local network. |
| **SSH Key Management** | Import, manage, and auto-detect SSH keys from `~/.ssh` for seamless authentication. |

---

## 🔐 Security Model

- **Vault encryption** — All sensitive credentials (passwords, private keys, passphrases) are encrypted at rest using **AES-256-GCM** with keys derived from a master password via **Argon2id**.
- **Zero plaintext on disk** — The vault must be unlocked before any protected value can be read or used. Locking the vault clears the in-memory master key.
- **Master password rotation** — Change your master password at any time from **Settings → Security**. After verifying the current password, every stored secret is re-encrypted under a freshly derived key in a single atomic transaction, with an automatic database backup taken beforehand.
- **LAN sync** — Pairing uses **X25519 key exchange** and **Noise protocol** for encrypted peer-to-peer communication. Mobile peers authenticate via **HMAC-SHA256 challenge-response**. No cloud relay or hosted service is involved.
- **Local-first** — All connection data stays on the device by default. Nothing leaves the machine unless you explicitly pair and sync.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** (v20+) and **npm**
- **Rust** and **Cargo** (stable toolchain)
- **Tauri 2 system dependencies** for your Linux distribution:
  ```bash
  # Ubuntu / Debian
  sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev \
    librsvg2-dev patchelf libssl-dev libdbus-1-dev \
    libgtk-3-dev libsoup-3.0-dev javascriptcoregtk-4.1
  ```

### Install Dependencies

```bash
npm install
```

### Run in Development

```bash
npm run dev
```

### Build Packages

```bash
# Debian / Ubuntu (.deb)
npm run build:deb

# AppImage
npm run build:appimage

# All targets
npm run build:all
```

Build output is written to `src-tauri/target/release/bundle/`.

---

## 📁 Project Structure

```text
secureshell-pro/
├── src/                        # Frontend (HTML, CSS, JavaScript)
│   ├── index.html              # App shell
│   ├── js/
│   │   ├── api.js              # Tauri IPC wrapper
│   │   ├── app.js              # Entry point & routing
│   │   ├── titlebar.js         # Custom window titlebar
│   │   ├── components/         # Reusable UI components
│   │   ├── utils/              # Helpers, icons, clipboard, themes
│   │   └── views/              # View modules (hosts, terminal, sftp, etc.)
│   ├── styles/                 # CSS stylesheets
│   └── assets/                 # Fonts, icons, xterm.js
├── src-tauri/                  # Tauri & Rust backend
│   ├── src/
│   │   ├── main.rs             # App entry
│   │   ├── lib.rs              # Tauri plugin setup & command registration
│   │   ├── vault.rs            # Vault encrypt / decrypt / init / lock
│   │   ├── crypto.rs           # AES-GCM, Argon2id, key derivation
│   │   ├── db/                 # SQLite database & migrations
│   │   ├── commands/           # Tauri IPC command handlers
│   │   ├── ssh/                # SSH session management (PTY)
│   │   ├── sftp/               # SFTP session management
│   │   └── sync/               # LAN discovery, pairing, peer sync
│   ├── Cargo.toml
│   └── tauri.conf.json
├── .github/workflows/          # CI: build & release (Linux .deb + Windows .exe)
└── package.json
```

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` | Switch to Hosts |
| `Ctrl+2` | Switch to Terminal |
| `Ctrl+3` | Switch to Snippets |
| `Ctrl+4` | Switch to Keys |
| `Ctrl+5` | Switch to SFTP |
| `Ctrl+,` | Switch to Settings |
| `Ctrl+R` / `F5` | Reload app |

---

## 📦 CI / CD

Pushing a version tag (`v*`) triggers the GitHub Actions workflow which:

1. Builds a `.deb` package on Ubuntu 22.04
2. Builds a `.exe` (NSIS installer) on Windows
3. Creates a draft GitHub Release with both artifacts attached

---

## 📄 License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
