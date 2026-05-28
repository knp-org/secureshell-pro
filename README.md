# SecureShell Pro

SecureShell Pro is a desktop SSH workspace for managing remote hosts, private keys, reusable command snippets, terminal sessions, and encrypted LAN sync with the Android companion app.

The app is built for users who work across multiple servers and need a private, organized, local-first SSH environment. Connection data stays on the device by default, sensitive credentials are protected by the vault, and paired devices can sync over the local network without relying on a cloud account.

## Features

- Manage SSH hosts with labels, authentication settings, tags, and saved connection details.
- Store SSH keys and host passwords in an encrypted local vault.
- Open interactive terminal sessions with tabbed session management.
- Save reusable command snippets and run them from the terminal.
- Use runtime snippet variables such as `{{host}}` or `{{service}}` and fill them just before execution.
- Organize snippets into folders and map snippets to specific hosts.
- Pair with the Android app over LAN and sync hosts, keys, snippets, and groups.
- Use QR-based pairing and local network discovery for device setup.

## Security Model

SecureShell Pro uses a master-password-protected vault for sensitive SSH credentials. The vault stores encrypted secrets locally and requires unlock before protected values can be read or used.

LAN sync is designed for local trusted devices. Pairing establishes device trust, and sync transfers records between paired peers on the same network. The app does not require a hosted service for normal operation.

## Development

### Requirements

- Node.js and npm
- Rust and Cargo
- Tauri system dependencies for your Linux distribution

### Install Dependencies

```bash
npm install
```

### Run In Development

```bash
npm run dev
```

### Build Debian Package

```bash
npm run build:deb
```

The generated `.deb` package is written under:

```text
src-tauri/target/release/bundle/deb/
```

## Project Structure

```text
src/             Frontend HTML, CSS, and JavaScript
src-tauri/       Tauri and Rust backend
docs/            Sync and vault format notes
```

## License

Private project.
