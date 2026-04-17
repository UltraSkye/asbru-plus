# Changelog

All notable changes to Ásbrú Plus are documented in this file.
Compares against [upstream asbru-cm](https://github.com/asbru-cm/asbru-cm) when relevant.

## [6.5.0] — 2026-04-17

First tagged release of Ásbrú Plus on top of upstream `asbru-cm` 6.4.2.
Carries a security-hardening track that won't be upstreamed plus a set of
new features and bug fixes contributed back to upstream where applicable.

### Added

- **`Import from ~/.ssh/config`** — new tree context-menu entry that
  bulk-imports SSH hosts from an OpenSSH client config file. Skips
  wildcard `Host *` blocks, `Match` blocks, and `Include` directives.
  Honors `HostName`, `Port`, `User`, `IdentityFile`. Closes upstream
  [#1017](https://github.com/asbru-cm/asbru-cm/issues/1017).
- **Keep connection alive** — one-click checkbox in the SSH connection
  panel that adds `-o ServerAliveInterval=60 -o ServerAliveCountMax=3`,
  preventing idle NAT/firewall drops. Closes upstream
  [#728](https://github.com/asbru-cm/asbru-cm/issues/728).
- **Disable bold** — terminal preference that calls VTE's
  `set_allow_bold(false)`. Useful with small fonts or low-contrast
  themes. Closes upstream [#149](https://github.com/asbru-cm/asbru-cm/issues/149).
- **Hide the Info tab** — preference that detaches the welcome tab so
  Ctrl+PageUp/PageDown doesn't cycle through it. Closes upstream
  [#1082](https://github.com/asbru-cm/asbru-cm/issues/1082).
- **Active SSH port forwards in status tooltip** — when a connection
  becomes active, the green status icon's tooltip lists any `-L / -R / -D`
  declarations from the SSH options string. Closes upstream
  [#742](https://github.com/asbru-cm/asbru-cm/issues/742).
- **Disable pseudo-terminal allocation** — adds `-T` checkbox in SSH
  connection panel. Ported from upstream
  [`6a7e6c9`](https://github.com/asbru-cm/asbru-cm/commit/6a7e6c9).
- **`<<ASK_PASS>>` as generic subst keyword** — interactive password
  prompt available in any field that goes through `_subst()`, not just
  the password field. Generalized from upstream
  [`34fd758`](https://github.com/asbru-cm/asbru-cm/commit/34fd758).
- **Escape sequences `\n \r \t` in commands** — multi-line `send`/`local
  command` fields now honor literal escapes. Ported from upstream
  [`ca69266`](https://github.com/asbru-cm/asbru-cm/commit/ca69266).
- **Session log rotation on reopen** — when the resolved log path
  already exists at session start, an `.HHMMSS` suffix is appended
  instead of overwriting. Closes upstream
  [#1009](https://github.com/asbru-cm/asbru-cm/issues/1009).

### Fixed

- **Wide-char warning in `asbru_conn`** — STDERR now uses `:utf8`
  layer so diagnostic messages with multi-byte chars don't trigger
  `Wide character in print` warnings (related to upstream
  [#1188](https://github.com/asbru-cm/asbru-cm/issues/1188)).
- **Compact-mode crash on `btnShowButtonBar`** — guarded
  `set_image()` call that throws when the button isn't built in
  compact mode. Ported from upstream
  [`954c7cc`](https://github.com/asbru-cm/asbru-cm/commit/954c7cc),
  closes upstream [#1189](https://github.com/asbru-cm/asbru-cm/issues/1189).
- **Zoom in/out drift** — replaced floating-point arithmetic with
  integer-based scaling (`(100*scale±10)/100`). Ported from upstream
  [`a9b61cb`](https://github.com/asbru-cm/asbru-cm/commit/a9b61cb),
  closes upstream [#1136](https://github.com/asbru-cm/asbru-cm/issues/1136).
- **Manual data entry cancellation** — cancelling a `WENTER` prompt
  no longer pushes `undef` into the socket protocol.
- **VTE feature detection** — replaced version-number checks with
  runtime `eval` probes for `match_add_regex` and
  `get_text_range_format`, so the same binary works against any VTE
  version without hardcoded version gates.
- **SSH jump host authentication** — generated SSH config no longer
  pins `PreferredAuthentications=publickey` on the jumphost, so
  user-selected auth method takes effect. Closes upstream
  [#1027](https://github.com/asbru-cm/asbru-cm/issues/1027).

### Security

(Carried over from the asbru-plus security-hardening track.)

- AES-256 + opensslv2 PBKDF (10 000+ iterations) replacing legacy
  Blowfish-64 + 1-iteration PBKDF for credential storage.
- Master-password-derived key for credential vault, with automatic
  migration of existing connections.
- HMAC-SHA256 integrity verification on config files.
- `flock(LOCK_EX)` on config save to prevent corruption.
- List-form `exec()` / `IPC::Open3` for xdg-open, VNC password,
  RDP password, KeePass CLI, gsettings — closes shell-injection
  vectors.
- Async-safe re-entrancy protection in `asbru_conn` signal handlers.
- `chmod 0600` on credential-containing temp files.
- UUID format validation in `asbru_conn` to prevent path traversal.
- Proxy credentials passed via env var, not visible in `ps aux`.
- SSH option whitelist blocks `ProxyCommand`, `LocalCommand`,
  `PermitLocalCommand`.
- `<CMD:...>` template variables restricted to safe characters;
  blocks pipes, subshells, redirections, `eval`.
- `--dump-uuid` redacts plaintext passwords by default.
- Storable RCE gate; vault constant-time comparison.

### Build / packaging

- **AppImage** — now built in CI as part of every release, alongside
  `.deb` and `.rpm`.
- **One-line installer** — `install.sh` auto-detects distro and
  fetches the matching artifact:
  ```
  curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash
  ```
- **Package matrix**: Debian Bullseye/Bookworm/Trixie, Ubuntu
  Jammy/Noble, RHEL 8, AlmaLinux 9, Fedora 39.
- **Replaced `OSSP::uuid` with `UUID::Tiny`** — pure-Perl, no system
  library dependency, works out-of-the-box on Ubuntu 24.04+.
  Different approach from upstream's
  [`338b482`](https://github.com/asbru-cm/asbru-cm/commit/338b482)
  (Data::UUID).

### Tests

- 540+ tests across 23 files covering: security hardening,
  cryptography, config integrity, SSH config import, dark-mode
  detection, Wayland routing, dump-uuid redaction, vault scaffold,
  and dead-asset gates.
- New `t/23-ssh-config-import.t` — 20 cases for the SSH config parser.

---

For changes prior to the asbru-plus fork, see upstream's
[Changelog](https://docs.asbru-cm.net/General/Changelog/).
