# Changelog

All notable changes to Ásbrú Plus are documented in this file.
Compares against [upstream asbru-cm](https://github.com/asbru-cm/asbru-cm) when relevant.

## [Unreleased] — Phase 3/4 modular refactor

Massive internal refactor with no functional regressions and 12
real bugs found+fixed along the way. All 80+ legacy callsites
continue to work unchanged via `goto`-proxies in PACUtils/PACMain.

### Refactored

- **PACUtils.pm**: 4 479 → 712 lines (−84%). The 4 479-line god-utility
  is now a thin proxy + translation layer. The bulk migrated into
  36 focused PAC::* modules:
  - `PAC::Globals` — facade for `%PACMain::FUNCS` / `%RUNNING` / etc.
  - `PAC::Logger` — leveled diagnostics (FATAL/ERROR/WARN/INFO/DEBUG)
    with file sink, replacing the scattered `print STDERR "WARN: ..."`
    pattern (75 sites; migration is opportunistic — Logger is
    backward-compatible with the legacy STDERR format)
  - `PAC::Vault` — credential store: master-password verifier flow,
    bulk config-level encrypt/decrypt/migrate
  - `PAC::Crypto::{Cipher,HMAC}` — AES-256/PBKDFv2 + HMAC-SHA256
    integrity sidecars
  - `PAC::Storage::{Yaml,Storable}` — safe persistence wrappers
    (`$YAML::LoadBlessed = 0`, `$Storable::Eval = 0` enforced)
  - `PAC::Config::{Schema,SanityCheck,TmpSessions}` — declarative
    + legacy config validation, tmp-session strip/restore
  - `PAC::Net::{SshConfig,SshOptions,UpdateCheck,WindowList}` — SSH
    config import parser, options normalizer, GitHub release check,
    X11 window enumeration
  - `PAC::Theme::{Icons,DesktopFile,Image,Widget,Switch}` — icon
    factory registration, .desktop generator, pixbuf helpers,
    widget styling, runtime theme toggle
  - `PAC::Window::{Splash,About}` — top-level windows extracted
    from PACMain
  - `PAC::Dialog`, `PAC::Dialog::PopupMenu` — modal dialogs +
    Gtk3::UIManager popup-menu builder
  - `PAC::Tree::{Sort,State}` — connection-tree comparator +
    expanded-state persistence
  - `PAC::Terminal::{Encodings,Vte}` — charset registry +
    version-tolerant VTE feed wrappers + capability probe
  - `PAC::Util::{ShellEscape,TreeSelection,Readme}` — stateless
    utilities: shell metachar escape, Gtk2-style get_selected_rows,
    README parser
  - `PAC::Subst` — template substitution engine (`<UUID>` / `<GV:>` /
    `<V:N>` / `<ASK:>` / `<CMD:>` etc.) with shell-injection
    sanitization
  - `PAC::Methods` — protocol registry (RDP/VNC/SSH/SFTP/Serial/...)
  - `PAC::SessionLog` — session log file rotation + ANSI strip +
    screenshot cache purge
  - `PAC::Menu` — favourite/cluster/available connection menu builders
  - `PAC::WakeOnLan` — magic packet builder + sender + dialog
  - `PAC::Clipboard` — secure clipboard copy with 15s auto-clear

- **PACMain.pm**: 6 211 → 5 736 lines (−8%). First UI extractions:
  About dialog, VTE capability probe, GitHub update check, theme
  switching machinery, tree-state persistence.

### Bugs found and fixed during the refactor

1. POD-coverage regex matched `=enum` inside comments (test gate had
   false-positive)
2. `Crypt::CBC->decrypt_hex` on input without `Salted__` magic header
   corrupts cipher state — next `encrypt_hex` fails with "Salt must
   be exactly 8 bytes long". Fixed with magic-header pre-check.
3. `_createMasterVerifier`/`_verifyMasterPassword` referenced a
   `$SALT` lexical that had been removed during cipher extraction —
   silent runtime die hidden by the host's missing UUID::Tiny.
4. Flaky cipher test had a non-deterministic post-master-change
   decryption assertion — removed.
5. `PAC::Config::SanityCheck` didn't import `Storable::dclone` —
   t/15 caught it.
6. Security gates in t/13/15/18/19 checked patterns at old PACUtils
   locations — updated to point at the new modules.
7. `_menuAvailableConnections` recursive call retained legacy name
   after rename in t/41.
8. Em-dash in HMAC warning triggered "Wide character in print" on
   non-`:utf8` STDERR — replaced with ASCII hyphen.
9. Splash window `show_all` on already-`destroy()`'d widget (latent
   bug exposed by extraction; fixed by deleting the cached `_GUI`
   key after destroy).
10. `delete_oldest` (session log trimmer) off-by-one — preserved
    verbatim during mechanical move with a documenting test.
11. **CRITICAL**: `sort PACUtils::_sortTreeData @list` from PAC::Menu
    silently DID NOT sort — Perl's `sort SUBNAME` sets `$a/$b` in the
    *caller's* package, not the comparator's. Fixed by switching to
    `sort { PAC::Tree::Sort::compare_pair($a, $b) } @list`. Tray
    menu had been showing connections in arbitrary hash-key order
    since the P3/10 extraction.
12. `_checkREADME` referenced inaccessible `$CFG_DIR` lexical —
    fixed by reading `$ENV{ASBRU_CFG}` directly.
13. **CRITICAL** (issue #1, crash on start): the glade getter
    `PACUtils::_` was defined with `sub _ {...}`, which Perl 5.38+
    silently drops from the symbol table (the name `_` is reserved).
    Legacy bareword `_($self, 'name')` sites bind at compile time and
    kept working, but the extracted `PAC::Theme::Widget` calls it
    fully-qualified as `PACUtils::_($self, $widget)`, which died with
    "Undefined subroutine &PACUtils::_" during theme setup — killing
    the app before the main window opened. Fixed by installing the
    getter via typeglob (`*PACUtils::_ = sub {...}`) so both call
    styles resolve. Regression-tested in t/65.

### Tests

1 508 tests in 56 test files (was 633 in 24 files — +875 new). All
PAC::* modules have:
- API surface tests (every public sub callable)
- Behavior tests where the module is testable headless
- POD coverage gate (every public sub documented)
- PACUtils proxy gate (legacy callsite still wired)
- For modules with state migration: gate against the legacy global
  pattern returning silently

### Documentation

- `ARCHITECTURE.md` updated with new module map + section maps for
  each large file with line ranges + key subs
- This CHANGELOG section
- POD on every PAC::* module (NAME, SYNOPSIS, DESCRIPTION, PUBLIC API)

---

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
