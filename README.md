# Ásbrú Plus

[![Build Packages](https://github.com/UltraSkye/asbru-plus/actions/workflows/build-snapshots.yml/badge.svg)](https://github.com/UltraSkye/asbru-plus/actions/workflows/build-snapshots.yml)
[![Tests](https://github.com/UltraSkye/asbru-plus/actions/workflows/test.yml/badge.svg)](https://github.com/UltraSkye/asbru-plus/actions/workflows/test.yml)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](#security-hardening)
[![License](https://img.shields.io/badge/License-GPL--3-blue.svg?style=flat)](LICENSE)

A community-maintained fork of [Ásbrú Connection Manager](https://github.com/asbru-cm/asbru-cm), actively developed for Ubuntu 24.04+ and modern Debian-based systems.

> The original project has been unmaintained since 2022. This fork picks up where it left off.

## What is Ásbrú Plus?

Ásbrú Plus is a **Linux desktop GUI** for managing remote connections — think of it as an open-source alternative to [MobaXterm](https://mobaxterm.mobatek.net/) or [SecureCRT](https://www.vandyke.com/products/securecrt/), but native to Linux.

It lets you organize, launch, and automate SSH, RDP, VNC, Telnet, and SFTP sessions from a single interface. You store all your servers, credentials, tunnels, and scripts in one place, and connect with a double-click.

**Platform:** Linux only. Requires a GTK3 desktop environment (GNOME, XFCE, KDE with GTK support, etc.).
Tested on Ubuntu 20.04–26.04, Debian 11/12/13, Fedora 39+, RHEL 8/9, AlmaLinux 9. **Does not run on Windows or macOS natively.**

> **Security note:** Ásbrú Plus stores credentials locally in `~/.config/asbru/`. If you manage access to sensitive production servers, consider running it inside a **dedicated VM or Docker container** rather than directly on your daily-use machine. This limits the blast radius if your desktop is ever compromised. See [Running in Docker](#running-in-docker) below.

## Features

- Manage SSH, RDP, VNC, Telnet, SFTP sessions from a single GUI
- Tabbed and windowed terminals with cluster support
- Expect-based login automation — chain SSH hops, auto-fill passwords, automate tunnels
- Pre/post connection local command execution
- Configurable macros sent to connected sessions
- [KeePassXC](https://keepassxc.org/) integration
- SOCKS5 proxy and SSH jump host support
- Dynamic SSH port forwarding
- Local and global variables (password vault, reusable strings)
- Session logging and statistics (now with auto-rotation on reopen)
- Wake on LAN
- GTK3 / GNOME integration with tray icon
- **Bulk-import** SSH connections from `~/.ssh/config`
- **Keep-alive** one-click toggle for SSH (`ServerAliveInterval=60`)
- **Active forwards** shown in connection status tooltip
- **Master password** vault with AES-256 + opensslv2 PBKDF (10 000 iter)
- **Dark mode auto-detection** (GNOME `color-scheme`, GTK_THEME fallback)
- **Wayland-aware** routing (auto-fallback to Xwayland for problem widgets)

## Installation

### Quick install (recommended)

One command, auto-detects your distro, downloads the matching package:

```bash
curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash
```

To install the development snapshot instead of the latest tagged release:

```bash
curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash -s -- --channel=snapshot
```

### AppImage (any Linux, no install)

```bash
curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash -s -- --appimage
```

Drops a single `asbru-plus.AppImage` into `~/.local/bin/`. Works on any glibc-based distro without root.

### Manual download

Released `.deb`, `.rpm`, and `.AppImage` artifacts are on the [Releases page](https://github.com/UltraSkye/asbru-plus/releases):

- `.deb` for Debian 11/12/13, Ubuntu 22.04/24.04/26.04
- `.rpm` for RHEL 8, AlmaLinux 9, Fedora 39
- `.AppImage` (universal Linux x86_64)

Then `sudo apt install ./asbru-plus_*.deb` or `sudo dnf install ./asbru-plus-*.rpm`.

### From source

```bash
git clone https://github.com/UltraSkye/asbru-plus.git
cd asbru-plus
./asbru-cm
```

You'll need the system dependencies — see [Manual dependencies](#manual-dependencies) below.

### Manual dependencies

Only needed if you're running from source.

<details>
<summary><b>Ubuntu / Debian</b></summary>

```bash
sudo apt-get install \
  perl libvte-2.91-0 libcairo-perl libglib-perl libpango-perl \
  libsocket6-perl libexpect-perl libyaml-perl libcrypt-cbc-perl \
  libcrypt-blowfish-perl libgtk3-perl libnet-arp-perl libuuid-tiny-perl \
  openssh-client libcrypt-rijndael-perl libxml-parser-perl \
  libcanberra-gtk-module dbus-x11 libgtk3-simplelist-perl \
  gir1.2-wnck-3.0 gir1.2-vte-2.91 ncat
```

Optional:

```bash
sudo apt-get install keepassxc telnet ftp freerdp3-x11 tigervnc-viewer mosh
```
</details>

<details>
<summary><b>Fedora / RHEL / AlmaLinux</b></summary>

```bash
sudo dnf install \
  perl vte291 perl-Gtk3 perl-Cairo perl-Glib perl-Pango \
  perl-Socket6 perl-Expect perl-YAML perl-Crypt-CBC \
  perl-Crypt-Blowfish perl-Net-ARP perl-UUID-Tiny \
  perl-Crypt-Rijndael perl-XML-Parser openssh-clients \
  dbus-x11 nmap-ncat
```

Optional:

```bash
sudo dnf install keepassxc freerdp tigervnc mosh
```
</details>

## Running in Docker

If you want to isolate Ásbrú Plus from your host system (recommended for managing access to sensitive servers), you can run it in a Docker container with X11 forwarding:

```bash
docker run -it --rm \
  --network host \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v "$HOME/.config/asbru:/root/.config/asbru" \
  ubuntu:24.04 bash -c "
    apt-get update -q && apt-get install -y --no-install-recommends \
      perl libvte-2.91-0 libcairo-perl libglib-perl libpango-perl \
      libsocket6-perl libexpect-perl libyaml-perl libcrypt-cbc-perl \
      libcrypt-blowfish-perl libgtk3-perl libnet-arp-perl libuuid-tiny-perl \
      openssh-client libcrypt-rijndael-perl libxml-parser-perl \
      libcanberra-gtk-module dbus-x11 libgtk3-simplelist-perl \
      gir1.2-wnck-3.0 gir1.2-vte-2.91 ncat git && \
    git clone https://github.com/UltraSkye/asbru-plus.git /opt/asbru-plus && \
    /opt/asbru-plus/asbru-cm
  "
```

Your configuration is persisted via the bind-mounted `~/.config/asbru` directory.
Allow the container access to your X server first: `xhost +local:docker`

`--network host` is needed so SSH local port forwards and SOCKS tunnels bind
to ports reachable from your host browser/tools.

## What's new in 6.5.0

User-facing additions ported from upstream and original to this fork:

- **Import from ~/.ssh/config** — right-click → bulk-import OpenSSH hosts
- **Keep connection alive** — checkbox in SSH options panel
- **Disable bold** — terminal preference for low-contrast themes
- **Hide Info tab** — preference; Ctrl+PgUp/Dn won't cycle through it
- **Active SSH forwards in tooltip** — green status icon now lists `-L/-R/-D`
- **Session log auto-rotation** — appends `.HHMMSS` instead of overwriting
- **`<<ASK_PASS>>` keyword** — interactive password prompt in any subst-aware field
- **`-T` (no PTY)** — checkbox in SSH options
- **Backslash escapes** — `\n \r \t` honored in send/command fields

Plus upstream fixes ported in: compact-mode crash, zoom drift,
multi-select connect, `_getSelectedTerminals` arrayref, VTE feature
detection (eval-probe), GNOME dark-mode detection.

## What's fixed vs upstream

Bug fixes specific to this fork (not in upstream):

- **Keyboard shortcuts** — modifier key detection was broken (`*` vs `->{}`)
- **Telnet autologin** — now correctly sends `\r` per RFC 854
- **RDP/xfreerdp passwords** — special characters (`'`, `"`) no longer break the connection
- **Jump host SSH** — no longer overrides user-configured authentication method
- **Session log** — only written when logging is explicitly enabled
- **known_hosts handling** — removed shell injection via backtick+echo
- **Proxy credentials** — password no longer visible in `ps aux`
- **Read-only config** — no crash when started with `--readonly`
- **Regex group edit** — replaced dangerous double-eval (`/eeeg`) with safe `/g`
- **Ubuntu 24.04 Noble** — updated package dependencies (`freerdp3`, `dbus-broker`)
- **Ubuntu 26.04 / Perl 5.40** — fixed crash on start (`Undefined subroutine &PACUtils::_`); the glade getter is now installed via typeglob since modern Perl silently drops `sub _`
- **chmod** — was applied to filehandle instead of filename (no-op), now fixed
- **Wayland detection** — automatic fallback to Xwayland for problematic widgets
- **Dark mode** — auto-detect GNOME `color-scheme` setting
- **Screenshot cleanup** — automatic purge of orphaned files
- **AlmaLinux 9 / RHEL 9 builds** — added to package build matrix
- **Compact-mode crash** — guard for `btnShowButtonBar` when not built
- **Zoom drift** — integer-cent arithmetic instead of `+= 0.1` floats
- **OSSP::uuid → UUID::Tiny** — pure-Perl, no system library dep
- **Wide-char STDERR** — `:utf8` layer in `asbru_conn` diagnostic output

## Security hardening

Ásbrú Plus has undergone a comprehensive security audit and hardening pass
beyond what's in upstream:

- **Credential encryption**: migrated from legacy Blowfish (64-bit blocks,
  1-iteration PBKDF) to AES-256 with opensslv2 PBKDF (10000+ iterations)
- **Master password**: optional user-derived key for credential vault,
  with automatic migration of existing credentials
- **Config integrity**: HMAC-SHA256 verification of config files to detect
  tampering
- **File locking**: `flock(LOCK_EX)` on config save to prevent corruption
- **Shell injection fixes**: xdg-open, VNC password, RDP password, KeePass
  CLI, gsettings — all migrated to list-form `exec()` or `IPC::Open3`
- **Signal handler safety**: async-safe re-entrancy protection in asbru_conn
- **Temp file permissions**: `chmod 0600` on credential-containing temp files
- **UUID validation**: prevents path traversal via config UUID field
- **Proxy credentials**: passed via environment variable, not visible in
  `ps aux`
- **SSH option whitelist**: blocks `ProxyCommand`, `LocalCommand`,
  `PermitLocalCommand` to prevent arbitrary command execution via config
- **CMD substitution whitelist**: `<CMD:...>` template variables restricted
  to safe characters; blocks pipes, subshells, redirections, `eval`

## Running tests

```bash
prove -lr t/
```

Test suite covers syntax, packaging, security hardening, cryptography,
config handling, connection methods, shell escaping, message framing,
HMAC integrity, Wake-on-LAN packet construction, dark-mode detection,
Wayland routing, dump-uuid redaction, vault scaffold, dead-asset gates,
and SSH config import. 540+ tests across 23 files.

## Relation to upstream

Ásbrú Plus periodically syncs non-conflicting fixes and CI improvements from
[asbru-cm/asbru-cm](https://github.com/asbru-cm/asbru-cm) while maintaining
its own security hardening track that will not be upstreamed. The package
build matrix, CI workflows, and test suite are independent from upstream.

## License

GNU General Public License version 3. See [LICENSE](LICENSE).

Based on Ásbrú Connection Manager © 2017–2022 Ásbrú Connection Manager team
Based on PAC Manager © 2010–2016 David Torrejón Vaquerizas
