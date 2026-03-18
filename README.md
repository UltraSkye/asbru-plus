# Ásbrú Plus

[![Build Packages](https://github.com/UltraSkye/asbru-plus/actions/workflows/build-snapshots.yml/badge.svg)](https://github.com/UltraSkye/asbru-plus/actions/workflows/build-snapshots.yml)
[![License](https://img.shields.io/badge/License-GPL--3-blue.svg?style=flat)](LICENSE)

A community-maintained fork of [Ásbrú Connection Manager](https://github.com/asbru-cm/asbru-cm), actively developed for Ubuntu 24.04+ and modern Debian-based systems.

> The original project has been unmaintained since 2022. This fork picks up where it left off.

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
- Session logging and statistics
- Wake on LAN
- GTK3 / GNOME integration with tray icon

## Installation

Clone the repository and run directly:

```bash
git clone https://github.com/UltraSkye/asbru-plus.git
cd asbru-plus
./asbru-cm
```

### Dependencies (Ubuntu/Debian)

```bash
sudo apt-get install \
  perl libvte-2.91-0 libcairo-perl libglib-perl libpango-perl \
  libsocket6-perl libexpect-perl libyaml-perl libcrypt-cbc-perl \
  libcrypt-blowfish-perl libgtk3-perl libnet-arp-perl libossp-uuid-perl \
  openssh-client libcrypt-rijndael-perl libxml-parser-perl \
  libcanberra-gtk-module dbus-x11 libgtk3-simplelist-perl \
  gir1.2-wnck-3.0 gir1.2-vte-2.91 ncat
```

Optional:

```bash
sudo apt-get install keepassxc telnet ftp freerdp3-x11 tigervnc-viewer mosh
```

## What's fixed vs upstream

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
- **chmod** — was applied to filehandle instead of filename (no-op), now fixed

## License

GNU General Public License version 3. See [LICENSE](LICENSE).

Based on Ásbrú Connection Manager © 2017–2022 Ásbrú Connection Manager team
Based on PAC Manager © 2010–2016 David Torrejón Vaquerizas
