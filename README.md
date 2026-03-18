# Ásbrú Plus

[![Build Packages](https://github.com/UltraSkye/asbru-plus/actions/workflows/build-snapshots.yml/badge.svg)](https://github.com/UltraSkye/asbru-plus/actions/workflows/build-snapshots.yml)
[![License](https://img.shields.io/badge/License-GPL--3-blue.svg?style=flat)](LICENSE)

A community-maintained fork of [Ásbrú Connection Manager](https://github.com/asbru-cm/asbru-cm), actively developed for Ubuntu 24.04+ and modern Debian-based systems.

> The original project has been unmaintained since 2022. This fork picks up where it left off.

## What is Ásbrú Plus?

Ásbrú Plus is a **Linux desktop GUI** for managing remote connections — think of it as an open-source alternative to [MobaXterm](https://mobaxterm.mobatek.net/) or [SecureCRT](https://www.vandyke.com/products/securecrt/), but native to Linux.

It lets you organize, launch, and automate SSH, RDP, VNC, Telnet, and SFTP sessions from a single interface. You store all your servers, credentials, tunnels, and scripts in one place, and connect with a double-click.

**Platform:** Linux only. Requires a GTK3 desktop environment (GNOME, XFCE, KDE with GTK support, etc.).
Tested on Ubuntu 18.04–24.04, Debian 11/12, Fedora 39+. **Does not run on Windows or macOS natively.**

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

## Running in Docker

If you want to isolate Ásbrú Plus from your host system (recommended for managing access to sensitive servers), you can run it in a Docker container with X11 forwarding:

```bash
docker run -it --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v "$HOME/.config/asbru:/root/.config/asbru" \
  ubuntu:24.04 bash -c "
    apt-get update -q && apt-get install -y --no-install-recommends \
      perl libvte-2.91-0 libcairo-perl libglib-perl libpango-perl \
      libsocket6-perl libexpect-perl libyaml-perl libcrypt-cbc-perl \
      libcrypt-blowfish-perl libgtk3-perl libnet-arp-perl libossp-uuid-perl \
      openssh-client libcrypt-rijndael-perl libxml-parser-perl \
      libcanberra-gtk-module dbus-x11 libgtk3-simplelist-perl \
      gir1.2-wnck-3.0 gir1.2-vte-2.91 ncat git && \
    git clone https://github.com/UltraSkye/asbru-plus.git /opt/asbru-plus && \
    /opt/asbru-plus/asbru-cm
  "
```

Your configuration is persisted via the bind-mounted `~/.config/asbru` directory.
Allow the container access to your X server first: `xhost +local:docker`

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
