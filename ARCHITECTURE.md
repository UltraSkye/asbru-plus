# Architecture

This document describes how Ásbrú Plus is laid out today and where the
ongoing modernization is taking it. Read this before any non-trivial PR.

## High-level

```
┌─────────────────────────────────────────────────────────────────┐
│                        asbru-cm (entry)                          │
│  - parses argv, sets ASBRU_CFG, prctl(PR_SET_DUMPABLE,0)         │
│  - tightens config dir/file perms                                │
│  - delegates to PACMain->new->start                              │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼─────────────────┐    ┌─────────────────────────────┐
│       PACMain  (god-object) │◄──►│  PACUtils  (god-utility)    │
│  ~5300 LOC, mixes:          │    │  ~4400 LOC, mixes:          │
│  - app lifecycle            │    │  - crypto ($CIPHER)         │
│  - main window UI           │    │  - icon factory             │
│  - tree model               │    │  - dialog helpers           │
│  - master password flow     │    │  - method definitions       │
│  - tray, theme, save/load   │    │  - config sanity            │
│  - update banner            │    │  - splash screen            │
└────┬──────┬───────┬──────┬──┘    └─────────────────────────────┘
     │      │       │      │
     │      │       │      └─►  PACEdit          (connection edit dialog)
     │      │       └─────────►  PACConfig        (Preferences window)
     │      └─────────────────►  PACScripts       (Perl + Python scripts)
     └────────────────────────►  PACTerminal      (per-tab VTE wrapper)
                                  └─►  PACTray, PACCluster, PACPCC, ...
```

Plus:

- `lib/method/PACMethod_*.pm` — one module per protocol (ssh, sftp,
  rdesktop, vnc, telnet, mosh, …) defining how to build the command
  line and what fields to expose in PACEdit.
- `lib/edit/PACMethod.pm` — shared Edit-tab logic.
- `lib/ex/PACTree.pm`, `SortedTreeStore.pm` — connection tree widget.
- `res/asbru.glade` — **single 9700-line Glade XML** describing every
  dialog and form. This is the largest piece of legacy debt.
- `res/themes/{default,asbru-dark}/` — per-theme color CSS, icons.
- `res/themes/_base.css` — shared structural rules (no colors).

## Data flow

1. **Startup** (`asbru-cm` → `PACMain::new`):
   1. argv + env validation
   2. perms tightening + `PR_SET_DUMPABLE=0`
   3. early CSS load (theme picked from `asbru.yml` or GNOME prefer-dark)
   4. splash window
   5. `_readConfiguration` → `_safe_retrieve(asbru.nfreeze)` after HMAC
      verification
   6. `_promptSetMasterPassword` (first run only, after CSS so the modal
      renders themed)
   7. `_initGUI` builds the main window from `asbru.glade`
   8. `start` finalises tray, splash, autostart, update check

2. **Connection launch**:
   1. User selects a node in `treeConnections`
   2. `_launchTerminals` → `PACTerminal->new($cfg, $uuid)`
   3. PACTerminal calls `$$self{_METHODS}{$method}{cmd}->()` to build
      the argv list, then forks `Vte::Terminal::spawn_async`
   4. `Expect`-style auto-input runs (auto-accept SSH key, password,
      sudo, etc.) via patterns from the connection config

3. **Save**:
   1. `_saveConfiguration` → `_cipherCFG` re-encrypts password fields
   2. `nstore($cfg, $CFG_FILE_NFREEZE)` (a Storable binary)
   3. `_writeConfigHMAC` writes the sidecar
   4. Optional YAML + Data::Dumper exports for human readability /
      version control

## Module boundaries (current)

| Module | Lines | Owns |
|--------|-------|------|
| `PACMain.pm` | ~5300 | App lifecycle, main window, tree, save/load, theme switch, update banner |
| `PACUtils.pm` | ~4400 | Crypto, icons, splash, dialog helpers, method definitions |
| `PACConfig.pm` | ~2400 | Preferences window |
| `PACEdit.pm` | ~3200 | Edit Connection dialog |
| `PACTerminal.pm` | ~4500 | Per-connection terminal lifecycle, expect, log |
| `PACScripts.pm` | ~1700 | Scripts manager (Perl + Python) |
| `PACCluster.pm` | ~900 | Cluster manager |
| `PACTray.pm` | ~250 | System tray icon |
| `PACKeePass.pm` | ~900 | KeePass CLI bridge |
| `PACPCC.pm` | ~500 | Power Cluster Controller |
| `lib/method/*.pm` | ~3500 (total) | Per-protocol command builders |

The boundaries are **leaky**:

- `PACUtils` calls `PACMain::FUNCS{...}` (circular)
- Many modules reach into `$$self{_GUI}{main}` of PACMain by name
- Global state via `our %SHARED`, `our %COMMON`, `$FUNCS{...}`, `%RUNNING`
- Glade widgets fetched by string ID across module boundaries

## Crypto / Vault state (today)

- Active key: `$PACUtils::CIPHER` — a single `Crypt::CBC` object held
  for the lifetime of the process.
- Initial cipher uses a hardcoded legacy key (PBKDF2-HMAC-SHA256
  opensslv2, ~10k iter) — overridden when the user sets a master
  password via `_initMasterCipher`.
- Verifier token (`ASBRU_MASTER_VERIFY_TOKEN_V1`) encrypted under the
  master key, stored in `$cfg{defaults}{master_password_verifier}`,
  used to validate the password without needing to decrypt the whole
  config.
- Cleartext passwords sit in `$cfg{environments}{$uuid}{pass}` after
  `_decipherCFG` — for the **lifetime of the process**. This is a
  known weakness; see SECURITY.md.

## Planned refactor (audit-driven)

Phase A — extract crypto into a single owner:

```
┌────────────────────────────┐
│         PAC::Vault         │
│  - new($cfg_path, $key?)   │
│  - unlock($pwd)            │
│  - lock                    │
│  - get_secret($uuid, $key) │  ← decrypt-on-demand
│  - put_secret($uuid, ...)  │
│  - rotate_kdf              │  ← Argon2id migration
│  - persist                 │
└────────────────────────────┘
```

Phase B — extract theme + update:

```
┌──────────────┐  ┌──────────────┐
│  PAC::Theme  │  │  PAC::Update │
│              │  │              │
│ - apply($n)  │  │ - check()    │
│ - toggle     │  │ - banner()   │
│ - providers  │  │ - URL open   │
└──────────────┘  └──────────────┘
```

Phase C — extract main window construction from `PACMain::new` into
`PAC::Window::Main` so PACMain becomes just an application object.

Phase D — split `res/asbru.glade` into per-dialog `.ui` files
(`preferences.ui`, `edit_connection.ui`, `cluster.ui`, `scripts.ui`,
`wol.ui`, `about.ui`). Use `Gtk3::Builder->new_from_file` per file owned
by the corresponding module.

## File layout reference

```
asbru-plus/
├── asbru-cm                  # entry-point script
├── lib/
│   ├── PAC*.pm               # main modules
│   ├── method/PACMethod_*.pm # per-protocol command builders
│   ├── edit/                 # Edit Connection sub-tabs
│   └── ex/                   # external/extracted helpers
├── res/
│   ├── asbru.glade           # GLADE UI (legacy, monolithic)
│   ├── themes/
│   │   ├── _base.css         # shared structural rules
│   │   ├── asbru-dark/       # dark theme: colors + Lucide icons
│   │   ├── default/          # light theme
│   │   └── DESIGN_TOKENS.md
│   ├── asbru-logo-*.png
│   └── script_template.py
├── utils/
│   ├── pac2asbru.pl          # legacy migration
│   └── asbru_py.py           # Python scripts helper
├── t/
│   ├── 00..10*.t             # syntax / packaging / smoke
│   ├── 13-15*.t              # security functional
│   ├── 18-20*.t              # this fork's regression tests
│   └── lib/
├── docker/                   # build/test/run images
├── ci/                       # CI helper scripts
└── docs/                     # generated/written docs
```
