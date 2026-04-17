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

Numbers updated 2026-04-17 (post v6.5.0).

| Module | Lines | Subs | Owns |
|--------|------:|-----:|------|
| `lib/PACMain.pm` | 6 211 | 64 | App lifecycle, main window, tree, save/load, theme switch, update banner, copy/cut/paste/import/export |
| `lib/PACTerminal.pm` | 5 020 | 51 | Per-connection terminal lifecycle, expect, screenshots, session log |
| `lib/PACUtils.pm` | 4 479 | 57 | Crypto, icons, splash, dialog helpers, method definitions, `_subst()`, `_cfgSanityCheck`, Wake-on-LAN |
| `lib/asbru_conn` | 2 759 | — | Connection helper (separate process, talks back to PACTerminal via FIFO) |
| `lib/ex/KeePass.pm` | 2 317 | — | Vendored copy of `File::KeePass` |
| `lib/PACScripts.pm` | 1 985 | — | Scripts manager (Perl + Python) |
| `lib/PACCluster.pm` | 1 728 | — | Cluster manager |
| `lib/PACConfig.pm` | 1 331 | — | Preferences window |
| `lib/method/PACMethod_ssh.pm` | 1 186 | — | SSH command builder + Edit-tab fields |
| `lib/PACPCC.pm` | 1 074 | — | Power Cluster Controller |
| `lib/PACKeePass.pm` | 1 032 | — | KeePass CLI bridge |
| `lib/PACEdit.pm` | 1 026 | — | Edit Connection dialog |
| `lib/edit/PACExpectEntry.pm` | 911 | — | Expect-pattern editor sub-tab |
| `lib/PACKeyBindings.pm` | 681 | — | Keyboard shortcut registration / dispatch |
| `lib/method/PACMethod_xfreerdp.pm` | 608 | — | xfreerdp command builder |
| `lib/edit/PACExecEntry.pm` | 553 | — | Pre/post local exec editor |
| `asbru-cm` | 531 | — | Entry script — argv, perms, `prctl(DUMPABLE,0)`, hand-off |
| `lib/method/PACMethod_rdesktop.pm` | 521 | — | rdesktop command builder |

The boundaries are **leaky**:

- `PACUtils` calls `PACMain::FUNCS{...}` (circular)
- Many modules reach into `$$self{_GUI}{main}` of PACMain by name
- Global state via `our %SHARED`, `our %COMMON`, `$FUNCS{...}`, `%RUNNING`
- Glade widgets fetched by string ID across module boundaries

## Section maps for large files

The biggest files are mostly inherited from upstream. Splitting them
mass-style breaks `git blame` and complicates upstream merges, so the
plan is to extract one well-bounded chunk at a time. Until then, here
is where to look in each:

### `lib/PACMain.pm` (6 211 lines, 64 subs)

| Lines | Section | Key subs |
|------:|---------|----------|
|   30– 130 | imports + globals | — |
|  130– 456 | constructor | `new` |
|  463– 587 | finalize / start-up | `start`, `DESTROY` |
|  587–1310 | main window UI build | `_initGUI` (723 lines) |
| 1310–2578 | GTK signal wiring | `_setupCallbacks` (1268 lines) |
| 2578–2941 | tree + favorites + lock | `_setFavourite`, `_lockAsbru`, `__search`, `__treeBuildNodeName` |
| 2941–3331 | tree right-click menus | `_treeConnections_menu`, `_treeConnections_menu_lite` |
| 3331–3500 | updates banner + theme | `_checkForUpdates`, `_toggleTheme`, `_resetStyleRecursively` |
| 3500–3758 | about / cluster / terminals | `_showAboutWindow`, `_startCluster`, `_launchTerminals`, `_quitProgram` |
| 3867–4129 | save / load configuration | `_saveConfiguration`, `_readConfiguration` |
| 4129–4477 | tree state + GUI prefs | `_promptSetMasterPassword`, `_loadTreeConfiguration`, `_updateGUIWithUUID` |
| 4477–4798 | favorites / clusters / hide-show / cut-paste | many small |
| 4798–5135 | clone / dup / export / import | `_pasteNodes`, `__dupNodes`, `__exportNodes`, `__importNodes` |
| 5135–5226 | import from `~/.ssh/config` | `__importSshConfig` |
| 5226–5571 | bulk edit | `_bulkEdit` |
| 5571–5806 | layout / focus / VTE caps | `_ApplyLayout`, `_setVteCapabilities`, `_doFocusPage` |
| 5806–end  | HMAC integrity, safe retrieve | `_writeConfigHMAC`, `_verifyConfigHMAC`, `_safe_retrieve` |

### `lib/PACUtils.pm` (4 479 lines, 57 subs)

| Lines | Section | Key subs |
|------:|---------|----------|
|   30– 190 | imports + module-level state ($CIPHER) | — |
|  190– 309 | master cipher / verifier | `_initMasterCipher`, `_verifyMasterPassword`, `_migrateCipherCFG` |
|  309– 421 | legacy decrypt compat | `_decrypt_hex_compat` |
|  421– 549 | translation + image helpers | `_`, `__`, `_splash`, `_screenshot`, `_pixBufFromFile` |
|  549–1384 | **method definitions** (giant) | `_getMethods` (835 lines!) — **prime split target** |
| 1384–1699 | icon registry + tree sort | `_registerPACIcons`, `_sortTreeData` |
| 1699–2275 | **dialog helpers** | `_wEnterValue`, `_wMessage`, `_wConfirm`, `_wYesNoCancel`, `_wPopUpMenu` — **extracting now to `PAC::Dialog`** |
| 2275–2316 | password dialog | `_wSetPACPassword` |
| 2316–2978 | **`_cfgSanityCheck`** | schema validation + migration (massive) |
| 2978–3074 | crypto on cfg | `_cipherCFG`, `_decipherCFG` — **belongs in `PAC::Vault`** |
| 3074–3345 | **substitution engine** | `_substCFG`, `_subst` — `_subst` is 215 lines |
| 3345–3590 | **Wake-on-LAN** | `_wakeOnLan` (245 lines) — **easy extraction** |
| 3590–3712 | session log purge / regex / screenshots | `_deleteOldestSessionLog`, `_replaceBadChars`, `_purgeUnusedOrMissingScreenshots` |
| 3712–3755 | X11 window list, README check | `_getXWindowsList`, `_checkREADME` |
| 3755–4016 | encodings, desktop file | `_getEncodings`, `_makeDesktopFile` |
| 4016+ | small helpers | `_updateWidgetColor`, `_vteFeed*`, `_createBanner`, `_doShellEscape`, `_appName` |

### `lib/PACTerminal.pm` (5 020 lines, 51 subs)

Less amenable to splitting — most of the file is one big `PACTerminal`
class with lifecycle methods. Sections of interest:

| Lines | Section |
|------:|---------|
|  150– 510 | `new` — constructor, log file resolution, expect setup |
|  510– 750 | `start` — VTE spawn, FIFO pipe to asbru_conn |
| 1380–1700 | socket reader — handles `CONNECTED`/`DISCONNECTED`/`WENTER`/expect events |
| 2480–2545 | `_setTabColour` — title + icon update + status |
| 3475–3540 | `_execLocalPPE` — local pre/post execution |
| 4570–4610 | `_zoomHandler` |
| 4670–4700 | `_summarizeForwards` — forward port tooltip helper (this fork) |

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
