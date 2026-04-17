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

Numbers updated post-Phase-3/4 refactor. Compare against the pre-refactor
state in commit c9e42c8 to see what changed.

### Legacy (god-objects)

| Module | Was | Now | Notes |
|--------|----:|----:|-------|
| `lib/PACUtils.pm` | 4 479 | **712** | −84%. Mostly proxies + translation helpers + `our $CIPHER` alias for back-compat |
| `lib/PACMain.pm`  | 6 211 | **4 761** | −23%. Phase 4 extractions cover sidebar refresh, connections-list panel, config save, tree build, master-password prompt, terminal focus, etc. The bulk that remains is the application class itself |
| `lib/PACTerminal.pm` | 5 020 | 5 020 | unchanged |
| `lib/asbru_conn` | 2 759 | 2 753 | dead helpers + PPK passphrase temp-file leak fix |
| `lib/ex/KeePass.pm` | 2 317 | 2 317 | vendored, do not modify |
| `lib/PACScripts.pm` | 1 985 | 1 985 | unchanged |
| `lib/PACCluster.pm` | 1 728 | 1 728 | unchanged |
| `lib/PACConfig.pm` | 1 331 | 1 331 | unchanged |
| `lib/method/PACMethod_ssh.pm` | 1 186 | 1 186 | unchanged |
| `lib/PACPCC.pm` | 1 074 | 1 074 | unchanged |
| `lib/PACKeePass.pm` | 1 032 | 1 032 | unchanged |
| `lib/PACEdit.pm` | 1 026 | 1 026 | unchanged |

### New (PAC::* hierarchy — 46 modules)

The new namespace organizes by responsibility. Every entry has POD,
strict perlcritic gate (severity 3), and at least one focused test
file.

| Namespace | Modules | Purpose |
|-----------|---------|---------|
| `PAC::*` (top) | Globals, Logger, Vault, Subst, Methods, Menu, SessionLog, WakeOnLan, Clipboard, Dialog | Cross-cutting domain code |
| `PAC::Crypto::*` | Cipher, HMAC | Symmetric crypto + integrity (extracted from PACUtils + PACMain) |
| `PAC::Storage::*` | Yaml, Storable | Safe persistence wrappers (LoadBlessed=0, Storable::Eval=0) |
| `PAC::Config::*` | Schema, SanityCheck, TmpSessions, **Save** | Declarative + legacy config validation, tmp-session strip/restore, full save pipeline (flock + symlink-refusal + HMAC sidecar) |
| `PAC::Net::*` | SshConfig, SshOptions, UpdateCheck, WindowList | SSH config parser, options normalizer, GitHub release check, X11 window list |
| `PAC::Theme::*` | Icons, DesktopFile, Image, Widget, Switch | Icon factory, .desktop generator, pixbuf helpers, widget styling, theme toggle |
| `PAC::Window::*` | Splash, About, **Layout**, **State**, **ConnectionsList** | Top-level windows + window-state persistence + Traditional/Compact layout switcher + sidebar panel show/hide |
| `PAC::Dialog::*` | Dialog (top), PopupMenu, **BulkEdit**, **MasterPasswordPrompt** | Modal dialogs + context menus + bulk-edit grid + first-run vault prompt |
| `PAC::Tree::*` | Sort, State, **Build** | Connection-tree comparator + expanded-state persistence + data-array builder |
| `PAC::Terminal::*` | Encodings, Vte, **Focus** | Terminal-related domain (charsets + VTE version-tolerant wrappers + tab-focus management) |
| `PAC::UI::*` | **Refresh** | Sidebar tab refresh + info-pane refresh (8 functions: connections/favourites/history/clusters tabs + their model rebuilders + with_uuid info-pane sync) |
| `PAC::Util::*` | ShellEscape, TreeSelection, Readme, **ImportScan** | Stateless utilities + recursive scan of imported YAML for shell-injection patterns |

Bold entries arrived during Phase 4 (post-2026-04 PACMain
extraction wave); see `git log --grep "feat(.*): extract"` for
the per-module history.

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

### `lib/PACMain.pm` (4 761 lines)

Phase 4 extractions (each leaves a 1-line `goto`-proxy in PACMain
so existing callsites stay unchanged — see the `=head1 EXTRACTED
MODULES` POD section at the bottom of PACMain.pm for the full
cross-reference list):

- `_showAboutWindow` → `PAC::Window::About::show`
- `_setVteCapabilities` → `PAC::Terminal::Vte::probe`
- `_checkForUpdates` (HTTP half) → `PAC::Net::UpdateCheck`
- `_toggleTheme` / `_resetStyleRecursively` /
  `_refreshImagesRecursively` → `PAC::Theme::Switch`
- `_saveTreeExpanded` / `_loadTreeExpanded` → `PAC::Tree::State`
- `_saveGUIData` / `_loadGUIData` → `PAC::Window::State`
- `_setSafeLayoutOptions` / `_ApplyLayout` → `PAC::Window::Layout`
- `_showConnectionsList` / `_hideConnectionsList` /
  `_toggleConnectionsList` / `_doToggleDisplayConnectionsList`
  → `PAC::Window::ConnectionsList`
- `_doFocusPage` → `PAC::Terminal::Focus::focus_page`
- `_updateGUIWithUUID` / `_clearLeftMenuTabLabels` /
  `_updateGUIPreferences` / `_updateGUIFavourites` /
  `_updateGUIHistory` / `_updateGUIClusters` /
  `_updateClustersList` / `_updateFavouritesList`
  → `PAC::UI::Refresh`
- `_saveConfiguration` → `PAC::Config::Save::save`
- `_loadTreeConfiguration` / `__recurLoadTree` →
  `PAC::Tree::Build`
- `_promptSetMasterPassword` →
  `PAC::Dialog::MasterPasswordPrompt`
- `_bulkEdit` → `PAC::Dialog::BulkEdit`
- `_writeConfigHMAC` / `_verifyConfigHMAC` / `_ct_eq` →
  `PAC::Crypto::HMAC`
- `_safe_retrieve` → `PAC::Storage::Storable`
- the YAML-import shell-injection scan inside `__importNodes` →
  `PAC::Util::ImportScan`

Key sections still implemented in PACMain itself:

| Section | Functions | Notes |
|---------|-----------|-------|
| App lifecycle | `new`, `start`, `DESTROY`, `_quitProgram` (~110) | Lifecycle code; risky to split |
| Main window UI build | `_initGUI` (~723 lines) | Glade widget wiring |
| GTK signal wiring | `_setupCallbacks` (~1 268 lines) | Event handler installation |
| Tree menus + favourites + lock | many small | `_treeConnections_menu*`, `_lockAsbru`, `_unlockAsbru`, `__treeBuildNodeName`, etc. |
| Read configuration | `_readConfiguration` (~200) | Includes vendor-cfg overlay + HMAC verification + Safe-compartment fallback |
| Cluster launch | `_startCluster`, `_launchTerminals` | |
| Clone / dup / export / import | `_copyNodes`, `_cutNodes`, `_pasteNodes`, `__dupNodes`, `__exportNodes`, `__importNodes`, `__importSshConfig` | |
| `_setCFGChanged` / `_sendAppMessage` / `_getCurrentTree` | small leaf helpers | |

Most of the remaining bulk is the PACMain class itself: methods
that mutate `$$self` and call into the GUI hierarchy. Further
mechanical extraction has diminishing returns — a real reduction
needs a class split (`PAC::App` + `PAC::Window::Main`), which is
high-risk and out of scope for this phase.

### `lib/PACUtils.pm` (712 lines, mostly proxies)

PACUtils is now a thin dispatch layer. The original 4 479-line
god-utility was decomposed into 36 PAC::* modules; PACUtils retains:

- `\@EXPORT` list (50+ entries) for back-compat
- `our \$CIPHER` alias to `PAC::Crypto::Cipher::active()` for the
  50+ legacy direct-access call sites
- ~50 1-line `goto`-proxies forwarding to PAC::* modules
- 7 real bodies: `_`, `__`, `__text` (translation), master-cipher
  state proxies, `_appName`

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
