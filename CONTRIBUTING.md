# Contributing to Ásbrú Plus

Thanks for your interest. This is a security-conscious fork — contributions
are welcome but the bar for code quality is deliberately set higher than for
the upstream project we forked from.

Please read this entire file before opening a PR.

---

## Before you start

1. Open an issue first describing what you want to change. This avoids
   duplicate work and lets us align on the approach before you write code.
2. For non-trivial changes, link the issue from the PR.
3. For security-sensitive changes (crypto, auth, IPC, anything touching
   `~/.config/asbru/`), see [SECURITY.md](SECURITY.md) and CC the maintainer
   on the issue.

---

## Repository structure

```
asbru-plus/
├── asbru-cm                    # entry point — argv, perms, hand-off
├── lib/
│   ├── PAC/                    # NEW code: focused modules, strict lint
│   │   ├── Dialog.pm           #   modal Gtk dialogs
│   │   ├── Vault.pm            #   credential vault (scaffold)
│   │   ├── WakeOnLan.pm        #   WoL magic-packet builder
│   │   └── ...
│   ├── PACMain.pm              # LEGACY god-object — being decomposed
│   ├── PACUtils.pm             # LEGACY catch-all utility — being decomposed
│   ├── PACTerminal.pm          # LEGACY per-tab terminal class
│   ├── method/PACMethod_*.pm   # per-protocol command builders
│   ├── edit/                   # Edit-Connection sub-tabs
│   ├── ex/                     # external/vendored helpers (KeePass, etc.)
│   └── PACSshConfig.pm         # transitional naming, will move into PAC::
├── res/
│   ├── asbru.glade             # 9 700-line legacy GLADE — being split
│   └── themes/                 # CSS + per-theme assets
├── t/                          # tests (numbered: 00–25, …)
├── docker/                     # build/test container definitions
├── ci/                         # CI helper scripts
├── dist/                       # per-format packaging (deb / rpm / AppImage)
└── ARCHITECTURE.md             # — read this before any non-trivial PR —
```

The `ARCHITECTURE.md` document includes section maps for every file >500
LOC. Read those before navigating a god-object.

---

## Naming conventions

### Module namespace

| Namespace | Purpose | Quality bar |
|-----------|---------|-------------|
| `PAC::*` | New, modern, focused modules | strict perlcritic, POD required |
| `lib/method/PACMethod_*` | Per-protocol command builders | legacy bar |
| `PAC<Name>` (no `::`) | LEGACY — `PACMain`, `PACUtils`, `PACTerminal` | legacy bar, freeze in place |

**Rule:** new code goes under `PAC::*`. The flat `PAC<Name>` namespace is
frozen — only modify existing legacy files for bug fixes or extractions.

### Public vs internal API

| Convention | Visibility |
|-----------|------------|
| `sub publicThing { ... }` | Public — POD-documented, semver-stable |
| `sub _internalThing { ... }` | Internal — leading underscore, may change without notice |
| `our $PUBLIC_VAR` | Public package variable |
| `my $internal` | File-local |

Anything in `PAC::*` without a leading underscore is part of the public API
and **must** carry a POD entry. The pod-coverage test enforces this.

### File names

- Test files: `t/NN-short-description.t` — incrementing two-digit prefix.
- New modules in `lib/PAC/Foo.pm` provide `package PAC::Foo;`.
- Avoid abbreviations in new code. `PAC::SshConfig`, not `PAC::SshCfg`.

---

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/). The
title is one line ≤ 72 chars; the body wraps at 72.

```
<type>(<scope>): <subject>

<body explaining what and why, not how>
```

| Type | When to use |
|------|-------------|
| `feat` | New user-visible feature |
| `fix` | Bug fix (user-visible) |
| `refactor` | Code restructure with no behavior change |
| `perf` | Performance improvement |
| `test` | Adding / changing tests |
| `docs` | Documentation only |
| `ci` | CI/CD pipeline only |
| `chore` | Tooling, deps, gitignore, etc. |
| `security` | Security-sensitive change (note in CHANGELOG) |

Scope is the area touched: `terminal`, `vault`, `ssh`, `release`, `utils`,
`import`, `ui`, etc.

Examples from the existing log:

```
feat(import): import connections from ~/.ssh/config (#1017)
fix(terminal): port upstream compact-mode guard and zoom drift fix
refactor(utils): extract Wake-on-LAN into PAC::WakeOnLan
ci(test): fix YAML line-continuation leaving leading space in test path
```

---

## PR rules

### Size

- **One concept per PR.** No "and while I was there I also..." commits.
- Aim for ≤ 300 lines net change per PR. Above that, split.
- Never bundle a refactor with a feature. Refactor first, merge, then feat.

### Files

- Touch only what you need. No drive-by formatting.
- Never commit: `*.bak`, `*.orig`, `*.swp`, `*~`, `cover_db/`, `.idea/`,
  `.vscode/`, `*.log`. (`.gitignore` covers these — verify with
  `git status` before pushing.)
- New modules under `lib/PAC/*` come with a `t/NN-<module>-extraction.t`
  test guarding API surface and proxy wiring.

### Quality gates

Every PR must:

- [ ] Pass the full test suite (`prove -lr t/`)
- [ ] Pass `perlcritic --severity 3` for any file under `lib/PAC/*`
- [ ] Carry POD on every new public sub
- [ ] Not drop coverage by more than 1pp (CI gate)
- [ ] Have a green CI workflow

Refactor-only PRs additionally:

- [ ] Include a test verifying behavior is preserved
- [ ] Note "no behavior change" in the commit body
- [ ] Leave a 1-line proxy in the legacy module so callers don't break

### Backward compatibility

- Don't break the on-disk config format (`~/.config/asbru/asbru.yml`,
  `asbru.nfreeze`). Migrations go in `_cfgSanityCheck` (until extracted).
- Don't remove public APIs without a deprecation cycle (1 release with
  warning, then removal).
- Glade widget IDs are public surface — renaming one breaks downstream
  themes.

---

## Local development

```bash
# Install all CPAN deps locally
cpanm --installdeps . --notest

# Or use system packages (preferred — see README → Manual dependencies)

# Run tests
prove -lr t/

# Run a single test
prove -lv t/23-ssh-config-import.t

# Run perlcritic on new modules
perlcritic --severity 3 --profile .perlcriticrc-strict lib/PAC/

# Build a .deb
docker compose run --rm build-deb

# Run the app from source
./asbru-cm
```

For UI changes, run under `xvfb-run` or a real X session — Glade widget
errors won't surface in headless smoke tests.

---

## Versioning

[SemVer](https://semver.org/):

- **Patch** (6.5.x) — bug fixes, no behavior change to documented APIs
- **Minor** (6.x.0) — new features, backward-compatible
- **Major** (x.0.0) — breaking changes (rare; needs maintainer sign-off)

Tag `v<version>` on master triggers the release workflow.

---

## Reporting security issues

**Do not** open public issues for security bugs. See [SECURITY.md](SECURITY.md)
for the disclosure policy and contact.
