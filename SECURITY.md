# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.5.x   | ✅ — current development line |
| ≤ 6.4   | ❌ — upstream Ásbrú CM, report there |

## Reporting a Vulnerability

**Do not file public GitHub issues for security problems.**

Send a private report to the maintainer's GitHub Security Advisory at:
<https://github.com/UltraSkye/asbru-plus/security/advisories/new>

Or, for non-GitHub-account submissions, encrypt with the project GPG key
(fingerprint and download instructions will be added before the first
public release).

We aim to respond within **5 business days** with an initial triage and
within **30 days** with a fix or coordinated disclosure plan.

## Threat Model (summary)

Ásbrú Plus is a **local desktop credential manager**. Its primary asset
is the user's collection of remote-access credentials (SSH passwords,
private keys, RDP passwords, KeePass references). The threat actors we
defend against:

| # | Actor | In scope | Mitigation |
|---|-------|----------|------------|
| T1 | Other local user on a shared machine | ✅ | 0600 file perms, PR_SET_DUMPABLE, master password |
| T2 | Attacker who has briefly written `~/.config/asbru/asbru.nfreeze` (e.g. dotfile sync compromise) | ✅ | Storable Eval=0, HMAC fail-closed |
| T3 | Attacker with persistent root on the workstation | ❌ | Out of scope — root owns the user |
| T4 | Network attacker on the wire to the SSH/RDP server | ❌ | Delegated to SSH/RDP itself |
| T5 | Compromised connection method binary (`ssh`, `xfreerdp`) | ❌ | We trust the system distro packages |

## Current Security Posture (as of audit, see `docs/audit-report.md`)

The Ásbrú Plus fork (this repository) addresses several concrete issues
inherited from the upstream codebase:

### Hardened ✅

- **Storable RCE gate** — every `retrieve()` goes through `_safe_retrieve`
  with `local $Storable::Eval = 0` and `local $Storable::Deparse = 0`,
  preventing CODE/Deparse blocks in the serialized stream from being
  executed.
- **HMAC integrity** — every config file has an HMAC-SHA256 sidecar.
  Missing sidecars are **rejected** when a master password is set
  (no backward-compat bypass).
- **Constant-time HMAC compare** — `_ct_eq` removes the timing oracle
  on integrity verification.
- **Constant-time master password verify** — `_ctEq` on the decrypted
  verifier token, removes timing oracle on wrong-password attempts.
- **`prctl(PR_SET_DUMPABLE, 0)`** — set in `BEGIN` so once the process
  holds credential material, `/proc/self/{mem,maps}` is unreadable to
  other users and core dumps are disabled.
- **Lock GUI re-ciphers memory** — when the user locks the GUI, the
  in-memory cfg is re-encrypted so plaintext password fields don't sit
  in process memory while locked.
- **0600 enforcement** — `~/.config/asbru/asbru.nfreeze`, the `.hmac`
  sidecar, `.salt`, `asbru.yml` and `asbru_stats.nfreeze` are tightened
  on every launch if a previous version left them group/world-readable.
- **Connection method input validation** — every method (`PACMethod_*`)
  rejects shell metacharacters in user / host / option fields.
- **Safe.pm compartment** — the legacy `Data::Dumper` config import
  path runs in a restricted compartment with only data-handling opcodes
  permitted.

### Known weaknesses (work in progress)

- **KDF strength**: master password is currently stretched with
  `Crypt::CBC -pbkdf => 'opensslv2'`, which is PBKDF2-HMAC-SHA256 with a
  fixed iteration count of ~10000. OWASP 2023 recommends 600000+, or
  Argon2id. Migration to Argon2id (with versioned envelope and a
  one-shot upgrade on first unlock) is the next sprint.
- **Cleartext credentials in process memory**: after unlock, decrypted
  passwords sit in the cfg hash for the lifetime of the process. The
  PAC::Vault refactor (planned) will move to a decrypt-on-demand model
  with explicit zeroization.
- **Single global $CIPHER**: the active cipher is module-level state in
  `PACUtils`. The same refactor will scope it to a `PAC::Vault` instance.
- **Connection logs unsigned**: session log files are written without
  HMAC. A future release will optionally encrypt session logs with the
  master password.

### Out of scope (do not file as a vulnerability)

- An attacker who is already root on the workstation reading
  `/proc/$pid/mem` of a launched ssh process — this is fundamental to
  the trust model of any local credential manager.
- An attacker who has persistent write access to `~/.config/asbru/` —
  if you can write the user's config you can also write `~/.bashrc`.
- A user who chooses a weak master password.

## Hardening Checklist (operator-facing)

When deploying Ásbrú Plus on a multi-user host:

- [ ] Confirm `~/.config/asbru` is mode `0700`
- [ ] Confirm `~/.config/asbru/asbru.nfreeze` is mode `0600`
- [ ] Confirm `asbru.nfreeze.hmac` exists alongside the nfreeze
- [ ] Set a master password (otherwise the legacy hardcoded key applies)
- [ ] Run `asbru-cm --verbose` once and grep stderr for `SECURITY:` lines
- [ ] If on a system with `systemd-coredump`, confirm coredumps are off
      for this binary (we set `PR_SET_DUMPABLE=0` but belt-and-braces)

## Disclosure Timeline (for accepted reports)

| Day | Milestone |
|-----|-----------|
| 0 | Report received |
| 0-5 | Triage, severity assigned, reporter acknowledged |
| 5-30 | Patch developed and tested |
| 30 | CVE assigned (if applicable), private fix available |
| 60 | Public disclosure with patched release |

We support coordinated disclosure timelines up to **90 days** for complex
issues. Researchers acting in good faith will be credited in the release
notes unless they request anonymity.
