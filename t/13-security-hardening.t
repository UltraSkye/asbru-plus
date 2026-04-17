#!/usr/bin/perl
# t/13-security-hardening.t — Verify security hardening measures
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

sub read_file {
    my $path = shift;
    open my $fh, '<', $path or BAIL_OUT("Cannot open $path: $!");
    my $content = do { local $/; <$fh> };
    close $fh;
    return $content;
}

my $asbru_conn   = read_file('lib/asbru_conn');
my $pac_utils    = read_file('lib/PACUtils.pm');
my $pac_main     = read_file('lib/PACMain.pm');
my $pac_config   = read_file('lib/PACConfig.pm');
my $pac_terminal = read_file('lib/PACTerminal.pm');
my $pac_scripts  = read_file('lib/PACScripts.pm');
my $pac_keepass  = read_file('lib/PACKeePass.pm');
my $pac_tray     = read_file('lib/PACTray.pm');
my $pac_screenshots = read_file('lib/PACScreenshots.pm');
my $asbru_cm     = read_file('asbru-cm');

# After the Phase 2/3 extractions, several security gates moved out of
# PACUtils into focused PAC::* modules. Read them all so the gates can
# point at the correct file. The "all" string is convenient for checks
# that don't care which file holds the pattern any more.
my $pac_crypto_cipher  = read_file('lib/PAC/Crypto/Cipher.pm');
my $pac_crypto_hmac    = read_file('lib/PAC/Crypto/HMAC.pm');
my $pac_subst          = read_file('lib/PAC/Subst.pm');
my $pac_cfg_sanity     = read_file('lib/PAC/Config/SanityCheck.pm');
my $pac_storage_stor   = read_file('lib/PAC/Storage/Storable.pm');
my $pac_vault          = read_file('lib/PAC/Vault.pm');
my $pac_utils_all      = $pac_utils . $pac_crypto_cipher . $pac_crypto_hmac
                       . $pac_subst . $pac_cfg_sanity . $pac_vault;

# ── Shell escape function ─────────────────────────────────────────────────────

subtest '_doShellEscape covers all dangerous chars' => sub {
    # Moved to PAC::Util::ShellEscape in P3/20.
    my $shell_pm = read_file('lib/PAC/Util/ShellEscape.pm');
    like($shell_pm, qr/escape.*\$.*\\.*`.*".*!/s,
        'escape() escapes $, \\, `, ", !');
    like($shell_pm, qr/escape.*\\n/s,    'escape() handles newlines');
    like($shell_pm, qr/escape.*\\r/s,    'escape() handles carriage returns');
};

# ── UUID validation ──────────────────────────────────────────────────────────

subtest 'UUID format validation in asbru_conn' => sub {
    like($asbru_conn, qr/UUID.*!~.*\[0-9a-f\]/s,
        'UUID format is validated against hex pattern');
    like($asbru_conn, qr/__PAC__ROOT__/,
        '__PAC__ROOT__ is allowed as UUID');
};

# ── Proxy parameter validation ────────────────────────────────────────────────

subtest 'Proxy parameter validation' => sub {
    like($asbru_conn, qr/proxy_ip.*!~.*Invalid proxy host/s,
        'Proxy IP is validated');
    like($asbru_conn, qr/proxy_port.*Invalid proxy port/s,
        'Proxy port is validated');
    like($asbru_conn, qr/proxy_type.*!~.*socks4\|socks5\|http/s,
        'Proxy type is validated against whitelist');
};

# ── Connection parameter validation ──────────────────────────────────────────

subtest 'Connection parameters validated' => sub {
    like($asbru_conn, qr/\$IP.*=~.*invalid characters/is,
        'IP/hostname validated for shell metacharacters');
    like($asbru_conn, qr/\$PORT.*!~.*\d/s,
        'Port validated as numeric');
    like($asbru_conn, qr/\$USER.*=~.*invalid characters/is,
        'Username validated for shell metacharacters');
};

# ── No bareword filehandles in critical files ─────────────────────────────────

subtest 'No bareword filehandle F in critical files' => sub {
    # Allow only commented-out lines or string literals
    my $active_F_pattern = qr/^\s*(?:open|print|close)\s*\(?F[\s,]/m;
    unlike($pac_main, $active_F_pattern,
        'PACMain.pm: no active bareword F filehandles');
    unlike($pac_scripts, $active_F_pattern,
        'PACScripts.pm: no active bareword F filehandles');
    unlike($pac_terminal, $active_F_pattern,
        'PACTerminal.pm: no active bareword F filehandles');
};

# ── xdg-open uses fork+exec, not system() ───────────────────────────────────

subtest 'xdg-open calls use fork+exec' => sub {
    unlike($pac_terminal, qr/system.*xdg-open/,
        'PACTerminal: no system() with xdg-open');
    unlike($pac_config, qr/system.*xdg-open/,
        'PACConfig: no system() with xdg-open');
    unlike($pac_screenshots, qr/system.*xdg-open/,
        'PACScreenshots: no system() with xdg-open');
};

# ── No string eval in PACConfig export ───────────────────────────────────────

subtest 'No string eval in config export' => sub {
    unlike($pac_config, qr/eval\s+"/, 'PACConfig: no string eval');
    like($pac_config, qr/export_func/, 'PACConfig: uses closure-based export');
};

# ── GtkStatusIcon has eval fallback ─────────────────────────────────────────

subtest 'GtkStatusIcon uses eval fallback' => sub {
    like($pac_tray, qr/eval\s*\{.*StatusIcon/s,
        'PACTray: StatusIcon wrapped in eval');
    like($pac_tray, qr/tray available.*=\s*0/s,
        'PACTray: sets tray to 0 on failure');
};

# ── Script name validation prevents path traversal ──────────────────────────

subtest 'Script name rejects path separators' => sub {
    like($pac_scripts, qr/name.*=~.*[\/\\]/s,
        'PACScripts: validates script name against path separators');
};

# ── KeePass CLI path is quoted ──────────────────────────────────────────────

subtest 'KeePass CLI path is single-quoted' => sub {
    like($pac_keepass, qr/'\$CLI'/,
        'PACKeePass: CLI binary path is single-quoted');
};

# ── CMD substitution has whitelist-based sanitization ────────────────────────

subtest 'CMD substitution has injection protection' => sub {
    # Moved to PAC::Subst in P3/1 extraction
    like($pac_subst, qr/CMD.*Blocked.*disallowed/s,
        'PAC::Subst: CMD substitution uses whitelist - blocks disallowed chars');
    like($pac_subst, qr/\^\[\\w/,
        'PAC::Subst: CMD whitelist uses character class approach');
};

# ── No rm -rf via shell in main files ────────────────────────────────────────

subtest 'No shell rm -rf in main files' => sub {
    unlike($pac_main, qr/system.*rm\s+-rf/,
        'PACMain: no system() rm -rf');
    unlike($asbru_cm, qr/system.*rm\s+-Rf/,
        'asbru-cm: no system() rm -Rf');
};

# ── Encryption uses AES (Rijndael) not Blowfish for new data ────────────────

subtest 'Encryption uses AES-256 / Rijndael' => sub {
    # Moved to PAC::Crypto::Cipher in P2/1 extraction
    like($pac_crypto_cipher, qr/Crypt::Rijndael/,
        'PAC::Crypto::Cipher: uses Crypt::Rijndael (AES)');
    like($pac_crypto_cipher, qr/opensslv2/,
        'PAC::Crypto::Cipher: uses opensslv2 PBKDF');
};

# ── Master password infrastructure ──────────────────────────────────────────

subtest 'Master password system exists' => sub {
    # Compat proxies remain in PACUtils; real impl in PAC::Vault
    like($pac_utils, qr/sub _initMasterCipher/,
        'PACUtils: _initMasterCipher proxy exists');
    like($pac_utils, qr/sub _createMasterVerifier/,
        'PACUtils: _createMasterVerifier proxy exists');
    like($pac_utils, qr/sub _verifyMasterPassword/,
        'PACUtils: _verifyMasterPassword proxy exists');
    like($pac_utils, qr/sub _migrateCipherCFG/,
        'PACUtils: _migrateCipherCFG function exists');
    like($pac_vault, qr/sub _create_verifier/,
        'PAC::Vault: _create_verifier real impl exists');
    like($pac_vault, qr/sub _verify\b/,
        'PAC::Vault: _verify real impl exists');
    like($pac_main, qr/master_password_verifier/,
        'PACMain: master password flow integrated');
};

# ── Signal handlers have re-entrancy protection ─────────────────────────────

subtest 'Signal handlers protect against re-entrancy' => sub {
    like($asbru_conn, qr/SIG\{'HUP'\}\s*=\s*'IGNORE'/,
        'HUP handler sets self to IGNORE');
    like($asbru_conn, qr/SIG\{'USR1'\}\s*=\s*'IGNORE'/,
        'USR1 handler sets self to IGNORE');
    like($asbru_conn, qr/SIG\{'USR2'\}\s*=\s*'IGNORE'/,
        'USR2 handler sets self to IGNORE');
    # PACMain's TERM/QUIT/INT handler also needs re-entrancy
    # protection — _quitProgram pumps Gtk3::main_iteration() which
    # can yield and let a second signal fire on the same handler.
    like($pac_main,
        qr/SIG\{'TERM'\}\s*=\s*\$SIG\{'QUIT'\}\s*=\s*\$SIG\{'INT'\}\s*=\s*'IGNORE'/,
        'PACMain TERM/QUIT/INT handler disarms itself on entry');
};

# ── Temp config files have restricted permissions ───────────────────────────

subtest 'Temp config files get chmod 0600' => sub {
    like($pac_terminal, qr/chmod\s+0600.*TMPCFG/s,
        'PACTerminal: nstore temp file gets chmod 0600');
    # REGRESSION: temp file contains plaintext passwords; the trailing
    # chmod is a TOCTOU race window. Tighten umask BEFORE nstore so the
    # file is created mode 0600 atomically, no race.
    like($pac_terminal, qr/umask\(0077\)\s*;\s*\n\s*nstore\([^)]*\$\$self\{_TMPCFG\}\)/,
        'PACTerminal: umask(0077) tightened before nstore (no TOCTOU)');
};

# ── mkdir uses explicit mode ─────────────────────────────────────────────────

subtest 'mkdir uses explicit mode 0700' => sub {
    like($asbru_cm, qr/mkdir\(.*, 0700\)/,
        'asbru-cm: mkdir with mode 0700');
    like($pac_config, qr/mkdir\(.*, 0700\)/,
        'PACConfig: mkdir with mode 0700');
};

# ── File locking on config save ──────────────────────────────────────────────

subtest 'Config save uses file locking' => sub {
    # Save pipeline lives in PAC::Config::Save (extracted from PACMain).
    my $save = read_file('lib/PAC/Config/Save.pm');
    like($save, qr/flock.*LOCK_EX/s,
        'PAC::Config::Save uses LOCK_EX');
    like($pac_main, qr/PAC::Config::Save/,
        'PACMain proxies to PAC::Config::Save');
};

# ── VNC password uses IPC::Open3, not shell echo ────────────────────────────

subtest 'VNC password avoids shell echo' => sub {
    unlike($asbru_conn, qr/echo.*vncpasswd/,
        'No echo|vncpasswd shell pipe');
    like($asbru_conn, qr/IPC::Open3.*vncpasswd/s,
        'VNC uses IPC::Open3');
};

# ── CRIT-01: No unsafe eval of config data ──────────────────────────────────

subtest 'Config loading uses Safe compartment, not bare eval' => sub {
    like($pac_main, qr/Safe->new\(\)/,
        'PACMain: uses Safe.pm compartment for .dumper loading');
    like($pac_main, qr/safe->reval\(/,
        'PACMain: uses safe->reval() not bare eval');
    unlike($pac_main, qr/eval \$data;/,
        'PACMain: no bare eval $data for config loading');
    like($pac_main, qr/ref\(\$result\) ne 'HASH'/,
        'PACMain: validates that loaded data is a hash reference');
};

# ── CRIT-02: Script execution is sandboxed ──────────────────────────────────

subtest 'Script execution uses Safe compartment' => sub {
    like($asbru_conn, qr/Safe->new/,
        'asbru_conn: uses Safe.pm for script execution');
    like($asbru_conn, qr/safe->reval\(\$script\)/,
        'asbru_conn: scripts run via safe->reval');
    like($asbru_conn, qr/permit_only/,
        'asbru_conn: Safe compartment uses permit_only (whitelist)');
    like($asbru_conn, qr/share_from/,
        'asbru_conn: API variables shared into compartment');
};

# ── HIGH-01: Local pre/post commands use explicit shell ─────────────────────

subtest 'Local commands use explicit shell invocation' => sub {
    like($pac_terminal, qr{system\('/bin/sh', '-c'},
        'PACTerminal: local commands use system() with explicit /bin/sh -c');
};

# ── HIGH-03: YAML import has security validation ────────────────────────────

subtest 'YAML import scans for suspicious patterns' => sub {
    like($pac_main, qr/Security Warning.*suspicious pattern/s,
        'PACMain: YAML import warns about suspicious patterns');
    # Recursive value scanner moved to PAC::Util::ImportScan in P4/9
    my $scan_pm = read_file("$RealBin/../lib/PAC/Util/ImportScan.pm");
    like($scan_pm, qr/walk\s*=\s*sub|sub scan/,
        'PAC::Util::ImportScan: recursive value scanner present');
    like($pac_main, qr/PAC::Util::ImportScan::scan/,
        'PACMain calls PAC::Util::ImportScan::scan');
};

# ── HIGH-04: SSH auto-accept-key defaults to OFF ────────────────────────────

subtest 'SSH auto-accept-key defaults to OFF' => sub {
    # Moved to PAC::Config::SanityCheck in P3/6 extraction
    like($pac_cfg_sanity, qr/auto accept key.*\/\/=\s*0/,
        'PAC::Config::SanityCheck: auto accept key defaults to 0 (OFF)');
};

# ── HIGH-06: Per-installation random salt ────────────────────────────────────

subtest 'Per-installation random salt' => sub {
    # Moved to PAC::Crypto::Cipher in P2/1 extraction
    like($pac_crypto_cipher, qr{/dev/urandom},
        'PAC::Crypto::Cipher: uses /dev/urandom for salt generation');
    like($pac_crypto_cipher, qr/\.salt/,
        'PAC::Crypto::Cipher: salt persisted to .salt file');
    like($pac_crypto_cipher, qr/chmod 0600,?\s*\$path/s,
        'PAC::Crypto::Cipher: salt file gets chmod 0600');
    # REGRESSION: salt + public default key enables offline pw cracking;
    # the chmod after open is a TOCTOU window if the file is brand-new.
    # Tighten umask around the open so creation is mode 0600 atomically.
    like($pac_crypto_cipher,
        qr/umask\(0077\).*?\n\s*if \(open\(my \$fh,\s*'>:raw',\s*\$path\)\)/s,
        'PAC::Crypto::Cipher: umask(0077) wraps salt-file open (no TOCTOU)');
    like($pac_crypto_cipher, qr/LEGACY_SALT_STR\s*=\s*'12345678'/,
        'PAC::Crypto::Cipher: legacy salt preserved for backward compat');
};

# ── MED-01/02: Temp files use File::Temp ─────────────────────────────────────

subtest 'Temp files use File::Temp (no TOCTOU)' => sub {
    like($pac_terminal, qr/use File::Temp/,
        'PACTerminal: imports File::Temp');
    like($pac_terminal, qr/tempfile.*asbru_PID/,
        'PACTerminal: pipes/sockets use tempfile()');
    like($pac_terminal, qr/tempfile.*asbru_screenshot/,
        'PACTerminal: screenshots use tempfile()');
    unlike($pac_terminal, qr{'/tmp/asbru_screenshot_' \. rand},
        'PACTerminal: no weak rand() for screenshot filenames');
};

# ── MED-04: Additional field validation ──────────────────────────────────────

subtest 'PUBKEY/TITLE/PASSPHRASE_USER validated' => sub {
    like($asbru_conn, qr/PUBKEY.*invalid characters/s,
        'asbru_conn: PUBKEY path validated');
    like($asbru_conn, qr/TITLE.*invalid characters/s,
        'asbru_conn: TITLE validated');
    like($asbru_conn, qr/PASSPHRASE_USER.*invalid characters/s,
        'asbru_conn: PASSPHRASE_USER validated');
};

# ── MED-05: Log path directory traversal protection ──────────────────────────

subtest 'Log paths reject directory traversal' => sub {
    like($pac_terminal, qr/canonpath.*LOGFILE/s,
        'PACTerminal: log paths canonicalized');
    like($pac_terminal, qr/\.\./,
        'PACTerminal: log paths checked for ..');
    like($pac_terminal, qr/-l \$canon/,
        'PACTerminal: log paths checked for symlinks');
};

# ── MED-06: Config dir permissions verified at startup ───────────────────────

subtest 'Config dir permissions verified and fixed' => sub {
    like($asbru_cm, qr/symlink.*not allowed/s,
        'asbru-cm: rejects symlink config dir');
    like($asbru_cm, qr/chmod\(0700, \$CFG_DIR\)/,
        'asbru-cm: fixes permissive config dir to 0700');
    like($asbru_cm, qr/not owned by the current user/,
        'asbru-cm: warns about wrong ownership');
};

# ── MED-08: HMAC integrity on config files ───────────────────────────────────

subtest 'Config file HMAC integrity' => sub {
    # Real impl moved to PAC::Crypto::HMAC in P2/2; PACMain has proxies
    like($pac_crypto_hmac, qr/hmac_sha256_hex/,
        'PAC::Crypto::HMAC: uses HMAC-SHA256');
    like($pac_main, qr/sub _writeConfigHMAC/,
        'PACMain: _writeConfigHMAC proxy exists');
    like($pac_main, qr/sub _verifyConfigHMAC/,
        'PACMain: _verifyConfigHMAC proxy exists');
    like($pac_main, qr/_verifyConfigHMAC.*CFG_FILE_NFREEZE/s,
        'PACMain: HMAC verified on config load');
    # HMAC sidecar emission now lives in PAC::Config::Save
    # (extracted from PACMain::_saveConfiguration).
    my $config_save = read_file('lib/PAC/Config/Save.pm');
    like($config_save,
        qr/PAC::Crypto::HMAC::write_for.*CFG_FILE_NFREEZE/s,
        'PAC::Config::Save: HMAC written on config save');
    like($pac_crypto_hmac, qr/has a master password set but no HMAC sidecar/,
        'PAC::Crypto::HMAC: missing HMAC sidecar REJECTED when master password is set');
    like($pac_main, qr/_safe_retrieve/,
        'PACMain: Storable retrieve goes through safety wrapper');

    # REGRESSION: every nstore() write to CFG_FILE_NFREEZE in
    # _readConfiguration migration paths must be paired with a
    # _writeConfigHMAC($CFG_FILE_NFREEZE) on the next non-blank line.
    # Otherwise master-password users lose their config on the next
    # launch (HMAC verify_for() rejects sidecar-missing files when
    # a master_password_verifier is set).
    my @nfreeze_writes = ($pac_main =~ m{
        nstore\([^)]*\$CFG_FILE_NFREEZE\)\s*or\s+die[^\n]*\n
        \s*_writeConfigHMAC\(\$CFG_FILE_NFREEZE\)
    }gx);
    cmp_ok(scalar(@nfreeze_writes), '>=', 4,
        'PACMain: every NFREEZE migration nstore() is paired with _writeConfigHMAC');

    my @r_cfg_writes = ($pac_main =~ m{
        nstore\([^)]*\$R_CFG_FILE\)\s*or\s+die[^\n]*\n
        \s*_writeConfigHMAC\(\$R_CFG_FILE\)
    }gx);
    cmp_ok(scalar(@r_cfg_writes), '>=', 4,
        'PACMain: every R_CFG_FILE migration nstore() is paired with _writeConfigHMAC');
    like($pac_storage_stor, qr/Storable::Eval\s*=\s*0/,
        'PAC::Storage::Storable: enforces Storable::Eval=0');
};

# ── ASBRU_TMP mkdir uses explicit mode ──────────────────────────────────────

subtest 'ASBRU_TMP mkdir uses mode 0700' => sub {
    like($asbru_cm, qr/mkdir\(\$ENV\{"ASBRU_TMP"\}, 0700\)/,
        'asbru-cm: ASBRU_TMP mkdir with mode 0700');
};

# ══════════════════════════════════════════════════════════════════════════════
# Phase 2: Offensive security audit fixes
# ══════════════════════════════════════════════════════════════════════════════

# ── C-1: CMD substitution in asbru_conn uses whitelist (not blacklist) ───────

subtest 'CMD substitution in asbru_conn uses whitelist' => sub {
    like($asbru_conn, qr/CMD.*Whitelist.*validation/s,
        'asbru_conn: CMD substitution has whitelist comment');
    like($asbru_conn, qr/<CMD:.*\^\[\\w/s,
        'asbru_conn: CMD uses whitelist character class');
    unlike($asbru_conn, qr/<CMD:.*\[;\&\|\].*\[;\&\|\]/s,
        'asbru_conn: CMD no longer uses weak blacklist pattern');
};

# ── C-2: HMAC verified BEFORE Storable deserialization ───────────────────────

subtest 'HMAC verified before Storable::retrieve' => sub {
    # Verify that when HMAC fails, retrieve is NOT called
    like($pac_main, qr/HMAC verification failed.*refusing to load/s,
        'PACMain: HMAC failure blocks loading (not just warns)');
    # Retrieve happens through _safe_retrieve (after the HMAC check
    # in the same conditional). Match the _safe_retrieve callsite
    # being inside the HMAC-passed branch.
    like($pac_main, qr/_verifyConfigHMAC[^)]*\)[^{]*\{[\s\S]*?_safe_retrieve/s,
        'PACMain: _safe_retrieve only called when HMAC passes');
};

# ── C-3: Pre/post hook commands have dangerous pattern blocking ──────────────

subtest 'Pre/post hook commands block dangerous patterns' => sub {
    like($pac_terminal, qr{/dev/tcp/.*curl.*wget.*nc\b}s,
        'PACTerminal: pre/post hooks block reverse shell patterns');
    like($pac_terminal, qr/Blocked suspicious pre\/post command/,
        'PACTerminal: blocked hook commands produce warning');
};

# ── C-4: RDP password uses temp file instead of cmdline ──────────────────────

subtest 'RDP password not on command line' => sub {
    like($asbru_conn, qr{rdp_.*\.pass},
        'asbru_conn: RDP password written to temp file');
    like($asbru_conn, qr{chmod 0600.*rdp_}s,
        'asbru_conn: RDP password file gets chmod 0600');
    like($asbru_conn, qr{/p:file:},
        'asbru_conn: xfreerdp uses /p:file: syntax');
    like($asbru_conn, qr/unlink.*_rdp_pass_file/,
        'asbru_conn: RDP password file cleaned up in END block');
    unlike($asbru_conn, qr{/p:'\$rdp_pass'},
        'asbru_conn: no inline password in xfreerdp command');
};

# ── H-1: CONNECT_OPTS validated against shell injection ──────────────────────

subtest 'CONNECT_OPTS validated' => sub {
    like($asbru_conn, qr/CONNECT_OPTS.*disallowed/s,
        'asbru_conn: CONNECT_OPTS validated for dangerous chars');
    like($asbru_conn, qr/ProxyCommand|LocalCommand/,
        'asbru_conn: CONNECT_OPTS rejects ProxyCommand/LocalCommand');
};

# ── H-2: KeePass uses list-form open3 ───────────────────────────────────────

subtest 'KeePass uses list-form open3' => sub {
    like($pac_keepass, qr/sub _kpxc_cmd_list/,
        'PACKeePass: _kpxc_cmd_list helper exists');
    like($pac_keepass, qr/_kpxc_cmd_list.*show/s,
        'PACKeePass: show command uses _kpxc_cmd_list');
    like($pac_keepass, qr/open3\(.*\@cmd\)/,
        'PACKeePass: open3 called with list form (@cmd)');
    like($pac_keepass, qr/open2\(.*\@cmd\)/,
        'PACKeePass: open2 called with list form (@cmd)');
    unlike($pac_keepass, qr/open3\(.*"'\$CLI'/,
        'PACKeePass: no string-form open3 with shell interpolation');
    # REGRESSION: stat()->mtime crashes when DB is missing/unreadable.
    # Defensive check: stat result must be assigned and tested before
    # being dereferenced.
    like($pac_keepass,
        qr/my \$stat = stat\(\$\$cfg\{database\}\);\s*\n\s*if \(!\$stat\)/,
        'PACKeePass: defensive stat() before ->mtime (DB-missing-safe)');
    # REGRESSION: STDERR redirect must not leak past a die() inside the
    # open2 block — eval-wrap and restore on every path.
    like($pac_keepass,
        qr/eval \{[^}]*open2\([^}]*\};.*?\n\s*my \$err = \$\@;\s*\n\s*open\(STDERR/s,
        'PACKeePass: STDERR is restored even when open2 dies');
};

# ── H-3: YAML LoadBlessed disabled ──────────────────────────────────────────

subtest 'YAML object instantiation disabled' => sub {
    like($pac_main, qr/\$YAML::LoadBlessed\s*=\s*0/,
        'PACMain: $YAML::LoadBlessed set to 0');
};

# ── H-5: SSH configs include StrictHostKeyChecking ───────────────────────────

subtest 'Generated SSH configs include hardening options' => sub {
    like($asbru_conn, qr/StrictHostKeyChecking accept-new/,
        'asbru_conn: SSH configs include StrictHostKeyChecking');
    like($asbru_conn, qr/HashKnownHosts yes/,
        'asbru_conn: SSH configs include HashKnownHosts');
};

# ── H-6: KeePass master password not in environment ─────────────────────────

subtest 'KeePass master password removed from environment' => sub {
    like($pac_keepass, qr/delete \$ENV\{'KPXC_MP'\}/,
        'PACKeePass: KPXC_MP deleted from environment');
    # Verify no new assignments to $ENV{'KPXC_MP'}
    my @env_assigns = ($pac_keepass =~ /\$ENV\{'KPXC_MP'\}\s*=\s*(?!['"]?\s*$)/g);
    is(scalar @env_assigns, 0,
        'PACKeePass: no assignments of passwords to $ENV{KPXC_MP}');
};

# ── M-1: Pipe commands validated ─────────────────────────────────────────────

subtest 'Pipe commands validated before execution' => sub {
    like($pac_terminal, qr/Blocked pipe command.*disallowed/,
        'PACTerminal: pipe commands validated with whitelist');
};

# ── M-4: TITLE validated against double-quote breakout ───────────────────────

subtest 'TITLE validated against quote breakout' => sub {
    like($asbru_conn, qr/TITLE.*\[.*".*\\.*\]/s,
        'asbru_conn: TITLE validated against double quotes and backslashes');
};

# ── M-5: Proxy password escaped in substitutions ────────────────────────────

subtest 'Proxy password escaped in substitutions' => sub {
    like($asbru_conn, qr/_safe_proxy_pass.*=~.*s\//,
        'asbru_conn: proxy password shell-escaped before substitution');
    like($asbru_conn, qr/_safe_proxy_pass/,
        'asbru_conn: uses escaped version for substitution');
};

# ══════════════════════════════════════════════════════════════════════════════
# Phase 3: Deep audit fixes
# ══════════════════════════════════════════════════════════════════════════════

# ── Socket umask protection ──────────────────────────────────────────────────

subtest 'Unix sockets created with restrictive umask' => sub {
    like($pac_terminal, qr/umask\(0177\)/,
        'PACTerminal: umask set to 0177 before socket creation');
    like($pac_terminal, qr/umask\(\$_prev_umask\)/,
        'PACTerminal: umask restored after socket creation');
};

# ── IPC auth uses random token ───────────────────────────────────────────────

subtest 'IPC socket uses random auth token' => sub {
    like($pac_terminal, qr/auth_token.*urandom/s,
        'PACTerminal: auth token generated from /dev/urandom');
    like($asbru_conn, qr/auth_token.*\/\/.*uuid/s,
        'asbru_conn: auth uses token with UUID fallback');
};

# ── Expect pattern validation ────────────────────────────────────────────────

subtest 'Expect patterns validated before use' => sub {
    like($asbru_conn, qr/eval.*qr\/\$pattern/,
        'asbru_conn: expect patterns validated with eval qr//');
    like($asbru_conn, qr/quotemeta.*pattern/,
        'asbru_conn: invalid patterns fall back to literal match');
};

# ── ASBRU_ENV_FOR_EXTERNAL validated ─────────────────────────────────────────

subtest 'ASBRU_ENV_FOR_EXTERNAL validated in CMD execution' => sub {
    # Moved to PAC::Subst in P3/1 extraction
    like($pac_subst, qr/ASBRU_ENV_FOR_EXTERNAL.*suspicious/s,
        'PAC::Subst: ASBRU_ENV_FOR_EXTERNAL validated before use');
    like($asbru_conn, qr/ASBRU_ENV_FOR_EXTERNAL.*suspicious/s,
        'asbru_conn: ASBRU_ENV_FOR_EXTERNAL validated before use');
};

# ── Import scan_value expanded ───────────────────────────────────────────────

subtest 'Import scan detects expanded attack patterns' => sub {
    # Patterns moved to PAC::Util::ImportScan in P4/9
    my $scan_pm = read_file("$RealBin/../lib/PAC/Util/ImportScan.pm");
    like($scan_pm, qr/mkfifo|socat|\/dev\/tcp/,
        'PAC::Util::ImportScan detects reverse shell patterns');
    like($scan_pm, qr/python.*perl.*ruby.*php/s,
        'PAC::Util::ImportScan detects alternative interpreters');
};

# ── Vendor config scanned ────────────────────────────────────────────────────

subtest 'Vendor config scanned for malicious patterns' => sub {
    like($pac_main, qr/vendor.*suspicious pattern/is,
        'PACMain: vendor config scanned before merge');
};

# ── HMAC key derived from salt ───────────────────────────────────────────────

subtest 'HMAC key derived from installation salt' => sub {
    # Moved to PAC::Crypto::HMAC in P2/2 extraction
    like($pac_crypto_hmac, qr/hmac_sha256_hex.*integrity.*salt/s,
        'PAC::Crypto::HMAC: HMAC key derived from salt file');
};

# ── EXPLORER path validated ──────────────────────────────────────────────────

subtest 'EXPLORER path validated before xdg-open' => sub {
    like($pac_terminal, qr/EXPLORER.*Blocked suspicious/s,
        'PACTerminal: EXPLORER path validated');
    like($pac_terminal, qr/EXPLORER.*https?/s,
        'PACTerminal: EXPLORER blocks URL injection');
};

# ── Clipboard auto-clear ────────────────────────────────────────────────────

subtest 'Clipboard auto-clear after password copy' => sub {
    # Moved to PAC::Clipboard in P3/17 extraction
    my $clip_pm = read_file('lib/PAC/Clipboard.pm');
    like($clip_pm, qr/Glib::Timeout->add_seconds.*15/s,
        'PAC::Clipboard: clipboard cleared after 15s timeout');
    like($clip_pm, qr/\\0.*x length/,
        'PAC::Clipboard: password reference zeroed after clipboard clear');
};

# ── IP validation strengthened ───────────────────────────────────────────────

subtest 'IP validation blocks extended metacharacters' => sub {
    like($asbru_conn, qr/IP.*<>&/s,
        'asbru_conn: IP validation blocks <, >, &');
    like($asbru_conn, qr/IP.*\\r\\n/s,
        'asbru_conn: IP validation blocks newlines');
};

# ── Global variable values escaped ───────────────────────────────────────────

subtest 'Global variable values sanitized against shell injection' => sub {
    # Moved to PAC::Subst in P3/1 extraction
    like($pac_subst, qr/Global variable.*shell metacharacters/s,
        'PAC::Subst: global variable values checked for shell metacharacters');
    like($pac_subst, qr/Session variable.*shell metacharacters/s,
        'PAC::Subst: session variable values checked for shell metacharacters');
};

# ── AppRun quoted $@ ────────────────────────────────────────────────────────

subtest 'AppRun uses quoted parameter expansion' => sub {
    my $apprun = read_file('dist/appimage/AppRun');
    like($apprun, qr/"\$\@"/,
        'AppRun: uses quoted "$@" for argument passing');
};

# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Deep audit fixes — protocol handlers, deserialization, runtime
# ══════════════════════════════════════════════════════════════════════════════

# ── Legacy .freeze file HMAC-protected ───────────────────────────────────────

subtest 'Legacy CFG_FILE_FREEZE has HMAC check' => sub {
    like($pac_main, qr/CFG_FILE_FREEZE.*HMAC.*refusing/s,
        'PACMain: .freeze file verified with HMAC before retrieve()');
};

# ── KeePass kpxc_cli validated ───────────────────────────────────────────────

subtest 'KeePass kpxc_cli subcommand validated' => sub {
    like($pac_keepass, qr/kpxc_cli.*ne.*cli/s,
        'PACKeePass: kpxc_cli validated as empty or "cli" only');
};

# ── Method handlers validate user input ──────────────────────────────────────

subtest 'RDP method handlers validate shell metacharacters' => sub {
    my $rdesktop = read_file('lib/method/PACMethod_rdesktop.pm');
    my $xfreerdp = read_file('lib/method/PACMethod_xfreerdp.pm');
    like($rdesktop, qr/_shell_reject/,
        'rdesktop: shell injection validation present');
    like($rdesktop, qr/otherOptions.*shell metacharacters/s,
        'rdesktop: otherOptions validated');
    like($xfreerdp, qr/_shell_reject/,
        'xfreerdp: shell injection validation present');
    like($xfreerdp, qr/otherOptions.*shell metacharacters/s,
        'xfreerdp: otherOptions validated');
};

subtest 'SSH/SFTP block dangerous options' => sub {
    my $ssh = read_file('lib/method/PACMethod_ssh.pm');
    my $sftp = read_file('lib/method/PACMethod_sftp.pm');
    like($ssh, qr/ProxyCommand.*LocalCommand.*PermitLocalCommand/s,
        'SSH: blocks ProxyCommand/LocalCommand/PermitLocalCommand');
    like($sftp, qr/ProxyCommand.*LocalCommand.*PermitLocalCommand/s,
        'SFTP: blocks ProxyCommand/LocalCommand/PermitLocalCommand');

    # REGRESSION: the value-side regex must also reject '"' so a
    # malicious value can't break out of the surrounding double-quotes
    # and inject an additional -o ProxyCommand=... that the explicit
    # blocklist a few lines above tries to keep out. Previously the
    # value-side regex omitted '"' (only the option-side rejected it).
    for my $pair (['SSH', $ssh], ['SFTP', $sftp]) {
        my ($label, $src) = @$pair;
        # Both option-side AND value-side must contain the same character
        # class — i.e. there should be exactly TWO matches of the regex
        # `=~ /[..."...]/` on the same line, and `"` must appear in both.
        my @lines = grep { /\$\$opt\{(?:option|value)\}\s*=~/ } split /\n/, $src;
        my $has_quote_in_value =
            grep { /\$\$opt\{value\}\s*=~\s*\/\[[^\]]*"[^\]]*\]/ } @lines;
        ok($has_quote_in_value,
            "$label: value-side regex rejects '\"' (no quote-break-out)");
    }
};

subtest 'Serial/3270/Telnet handlers validate input' => sub {
    my $cu = read_file('lib/method/PACMethod_cu.pm');
    my $c3270 = read_file('lib/method/PACMethod_3270.pm');
    my $telnet = read_file('lib/method/PACMethod_telnet.pm');
    like($cu, qr/_reject/,
        'cu: shell injection validation present');
    like($cu, qr/speed.*\\d/s,
        'cu: speed validated as numeric');
    like($c3270, qr/_reject/,
        '3270: shell injection validation present');
    like($telnet, qr/_reject/,
        'telnet: shell injection validation present');
};

# ── xfreerdp cert-ignore produces security warning ───────────────────────────

subtest 'xfreerdp cert-ignore warns about MITM risk' => sub {
    my $xfreerdp = read_file('lib/method/PACMethod_xfreerdp.pm');
    like($xfreerdp, qr/cert-ignore.*MITM/s,
        'xfreerdp: cert-ignore produces MITM warning');
};

# ── Core dump protection ────────────────────────────────────────────────────

subtest 'Core dump protection attempted' => sub {
    like($asbru_conn, qr/RLIMIT_CORE/,
        'asbru_conn: attempts to disable core dumps');
    like($asbru_conn, qr/credential leakage.*core dump/is,
        'asbru_conn: documents core dump risk');
};

# ══════════════════════════════════════════════════════════════════════════════
# Phase 5: Password flow & credential leakage fixes
# ══════════════════════════════════════════════════════════════════════════════

# ── Session log password suppression ─────────────────────────────────────────

subtest 'send_slow suppresses log_file for passwords' => sub {
    like($asbru_conn, qr/send_slow.*hide.*log_file.*undef/s,
        'asbru_conn: send_slow() suspends log_file when hide=true');
    like($asbru_conn, qr/saved_log.*log_file/s,
        'asbru_conn: send_slow() restores log_file after password send');
};

# ── GETCMD uses connection_txt (sanitized) ───────────────────────────────────

subtest 'GETCMD output uses sanitized connection_txt' => sub {
    like($asbru_conn, qr/GETCMD.*connection_txt/s,
        'asbru_conn: GETCMD prints connection_txt not connection_cmd');
    like($asbru_conn, qr/Cannot spawn.*connection_txt/,
        'asbru_conn: spawn error uses connection_txt');
};

# ── VNC password no longer in echo pipe ──────────────────────────────────────

subtest 'VNC password not exposed in echo pipe' => sub {
    unlike($asbru_conn, qr/echo.*_doShellEscape.*PASS.*vncviewer/,
        'asbru_conn: no echo+password pipe for VNC');
    like($asbru_conn, qr/vnc_.*\.pass/,
        'asbru_conn: VNC uses secure temp file');
};

# ── Screenshot uses File::Temp ───────────────────────────────────────────────

subtest 'Screenshot file creation uses File::Temp' => sub {
    like($pac_screenshots, qr/File::Temp::tempfile.*asbru_screenshot/s,
        'PACScreenshots: uses File::Temp for atomic creation');
    unlike($pac_screenshots, qr/rand\(123456789\).*screenshots/,
        'PACScreenshots: no weak rand() for screenshot filenames');
};

# ── Pipe command whitelist no longer allows pipe char ────────────────────────

subtest 'Pipe command whitelist excludes pipe character' => sub {
    # Verify the pipe validation regex does NOT include \| in the character class
    unlike($pac_terminal, qr/Validate pipe commands.*\[.*\\\|.*\]\+\$/s,
        'PACTerminal: pipe whitelist does not include | character');
};

# ── Command file cleanup in END block ────────────────────────────────────────

subtest 'Command file cleaned up in END block' => sub {
    like($asbru_conn, qr/_cmd_file.*END|END.*_cmd_file/s,
        'asbru_conn: command file variable accessible to END block');
    like($asbru_conn, qr/unlink \$_cmd_file/,
        'asbru_conn: command file unlinked in END block');
};

# ── Config export re-encrypts passwords ──────────────────────────────────────

subtest 'Config export re-encrypts before writing' => sub {
    like($pac_config, qr/_cipherCFG.*export_cfg/s,
        'PACConfig: passwords re-encrypted before export');
    like($pac_config, qr/dclone.*_CFG.*_cipherCFG/s,
        'PACConfig: exports a deep-cloned+encrypted copy');
};

# ══════════════════════════════════════════════════════════════════════════════
# Phase 6: Entry point hardening & final sweep
# ══════════════════════════════════════════════════════════════════════════════

# ── Root privilege check ─────────────────────────────────────────────────────

subtest 'asbru-cm refuses to run as root' => sub {
    like($asbru_cm, qr/must not be run as root/,
        'asbru-cm: root privilege check present');
    like($asbru_cm, qr/\$< == 0.*\$> == 0/,
        'asbru-cm: checks both real and effective UID');
};

# ── Config-dir path traversal blocked ────────────────────────────────────────

subtest 'config-dir rejects path traversal' => sub {
    like($asbru_cm, qr/config-dir.*\.\./s,
        'asbru-cm: --config-dir rejects ..');
    like($asbru_cm, qr/temp-dir.*\.\./s,
        'asbru-cm: --temp-dir rejects ..');
};

# ── system() calls replaced with Perl builtins ──────────────────────────────

subtest 'Config backup uses File::Copy not system()' => sub {
    like($asbru_cm, qr/File::Copy::copy.*BACKUP/,
        'asbru-cm: backup uses File::Copy::copy');
    unlike($asbru_cm, qr/system.*cp -fp.*BACKUP/,
        'asbru-cm: no system() cp for backup operations');
};

# ── ASBRU_ENV_FOR_EXTERNAL validated at startup ──────────────────────────────

subtest 'ASBRU_ENV_FOR_EXTERNAL validated at startup' => sub {
    like($asbru_cm, qr/ASBRU_ENV_FOR_EXTERNAL.*suspicious.*clearing/s,
        'asbru-cm: ASBRU_ENV_FOR_EXTERNAL validated and cleared if suspicious');
};

# ── ASBRU_TMP symlink protection ────────────────────────────────────────────

subtest 'ASBRU_TMP rejects symlinks' => sub {
    like($asbru_cm, qr/ASBRU_TMP.*symlink.*not allowed/s,
        'asbru-cm: ASBRU_TMP rejects symlink paths');
};

# ── KeePass CLI path validated ───────────────────────────────────────────────

subtest 'KeePass CLI path validated against injection' => sub {
    like($pac_keepass, qr/pathcli.*invalid characters/s,
        'PACKeePass: CLI path rejects shell metacharacters');
    like($pac_keepass, qr/pathcli.*not a regular file/s,
        'PACKeePass: CLI path must be a regular file');
};

# ── _wPopUP uses list-form execution ────────────────────────────────────────

subtest '_wPopUP uses safe list-form execution' => sub {
    like($asbru_cm, qr/open\(my \$fh.*'-\|'.*asbru_confirm/s,
        'asbru-cm: _wPopUP uses list-form pipe open');
    unlike($asbru_cm, qr/`.*asbru_confirm/,
        'asbru-cm: _wPopUP no longer uses backticks');
};

done_testing();
