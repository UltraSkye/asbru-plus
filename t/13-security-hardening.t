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

# ── Shell escape function ─────────────────────────────────────────────────────

subtest '_doShellEscape covers all dangerous chars' => sub {
    like($pac_utils, qr/_doShellEscape.*\$.*\\.*`.*".*!/s,
        '_doShellEscape escapes $, \\, `, ", !');
    like($pac_utils, qr/_doShellEscape.*\\n/s,
        '_doShellEscape handles newlines');
    like($pac_utils, qr/_doShellEscape.*\\r/s,
        '_doShellEscape handles carriage returns');
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

# ── CMD substitution has sanitization ────────────────────────────────────────

subtest 'CMD substitution has injection protection' => sub {
    like($asbru_conn, qr/CMD.*Blocked suspicious/s,
        'asbru_conn: CMD substitution blocks suspicious patterns');
    like($pac_utils, qr/CMD.*Blocked suspicious/s,
        'PACUtils: CMD substitution blocks suspicious patterns');
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
    like($pac_utils, qr/Crypt::Rijndael/,
        'PACUtils: uses Crypt::Rijndael (AES)');
    like($pac_utils, qr/opensslv2/,
        'PACUtils: uses opensslv2 PBKDF');
};

# ── Master password infrastructure ──────────────────────────────────────────

subtest 'Master password system exists' => sub {
    like($pac_utils, qr/sub _initMasterCipher/,
        'PACUtils: _initMasterCipher function exists');
    like($pac_utils, qr/sub _createMasterVerifier/,
        'PACUtils: _createMasterVerifier function exists');
    like($pac_utils, qr/sub _verifyMasterPassword/,
        'PACUtils: _verifyMasterPassword function exists');
    like($pac_utils, qr/sub _migrateCipherCFG/,
        'PACUtils: _migrateCipherCFG function exists');
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
};

# ── Temp config files have restricted permissions ───────────────────────────

subtest 'Temp config files get chmod 0600' => sub {
    like($pac_terminal, qr/chmod\s+0600.*TMPCFG/s,
        'PACTerminal: nstore temp file gets chmod 0600');
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
    like($pac_main, qr/flock.*LOCK_EX/s,
        'PACMain: config save uses LOCK_EX');
};

# ── VNC password uses IPC::Open3, not shell echo ────────────────────────────

subtest 'VNC password avoids shell echo' => sub {
    unlike($asbru_conn, qr/echo.*vncpasswd/,
        'No echo|vncpasswd shell pipe');
    like($asbru_conn, qr/IPC::Open3.*vncpasswd/s,
        'VNC uses IPC::Open3');
};

done_testing();
