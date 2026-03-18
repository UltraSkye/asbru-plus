#!/usr/bin/perl
# t/03-critical-fixes.t — Verify that critical bug fixes are present in source
use strict;
use warnings;
use Test::More;

sub read_file {
    my $path = shift;
    open my $fh, '<', $path or BAIL_OUT("Cannot open $path: $!");
    my $content = do { local $/; <$fh> };
    close $fh;
    return $content;
}

my $keybindings = read_file('lib/PACKeyBindings.pm');
my $asbru_conn  = read_file('lib/asbru_conn');
my $pac_main    = read_file('lib/PACMain.pm');
my $pac_utils   = read_file('lib/PACUtils.pm');
my $pac_terminal = read_file('lib/PACTerminal.pm');
my $pac_edit    = read_file('lib/PACEdit.pm');
my $pac_config  = read_file('lib/PACConfig.pm');
my $pac_scripts = read_file('lib/PACScripts.pm');

# ── #1091: Keybinding modifier detection ─────────────────────────────────────

subtest 'Fix #1091 — keybinding modifier detection' => sub {
    unlike($keybindings, qr/\$state\s*\*\s*\[/,
        'No multiplication operator on state mask (old bug)');
    like($keybindings, qr/\$state->\{'shift-mask'\}/,
        'Uses hash dereference for shift-mask');
    like($keybindings, qr/\$state->\{'control-mask'\}/,
        'Uses hash dereference for control-mask');
    like($keybindings, qr/\$state->\{'mod1-mask'\}/,
        'Uses hash dereference for mod1-mask');
};

# ── #967: Telnet sends \r ─────────────────────────────────────────────────────

subtest 'Fix #967 — telnet sends CR not LF' => sub {
    like($asbru_conn, qr/METHOD.*eq.*telnet.*\\r/s,
        'Telnet condition with \\r present in asbru_conn');
    unlike($asbru_conn, qr/send_slow\(\$EXP,\s*"\$USER\\n"/,
        'No unconditional \\n after USERNAME send');
};

# ── #1027: Jump host PreferredAuthentications ─────────────────────────────────

subtest 'Fix #1027 — jump host does not hardcode PreferredAuthentications' => sub {
    unlike($asbru_conn,
        qr/PreferredAuthentications publickey,hostbased,keyboard-interactive,password/,
        'Hardcoded PreferredAuthentications removed from jump host config');
};

# ── #1112: Session log conditional ───────────────────────────────────────────

subtest 'Fix #1112 — session log only opened when enabled' => sub {
    like($asbru_conn, qr/save session logs.*&&.*LOG_FILE/s,
        'Log file open guarded by save session logs flag');
    unlike($asbru_conn, qr/# Set log file\nif \(open\(LOG/,
        'Log not unconditionally opened');
};

# ── #1148: known_hosts shell injection ───────────────────────────────────────

subtest 'Fix #1148 — known_hosts uses direct file open' => sub {
    unlike($asbru_conn, qr/open\s*\(F\s*,\s*`.*echo.*known_hosts/,
        'No backtick+echo in known_hosts open');
    like($asbru_conn, qr/open\s*\(\s*my\s+\$fh_in.*known_hosts/,
        'Uses lexical filehandle for known_hosts read');
};

# ── #968: readonly mode ───────────────────────────────────────────────────────

subtest 'Fix #968 — readonly mode skips nstore' => sub {
    like($pac_main, qr/return 1 if \$\$self\{_READONLY\}/,
        'nstore skipped in readonly mode');
};

# ── Security: proxy credentials not in process args ──────────────────────────

subtest 'Security — proxy password not in plain command args' => sub {
    unlike($asbru_conn,
        qr/--proxy-auth \$proxy_user:"\$proxy_pass"/,
        'Proxy password not passed as plain command-line argument');
    like($asbru_conn, qr/ASBRU_PROXY_AUTH/,
        'Proxy credentials passed via environment variable');
};

# ── Security: no double-eval regex ───────────────────────────────────────────

subtest 'Security — no dangerous double-eval regex' => sub {
    unlike($pac_utils, qr|/eeeg|,
        'No /eeeg double-eval in PACUtils.pm');
    unlike($pac_utils, qr|/eeg|,
        'No /eeg double-eval in PACUtils.pm');
};

# ── RDP password escaping ─────────────────────────────────────────────────────

subtest 'Fix #1113 — RDP password single-quote escaped' => sub {
    like($asbru_conn, qr/rdp_pass\s*=\s*\$PASS.*s\/'/s,
        'RDP password has single-quote escape applied');
};

# ── PPK key conversion ───────────────────────────────────────────────────────

subtest 'PPK key auto-conversion (PuTTY → OpenSSH)' => sub {
    like($asbru_conn, qr/\.ppk/i,
        'PPK extension detection present');
    like($asbru_conn, qr/puttygen/,
        'puttygen invocation present');
    like($asbru_conn, qr/private-openssh/,
        'Converts to OpenSSH format');
    like($asbru_conn, qr/putty-tools/,
        'Missing puttygen warning mentions putty-tools');
    like($asbru_conn, qr/unlink.*_ppk_tmp/,
        'Temp key file cleanup registered via END block');
    like($asbru_conn, qr/old-passphrase/,
        'Passphrase-protected PPK: --old-passphrase flag used');
    like($asbru_conn, qr/_ppk_pass_tmp/,
        'PPK passphrase written to temp file (not exposed on command line)');
    like($asbru_conn, qr/\$PASSPHRASE\s*=\s*''/,
        'PASSPHRASE cleared after conversion (converted key is unencrypted)');
    # Security: temp files must use File::Temp, not /tmp/$$
    like($asbru_conn, qr/use File::Temp/,
        'File::Temp imported for secure temp file creation');
    like($asbru_conn, qr/tempfile\(/,
        'tempfile() used instead of /tmp/$$  (no TOCTOU)');
    unlike($asbru_conn, qr|/tmp/asbru_key_\$\$|,
        'No direct /tmp/$$ path construction for key file');
};

# ── Security: password zeroing in END block ───────────────────────────────────

subtest 'Security — password zeroing in END block' => sub {
    like($asbru_conn, qr/END\s*\{/,
        'END block defined');
    like($asbru_conn, qr/\$PASS\s*=\s*"\\0" x length/,
        'PASS zeroed in END block');
    like($asbru_conn, qr/\$PASSPHRASE\s*=\s*"\\0" x length/,
        'PASSPHRASE zeroed in END block');
    like($asbru_conn, qr/\$SUDO_PASSWORD\s*=\s*"\\0" x length/,
        'SUDO_PASSWORD zeroed in END block');
    like($asbru_conn, qr/\$proxy_pass\s*=\s*"\\0" x length/,
        'proxy_pass zeroed in END block');
    like($asbru_conn, qr/delete \$ENV\{'ASBRU_PROXY_AUTH'\}/,
        'ASBRU_PROXY_AUTH deleted in END block');
};

# ── Security: VNC pfile cleanup ───────────────────────────────────────────────

subtest 'Security — VNC pfile cleaned up in END block' => sub {
    like($asbru_conn, qr/my \$_vnc_pfile/,
        '_vnc_pfile variable declared');
    like($asbru_conn, qr/unlink \$_vnc_pfile/,
        '_vnc_pfile unlinked in END block');
};

# ── Security: FIFO pipe quoting ───────────────────────────────────────────────

subtest 'Security — FIFO pipe path is double-quoted in shell' => sub {
    like($asbru_conn, qr/mkfifo\s+\\"\$pipe\\"/,
        'mkfifo argument is quoted');
    unlike($asbru_conn, qr/mkfifo\s+\$pipe\b/,
        'mkfifo does not use unquoted $pipe');
};

# ── Security: Pango markup escape ────────────────────────────────────────────

subtest 'Security — Pango markup uses @{[__()]} interpolation' => sub {
    like($pac_terminal, qr/\@\{\[__\(.*_TITLE.*\)\]\}/,
        'Title interpolated via @{[__(...)]} in tab label markup');
    unlike($pac_terminal, qr/>\s*__\(\$PACMain::RUNNING.*_TITLE.*\)\s*</,
        'No bare __() call outside @{[]} in Pango markup');
};

# ── Security: xdg-open path quoting ──────────────────────────────────────────

subtest 'Security — xdg-open in PACEdit quotes folder path' => sub {
    like($pac_edit, qr/\$folder\s*=~\s*s\/'/,
        'PACEdit: single-quote escape applied to folder');
    like($pac_edit, qr/xdg-open\s+'\\?\$folder'/,
        'PACEdit: folder wrapped in single quotes for xdg-open');
};

subtest 'Security — xdg-open in PACConfig quotes folder path' => sub {
    like($pac_config, qr/\$folder\s*=~\s*s\/'/,
        'PACConfig: single-quote escape applied to folder');
    like($pac_config, qr/xdg-open\s+'\\?\$folder'/,
        'PACConfig: folder wrapped in single quotes for xdg-open');
};

# ── Security: PACScripts tmpfile quoting ─────────────────────────────────────

subtest 'Security — PACScripts tmpfile is quoted in backtick call' => sub {
    like($pac_scripts, qr/'\$\^X'\s+-cw\s+'[^']/,
        'PACScripts: perl syntax-check uses quoted tmpfile path');
    unlike($pac_scripts, qr/'\$\^X'\s+-cw\s+\$tmpfile\b/,
        'PACScripts: unquoted $tmpfile no longer used directly');
};

done_testing();
