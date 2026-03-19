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

done_testing();
