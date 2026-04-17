#!/usr/bin/perl
# t/34-subst.t — PAC::Subst template substitution engine.
# Tests the non-interactive paths (no <ASK:> dialog needed).

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# PAC::Subst pulls in PAC::Globals (which needs PACMain/PACScripts namespaces
# to alias to) and PAC::Dialog (which loads Gtk3). Stub the dependencies so
# the test can run headless on bare Perl.
BEGIN {
    package PACMain;
    our %FUNCS       = ();
    our %RUNNING     = ();
    our %SOCKS5PORTS = ();

    package PACScripts;
    our %SHARED   = ();
    our %COMMON   = ();
    our %PAC      = ();
    our %TERMINAL = ();

    # Stub PAC::Dialog so we don't need Gtk3 loaded for the non-interactive
    # path tests. The <ASK:> branches aren't exercised here.
    package PAC::Dialog;
    sub _wEnterValue { return 'STUBBED' }
    $INC{'PAC/Dialog.pm'} = 'stub';

    # Stub Gtk3 so PAC::Globals' use of it doesn't fail (it doesn't use
    # Gtk3 directly, but PAC::Dialog used to require it at use time).
    $INC{'Gtk3.pm'} = 'stub';
}

require_ok('PAC::Subst');
can_ok('PAC::Subst', $_) for qw(subst subst_cfg);

#-------------------------------------------------------------------------
# Build a minimal cfg with one connection
#-------------------------------------------------------------------------
my %cfg = (
    defaults => {
        'global variables' => {
            'editor'  => { value => 'vim' },
            'malicious' => { value => 'foo;rm -rf /' },
        },
        'keepass' => { 'use_keepass' => 0 },
    },
    environments => {
        'uuid-1' => {
            name      => 'webserver',
            title     => 'Web Server',
            ip        => '10.0.0.1',
            port      => 22,
            user      => 'alice',
            pass      => 'secret',
            method    => 'ssh',
            'auth type' => 'userpass',
            variables => [
                { txt => 'first-var' },
                { txt => 'with;injection' },
            ],
        },
    },
);

#-------------------------------------------------------------------------
# 1. Built-in vars
#-------------------------------------------------------------------------
my $r = PAC::Subst::subst('ssh <USER>@<IP> -p <PORT>', \%cfg, 'uuid-1');
is($r, 'ssh alice@10.0.0.1 -p 22', 'built-in <USER>/<IP>/<PORT>');

$r = PAC::Subst::subst('echo <NAME> / <TITLE>', \%cfg, 'uuid-1');
is($r, 'echo webserver / Web Server', '<NAME>/<TITLE>');

$r = PAC::Subst::subst('id=<UUID>', \%cfg, 'uuid-1');
is($r, 'id=uuid-1', '<UUID>');

#-------------------------------------------------------------------------
# 2. <GV:>  global variables
#-------------------------------------------------------------------------
$r = PAC::Subst::subst('vi=<GV:editor>', \%cfg, 'uuid-1');
is($r, 'vi=vim', '<GV:name> resolves');

# Shell-meta sanitization on <GV:> values
{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $r = PAC::Subst::subst('cmd=<GV:malicious>', \%cfg, 'uuid-1');
    # Sanitization escapes only [`$(){};&|<>] — `;` matches; `/` and `-`
    # don't, so they pass through untouched.
    is($r, 'cmd=foo\;rm -rf /', '<GV:> shell metachars (only ;) sanitized');
    like(join('', @warnings), qr/shell metacharacters/,
        'sanitization emits a warning');
}

#-------------------------------------------------------------------------
# 3. <V:N>  session variables
#-------------------------------------------------------------------------
$r = PAC::Subst::subst('a=<V:0>', \%cfg, 'uuid-1');
is($r, 'a=first-var', '<V:0> resolves');

# Shell-meta sanitization on <V:>
{
    local $SIG{__WARN__} = sub {};
    $r = PAC::Subst::subst('b=<V:1>', \%cfg, 'uuid-1');
    like($r, qr/with\\;injection/, '<V:N> shell metachars sanitized');
}

#-------------------------------------------------------------------------
# 4. <ENV:>
#-------------------------------------------------------------------------
local $ENV{ASBRU_TEST_VAR} = 'env-value';
$r = PAC::Subst::subst('e=<ENV:ASBRU_TEST_VAR>', \%cfg, 'uuid-1');
is($r, 'e=env-value', '<ENV:NAME> resolves');

$r = PAC::Subst::subst('e=<ENV:NONEXISTENT_TEST>', \%cfg, 'uuid-1');
is($r, 'e=<ENV:NONEXISTENT_TEST>', 'unset env var left as-is');

#-------------------------------------------------------------------------
# 5. Escape sequences
#-------------------------------------------------------------------------
$r = PAC::Subst::subst('hi\nworld', \%cfg, 'uuid-1');
is($r, "hi\nworld", '\\n -> newline');

$r = PAC::Subst::subst('a\tb\rc', \%cfg, 'uuid-1');
is($r, "a\tb\rc", '\\t and \\r recognized');

#-------------------------------------------------------------------------
# 6. <CMD:> whitelist + blocking
#-------------------------------------------------------------------------
{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    # Bad: shell operator
    $r = PAC::Subst::subst('x=<CMD:rm -rf /; whoami>', \%cfg, 'uuid-1');
    is($r, 'x=', '<CMD:> with disallowed chars stripped');
    like(join('', @warnings), qr/disallowed characters/,
        '<CMD:> blocking emits warning');

    # Bad: eval keyword
    @warnings = ();
    $r = PAC::Subst::subst('y=<CMD:perl eval xyz>', \%cfg, 'uuid-1');
    is($r, 'y=', '<CMD:> with eval keyword stripped');
    like(join('', @warnings), qr/disallowed characters/,
        '<CMD:eval ...> blocking emits warning');
}

# Good <CMD:> — whitelist allows it, runs `echo foo`. Use a real
# binary that's available everywhere.
$r = PAC::Subst::subst('out=<CMD:echo asbru-cmd-test>', \%cfg, 'uuid-1');
is($r, 'out=asbru-cmd-test', '<CMD:echo ...> runs and substitutes');

#-------------------------------------------------------------------------
# 7. ASBRU_ENV_FOR_EXTERNAL validation
#-------------------------------------------------------------------------
{
    local $ENV{ASBRU_ENV_FOR_EXTERNAL} = 'rm -rf /';
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $r = PAC::Subst::subst('z=<CMD:echo hi>', \%cfg, 'uuid-1');
    like(join('', @warnings), qr/ASBRU_ENV_FOR_EXTERNAL.*suspicious/,
        'malicious ASBRU_ENV_FOR_EXTERNAL rejected with warning');
    is($r, 'z=hi', '<CMD:> still runs but with ignored prefix');
}

{
    local $ENV{ASBRU_ENV_FOR_EXTERNAL} = 'LD_LIBRARY_PATH=/opt/x';
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $r = PAC::Subst::subst('z=<CMD:echo ok>', \%cfg, 'uuid-1');
    is(join('', @warnings), '',
        'well-formed ASBRU_ENV_FOR_EXTERNAL accepted (no warning)');
}

#-------------------------------------------------------------------------
# 8. <TEE:> / <PIPE:> / <CTRL_*:> output meta
#-------------------------------------------------------------------------
my ($cmd, $meta) = PAC::Subst::subst('echo x <TEE:my-out>', \%cfg, 'uuid-1');
is($cmd, 'echo x ', '<TEE:> stripped from string');
is($meta->{tee}, 'my-out', '<TEE:> recorded in meta');

($cmd, $meta) = PAC::Subst::subst('cmd <PIPE:sort>', \%cfg, 'uuid-1');
is_deeply($meta->{pipe}, ['sort'], '<PIPE:> recorded in meta');

($cmd, $meta) = PAC::Subst::subst('foo <CTRL_C:cancel>', \%cfg, 'uuid-1');
is($meta->{ctrl}{ctrl}, 'C',      '<CTRL_X:> ctrl recorded');
is($meta->{ctrl}{cmd},  'cancel', '<CTRL_X:> cmd recorded');

#-------------------------------------------------------------------------
# 9. Unknown uuid → return original string unchanged
#-------------------------------------------------------------------------
$r = PAC::Subst::subst('a <USER>', \%cfg, 'no-such-uuid');
is($r, 'a <USER>', 'unknown uuid → string unchanged');

#-------------------------------------------------------------------------
# 10. asbru_conn flag suppresses interactive + CMD branches
#-------------------------------------------------------------------------
$r = PAC::Subst::subst('hello <CMD:echo ignored>',
    \%cfg, 'uuid-1', undef, 1);  # 5th arg = asbru_conn=1
is($r, 'hello <CMD:echo ignored>',
    'asbru_conn=1: <CMD:> not executed (left in place)');

#-------------------------------------------------------------------------
# 11. subst_cfg bulk-edit
#-------------------------------------------------------------------------
my %env = (name => 'old-name', port => 22);
my %list = (
    'name' => { change => 1, value => 'new-name' },
    'port' => { change => 0, value => 999 },          # change=0 → no-op
);
PAC::Subst::subst_cfg(\%env, \%list);
is($env{name}, 'new-name', 'subst_cfg: change=1 applies value');
is($env{port}, 22, 'subst_cfg: change=0 leaves value alone');

# regex mode
my %env2 = (name => 'host-prod-01');
my %list2 = (
    'name' => { change => 1, regexp => 1,
                match => 'prod', value => 'staging' },
);
PAC::Subst::subst_cfg(\%env2, \%list2);
is($env2{name}, 'host-staging-01', 'subst_cfg: regex match/replace');

#-------------------------------------------------------------------------
# 12. POD coverage
#-------------------------------------------------------------------------
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Subst.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item subst\b/m,     'POD =item for subst');
like($src, qr/^=item subst_cfg\b/m, 'POD =item for subst_cfg');

done_testing();
