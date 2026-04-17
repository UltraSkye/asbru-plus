#!/usr/bin/perl
# t/38-config-sanitycheck.t — surface AND behavior tests for the
# PAC::Config::SanityCheck extraction.
#
# The original test only static-grepped the source. After finding a
# critical extraction-regression in PAC::SessionLog::purge_screenshots
# (a literal "_cfg_dir()/screenshots" string that never interpolated,
# and went unnoticed for the same surface-only-test reason), we now
# also CALL run() and assert observable behavior on a real cfg hash.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

my $sc = "$RealBin/../lib/PAC/Config/SanityCheck.pm";
ok(-r $sc, 'lib/PAC/Config/SanityCheck.pm exists');

my $src = do {
    open my $f, '<', $sc or die "open: $!";
    local $/; <$f>;
};

# 1. Package + entry point
like($src, qr/^package PAC::Config::SanityCheck;/m, 'declares package');
like($src, qr/^sub run\b/m, 'declares sub run');

# 2. Default keys we know must be set (a small spot-check)
for my $key (
    "'auto accept key'",
    "'show screenshots'",
    "'tabs in main window'",
    "'session log pattern'",
    "'session logs folder'",
    "'sudo password'",
    "'use gui password'",
    "'terminal scrollback lines'",
    "'command prompt'",
) {
    like($src, qr/\Q$key\E/, "body sets $key");
}

# 3. DEFAULT_*_PROMPT references are properly qualified to PACUtils::
#    (the sed-driven extraction had to rewrite these — a regression here
#    would mean the prompts default to undef silently)
for my $sym (qw(
    DEFAULT_COMMAND_PROMPT
    DEFAULT_USERNAME_PROMPT
    DEFAULT_PASSWORD_PROMPT
    DEFAULT_HOSTKEYCHANGED_PROMPT
    DEFAULT_PRESSANYKEY_PROMPT
    DEFAULT_REMOTEHOSTCHANGED_PROMPT
)) {
    like($src, qr/\$PACUtils::\Q$sym\E/, "$sym qualified to PACUtils::");
    unlike($src, qr/\$\Q$sym\E[^A-Za-z]/, "no unqualified bare \$$sym");
}

# 4. _cfg_dir helper recovers the config directory from $ENV{ASBRU_CFG}
like($src, qr/sub _cfg_dir/, 'has _cfg_dir helper');
like($src, qr/\$ENV\{ASBRU_CFG\}/, 'reads ASBRU_CFG env var');

# 5. PACUtils.pm wires the proxy
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Config::SanityCheck/m,
    'PACUtils requires PAC::Config::SanityCheck');
like($utils,
    qr/sub _cfgSanityCheck\s*\{\s*goto\s*&PAC::Config::SanityCheck::run\s*;\s*\}/,
    'PACUtils._cfgSanityCheck is goto-proxy to ::run');

# 6. POD presence
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item run\b/m,       'POD =item run');

# 7. BEHAVIOR — actually invoke run() on a fresh cfg and verify
# observable outputs. This is the test that would have caught a
# literal-string-not-interpolated regression like the one in
# PAC::SessionLog::purge_screenshots.
SKIP: {
    eval { require PAC::Config::SanityCheck; };
    skip "PAC::Config::SanityCheck unloadable (UUID::Tiny missing?)", 11
        if $@;

    local $ENV{ASBRU_CFG} = '/tmp/test_asbru_cfg_sanity_dir';

    # Mock the PACUtils prompt constants — in production these are set
    # by `use PACUtils;` (which we can't do here without Gtk3::Gdk).
    # The qualified references in SanityCheck.pm read the package vars
    # directly, so setting them in the test package works.
    no warnings 'once';
    local $PACUtils::DEFAULT_COMMAND_PROMPT     = 'TEST_CMD_PROMPT';
    local $PACUtils::DEFAULT_USERNAME_PROMPT    = 'TEST_USER_PROMPT';
    local $PACUtils::DEFAULT_PASSWORD_PROMPT    = 'TEST_PASS_PROMPT';
    local $PACUtils::DEFAULT_HOSTKEYCHANGED_PROMPT  = 'TEST_HK';
    local $PACUtils::DEFAULT_PRESSANYKEY_PROMPT = 'TEST_PAK';
    local $PACUtils::DEFAULT_REMOTEHOSTCHANGED_PROMPT = 'TEST_RH';

    my $cfg = {};
    PAC::Config::SanityCheck::run($cfg);

    isa_ok($cfg->{defaults}, 'HASH', 'defaults populated');
    cmp_ok(scalar keys %{$cfg->{defaults}}, '>', 100,
        'run() populates 100+ default keys');

    # _cfg_dir() interpolation — this is THE regression-class to catch.
    # If `_cfg_dir() . "/session_logs"` were ever rewritten as
    # "_cfg_dir()/session_logs", session_logs would be a relative path.
    is($cfg->{defaults}{'session logs folder'},
        '/tmp/test_asbru_cfg_sanity_dir/session_logs',
        'session logs folder = $ENV{ASBRU_CFG}/session_logs (interpolation works)');

    # SECURITY-relevant default: auto-accept-key MUST be off by default
    is($cfg->{defaults}{'auto accept key'}, 0,
        'auto accept key default is 0 (MITM-safe)');

    # DEFAULT_*_PROMPT pulled from PACUtils package globals — verify the
    # qualified-name reference at line 66-71 actually resolves.
    is($cfg->{defaults}{'command prompt'}, 'TEST_CMD_PROMPT',
        'command prompt default resolved from $PACUtils::DEFAULT_COMMAND_PROMPT');
    is($cfg->{defaults}{'username prompt'}, 'TEST_USER_PROMPT',
        'username prompt default resolved');
    is($cfg->{defaults}{'password prompt'}, 'TEST_PASS_PROMPT',
        'password prompt default resolved');

    # Idempotence: running twice on the same cfg must not change anything.
    use Storable qw(dclone);
    my $snapshot = dclone($cfg);
    PAC::Config::SanityCheck::run($cfg);
    is_deeply($cfg, $snapshot, 'run() is idempotent on already-sanitized cfg');

    # Pre-existing user values are preserved (//= semantics).
    my $cfg2 = { defaults => { 'auto accept key' => 1, 'tabs position' => 'left' } };
    PAC::Config::SanityCheck::run($cfg2);
    is($cfg2->{defaults}{'auto accept key'}, 1,
        'pre-existing user value for auto accept key preserved');
    is($cfg2->{defaults}{'tabs position'}, 'left',
        'pre-existing user value for tabs position preserved');

    # Empty environments hash gets created.
    isa_ok($cfg->{environments}, 'HASH', 'environments populated');
}

done_testing();
