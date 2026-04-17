#!/usr/bin/perl
# t/38-config-sanitycheck.t — Surface check for the PAC::Config::SanityCheck
# extraction.
#
# We don't load and execute the function (it pulls PACUtils which needs
# UUID::Tiny + GTK in scope to fully load) — instead static-check that:
#   - file exists with right package + sub
#   - PACUtils proxies _cfgSanityCheck → SanityCheck::run
#   - body contains key default keys (regression: nobody accidentally
#     drops a 660-line block)
#   - DEFAULT_*_PROMPT references are qualified to $PACUtils:: (would
#     otherwise be undefined globals at runtime)

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

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

done_testing();
