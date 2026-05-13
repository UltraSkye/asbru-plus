#!/usr/bin/perl
# t/42-ssh-options.t — PAC::Net::SshOptions parser/normalizer.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# Pull Gtk3 in at compile time so Glib::Object::Introspection wires up
# its INIT block before any test code runs (avoids "Too late to run INIT
# block" stderr noise from require_ok of a Gtk3-using module).
use Gtk3;

require_ok('PAC::Net::SshOptions');
can_ok('PAC::Net::SshOptions', 'normalize_options');

# 1. Round-trip preserves common flags
my $r = PAC::Net::SshOptions::normalize_options(' -2 -X -C -g -A');
like($r, qr/-2/, 'preserves -2');
like($r, qr/-X/, 'preserves -X');
like($r, qr/-C/, 'preserves -C');
like($r, qr/-g/, 'preserves -g');
like($r, qr/-A/, 'preserves -A');

# 2. SSH version
like(PAC::Net::SshOptions::normalize_options(' -1 -X'), qr/-1/, 'SSH v1');
like(PAC::Net::SshOptions::normalize_options(' -2 -X'), qr/-2/, 'SSH v2');

# 3. Empty / undef inputs are safe (yield default-only output, not crash)
my $empty = PAC::Net::SshOptions::normalize_options('');
ok(defined $empty, 'empty input does not crash');
my $undef = PAC::Net::SshOptions::normalize_options(undef);
ok(defined $undef, 'undef input does not crash');
is($empty, $undef, 'empty and undef produce identical output (default flags)');

# 4. PACUtils proxy is wired
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Net::SshOptions/m, 'PACUtils requires PAC::Net::SshOptions');
like($utils,
    qr/sub _updateSSHToIPv6\s*\{\s*goto\s*&PAC::Net::SshOptions::normalize_options\s*;\s*\}/,
    '_updateSSHToIPv6 is goto-proxy');

# 5. Calling through legacy PACUtils::_updateSSHToIPv6 still works
SKIP: {
    skip 'PACUtils not loadable here (UUID::Tiny etc.)', 1
        unless eval { require PACUtils; 1 };
    my $via_proxy = PACUtils::_updateSSHToIPv6(' -2 -X');
    like($via_proxy, qr/-2/, 'legacy proxy returns same as direct call');
}

# 6. POD
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Net/SshOptions.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,            'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m,      'POD: PUBLIC API');
like($src, qr/^=item normalize_options/m, 'POD =item normalize_options');

done_testing();
