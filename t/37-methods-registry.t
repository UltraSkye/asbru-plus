#!/usr/bin/perl
# t/37-methods-registry.t — PAC::Methods registry surface check.
#
# Loading the actual registry needs a live PACEdit instance with Glade
# widgets, so we don't call it here. Instead we verify:
#   - source file is well-formed
#   - declares the right sub
#   - PACUtils._getMethods is wired as a goto-proxy
#   - all expected protocols are mentioned in the body

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $methods_pm = "$RealBin/../lib/PAC/Methods.pm";
ok(-r $methods_pm, 'lib/PAC/Methods.pm exists');

my $src = do {
    open my $f, '<', $methods_pm or die "open: $!";
    local $/; <$f>;
};

# 1. Package declaration
like($src, qr/^package PAC::Methods;/m, 'declares package PAC::Methods');

# 2. The single public function
like($src, qr/^sub registry\b/m, 'declares sub registry');

# 3. Imports the widget-accessor + escape helpers from PACUtils
like($src, qr/use PACUtils\s+qw\(\s*_\s+__\s*\)/, 'imports _ and __ from PACUtils');

# 4. All expected protocols present in the registry
my @expected = (
    'RDP (rdesktop)',
    'RDP (xfreerdp)',
    'VNC',
    'Serial (cu)',
    'Serial (remote-tty)',
    'IBM 3270/5250',
    'SSH',
);
for my $proto (@expected) {
    my $needle = quotemeta("\$methods{'$proto'}");
    like($src, qr/$needle\s*=/, "registry defines '$proto'");
}

# 5. PACUtils.pm wires the proxy
my $utils_pm = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils_pm, qr/^require PAC::Methods/m, 'PACUtils requires PAC::Methods');
like($utils_pm,
    qr/sub _getMethods\s*\{\s*goto\s*&PAC::Methods::registry\s*;\s*\}/,
    'PACUtils._getMethods is goto-proxy to registry');

# 6. Old body is gone — nothing should match the original "my %methods;"
#    pattern in PACUtils.pm anymore
unlike($utils_pm, qr/^sub _getMethods\s*\{\s*\n.*?my %methods;/ms,
    'old _getMethods body removed from PACUtils');

# 7. POD presence (also covered by t/27)
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item registry\b/m,  'POD =item registry');

done_testing();
