#!/usr/bin/perl
# t/39-theme-icons.t — Surface check for PAC::Theme::Icons extraction.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $icons_pm = "$RealBin/../lib/PAC/Theme/Icons.pm";
ok(-r $icons_pm, 'lib/PAC/Theme/Icons.pm exists');

my $src = do {
    open my $f, '<', $icons_pm or die "open: $!";
    local $/; <$f>;
};

# 1. Package + entry sub
like($src, qr/^package PAC::Theme::Icons;/m, 'declares package');
like($src, qr/^sub register\b/m, 'declares sub register');

# 2. Imports / state
like($src, qr/use Gtk3\b/, 'uses Gtk3');
like($src, qr/my \$THEME_DIR/, 'has private THEME_DIR');
like($src, qr/my \$RES_DIR/, 'has private RES_DIR');

# 3. Reads PACUtils RES_DIR via package var (after promotion to 'our')
like($src, qr/\$PACUtils::RES_DIR/, 'reads $PACUtils::RES_DIR for fallback');

# 4. Several known asbru icons present in the registry
my @must_have_icons = (
    'asbru-help',
    'asbru-app-big',
    'asbru-cluster-manager',
    'asbru-favourite-on',
    'asbru-favourite-off',
);
for my $icon (@must_have_icons) {
    my $needle = quotemeta("'$icon'");
    like($src, qr/$needle\s*=>/, "registers '$icon'");
}

# 5. Builds a Gtk3::IconFactory and adds it as default
like($src, qr/Gtk3::IconFactory/, 'creates Gtk3::IconFactory');
like($src, qr/->add_default\(\)/, 'registers as default factory');

# 6. PACUtils proxy in place
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Theme::Icons/m, 'PACUtils requires PAC::Theme::Icons');
like($utils, qr/sub _registerPACIcons\s*\{\s*goto\s*&PAC::Theme::Icons::register\s*;\s*\}/,
    'PACUtils._registerPACIcons is goto-proxy to register');

# 7. RES_DIR / THEME_DIR were promoted to 'our' so PAC::Theme::Icons can
#    read them. Confirm the promotion (regression: somebody changing back
#    to 'my' would silently break the icon factory at runtime).
like($utils, qr/^our \$RES_DIR\s*=/m, 'PACUtils $RES_DIR is "our" (visible to PAC::Theme::Icons)');
like($utils, qr/^our \$THEME_DIR\s*=/m, 'PACUtils $THEME_DIR is "our"');

# 8. POD presence
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item register\b/m,  'POD =item register');

done_testing();
