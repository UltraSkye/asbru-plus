#!/usr/bin/perl
# t/47-popup-menu.t — PAC::Dialog::PopupMenu extraction surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $pm = "$RealBin/../lib/PAC/Dialog/PopupMenu.pm";
ok(-r $pm, 'lib/PAC/Dialog/PopupMenu.pm exists');

my $src = do {
    open my $f, '<', $pm or die "open: $!";
    local $/; <$f>;
};

# 1. Package + show
like($src, qr/^package PAC::Dialog::PopupMenu;/m, 'declares package');
like($src, qr/^sub show\b/m,             'has show()');
like($src, qr/^sub _build_menu_data\b/m, 'has _build_menu_data internal');
like($src, qr/^sub _pos\b/m,             'has _pos internal');

# 2. State moved out of PACUtils namespace
like($src, qr/^my \$WIDGET_POPUP;/m, '$WIDGET_POPUP is module-lexical');
like($src, qr/^my \$JARI/m, '$JARI counter is module-lexical');
like($src, qr/^my \$EVENT;/m, '$EVENT is module-lexical');

# 3. Refs to PACUtils helpers properly qualified
like($src, qr/PACUtils::__text\(/, '__text qualified to PACUtils::');
like($src, qr/PACUtils::__\(\$label\)/, '__() qualified to PACUtils::');

# 4. Reentrancy guard preserved
like($src, qr/return 1 if defined \$WIDGET_POPUP && \$WIDGET_POPUP->get_visible/,
    'preserves "popup already open" guard');

# 5. Menu spec features supported
like($src, qr/\$m->\{separator\}/,    'supports separator');
like($src, qr/\$m->\{submenu\}/,      'supports submenu (recursive)');
like($src, qr/\$m->\{sensitive\}/,    'supports sensitive');
like($src, qr/\$m->\{tooltip\}/,      'supports tooltip');
like($src, qr/\$m->\{shortcut\}/,     'supports shortcut');
like($src, qr/\$m->\{stockicon\}/,    'supports stockicon');
like($src, qr/\$m->\{code\}/,         'supports code (callback)');

# 6. PACUtils proxy + state removal
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Dialog::PopupMenu/m,
    'PACUtils requires PAC::Dialog::PopupMenu');
like($utils, qr/sub _wPopUpMenu\s*\{\s*goto\s*&PAC::Dialog::PopupMenu::show/,
    '_wPopUpMenu is goto-proxy to ::show');
unlike($utils, qr/^my \$WIDGET_POPUP;/m,
    'PACUtils no longer declares "my \$WIDGET_POPUP"');
unlike($utils, qr/^sub _buildMenuData\b/m,
    'PACUtils no longer has _buildMenuData');
unlike($utils, qr/^sub _pos\b/m,
    'PACUtils no longer has _pos');

# 7. POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item show\b/m,      'POD =item show');

done_testing();
