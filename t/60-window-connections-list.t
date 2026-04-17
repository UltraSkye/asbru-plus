#!/usr/bin/perl
# t/60-window-connections-list.t — PAC::Window::ConnectionsList surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Window::ConnectionsList');
can_ok('PAC::Window::ConnectionsList', $_)
    for qw(show hide toggle apply_toggle);

my $src = do {
    open my $fh, '<', "$RealBin/../lib/PAC/Window/ConnectionsList.pm"
        or die "open: $!";
    local $/; <$fh>;
};

# Package + entries
like($src, qr/^package PAC::Window::ConnectionsList;/m, 'declares package');
like($src, qr/^sub show\b/m,         'has show');
like($src, qr/^sub hide\b/m,         'has hide');
like($src, qr/^sub toggle\b/m,       'has toggle');
like($src, qr/^sub apply_toggle\b/m, 'has apply_toggle');

# Layout-aware behavior preserved
like($src, qr/Compact/, 'mentions Compact layout');
like($src, qr/vboxCommandPanel/, 'touches vboxCommandPanel');
like($src, qr/showConnBtn/, 'reads showConnBtn');

# show() force semantics
like($src, qr/->hide\(\);\s*\$\$self\{_GUI\}\{main\}->show\(\)/,
    'show(force=1) hides+shows main to unstick wm');
like($src, qr/_CMDLINETRAY/, 'show() handles CMDLINETRAY iconified bootstrap');
like($src, qr/->present\(\)/, 'show() calls present()');

# hide() snapshots position
like($src, qr/get_position/, 'hide() snapshots window position');
like($src, qr/posx.*posy|posy.*posx/, 'hide() stores posx/posy');

# toggle() flips toolbar button
like($src, qr/set_active\(\s*!\s*\$\$self\{_GUI\}\{showConnBtn\}->get_active/,
    'toggle() flips showConnBtn');

# apply_toggle delegates to PACMain in Compact, manipulates panel in Traditional
like($src, qr/\$PACMain::FUNCS\{_MAIN\}->_showConnectionsList/,
    'apply_toggle Compact -> _showConnectionsList');
like($src, qr/\$PACMain::FUNCS\{_MAIN\}->_hideConnectionsList/,
    'apply_toggle Compact -> _hideConnectionsList');
like($src, qr/_HAS_FOCUS.*=.*''|_HAS_FOCUS.*=.*""/,
    'apply_toggle Traditional clears _HAS_FOCUS when showing');
like($src, qr/_doFocusPage/,
    'apply_toggle Traditional refocuses tab when hiding');

# PACMain wrappers
my $main = do {
    open my $fh, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$fh>;
};
like($main, qr/^require PAC::Window::ConnectionsList/m,
    'PACMain requires PAC::Window::ConnectionsList');
like($main, qr/sub _showConnectionsList\s*\{\s*goto\s*&PAC::Window::ConnectionsList::show\s*;\s*\}/,
    '_showConnectionsList proxy');
like($main, qr/sub _hideConnectionsList\s*\{\s*goto\s*&PAC::Window::ConnectionsList::hide\s*;\s*\}/,
    '_hideConnectionsList proxy');
like($main, qr/sub _toggleConnectionsList\s*\{\s*goto\s*&PAC::Window::ConnectionsList::toggle\s*;\s*\}/,
    '_toggleConnectionsList proxy');
like($main, qr/sub _doToggleDisplayConnectionsList\s*\{\s*goto\s*&PAC::Window::ConnectionsList::apply_toggle\s*;\s*\}/,
    '_doToggleDisplayConnectionsList proxy');

# POD
like($src, qr/^=head1 NAME/m,            'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m,      'POD: PUBLIC API');
like($src, qr/^=item show\b/m,           'POD =item show');
like($src, qr/^=item hide\b/m,           'POD =item hide');
like($src, qr/^=item toggle\b/m,         'POD =item toggle');
like($src, qr/^=item apply_toggle\b/m,   'POD =item apply_toggle');

done_testing();
