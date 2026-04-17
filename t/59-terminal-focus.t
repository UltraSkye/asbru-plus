#!/usr/bin/perl
# t/59-terminal-focus.t — PAC::Terminal::Focus surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $f = "$RealBin/../lib/PAC/Terminal/Focus.pm";
ok(-r $f, 'PAC/Terminal/Focus.pm exists');

my $src = do {
    open my $f, '<', $f or die "open: $!";
    local $/; <$f>;
};

# Package + entry
like($src, qr/^package PAC::Terminal::Focus;/m, 'declares package');
like($src, qr/^sub focus_page\b/m,              'has focus_page');

# Reads PACMain::RUNNING (qualified)
like($src, qr/%PACMain::RUNNING/, 'reads %PACMain::RUNNING');

# Side effect chain preserved
like($src, qr/expand_to_path/,    'expands tree to path');
like($src, qr/set_cursor/,        'moves tree cursor');
like($src, qr/_setTabColour/,     'refreshes tab colour');
like($src, qr/grab_focus/,        'VTE grabs focus');
like($src, qr/_HAS_FOCUS/,        'stores _HAS_FOCUS');

# Defensive: skips terminals with undef container
like($src, qr/next unless defined \$check_gui/,
    'skips RUNNING entries with undef container');

# PACMain wrapper
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Terminal::Focus/m,
    'PACMain requires PAC::Terminal::Focus');
like($main, qr/sub _doFocusPage\s*\{\s*goto\s*&PAC::Terminal::Focus::focus_page\s*;\s*\}/,
    '_doFocusPage proxy');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item focus_page\b/m,'POD =item focus_page');

done_testing();
