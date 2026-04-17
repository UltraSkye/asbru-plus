#!/usr/bin/perl
# t/51-window-about.t — PAC::Window::About surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $about_pm = "$RealBin/../lib/PAC/Window/About.pm";
ok(-r $about_pm, 'PAC/Window/About.pm exists');

my $src = do {
    open my $f, '<', $about_pm or die "open: $!";
    local $/; <$f>;
};

# Package + show() entry
like($src, qr/^package PAC::Window::About;/m, 'declares package');
like($src, qr/^sub show\b/m, 'has show()');

# Reads from PACUtils package vars (qualified)
like($src, qr/\$PACUtils::APPNAME/, 'reads $PACUtils::APPNAME');
like($src, qr/\$PACUtils::APPVERSION/, 'reads $PACUtils::APPVERSION');
like($src, qr/\$PACUtils::RES_DIR/, 'reads $PACUtils::RES_DIR');

# UI structure: logo, version, info grid, Close + Visit buttons
like($src, qr/asbru-logo-256\.png/, 'shows logo');
like($src, qr/Visit Repository/,    'has Visit Repository button');
like($src, qr/Close/,               'has Close button');
like($src, qr/UltraSkye\/asbru-plus/, 'links to fork');
like($src, qr/asbru-cm\/asbru-cm/,  'links to upstream');

# Browser-open fallback chain
like($src, qr/xdg-open.*gio.*sensible-browser.*firefox/s,
    'tries xdg-open / gio / sensible-browser / firefox in order');

# Falls back to PAC::Dialog::_wMessage on failure
like($src, qr/PAC::Dialog::_wMessage/, 'falls back to _wMessage on URL-open failure');

# PACMain wrapper preserved
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Window::About/m,
    'PACMain requires PAC::Window::About');
like($main, qr/sub _showAboutWindow \{[^}]*PAC::Window::About::show/s,
    '_showAboutWindow wrapper calls PAC::Window::About::show');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item show\b/m,      'POD =item show');

done_testing();
