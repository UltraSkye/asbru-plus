#!/usr/bin/perl
# t/45-window-splash.t — PAC::Window::Splash extraction surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $splash_pm = "$RealBin/../lib/PAC/Window/Splash.pm";
ok(-r $splash_pm, 'PAC/Window/Splash.pm exists');

my $src = do {
    open my $f, '<', $splash_pm or die "open: $!";
    local $/; <$f>;
};

# Package + 2 public functions
like($src, qr/^package PAC::Window::Splash;/m, 'declares package');
like($src, qr/^sub show\b/m, 'has show()');
like($src, qr/^sub gui\b/m,  'has gui()');

# Singleton state via my %WIN
like($src, qr/^my %WIN;/m, 'singleton state via my %WIN lexical');

# Honors $PACMain::_NO_SPLASH
like($src, qr/\$PACMain::_NO_SPLASH/, 'honors $PACMain::_NO_SPLASH');

# Reads $PACUtils::APPNAME / APPVERSION (qualified)
like($src, qr/\$PACUtils::APPNAME/,    'reads $PACUtils::APPNAME');
like($src, qr/\$PACUtils::APPVERSION/, 'reads $PACUtils::APPVERSION');

# Splash image path computed from $PACUtils::RES_DIR (after the
# RES_DIR promotion to 'our' in P3/8)
like($src, qr/\$PACUtils::RES_DIR/, 'reads $PACUtils::RES_DIR for splash image');

# Show/destroy cycle: must include show_all + destroy
like($src, qr/->show_all/, 'show_all on truthy show');
like($src, qr/->destroy/,  'destroy on falsy show');

# PACUtils proxy + lexical removal
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Window::Splash/m,
    'PACUtils requires PAC::Window::Splash');
like($utils,
    qr/sub _splash\s*\{\s*goto\s*&PAC::Window::Splash::show\s*;\s*\}/,
    '_splash is goto-proxy to ::show');

# Old %WINDOWSPLASH lexical removed (commented out, not active)
unlike($utils, qr/^my %WINDOWSPLASH;/m,
    'old "my %WINDOWSPLASH" no longer active');

# PAC::Dialog uses the new gui() accessor
my $dialog = do {
    open my $f, '<', "$RealBin/../lib/PAC/Dialog.pm" or die "open: $!";
    local $/; <$f>;
};
like($dialog, qr/PAC::Window::Splash::gui\(\)/,
    'PAC::Dialog uses PAC::Window::Splash::gui() for fallback parent');
unlike($dialog, qr/\$PACUtils::WINDOWSPLASH/,
    'PAC::Dialog no longer reads legacy $PACUtils::WINDOWSPLASH');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item show\b/m,      'POD =item show');
like($src, qr/^=item gui\b/m,       'POD =item gui');

done_testing();
