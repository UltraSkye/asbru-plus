#!/usr/bin/perl
# t/06-dark-mode.t — Verify dark mode auto-detection is correctly implemented
use strict;
use warnings;
use Test::More tests => 6;

my $main = 'lib/PACMain.pm';
open my $fh, '<', $main or BAIL_OUT("Cannot open $main: $!");
my $src = do { local $/; <$fh> };
close $fh;

# Dark theme auto-detection is present
like($src, qr/gsettings get org\.gnome\.desktop\.interface color-scheme/,
    'Queries GNOME color-scheme via gsettings');

like($src, qr/prefer-dark/,
    'Checks for prefer-dark value');

like($src, qr/GTK_THEME.*:dark/i,
    'Falls back to GTK_THEME env var for dark detection');

like($src, qr/asbru-dark/,
    'Selects asbru-dark theme when system is dark');

# GTK dark variant hint is applied
like($src, qr/gtk-application-prefer-dark-theme/,
    'Sets gtk-application-prefer-dark-theme for native widget tinting');

# The dark mode code is guarded — only when no theme explicitly set
like($src, qr/unless.*\$\{?\$self\}?.*defaults.*theme/,
    'Dark auto-select only fires when no theme explicitly configured');
