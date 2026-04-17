#!/usr/bin/perl
# t/58-window-layout.t — PAC::Window::Layout extraction surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Window::Layout');
can_ok('PAC::Window::Layout', $_) for qw(set_safe_options apply);

my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Window/Layout.pm" or die "open: $!";
    local $/; <$f>;
};

# Reads $PACMain::STRAY (qualified)
like($src, qr/\$PACMain::STRAY/, 'reads $PACMain::STRAY');

# Layouts handled
like($src, qr/Compact/, 'handles Compact layout');
like($src, qr/lt tabs in main window/, 'shadows traditional settings as lt …');

# Apply Compact: hides toolbar widgets, resizes
like($src, qr/connSearch.*connExecBtn|connExecBtn.*connSearch/s,
    'apply Compact hides toolbar widgets');
like($src, qr/set_default_size\(220/, 'apply Compact sets compact size');

# ── set_safe_options behavior tests ─────────────────────────────────
no warnings 'once';
$PACMain::STRAY = 1;

# Going INTO Compact
my $self = { _CFG => { defaults => {
    'tabs in main window'        => 1,
    'auto hide connections list' => 1,
    'start iconified'            => 1,
    'close to tray'              => 0,
    'auto save'                  => 1,
    'layout previous'            => 'Traditional',
} } };
PAC::Window::Layout::set_safe_options($self, 'Compact');
is($self->{_CFG}{defaults}{'tabs in main window'}, 0,
    'Compact: tabs in main window forced to 0');
is($self->{_CFG}{defaults}{'auto hide connections list'}, 0,
    'Compact: auto hide connections list forced to 0');
is($self->{_CFG}{defaults}{'close to tray'}, 1,
    'Compact + STRAY: close to tray forced to 1');
is($self->{_CFG}{defaults}{'layout previous'}, 'Compact',
    'Compact: layout_previous updated');

# Going to Traditional first time → backs up to lt … keys
$self = { _CFG => { defaults => {
    'tabs in main window'        => 1,
    'start iconified'            => 0,
    'close to tray'              => 1,
    'auto save'                  => 1,
    'layout previous'            => 'Traditional',
} } };
PAC::Window::Layout::set_safe_options($self, 'Traditional');
is($self->{_CFG}{defaults}{'lt tabs in main window'}, 1,
    'Traditional: shadows tabs in main window as lt key');
is($self->{_CFG}{defaults}{'lt close to tray'}, 1,
    'Traditional: shadows close to tray as lt key');
is($self->{_CFG}{defaults}{'layout traditional settings'}, 1,
    'Traditional: marks shadow set as initialized');

# Returning from Compact → restores from lt …
$self = { _CFG => { defaults => {
    'tabs in main window'             => 0,                # Compact value
    'start iconified'                 => 0,
    'close to tray'                   => 1,
    'auto save'                       => 0,
    'layout previous'                 => 'Compact',        # was in Compact
    'layout traditional settings'     => 1,                # have a backup
    'lt tabs in main window'          => 1,                # original value
    'lt start iconified'              => 1,
    'lt close to tray'                => 0,
    'lt auto save'                    => 1,
} } };
PAC::Window::Layout::set_safe_options($self, 'Traditional');
is($self->{_CFG}{defaults}{'tabs in main window'}, 1,
    'returning to Traditional: restored tabs in main window from lt');
is($self->{_CFG}{defaults}{'auto save'}, 1,
    'returning to Traditional: restored auto save from lt');

# PACMain wrappers
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Window::Layout/m,
    'PACMain requires PAC::Window::Layout');
like($main, qr/sub _setSafeLayoutOptions\s*\{\s*goto\s*&PAC::Window::Layout::set_safe_options/,
    '_setSafeLayoutOptions proxy');
like($main, qr/sub _ApplyLayout\s*\{\s*goto\s*&PAC::Window::Layout::apply/,
    '_ApplyLayout proxy');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item set_safe_options\b/m, 'POD =item set_safe_options');
like($src, qr/^=item apply\b/m,            'POD =item apply');

done_testing();
