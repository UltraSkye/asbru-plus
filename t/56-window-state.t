#!/usr/bin/perl
# t/56-window-state.t — PAC::Window::State persistence helpers.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempfile tempdir);
use lib "$RealBin/../lib";

require_ok('PAC::Window::State');
can_ok('PAC::Window::State', $_) for qw(save load);

my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Window/State.pm" or die "open: $!";
    local $/; <$f>;
};

# Reads PACMain::CFG_FILE
like($src, qr/\$PACMain::CFG_FILE/, 'reads $PACMain::CFG_FILE');

# Format markers
like($src, qr/maximized/, 'handles "maximized" sentinel');
like($src, qr/x:y:w:h|x:\$y:\$w/, 'uses x:y:w:h format');
like($src, qr/hpanepos/, 'tracks hpanepos');

# load() short-circuits when file is missing
like($src, qr/return 1 unless -f \$path/, 'load() no-op for missing file');

# Mock save+load round-trip with a fake $self.
# `no warnings 'once'` — $PACMain::CFG_FILE is touched only here in test
# scope; in production it's set + read inside PACMain.pm. Without the
# pragma Perl warns "Name "PACMain::CFG_FILE" used only once" because
# the test never reads it back through the package symbol.
no warnings 'once';
my $dir = tempdir(CLEANUP => 1);
$PACMain::CFG_FILE = "$dir/asbru.yml";

# Mock GUI objects
{
    package MockMain;
    sub new { bless { posx => 100, posy => 200 }, 'MockMain' }
    sub get_position { return (10, 20) }
    sub get_size     { return (800, 600) }
    package MockHpane;
    sub new { bless {}, 'MockHpane' }
    sub get_position { return 250 }
}

my $self = {
    _GUI => {
        main      => MockMain->new,
        hpane     => MockHpane->new,
        maximized => 0,
    },
    _VERBOSE => 0,
};

ok(PAC::Window::State::save($self), 'save() returns truthy');
ok(-f "$dir/asbru.yml.gui", 'gui state file written');

my $loaded = { _GUI => {}, _VERBOSE => 0 };
ok(PAC::Window::State::load($loaded), 'load() returns truthy');
is($loaded->{_GUI}{posx}, 10, 'posx round-trips');
is($loaded->{_GUI}{posy}, 20, 'posy round-trips');
is($loaded->{_GUI}{sw},   800, 'width round-trips');
is($loaded->{_GUI}{sh},   600, 'height round-trips');
is($loaded->{_GUI}{hpanepos}, 250, 'tree pane pos round-trips');

# Maximized save
$self->{_GUI}{maximized} = 1;
ok(PAC::Window::State::save($self), 'save() maximized');
$loaded = { _GUI => {} };
PAC::Window::State::load($loaded);
is($loaded->{_GUI}{posx}, 'maximized', 'maximized sentinel preserved');

# Missing file -> no-op
unlink "$dir/asbru.yml.gui";
$loaded = { _GUI => {} };
ok(PAC::Window::State::load($loaded), 'load missing file -> 1');

# PACMain wrappers
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Window::State/m,
    'PACMain requires PAC::Window::State');
like($main, qr/sub _saveGUIData\s*\{\s*goto\s*&PAC::Window::State::save\s*;\s*\}/,
    '_saveGUIData proxy');
like($main, qr/sub _loadGUIData\s*\{\s*goto\s*&PAC::Window::State::load\s*;\s*\}/,
    '_loadGUIData proxy');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item save\b/m,      'POD =item save');
like($src, qr/^=item load\b/m,      'POD =item load');

done_testing();
