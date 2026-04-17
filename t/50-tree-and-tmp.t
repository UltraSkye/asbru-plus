#!/usr/bin/perl
# t/50-tree-and-tmp.t — PAC::Util::TreeSelection + PAC::Config::TmpSessions.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# ── PAC::Util::TreeSelection ────────────────────────────────────────
require_ok('PAC::Util::TreeSelection');
can_ok('PAC::Util::TreeSelection', 'rows');

# Mock TreeSelection
{
    package MockSel;
    sub new { my (undef, $paths) = @_; bless { paths => $paths }, 'MockSel' }
    sub get_selected_rows { my $self = shift; return ($self->{paths}, undef) }
    package MockSelEmpty;
    sub new { bless {}, 'MockSelEmpty' }
    sub get_selected_rows { return (undef, undef) }
}

is_deeply([PAC::Util::TreeSelection::rows(MockSel->new(['p1', 'p2', 'p3']))],
    ['p1', 'p2', 'p3'], 'rows() returns selected paths as list');

is_deeply([PAC::Util::TreeSelection::rows(MockSelEmpty->new)],
    [], 'rows() empty selection -> empty list');

# ── PAC::Config::TmpSessions ────────────────────────────────────────
require_ok('PAC::Config::TmpSessions');
can_ok('PAC::Config::TmpSessions', $_) for qw(extract restore);

my %cfg = (
    environments => {
        'real-uuid-1234'    => { name => 'Real session 1' },
        'real-uuid-5678'    => { name => 'Real session 2' },
        'HASH(0xabcdef)'    => { name => 'Tmp HASH session' },
        '_tmp_session_42'   => { name => 'Tmp _tmp_ session' },
        'pacshell_PID12345' => { name => 'Tmp pacshell' },
    },
);

my %extracted = PAC::Config::TmpSessions::extract(\%cfg);
is(scalar(keys %extracted), 3, 'extract pulls 3 tmp entries');
ok(exists $extracted{'HASH(0xabcdef)'},    'HASH session extracted');
ok(exists $extracted{'_tmp_session_42'},   '_tmp_ session extracted');
ok(exists $extracted{'pacshell_PID12345'}, 'pacshell session extracted');
ok(!exists $extracted{'real-uuid-1234'},   'real session NOT extracted');

# extract() does NOT mutate $cfg
is(scalar(keys %{$cfg{environments}}), 5, 'extract is non-mutating');

# Now simulate a save: strip them, save, restore
delete $cfg{environments}{$_} for keys %extracted;
is(scalar(keys %{$cfg{environments}}), 2, 'after strip: 2 real sessions left');

PAC::Config::TmpSessions::restore(\%cfg, \%extracted);
is(scalar(keys %{$cfg{environments}}), 5, 'restore puts them back');
is($cfg{environments}{'HASH(0xabcdef)'}{name}, 'Tmp HASH session',
    'restored data matches original');

# ── PACUtils proxies ────────────────────────────────────────────────
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Util::TreeSelection/m, 'requires TreeSelection');
like($utils, qr/^require PAC::Config::TmpSessions/m, 'requires TmpSessions');
like($utils, qr/sub _getSelectedRows\s*\{\s*goto\s*&PAC::Util::TreeSelection::rows/,
    '_getSelectedRows is proxy');
like($utils, qr/sub _cfgGetTmpSessions\s*\{\s*goto\s*&PAC::Config::TmpSessions::extract/,
    '_cfgGetTmpSessions is proxy');
like($utils, qr/sub _cfgAddSessions\s*\{\s*goto\s*&PAC::Config::TmpSessions::restore/,
    '_cfgAddSessions is proxy');

# ── POD ─────────────────────────────────────────────────────────────
for my $pair (
    ['lib/PAC/Util/TreeSelection.pm', 'rows'],
    ['lib/PAC/Config/TmpSessions.pm', 'extract'],
) {
    my ($file, $sub) = @$pair;
    my $src = do { open my $f, '<', "$RealBin/../$file" or die; local $/; <$f> };
    like($src, qr/^=head1 NAME/m,       "$file: POD NAME");
    like($src, qr/^=head1 PUBLIC API/m, "$file: POD PUBLIC API");
    like($src, qr/^=item \Q$sub\E\b/m,  "$file: POD =item $sub");
}

done_testing();
