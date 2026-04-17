#!/usr/bin/perl
# t/30-config-schema.t — PAC::Config::Schema declarative config validator.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Config::Schema');

for my $sub (qw(all_keys get default_for validate_value
                validate_cfg apply_defaults)) {
    can_ok('PAC::Config::Schema', $sub);
}

# ── 1. Registry contains the v6.5.0 keys ────────────────────────────
my @keys = PAC::Config::Schema::all_keys();
ok(scalar(@keys) >= 5, 'registry has >=5 declared keys');
ok((grep { $_ eq 'defaults.disable bold'  } @keys), 'disable bold registered');
ok((grep { $_ eq 'defaults.hide info tab' } @keys), 'hide info tab registered');
ok((grep { $_ eq 'defaults.theme'         } @keys), 'theme registered');

# ── 2. get() and default_for() ──────────────────────────────────────
my $entry = PAC::Config::Schema::get('defaults.disable bold');
is($entry->{type}, 'bool', 'disable bold is bool');
is($entry->{default}, 0,   'disable bold default 0');
is(PAC::Config::Schema::default_for('defaults.theme'), 'default',
    'theme default value');
is(PAC::Config::Schema::get('defaults.nonexistent'), undef,
    'unknown key returns undef');

# ── 3. validate_value bool ──────────────────────────────────────────
my ($ok, $err) = PAC::Config::Schema::validate_value('defaults.disable bold', 1);
ok($ok, 'bool 1 valid');
($ok, $err) = PAC::Config::Schema::validate_value('defaults.disable bold', 0);
ok($ok, 'bool 0 valid');
($ok, $err) = PAC::Config::Schema::validate_value('defaults.disable bold', 'true');
ok(!$ok, 'bool "true" invalid');
like($err, qr/expected bool/, 'bool error mentions expected type');
($ok, $err) = PAC::Config::Schema::validate_value('defaults.disable bold', 2);
ok(!$ok, 'bool 2 invalid (out of {0,1})');

# ── 4. validate_value int + min/max ─────────────────────────────────
($ok, $err) = PAC::Config::Schema::validate_value(
    'defaults.terminal scrollback lines', 1000);
ok($ok, 'int 1000 valid');
($ok, $err) = PAC::Config::Schema::validate_value(
    'defaults.terminal scrollback lines', -2);
ok(!$ok, 'int below min invalid');
like($err, qr/below min/, 'min error message');
($ok, $err) = PAC::Config::Schema::validate_value(
    'defaults.terminal scrollback lines', 999_999);
ok(!$ok, 'int above max invalid');
like($err, qr/above max/, 'max error message');
($ok, $err) = PAC::Config::Schema::validate_value(
    'defaults.terminal scrollback lines', 'fifty');
ok(!$ok, 'int non-numeric invalid');

# ── 5. validate_value enum ──────────────────────────────────────────
($ok, $err) = PAC::Config::Schema::validate_value('defaults.theme', 'asbru-dark');
ok($ok, 'theme asbru-dark valid');
($ok, $err) = PAC::Config::Schema::validate_value('defaults.theme', 'fancy');
ok(!$ok, 'theme fancy invalid');
like($err, qr/not in allowed/, 'enum error mentions allowed list');

# ── 6. validate_value undef ─────────────────────────────────────────
($ok, $err) = PAC::Config::Schema::validate_value('defaults.disable bold', undef);
ok(!$ok, 'undef value rejected');

# ── 7. Unknown paths pass-through ───────────────────────────────────
($ok, $err) = PAC::Config::Schema::validate_value('defaults.unknown', 'whatever');
ok($ok, 'unknown path returns valid (gated on declared keys only)');

# ── 8. validate_cfg with valid + invalid ────────────────────────────
my %cfg = (
    defaults => {
        'disable bold'  => 1,
        'hide info tab' => 'oops',                   # invalid: bool
        'theme'         => 'fancy',                   # invalid: enum
        'terminal scrollback lines' => 500_000,       # invalid: above max
    },
);
my $errs = PAC::Config::Schema::validate_cfg(\%cfg);
isa_ok($errs, 'ARRAY', 'validate_cfg returns arrayref');
is(scalar @$errs, 3, 'three invalid keys detected');
my %by_path = map { $_->{path} => $_ } @$errs;
ok(exists $by_path{'defaults.hide info tab'}, 'reports bad bool path');
ok(exists $by_path{'defaults.theme'}, 'reports bad enum path');
ok(exists $by_path{'defaults.terminal scrollback lines'}, 'reports bad int path');
like($by_path{'defaults.theme'}{error}, qr/not in allowed/, 'enum err message');

# ── 9. apply_defaults fills only missing keys ───────────────────────
my %fresh;
my $filled = PAC::Config::Schema::apply_defaults(\%fresh);
ok($filled >= 5, "filled at least 5 defaults (got $filled)");
is($fresh{defaults}{'disable bold'}, 0, 'disable bold default applied');
is($fresh{defaults}{'theme'}, 'default', 'theme default applied');

my %partial = (defaults => { 'disable bold' => 1 });
PAC::Config::Schema::apply_defaults(\%partial);
is($partial{defaults}{'disable bold'}, 1, 'existing value preserved');
is($partial{defaults}{'theme'}, 'default', 'missing default added alongside');

# ── 10. apply_defaults rejects non-hash ─────────────────────────────
eval { PAC::Config::Schema::apply_defaults('not a hashref') };
like($@, qr/requires hashref/, 'apply_defaults rejects scalar');

# ── 11. POD coverage ────────────────────────────────────────────────
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Config/Schema.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m, 'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(all_keys get default_for validate_value
                validate_cfg apply_defaults)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item for $sub");
}

done_testing();
