#!/usr/bin/perl
# t/36-storage-yaml.t — PAC::Storage::Yaml safe YAML wrapper.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempfile tempdir);
use lib "$RealBin/../lib";

unless (eval { require YAML; 1 }) {
    plan skip_all => 'YAML not installed';
}

require_ok('PAC::Storage::Yaml');
can_ok('PAC::Storage::Yaml', $_) for qw(load_file dump_file load_string);

my $dir = tempdir(CLEANUP => 1);

# ── 1. The BEGIN block forces $YAML::LoadBlessed=0 globally ──────────
is($YAML::LoadBlessed, 0,
    'use PAC::Storage::Yaml flips $YAML::LoadBlessed to 0');

# ── 2. Round-trip ────────────────────────────────────────────────────
my %cfg = (
    str    => 'hello',
    num    => 42,
    list   => [1, 2, 3],
    nested => { deep => { deeper => 'value' } },
    unicode => 'пароль',
);
my $path = "$dir/cfg.yml";
PAC::Storage::Yaml::dump_file(\%cfg, $path);
ok(-f $path, 'dump_file produced output');

my $back = PAC::Storage::Yaml::load_file($path);
is($back->{str},     'hello',  'str preserved');
is($back->{num},     42,       'num preserved');
is_deeply($back->{list}, [1, 2, 3], 'list preserved');
is_deeply($back->{nested}, { deep => { deeper => 'value' } }, 'nested preserved');
is($back->{unicode}, 'пароль', 'unicode preserved');

# ── 3. load_string ───────────────────────────────────────────────────
my $struct = PAC::Storage::Yaml::load_string(<<'YAML');
---
fruits:
  - apple
  - banana
count: 2
YAML
is_deeply($struct->{fruits}, ['apple', 'banana'], 'load_string parses');
is($struct->{count}, 2, 'load_string preserves int');

# ── 4. !!perl/* tags do NOT instantiate blessed objects ──────────────
# This is the security gate — even if someone tries to plant a
# !!perl/hash:Foo::Bar in the YAML file, our LoadBlessed=0 prevents it
# from coming back as a Foo::Bar instance.
my $attack = <<'YAML';
---
plain: ok
victim: !!perl/hash:Some::Class
  field: 1
YAML
my $loaded;
eval { $loaded = PAC::Storage::Yaml::load_string($attack); };
ok(!ref($loaded->{victim}) || ref($loaded->{victim}) eq 'HASH',
    'blessed-object tag NOT instantiated as Some::Class (got ' . (ref($loaded->{victim}) // 'plain') . ')');
is($loaded->{plain}, 'ok', 'sibling data still loaded');

# ── 5. Even if someone flips the global later, our load is still safe
{
    local $YAML::LoadBlessed = 1;     # someone enables it
    my $loaded2;
    eval { $loaded2 = PAC::Storage::Yaml::load_string($attack); };
    ok(!ref($loaded2->{victim}) || ref($loaded2->{victim}) eq 'HASH',
        'load_string overrides ambient LoadBlessed=1 with local 0');
}

# ── 6. Input validation ──────────────────────────────────────────────
eval { PAC::Storage::Yaml::load_file("$dir/no-such-file") };
like($@, qr/not readable/, 'missing path croaks');
eval { PAC::Storage::Yaml::load_file(undef) };
like($@, qr/path required/, 'undef path croaks');
eval { PAC::Storage::Yaml::load_file('') };
like($@, qr/path required/, 'empty path croaks');

eval { PAC::Storage::Yaml::dump_file(undef, "$dir/x.yml") };
like($@, qr/data required/, 'dump_file(undef) croaks');
eval { PAC::Storage::Yaml::dump_file({}, '') };
like($@, qr/path required/, 'dump_file empty path croaks');

eval { PAC::Storage::Yaml::load_string(undef) };
like($@, qr/text required/, 'load_string(undef) croaks');

# ── 7. Garbage YAML croaks (does not silently return undef) ─────────
my ($fh, $bad) = tempfile(UNLINK => 1, SUFFIX => '.yml');
print {$fh} "this is not\n  valid: yaml: at all: ::: \xff\n";
close $fh;
my $rc;
eval { $rc = PAC::Storage::Yaml::load_file($bad); };
ok($@ || defined $rc,
    'malformed yaml: either croaks (good) or returns something (no silent corruption)');

# ── 8. POD coverage ─────────────────────────────────────────────────
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Storage/Yaml.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,           'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m,     'POD: PUBLIC API');
like($src, qr/^=head1 SECURITY POSTURE/m,'POD: SECURITY POSTURE');
for my $sub (qw(load_file dump_file load_string)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item for $sub");
}

done_testing();
