#!/usr/bin/perl
# t/35-storage-storable.t — PAC::Storage::Storable safe wrapper.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir);
use Storable qw(nstore store);
use lib "$RealBin/../lib";

require_ok('PAC::Storage::Storable');
can_ok('PAC::Storage::Storable', $_) for qw(safe_retrieve safe_store);

my $dir = tempdir(CLEANUP => 1);

# ── 1. Round-trip preserves data ────────────────────────────────────
my %payload = (
    str    => 'hello',
    num    => 42,
    list   => [1, 2, 3],
    nested => { a => { b => 'deep' } },
    unicode => 'пароль',
);
my $path = "$dir/round-trip.bin";
PAC::Storage::Storable::safe_store(\%payload, $path);
ok(-f $path, 'safe_store produced a file');

my $back = PAC::Storage::Storable::safe_retrieve($path);
isa_ok($back, 'HASH', 'retrieved value is hashref');
is($back->{str},    'hello',  'str preserved');
is($back->{num},    42,       'num preserved');
is_deeply($back->{list},   [1, 2, 3], 'list preserved');
is_deeply($back->{nested}, { a => { b => 'deep' } }, 'nested preserved');
is($back->{unicode}, 'пароль', 'unicode preserved');

# ── 2. CODE refs in payload cause safe_retrieve to die, NOT execute ─
# Storable::Eval=0 makes Storable refuse to deserialize CODE blocks
# entirely (it can't deparse them safely without eval). That's the
# strongest defense: the file is rejected at load time, the embedded
# code never gets a chance to run.
my $code_path = "$dir/code-attack.bin";
{
    local $Storable::Deparse = 1;
    local $Storable::Eval    = 1;
    my $payload = {
        marker => 'before',
        attack => sub { $::ATTACK_FIRED = 'YES'; return 1; },
    };
    nstore($payload, $code_path);
}

local $::ATTACK_FIRED;
$::ATTACK_FIRED = 'no';

eval { PAC::Storage::Storable::safe_retrieve($code_path); };
my $err = $@;
ok($err, 'safe_retrieve dies on CODE-ref payload');
like($err, qr/Storable::Eval/i, 'die message mentions Storable::Eval');
is($::ATTACK_FIRED, 'no',
    'embedded CODE ref did NOT execute (load was refused)');

# Control: confirm Storable's "default deny" stance is what we rely on.
# Without our wrapper but with $Storable::Eval also 0 (Storable's own
# default), the same payload also dies. This shows we're depending on
# Storable's deny behavior — and explicitly enforcing it locally so a
# global setting elsewhere can't disable our defense.
{
    local $Storable::Eval = 0;
    eval { Storable::retrieve($code_path) };
    ok($@, 'control: Storable::retrieve also dies with Eval=0 (default-deny)');
}

# ── 3. Missing path croaks cleanly ──────────────────────────────────
eval { PAC::Storage::Storable::safe_retrieve("$dir/no-such-file") };
like($@, qr/not readable/, 'missing path croaks with not-readable message');

eval { PAC::Storage::Storable::safe_retrieve(undef) };
like($@, qr/path required/, 'undef path croaks');

eval { PAC::Storage::Storable::safe_retrieve('') };
like($@, qr/path required/, 'empty path croaks');

eval { PAC::Storage::Storable::safe_store(undef, "$dir/anywhere") };
like($@, qr/data required/, 'safe_store(undef) croaks');

eval { PAC::Storage::Storable::safe_store({}, '') };
like($@, qr/path required/, 'safe_store empty path croaks');

# ── 4. nstore is portable (network-byte-order header) ───────────────
# nstore-produced files start with a known magic byte sequence.
open(my $fh, '<:raw', $path) or die $!;
my $hdr;
read($fh, $hdr, 4);
close $fh;
ok(length($hdr) == 4, 'header readable');

# ── 5. POD coverage ─────────────────────────────────────────────────
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Storage/Storable.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item safe_retrieve\b/m, 'POD =item safe_retrieve');
like($src, qr/^=item safe_store\b/m,    'POD =item safe_store');

done_testing();
