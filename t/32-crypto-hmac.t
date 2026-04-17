#!/usr/bin/perl
# t/32-crypto-hmac.t — PAC::Crypto::HMAC config-integrity helpers.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir);
use Storable qw(nstore);
use lib "$RealBin/../lib";

unless (eval { require Digest::SHA; 1 }) {
    plan skip_all => 'Digest::SHA not installed';
}

require_ok('PAC::Crypto::HMAC');

for my $sub (qw(init key write_for verify_for ct_eq)) {
    can_ok('PAC::Crypto::HMAC', $sub);
}

# ── 1. init() with cfg_dir derives a key from .salt ─────────────────
my $dir = tempdir(CLEANUP => 1);
open(my $sf, '>:raw', "$dir/.salt") or die $!;
print {$sf} pack('a8', 'TESTSALT');
close $sf;
PAC::Crypto::HMAC::init({ cfg_dir => $dir });
my $k1 = PAC::Crypto::HMAC::key();
ok(length($k1) == 64, 'key is 64-char hex');

# Same salt → same key (idempotent)
PAC::Crypto::HMAC::init({ cfg_dir => $dir });
is(PAC::Crypto::HMAC::key(), $k1, 'init() idempotent for same salt');

# Different salt → different key
my $dir2 = tempdir(CLEANUP => 1);
open(my $sf2, '>:raw', "$dir2/.salt") or die $!;
print {$sf2} pack('a8', 'OTHERSAL');
close $sf2;
PAC::Crypto::HMAC::init({ cfg_dir => $dir2 });
isnt(PAC::Crypto::HMAC::key(), $k1, 'different salt → different key');

# Reset to first dir for the rest
PAC::Crypto::HMAC::init({ cfg_dir => $dir });

# ── 2. write_for + verify_for round-trip ────────────────────────────
my $cfg_path = "$dir/test.cfg";
open(my $cfh, '>:raw', $cfg_path) or die $!;
print {$cfh} "fake config contents\n";
close $cfh;

ok(PAC::Crypto::HMAC::write_for($cfg_path), 'write_for returns truthy');
ok(-f "${cfg_path}.hmac", 'sidecar file created');
my $perm = (stat "${cfg_path}.hmac")[2] & 07777;
is($perm, 0600, 'sidecar mode 0600');

ok(PAC::Crypto::HMAC::verify_for($cfg_path), 'verify_for: untampered passes');

# ── 3. Tamper detection ─────────────────────────────────────────────
open(my $tcfh, '>>:raw', $cfg_path) or die $!;
print {$tcfh} "tampered\n";
close $tcfh;
ok(!PAC::Crypto::HMAC::verify_for($cfg_path), 'verify_for: tampered fails');

# Restore + re-write so subsequent tests have clean state
open($cfh, '>:raw', $cfg_path) or die $!;
print {$cfh} "clean again\n";
close $cfh;
PAC::Crypto::HMAC::write_for($cfg_path);
ok(PAC::Crypto::HMAC::verify_for($cfg_path), 'verify after re-write');

# ── 4. Sidecar deletion logic ───────────────────────────────────────
unlink "${cfg_path}.hmac" or die "unlink hmac: $!";

# Without master_password_verifier in config: missing sidecar accepted
ok(PAC::Crypto::HMAC::verify_for($cfg_path),
    'missing sidecar accepted on plain config (no verifier)');

# Plant a master_password_verifier via Storable. Need a Storable file at
# the cfg path for the verifier check to work.
my $cfg_storable = "$dir/cfg-with-verifier.bin";
nstore({ defaults => { master_password_verifier => 'sentinel-token-v1' } },
    $cfg_storable);
ok(!PAC::Crypto::HMAC::verify_for($cfg_storable),
    'missing sidecar REJECTED when master_password_verifier present');

# Add the sidecar — verifier-bearing config now passes
PAC::Crypto::HMAC::write_for($cfg_storable);
ok(PAC::Crypto::HMAC::verify_for($cfg_storable),
    'verifier-bearing config passes once sidecar exists');

# ── 5. Symlink protection on write ──────────────────────────────────
SKIP: {
    skip 'symlink unsupported', 2 unless eval { symlink('/dev/null', "$dir/sl-test"); 1 };
    unlink "$dir/sl-test";

    # Plant a symlink at the would-be sidecar path
    my $target = "$dir/sl-target";
    open(my $tfh, '>', $target) or die $!;
    print {$tfh} "victim\n";
    close $tfh;

    my $sym_cfg = "$dir/sym-cfg";
    open($cfh, '>:raw', $sym_cfg) or die $!;
    print {$cfh} "data\n";
    close $cfh;
    symlink($target, "${sym_cfg}.hmac") or die "symlink: $!";

    PAC::Crypto::HMAC::write_for($sym_cfg);

    # The pre-existing symlink should have been unlinked first, target unchanged
    open(my $vfh, '<', $target) or die $!;
    my $contents = do { local $/; <$vfh> };
    close $vfh;
    is($contents, "victim\n", 'write_for did not follow symlink to clobber target');
    ok(!-l "${sym_cfg}.hmac", 'sidecar is no longer a symlink after write');
}

# ── 6. write_for refuses symlinked config ───────────────────────────
SKIP: {
    skip 'symlink unsupported', 1 unless eval { symlink('/dev/null', "$dir/sl-cfg"); 1 };
    unlink "$dir/sl-cfg";

    open($cfh, '>:raw', "$dir/real-cfg") or die $!;
    print {$cfh} "real\n";
    close $cfh;
    symlink("$dir/real-cfg", "$dir/symlinked-cfg") or die $!;

    my $rc = PAC::Crypto::HMAC::write_for("$dir/symlinked-cfg");
    ok(!defined $rc, 'write_for skips symlinked config (no sidecar produced)');
}

# ── 7. ct_eq constant-time compare ──────────────────────────────────
ok( PAC::Crypto::HMAC::ct_eq('abc', 'abc'),     'ct_eq: equal strings');
ok(!PAC::Crypto::HMAC::ct_eq('abc', 'abd'),     'ct_eq: different strings');
ok(!PAC::Crypto::HMAC::ct_eq('abc', 'abcd'),    'ct_eq: different lengths');
ok(!PAC::Crypto::HMAC::ct_eq(undef, 'abc'),     'ct_eq: undef arg');
ok(!PAC::Crypto::HMAC::ct_eq('abc', undef),     'ct_eq: undef other arg');
ok( PAC::Crypto::HMAC::ct_eq('', ''),           'ct_eq: both empty');

# ── 8. POD coverage ─────────────────────────────────────────────────
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Crypto/HMAC.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m, 'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(init key write_for verify_for ct_eq)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item for $sub");
}

done_testing();
