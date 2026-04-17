#!/usr/bin/perl
# t/33-vault.t — PAC::Vault verifier flow + field encrypt/decrypt.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir);
use lib "$RealBin/../lib";

unless (eval { require Crypt::CBC; require Crypt::Rijndael; 1 }) {
    plan skip_all => 'Crypt::CBC / Crypt::Rijndael not installed';
}

require_ok('PAC::Vault');
require_ok('PAC::Crypto::Cipher');

for my $sub (qw(instance is_unlocked unlock verify create_verifier
                encrypt_field decrypt_field kdf_strength)) {
    can_ok('PAC::Vault', $sub);
}

# Reset cipher state to a fresh tempdir for this test so we don't pick up
# a salt from any previous run.
my $dir = tempdir(CLEANUP => 1);
PAC::Crypto::Cipher::init({ cfg_dir => $dir });

my $vault = PAC::Vault->instance(cfg_path => "$dir/asbru.nfreeze");
isa_ok($vault, 'PAC::Vault');

# ── 1. is_unlocked reflects PAC::Crypto::Cipher state ───────────────
ok(!$vault->is_unlocked, 'fresh vault: is_unlocked=0');

# ── 2. create_verifier → verify round-trip succeeds ─────────────────
my $verifier = $vault->create_verifier('correct horse battery staple');
ok(defined $verifier && length($verifier) > 16,
    'verifier is non-empty hex blob');

ok( $vault->verify('correct horse battery staple', $verifier),
    'verify accepts correct password');
ok(!$vault->verify('wrong password', $verifier),
    'verify rejects wrong password');
ok(!$vault->verify(undef, $verifier), 'verify rejects undef password');
ok(!$vault->verify('something', undef), 'verify rejects undef verifier');
ok(!$vault->verify('something', ''), 'verify rejects empty verifier');

# ── 3. unlock switches the active cipher ────────────────────────────
$vault->unlock('correct horse battery staple');
ok($vault->is_unlocked, 'is_unlocked=1 after unlock');
ok(PAC::Crypto::Cipher::is_master_active(),
    'PAC::Crypto::Cipher reflects master_active');

eval { $vault->unlock(undef) };
like($@, qr/master password required/, 'unlock(undef) dies');

# Reset for downstream tests
PAC::Crypto::Cipher::init({ cfg_dir => $dir });

# ── 4. Verifier survives unicode passwords ──────────────────────────
my $u_pass = 'пароль с emoji 🔐';
my $u_verifier = $vault->create_verifier($u_pass);
ok( $vault->verify($u_pass, $u_verifier), 'unicode password verifies');
ok(!$vault->verify('wrong', $u_verifier), 'unicode verifier rejects wrong pass');

# ── 5. Legacy-salt fallback verification ────────────────────────────
# Hand-craft a verifier using the LEGACY static salt — matches what an
# old config file would contain.
{
    my $legacy_cipher = Crypt::CBC->new(
        -key    => 'legacy-pwd',
        -cipher => 'Crypt::Rijndael',
        -salt   => pack('Q', '12345678'),
        -pbkdf  => 'opensslv2',
    );
    my $legacy_verifier = $legacy_cipher->encrypt_hex('ASBRU_MASTER_VERIFY_TOKEN_V1');

    ok($vault->verify('legacy-pwd', $legacy_verifier),
        'legacy-salt verifier accepted via fallback');
    ok(!$vault->verify('not-the-pwd', $legacy_verifier),
        'legacy-salt verifier rejects wrong password');
}

# ── 6. Field encrypt/decrypt round-trip ─────────────────────────────
PAC::Crypto::Cipher::init({ cfg_dir => $dir });
for my $plain ('ssh-pass', 'unicode-секрет-🔐', '', 'a' x 500) {
    my $cipher = $vault->encrypt_field($plain);
    my $back   = $vault->decrypt_field($cipher);
    is($back, $plain, "field round-trip: " . substr($plain, 0, 20));
}

# ── 7. encrypt_field('') and decrypt_field(garbage) return '' ───────
is($vault->encrypt_field(''), '',    'encrypt_field empty → ""');
is($vault->encrypt_field(undef), '', 'encrypt_field undef → ""');
is($vault->decrypt_field(''), '',    'decrypt_field empty → ""');
is($vault->decrypt_field('not-hex-zzz'), '', 'decrypt_field non-hex → ""');

# ── 8. Future-API placeholders throw cleanly ────────────────────────
eval { $vault->get_secret('uuid', 'pass') };
like($@, qr/not yet implemented/, 'get_secret throws');
eval { $vault->put_secret('uuid', 'pass', 'val') };
like($@, qr/not yet implemented/, 'put_secret throws');
eval { $vault->rotate_kdf };
like($@, qr/not yet implemented/, 'rotate_kdf throws');
eval { $vault->zero_memory };
like($@, qr/not yet implemented/, 'zero_memory throws');

# ── 8b. Bulk config crypto: cipher_cfg / decipher_cfg round-trip ────
PAC::Crypto::Cipher::init({ cfg_dir => $dir });
my %cfg = (
    defaults => {
        'global variables' => {
            secret => { hidden => '1', value => 'hidden-secret' },
            visible => { hidden => '0', value => 'plain-value' },
        },
        'sudo password' => 'sudo-pwd',
        'keepass'       => { password => 'kp-pwd' },
    },
    environments => {
        'uuid-1' => {
            _is_group  => 0,
            pass       => 'login-pwd',
            passphrase => 'ssh-passphrase',
            expect     => [ { hidden => '1', send => 'expected-secret' } ],
            variables  => [ { hide => '1', txt => 'hidden-var' } ],
        },
    },
);

# Snapshot plaintext for round-trip comparison
my %before = %{ Storable::dclone(\%cfg) };

PAC::Vault::cipher_cfg(\%cfg);
isnt($cfg{defaults}{'sudo password'}, 'sudo-pwd',
    'cipher_cfg: sudo password is encrypted (not plain)');
isnt($cfg{environments}{'uuid-1'}{pass}, 'login-pwd',
    'cipher_cfg: per-connection pass encrypted');
is($cfg{defaults}{'global variables'}{visible}{value}, 'plain-value',
    'cipher_cfg: visible global var NOT encrypted');

PAC::Vault::decipher_cfg(\%cfg);
is($cfg{defaults}{'sudo password'}, 'sudo-pwd',
    'decipher_cfg: sudo password round-trips');
is($cfg{environments}{'uuid-1'}{pass}, 'login-pwd',
    'decipher_cfg: per-connection pass round-trips');
is($cfg{defaults}{'global variables'}{secret}{value}, 'hidden-secret',
    'decipher_cfg: hidden global var round-trips');
is($cfg{environments}{'uuid-1'}{expect}[0]{send}, 'expected-secret',
    'decipher_cfg: hidden expect send round-trips');

# Single-uuid mode only touches the named environment
PAC::Vault::cipher_cfg(\%cfg);
my $cipher_only_one = {
    defaults => { 'global variables' => {}, 'sudo password' => '' },
    environments => {
        'uuid-A' => { _is_group => 0, pass => $cfg{environments}{'uuid-1'}{pass} },
        'uuid-B' => { _is_group => 0, pass => 'plain-but-listed' },
    },
};
PAC::Vault::decipher_cfg($cipher_only_one, 'uuid-A');
isnt($cipher_only_one->{environments}{'uuid-A'}{pass}, undef,
    'single_uuid mode: target uuid is processed');
is($cipher_only_one->{environments}{'uuid-B'}{pass}, 'plain-but-listed',
    'single_uuid mode: other uuids untouched');

# ── 9. POD coverage ─────────────────────────────────────────────────
use Storable;
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Vault.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m, 'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(instance is_unlocked unlock verify create_verifier
                encrypt_field decrypt_field kdf_strength
                get_secret put_secret rotate_kdf zero_memory
                cipher_cfg decipher_cfg migrate_cipher_cfg)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item for $sub");
}

done_testing();
