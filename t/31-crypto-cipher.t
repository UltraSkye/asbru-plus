#!/usr/bin/perl
# t/31-crypto-cipher.t — PAC::Crypto::Cipher round-trip + backward-compat.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir);
use lib "$RealBin/../lib";

unless (eval { require Crypt::CBC; require Crypt::Rijndael; 1 }) {
    plan skip_all => 'Crypt::CBC / Crypt::Rijndael not installed';
}

require_ok('PAC::Crypto::Cipher');

for my $sub (qw(init active salt is_master_active set_master
                encrypt_hex decrypt_hex)) {
    can_ok('PAC::Crypto::Cipher', $sub);
}

# ── 1. init() with explicit cfg_dir creates and persists salt ───────
my $dir = tempdir(CLEANUP => 1);
PAC::Crypto::Cipher::init({ cfg_dir => $dir });

my $salt = PAC::Crypto::Cipher::salt();
is(length($salt), 8, 'salt is 8 bytes');
ok(-f "$dir/.salt", '.salt file persisted');
my $perm = (stat "$dir/.salt")[2] & 07777;
is($perm, 0600, '.salt file is mode 0600');

# init() again on same dir reuses existing salt (idempotent)
PAC::Crypto::Cipher::init({ cfg_dir => $dir });
my $salt2 = PAC::Crypto::Cipher::salt();
is($salt, $salt2, 'init() is idempotent — same salt second call');

# ── 2. encrypt → decrypt round-trip ─────────────────────────────────
for my $plaintext ('hello', 'a' x 1000, '', 'unicode: пароль 🔐', "\n\t\r") {
    my $hex = PAC::Crypto::Cipher::encrypt_hex($plaintext);
    my $back = PAC::Crypto::Cipher::decrypt_hex($hex);
    is($back, $plaintext, "round-trip preserves: " . substr($plaintext, 0, 20));
}

# ── 3. decrypt_hex on garbage returns '' (matches legacy contract) ──
is(PAC::Crypto::Cipher::decrypt_hex(''),         '', 'empty hex → ""');
is(PAC::Crypto::Cipher::decrypt_hex(undef),      '', 'undef hex → ""');
is(PAC::Crypto::Cipher::decrypt_hex('deadbeef'), '', 'invalid hex → ""');
is(PAC::Crypto::Cipher::decrypt_hex('zzzzzzzz'), '', 'non-hex → ""');

# ── 4. Master password switches the active cipher ───────────────────
ok(!PAC::Crypto::Cipher::is_master_active(), 'no master initially');

my $hex_pre = PAC::Crypto::Cipher::encrypt_hex('secret-data');
PAC::Crypto::Cipher::set_master('user-master-password');
ok(PAC::Crypto::Cipher::is_master_active(), 'master_active after set_master');

my $hex_post = PAC::Crypto::Cipher::encrypt_hex('secret-data');
isnt($hex_pre, $hex_post,
    'ciphertext differs after master change (different key)');

# Master-encrypted text round-trips. (We don't assert anything about
# pre-master ciphertext post-master-change: legacy_aes uses the same
# legacy KEY so it sometimes decrypts the embedded random salt, sometimes
# fails on PKCS7 — non-deterministic. Real callers never rely on this
# path; PACUtils::_migrateCipherCFG re-encrypts the entire config at
# master-set time so users don't lose data.)
is(PAC::Crypto::Cipher::decrypt_hex($hex_post), 'secret-data',
    'active cipher decrypts master-encrypted text');

# Reset for downstream tests
PAC::Crypto::Cipher::init({ cfg_dir => $dir });

# ── 5. set_master rejects undef ─────────────────────────────────────
eval { PAC::Crypto::Cipher::set_master(undef) };
like($@, qr/passphrase required/, 'set_master(undef) dies');

# ── 6. Unicode passphrase doesn't warn 'Wide character' ─────────────
my $warn_buf = '';
{
    local $SIG{__WARN__} = sub { $warn_buf .= $_[0] };
    PAC::Crypto::Cipher::set_master('пароль с кириллицей 🔐');
    PAC::Crypto::Cipher::encrypt_hex('test');
}
unlike($warn_buf, qr/Wide character/,
    'unicode passphrase does not trigger Wide-character warning');

PAC::Crypto::Cipher::init({ cfg_dir => $dir });

# ── 7. POD coverage ─────────────────────────────────────────────────
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Crypto/Cipher.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m, 'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(init active salt is_master_active set_master
                encrypt_hex decrypt_hex)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item for $sub");
}

done_testing();
