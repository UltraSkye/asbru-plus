package PAC::Vault;

###############################################################################
# PAC::Vault — credential storage facade for asbru-plus.
#
# Owns the master-password verifier flow:
#   - create_verifier($pass)  → encrypted token to store in cfg
#   - verify($pass, $token)   → 1 if password matches, 0 otherwise
#   - unlock($pass)           → switch the active cipher to the master key
#
# Field-level encrypt/decrypt remain delegated to PAC::Crypto::Cipher so
# we don't double-wrap or duplicate cipher state. Vault is the policy
# layer; Cipher is the primitive.
#
# This module replaces the inline _createMasterVerifier /
# _verifyMasterPassword that used to live in PACUtils.pm. PACUtils now
# delegates to PAC::Vault for both, so the 5+ legacy callsites need no
# changes.
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);
use Crypt::CBC;
use Crypt::Rijndael;
use Encode qw(encode_utf8);

use PAC::Crypto::Cipher;
use PAC::Crypto::HMAC qw();   # for ct_eq

our $VERSION = '0.2.0';

# The constant token encrypted with the master key. If decryption of the
# stored verifier yields this exact string, the password is correct.
# Frozen for backward compat with existing configs.
my $VERIFY_TOKEN = 'ASBRU_MASTER_VERIFY_TOKEN_V1';

# Legacy static salt — used as a fallback when verifying tokens written
# before the per-installation random salt was introduced. Same value as
# PAC::Crypto::Cipher's $LEGACY_SALT_STR.
my $LEGACY_SALT_STR = '12345678';

#-------------------------------------------------------------------------
# Singleton
#-------------------------------------------------------------------------

my $INSTANCE;

sub instance {
    my $class = shift;
    $INSTANCE //= $class->_new(@_);
    return $INSTANCE;
}

sub _new {
    my ($class, %args) = @_;
    my $self = {
        cfg_path    => $args{cfg_path},
        unlocked    => 0,
        kdf_version => 1,    # 1 = legacy opensslv2; 2 = future Argon2id
    };
    return bless $self, $class;
}

#-------------------------------------------------------------------------
# Master-password lifecycle
#-------------------------------------------------------------------------

sub is_unlocked {
    my $self = shift;
    return PAC::Crypto::Cipher::is_master_active() ? 1 : 0;
}

# unlock($master_password) — switches the active cipher to a key derived
# from the supplied master password. Returns true on success.
sub unlock {
    my ($self, $master_pass) = @_;
    croak 'unlock: master password required' unless defined $master_pass;
    PAC::Crypto::Cipher::set_master($master_pass);
    $self->{unlocked} = 1;
    return 1;
}

# create_verifier($master_password) — produce a verifier blob to store
# in the cfg under defaults.master_password_verifier. Independent of the
# active-cipher state so the caller can compute it before calling
# unlock().
sub create_verifier {
    my ($self, $master_pass) = @_;
    return _create_verifier($master_pass);
}

# verify($master_password, $verifier) — constant-time check against the
# stored verifier. Tries the per-installation salt first, then the
# legacy static salt for backward compat with verifiers written before
# the random-salt era.
sub verify {
    my ($self, $master_pass, $verifier) = @_;
    return _verify($master_pass, $verifier);
}

#-------------------------------------------------------------------------
# Field-level encryption (delegates to PAC::Crypto::Cipher)
#-------------------------------------------------------------------------

sub encrypt_field {
    my ($self, $plain) = @_;
    return '' unless defined $plain && length $plain;
    return PAC::Crypto::Cipher::encrypt_hex($plain);
}

sub decrypt_field {
    my ($self, $ciphertext) = @_;
    return '' unless defined $ciphertext && length $ciphertext;
    return PAC::Crypto::Cipher::decrypt_hex($ciphertext);
}

#-------------------------------------------------------------------------
# Diagnostics
#-------------------------------------------------------------------------

sub kdf_strength {
    my $self = shift;
    return 'pbkdf2-hmac-sha256/opensslv2 (legacy, 10k iter)';
}

#-------------------------------------------------------------------------
# Future API surface — declared so callers can write against it today
# and the implementation lands later without an API break.
#-------------------------------------------------------------------------

sub get_secret  { croak 'PAC::Vault::get_secret not yet implemented (decrypt-on-demand)'; }
sub put_secret  { croak 'PAC::Vault::put_secret not yet implemented'; }
sub rotate_kdf  { croak 'PAC::Vault::rotate_kdf not yet implemented (Argon2id migration)'; }
sub zero_memory { croak 'PAC::Vault::zero_memory not yet implemented'; }

#-------------------------------------------------------------------------
# Function-form helpers (used by PACUtils proxies — same call shape as
# the legacy _createMasterVerifier / _verifyMasterPassword)
#-------------------------------------------------------------------------

sub _create_verifier {
    my $master_pass = shift;
    return undef unless defined $master_pass;
    $master_pass = encode_utf8($master_pass);

    PAC::Crypto::Cipher::init() unless defined PAC::Crypto::Cipher::salt();

    my $cipher = Crypt::CBC->new(
        -key    => $master_pass,
        -cipher => 'Crypt::Rijndael',
        -salt   => PAC::Crypto::Cipher::salt(),
        -pbkdf  => 'opensslv2',
    ) or return undef;

    return $cipher->encrypt_hex($VERIFY_TOKEN);
}

sub _verify {
    my ($master_pass, $verifier) = @_;
    return 0 unless defined $verifier && $verifier ne '';
    return 0 unless defined $master_pass;
    $master_pass = encode_utf8($master_pass);

    PAC::Crypto::Cipher::init() unless defined PAC::Crypto::Cipher::salt();

    # Try per-installation salt first
    my $cipher = Crypt::CBC->new(
        -key    => $master_pass,
        -cipher => 'Crypt::Rijndael',
        -salt   => PAC::Crypto::Cipher::salt(),
        -pbkdf  => 'opensslv2',
    ) or return 0;
    my $plain;
    eval { $plain = $cipher->decrypt_hex($verifier); };
    if (!$@ && defined $plain && PAC::Crypto::HMAC::ct_eq($plain, $VERIFY_TOKEN)) {
        return 1;
    }

    # Backward compat: legacy static salt
    $cipher = Crypt::CBC->new(
        -key    => $master_pass,
        -cipher => 'Crypt::Rijndael',
        -salt   => pack('Q', $LEGACY_SALT_STR),
        -pbkdf  => 'opensslv2',
    ) or return 0;
    eval { $plain = $cipher->decrypt_hex($verifier); };
    return (!$@ && defined $plain && PAC::Crypto::HMAC::ct_eq($plain, $VERIFY_TOKEN));
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Vault — credential storage facade for Ásbrú Plus

=head1 SYNOPSIS

    use PAC::Vault;
    my $vault = PAC::Vault->instance(cfg_path => '/path/to/asbru.nfreeze');

    # First time: create + store the verifier
    my $verifier = $vault->create_verifier($master_pass);
    $cfg->{defaults}{master_password_verifier} = $verifier;

    # Subsequent runs: verify before unlocking
    if (!$vault->verify($pwd, $cfg->{defaults}{master_password_verifier})) {
        die 'wrong master password';
    }
    $vault->unlock($pwd);

    my $cipher = $vault->encrypt_field('secret123');
    my $plain  = $vault->decrypt_field($cipher);

=head1 DESCRIPTION

Owns the master-password verifier flow on top of L<PAC::Crypto::Cipher>.
The verifier is a known constant string encrypted under the master key
plus the per-installation salt — verifying it round-trip authenticates
the password without exposing the key or the rest of the config.

Field-level encryption delegates to L<PAC::Crypto::Cipher> so cipher
state is owned in exactly one place. Vault is the policy layer; Cipher
is the primitive.

=head1 BACKWARD COMPATIBILITY

Verifiers written before the per-installation random salt was
introduced used a static legacy salt. C<verify> tries the active salt
first, then falls back to the legacy salt — old configs continue to
authenticate.

=head1 STATUS

Master-password lifecycle (verifier + unlock) and field-level encrypt/
decrypt are fully implemented. The future surface
(C<get_secret> / C<put_secret> / C<rotate_kdf> / C<zero_memory>) is
declared but throws — see L<SECURITY.md> "Known weaknesses" for the
roadmap to decrypt-on-demand and Argon2id migration.

=head1 PUBLIC API

=over

=item instance(%args)

Class method. Returns the singleton vault instance, creating it on
first call. Accepts C<cfg_path =E<gt> '/path/to/asbru.nfreeze'>.

=item is_unlocked

Returns true iff the vault is currently in an unlocked state (master
password set on the active cipher).

=item unlock($password)

Switches the active cipher to a key derived from the master password.
Throws if the password is undef.

=item verify($password, $verifier)

Constant-time check of C<$password> against the stored verifier.
Returns 1 on match, 0 otherwise. Tries the per-installation salt
first, then the legacy static salt for backward compat.

=item create_verifier($password)

Produces a verifier blob to store in the cfg under
C<defaults.master_password_verifier>. Independent of the active
cipher state.

=item encrypt_field($plaintext)

Encrypts a single value using the active cipher (delegates to
C<PAC::Crypto::Cipher::encrypt_hex>).

=item decrypt_field($ciphertext)

Inverse of C<encrypt_field>. Tries active cipher then legacy
fallbacks (delegates to C<PAC::Crypto::Cipher::decrypt_hex>).

=item kdf_strength

Returns a string identifier of the active KDF.

=item get_secret($uuid, $key)

Future API: decrypt-on-demand secret retrieval. Currently throws.

=item put_secret($uuid, $key, $value)

Future API: store an encrypted secret. Currently throws.

=item rotate_kdf

Future API: migrate the vault to a stronger KDF (Argon2id). Currently
throws.

=item zero_memory

Future API: scrub decrypted secrets from process memory. Currently
throws.

=back

=head1 SEE ALSO

L<PAC::Crypto::Cipher>, L<PAC::Crypto::HMAC>, L<SECURITY.md>,
L<ARCHITECTURE.md>.

=cut
