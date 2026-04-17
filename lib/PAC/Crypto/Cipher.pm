package PAC::Crypto::Cipher;

###############################################################################
# PAC::Crypto::Cipher — symmetric cipher wrapper for asbru-plus.
#
# Wraps the active Crypt::CBC cipher (AES-256, opensslv2 PBKDF) plus two
# legacy fallbacks (AES with static salt, Blowfish with static salt + opensslv1
# PBKDF) so we can keep reading configs encrypted by the original Ásbrú CM.
#
# This module is the SOLE owner of the active cipher state going forward.
# PACUtils::$CIPHER stays as an alias so the 50+ legacy callsites keep
# working unchanged.
#
# Public API:
#   PAC::Crypto::Cipher::active                  — get the active Crypt::CBC
#   PAC::Crypto::Cipher::set_master($passphrase) — derive new active cipher
#   PAC::Crypto::Cipher::encrypt_hex($plain)     — hex-string ciphertext
#   PAC::Crypto::Cipher::decrypt_hex($hex)       — try active, then legacy
#   PAC::Crypto::Cipher::salt                    — the per-installation salt
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);
use Crypt::CBC;
use Crypt::Rijndael;
use Encode qw(encode_utf8);

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Constants — values frozen by backward-compat with original Ásbrú CM.
#-------------------------------------------------------------------------

# Hardcoded key used for installations without a user-set master password.
# Same string as upstream so we can read existing configs.
my $LEGACY_KEY = 'PAC Manager (David Torrejon Vaquerizas, david.tv@gmail.com)';

# Static salt used by very-old configs (pre-random-salt era).
my $LEGACY_SALT_STR = '12345678';

#-------------------------------------------------------------------------
# Module state
#-------------------------------------------------------------------------

my $SALT;                # per-installation 8 random bytes (or legacy)
my $SALT_PATH;           # where it's persisted
my $ACTIVE_CIPHER;       # the live Crypt::CBC instance
my $LEGACY_AES_CIPHER;   # for decrypting old configs (static salt, AES)
my $LEGACY_BF_CIPHER;    # for decrypting ancient configs (static salt, BF)
my $MASTER_ACTIVE = 0;   # true once set_master() has been called

#-------------------------------------------------------------------------
# Initialization
#-------------------------------------------------------------------------

# init(\%opts) -> initializes module state. Called once by PACUtils during
# module load so the salt/cipher are ready before anyone calls encrypt_hex.
# Idempotent: safe to call multiple times.
#
# Options:
#   cfg_dir => '/path/to/asbru'   (where to read/write .salt)
sub init {
    my %opts = @_ ? %{$_[0]} : ();
    my $cfg_dir = $opts{cfg_dir} // $ENV{ASBRU_CFG} // '';

    $SALT_PATH = ($cfg_dir ne '') ? "$cfg_dir/.salt" : undef;
    $SALT      = _load_or_generate_salt($SALT_PATH);

    $ACTIVE_CIPHER = Crypt::CBC->new(
        -key    => $LEGACY_KEY,
        -cipher => 'Crypt::Rijndael',
        -salt   => $SALT,
        -pbkdf  => 'opensslv2',
    ) or croak "PAC::Crypto::Cipher: cannot init active cipher: $!";

    $LEGACY_AES_CIPHER = Crypt::CBC->new(
        -key    => $LEGACY_KEY,
        -cipher => 'Crypt::Rijndael',
        -salt   => pack('Q', $LEGACY_SALT_STR),
        -pbkdf  => 'opensslv2',
    ) or croak "PAC::Crypto::Cipher: cannot init legacy AES cipher: $!";

    $LEGACY_BF_CIPHER = Crypt::CBC->new(
        -key         => $LEGACY_KEY,
        -cipher      => 'Blowfish',
        -salt        => pack('Q', $LEGACY_SALT_STR),
        -pbkdf       => 'opensslv1',
        -nodeprecate => 1,
    ) or croak "PAC::Crypto::Cipher: cannot init legacy Blowfish cipher: $!";

    return 1;
}

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

sub active {
    init() unless $ACTIVE_CIPHER;
    return $ACTIVE_CIPHER;
}

sub salt {
    init() unless defined $SALT;
    return $SALT;
}

sub is_master_active { return $MASTER_ACTIVE; }

# set_master($passphrase) — derive a new active cipher from the user's
# master password. Returns the new cipher.
sub set_master {
    my $pass = shift;
    croak 'set_master: passphrase required' unless defined $pass;
    init() unless defined $SALT;
    $pass = encode_utf8($pass);   # Crypt::CBC PBKDF expects bytes

    $ACTIVE_CIPHER = Crypt::CBC->new(
        -key    => $pass,
        -cipher => 'Crypt::Rijndael',
        -salt   => $SALT,
        -pbkdf  => 'opensslv2',
    ) or croak "PAC::Crypto::Cipher: master cipher init failed: $!";

    $MASTER_ACTIVE = 1;
    return $ACTIVE_CIPHER;
}

# Convenience wrappers — same interface as Crypt::CBC->encrypt_hex/decrypt_hex.
sub encrypt_hex {
    my $plain = shift;
    return active()->encrypt_hex($plain);
}

# decrypt_hex tries the active cipher first, then falls back to the legacy
# ciphers — ensures we can still read configs from any era.
#
# Defensive about input: rejects non-hex strings AND ciphertexts that
# don't start with the OpenSSL "Salted__" magic. Crypt::CBC's decrypt_hex
# on malformed input throws "Ciphertext does not begin with a valid
# header" and leaves the cipher's internal state in a corrupted condition
# that breaks the NEXT encrypt_hex call ("Salt must be exactly 8 bytes
# long"). Validating up-front avoids that class of bug.
sub decrypt_hex {
    my $hex = shift;
    return '' unless defined $hex && $hex ne '';
    return '' unless $hex =~ /\A[0-9a-fA-F]+\z/;     # hex-only
    return '' unless length($hex) % 2 == 0;          # whole bytes

    # Quick structural sanity check: hex-decoded bytes must start with the
    # OpenSSL salted-header magic. All three of our ciphers use this format.
    my $magic_hex = unpack('H*', 'Salted__');         # '53616c7465645f5f'
    return '' unless lc(substr($hex, 0, 16)) eq lc($magic_hex);

    init() unless $ACTIVE_CIPHER;

    my $result;
    eval { $result = $ACTIVE_CIPHER->decrypt_hex($hex); };
    return $result if !$@ && defined $result;

    eval { $result = $LEGACY_AES_CIPHER->decrypt_hex($hex); };
    return $result if !$@ && defined $result;

    eval { $result = $LEGACY_BF_CIPHER->decrypt_hex($hex); };
    return $result if !$@ && defined $result;

    return '';
}

#-------------------------------------------------------------------------
# Internal
#-------------------------------------------------------------------------

sub _load_or_generate_salt {
    my $path = shift;
    my $salt;

    if (defined $path && -f $path) {
        if (open(my $fh, '<:raw', $path)) {
            read($fh, $salt, 8);
            close $fh;
            return $salt if defined $salt && length($salt) == 8;
        }
    }

    if (open(my $rng, '<:raw', '/dev/urandom')) {
        read($rng, $salt, 8);
        close $rng;
        if (defined $path) {
            if (open(my $fh, '>:raw', $path)) {
                print {$fh} $salt;
                close $fh;
                chmod 0600, $path;
            }
        }
        return $salt;
    }

    # Last-resort fallback for systems without /dev/urandom (e.g. test envs).
    return $LEGACY_SALT_STR;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Crypto::Cipher — symmetric cipher wrapper for asbru-plus

=head1 SYNOPSIS

    use PAC::Crypto::Cipher;

    PAC::Crypto::Cipher::init({ cfg_dir => "$ENV{HOME}/.config/asbru" });
    my $hex   = PAC::Crypto::Cipher::encrypt_hex('s3cret');
    my $plain = PAC::Crypto::Cipher::decrypt_hex($hex);

    # Switch to a user-derived key
    PAC::Crypto::Cipher::set_master($master_password);

=head1 DESCRIPTION

Wraps three Crypt::CBC instances:

=over

=item *

B<Active cipher> — AES-256 (Crypt::Rijndael) with C<opensslv2> PBKDF and
a per-installation random 8-byte salt. Used for all new encryption and
the first decryption attempt.

=item *

B<Legacy AES cipher> — same algorithm but with a static salt. Tried on
decryption when the active cipher fails (older configs that predate
random-salt support).

=item *

B<Legacy Blowfish cipher> — original Ásbrú CM cipher (Blowfish, static
salt, opensslv1 PBKDF). Tried last on decryption to support migration
from the upstream project.

=back

The legacy hardcoded key is kept for installations that have not set a
master password — same string as upstream so existing configs decrypt.
Calling C<set_master($passphrase)> derives a new active cipher from the
user's master password; legacy fallbacks remain available.

=head1 PUBLIC API

=over

=item init(\%opts)

Initializes module state: loads or generates the per-installation salt
(persisted at C<$cfg_dir/.salt>, mode 0600), constructs the three
ciphers. Idempotent — safe to call multiple times. Called automatically
on first use of any other API.

Options: C<cfg_dir =E<gt> '/path/to/config'>. Defaults to
C<$ENV{ASBRU_CFG}>.

=item active

Returns the active C<Crypt::CBC> instance. Forces C<init()> if not yet
initialized.

=item salt

Returns the per-installation salt (8 bytes).

=item is_master_active

Returns true after C<set_master> has been called.

=item set_master($passphrase)

Derives a new active cipher from the user's master password. The
passphrase is UTF-8 encoded before being passed to the PBKDF
(Crypt::CBC's PBKDF expects bytes).

=item encrypt_hex($plain)

Returns hex-encoded ciphertext using the active cipher.

=item decrypt_hex($hex)

Tries the active cipher, then legacy AES, then legacy Blowfish.
Returns the empty string on total failure (matches the legacy
C<_decrypt_hex_compat> contract).

=back

=head1 SEE ALSO

L<PAC::Vault>, L<Crypt::CBC>, L<Crypt::Rijndael>.

=cut
