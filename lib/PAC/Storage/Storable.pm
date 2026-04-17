package PAC::Storage::Storable;

###############################################################################
# PAC::Storage::Storable — safe wrapper around Perl's Storable module.
#
# Storable's default behavior accepts serialized CODE references and
# evaluates them on retrieve when $Storable::Eval is true. A malicious
# config file (e.g. one substituted by an attacker who has filesystem
# access) could embed a CODE block that runs during load and gets
# arbitrary code execution as the user.
#
# Defense: this module ALWAYS retrieves with Storable::Eval = 0,
# Storable::Deparse = 0, Storable::forgive_me = 0 — code blocks become
# the literal string "<code reference>" instead of running. Pair with
# PAC::Crypto::HMAC integrity verification before every retrieve to
# prevent tamper.
#
# The module also wraps Storable::nstore (network-byte-order, portable
# format) for write so configs are portable across architectures.
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);
use Storable qw(retrieve nstore);

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

# safe_retrieve($path) -> deserialized data structure (or croaks)
# Always retrieves with code-execution disabled.
sub safe_retrieve {
    my $path = shift;
    croak 'safe_retrieve: path required' unless defined $path && $path ne '';
    croak "safe_retrieve: '$path' not readable" unless -r $path;

    local $Storable::Eval        = 0;
    local $Storable::Deparse     = 0;
    local $Storable::forgive_me  = 0;
    return retrieve($path);
}

# safe_store($data, $path) -> 1 on success
# Wraps Storable::nstore (portable, network byte order) so configs are
# architecture-independent. Returns 1 on success, croaks on failure.
sub safe_store {
    my ($data, $path) = @_;
    croak 'safe_store: data required' unless defined $data;
    croak 'safe_store: path required' unless defined $path && $path ne '';

    nstore($data, $path) or croak "safe_store: nstore('$path') failed: $!";
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Storage::Storable — safe wrapper around Perl's Storable module

=head1 SYNOPSIS

    use PAC::Storage::Storable;

    # Read — always with code execution disabled
    my $cfg = PAC::Storage::Storable::safe_retrieve($path);

    # Write — portable nstore format
    PAC::Storage::Storable::safe_store($cfg, $path);

=head1 DESCRIPTION

Wraps L<Storable>'s C<retrieve> and C<nstore> with security and
portability defaults applied:

=over

=item *

C<$Storable::Eval = 0> — embedded CODE refs do NOT execute on retrieve.

=item *

C<$Storable::Deparse = 0> — CODE refs are not deparsed either.

=item *

C<$Storable::forgive_me = 0> — strict on serialization errors.

=item *

C<nstore> instead of C<store> — network byte order, portable across
architectures.

=back

The module replaces the C<_safe_retrieve> helper that used to live as
a private sub in C<PACMain.pm>. The 4 read sites in C<PACMain.pm>
(legacy retrieve, current retrieve, freeze-format retrieve, verifier
check inside HMAC) all delegate here.

=head1 SECURITY POSTURE

This module is a defensive layer. It does NOT validate the deserialized
data structure — only that the deserialization itself can't run code.
Callers MUST verify integrity (HMAC) BEFORE calling C<safe_retrieve>
to defend against tampered Storable headers.

The legacy C<retrieve> function in this module's name is misleading —
even with C<Storable::Eval = 0>, a sufficiently malformed Storable
file can still trigger memory corruption in older C<Storable> versions
(CVE-2015-1592 et al.). Pinning C<Storable E<gt>= 3.21> in C<cpanfile>
is part of the defense.

=head1 PUBLIC API

=over

=item safe_retrieve($path)

Deserializes the Storable file at C<$path> with code-execution
disabled. Croaks if the path is missing or unreadable.

=item safe_store($data, $path)

Serializes C<$data> to C<$path> using portable network-byte-order
format. Returns 1 on success, croaks on failure.

=back

=head1 SEE ALSO

L<Storable>, L<PAC::Crypto::HMAC>, L<SECURITY.md>.

=cut
