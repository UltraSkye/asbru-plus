package PAC::Clipboard;

###############################################################################
# PAC::Clipboard — secure clipboard helpers.
#
# Currently exposes copy_password($uuid) — copies the connection's
# password to the PRIMARY clipboard with a 15-second auto-clear and
# in-memory zeroing of the captured plaintext. KeePass masks are
# resolved before copy.
#
# Mechanical extraction of PACUtils::_copyPass. PACUtils retains a
# 1-line goto-proxy under the legacy name.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;
# Gtk3::Gdk symbols (Atom::intern) are provided by Gtk3 introspection
# at runtime — no separate `use Gtk3::Gdk` needed.

our $VERSION = '0.1.0';

# copy_password($uuid)
# Copies the password (or passphrase if present) for the given
# connection UUID to the PRIMARY clipboard. KeePass-masked values
# are resolved before copy. Schedules a 15-second timer to clear the
# clipboard and zero the captured plaintext.
sub copy_password {
    my $uuid = shift;
    my $cfg = $PACMain::FUNCS{_MAIN}{_CFG};
    my $clip;

    my $clipboard = Gtk3::Clipboard::get(Gtk3::Gdk::Atom::intern('PRIMARY', 0));
    if ($$cfg{environments}{$uuid}{'passphrase'} ne '') {
        $clip = $$cfg{environments}{$uuid}{'passphrase'};
    } else {
        $clip = $$cfg{environments}{$uuid}{'pass'};
    }
    if ($$cfg{'defaults'}{'keepass'}{'use_keepass'}
        && PACKeePass->isKeePassMask($clip))
    {
        my $kpxc = $PACMain::FUNCS{_KEEPASS};
        $clip = $kpxc->applyMask($clip);
    }
    use bytes;
    $clipboard->set_text($clip, length($clip));

    # Auto-clear + zero the captured plaintext after 15 seconds.
    my $clip_ref = \$clip;
    Glib::Timeout->add_seconds(15, sub {
        my $cb = Gtk3::Clipboard::get(Gtk3::Gdk::Atom::intern('PRIMARY', 0));
        $cb->set_text('', 0);
        $$clip_ref = "\0" x length($$clip_ref)
            if defined $$clip_ref && length($$clip_ref);
        return 0;
    });
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Clipboard — secure clipboard helpers for asbru-plus

=head1 SYNOPSIS

    use PAC::Clipboard;

    PAC::Clipboard::copy_password($uuid);
    # Password is on the PRIMARY clipboard for 15 seconds, then
    # cleared + zeroed in memory.

=head1 DESCRIPTION

Mechanical extraction of C<PACUtils::_copyPass>. PACUtils retains a
1-line goto-proxy under the legacy name.

=head1 SECURITY POSTURE

The 15-second auto-clear timer is the primary defense: any process
sniffing the clipboard has a small window to grab the value. The
in-memory zero of the captured plaintext is best-effort — Perl scalars
may keep references to the original string in regex backrefs, the
PAD, etc.; a determined memory dumper could still recover it.

For high-value secrets, prefer the master-password vault flow which
keeps decrypted values out of long-lived buffers entirely.

=head1 PUBLIC API

=over

=item copy_password($uuid)

Copies the passphrase (if non-empty) or password for the given
connection to the PRIMARY clipboard. Resolves KeePass masks.
Schedules a 15-second clipboard clear + memory zero.

Returns 1.

=back

=head1 SEE ALSO

L<PACKeePass>, L<PAC::Vault>, L<Gtk3::Clipboard>.

=cut
