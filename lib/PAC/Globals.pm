package PAC::Globals;

###############################################################################
# PAC::Globals — public-API facade for the asbru process-wide state hashes.
#
# Historically these were declared as `our %FUNCS`, `our %RUNNING` (in
# PACMain.pm), `our %SHARED`, `our %COMMON` (in PACScripts.pm), and accessed
# directly by 18+ modules via fully-qualified names like
# `$PACMain::FUNCS{_MAIN}{_GUI}{main}`. That coupling is the single biggest
# obstacle to refactoring.
#
# This module gives new code a stable namespace to migrate to. The hashes
# themselves still live in PACMain / PACScripts — we ALIAS to them, not copy.
# A change made via PAC::Globals::funcs() is visible to legacy callsites
# inspecting $PACMain::FUNCS, and vice versa.
#
# Migration policy:
#   - New code MUST use PAC::Globals.
#   - Legacy callsites continue to work unchanged.
#   - When ownership eventually moves into PAC::Globals proper (deleting the
#     `our %FUNCS` declaration in PACMain), this module becomes the single
#     point of truth — no migration of callers needed for the move itself,
#     because they already go through here.
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);

our $VERSION = '0.1.0';

# Aliases. These are not copies — assigning to *PAC::Globals::FUNCS = \%X
# makes %PAC::Globals::FUNCS refer to the SAME storage as %X. Each accessor
# returns a hashref into that storage so callers can read/write transparently.
#
# We can't do the alias at compile time because PACMain may not have loaded
# yet. The first call to any accessor wires the alias on demand.

my $WIRED = 0;

sub _wire {
    return if $WIRED;
    no strict 'refs';
    no warnings 'once';

    # PACMain owns FUNCS / RUNNING / SOCKS5PORTS.
    if (defined &PACMain::new || %PACMain::) {
        *PAC::Globals::FUNCS       = \%PACMain::FUNCS;
        *PAC::Globals::RUNNING     = \%PACMain::RUNNING;
        *PAC::Globals::SOCKS5PORTS = \%PACMain::SOCKS5PORTS;
    }

    # PACScripts owns SHARED / COMMON / PAC / TERMINAL.
    if (defined &PACScripts::new || %PACScripts::) {
        *PAC::Globals::SHARED   = \%PACScripts::SHARED;
        *PAC::Globals::COMMON   = \%PACScripts::COMMON;
        *PAC::Globals::SCRIPT_PAC      = \%PACScripts::PAC;
        *PAC::Globals::SCRIPT_TERMINAL = \%PACScripts::TERMINAL;
    }

    $WIRED = 1;
}

#-------------------------------------------------------------------------
# Public accessors — return a hashref aliased to the underlying storage.
#-------------------------------------------------------------------------

# funcs() -> hashref of cross-module function tables (mostly UI-component
# instances: { _MAIN => $main, _CLUSTER => $cluster, _TRAY => $tray, ... }).
sub funcs {
    _wire();
    return \%PAC::Globals::FUNCS;
}

# running() -> hashref of currently-active connections.
# Keys are temporary connection IDs ("asbru_PID{$$}_n$N").
sub running {
    _wire();
    return \%PAC::Globals::RUNNING;
}

# socks5_ports() -> hashref tracking allocated SOCKS5 forwarding ports.
sub socks5_ports {
    _wire();
    return \%PAC::Globals::SOCKS5PORTS;
}

# shared() -> hashref for SESSION → CONNECTION script handoff.
sub shared {
    _wire();
    return \%PAC::Globals::SHARED;
}

# common() -> hashref of asbru-internal helpers exposed to user scripts.
sub common {
    _wire();
    return \%PAC::Globals::COMMON;
}

# main_window() -> the top-level Gtk3::Window, or undef before init.
# Convenience wrapper around the deeply-nested funcs()->{_MAIN}{_GUI}{main}.
sub main_window {
    my $f = funcs();
    return $f->{_MAIN} && $f->{_MAIN}{_GUI} ? $f->{_MAIN}{_GUI}{main} : undef;
}

# cfg() -> the live config hashref, or undef before _readConfiguration.
sub cfg {
    my $f = funcs();
    return $f->{_MAIN} ? $f->{_MAIN}{_CFG} : undef;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Globals — public-API facade for asbru process-wide state hashes

=head1 SYNOPSIS

    use PAC::Globals;

    my $funcs   = PAC::Globals::funcs();        # \%PACMain::FUNCS
    my $running = PAC::Globals::running();      # \%PACMain::RUNNING
    my $main    = PAC::Globals::main_window();  # Gtk3::Window or undef
    my $cfg     = PAC::Globals::cfg();          # asbru config hashref

    $funcs->{_MAIN}{_PENDING_TASKS}++;          # mutation visible to legacy
                                                # $PACMain::FUNCS readers

=head1 DESCRIPTION

The asbru-plus codebase historically scattered process-wide state across
two C<our %HASH> declarations (in C<PACMain.pm> and C<PACScripts.pm>) that
18+ modules then accessed by fully-qualified name. This module wraps those
hashes behind a small public API so new code never needs to know which
legacy module owns them.

The hashes are aliased, not copied — mutations through C<PAC::Globals>
are visible to legacy C<$PACMain::FUNCS> readers, and vice versa.

=head1 PUBLIC API

=over

=item funcs

Returns a hashref of cross-module function tables. Keys typically include
C<_MAIN>, C<_CLUSTER>, C<_TRAY>, C<_KEYBINDS>, C<_SCRIPTS>, ...

=item running

Returns a hashref of currently-active connections, keyed by temporary
connection ID.

=item socks5_ports

Returns a hashref of allocated SOCKS5 forward ports, used to detect
collisions when launching a new SOCKS tunnel.

=item shared

Returns the SESSION → CONNECTION script-handoff hashref (owned by
PACScripts).

=item common

Returns the hashref of asbru-internal helpers exposed to user scripts.

=item main_window

Convenience accessor — returns the top-level C<Gtk3::Window> instance,
or C<undef> if called before C<_initGUI>. Equivalent to
C<funcs()-E<gt>{_MAIN}{_GUI}{main}>.

=item cfg

Convenience accessor — returns the live config hashref, or C<undef>
before C<_readConfiguration> has run.

=back

=head1 MIGRATION POLICY

=over

=item *

New code MUST use C<PAC::Globals>, not direct C<$PACMain::FUNCS>
references.

=item *

Legacy callsites continue to work unchanged — they read/write the
same underlying storage.

=item *

When ownership eventually moves into C<PAC::Globals> proper (and the
C<our %FUNCS> declaration in PACMain.pm is deleted), this module becomes
the single point of truth. No migration of callers is needed for that
move — they already go through here.

=back

=head1 SEE ALSO

L<ARCHITECTURE.md> for the full leaky-boundary discussion.

=cut
