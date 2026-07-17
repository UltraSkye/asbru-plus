package PAC::Theme::DesktopFile;

###############################################################################
# PAC::Theme::DesktopFile — generate the XDG .desktop launcher.
#
# Writes the menu launcher to ~/.local/share/applications/asbru.desktop
# with the standard "Shell / Quick connect / Preferences" sub-actions,
# then refreshes the XDG menu cache via xdg-desktop-menu.
#
# Mechanical extraction from PACUtils::_makeDesktopFile. PACUtils
# retains a 1-line proxy. The function is currently NOT called from
# any production code path (the single caller in PACMain is commented
# out), but kept as part of the public API surface.
###############################################################################

use strict;
use warnings;
use utf8;

use POSIX qw();

our $VERSION = '0.1.0';

# generate($cfg) — see POD at end of file.
sub generate {
    my $cfg = shift;

    if (! $$cfg{'defaults'}{'show favourites in unity'}) {
        unlink "$ENV{HOME}/.local/share/applications/asbru.desktop";
        system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} /usr/bin/xdg-desktop-menu forceupdate &");
        return 1;
    }

    my $d = "[Desktop Entry]\n";
    $d .= "Name=Ásbrú Connection Manager\n";
    $d .= "Comment=A user interface that helps organizing remote terminal sessions and automating repetitive tasks\n";
    $d .= "Terminal=false\n";
    $d .= "Icon=pac\n";
    $d .= "Type=Application\n";
    $d .= "Exec=env GDK_BACKEND=x11 /usr/bin/asbru-cm\n";
    $d .= "StartupNotify=true\n";
    $d .= "Name[en_US]=Ásbrú Connection Manager\n";
    $d .= "Comment[en_US]=A user interface that helps organizing remote terminal sessions and automating repetitive tasks\n";
    $d .= "Categories=Applications;Network;\n";
    $d .= "X-GNOME-Autostart-enabled=false\n";
    my $dal = 'Actions=Shell;Quick;Preferences;';
    my $da = "\n[Desktop Action Shell]\n";
    $da .= "Name=<Start local shell>\n";
    $da .= "Exec=env GDK_BACKEND=x11 /usr/bin/asbru-cm --start-shell\n";
    $da .= "\n[Desktop Action Quick]\n";
    $da .= "Name=<Quick connect...>\n";
    $da .= "Exec=env GDK_BACKEND=x11 /usr/bin/asbru-cm --quick-conn\n";
    $da .= "\n[Desktop Action Preferences]\n";
    $da .= "Name=<Open Preferences...>\n";
    $da .= "Exec=env GDK_BACKEND=x11 /usr/bin/asbru-cm --preferences\n";
#    my $action = 0;
#    foreach my $uuid (keys %{$$cfg{environments}}) {
#        if (($uuid eq '__PAC__ROOT__') || (! $$cfg{'environments'}{$uuid}{'favourite'})) {
#            next;
#        }

#        $dal .= "$action;";
#        $da .= "\n[Desktop Action " . $action++ . "]\n";
#        $da .= "Name=" . ($$cfg{'environments'}{$uuid}{'name'} =~ s/_/__/go) . "\n";
#        $da .= "Exec=asbru-cm --start-uuid=$uuid\n";
#    }

    open(my $fh, '>:encoding(UTF-8)', "$ENV{HOME}/.local/share/applications/asbru.desktop") or return 0;
    print $fh "$d\n$dal\n$da\n";
    close $fh;
    # Double-fork the xdg-desktop-menu refresh so the grandchild is
    # reaped by init and we never leave a zombie on the parent.
    my $pid = fork();
    if (defined $pid && $pid == 0) {
        my $pid2 = fork();
        POSIX::_exit(0) if !defined $pid2 || $pid2 > 0;
        exec('xdg-desktop-menu', 'forceupdate') or POSIX::_exit(1);
    }
    waitpid($pid, 0) if defined $pid && $pid > 0;

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Theme::DesktopFile — generate the XDG .desktop launcher

=head1 SYNOPSIS

    use PAC::Theme::DesktopFile;

    PAC::Theme::DesktopFile::generate($cfg);

=head1 DESCRIPTION

Writes the menu launcher to
C<~/.local/share/applications/asbru.desktop> with the standard "Start
local shell / Quick connect / Open Preferences" sub-actions. After
write, refreshes the XDG menu cache via a double-forked C<xdg-desktop-menu>
so the grandchild is reaped by init and we never leave a zombie.

If C<defaults.show favourites in unity> is false, removes any existing
launcher instead.

=head1 PUBLIC API

=over

=item generate($cfg)

Reads C<defaults.show favourites in unity> from C<$cfg>. Writes the
launcher and refreshes XDG cache when true; removes it when false.
Returns 1 on success, 0 if the launcher file couldn't be written.

=back

=head1 SEE ALSO

L<https://specifications.freedesktop.org/desktop-entry-spec/>,
L<xdg-desktop-menu(1)>.

=cut
