package PAC::Theme::Icons;

###############################################################################
# PAC::Theme::Icons — register the application's stock icons with the
# active Gtk3 theme.
#
# Mechanical extraction of PACUtils::_registerPACIcons (~145 lines, 90+
# icon mappings). PACUtils keeps a 1-line proxy so the 2 callsites in
# PACMain (initial setup + theme switch) work unchanged.
#
# The function reads icon paths from the per-theme directory and falls
# back to res/ for assets that don't have a per-theme variant.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# Local-to-this-module mirrors of PACUtils' lexicals. Set on each call.
my $THEME_DIR;
my $RES_DIR;

# register($theme_dir) — see POD at end of file.
sub register {
    $RES_DIR //= $PACUtils::RES_DIR;
    my $theme_dir = shift;
    if ($theme_dir) {
        $THEME_DIR = $theme_dir;
    }

    # Icon registration — all paths point to SVG (Lucide) where available;
    # PNG fallback is kept only for files that have no SVG equivalent.
    my %icons = (
        'asbru-help'                       => "$THEME_DIR/asbru-help.svg",
        'gtk-edit'                         => "$THEME_DIR/gtk-edit.svg",
        'gtk-delete'                       => "$THEME_DIR/gtk-delete.svg",
        'gtk-find'                         => "$THEME_DIR/gtk-find.svg",
        'gtk-spell-check'                  => "$THEME_DIR/gtk-spell-check.svg",
        'asbru-app-big'                    => "$RES_DIR/asbru-logo-64.png",
        'asbru-group-add'                  => "$THEME_DIR/asbru_group_add_16x16.svg",
        'asbru-node-add'                   => "$THEME_DIR/asbru_node_add.svg",
        'asbru-node-del'                   => "$THEME_DIR/gtk-delete.svg",
        'asbru-chain'                      => "$THEME_DIR/asbru_chain.svg",
        'asbru-cluster-auto'               => "$THEME_DIR/asbru_cluster_auto.svg",
        'asbru-cluster-manager2'           => "$THEME_DIR/asbru_cluster_manager2.svg",
        'asbru-cluster-manager'            => "$THEME_DIR/asbru_cluster_manager.svg",
        'asbru-cluster-manager-off'        => "$THEME_DIR/asbru_cluster_manager_off.svg",
        'asbru-favourite-on'               => "$THEME_DIR/asbru_favourite_on.svg",
        'asbru-favourite-off'              => "$THEME_DIR/asbru_favourite_off.svg",
        'asbru-group-closed'               => "$THEME_DIR/asbru_group_closed_16x16.svg",
        'asbru-group-open'                 => "$THEME_DIR/asbru_group_open_16x16.svg",
        'asbru-group'                      => "$THEME_DIR/asbru_group.svg",
        'asbru-history'                    => "$THEME_DIR/asbru_history.svg",
        'asbru-keepass'                    => "$THEME_DIR/asbru_keepass.svg",
        'asbru-method-WebDAV'              => "$THEME_DIR/asbru_method_cadaver.svg",
        'asbru-method-MOSH'                => "$THEME_DIR/asbru_method_mosh.svg",
        'asbru-method-IBM 3270/5250'       => "$THEME_DIR/asbru_method_3270.svg",
        'asbru-method-Serial (cu)'         => "$THEME_DIR/asbru_method_cu.svg",
        'asbru-method-FTP'                 => "$THEME_DIR/asbru_method_ftp.svg",
        'asbru-method-Generic Command'     => "$THEME_DIR/asbru_method_generic.svg",
        'asbru-method-RDP (Windows)'       => "$THEME_DIR/asbru_method_rdesktop.svg",
        'asbru-method-RDP (rdesktop)'      => "$THEME_DIR/asbru_method_rdesktop.svg",
        'asbru-method-RDP (xfreerdp)'      => "$THEME_DIR/asbru_method_rdesktop.svg",
        'asbru-method-Serial (remote-tty)' => "$THEME_DIR/asbru_method_remote-tty.svg",
        'asbru-method-SFTP'                => "$THEME_DIR/asbru_method_sftp.svg",
        'asbru-method-SSH'                 => "$THEME_DIR/asbru_method_ssh.svg",
        'asbru-method-Telnet'              => "$THEME_DIR/asbru_method_telnet.svg",
        'asbru-method-VNC'                 => "$THEME_DIR/asbru_method_vncviewer.svg",
        'asbru-quick-connect'              => "$THEME_DIR/asbru_quick_connect.svg",
        'asbru-script'                     => "$THEME_DIR/asbru_script.svg",
        'asbru-shell'                      => "$THEME_DIR/asbru_shell.svg",
        'asbru-tab'                        => "$THEME_DIR/asbru_tab.svg",
        'asbru-terminal-ok-small'          => "$RES_DIR/asbru_terminal16x16.png",
        'asbru-terminal-ok-big'            => "$RES_DIR/asbru_terminal64x64.png",
        'asbru-terminal-ko-small'          => "$RES_DIR/asbru_terminal_x16x16.png",
        'asbru-terminal-ko-big'            => "$RES_DIR/asbru_terminal_x64x64.png",
        'asbru-tray-bw'                    => "$RES_DIR/asbru_tray_bw.png",
        'asbru-tray'                       => "$RES_DIR/asbru-logo-tray.png",
        'asbru-treelist'                   => "$THEME_DIR/asbru_treelist.svg",
        'asbru-wol'                        => "$THEME_DIR/asbru_wol.svg",
        'asbru-prompt'                     => "$THEME_DIR/asbru_prompt.svg",
        'asbru-protected'                  => "$THEME_DIR/asbru_protected.svg",
        'asbru-unprotected'                => "$THEME_DIR/asbru_unprotected.svg",
        'asbru-buttonbar-show'             => "$THEME_DIR/asbru_buttonbar_show.svg",
        'asbru-buttonbar-hide'             => "$THEME_DIR/asbru_buttonbar_hide.svg",
        # GTK stock icon overrides — replace deprecated stock with Lucide
        'gtk-close'              => "$THEME_DIR/gtk-close.svg",
        'gtk-connect'            => "$THEME_DIR/gtk-connect.svg",
        'gtk-disconnect'         => "$THEME_DIR/gtk-disconnect.svg",
        'gtk-execute'            => "$THEME_DIR/gtk-execute.svg",
        'gtk-go-back'            => "$THEME_DIR/gtk-go-back.svg",
        'gtk-go-forward'         => "$THEME_DIR/gtk-go-forward.svg",
        'gtk-go-up'              => "$THEME_DIR/gtk-go-up.svg",
        'gtk-go-down'            => "$THEME_DIR/gtk-go-down.svg",
        'gtk-goto-first'         => "$THEME_DIR/gtk-goto-first.svg",
        'gtk-goto-last'          => "$THEME_DIR/gtk-goto-last.svg",
        'gtk-goto-top'           => "$THEME_DIR/gtk-goto-top.svg",
        'gtk-goto-bottom'        => "$THEME_DIR/gtk-goto-bottom.svg",
        'gtk-home'               => "$THEME_DIR/gtk-home.svg",
        'gtk-media-play'         => "$THEME_DIR/gtk-media-play.svg",
        'gtk-network'            => "$THEME_DIR/gtk-network.svg",
        'gtk-open'               => "$THEME_DIR/gtk-open.svg",
        'gtk-page-setup'         => "$THEME_DIR/gtk-page-setup.svg",
        'gtk-preferences'        => "$THEME_DIR/gtk-preferences.svg",
        'gtk-properties'         => "$THEME_DIR/gtk-properties.svg",
        'gtk-quit'               => "$THEME_DIR/gtk-quit.svg",
        'gtk-save'               => "$THEME_DIR/gtk-save.svg",
        'gtk-add'                => "$THEME_DIR/gtk-add.svg",
        'gtk-cancel'             => "$THEME_DIR/gtk-cancel.svg",
        'gtk-copy'               => "$THEME_DIR/gtk-copy.svg",
        'gtk-cut'                => "$THEME_DIR/gtk-cut.svg",
        'gtk-paste'              => "$THEME_DIR/gtk-paste.svg",
        'gtk-clear'              => "$THEME_DIR/gtk-clear.svg",
        'gtk-fullscreen'         => "$THEME_DIR/gtk-fullscreen.svg",
        'gtk-help'               => "$THEME_DIR/gtk-help.svg",
        'gtk-info'               => "$THEME_DIR/gtk-info.svg",
        'gtk-refresh'            => "$THEME_DIR/gtk-refresh.svg",
        'gtk-redo'               => "$THEME_DIR/gtk-redo.svg",
        'gtk-undo'               => "$THEME_DIR/gtk-undo.svg",
        'gtk-stop'               => "$THEME_DIR/gtk-stop.svg",
        'gtk-yes'                => "$THEME_DIR/gtk-yes.svg",
        'gtk-no'                 => "$THEME_DIR/gtk-no.svg",
        'gtk-ok'                 => "$THEME_DIR/gtk-ok.svg",
        'gtk-revert-to-saved'    => "$THEME_DIR/gtk-revert-to-saved.svg",
        'gtk-print-preview'      => "$THEME_DIR/gtk-print-preview.svg",
        'gtk-print'              => "$THEME_DIR/gtk-print.svg",
        'gtk-dialog-question'    => "$THEME_DIR/gtk-dialog-question.svg",
        'gtk-missing-image'      => "$THEME_DIR/gtk-missing-image.svg",
        'gtk-about'              => "$THEME_DIR/gtk-about.svg",
        'gtk-apply'              => "$THEME_DIR/gtk-apply.svg",
        'gtk-zoom-in'            => "$THEME_DIR/gtk-zoom-in.svg",
        'gtk-zoom-out'           => "$THEME_DIR/gtk-zoom-out.svg",
        'gtk-zoom-100'           => "$THEME_DIR/gtk-zoom-100.svg",
        'gtk-zoom-fit'           => "$THEME_DIR/gtk-zoom-fit.svg",
        'gtk-select-all'         => "$THEME_DIR/gtk-select-all.svg",
        'gtk-jump-to'            => "$THEME_DIR/gtk-jump-to.svg",
        'gtk-floppy'             => "$THEME_DIR/gtk-floppy.svg",
        'gtk-cdrom'              => "$THEME_DIR/gtk-cdrom.svg",
        'gtk-select-font'        => "$THEME_DIR/gtk-select-font.svg",
        'gtk-dialog-info'        => "$THEME_DIR/gtk-dialog-info.svg",
        # Preferences sidebar tab icons (consistent Lucide set)
        'asbru-prefs-main'        => "$THEME_DIR/asbru-prefs-main.svg",
        'asbru-prefs-terminal'    => "$THEME_DIR/asbru-prefs-terminal.svg",
        'asbru-prefs-shell'       => "$THEME_DIR/asbru-prefs-shell.svg",
        'asbru-prefs-network'     => "$THEME_DIR/asbru-prefs-network.svg",
        'asbru-prefs-vars'        => "$THEME_DIR/asbru-prefs-vars.svg",
        'asbru-prefs-localcmd'    => "$THEME_DIR/asbru-prefs-localcmd.svg",
        'asbru-prefs-remotecmd'   => "$THEME_DIR/asbru-prefs-remotecmd.svg",
        'asbru-prefs-keepass'     => "$THEME_DIR/asbru-prefs-keepass.svg",
        'asbru-prefs-keybindings' => "$THEME_DIR/asbru-prefs-keybindings.svg",
        'asbru-theme-toggle'      => "$THEME_DIR/asbru-theme-toggle.svg",
    );

    my $icon_factory = Gtk3::IconFactory->new();

    foreach my $icon (keys %icons) {
        my $icon_source = Gtk3::IconSource->new();
        $icon_source->set_filename($icons{$icon});

        my $icon_set = Gtk3::IconSet->new();
        $icon_set->add_source($icon_source);

        $icon_factory->add($icon, $icon_set);
    }

    $icon_factory->add_default();

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Theme::Icons — register asbru-plus stock icons with Gtk3 theme

=head1 SYNOPSIS

    use PAC::Theme::Icons;

    PAC::Theme::Icons::register("$RealBin/res/themes/asbru-dark");

=head1 DESCRIPTION

Mechanical extraction of C<PACUtils::_registerPACIcons>. Builds a
C<Gtk3::IconFactory> from the per-theme SVG/PNG assets and registers
it as the application's default.

=head1 PUBLIC API

=over

=item register($theme_dir)

Reads icon paths from C<$theme_dir>. The C<$RES_DIR> for shared
fallback assets is auto-resolved from C<$PACUtils::RES_DIR>.
Returns 1.

=back

=head1 SEE ALSO

L<Gtk3::IconFactory>, L<PACUtils>.

=cut
