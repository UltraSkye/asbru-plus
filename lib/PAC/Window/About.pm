package PAC::Window::About;

###############################################################################
# PAC::Window::About — modal "About" dialog.
#
# Mechanical extraction of PACMain::_showAboutWindow (102 lines).
# The dialog has no internal state to share with the rest of PACMain;
# extracting it is purely a navigability win.
#
# PACMain retains a 1-line wrapper so the 2 callsites in PACTray and
# PACTrayUnity (`\$\$self{_MAIN}->_showAboutWindow()`) keep working.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

use PAC::Dialog;   # _wMessage for the URL-fallback notice

our $VERSION = '0.1.0';

# show($parent_window) — builds and runs the modal About dialog.
# $parent_window is used as the transient_for parent (typically the
# main window). Returns 1.
sub show {
    my $parent = shift;

    my $appname    = $PACUtils::APPNAME    // 'Ásbrú Plus';
    my $appversion = $PACUtils::APPVERSION // '?';
    my $res_dir    = $PACUtils::RES_DIR    // '';

    my $dlg = Gtk3::Dialog->new();
    $dlg->set_transient_for($parent) if defined $parent;
    $dlg->set_modal(1);
    $dlg->set_title("About $appname");
    $dlg->set_default_size(560, 0);
    $dlg->set_icon_name('asbru-app-big');
    $dlg->set_resizable(0);
    $dlg->get_style_context->add_class('asbru-about');

    my $content = $dlg->get_content_area;
    $content->set_border_width(28);
    $content->set_spacing(16);

    # Logo (smaller than 400px to keep dialog compact)
    my $logo = Gtk3::Image->new_from_file("$res_dir/asbru-logo-256.png");
    $logo->set_pixel_size(120);
    $logo->set_halign('center');
    $content->pack_start($logo, 0, 0, 0);

    # Title block
    my $title = Gtk3::Label->new();
    $title->set_markup("<span size='xx-large' weight='bold'>$appname</span>");
    $title->set_halign('center');
    $content->pack_start($title, 0, 0, 0);

    my $tagline = Gtk3::Label->new();
    $tagline->set_markup("<span size='medium'>A modern fork of <b>Ásbrú Connection Manager</b></span>");
    $tagline->set_halign('center');
    $content->pack_start($tagline, 0, 0, 0);

    my $version = Gtk3::Label->new();
    $version->set_markup("<span size='small' alpha='65%'>Version $appversion</span>");
    $version->set_halign('center');
    $content->pack_start($version, 0, 0, 0);

    # Separator
    my $sep = Gtk3::Separator->new('horizontal');
    $sep->set_margin_top(8);
    $sep->set_margin_bottom(8);
    $content->pack_start($sep, 0, 0, 0);

    # Info grid
    my $grid = Gtk3::Grid->new();
    $grid->set_column_spacing(16);
    $grid->set_row_spacing(8);
    $grid->set_halign('center');

    my @rows = (
        ['Fork by',     '<a href="https://github.com/UltraSkye/asbru-plus">UltraSkye/asbru-plus</a>'],
        ['Upstream',    '<a href="https://github.com/asbru-cm/asbru-cm">asbru-cm/asbru-cm</a>'],
        ['Original',    'David Torrejón Vaquerizas (2010–2016)'],
        ['Maintainers', 'Ásbrú Connection Manager team (2017–2026)'],
        ['License',     'GPL-3.0-or-later'],
        ['Platform',    'Linux · GTK 3'],
    );
    my $r = 0;
    for my $row (@rows) {
        my ($k, $v) = @$row;
        my $key = Gtk3::Label->new();
        $key->set_markup("<b>$k</b>");
        $key->set_halign('end');
        $grid->attach($key, 0, $r, 1, 1);
        my $val = Gtk3::Label->new();
        $val->set_markup($v);
        $val->set_halign('start');
        $val->set_use_markup(1);
        $val->set_selectable(1);
        $grid->attach($val, 1, $r, 1, 1);
        $r++;
    }
    $content->pack_start($grid, 0, 0, 0);

    # Action area: Close + Visit repo
    my $area = $dlg->get_action_area;
    $area->set_layout('end');
    $area->set_spacing(8);
    $area->set_border_width(12);

    my $btnClose = Gtk3::Button->new_with_label('Close');
    $btnClose->signal_connect('clicked' => sub { $dlg->destroy; });

    my $btnRepo = Gtk3::Button->new_with_label('Visit Repository');
    $btnRepo->get_style_context->add_class('suggested-action');
    $btnRepo->signal_connect('clicked' => sub {
        my $url = 'https://github.com/UltraSkye/asbru-plus';
        my $opened = 0;
        for my $cmd (
            ['xdg-open', $url], ['gio', 'open', $url],
            ['sensible-browser', $url], ['firefox', $url],
        ) {
            if (system(@$cmd) == 0) { $opened = 1; last; }
        }
        PAC::Dialog::_wMessage($dlg, "Open this URL manually:\n$url") unless $opened;
    });

    $area->pack_end($btnRepo, 0, 0, 0);
    $area->pack_end($btnClose, 0, 0, 0);

    $dlg->show_all;
    $dlg->run;
    $dlg->destroy if Gtk3::Widget::is_visible($dlg);
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Window::About — modal "About" dialog

=head1 SYNOPSIS

    use PAC::Window::About;

    PAC::Window::About::show($main_window);

=head1 DESCRIPTION

Shows the asbru-plus "About" dialog — logo, version, fork/upstream
links, license, maintainers grid, plus a "Visit Repository" button
that tries C<xdg-open / gio open / sensible-browser / firefox> in
turn (and falls back to a "open this URL manually" message dialog
if all fail).

Mechanical extraction of C<PACMain::_showAboutWindow>. PACMain
retains a 1-line wrapper so the 2 tray callsites work unchanged.

=head1 PUBLIC API

=over

=item show($parent_window?)

Builds and runs the modal About dialog. C<$parent_window> is used
as the C<transient_for> parent (typically the main window).
Returns 1.

=back

=head1 SEE ALSO

L<PAC::Dialog>, L<Gtk3::Dialog>.

=cut
