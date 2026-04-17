package PAC::Window::Splash;

###############################################################################
# PAC::Window::Splash — startup splash window.
#
# Singleton Gtk3::Window with logo + progress bar shown during app
# startup. Mechanical extraction from PACUtils::_splash.
#
# PACUtils retains a 1-line proxy. PAC::Dialog reads gui() to use the
# splash window as a fallback parent during early startup before the
# main window exists.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# Singleton state — created on first show, destroyed on dismiss.
my %WIN;

# show($show, $txt?, $partial?, $total?)
# Replaces the legacy PACUtils::_splash. With $show truthy, displays
# the splash + updates the progress bar; with falsy $show, hides +
# destroys it. Returns 1 always.
sub show {
    my ($show, $txt, $partial, $total) = @_;

    return 1 if $PACMain::_NO_SPLASH;

    $txt     //= "<b>Starting $PACUtils::APPNAME (v$PACUtils::APPVERSION)...</b>";
    $partial //= 0;
    $total   //= 1;

    if (!defined $WIN{_GUI}) {
        $WIN{_GUI} = Gtk3::Window->new();
        $WIN{_GUI}->set_type_hint('splashscreen');
        $WIN{_GUI}->set_position('center');
        $WIN{_GUI}->set_keep_above(1);
        $WIN{_GUI}->get_style_context->add_class('asbru-splash');

        $WIN{_VBOX} = Gtk3::Box->new('vertical', 8);
        $WIN{_VBOX}->set_border_width(12);
        $WIN{_GUI}->add($WIN{_VBOX});

        my $splash_img = ($PACUtils::RES_DIR // '') . '/asbru-logo-400.png';
        $WIN{_IMG} = Gtk3::Image->new_from_file($splash_img);
        $WIN{_VBOX}->pack_start($WIN{_IMG}, 1, 1, 0);

        $WIN{_LBL} = Gtk3::ProgressBar->new();
        $WIN{_VBOX}->pack_start($WIN{_LBL}, 1, 1, 5);
    }

    $WIN{_LBL}->set_show_text(1);
    $WIN{_LBL}->set_text($txt);
    $WIN{_LBL}->set_fraction($partial / $total);

    if ($show) {
        $WIN{_GUI}->show_all();
        $WIN{_GUI}->present();
        Gtk3::main_iteration() while Gtk3::events_pending;
    } else {
        $WIN{_GUI}->hide();
        $WIN{_GUI}->destroy();
        delete $WIN{_GUI};   # singleton: re-create on next show
    }

    return 1;
}

# gui() — returns the splash Gtk3::Window or undef. Used by PAC::Dialog
# as a fallback transient parent during early startup before the main
# window has been built.
sub gui { return $WIN{_GUI}; }

1;

__END__

=encoding utf8

=head1 NAME

PAC::Window::Splash — startup splash window

=head1 SYNOPSIS

    use PAC::Window::Splash;

    PAC::Window::Splash::show(1, 'Loading config...', 1, 4);
    PAC::Window::Splash::show(1, 'Initializing UI...', 2, 4);
    PAC::Window::Splash::show(1, 'Almost done...',     3, 4);
    PAC::Window::Splash::show(0);   # hide + destroy

    # PAC::Dialog uses this as a fallback parent during early startup
    my $win = PAC::Window::Splash::gui();

=head1 DESCRIPTION

Singleton Gtk3 splash window with the asbru logo and a progress bar.
Created on first call to C<show($truthy, ...)>, destroyed on
C<show(0)>. Mechanical extraction from C<PACUtils::_splash>; PACUtils
retains a 1-line proxy under the legacy name.

The C<gui()> accessor is used by L<PAC::Dialog> as a fallback transient
parent for modal dialogs that fire before the main window exists.

=head1 PUBLIC API

=over

=item show($show, $txt?, $partial?, $total?)

If C<$show> truthy: shows the splash and updates the progress bar
(C<$partial / $total>). If falsy: hides and destroys it. Title text
defaults to "Starting Ásbrú Plus (v…)".

Honors C<$PACMain::_NO_SPLASH>: when set, no-ops.

=item gui

Returns the splash C<Gtk3::Window> (or undef if not currently shown).

=back

=head1 SEE ALSO

L<PAC::Dialog>, L<PACUtils>.

=cut
