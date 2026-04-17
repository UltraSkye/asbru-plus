package PAC::Theme::Widget;

###############################################################################
# PAC::Theme::Widget — Gtk3 widget styling helpers.
#
# Bundles four small widget-styling helpers from PACUtils:
#   - update_color($self, $cfg, $widget, $cfg_name, $default_color)
#   - set_default_rgba($r, $g, $b, $a)
#   - set_window_paintable($win)
#   - draw_callback($widget, $cairo)   — internal, used as Gtk3 'draw' handler
#
# The R/G/B/A defaults are module-scoped (used by draw_callback when
# painting a transparent window background).
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# Module-local state for the transparent-window paint:
#   set by set_default_rgba(), read by draw_callback().
my ($R, $G, $B, $A);

# update_color($self, $cfg, $widget, $cfg_name, $default_color)
# Reads $cfg->{$cfg_name} (or $default_color), parses as Gdk::RGBA,
# applies via $widget->set_rgba(). $widget may be a name to look up
# via PACUtils::_($self, $name).
sub update_color {
    my ($self, $cfg, $widget, $cfg_name, $default_color) = @_;
    if (ref($widget) eq '') {
        $widget = PACUtils::_($self, $widget);
    }
    my $rgba = Gtk3::Gdk::RGBA::parse($cfg->{$cfg_name} // $default_color);
    $widget->set_rgba($rgba);
}

# set_default_rgba($r, $g, $b, $a) — set the default paint color
# (each channel 0..255 except $a which is 0..1).
sub set_default_rgba {
    ($R, $G, $B, $A) = ($_[0] / 255, $_[1] / 255, $_[2] / 255, $_[3]);
}

# set_window_paintable($win) — wires a window for transparent
# background painting. Connects the 'draw' signal to draw_callback,
# selects an RGBA visual on composited screens, and marks the window
# app-paintable.
sub set_window_paintable {
    my $win = shift;

    $win->signal_connect('draw' => \&draw_callback);
    my $screen = $win->get_screen();
    my $visual = $screen->get_rgba_visual();
    if ($visual && $screen->is_composited()) {
        $win->set_visual($visual);
    }
    $win->set_app_paintable(1);
}

# draw_callback($widget, $cairo) — Gtk3 'draw' signal handler that
# fills the window with the module-scoped RGBA color. Used by
# set_window_paintable.
sub draw_callback {
    my ($w, $c) = @_;
    $c->set_source_rgba($R, $G, $B, $A);
    $c->set_operator('source');
    $c->paint();
    $c->set_operator('over');
    return 0;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Theme::Widget — Gtk3 widget styling helpers

=head1 SYNOPSIS

    use PAC::Theme::Widget;

    PAC::Theme::Widget::set_default_rgba(0, 0, 0, 0.7);
    PAC::Theme::Widget::set_window_paintable($main_window);

    PAC::Theme::Widget::update_color($self, $cfg,
        'colorBack', 'back color', '#000000');

=head1 DESCRIPTION

Bundles four small Gtk3 styling helpers previously in PACUtils. Each
is mechanically identical to its predecessor; PACUtils retains
1-line goto-proxies under the legacy underscored names
(C<_updateWidgetColor>, C<_setDefaultRGBA>, C<_setWindowPaintable>,
C<mydraw>).

=head1 PUBLIC API

=over

=item update_color($self, $cfg, $widget, $cfg_name, $default_color)

Sets the RGBA color on a widget from a config value (with a default
fallback). C<$widget> may be a Glade widget name string, in which
case it's resolved via C<PACUtils::_($self, $name)>.

=item set_default_rgba($r, $g, $b, $a)

Stores the default paint color used by C<draw_callback>. C<$r>/C<$g>/C<$b>
are 0..255 octets; C<$a> is 0..1 alpha.

=item set_window_paintable($win)

Wires C<$win> for transparent background painting: connects the
'draw' signal to C<draw_callback>, selects an RGBA visual on
composited screens, marks the window app-paintable.

=item draw_callback($widget, $cairo)

Gtk3 'draw' signal handler that fills the window with the
RGBA color set by C<set_default_rgba>. Public so the legacy
C<PACUtils::mydraw> proxy can goto into it.

=back

=head1 SEE ALSO

L<Gtk3::Gdk::RGBA>, L<Gtk3::Window>, L<Cairo>.

=cut
