package PAC::Theme::Image;

###############################################################################
# PAC::Theme::Image — pixbuf and image-widget helpers.
#
# Bundles four small image manipulators previously in PACUtils:
#   - screenshot($widget, $file?)        — capture widget to PNG
#   - scale($file_or_pixbuf, $w, $h, $ratio?) — fit-to-box scale
#   - pixbuf_from_file($file)            — load with eval-protected die
#   - banner($icon_filename, $text)      — themed icon+label Gtk box
#
# All functions are tolerant of malformed input — they print a STDERR
# warning and return 0 / undef rather than die. PACUtils retains 1-line
# proxies for the legacy underscored names.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;
use Gtk3::Gdk;

our $VERSION = '0.1.0';

# screenshot($widget, $file?)
# Captures the widget's window region as a Gdk::Pixbuf. If $file is
# given, saves it as PNG and returns the save() result; otherwise
# returns the pixbuf itself.
sub screenshot {
    my $widget = shift;
    my $file   = shift;

    my $alloc = $widget->get_allocation;
    my $px = Gtk3::Gdk::pixbuf_get_from_window(
        $widget->get_window,
        $alloc->{x}, $alloc->{y},
        $alloc->{width}, $alloc->{height},
    );

    return defined $file ? $px->save($file, 'png') : $px;
}

# scale($file_or_pixbuf, $w, $h, $ratio?)
# Loads/accepts a pixbuf and scales it to ($w x $h). With $ratio truthy,
# preserves aspect ratio when the image is bigger than the target box.
# Returns 0 on load failure (with STDERR warning).
sub scale {
    my $file  = shift;
    my $w     = shift;
    my $h     = shift;
    my $ratio = shift // '';

    my $pb;
    eval {
        $pb = ref($file) ? $file : Gtk3::Gdk::Pixbuf->new_from_file($file);
    };
    if ($@) {
        print STDERR "WARN: Error while loading pixBuf from file '$file': $@";
        return 0;
    }

    if ($ratio && ($pb->get_width > $w || $pb->get_height > $h)) {
        if ($pb->get_width > $pb->get_height) {
            $h = int(($w * $pb->get_height) / $pb->get_width);
        } elsif ($pb->get_height >= $pb->get_width) {
            $w = int(($h * $pb->get_width) / $pb->get_height);
        }
    }

    return $pb->scale_simple($w, $h, 'GDK_INTERP_HYPER');
}

# pixbuf_from_file($file)
# Load a Gdk::Pixbuf from disk with eval-protected die. Returns 0 on
# failure with STDERR warning.
sub pixbuf_from_file {
    my $file = shift;
    my $pb;
    eval { $pb = Gtk3::Gdk::Pixbuf->new_from_file($file) };
    if ($@) {
        print STDERR "WARN: Error while loading pixBuf from file '$file': $@";
        return 0;
    }
    return $pb;
}

# banner($icon_filename, $text)
# Build the asbru theme banner: a horizontal Gtk3::Box with the icon
# image (loaded from $PACUtils::THEME_DIR/$icon_filename) and a label.
# Returns the Gtk3::Box.
sub banner {
    my $icon_filename = shift;
    my $text_label    = shift;

    my $theme_dir = $PACUtils::THEME_DIR // '';

    my $icon = Gtk3::Image->new_from_file("$theme_dir/$icon_filename");
    $icon->set_margin_left(10);
    $icon->set_margin_right(10);

    my $text = Gtk3::Label->new();
    $text->set_margin_left(10);
    $text->set_margin_right(10);
    $text->set_text($text_label);
    $text->get_style_context->add_class('banner-text');

    my $box = Gtk3::Box->new('horizontal', 0);
    $box->set_size_request(-1, 50);
    $box->get_style_context->add_class('banner-fill');
    $box->pack_start($icon, 0, 1, 0);
    $box->pack_start($text, 0, 1, 0);

    return $box;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Theme::Image — pixbuf and image-widget helpers

=head1 SYNOPSIS

    use PAC::Theme::Image;

    # Capture a widget to PNG
    PAC::Theme::Image::screenshot($widget, '/tmp/snap.png');

    # Load + scale an image
    my $px = PAC::Theme::Image::scale('/path/to/img.png', 64, 64, 1);

    # Themed banner with icon + label
    my $b = PAC::Theme::Image::banner('asbru-wol.svg', 'Wake on LAN');

=head1 DESCRIPTION

Bundles four image utilities previously in PACUtils. Each is mechanical-
move identical to its predecessor; PACUtils retains 1-line goto-proxies
under the legacy names (C<_screenshot>, C<_scale>, C<_pixBufFromFile>,
C<_createBanner>).

=head1 PUBLIC API

=over

=item screenshot($widget, $file?)

Captures the widget's window region as a Gdk::Pixbuf. With C<$file>,
saves as PNG and returns the save() result; otherwise returns the
pixbuf itself.

=item scale($file_or_pixbuf, $w, $h, $ratio?)

Loads/accepts a pixbuf and scales to (C<$w> x C<$h>). With C<$ratio>
truthy, preserves aspect ratio. Returns 0 on load failure.

=item pixbuf_from_file($file)

Loads a Gdk::Pixbuf from disk with eval-protected die. Returns 0 on
failure (with STDERR warning).

=item banner($icon_filename, $text)

Builds the asbru-theme banner — horizontal Gtk3::Box with icon
(loaded from C<$PACUtils::THEME_DIR/$icon_filename>) and label.
Returns the Box.

=back

=head1 SEE ALSO

L<Gtk3::Gdk::Pixbuf>, L<PAC::Theme::Icons>, L<PACUtils>.

=cut
