# Minimal Gtk3 stub for unit tests — no display required.
# Defines bare functions (called without parens) and widget-like classes.
package Gtk3;

sub import {}
sub init   { 1 }

# These are called as bare words (no parens) in PACUtils.pm under strict subs
sub events_pending    { 0 }
sub main_iteration    { 0 }
sub main_iteration_do { 0 }
sub main_quit         {}
sub main              {}
sub TRUE              { 1 }
sub FALSE             { 0 }

# Generic widget stub
{
    no warnings 'redefine';
    for my $pkg (qw(
        Gtk3::Window  Gtk3::Dialog      Gtk3::VBox     Gtk3::HBox
        Gtk3::Image   Gtk3::Label       Gtk3::Button   Gtk3::Entry
        Gtk3::ProgressBar  Gtk3::Spinner Gtk3::Statusbar
        Gtk3::IconFactory  Gtk3::IconSet Gtk3::IconSource
        Gtk3::AccelGroup   Gtk3::Builder Gtk3::CssProvider
        Gtk3::StyleContext Gtk3::AboutDialog
    )) {
        no strict 'refs';
        *{"${pkg}::new"}     = sub { bless {}, $pkg };
        *{"${pkg}::import"}  = sub {};
        *{"${pkg}::DESTROY"} = sub {};
        *{"${pkg}::AUTOLOAD"} = sub {
            our $AUTOLOAD;
            return if $AUTOLOAD =~ /::DESTROY$/;
            return bless {}, $pkg;
        };
    }
}

package Gtk3::Gdk;
sub import {}
our $AUTOLOAD;
sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; return bless {}, 'Gtk3::Gdk' }
sub new { bless {}, 'Gtk3::Gdk' }
sub pixbuf_get_from_window { bless {}, 'Gtk3::Gdk::Pixbuf' }

package Gtk3::Gdk::Pixbuf;
sub import {}
sub new                    { bless {}, 'Gtk3::Gdk::Pixbuf' }
sub new_from_file          { bless {}, 'Gtk3::Gdk::Pixbuf' }
sub new_from_file_at_scale { bless {}, 'Gtk3::Gdk::Pixbuf' }
our $AUTOLOAD;
sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; return bless {}, 'Gtk3::Gdk::Pixbuf' }
sub DESTROY {}

package Gtk3::Gdk::RGBA;
sub new    { bless {}, 'Gtk3::Gdk::RGBA' }
sub import {}
our $AUTOLOAD;
sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; return 0 }
sub DESTROY {}

1;
