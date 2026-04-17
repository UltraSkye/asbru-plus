package PAC::Theme::Switch;

###############################################################################
# PAC::Theme::Switch — runtime theme switcher (default ↔ asbru-dark).
#
# Mechanical extraction of three related PACMain helpers:
#   - _resetStyleRecursively (12 lines)
#   - _refreshImagesRecursively (25 lines)
#   - _toggleTheme (101 lines)
#
# The toggle persists the new theme to disk, swaps the active CSS
# provider on the default Gtk3::Gdk::Screen, flips the GTK
# 'prefer-dark' hint, re-registers the asbru icon factory from the
# new theme dir, and walks every open window to invalidate cached
# styles + refresh stock-icon images.
#
# PACMain retains 1-line wrappers. The 1 callsite for _toggleTheme
# (theme-toggle keybinding) and any internal recursive helper uses
# work unchanged.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;
use Storable qw(nstore);

use PAC::Theme::Icons;
use PAC::Theme::Image;
use PAC::Vault;
use PAC::Crypto::HMAC;

our $VERSION = '0.1.0';

# reset_style($widget) — recursively call $widget->reset_style on
# the widget tree. Used after CSS provider swap to drop cached
# resolved styles.
sub reset_style {
    my $widget = shift;
    return unless $widget;
    eval {
        $widget->reset_style if $widget->can('reset_style');
        if ($widget->can('get_children')) {
            for my $c ($widget->get_children) {
                reset_style($c);
            }
        }
    };
}

# refresh_images($widget) — recursively re-issue set_from_stock on
# every Gtk3::Image in the widget tree, forcing the current icon
# factory to re-resolve. Used after a theme switch.
sub refresh_images {
    my $widget = shift;
    return unless $widget;
    eval {
        if ($widget->isa('Gtk3::Image')) {
            my $stype = $widget->get_storage_type;
            if (defined $stype && "$stype" eq 'stock') {
                my @stk = $widget->get_stock;
                my $id   = $stk[0];
                my $size = $stk[1] // 'small_toolbar';
                $widget->set_from_stock($id, $size) if $id;
            }
        }
        if ($widget->isa('Gtk3::Button') && $widget->get_image) {
            refresh_images($widget->get_image);
        }
        if ($widget->can('get_children')) {
            for my $c ($widget->get_children) {
                refresh_images($c);
            }
        }
    };
}

# toggle($self) — flip between default and asbru-dark themes.
# Mutates $self->{_CFG}{defaults}{theme}, $self->{_THEME},
# $self->{_THEME_PROVIDERS_BY_NAME}, $self->{_THEME_PROVIDER},
# $self->{_METHODS}, $PACMain::THEME_DIR, and the package-global
# pixbuf vars in PACMain::*. Persists the change to disk so the
# next launch is consistent.
sub toggle {
    my $self = shift;

    my $cur  = $$self{_CFG}{'defaults'}{'theme'} // 'default';
    my $next = ($cur eq 'asbru-dark') ? 'default' : 'asbru-dark';

    $$self{_CFG}{'defaults'}{'theme'} = $next;
    $PACMain::THEME_DIR = "$PACMain::RES_DIR/themes/$next";
    $$self{_THEME} = $PACMain::THEME_DIR;
    $self->_setCFGChanged(1);

    # Persist to disk so next launch is consistent.
    eval {
        PAC::Vault::cipher_cfg($$self{_CFG});
        nstore($$self{_CFG}, $PACMain::CFG_FILE_NFREEZE);
        PAC::Crypto::HMAC::write_for($PACMain::CFG_FILE_NFREEZE);
        PAC::Vault::decipher_cfg($$self{_CFG});
    };

    my $screen = Gtk3::Gdk::Screen::get_default;

    # Keep BOTH theme providers loaded; toggle by re-adding with new
    # priority. We never touch gtk-theme-name (unreliable mid-session).
    $$self{_THEME_PROVIDERS_BY_NAME} //= {};
    for my $tname ('asbru-dark', 'default') {
        next if $$self{_THEME_PROVIDERS_BY_NAME}{$tname};
        my $cp = Gtk3::CssProvider->new();
        eval { $cp->load_from_path("$PACMain::RES_DIR/themes/$tname/asbru.css"); };
        Gtk3::StyleContext::add_provider_for_screen($screen, $cp, 600);
        $$self{_THEME_PROVIDERS_BY_NAME}{$tname} = $cp;
    }

    # Demote previous to LOW (590), promote next to HIGH (USER=800).
    # Priorities can only be set at add-time — re-add to change.
    for my $tname (keys %{ $$self{_THEME_PROVIDERS_BY_NAME} }) {
        my $p = $$self{_THEME_PROVIDERS_BY_NAME}{$tname};
        eval { Gtk3::StyleContext::remove_provider_for_screen($screen, $p); };
        my $prio = ($tname eq $next) ? 800 : 590;
        Gtk3::StyleContext::add_provider_for_screen($screen, $p, $prio);
    }

    # Drop any older single-provider tracking from previous code paths.
    if ($$self{_THEME_PROVIDERS}) {
        for my $p (@{ $$self{_THEME_PROVIDERS} }) {
            next if grep { $_ == $p } values %{ $$self{_THEME_PROVIDERS_BY_NAME} };
            eval { Gtk3::StyleContext::remove_provider_for_screen($screen, $p); };
        }
        @{ $$self{_THEME_PROVIDERS} } = ();
    }
    $$self{_THEME_PROVIDER} = $$self{_THEME_PROVIDERS_BY_NAME}{$next};

    # Adwaita variant — only flip prefer-dark, don't touch gtk-theme-name.
    eval {
        my $s = Gtk3::Settings::get_default();
        $s->set_property('gtk-application-prefer-dark-theme',
            $next eq 'asbru-dark' ? 1 : 0) if $s;
    };

    # Re-register icon factory from the new theme dir.
    eval { PAC::Theme::Icons::register($PACMain::THEME_DIR); };

    # Globally invalidate cached resolved styles.
    eval { Gtk3::StyleContext::reset_widgets($screen); };

    # Walk every open window: refresh images + reset style + queue draw.
    eval {
        for my $win ($$self{_GUI}{main},
                     $$self{_CONFIG} ? $$self{_CONFIG}{_WINDOWCONFIG} : undef,
                     $$self{_EDIT}   ? $$self{_EDIT}{_WINDOWEDIT}     : undef)
        {
            next unless $win;
            refresh_images($win);
            reset_style($win);
            $win->queue_draw;
        }
    };

    # Reload tree group pixbufs + connection-method icons (these are
    # stored as GdkPixbuf inside the TreeStore — not refreshed by
    # the GtkImage walker).
    eval {
        $PACMain::GROUPICON_ROOT  = PAC::Theme::Image::pixbuf_from_file("$PACMain::THEME_DIR/asbru_group.svg");
        $PACMain::GROUPICON       = PAC::Theme::Image::pixbuf_from_file("$PACMain::THEME_DIR/asbru_group_open_16x16.svg");
        $PACMain::GROUPICONOPEN   = PAC::Theme::Image::pixbuf_from_file("$PACMain::THEME_DIR/asbru_group_open_16x16.svg");
        $PACMain::GROUPICONCLOSED = PAC::Theme::Image::pixbuf_from_file("$PACMain::THEME_DIR/asbru_group_closed_16x16.svg");
        $PACMain::AUTOCLUSTERICON = PAC::Theme::Image::pixbuf_from_file("$PACMain::THEME_DIR/asbru_cluster_auto.svg");
        $PACMain::CLUSTERICON     = PAC::Theme::Image::pixbuf_from_file("$PACMain::THEME_DIR/asbru_cluster_connection.svg");
        %{ $$self{_METHODS} } = PACUtils::_getMethods($self, $PACMain::THEME_DIR);
        $PACMain::FUNCS{_METHODS} = $$self{_METHODS};
        $self->_loadTreeConfiguration('__PAC__ROOT__')
            if $self->can('_loadTreeConfiguration');
        $$self{_GUI}{treeConnections}->queue_draw if $$self{_GUI}{treeConnections};
    };

    print STDERR "INFO: Theme switched to '$next'\n";
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Theme::Switch — runtime theme switcher (default ↔ asbru-dark)

=head1 SYNOPSIS

    use PAC::Theme::Switch;

    PAC::Theme::Switch::toggle($pacmain_self);
    # PAC::Theme::Switch::reset_style($widget);
    # PAC::Theme::Switch::refresh_images($widget);

=head1 DESCRIPTION

Mechanical extraction of three related PACMain helpers
(C<_resetStyleRecursively>, C<_refreshImagesRecursively>,
C<_toggleTheme>) into one cohesive module.

The toggle persists the new theme to disk, swaps the active CSS
provider on the default screen via priority manipulation (we keep
both providers loaded and re-add with new priority), flips the GTK
C<prefer-dark> hint, re-registers the asbru icon factory from the
new theme dir, and walks every open window to invalidate cached
styles + refresh stock-icon images.

PACMain retains 1-line wrappers. The single callsite for
C<_toggleTheme> (theme-toggle keybinding) works unchanged.

=head1 PUBLIC API

=over

=item toggle($self)

Flip between default and asbru-dark. Mutates C<\$self>'s theme
state, C<\$PACMain::THEME_DIR>, and the package-global pixbuf vars
in PACMain. Persists to disk via L<PAC::Vault> + L<PAC::Crypto::HMAC>.

=item reset_style($widget)

Recursively calls C<\$widget-E<gt>reset_style> on the widget tree
to drop cached resolved styles after a CSS provider swap.

=item refresh_images($widget)

Recursively re-issues C<set_from_stock> on every C<Gtk3::Image> in
the tree, forcing the current icon factory to re-resolve.

=back

=head1 SEE ALSO

L<PAC::Theme::Icons>, L<PAC::Theme::Image>, L<Gtk3::CssProvider>,
L<Gtk3::StyleContext>.

=cut
