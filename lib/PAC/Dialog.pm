package PAC::Dialog;

###############################################################################
# PAC::Dialog — modal Gtk3 dialog helpers extracted from PACUtils.pm.
#
# Functions are kept name-compatible with the legacy `_w*` helpers so callers
# don't have to migrate. PACUtils re-exports them via thin proxies — code can
# either keep calling `_wMessage(...)` (legacy) or call `PAC::Dialog::message(...)`
# (new code).
#
# Globals referenced from PACUtils:
#   $PACUtils::APPNAME            — title-bar prefix
#   %PACUtils::WINDOWSPLASH       — splash window (used as fallback parent)
# Plus the running app's main window: $PACMain::FUNCS{_MAIN}{_GUI}{main}
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Public API (legacy names — kept for source compatibility)
#-------------------------------------------------------------------------

sub _wEnterValue {
    my $parent = shift;
    my $lblup = shift;
    my $lbldown = shift;
    my $default = shift;
    my $visible = shift // 1;
    my $stock_icon = shift // 'asbru-help';
    my $entry;
    my @list;
    my $pos = -1;
    my %w;

    if (!defined $default) {
        $default = '';
    } elsif (ref($default)) {
        @list = @{$default};
    } elsif ($default =~ /.+?\|.+?\|/) {
        @list = split /\|/,$default;
    }

    if (defined $parent && ref $parent ne 'Gtk3::Window') {
        print STDERR "WARN: Wrong parent parameter received _wEnterValue ",ref $parent,"\n";
        undef $parent;
    }
    if (!defined $parent) {
        if (defined $PACMain::FUNCS{_MAIN}{_GUI}{main}) {
            $parent = $PACMain::FUNCS{_MAIN}{_GUI}{main};
        } elsif (defined $PACUtils::WINDOWSPLASH{_GUI}) {
            $parent = $PACUtils::WINDOWSPLASH{_GUI};
        }
    }
    if (!$stock_icon) {
        $stock_icon = 'asbru-help';
    }

    $w{window}{data} = Gtk3::Dialog->new_with_buttons(
        "$PACUtils::APPNAME : Enter data",
        $parent,
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok'
    );
    $w{window}{data}->set_decorated(0);
    $w{window}{data}->get_style_context()->add_class('w-entervalue');
    $w{window}{data}->set_default_response('ok');
    $w{window}{data}->set_position('center') unless $parent;
    $w{window}{data}->set_icon_name('asbru-app-big');
    $w{window}{data}->set_resizable(0);
    $w{window}{data}->set_border_width(15);

    $w{window}{gui}{vbox} = Gtk3::Box->new('vertical', 0);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{vbox}, 0, 0, 0);

    $w{window}{gui}{hbox} = Gtk3::Box->new('horizontal', 0);
    $w{window}{gui}{hbox}->set_border_width(0);
    $w{window}{gui}{vbox}->pack_start($w{window}{gui}{hbox}, 0, 0, 5);

    $w{window}{gui}{img} = Gtk3::Image->new_from_stock($stock_icon, 'dialog');
    $w{window}{gui}{hbox}->pack_start($w{window}{gui}{img}, 0, 1, 5);

    $w{window}{gui}{lblup} = Gtk3::Label->new();
    $w{window}{gui}{hbox}->pack_start($w{window}{gui}{lblup}, 0, 0, 0);
    $w{window}{gui}{lblup}->set_markup($lblup // '');

    $w{window}{gui}{lbldwn} = Gtk3::Label->new();
    $w{window}{gui}{vbox}->pack_start($w{window}{gui}{lbldwn}, 0, 0, 5);
    $w{window}{gui}{lbldwn}->set_markup($lbldown // '');

    if (@list) {
        $w{window}{gui}{comboList} = Gtk3::ComboBoxText->new();
        $w{window}{gui}{vbox}->pack_start($w{window}{gui}{comboList}, 0, 1, 5);
        $w{window}{gui}{comboList}->set_property('can_focus', 0);
        foreach my $text (@list) {
            $w{window}{gui}{comboList}->append_text($text)
        };
        $w{window}{gui}{comboList}->set_active(0);
    } else {
        $w{window}{gui}{entry} = Gtk3::Entry->new();
        $entry = $w{window}{gui}{entry};
        $w{window}{gui}{vbox}->pack_start($w{window}{gui}{entry}, 0, 1, 5);
        $w{window}{gui}{entry}->set_text($default);
        $w{window}{gui}{entry}->set_width_chars(30);
        $w{window}{gui}{entry}->set_activates_default(1);
        $w{window}{gui}{entry}->set_visibility($visible);
        $w{window}{gui}{entry}->grab_focus();
    }

    $entry->grab_focus() if $entry;
    $w{window}{data}->show_all();
    my $ok = $w{window}{data}->run();
    my $val;

    if (@list) {
        $val = $w{window}{gui}{comboList}->get_active_text() if $ok eq 'ok';
        $pos = $w{window}{gui}{comboList}->get_active();
    } else {
        $val = $w{window}{gui}{entry}->get_chars(0, -1) if $ok eq 'ok';
    }

    $w{window}{data}->destroy();
    Gtk3::main_iteration() while Gtk3::events_pending;

    return wantarray ? ($val, $pos) : $val;
}

sub _wMessage {
    my $window = shift;
    my $msg = shift;
    my $modal = shift // 1;
    my $selectable = shift // 0;
    my $class = shift // 'w-warning';
    my $msg_type = 'GTK_MESSAGE_WARNING';

    if (defined $window && ref $window ne 'Gtk3::Window') {
        print STDERR "WARN: Wrong parent parameter received _wMessage ",ref $window,"\n";
        undef $window;
    }
    if (!$window) {
        $window = $PACMain::FUNCS{_MAIN}{_GUI}{main};
    }
    if ($msg =~ /error/i) {
        $msg_type = 'GTK_MESSAGE_ERROR';
        $class = 'w-error';
    }
    my $w = Gtk3::MessageDialog->new($window,
        'GTK_DIALOG_DESTROY_WITH_PARENT', $msg_type, 'none', '');
    $w->set_decorated(0);
    $w->set_border_width(15);
    $w->get_style_context()->add_class($class);
    $w->set_markup($msg);
    $w->set_icon_name('asbru-app-big');
    $w->set_title("$PACUtils::APPNAME : Message");

    if ($selectable) {
        $w->get_message_area()->foreach(sub {
            my $child = shift;
            $child->set_selectable(1) if ref($child) eq 'Gtk3::Label';
        });
    }

    if ($modal) {
        $w->add_buttons('gtk-ok' => 'ok');
        _constrain_action_area($w);
        $w->show_all();
        $w->run();
        $w->destroy();
    } else {
        $w->show_all();
        Gtk3::main_iteration() while Gtk3::events_pending();
    }
    return $w;
}

sub _wConfirm {
    my $window = shift;
    my $msg = shift;
    my $default = shift // 'no';

    if (defined $window && ref $window ne 'Gtk3::Window') {
        print STDERR "WARN: Wrong parent parameter received _wConfirm ",ref $window,"\n";
        undef $window;
    }
    if (!$window) {
        $window = $PACMain::FUNCS{_MAIN}{_GUI}{main};
    }
    my $w = Gtk3::MessageDialog->new($window,
        'GTK_DIALOG_DESTROY_WITH_PARENT', 'GTK_MESSAGE_QUESTION', 'none', '');
    $w->set_decorated(0);
    $w->set_border_width(15);
    $w->get_style_context()->add_class('w-confirm');
    $w->set_markup($msg);
    $w->add_buttons('gtk-cancel' => 'no', 'gtk-ok' => 'yes');
    $w->set_icon_name('asbru-app-big');
    $w->set_title("Confirm action : $PACUtils::APPNAME");
    $w->set_default_response($default);
    _constrain_action_area($w);

    $w->show_all();
    my $close = $w->run();
    $w->destroy();
    return ($close eq 'yes');
}

sub _wYesNoCancel {
    my $window = shift;
    my $msg = shift;

    if (!$window) {
        $window = $PACMain::FUNCS{_MAIN}{_GUI}{main};
    }
    my $w = Gtk3::MessageDialog->new($window,
        'GTK_DIALOG_DESTROY_WITH_PARENT', 'GTK_MESSAGE_QUESTION', 'none', '');
    $w->set_decorated(0);
    $w->set_border_width(15);
    $w->get_style_context()->add_class('w-confirm');
    $w->set_markup($msg);
    $w->add_buttons('gtk-cancel' => 'cancel', 'gtk-no' => 'no', 'gtk-yes' => 'yes');
    $w->set_icon_name('asbru-app-big');
    $w->set_title("Confirm action : $PACUtils::APPNAME");
    _constrain_action_area($w);

    $w->show_all();
    my $close = $w->run();
    $w->destroy();
    return (($close eq 'delete-event') || ($close eq 'cancel')) ? 'cancel' : $close;
}

#-------------------------------------------------------------------------
# Internal
#-------------------------------------------------------------------------

# Prevent the OK/Cancel buttons from stretching across the dialog width.
sub _constrain_action_area {
    my $w = shift;
    eval {
        my $area = $w->get_action_area;
        if ($area) {
            $area->set_layout('end');
            $area->set_spacing(8);
            foreach my $child ($area->get_children) {
                $child->set_hexpand(0);
                $child->set_halign('center');
            }
        }
    };
}

#-------------------------------------------------------------------------
# Additional dialog helpers (moved from PACUtils in P3/7).
#-------------------------------------------------------------------------

# _wAddRenameNode($action, $cfg, $uuid)  — Add or rename a tree node.
# Returns ($new_name, $new_title) or (undef, undef) on cancel.
sub _wAddRenameNode {
    my $action = shift;
    my $cfg = shift;
    my $uuid = shift;

    my ($name, $parent_name, $title, $lblup);

    if ($action eq 'rename') {
        $name = $$cfg{'environments'}{$uuid}{'name'};
        $parent_name = $$cfg{'environments'}{$$cfg{'environments'}{$uuid}{'parent'}}{'name'} // '';
        $title = $$cfg{'environments'}{$uuid}{'title'};
        $lblup = "Renaming node <b>@{[PACUtils::__($name)]}</b>";
    } elsif ($action eq 'add') {
        $name = '';
        $parent_name = $$cfg{'environments'}{$uuid}{'name'};
        $title = $uuid eq '__PAC__ROOT__' || ! $$cfg{defaults}{'append group name'} ? '' : ($parent_name eq '' ? '' : " - $parent_name");
        $lblup = "Adding new node into <b>" . ($uuid eq '__PAC__ROOT__' ? 'ROOT' : PACUtils::__($parent_name)) . "</b>";
    }

    my %w;
    my $new_name;
    my $new_title;

    $w{window}{data} = Gtk3::Dialog->new_with_buttons(
        "$PACUtils::APPNAME : Enter data",
        $PACMain::FUNCS{_MAIN}{_GUI}{main},
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok'
    );
    $w{window}{data}->set_decorated(0);
    $w{window}{data}->get_style_context()->add_class('w-renamenode');
    $w{window}{data}->set_default_response('ok');
    $w{window}{data}->set_icon_name('asbru-app-big');
    $w{window}{data}->set_resizable(0);
    $w{window}{data}->set_border_width(5);

    $w{window}{gui}{hbox} = Gtk3::Box->new('horizontal', 0);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{hbox}, 0, 1, 0);
    $w{window}{gui}{hbox}->set_border_width(5);

    $w{window}{gui}{img} = Gtk3::Image->new_from_stock('gtk-edit', 'dialog');
    $w{window}{gui}{hbox}->pack_start($w{window}{gui}{img}, 0, 1, 0);

    $w{window}{gui}{lblup} = Gtk3::Label->new();
    $w{window}{gui}{hbox}->pack_start($w{window}{gui}{lblup}, 1, 1, 0);
    $w{window}{gui}{lblup}->set_markup($lblup);

    $w{window}{gui}{hbox1} = Gtk3::Box->new('horizontal', 0);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{hbox1}, 0, 1, 0);
    $w{window}{gui}{hbox1}->set_border_width(5);

    $w{window}{gui}{lbl1} = Gtk3::Label->new();
    $w{window}{gui}{hbox1}->pack_start($w{window}{gui}{lbl1}, 0, 1, 0);
    $w{window}{gui}{lbl1}->set_text('Enter new NAME ');

    $w{window}{gui}{entry1} = Gtk3::Entry->new();
    $w{window}{gui}{hbox1}->pack_start($w{window}{gui}{entry1}, 1, 1, 0);
    $w{window}{gui}{entry1}->set_text($name);
    $w{window}{gui}{entry1}->set_width_chars(30);
    $w{window}{gui}{entry1}->set_activates_default(1);
    $w{window}{gui}{entry1}->signal_connect('changed', sub {
        $w{window}{gui}{entry2}->set_text($w{window}{gui}{entry1}->get_chars(0, -1) . ($uuid eq '__PAC__ROOT__' || ! $$cfg{defaults}{'append group name'} ? '' : ($parent_name eq '' ? '' :  " - $parent_name")));
    });

    $w{window}{gui}{hbox2} = Gtk3::Box->new('horizontal', 0);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{hbox2}, 0, 1, 0);
    $w{window}{gui}{hbox2}->set_border_width(5);

    $w{window}{gui}{lbl2} = Gtk3::Label->new();
    $w{window}{gui}{hbox2}->pack_start($w{window}{gui}{lbl2}, 0, 1, 0);
    $w{window}{gui}{lbl2}->set_text('Enter new TITLE ');

    $w{window}{gui}{entry2} = Gtk3::Entry->new();
    $w{window}{gui}{hbox2}->pack_start($w{window}{gui}{entry2}, 1, 1, 0);
    $w{window}{gui}{entry2}->set_text($title);
    $w{window}{gui}{entry2}->set_width_chars(30);
    $w{window}{gui}{entry2}->set_activates_default(1);

    $w{window}{data}->show_all();
    my $ok = $w{window}{data}->run();

    if ($ok eq 'ok') {
        $new_name = $w{window}{gui}{entry1}->get_chars(0, -1);
        $new_title = $w{window}{gui}{entry2}->get_chars(0, -1);
    }

    $w{window}{data}->destroy();
    Gtk3::main_iteration while Gtk3::events_pending;

    return ($new_name, $new_title);
}

# _wProgress($parent, $title, $msg, $progress)  — Modal progress window.
# Singleton: re-uses the same window across calls. Returns 1 normally,
# 0 if user clicked Cancel.
my %WINDOWPROGRESS;
sub _wProgress {
    my $window   = shift;
    my $title    = shift;
    my $msg      = shift;
    my $progress = shift;

    $WINDOWPROGRESS{_RET} = 1;

    if (!defined $WINDOWPROGRESS{_GUI}) {
        $WINDOWPROGRESS{_GUI} = Gtk3::Window->new();
        $WINDOWPROGRESS{_GUI}->set_position('center');
        $WINDOWPROGRESS{_GUI}->set_icon_name('asbru-app-big');
        $WINDOWPROGRESS{_GUI}->set_size_request('400', '150');
        $WINDOWPROGRESS{_GUI}->set_resizable(0);
        $WINDOWPROGRESS{_GUI}->set_transient_for($window) if defined $window;
        $WINDOWPROGRESS{_GUI}->set_modal(1);

        $WINDOWPROGRESS{vbox} = Gtk3::Box->new('vertical', 0);
        $WINDOWPROGRESS{_GUI}->add($WINDOWPROGRESS{vbox});

        $WINDOWPROGRESS{lbl1} = Gtk3::Label->new();
        $WINDOWPROGRESS{vbox}->pack_start($WINDOWPROGRESS{lbl1}, 0, 1, 5);

        $WINDOWPROGRESS{pb} = Gtk3::ProgressBar->new();
        $WINDOWPROGRESS{vbox}->pack_start($WINDOWPROGRESS{pb}, 1, 1, 5);

        $WINDOWPROGRESS{sep} = Gtk3::HSeparator->new();
        $WINDOWPROGRESS{vbox}->pack_start($WINDOWPROGRESS{sep}, 0, 1, 5);

        $WINDOWPROGRESS{btnCancel} = Gtk3::Button->new_from_stock('gtk-cancel');
        $WINDOWPROGRESS{vbox}->pack_start($WINDOWPROGRESS{btnCancel}, 0, 1, 5);

        $WINDOWPROGRESS{_GUI}->signal_connect('delete_event' => sub { return 1 });
        $WINDOWPROGRESS{btnCancel}->signal_connect('clicked' => sub {
            $WINDOWPROGRESS{_RET} = 0;
            $WINDOWPROGRESS{_GUI}->hide();
            return 1;
        });
    }

    $WINDOWPROGRESS{_GUI}->set_icon_name('asbru-app-big');
    $WINDOWPROGRESS{_GUI}->set_title("$PACUtils::APPNAME (v$PACUtils::APPVERSION) : $title");

    if ($progress) {
        my ($partial, $total) = split('/', $progress);
        $WINDOWPROGRESS{lbl1}->set_markup('<b>Please, wait...</b>');
        $WINDOWPROGRESS{pb}->set_text($msg);
        $WINDOWPROGRESS{pb}->set_fraction($partial / $total);
        $WINDOWPROGRESS{_GUI}->show_all();
        Gtk3::main_iteration() while Gtk3::events_pending();
    } else {
        $WINDOWPROGRESS{_GUI}->hide();
    }

    return $WINDOWPROGRESS{_RET};
}

# _wSetPACPassword($self, $ask_old)  — Three-step GUI-password change
# dialog (old / new / confirm). Updates $self->{_CFG} and triggers
# _setCFGChanged.
sub _wSetPACPassword {
    my $self = shift;
    my $ask_old = shift // 0;

    require PAC::Crypto::Cipher;

    if ($ask_old) {
        my $old_pass = _wEnterValue($$self{_WINDOWCONFIG},
            'GUI Password Change', 'Please, enter <b>OLD</b> GUI Password...',
            undef, 0, 'asbru-protected');
        return 0 unless defined $old_pass;

        my $stored = PAC::Crypto::Cipher::decrypt_hex(
            $$self{_CFG}{'defaults'}{'gui password'});
        if ($old_pass ne $stored) {
            _wMessage($$self{_WINDOWCONFIG},
                'ERROR: Wrong <b>OLD</b> password!!');
            return 0;
        }
    }

    my $new_pass1 = _wEnterValue($$self{_WINDOWCONFIG},
        '<b>GUI Password Change</b>',
        'Please, enter <b>NEW</b> GUI Password...',
        undef, 0, 'asbru-protected');
    return 0 unless defined $new_pass1;

    my $new_pass2 = _wEnterValue($$self{_WINDOWCONFIG},
        '<b>GUI Password Change</b>',
        'Please, <b>confirm NEW</b> GUI Password...',
        undef, 0, 'asbru-protected');
    return 0 unless defined $new_pass2;

    if ($new_pass1 ne $new_pass2) {
        _wMessage($$self{_WINDOWCONFIG},
            '<b>ERROR</b>: Provided <b>NEW</b> passwords <span color="red"><b>DO NOT MATCH</b></span>!!!');
        return 0;
    }

    $$self{_CFG}{'defaults'}{'gui password'}
        = PAC::Crypto::Cipher::encrypt_hex($new_pass1);
    $PACMain::FUNCS{_MAIN}->_setCFGChanged(1);

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Dialog — modal Gtk3 dialog helpers

=head1 SYNOPSIS

    use PAC::Dialog;

    my $val = PAC::Dialog::_wEnterValue($parent, '<b>Name?</b>', 'Helper text');
    PAC::Dialog::_wMessage($parent, 'Operation completed.');
    my $ok = PAC::Dialog::_wConfirm($parent, 'Delete this connection?');

=head1 DESCRIPTION

This module provides four modal Gtk3 dialogs that were previously inline
in C<PACUtils.pm>:

=over

=item _wEnterValue($parent, $title_markup, $helper_markup, $default, $visible, $stock_icon)

Single-line entry or combo dropdown. Returns the entered string (or
C<undef> on cancel) in scalar context, or C<($val, $position)> in list
context.

C<$default> may be: a scalar (initial text), an arrayref (combo items),
or a pipe-separated string with at least three pipes (combo items).
C<$visible> defaults to 1; pass 0 for password entry.

=item _wMessage($parent, $markup, $modal, $selectable, $css_class)

Information / warning / error dialog. Auto-detects errors by matching
C</error/i> in C<$markup>. C<$modal> defaults to 1; non-modal mode shows
the dialog and returns immediately.

=item _wConfirm($parent, $markup, $default)

Yes / No question. Returns 1 on Yes, 0 on No or close.

=item _wYesNoCancel($parent, $markup)

Three-way choice. Returns C<'yes'>, C<'no'>, or C<'cancel'>.

=back

If C<$parent> is undef or not a C<Gtk3::Window>, the helpers fall back
to the application's main window or the splash window during early
startup.

=head1 INTERNAL

=over

=item _constrain_action_area($dialog)

Prevents OK/Cancel buttons from stretching across the dialog width.
Used internally by all four helpers.

=back

=head1 SEE ALSO

L<Gtk3::Dialog>, L<Gtk3::MessageDialog>.

=cut
