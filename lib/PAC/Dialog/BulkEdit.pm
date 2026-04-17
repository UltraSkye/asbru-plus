package PAC::Dialog::BulkEdit;

###############################################################################
# PAC::Dialog::BulkEdit — modal "bulk edit" dialog used by tree node
# bulk-rename and config export.
#
# Mechanical extraction of PACMain::_bulkEdit (343 lines). The original
# took \$self as first arg but never used it — the function is a pure
# dialog builder that returns the user's choices.
#
# Returns:  (\\%list, \$rballlevel_active, \$cipher_active?)
# where %list is a hash of { fieldname => { change, match, value, regexp } }.
#
# PACMain retains a wrapper that strips the unused \$self and forwards.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# show($title?, $label?, $groups?, $cipher?) — see legacy doc + POD below.
sub show {
    # $self argument removed in P4/7 — function does not use it
    my $title = shift // "$PACUtils::APPNAME (v$PACUtils::APPVERSION) : Bulk Edit";
    my $label = shift // "Select and change the values you want to modify in the list below.\n<b>Only those checked will be affected.</b>\nFor Regular Expressions, <b>Match pattern</b> will be substituted with <b>New value</b>,\nmuch like Perl's: <b>s/Match pattern/New value/g</b>";
    my $groups = shift // 0;
    my $cipher = shift // 0;
    my %list;
    my %w;

    # Create the 'bulkEdit' dialog window,
    $w{data} = Gtk3::Dialog->new_with_buttons(
        $title,
        undef,
        'modal',
        'gtk-ok' => 'ok',
        'gtk-cancel' => 'cancel'
    );

    $w{data}->signal_connect('delete_event' => sub {
        $w{data}->destroy();
        undef %w;
        return 1;
    });

    # and setup some dialog properties.
    $w{data}->set_border_width(5);
    $w{data}->set_position('center');
    $w{data}->set_icon_from_file($PACMain::APPICON);
    $w{data}->set_resizable(0);
    $w{data}->set_default_response('ok');

    $w{gui}{hboxIconLabel} = Gtk3::Box->new('horizontal', 5);
    $w{data}->get_content_area->pack_start($w{gui}{hboxIconLabel}, 0, 1, 5);

    $w{gui}{imgUP} = Gtk3::Image-> new_from_stock('gtk-edit', 'dialog');
    $w{gui}{hboxIconLabel}->pack_start($w{gui}{imgUP}, 0, 1, 0);

    $w{gui}{lblUP} = Gtk3::Label->new();
    $w{gui}{lblUP}->set_markup($label);
    $w{gui}{hboxIconLabel}->pack_start($w{gui}{lblUP}, 0, 1, 0);

    $w{data}->get_content_area->pack_start(Gtk3::HSeparator->new, 0, 1, 0);

    #$w{gui}{frameAffect} = Gtk3::Frame->new(' There are GROUP(S) in the selection. Apply to: ');
    $w{gui}{frameAffect} = Gtk3::Frame->new();
    my $lblaffect = Gtk3::Label->new();
    $lblaffect->set_markup(' There are <b>GROUP(S)</b> in the selection. Apply to: ');
    $w{gui}{frameAffect}->set_label_widget($lblaffect);
    $w{data}->get_content_area->pack_start($w{gui}{frameAffect}, 0, 1, 0);

    $w{gui}{vboxaffect} = Gtk3::Box->new('vertical', 0);
    $w{gui}{frameAffect}->add($w{gui}{vboxaffect});

    $w{gui}{rb1level} = Gtk3::RadioButton->new_with_label('level affected', "1st level children");
    $w{gui}{vboxaffect}->pack_start($w{gui}{rb1level}, 0, 1, 0);
    $w{gui}{rballlevel} = Gtk3::RadioButton->new_with_label_from_widget($w{gui}{rb1level}, "ALL sub-levels children");
    $w{gui}{vboxaffect}->pack_start($w{gui}{rballlevel}, 0, 1, 0);

    # Create a vbox for the list os elements to bulk-edit
    $w{gui}{vboxlist} = Gtk3::Box->new('vertical', 0);
    $w{data}->get_content_area->pack_start($w{gui}{vboxlist}, 1, 1, 0);

    $w{gui}{framecommon} = Gtk3::Frame->new();
    my $lblcom = Gtk3::Label->new();
    $lblcom->set_markup(' <b><span foreground="orange">COMMON</span></b> entries: ');
    $w{gui}{framecommon}->set_label_widget($lblcom);
    $w{data}->get_content_area->pack_start($w{gui}{framecommon}, 0, 1, 0);

    $w{gui}{vboxcommon} = Gtk3::Box->new('vertical', 0);
    $w{gui}{framecommon}->add($w{gui}{vboxcommon});

    # Build the COMMON elements
    foreach my $key ('title', 'ip', 'port', 'user', 'pass', 'passphrase user', 'passphrase') {
        $w{gui}{"hb$key"} = Gtk3::Box->new('horizontal', 0);
        $w{gui}{vboxcommon}->pack_start($w{gui}{"hb$key"}, 0, 1, 0);

        $w{gui}{"cb$key"} = Gtk3::CheckButton->new("Set '$key': ");
        $w{gui}{"hb$key"}->pack_start($w{gui}{"cb$key"}, 0, 1, 0);
        $w{gui}{"cb$key"}->set('can_focus', 0);

        $w{gui}{"hboxre$key"} = Gtk3::Box->new('horizontal', 0);
        $w{gui}{"hb$key"}->pack_start($w{gui}{"hboxre$key"}, 1, 1, 0);

        $w{gui}{"hboxre$key"}->pack_start(Gtk3::Label->new('change '), 0, 1, 0);

        $w{gui}{"entryWhat$key"} = Gtk3::Entry->new();
        $w{gui}{"hboxre$key"}->pack_start($w{gui}{"entryWhat$key"}, 1, 1, 0);
        $w{gui}{"entryWhat$key"}->set_activates_default(1);
        $w{gui}{"entryWhat$key"}->hide();

        $w{gui}{"hboxre$key"}->pack_start(Gtk3::Label->new(' with '), 0, 1, 0);

        $w{gui}{"entry$key"} = Gtk3::Entry->new();
        $w{gui}{"hb$key"}->pack_start($w{gui}{"entry$key"}, 1, 1, 0);
        $w{gui}{"entry$key"}->set_activates_default(1);

        $w{gui}{"cbRE$key"} = Gtk3::CheckButton->new('RegExp');
        $w{gui}{"hb$key"}->pack_start($w{gui}{"cbRE$key"}, 0, 1, 0);
        $w{gui}{"cbRE$key"}->set('can_focus', 0);
        $w{gui}{"cbRE$key"}->set_active(1);

        $w{gui}{"image$key"} = Gtk3::Image->new_from_stock('gtk-edit', 'button');
        $w{gui}{"hb$key"}->pack_start($w{gui}{"image$key"}, 0, 1, 0);

        # And setup some signals
        $w{gui}{"entry$key"}->signal_connect('changed', sub { $w{gui}{"cb$key"}->set_active($w{gui}{"entry$key"}->get_chars(0, -1) ne ''); });
        $w{gui}{"cb$key"}->signal_connect('toggled', sub { $w{gui}{"image$key"}->set_from_stock(($w{gui}{"cb$key"}->get_active() ? 'gtk-ok' : 'gtk-edit'), 'button'); });
        $w{gui}{"cbRE$key"}->signal_connect('toggled', sub { $w{gui}{"cbRE$key"}->get_active() ? $w{gui}{"hboxre$key"}->show() : $w{gui}{"hboxre$key"}->hide(); });

        # Asign a callback to populate this entry with its own context menu
        $w{gui}{"entry$key"}->signal_connect('button_press_event' => sub {
            my ($widget, $event) = @_;
            return 0 unless $event->button == 3;
            my @menu_items;

            # Populate with global defined variables
            my @global_variables_menu;
            foreach my $var (sort { $a cmp $b } keys %{ $PACMain::FUNCS{_MAIN}{_CFG}{'defaults'}{'global variables'} }) {
                my $val = $PACMain::FUNCS{_MAIN}{_CFG}{'defaults'}{'global variables'}{$var}{'value'};
                push(@global_variables_menu, {
                    label => "<GV:$var> ($val)",
                    code => sub { $w{gui}{"entry$key"}->insert_text("<GV:$var>", -1, $w{gui}{"entry$key"}->get_position()); }
                    });
                }
                push(@menu_items, {
                    label => 'Global variables...',
                    sensitive => scalar(@global_variables_menu),
                    submenu => \@global_variables_menu
                });

                # Populate with environment variables
                my @environment_menu;
                foreach my $key (sort { $a cmp $b } keys %ENV) {
                    # Do not offer Master Password, or any other environment variable with word PRIVATE, TOKEN
                    if ($key =~ /KPXC|PRIVATE|TOKEN/i) {
                        next;
                    }
                    my $value = $ENV{$key};
                    push(@environment_menu, {
                        label => "<ENV:$key>",
                        tooltip => "$key=$value",
                        code => sub { $w{gui}{"entry$key"}->insert_text("<ENV:$key>", -1, $w{gui}{"entry$key"}->get_position()); }
                    });
                }
                push(@menu_items, {
                    label => 'Environment variables...',
                    submenu => \@environment_menu
                });
                # Put an option to ask user for variable substitution
                push(@menu_items, {
                    label => 'Runtime substitution (<ASK:change_by_number>)',
                    code => sub {
                        my $pos = $w{gui}{"entry$key"}->get_property('cursor_position');
                        $w{gui}{"entry$key"}->insert_text("<ASK:change_by_number>", -1, $w{gui}{"entry$key"}->get_position());
                        $w{gui}{"entry$key"}->select_region($pos + 5, $pos + 21);
                    }
                });
                # Populate with <ASK:*|> special string
                push(@menu_items, {
                    label => 'Interactive user choose from list',
                    tooltip => 'User will be prompted to choose a value form a user defined list separated with "|" (pipes without quotes)',
                    code => sub {
                        my $pos = $w{gui}{"entry$key"}->get_property('cursor_position');
                        $w{gui}{"entry$key"}->insert_text('<ASK:descriptive line|opt1|opt2|...|optN>', -1, $w{gui}{"entry$key"}->get_position());
                        $w{gui}{"entry$key"}->select_region($pos + 5, $pos + 40);
                    }
                });
                # Populate with <CMD:*> special string
                push(@menu_items, {
                    label => 'Use a command output as value',
                    tooltip => 'The given command line will be locally executed, and its output (both STDOUT and STDERR) will be used to replace this value',
                    code => sub {
                        my $pos = $w{gui}{"entry$key"}->get_property('cursor_position');
                        $w{gui}{"entry$key"}->insert_text('<CMD:command to launch>', -1, $w{gui}{"entry$key"}->get_position());
                        $w{gui}{"entry$key"}->select_region($pos + 5, $pos + 22);
                    }
                });

                _wPopUpMenu(\@menu_items, $event);

                return 1;
        });
    }

    $w{gui}{frameExpect} = Gtk3::Frame->new();
    my $lblexp = Gtk3::Label->new();
    $lblexp->set_markup(' <b><span foreground="orange">EXPECT</span></b> entries: ');
    $w{gui}{frameExpect}->set_label_widget($lblexp);
    $w{data}->get_content_area->pack_start($w{gui}{frameExpect}, 0, 1, 0);

    $w{gui}{vboxexpect} = Gtk3::Box->new('vertical', 0);
    $w{gui}{frameExpect}->add($w{gui}{vboxexpect});

    # Build the EXPECT elements
    foreach my $key ('expect', 'send') {
        $w{gui}{"hb$key"} = Gtk3::Box->new('horizontal', 0);
        $w{gui}{vboxexpect}->pack_start($w{gui}{"hb$key"}, 0, 1, 0);

        $w{gui}{"cb$key"} = Gtk3::CheckButton->new("Set '$key': ");
        $w{gui}{"hb$key"}->pack_start($w{gui}{"cb$key"}, 0, 1, 0);
        $w{gui}{"cb$key"}->set('can_focus', 0);

        $w{gui}{"hboxre$key"} = Gtk3::Box->new('horizontal', 0);
        $w{gui}{"hb$key"}->pack_start($w{gui}{"hboxre$key"}, 1, 1, 0);

        $w{gui}{"hboxre$key"}->pack_start(Gtk3::Label->new('change '), 0, 1, 0);

        $w{gui}{"entryWhat$key"} = Gtk3::Entry->new();
        $w{gui}{"hboxre$key"}->pack_start($w{gui}{"entryWhat$key"}, 1, 1, 0);
        $w{gui}{"entryWhat$key"}->set_activates_default(1);
        $w{gui}{"entryWhat$key"}->hide();

        $w{gui}{"hboxre$key"}->pack_start(Gtk3::Label->new(' with '), 0, 1, 0);

        $w{gui}{"entry$key"} = Gtk3::Entry->new();
        $w{gui}{"hb$key"}->pack_start($w{gui}{"entry$key"}, 1, 1, 0);
        $w{gui}{"entry$key"}->set_activates_default(1);

        $w{gui}{"cbRE$key"} = Gtk3::CheckButton->new('RegExp');
        $w{gui}{"hb$key"}->pack_start($w{gui}{"cbRE$key"}, 0, 1, 0);
        $w{gui}{"cbRE$key"}->set('can_focus', 0);
        $w{gui}{"cbRE$key"}->set_active(1);

        $w{gui}{"image$key"} = Gtk3::Image->new_from_stock('gtk-edit', 'button');
        $w{gui}{"hb$key"}->pack_start($w{gui}{"image$key"}, 0, 1, 0);

        # And setup some signals
        $w{gui}{"entry$key"}->signal_connect('changed', sub { $w{gui}{"cb$key"}->set_active($w{gui}{"entry$key"}->get_chars(0, -1) ne ''); });
        $w{gui}{"cb$key"}->signal_connect('toggled', sub { $w{gui}{"image$key"}->set_from_stock(($w{gui}{"cb$key"}->get_active() ? 'gtk-ok' : 'gtk-edit'), 'button'); });
        $w{gui}{"cbRE$key"}->signal_connect('toggled', sub { $w{gui}{"cbRE$key"}->get_active() ? $w{gui}{"hboxre$key"}->show() : $w{gui}{"hboxre$key"}->hide(); });

        # Asign a callback to populate this entry with its own context menu
        $w{gui}{"entry$key"}->signal_connect('button_press_event' => sub {
            my ($widget, $event) = @_;

            return 0 unless $event->button == 3;

            my @menu_items;

            # Populate with global defined variables
            my @global_variables_menu;
            foreach my $var (sort { $a cmp $b } keys %{ $PACMain::FUNCS{_MAIN}{_CFG}{'defaults'}{'global variables'} }) {
                my $val = $PACMain::FUNCS{_MAIN}{_CFG}{'defaults'}{'global variables'}{$var}{'value'};
                push(@global_variables_menu, {
                    label => "<GV:$var> ($val)",
                    code => sub { $w{gui}{"entry$key"}->insert_text("<GV:$var>", -1, $w{gui}{"entry$key"}->get_position()); }
                });
            }
            push(@menu_items, {
                label => 'Global variables...',
                sensitive => scalar(@global_variables_menu),
                submenu => \@global_variables_menu
            });
            # Populate with environment variables
            my @environment_menu;
            foreach my $key (sort { $a cmp $b } keys %ENV) {
                # Do not offer Master Password, or any other environment variable with word PRIVATE, TOKEN
                if ($key =~ /KPXC|PRIVATE|TOKEN/i) {
                    next;
                }
                my $value = $ENV{$key};
                push(@environment_menu, {
                    label => "<ENV:$key>",
                    tooltip => "$key=$value",
                    code => sub { $w{gui}{"entry$key"}->insert_text("<ENV:$key>", -1, $w{gui}{"entry$key"}->get_position()); }
                });
            }
            push(@menu_items, {
                label => 'Environment variables...',
                submenu => \@environment_menu
            });

            # Put an option to ask user for variable substitution
            push(@menu_items, {
                label => 'Runtime substitution (<ASK:change_by_number>)',
                code => sub {
                    my $pos = $w{gui}{"entry$key"}->get_property('cursor_position');
                    $w{gui}{"entry$key"}->insert_text("<ASK:change_by_number>", -1, $w{gui}{"entry$key"}->get_position());
                    $w{gui}{"entry$key"}->select_region($pos + 5, $pos + 21);
                }
            });

            # Populate with <ASK:*|> special string
            push(@menu_items, {
                label => 'Interactive user choose from list',
                tooltip => 'User will be prompted to choose a value form a user defined list separated with "|" (pipes without quotes)',
                code => sub {
                    my $pos = $w{gui}{"entry$key"}->get_property('cursor_position');
                    $w{gui}{"entry$key"}->insert_text('<ASK:descriptive line|opt1|opt2|...|optN>', -1, $w{gui}{"entry$key"}->get_position());
                    $w{gui}{"entry$key"}->select_region($pos + 5, $pos + 40);
                }
            });

            # Populate with <CMD:*> special string
            push(@menu_items, {
                label => 'Use a command output as value',
                tooltip => 'The given command line will be locally executed, and its output (both STDOUT and STDERR) will be used to replace this value',
                code => sub {
                    my $pos = $w{gui}{"entry$key"}->get_property('cursor_position');
                    $w{gui}{"entry$key"}->insert_text('<CMD:command to launch>', -1, $w{gui}{"entry$key"}->get_position());
                    $w{gui}{"entry$key"}->select_region($pos + 5, $pos + 22);
                }
            });

            _wPopUpMenu(\@menu_items, $event);

            return 1;
        });
    }

    $w{gui}{cbDelHidden} = Gtk3::CheckButton->new("Remove strings checked 'Hide' from the 'Expect' configuration");
    $w{gui}{vboxexpect}->pack_start($w{gui}{cbDelHidden}, 0, 1, 0);
    $w{gui}{cbDelHidden}->set_tooltip_text("If checked, every field marked as 'hide' (for example, under 'Expect' TAB) will be erased.\nThis overrides any value set for both 'pass' and 'passphrase'");

    if ($cipher) {
        $w{gui}{cbCipher} = Gtk3::CheckButton->new("Cipher secure strings");
        $w{data}->get_content_area->pack_start($w{gui}{cbCipher}, 0, 1, 0);
        $w{gui}{cbCipher}->set_tooltip_text("If checked, every passord-like and field marked as 'hide' (for example, under 'Expect' TAB) will be ciphered.\nThis may cause incompatibilities when importing from a server other than this.");
    }

    $w{data}->get_content_area->pack_start(Gtk3::HSeparator->new, 0, 1, 0);

    $w{data}->show_all();
    $groups or $w{gui}{frameAffect}->hide();
    if ($w{data}->run ne 'ok') {
        defined $w{data} and $w{data}->destroy();
        return undef;
    }

    # Get the GUI data
    foreach my $key ('title', 'ip', 'port', 'user', 'pass', 'passphrase user', 'passphrase', 'expect', 'send') {
        my $tkey = $key;
        ($key eq 'expect') and $tkey = 'EXPECT:' . $key;
        ($key eq 'send')  and $tkey = 'EXPECT:' . $key;
        $list{$tkey}{change} = $w{gui}{"cb$key"}->get_active();
        $list{$tkey}{match} = $w{gui}{"entryWhat$key"}->get_chars(0, -1);
        $list{$tkey}{value} = $w{gui}{"entry$key"}->get_chars(0, -1);
        $list{$tkey}{regexp} = $w{gui}{"cbRE$key"}->get_active();
    }
    $list{'__delete_hidden_fields__'} = $w{gui}{cbDelHidden}->get_active();

    $w{data}->destroy();
    return \%list, $w{gui}{rballlevel}->get_active(), $cipher ? $w{gui}{cbCipher}->get_active() : undef;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Dialog::BulkEdit — modal "bulk edit" dialog

=head1 SYNOPSIS

    use PAC::Dialog::BulkEdit;

    my ($list, $level, $cipher) = PAC::Dialog::BulkEdit::show(
        'Bulk Edit',
        'Select fields to change...',
        $has_groups ? 1 : 0,
        $needs_cipher_choice ? 'ask for cipher' : 0,
    );
    return unless defined $list;
    # $list  = { fieldname => { change, match, value, regexp }, ... }
    # $level = 0/1/2 (which radio button is active)
    # $cipher = 0/1 (only if "ask for cipher" was passed)

=head1 DESCRIPTION

The bulk-edit dialog presents a checklist of connection fields
(title, ip, port, user, pass, passphrase user, passphrase, expect,
send) with two columns: a "Match pattern" and a "New value". Each
row has a check-box (apply or skip) and a regex toggle.

Used by the tree-node bulk-edit (PACMain) and by config export
(also PACMain) to pick fields to modify before applying changes.

Mechanical extraction from C<PACMain::_bulkEdit>. PACMain retains
a wrapper.

=head1 PUBLIC API

=over

=item show($title?, $label?, $groups?, $cipher?)

Builds and runs the modal dialog. Returns C<(undef)> on cancel, or
the C<(\\%list, \$rballlevel, \$cipher_choice?)> tuple on OK.

C<\$groups> truthy enables the "GROUP(S) in selection" radio bar.
C<\$cipher> truthy enables the "encrypt sensitive fields" checkbox
(used during config export).

=back

=head1 SEE ALSO

L<PACMain>, L<PAC::Dialog>, L<PAC::Subst/subst_cfg>.

=cut
