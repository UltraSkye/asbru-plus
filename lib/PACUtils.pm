package PACUtils;

###############################################################################
# This file is part of Ásbrú Connection Manager
#
# Copyright (C) 2017-2022 Ásbrú Connection Manager team (https://asbru-cm.net)
# Copyright (C) 2010-2016 David Torrejón Vaquerizas
#
# Ásbrú Connection Manager is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ásbrú Connection Manager is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with Ásbrú Connection Manager.
# If not, see <http://www.gnu.org/licenses/gpl-3.0.html>.
###############################################################################
use utf8;
binmode STDOUT,':utf8';
binmode STDERR,':utf8';

$|++;

###################################################################
# Import Modules

# Standard
use strict;
use warnings;

use FindBin qw ($RealBin $Bin $Script);
use POSIX qw (strftime);
use Storable qw (freeze thaw dclone);
use Crypt::CBC;
use Socket;
use Socket6;
use Sys::Hostname;
use Net::ARP;
use Net::Ping;
use YAML;
use UUID::Tiny ':std';
use Encode;
use DynaLoader; # Required for PACTerminal and PACShell modules

# GTK
use Gtk3 '-init';
use Gtk3::Gdk;
use Wnck; # for the windows list

use PAC::Dialog;     # _wEnterValue / _wMessage / _wConfirm / _wYesNoCancel impls
use PAC::WakeOnLan;  # _wakeOnLan impl + magic_packet builder

# Module's functions/variables to export
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
require Exporter;
@ISA        = qw(Exporter);
@EXPORT     = qw(
    _
    __
    _screenshot
    _scale
    _pixBufFromFile
    _getMethods
    _registerPACIcons
    _sortTreeData
    _menuFavouriteConnections
    _menuAvailableConnections
    _menuClusterConnections
    _wEnterValue
    _wAddRenameNode
    _wPopUpMenu
    _wConfirm
    _wMessage
    _wProgress
    _wYesNoCancel
    _wSetPACPassword
    _wPrePostEntry
    _wExecEntry
    _cfgCheckMigrationV3
    _cfgSanityCheck
    _cfgGetTmpSessions
    _cfgAddSessions
    _updateSSHToIPv6
    _cipherCFG
    _decipherCFG
    _substCFG
    _subst
    _wakeOnLan
    _deleteOldestSessionLog
    _replaceBadChars
    _removeEscapeSeqs
    _purgeUnusedOrMissingScreenshots
    _purgeUnusedScreenshots
    _purgeMissingScreenshots
    _splash
    _getXWindowsList
    _checkREADME
    _getEncodings
    _makeDesktopFile
    _updateWidgetColor
    _getSelectedRows
    _vteFeed
    _vteFeedChild
    _vteFeedChildBinary
    _createBanner
    _copyPass
    _appName
    _setWindowPaintable
    _setDefaultRGBA
    _doShellEscape
    _initMasterCipher
    _isMasterPasswordActive
    _createMasterVerifier
    _verifyMasterPassword
    _migrateCipherCFG
    _decrypt_hex_compat
); # Functions/variables to export

@EXPORT_OK  = qw();

# END: Import Modules
###################################################################

###################################################################
# Define GLOBAL CLASS variables

our $APPNAME = 'Ásbrú Plus';
our $APPVERSION = '6.5.0';
our $DEBUG_LEVEL = 1;
our $ARCH = '';
my $_UNAME_ENV = $ENV{'ASBRU_ENV_FOR_EXTERNAL'} // '';
my $ARCH_TMP = `$_UNAME_ENV /bin/uname -m 2>&1`;
if ($ARCH_TMP =~ /x86_64/gio) {
    $ARCH = 64;
} elsif ($ARCH_TMP =~ /ppc64/gio) {
    $ARCH = 'PPC64';
} elsif ($ARCH_TMP =~ /armv7l/gio) {
    $ARCH = 'ARMV7L';
} elsif ($ARCH_TMP =~ /arm/gio) {
    $ARCH = 'ARM';
} else {
    $ARCH = 32;
}
# RES_DIR / THEME_DIR were 'my' lexicals; promoted to 'our' so extracted
# modules (PAC::Theme::Icons, PAC::Methods) can read them as
# $PACUtils::RES_DIR / $PACUtils::THEME_DIR. Mutation of $THEME_DIR by
# theme switch still happens here.
our $RES_DIR = "$RealBin/res";
our $THEME_DIR = "$RES_DIR/themes/default";
my $SPLASH_IMG = "$RES_DIR/asbru-logo-400.png";
my $CFG_DIR = $ENV{"ASBRU_CFG"} // '';
my $CFG_FILE = $CFG_DIR ne '' ? "$CFG_DIR/asbru.yml" : '';
# Crypto state lives in PAC::Crypto::Cipher; PACUtils keeps an `our $CIPHER`
# alias so the 50+ legacy `$CIPHER->encrypt_hex / $PACUtils::CIPHER->...`
# callsites continue to work unchanged. Same Crypt::CBC instance — mutations
# from set_master() are visible everywhere.
require PAC::Crypto::Cipher;
PAC::Crypto::Cipher::init({ cfg_dir => $CFG_DIR });
our $CIPHER = PAC::Crypto::Cipher::active();

sub _initMasterCipher {
    my $master_pass = shift;
    $CIPHER = PAC::Crypto::Cipher::set_master($master_pass);
    return $CIPHER;
}

sub _isMasterPasswordActive { return PAC::Crypto::Cipher::is_master_active(); }

# Master-password verifier flow lives in PAC::Vault. PACUtils keeps
# proxies so the existing _createMasterVerifier / _verifyMasterPassword
# callsites in PACMain (master-password setup and prompt) work unchanged.
require PAC::Vault;
sub _createMasterVerifier { goto &PAC::Vault::_create_verifier; }
sub _verifyMasterPassword { goto &PAC::Vault::_verify; }

# Re-encrypt all password fields from old cipher to new cipher
sub _migrateCipherCFG {
    my ($cfg, $old_cipher, $new_cipher) = @_;

    # Helper to re-encrypt a single value
    my $reencrypt = sub {
        my $hex = shift;
        return '' unless defined $hex && $hex ne '';
        my $plain;
        eval { $plain = $old_cipher->decrypt_hex($hex); };
        return $hex if $@;  # Can't decrypt — leave as-is
        return $new_cipher->encrypt_hex($plain);
    };

    # Global variables
    foreach my $var (keys %{$$cfg{'defaults'}{'global variables'} // {}}) {
        if (($$cfg{'defaults'}{'global variables'}{$var}{'hidden'} // '') eq '1') {
            $$cfg{'defaults'}{'global variables'}{$var}{'value'} = $reencrypt->($$cfg{'defaults'}{'global variables'}{$var}{'value'});
        }
    }
    # KeePass password
    if (defined $$cfg{'defaults'}{'keepass'}) {
        $$cfg{'defaults'}{'keepass'}{'password'} = $reencrypt->($$cfg{'defaults'}{'keepass'}{'password'});
    }
    # Sudo password
    $$cfg{'defaults'}{'sudo password'} = $reencrypt->($$cfg{'defaults'}{'sudo password'}) if defined $$cfg{'defaults'}{'sudo password'};
    # GUI password
    $$cfg{'defaults'}{'gui password'} = $reencrypt->($$cfg{'defaults'}{'gui password'}) if defined $$cfg{'defaults'}{'gui password'};

    # Per-connection passwords
    foreach my $uuid (keys %{$$cfg{'environments'} // {}}) {
        next if $uuid =~ /^HASH/;
        next if $$cfg{'environments'}{$uuid}{'_is_group'};

        $$cfg{'environments'}{$uuid}{'pass'} = $reencrypt->($$cfg{'environments'}{$uuid}{'pass'}) if defined $$cfg{'environments'}{$uuid}{'pass'};
        $$cfg{'environments'}{$uuid}{'passphrase'} = $reencrypt->($$cfg{'environments'}{$uuid}{'passphrase'}) if defined $$cfg{'environments'}{$uuid}{'passphrase'};

        foreach my $hash (@{$$cfg{'environments'}{$uuid}{'expect'} // []}) {
            if (($$hash{'hidden'} // '') eq '1') {
                $$hash{'send'} = $reencrypt->($$hash{'send'});
            }
        }
        foreach my $hash (@{$$cfg{'environments'}{$uuid}{'variables'} // []}) {
            if (($$hash{'hide'} // '') eq '1') {
                $$hash{'txt'} = $reencrypt->($$hash{'txt'});
            }
        }
    }
    return 1;
}

# Backward-compat alias for the legacy decrypt-with-fallback helper.
# Implementation now lives in PAC::Crypto::Cipher::decrypt_hex which tries
# the active cipher, then legacy AES, then legacy Blowfish.
sub _decrypt_hex_compat { goto &PAC::Crypto::Cipher::decrypt_hex; }

my %WINDOWSPLASH;
my %WINDOWPROGRESS;
my $WIDGET_POPUP;
my ($R,$G,$B,$A);

our @DONATORS_LIST = (
    'Angelo Maria Lambiasi',
    'TWEB Inc',
    'Jeff Bakst',
    'Sebastian Treu',
    "Brian's Consultant Services",
    'Cheah CH',
    'Joseph Whipple',
    'Felix Brack',
    'Kalmykov Alexander',
    'Paul Verreth',
    'Iftimie Catalin Panaite',
    'Andre Geißler',
    'Arend de Boer',
    'Taylor Finklea',
    'Egbert Gerber',
    'Гусаров Андрей',
    'Carlos Bragatto',
    'Nicklas Börjesson',
    'Peter Taylor',
    'Javier Martin Garcia-Asenjo',
    'Helmut Kleinhans',
    'Richard Kozel',
    'Timo Büttner',
    'Max Maskevich',
    '1one - 18mind',
    'von Karman Institute',
    'Julian Thomas Bourne',
    'iPERFEX',
    'Joaquín Ferrero San Pedro',
    'Yan Lebedev ',
    'Florian Jerusalem',
    'Brendan Bell',
    'Microflow Software SA De CB',
    'Giuseppe Massimiani',
    'Рукавков Никита',
    'Miguel Rodriguez Vazquez',
    'Voronkov Vladislav',
    'Murathan Bostanci',
    'Adrian King',
    'Sebastian Treu',
    'Voronkov Vladislav',
    'Dejan Korent',
    'Diego Vasquez',
    'Christoph Korn',
    'Victor Demonchy',
    'Ilir Pruthi',
    'Robson Ramaldes',
    'justine cattiaux',
    'Ralph Hübner',
    'Kalin Ivanov',
    'Nikolay Penev',
    'panagiotis palias',
    'Lomakova Anastasia',
    'Andre M Saunite',
    'Jason Cyr',
    'Andreas Diesner',
    'Liam Ward',
    'Andrei Padshyvalau',
    'Gaston Martini',
    'Host Revenda Ltda',
    'Otto Schakenbos',
    'Fernando Moreira',
    'Don Jacobs'
);
our @PACDESKTOP = (
    '[Desktop Entry]',
    'Name=Ásbrú Plus',
    'Comment=A user interface that helps organizing remote terminal sessions and automating repetitive tasks',
    'Terminal=false',
    'Icon=pac',
    'Type=Application',
    'Exec=env GDK_BACKEND=x11 /usr/bin/asbru-cm --no-splash',
    'StartupNotify=false',
    'Name[en_US]=Ásbrú Plus',
    'Comment[en_US]=A user interface that helps organizing remote terminal sessions and automating repetitive tasks',
    'Categories=Applications;Network;',
    'X-GNOME-Autostart-enabled=true',
);

# Default configuration on application first startup
our $DEFAULT_COMMAND_PROMPT = '(([#%:>~\$\] ])(?!\g{-1})){3,4}|(\w[@\/]\w|sftp).*?[#%>~\$\]]|([\w\-\.]+)[%>\$\]]( |\033)|^[#%\$>\:\]~] *$';
our $DEFAULT_USERNAME_PROMPT = '([lL]ogin|[uU]suario|([uU]ser-?)*[nN]ame.*|[uU]ser)\s*:\s*$';
our $DEFAULT_PASSWORD_PROMPT = '([pP]ass|[pP]ass[wW]or[dt](\s+for\s+|\w+@[\w\-\.]+)*|[cC]ontrase.a|Enter passphrase for key \'.+\')\s*:\s*$';
our $DEFAULT_HOSTKEYCHANGED_PROMPT = '^.+ontinue connecting \(([^/]+)\/([^/]+)(?:[^)]+)?\)\?\s*$';
our $DEFAULT_PRESSANYKEY_PROMPT = '.*(any key to continue|tecla para continuar).*';
our $DEFAULT_REMOTEHOSTCHANGED_PROMPT = '.*ffending .*key in (.+?)\:(\d+).*';

# END: Define GLOBAL CLASS variables
###################################################################

######################################################
# START: Private functions definitions

sub _ {
    return shift->{_GLADE}->get_object(shift);
};

sub __ {
    my $str = shift // '';

    $str =~ s/\&/&amp;/go;
    $str =~ s/\|/&#124;/go;
    $str =~ s/\'/&apos;/go;
    $str =~ s/\"/&quot;/go;
    $str =~ s/</&lt;/go;
    $str =~ s/>/&gt;/go;

    return $str;
};

sub __text {
    my $str = shift // '';

    while ($str =~ s/&amp;/\&/g) {}
    $str =~ s/&#124;/\|/go;
    $str =~ s/&apos;/\'/go;
    $str =~ s/&quot;/\"/go;
    $str =~ s/&lt;/</go;
    $str =~ s/&gt;/>/go;

    return $str;
};

sub _splash {
    my $show = shift;
    my $txt = shift // "<b>Starting $APPNAME (v$APPVERSION)...</b>";
    my $partial = shift // 0;
    my $total = shift // 1;

    if ($PACMain::_NO_SPLASH) {
        return 1;
    }

    if (!defined $WINDOWSPLASH{_GUI}) {
        $WINDOWSPLASH{_GUI} = Gtk3::Window->new();
        $WINDOWSPLASH{_GUI}->set_type_hint('splashscreen');
        $WINDOWSPLASH{_GUI}->set_position('center');
        $WINDOWSPLASH{_GUI}->set_keep_above(1);
        $WINDOWSPLASH{_GUI}->get_style_context->add_class('asbru-splash');

        $WINDOWSPLASH{_VBOX} = Gtk3::Box->new('vertical', 8);
        $WINDOWSPLASH{_VBOX}->set_border_width(12);
        $WINDOWSPLASH{_GUI}->add($WINDOWSPLASH{_VBOX});

        $WINDOWSPLASH{_IMG} = Gtk3::Image->new_from_file($SPLASH_IMG);
        $WINDOWSPLASH{_VBOX}->pack_start($WINDOWSPLASH{_IMG}, 1, 1, 0);

        $WINDOWSPLASH{_LBL} = Gtk3::ProgressBar->new();
        $WINDOWSPLASH{_VBOX}->pack_start($WINDOWSPLASH{_LBL}, 1, 1, 5);
    }

    $WINDOWSPLASH{_LBL}->set_show_text(1);
    $WINDOWSPLASH{_LBL}->set_text($txt);
    $WINDOWSPLASH{_LBL}->set_fraction($partial / $total);

    if ($show) {
        $WINDOWSPLASH{_GUI}->show_all();
        $WINDOWSPLASH{_GUI}->present();
        while (Gtk3::events_pending) {
            Gtk3::main_iteration();
        }
    } else {
        $WINDOWSPLASH{_GUI}->hide();
        $WINDOWSPLASH{_GUI}->destroy();
    }

    return 1;
}

sub _screenshot {
    my $widget = shift;
    my $file = shift;

    my $gdkpixbuf = Gtk3::Gdk::pixbuf_get_from_window($widget->get_window, $widget->get_allocation->{'x'}, $widget->get_allocation->{'y'}, $widget->get_allocation->{'width'}, $widget->get_allocation->{'height'});

    return defined $file ? $gdkpixbuf->save($file, 'png') : $gdkpixbuf;
}

# TODO: This should validate for file existence, eval generates errors an warnings in verbose mode
sub _scale {
    my $file = shift;
    my $w = shift;
    my $h = shift;
    my $ratio = shift // '';

    my $gdkpixbuf;
    eval {
        $gdkpixbuf = ref($file) ? $file : Gtk3::Gdk::Pixbuf->new_from_file($file)
    };
    if ($@) {
        print STDERR "WARN: Error while loading pixBuf from file '$file': $@";
        return 0;
    }

    if ($ratio && (($gdkpixbuf->get_width > $w) || ($gdkpixbuf->get_height > $h))) {
        if ($gdkpixbuf->get_width > $gdkpixbuf->get_height) {
            $h = int(($w * $gdkpixbuf->get_height) / $gdkpixbuf->get_width);
        } elsif ($gdkpixbuf->get_height >= $gdkpixbuf->get_width) {
            $w = int(($h * $gdkpixbuf->get_width) / $gdkpixbuf->get_height);
        }
    }

    return $gdkpixbuf->scale_simple($w, $h, 'GDK_INTERP_HYPER');
}

# TODO: This should validate for file existence, eval generates errors an warnings in verbose mode
sub _pixBufFromFile {
    my $file = shift;

    my $gdkpixbuf;
    eval {
        $gdkpixbuf = Gtk3::Gdk::Pixbuf->new_from_file($file)
    };

    if ($@) {
        print STDERR "WARN: Error while loading pixBuf from file '$file': $@";
        return 0;
    }
    return $gdkpixbuf;
}

# Method registry lives in PAC::Methods. PACUtils keeps a 1-line proxy.
require PAC::Methods;
sub _getMethods { goto &PAC::Methods::registry; }

# Icon registration lives in PAC::Theme::Icons. PACUtils proxy.
require PAC::Theme::Icons;
sub _registerPACIcons { goto &PAC::Theme::Icons::register; }

sub _sortTreeData {
    my ($a_name,$b_name,$a_is_group,$b_is_group);
    my $cfg = $PACMain::FUNCS{_MAIN}{_CFG};
    my $groups_1st = $$cfg{'defaults'}{'sort groups first'} // 1;

    $a_name = lc($$a{'value'}[1]);
    $a_name =~ s/<.+>(.+?)<\/.+>/$1/go;
    $b_name = lc($$b{'value'}[1]);
    $b_name =~ s/<.+>(.+?)<\/.+>/$1/go;
    $a_is_group = $$cfg{'environments'}{$$a{'value'}[2]}{'_is_group'};
    $b_is_group = $$cfg{'environments'}{$$b{'value'}[2]}{'_is_group'};

    if ($groups_1st) {
        if ($a_is_group && ! $b_is_group) {
            return -1;
        }
        if (! $a_is_group && $b_is_group) {
            return 1;
        }
        if (! $a_is_group && ! $b_is_group) {
            return $a_name cmp  $b_name;
        }
        if ($a_is_group && $b_is_group) {
            return $a_name cmp  $b_name;
        }
    } else {
        return $a_name cmp $b_name;
    }
}

# TODO : displayed name should include group
sub _menuFavouriteConnections { goto &PAC::Menu::favourite_connections; }

sub _menuClusterConnections { goto &PAC::Menu::cluster_connections; }

sub _menuAvailableConnections { goto &PAC::Menu::available_connections; }

sub _wEnterValue { goto &PAC::Dialog::_wEnterValue; }

sub _wAddRenameNode { goto &PAC::Dialog::_wAddRenameNode; }

sub _wPopUpMenu {
    my $mref = shift;
    our $event = shift;
    my $below = shift // '0';
    my $ref = shift // '0';

    if (defined $WIDGET_POPUP && $WIDGET_POPUP->get_visible()) {
        return 1;
    }

    our $jari = -1;
    my @array;
    my %props;

    my $xml = "<ui>\n<popup name='Menu' accelerators='true'>\n";
    $xml .= _buildMenuData(\@array, $mref, \%props);
    $xml .= "</popup>\n</ui>";

    my $actions = Gtk3::ActionGroup->new('Actions');
    $actions->add_actions(\@array, undef);

    my $ui = Gtk3::UIManager->new();
    $ui->set_add_tearoffs(1);
    $ui->insert_action_group($actions, 0);

    $ui->add_ui_from_string($xml);

    foreach my $path (keys %props) {
        foreach my $prop (keys %{$props{$path}}) {
            $ui->get_widget('/Menu' . $path)->set($prop, $props{$path}{$prop});
        }
    }

    $WIDGET_POPUP = $ui->get_widget('/Menu');
    $WIDGET_POPUP->show_all();
    if ($ref) {
        return $WIDGET_POPUP;
    }

    if (defined $event) {
        $WIDGET_POPUP->popup(undef, undef, ($below ? \&_pos : undef), undef, $event->button, $event->time);
    } else {
        $WIDGET_POPUP->popup(undef, undef, undef, undef, 0, 0);
    }

    sub _buildMenuData {
        my $menu_array = shift;
        my $mref = shift;
        my $props = shift;
        my $path = shift // '';

        my $xml = '';

        for my $m (@{$mref}) {
            my $label = $$m{label} // '';
            my $sensitive = $$m{sensitive} // 1;
            my $tooltip = $$m{tooltip} // '';

            if (!$$m{shortcut}) {
                $$m{shortcut} = '';
            }

            my $label_orig =  __text($label);
            $label =~ s/\//__backslash__/go;
            my $pre_path = $path;

            ++$jari;
            if ($$m{separator}) {
                $xml .= "<separator/>\n";
            } elsif ($$m{submenu}) {
                $xml .= qq|<menu action="MenuParent@{[__($label)]}:$jari:EndMenuParent">\n|;
                push(@{$menu_array}, ["MenuParent$label:$jari:EndMenuParent", $$m{stockicon}, $label_orig]);

                $path .= "/MenuParent$label:$jari:EndMenuParent";
                $$props{$path}{sensitive} = $sensitive;
                $$props{$path}{tooltip_text} = $tooltip;
                $$props{$path}{use_underline} = 0;

                $xml .= _buildMenuData($menu_array, $$m{submenu}, $props, $path);
                $xml .= "</menu>\n";
            } else {
                $xml .= qq|<menuitem action="MenuItem@{[__($label)]}:$jari:EndMenuItem"/>\n|;
                push(@{$menu_array}, [
                    "MenuItem$label:$jari:EndMenuItem",
                    $$m{stockicon},
                    $label_orig, $$m{shortcut},
                    $$m{tooltip},
                    sub {&{$$m{code}};}
                ]);

                $path .= "/MenuItem$label:$jari:EndMenuItem";
                $$props{$path}{sensitive} = $sensitive;
                $$props{$path}{tooltip_text} = $tooltip;
                $$props{$path}{use_underline} = 0;
            }

            $path = $pre_path;
        }

        return $xml;
    }

    sub _pos {
        my $h = $_[0]->size_request->height;
        my $ymax = $event->get_screen()->get_height();
        my ($x, $y) = $event->window->get_origin();
        my $dy = $event->window->get_height();

        # Over the event widget
        if ($dy + $y + $h > $ymax) {
            $y -= $h;
            if ($y < 0) {
                $y = 0;
            }
        # Below the event widget
        } else {
            $y += $dy;
        }

        return $x, $y;
    }
 }

sub _wMessage { goto &PAC::Dialog::_wMessage; }

sub _wProgress { goto &PAC::Dialog::_wProgress; }

sub _wConfirm { goto &PAC::Dialog::_wConfirm; }

sub _wYesNoCancel { goto &PAC::Dialog::_wYesNoCancel; }

sub _wSetPACPassword { goto &PAC::Dialog::_wSetPACPassword; }

# Legacy config schema enforcement lives in PAC::Config::SanityCheck.
require PAC::Config::SanityCheck;
sub _cfgSanityCheck { goto &PAC::Config::SanityCheck::run; }

sub _cfgGetTmpSessions {
    my $cfg = shift;
    my %tmp;

    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        if ($uuid =~ /^(HASH|_tmp_|pacshell_PID)/go) {
            $tmp{$uuid} = $$cfg{'environments'}{$uuid};
        }
    }

    return %tmp;
}

sub _cfgAddSessions {
    my $cfg = shift;
    my $tmp = shift;

    foreach my $uuid (keys %{$tmp}) {
        $$cfg{'environments'}{$uuid} = $tmp->{$uuid};
    }
}

sub _updateSSHToIPv6 {
    my $cmd_line = shift // '';

    my %hash;
    $hash{sshVersion} = 'any';
    $hash{ipVersion} = 'any';
    $hash{forwardX} = 1;
    $hash{useCompression} = 0;
    $hash{allowRemoteConnection} = 0;
    $hash{forwardAgent} = 0;
    $hash{otherOptions} = '';
    @{$hash{dynamicForward}} = ();
    @{$hash{forwardPort}} = ();
    @{$hash{remotePort}} = ();

    while ($cmd_line =~ s/\s*\-o\s+\"(.+)\"//go) {
        $hash{otherOptions} .= qq| -o "$1"|;
    }
    my @opts = split(/\s+-/, $cmd_line);
    foreach my $opt (@opts) {
        if ($opt eq '') {
            next;
        }
        $opt =~ s/\s+$//go;

        if ($opt =~ /^([1|2]$)/go) {
            $hash{sshVersion} = $1;
        }
        if ($opt =~ /^([4|6]$)/go) {
            $hash{ipVersion} = $1;
        }
        if ($opt =~ /^([X|x]$)/go) {
            $hash{forwardX} = $1 eq 'X' ? 1 : 0;
        }
        if ($opt eq 'C') {
            $hash{useCompression} = 1;
        }
        if ($opt eq 'g') {
            $hash{allowRemoteConnection} = 1;
        }
        if ($opt eq 'A') {
            $hash{forwardAgent} = 1;
        }

        while ($opt =~ /^D\s+([^\s]*:)*(\d+)$/go) {
            my %dynamic;
            ($dynamic{dynamicIP}, $dynamic{dynamicPort}) = ($1 // '', $2);
            $dynamic{dynamicIP} =~ s/:+//go;
            push(@{$hash{dynamicForward}}, \%dynamic);
        }
        while ($opt =~ /^L\s+(.+)$/go) {
            my @fields = split(':', $1);
            my %forward;
            $forward{remotePort} = pop(@fields);
            $forward{remoteIP} = pop(@fields);
            $forward{localPort} = pop(@fields);
            $forward{localIP} = pop(@fields) // '';
            push(@{$hash{forwardPort}}, \%forward);
        }
        while ($opt =~ /^R\s+(.+)$/go) {
            my @fields = split(':', $1);
            my %remote;
            $remote{remotePort} = pop(@fields);
            $remote{remoteIP} = pop(@fields);
            $remote{localPort} = pop(@fields);
            $remote{localIP} = pop(@fields) // '';
            push(@{$hash{remotePort}}, \%remote);
        }
    }

    my $txt = '';

    if ($hash{sshVersion} ne 'any') {
        $txt .= " -$hash{sshVersion}";
    }
    if ($hash{ipVersion} ne 'any') {
        $txt .= " -$hash{ipVersion}";
    }
    $txt .= ' -' . ($hash{forwardX} ? 'X' : 'x');
    if ($hash{useCompression}) {
        $txt .= ' -C';
    }
    if ($hash{allowRemoteConnection}) {
        $txt .= ' -g';
    }
    if ($hash{forwardAgent}) {
        $txt .= ' -A';
    }
    if ($hash{otherOptions}) {
        $txt .= " $hash{otherOptions}";
    }
    foreach my $dynamic (@{$hash{dynamicForward}}) {
        $txt .= ' -D ' . ($$dynamic{dynamicIP} ? "$$dynamic{dynamicIP}/" : '') . $$dynamic{dynamicPort};
    }
    foreach my $forward (@{$hash{forwardPort}}) {
        $txt .= ' -L ' . ($$forward{localIP} ? "$$forward{localIP}/" : '') . $$forward{localPort} . '/' . $$forward{remoteIP} . '/' . $$forward{remotePort};
    }
    foreach my $remote (@{$hash{remotePort}}) {
        $txt .= ' -R ' . ($$remote{localIP} ? "$$remote{localIP}/" : '') . $$remote{localPort} . '/' . $$remote{remoteIP} . '/' . $$remote{remotePort};
    }

    return $txt;
}

sub _cipherCFG {
    my $cfg = shift;

    foreach my $var (keys %{$$cfg{'defaults'}{'global variables'}}) {
        if ($$cfg{'defaults'}{'global variables'}{$var}{'hidden'} eq '1') {
            $$cfg{'defaults'}{'global variables'}{$var}{'value'} = $CIPHER->encrypt_hex(encode('UTF-8',$$cfg{'defaults'}{'global variables'}{$var}{'value'}));
        }
    }
    if (defined $$cfg{'defaults'}{'keepass'}) {
        $$cfg{'defaults'}{'keepass'}{'password'} = $CIPHER->encrypt_hex(encode('UTF-8',$$cfg{'defaults'}{'keepass'}{'password'}));
    }
    $$cfg{'defaults'}{'sudo password'} = $CIPHER->encrypt_hex(encode('UTF-8',$$cfg{'defaults'}{'sudo password'}));

    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        if ($uuid =~ /^HASH/go) {
            delete $$cfg{'environments'}{$uuid};
            next
        }
        elsif ($$cfg{'environments'}{$uuid}{'_is_group'}) {
            delete $$cfg{'environments'}{$uuid}{'pass'};
            next;
        }
        $$cfg{'environments'}{$uuid}{'pass'} = $CIPHER->encrypt_hex(encode('UTF-8',$$cfg{'environments'}{$uuid}{'pass'}));
        $$cfg{'environments'}{$uuid}{'passphrase'} = $CIPHER->encrypt_hex(encode('UTF-8',$$cfg{'environments'}{$uuid}{'passphrase'}));

        foreach my $hash (@{$$cfg{'environments'}{$uuid}{'expect'}}) {
            if ($$hash{'hidden'} eq '1') {
                $$hash{'send'} = $CIPHER->encrypt_hex(encode('UTF-8',$$hash{'send'}));
            }
        }

        foreach my $hash (@{$$cfg{'environments'}{$uuid}{'variables'}}) {
            if ($$hash{'hide'} eq '1') {
                $$hash{'txt'} = $CIPHER->encrypt_hex(encode('UTF-8',$$hash{'txt'}));
            }
        }
    }

    return 1;
}

sub _decipherCFG {
    my $cfg = shift;
    my $single_uuid = shift // 0;

    if (! $single_uuid) {
        foreach my $var (keys %{$$cfg{'defaults'}{'global variables'}}) {
            if ($$cfg{'defaults'}{'global variables'}{$var}{'hidden'} eq '1') {
                eval {
                    $$cfg{'defaults'}{'global variables'}{$var}{'value'} = decode('UTF-8',_decrypt_hex_compat($$cfg{'defaults'}{'global variables'}{$var}{'value'}));
                };
            }
        }
    }

    if (defined $$cfg{'defaults'}{'keepass'}) {
        eval {
            $$cfg{'defaults'}{'keepass'}{'password'} = decode('UTF-8',_decrypt_hex_compat($$cfg{'defaults'}{'keepass'}{'password'}));
        };
    }
    eval {
        $$cfg{'defaults'}{'sudo password'} = decode('UTF-8',_decrypt_hex_compat($$cfg{'defaults'}{'sudo password'}));
    };

    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        if (($single_uuid) && ($single_uuid ne $uuid)) {
            next;
        }

        if ($$cfg{'environments'}{$uuid}{'_is_group'}) {
            delete $$cfg{'environments'}{$uuid}{'pass'};
            next;
        }
        eval {$$cfg{'environments'}{$uuid}{'pass'} = decode('UTF-8',_decrypt_hex_compat($$cfg{'environments'}{$uuid}{'pass'}));};
        eval {$$cfg{'environments'}{$uuid}{'passphrase'} = decode('UTF-8',_decrypt_hex_compat($$cfg{'environments'}{$uuid}{'passphrase'}));};

        foreach my $hash (@{$$cfg{'environments'}{$uuid}{'expect'}}) {
            if ($$hash{'hidden'} eq '1') {
                eval {
                    $$hash{'send'} = _decrypt_hex_compat(encode('UTF-8',$$hash{'send'}));
                };
            }
        }

        foreach my $hash (@{$$cfg{'environments'}{$uuid}{'variables'}}) {
            if ($$hash{'hide'} eq '1') {
                eval {
                    $$hash{'txt'} = _decrypt_hex_compat(encode('UTF-8',$$hash{'txt'}));
                };
            }
        }
    }

    return 1;
}

# Substitution engine lives in PAC::Subst. PACUtils keeps `_subst` and
# `_substCFG` proxies so the 30+ legacy callsites in PACMain/PACTerminal/
# PACScripts/PACPCC continue to work unchanged.
require PAC::Subst;
sub _substCFG { goto &PAC::Subst::subst_cfg; }
sub _subst    { goto &PAC::Subst::subst; }

sub _wakeOnLan { goto &PAC::WakeOnLan::_wakeOnLan; }

sub _deleteOldestSessionLog {
    my $uuid = shift;
    my $folder = shift;
    my $max = shift;

    # If MAX is 0, then keep ALL the logs.
    if (!$max) {
        return 1;
    }

    opendir(my $F, $folder) or die "ERROR: Could not open folder '$folder' for reading: $!\n";

    my @total;
    foreach my $file (readdir $F) {
        if ($file !~ /^PAC_\[(.+)_Name_(.+)\]_\[(\d{8})_(\d{6})\]\.txt$/g) {
            next;
        }
        my ($fenv, $fconn, $fdate, $ftime) = ($1, $2, $3, $4);
        push(@total, "$folder/$file");
    }

    close $F;

    if (scalar(@total) lt $max) {
        return 1;
    }

    my $i = 0;
    foreach my $file (sort {$a cmp $b} @total) {
        unlink $file or die "ERROR: Could not delete oldest log file '$file': $!\n";
        if ((scalar(@total) - $max) <= $i++) {
            last;
        }
    }

    return 1;
}

sub _replaceBadChars {
    my $string = shift // '';

    $string =~ s/\x0/'NUL (null)'/go;
    $string =~ s/\x1/'SOH(start of heading)'/go;
    $string =~ s/\x2/'STX (start of text)'/go;
    $string =~ s/\x3/'ETX (end of text)'/go;
    $string =~ s/\x4/'EOT (end of trans.)'/go;
    $string =~ s/\x5/'ENQ (enquiry)'/go;
    $string =~ s/\x6/'ACK (acknowledge)'/go;
    $string =~ s/\x7/'BEL (bell)'/go;
    $string =~ s/\x8/'BS (backspace)'/go;
    $string =~ s/\x9/'AB (horizontal tab)'/go;
    $string =~ s/\xA/'LF (NL New Line)'/go;
    $string =~ s/\xB/'VT (vertical tab)'/go;
    $string =~ s/\xC/'FF (NP new page)'/go;
    $string =~ s/\xD/'CR (carriage return)'/go;
    $string =~ s/\xE/'SO (shift out)'/go;
    $string =~ s/\xF/'SI (shift in)'/go;
    $string =~ s/\x10/'DLE (data link escape)'/go;
    $string =~ s/\x11/'DC1 (device control 1)'/go;
    $string =~ s/\x12/'DC2 (device control 2)'/go;
    $string =~ s/\x13/'DC3 (device control 3)'/go;
    $string =~ s/\x14/'DC4 (device control 4)'/go;
    $string =~ s/\x15/'NAK (negative acknow.)'/go;
    $string =~ s/\x16/'SYN (synchronous idle)'/go;
    $string =~ s/\x17/'ETB (end of trans.blow)'/go;
    $string =~ s/\x18/'CAN (cancel)'/go;
    $string =~ s/\x19/'EM (end of medium)'/go;
    $string =~ s/\x1A/'SUB (substitute)'/go;
    $string =~ s/\x1B/'ESC (escape)'/go;
    $string =~ s/\x1C/'FS (file separator)'/go;
    $string =~ s/\x1D/'GS (group separator)'/go;
    $string =~ s/\x1E/'RS (record separator)'/go;
    $string =~ s/\x1F/'US (unit separator)'/go;
    $string =~ s/\x7f/\(BACKSPACE\)/go;

    return $string;
}

sub _removeEscapeSeqs {
    my $string = shift // '';

    $string =~ s/\x07/\x07\n/g;
    $string =~ s/\x1B[=>]//g;
    $string =~ s/\e\[[0-9;]*[a-zA-Z]%?//g;
    $string =~ s/\e\[[0-9;]*m(?:\e\[K)?//g;
    $string =~ s/\x1B\]1.+?\x07\n?//g;
    $string =~ s/(\x1B|\x08|\x07)(\[w|=|\(B)?//g;
    $string =~ s/\[\?\d+\w{1,2}//g;
    $string =~ s/\]\d;//g;

    return $string;
}

sub _purgeUnusedOrMissingScreenshots {
    my $cfg = shift;

    my %screenshots;

    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        my $i = 0;
        foreach my $screenshot (@{$$cfg{'environments'}{$uuid}{'screenshots'}}) {
            if (! -f $screenshot) {
                splice(@{$$cfg{'environments'}{$uuid}{'screenshots'}}, $i, 1);
            } else {
                ++$i;
                $screenshots{$screenshot} = 1;
            }
        }
    }

    opendir(my $dir, "$CFG_DIR/screenshots") or die "ERROR: Could not open dir '$CFG_DIR/screenshots' for reading: $!\n";
    while (my $file = readdir($dir)) {
        if ($file =~ /^\.|\.\.$/go) {
            next;
        }
        defined $screenshots{"$CFG_DIR/screenshots/$file"} or unlink "$CFG_DIR/screenshots/$file";
    }
    closedir $dir;

    return 1;
}

sub _getXWindowsList {
    my %list;

    my $s = Wnck::Screen::get_default() or die print $!;
    $s->force_update();

    foreach my $w (@{$s->get_windows}) {
        my $xid = $w->get_xid() or next;
        my $data_name = $w->get_name();

        $list{'by_xid'}{$xid}{'title'} = $data_name;
        $list{'by_xid'}{$xid}{'window'} = $w;

        if (defined $data_name) {
            $list{'by_name'}{$data_name}{'xid'} = $xid;
            $list{'by_name'}{$data_name}{'window'} = $w;
        }
    }

    return \%list;
}

sub _checkREADME {
    my $readme_file = "$CFG_DIR/tmp/latest_README";
    open(my $fh, '<:utf8', $readme_file) or return 0;
    my @readme;
    while(my $line = <$fh>) {
        chomp $line;
        push(@readme, $line);
    }
    close $fh;

    my $version = $readme[56] // 0;
    $version =~ s/^\s+-\s+(.+):/$1/go;
    $version or return 0;

    my $i = 54;
    my @changes = splice(@readme, 54);
    unlink $readme_file;

    return $version, \@changes;
}

# Encodings registry lives in PAC::Terminal::Encodings.
require PAC::Terminal::Encodings;
sub _getEncodings { goto &PAC::Terminal::Encodings::all; }

sub _makeDesktopFile {
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

    open(my $fh, '>:utf8', "$ENV{HOME}/.local/share/applications/asbru.desktop") or return 0;
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

sub _updateWidgetColor {
    my $self = shift;
    my $cfg = shift;
    my $widget = shift;
    my $cfgName = shift;
    my $defaultColor = shift;
    # If we don't have an object yet, get it from self
    if (ref($widget) eq '') {
        $widget = _($self, $widget);
    }
    my $tmpColor = Gtk3::Gdk::RGBA::parse($$cfg{$cfgName} // $defaultColor);
    $widget->set_rgba($tmpColor);
}

sub _getSelectedRows {
    my $treeSelection = shift;
    # https://metacpan.org/pod/Gtk3
    # "Gtk3::TreeSelection: get_selected_rows() now returns two values: an array ref containing the selected paths, and the model."
    # Go back to the Gtk2 behavior: drop the model, return the selected paths as array.
    my ($aref, $model) = $treeSelection->get_selected_rows();
    if (!$aref) {
        return ();
    }
    return @$aref;
}

sub _vteFeed {
    my $vte = shift;
    my $str = shift;
    my @arr = unpack ('C*', $str);
    $vte->feed(\@arr);
}

sub _vteFeedChild {
    my $vte = shift;
    my $str = shift;
    my $feedVersion = $PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_child};

    use bytes;
    my $b = length($str);
    my @arr = unpack ('C*', $str);

    if ($feedVersion == 1) {
        # Newer version only requires 1 parameter
        $vte->feed_child(\@arr);
    } else {
        # Elder versions requires 2 parameters
        $vte->feed_child($str, $b);
    }
}

sub _vteFeedChildBinary {
    my $vte = shift;
    my $str = shift;
    my @arr = unpack ('C*', $str);
    my $feedVersion = $PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_binary};

    if ($feedVersion == 1) {
        # Newer version only requires 1 parameter
        $vte->feed_child_binary(\@arr);
    } else {
        # Elder versions requires 2 parameters
        $vte->feed_child_binary(\@arr, length(\@arr));
    }
}

sub _createBanner {
    my $icon_filename = shift;
    my $text_label = shift;
    my $banner;
    my $icon;
    my $text;

    $icon = Gtk3::Image->new_from_file("${THEME_DIR}/${icon_filename}");
    $icon->set_margin_left(10);
    $icon->set_margin_right(10);
    $text = Gtk3::Label->new();
    $text->set_margin_left(10);
    $text->set_margin_right(10);
    $text->set_text($text_label);
    $text->get_style_context->add_class('banner-text');
    $banner = Gtk3::Box->new('horizontal', 0);
    $banner->set_size_request(-1, 50);
    $banner->get_style_context->add_class('banner-fill');
    $banner->pack_start($icon, 0, 1, 0);
    $banner->pack_start($text, 0, 1, 0);

    return $banner;
}

sub _copyPass {
    my $uuid = shift;
    my $cfg = $PACMain::FUNCS{_MAIN}{_CFG};
    my $clip;

    my $clipboard = Gtk3::Clipboard::get(Gtk3::Gdk::Atom::intern('PRIMARY', 0));
    if ($$cfg{environments}{$uuid}{'passphrase'} ne '') {
        $clip = $$cfg{environments}{$uuid}{'passphrase'};
    } else {
        $clip = $$cfg{environments}{$uuid}{'pass'};
    }
    if ($$cfg{'defaults'}{'keepass'}{'use_keepass'} && PACKeePass->isKeePassMask($clip)) {
        my $kpxc = $PACMain::FUNCS{_KEEPASS};
        $clip = $kpxc->applyMask($clip);
    }
    use bytes;
    $clipboard->set_text($clip,length($clip));

    # SECURITY: Auto-clear clipboard after 15 seconds to prevent credential leakage.
    # Store reference for zeroing.
    my $clip_ref = \$clip;
    Glib::Timeout->add_seconds(15, sub {
        my $cb = Gtk3::Clipboard::get(Gtk3::Gdk::Atom::intern('PRIMARY', 0));
        $cb->set_text('', 0);
        $$clip_ref = "\0" x length($$clip_ref) if defined $$clip_ref && length($$clip_ref);
        return 0;  # Don't repeat
    });
}

sub _appName {
    return "$APPNAME $APPVERSION";
}

sub _setDefaultRGBA {
    ($R,$G,$B,$A) = ($_[0]/255,$_[1]/255,$_[2]/255,$_[3]);
}

sub _setWindowPaintable {
    my $win = shift;

    $win->signal_connect("draw" => \&mydraw);
    my $screen = $win->get_screen();
    my $visual = $screen->get_rgba_visual();
    if (($visual) && ($screen->is_composited())) {
        $win->set_visual($visual);
    }
    $win->set_app_paintable(1);
}

sub mydraw {
    my ($w,$c) = @_;

    $c->set_source_rgba($R,$G,$B,$A);
    $c->set_operator('source');
    $c->paint();
    $c->set_operator('over');
    return 0;
}

sub _doShellEscape {
    my $str = shift;

    $str =~ s/([\$\\`"!])/\\$1/g;
    $str =~ s/\n/\\n/g;
    $str =~ s/\r/\\r/g;

    return $str;
}

1;

__END__

=encoding utf8

=head1 NAME

PACUtils.pm

=head1 SYNOPSIS

General support routines for common tasks for all modules

=head1 DESCRIPTION

=head2 sub _ (_CONFIG object,name)

Returns GLADE object named "name" from _CONFIG object

Example

    _($$self{_CONFIG}, 'cbCfgStartIconified')

=head2 sub __(string)

Prepare string to be included in a HTML TAG

    Returns a new string after substituting
    &       &amp;
    '       &apos;
    "       &quot;
    <       &let;
    >       &gt;

=head2 sub __text(string)

Inverse of __(string)

=head2 sub _splash

Build and Show Splash screen

=head2 sub _screenshot (widget,file)

Creates a pixbuffer from widget and saves it to file

=head2 sub _scale(file,width,height[,ratio])

Scales a pixbuffer by width,height or using with or height as the relation of the ratio

=head2 sub _pixBufFromFile(file)

Loads a pixbuffer from file

=head2 sub _getMethods(PACMain object)

Test for the existence for support applications for selected connection methods : VNC, RDP, etc.

Depending on result sets the callbacks and error messages if you try tu use a non supported method.

=head2 sub _registerPACIcons

Registers al icons available for the application

=head2 sub _sortTreeData

Sorts the titles from the connections nodes tree

=head2 sub _menuFavouriteConnections

Creates the favorites list and attaches the callback routines to the elements

=head2 sub _menuClusterConnections

Creates the cluster connections list and attaches the callback routines to the elements

=head2 sub _menuAvailableConnections

Creates the list of connect to popups from the existing list of connections

=head2 sub _wEnterValue

Creates a Dialog Box to enter a value

=head2 sub _wAddRenameNode

Adds or renames a connection node in the node tree

=head2 sub _wPopUpMenu

Creates popup menus for Cluster, Favorites, Connections

=head3 sub _buildMenuData

Support function to build and xml file to build the popup menu

=head3 sub _pos

Support function to calculate the location of the popup menu

=head2 sub _wMessage(window,msg,modal,selectable,class)

    window      parent window to be transient for
    msg         message to display
    modal       0 no, 1 yes (defaul yes)
    selectable  should message be selectable (default no)
    class       css class : w-warning, w-info, w-error (default w-warning)

Create a modal message to the user

=head2 sub _wProgress

Loading progress display in splash screen

=head2 sub _wConfirm

Create Confirm Dialog

=head2 sub _wYesNoCancel

Create Yes, No, Cancel Dialog

=head2 sub _wSetPACPassword

Sets the Application password

=head2 sub _cfgSanityCheck

Sanitize the configuration and delete temporary sessions that should not be persisted

=head2 sub _cfgGetTmpSessions

Extract the temporary sessions from the configuration.  Those sessions will be deleted by _cfgSanityCheck

=head2 sub _cfgAddSessions

Restore a list of sessions to the configuration.

=head2 sub _updateSSHToIPv6

Pending

=head2 sub _cipherCFG

Pending

=head2 sub _decipherCFG

Pending

=head2 sub _substCFG

Pending

=head2 sub _subst

Substitution of tags for corresponding string value

=head2 sub _wakeOnLan

Pending

=head2 sub _deleteOldestSessionLog

Pending

=head2 sub _replaceBadChars

Transform non printable messages in a printable message

=head2 sub _removeEscapeSeqs

Remove escape sequences from string

=head2 sub _purgeUnusedOrMissingScreenshots

Deletes screen shots, missing, old

=head2 sub _getXWindowsList

Pending

=head2 sub _getREADME

Get the readme file from url location

=head2 sub _checkREADME

Return README file if exists

=head2 sub _showUpdate

UNIMPLEMENTED : Check for updates and notify

=head2 sub _getEncodings

Get hash (table, dictionary list) or encoders

=head2 sub _makeDesktopFile

Creates a asbru.desktop file to launch application

=head2 sub _updateWidgetColor

Pendind

=head2 sub _getSelectedRows

Pending

=head2 sub _vteFeed

Call Vte->feed(array reference)

=head2 sub _vteFeedChild

Call Vte->vteFeedChild, depending on the version installed

=head2 sub _vteFeedChildBinary

Call Vte->vteFeedChildBinary, depending on the version installed

=head2 sub _createBanner

Create a standard banner to be displayed on all Ásbrú Connection Manager dialogs

=head2 sub _setWindowPaintable

Takes a window object, attaches a general drawing routine and sets the paintable property to true

Hack to make transparent terminals

=head2 sub mydraw

Generic routine to draw a gray background for widgets that do not painted their own.

=head2 _doShellEscape

Escape characters so that the text can be used in a shell string command, like echo "$VAR"

=head1 Perl particulars

    @{[function(parameters)]} ==> Inside an interpolation, executes the function and uses the result as the string in that position
    Used as   : "My string @{[function(parameters)]} continues here"
    Instead of: "My string " . function(parameters) . " continues here"
