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
# Bulk config crypto lives in PAC::Vault. PACUtils retains proxies.
sub _migrateCipherCFG { goto &PAC::Vault::migrate_cipher_cfg; }

# Backward-compat alias for the legacy decrypt-with-fallback helper.
# Implementation now lives in PAC::Crypto::Cipher::decrypt_hex which tries
# the active cipher, then legacy AES, then legacy Blowfish.
sub _decrypt_hex_compat { goto &PAC::Crypto::Cipher::decrypt_hex; }

# WINDOWSPLASH state moved to PAC::Window::Splash; the old
# my-lexical is no longer referenced — kept commented for diff readability.
# my %WINDOWSPLASH;
my %WINDOWPROGRESS;
# WIDGET_POPUP state moved to PAC::Dialog::PopupMenu (P3/18).
# RGBA paint state moved to PAC::Theme::Widget (P3/21).

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

# Splash window lives in PAC::Window::Splash.
require PAC::Window::Splash;
sub _splash { goto &PAC::Window::Splash::show; }

# Image helpers live in PAC::Theme::Image.
require PAC::Theme::Image;
sub _screenshot { goto &PAC::Theme::Image::screenshot; }

# TODO: This should validate for file existence, eval generates errors an warnings in verbose mode
sub _scale { goto &PAC::Theme::Image::scale; }

# TODO: This should validate for file existence, eval generates errors an warnings in verbose mode
sub _pixBufFromFile { goto &PAC::Theme::Image::pixbuf_from_file; }

# Method registry lives in PAC::Methods. PACUtils keeps a 1-line proxy.
require PAC::Methods;
sub _getMethods { goto &PAC::Methods::registry; }

# Icon registration lives in PAC::Theme::Icons. PACUtils proxy.
require PAC::Theme::Icons;
sub _registerPACIcons { goto &PAC::Theme::Icons::register; }

# Tree-node comparator lives in PAC::Tree::Sort. Wrapper (not goto-proxy)
# because Perl's `sort SUBNAME` sets $a/$b in the *caller's* package and
# legacy callers (PACUtils internals + t/16) set $PACUtils::a/b — so we
# resolve them here and forward via the explicit-args form.
require PAC::Tree::Sort;
sub _sortTreeData {
    no strict 'refs';
    return PAC::Tree::Sort::compare_pair(${"PACUtils::a"}, ${"PACUtils::b"});
}

# TODO : displayed name should include group
sub _menuFavouriteConnections { goto &PAC::Menu::favourite_connections; }

sub _menuClusterConnections { goto &PAC::Menu::cluster_connections; }

sub _menuAvailableConnections { goto &PAC::Menu::available_connections; }

sub _wEnterValue { goto &PAC::Dialog::_wEnterValue; }

sub _wAddRenameNode { goto &PAC::Dialog::_wAddRenameNode; }

# Popup menu builder lives in PAC::Dialog::PopupMenu.
require PAC::Dialog::PopupMenu;
sub _wPopUpMenu { goto &PAC::Dialog::PopupMenu::show; }

sub _wMessage { goto &PAC::Dialog::_wMessage; }

sub _wProgress { goto &PAC::Dialog::_wProgress; }

sub _wConfirm { goto &PAC::Dialog::_wConfirm; }

sub _wYesNoCancel { goto &PAC::Dialog::_wYesNoCancel; }

sub _wSetPACPassword { goto &PAC::Dialog::_wSetPACPassword; }

# Legacy config schema enforcement lives in PAC::Config::SanityCheck.
require PAC::Config::SanityCheck;
sub _cfgSanityCheck { goto &PAC::Config::SanityCheck::run; }

# Temp session strip/restore lives in PAC::Config::TmpSessions.
require PAC::Config::TmpSessions;
sub _cfgGetTmpSessions { goto &PAC::Config::TmpSessions::extract; }

sub _cfgAddSessions { goto &PAC::Config::TmpSessions::restore; }

# SSH options parser lives in PAC::Net::SshOptions.
require PAC::Net::SshOptions;
sub _updateSSHToIPv6 { goto &PAC::Net::SshOptions::normalize_options; }

sub _cipherCFG { goto &PAC::Vault::cipher_cfg; }

sub _decipherCFG { goto &PAC::Vault::decipher_cfg; }

# Substitution engine lives in PAC::Subst. PACUtils keeps `_subst` and
# `_substCFG` proxies so the 30+ legacy callsites in PACMain/PACTerminal/
# PACScripts/PACPCC continue to work unchanged.
require PAC::Subst;
sub _substCFG { goto &PAC::Subst::subst_cfg; }
sub _subst    { goto &PAC::Subst::subst; }

sub _wakeOnLan { goto &PAC::WakeOnLan::_wakeOnLan; }

# Session-log helpers live in PAC::SessionLog.
require PAC::SessionLog;
sub _deleteOldestSessionLog { goto &PAC::SessionLog::delete_oldest; }

sub _replaceBadChars { goto &PAC::SessionLog::replace_bad_chars; }

sub _removeEscapeSeqs { goto &PAC::SessionLog::remove_escape_seqs; }

sub _purgeUnusedOrMissingScreenshots { goto &PAC::SessionLog::purge_screenshots; }

# X11 window list lives in PAC::Net::WindowList.
require PAC::Net::WindowList;
sub _getXWindowsList { goto &PAC::Net::WindowList::all; }

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

# .desktop generator lives in PAC::Theme::DesktopFile.
require PAC::Theme::DesktopFile;
sub _makeDesktopFile { goto &PAC::Theme::DesktopFile::generate; }

# Widget styling helpers live in PAC::Theme::Widget.
require PAC::Theme::Widget;
sub _updateWidgetColor { goto &PAC::Theme::Widget::update_color; }

# Tree selection helper lives in PAC::Util::TreeSelection.
require PAC::Util::TreeSelection;
sub _getSelectedRows { goto &PAC::Util::TreeSelection::rows; }

# VTE feed helpers live in PAC::Terminal::Vte.
require PAC::Terminal::Vte;
sub _vteFeed { goto &PAC::Terminal::Vte::feed; }

sub _vteFeedChild { goto &PAC::Terminal::Vte::feed_child; }

sub _vteFeedChildBinary { goto &PAC::Terminal::Vte::feed_child_binary; }

sub _createBanner { goto &PAC::Theme::Image::banner; }

# Clipboard helpers live in PAC::Clipboard.
require PAC::Clipboard;
sub _copyPass { goto &PAC::Clipboard::copy_password; }

sub _appName {
    return "$APPNAME $APPVERSION";
}

sub _setDefaultRGBA { goto &PAC::Theme::Widget::set_default_rgba; }

sub _setWindowPaintable { goto &PAC::Theme::Widget::set_window_paintable; }

sub mydraw { goto &PAC::Theme::Widget::draw_callback; }

# Shell escape lives in PAC::Util::ShellEscape.
require PAC::Util::ShellEscape;
sub _doShellEscape { goto &PAC::Util::ShellEscape::escape; }

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
