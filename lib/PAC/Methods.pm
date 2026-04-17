package PAC::Methods;

###############################################################################
# PAC::Methods — registry of supported connection protocols.
#
# Each entry in the returned hash describes one protocol (RDP, VNC, SSH,
# SFTP, Serial, IBM 3270, Telnet, Cadaver, Mosh, ...) with a uniform
# interface that PACEdit and PACTerminal use to:
#
#   - test whether the underlying binary is installed
#   - validate the connection configuration
#   - escape user-supplied values for the command line
#   - build the argv to spawn
#   - (optionally) embed the protocol's window inside our terminal tab
#   - load a 16x16 icon for the connections-tree row
#
# Mechanical extraction from PACUtils::_getMethods. PACUtils keeps a
# 1-line proxy so the existing 6+ callsites (PACEdit, PACMain, asbru-cm,
# tests) continue to work unchanged.
#
# This module ships the registry as ONE big function. A future split
# into one PAC::Method::<Name> file per protocol is tracked in
# ARCHITECTURE.md as a follow-up.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;
use Gtk3::Gdk;

use PACUtils qw(_ __);

our $VERSION = '0.1.0';

# Loaded from the asbru-plus theme directory; PACUtils sets this and
# passes it in. Kept module-local so we don't reach back into PACUtils
# state on every invocation.
my $THEME_DIR;

# registry($self, $theme_dir) -> %methods
# $self is the PACEdit instance whose Glade widgets are accessed via
# `_($self, 'widgetName')`. $theme_dir overrides the icon search path.
sub registry {
    my $self = shift;
    my $theme_dir = shift;
    my %methods;

    if ($theme_dir) {
        $THEME_DIR = $theme_dir;
    }

    my $rdesktop = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which rdesktop 1>/dev/null 2>&1") == 0);
    $methods{'RDP (rdesktop)'} = {
        'installed' => sub {return $rdesktop ? 1 : "No 'rdesktop' binary found.\nTo use this option, please, install :'rdesktop'";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (! _($self, 'entryPort')->get_chars(0, -1)) {
                push(@faults, 'Port');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
                if (! _($self, 'entryPassword')->get_chars(0, -1)) {
                    push(@faults, 'Password (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'RDP (rdesktop)';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 3389);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryIP')->set_text($$cfg{ip} // '');
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'frameExpect')->set_sensitive(0);
            _($self, 'frameRemoteMacros')->set_sensitive(0);
            _($self, 'frameLocalMacros')->set_sensitive(0);
            _($self, 'frameVariables')->set_sensitive(0);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(0);
            _($self, 'labelRemoteMacros')->set_sensitive(0);
            _($self, 'labelLocalMacros')->set_sensitive(0);
            _($self, 'labelVariables')->set_sensitive(0);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_rdesktop.svg", 16, 16, 0),
        'escape' => ["\cc"]
    };

    my $xfreerdp = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which xfreerdp 1>/dev/null 2>&1") == 0);
    $methods{'RDP (xfreerdp)'} = {
        'installed' => sub {return $xfreerdp ? 1 : "No 'xfreerdp' binary found.\nTo use this option, please, install:\n'freerdp2-x11'";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (! _($self, 'entryPort')->get_chars(0, -1)) {
                push(@faults, 'Port');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
                if (! _($self, 'entryPassword')->get_chars(0, -1)) {
                    push(@faults, 'Password (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'RDP (xfreerdp)';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 3389);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryIP')->set_text($$cfg{ip} // '');
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'frameExpect')->set_sensitive(0);
            _($self, 'frameRemoteMacros')->set_sensitive(0);
            _($self, 'frameLocalMacros')->set_sensitive(0);
            _($self, 'frameVariables')->set_sensitive(0);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(0);
            _($self, 'labelRemoteMacros')->set_sensitive(0);
            _($self, 'labelLocalMacros')->set_sensitive(0);
            _($self, 'labelVariables')->set_sensitive(0);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_rdesktop.svg", 16, 16, 0),
        'escape' => ["\cc"]
    };

    my $xtightvncviewer = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which vncviewer 1>/dev/null 2>&1") == 0);
    my $tigervnc = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} vncviewer --help 2>&1 | /bin/grep -q TigerVNC") == 0);
    $methods{'VNC'} = {
        'installed' => sub {return $xtightvncviewer || $tigervnc ? 1 : "No 'vncviewer' binary found.\nTo use this option, please, install any of:\n'xtightvncviewer' or 'tigervnc'\n'tigervnc' is preferred, since it allows embedding its window into Ásbrú Connection Manager.";},
        'checkCFG' => sub {

            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (! _($self, 'entryPort')->get_chars(0, -1)) {
                push(@faults, 'Port');
            }
            if ((_($self, 'rbCfgAuthUserPass')->get_active()) && (_($self, 'entryPassword')->get_chars(0, -1) eq '')) {
                push(@faults, "Password (User/Password authentication method selected)");
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'VNC';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 5900);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryIP')->set_text($$cfg{ip} // '');
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'frameExpect')->set_sensitive(0);
            _($self, 'frameRemoteMacros')->set_sensitive(0);
            _($self, 'frameLocalMacros')->set_sensitive(0);
            _($self, 'frameVariables')->set_sensitive(0);
            _($self, 'frameTerminalOptions')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(0);
            _($self, 'labelRemoteMacros')->set_sensitive(0);
            _($self, 'labelLocalMacros')->set_sensitive(0);
            _($self, 'labelVariables')->set_sensitive(0);
            _($self, 'labelTerminalOptions')->set_sensitive(0);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_vncviewer.svg", 16, 16, 0),
        'escape' => ["\cc"]
    };

    my $cu = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which cu 1>/dev/null 2>&1") == 0);
    $methods{'Serial (cu)'} = {
        'installed' => sub {return $cu ? 1 : "No 'cu' binary found.\nTo use this option, please, install 'cu'.";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;
            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'Serial (cu)';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(0);
            _($self, 'entryPort')->set_value(0);
            _($self, 'labelIP')->set_text('System / Phone / "dir": ');
            _($self, 'entryIP')->set_property('tooltip-markup', "Enter string of kind: system | phone | 'dir' or\nleave empty and use the 'Line' option under the 'cu options' tab on the left");
            _($self, 'entryIP')->set_text($$cfg{ip} // '');
            _($self, 'entryUser')->set_text('');
            _($self, 'entryPassword')->set_text('');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(0);
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'rbCfgAuthManual')->set_active(1);
            _($self, 'vboxAuthMethod')->set_sensitive(0);
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_cu.svg", 16, 16, 0),
        'escape' => ['~.']
    };

    my $remote_tty = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which remote-tty 1>/dev/null 2>&1") == 0);
    $methods{'Serial (remote-tty)'} = {
        'installed' => sub {return $remote_tty ? 1 : "No 'remote-tty' binary found.\nTo use this option, please, install 'remote-tty'.";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'TTY Socket');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
                if (! _($self, 'entryPassword')->get_chars(0, -1)) {
                    push(@faults, 'Password (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'Serial (remote-tty)';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(0);
            _($self, 'entryPort')->set_value(0);
            _($self, 'labelIP')->set_text('TTY Socket: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'Enter a TTY / Serial socket (eg: /dev/tty*)');
            _($self, 'entryIP')->set_text($$cfg{ip} // '');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_remote-tty.svg", 16, 16, 0)
    };

    my $c3270 = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which c3270 1>/dev/null 2>&1") == 0);
    $methods{'IBM 3270/5250'} = {
        'installed' => sub {return $c3270 ? 1 : "No 'c3270' binary found.\nTo use this option, please, install 'c3270' or 'x3270-text'.";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;
            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }

            return @faults;
        },
        'updateGUI'  => sub {
            my $cfg = shift;

            my $method = 'IBM 3270/5250';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value(23);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the host to connect to');
            _($self, 'entryUser')->set_text('');
            _($self, 'entryPassword')->set_text('');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'vboxAuthMethod')->set_sensitive(0);
            _($self, 'rbCfgAuthManual')->set_active(1);
            _($self, 'entryUser')->set_sensitive(0);
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_3270.svg", 16, 16, 0)
    };

    my $autossh = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which autossh 1>/dev/null 2>&1") == 0);
    $methods{'SSH'} = {
        'installed' => sub {return 1;},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname cannot be empty');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active() && !_($self, 'entryUser')->get_chars(0, -1)) {
                push(@faults, 'User name cannot be empty if User/Password authentication method selected');
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'SSH';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_range(0, 65536);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 22);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(1);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(1);
            _($self, 'entryPassphrase')->set_text($$cfg{passphrase} // '');
            _($self, 'rbCfgAuthPublicKey')->set_active($$cfg{'auth type'} eq 'publickey');
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive($autossh);
            _($self, 'cbAutossh')->set_active($$cfg{'autossh'});
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_ssh.svg", 16, 16, 0),
        'escape' => ['~.']
    };

    my $mosh = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which mosh 1>/dev/null 2>&1") == 0);
    $methods{'MOSH'} = {
        'installed' => sub {return $mosh ? 1 : "No 'mosh' binary found.\nTo use this option, please, install 'mosh'.";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'MOSH';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 22);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(1);
            _($self, 'entryPassphrase')->set_text($$cfg{passphrase} // '');
            _($self, 'fileCfgPublicKey')->set_filename($$cfg{'public key'} // '');
            _($self, 'rbCfgAuthPublicKey')->set_active($$cfg{'auth type'} eq 'publickey');
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_mosh.svg", 16, 16, 0),
        'escape' => ["\c^x."]
    };

    my $cadaver = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which cadaver 1>/dev/null 2>&1") == 0);
    $methods{'WebDAV'} = {
        'installed' => sub {return $cadaver ? 1 : "No 'cadaver' binary found.\nTo use this option, please, install 'cadaver'.";},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'WebDAV';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(0);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 80);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'entryPassphrase')->set_text($$cfg{passphrase} // '');
            _($self, 'fileCfgPublicKey')->set_filename($$cfg{'public key'} // '');
            _($self, 'rbCfgAuthPublicKey')->set_active($$cfg{'auth type'} eq 'publickey');
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_cadaver.svg", 16, 16, 0),
        'escape' => ["\cc", "quit\n"]
    };

    my $telnet = (system("$ENV{'ASBRU_ENV_FOR_EXTERNAL'} which telnet 1>/dev/null 2>&1") == 0);
    $methods{'Telnet'} = {
        'installed' => sub {return $telnet ? 1 : "No 'telnet' binary found.\nTo use this option, please, install 'telnet' or 'telnet-ssl'.";},
        'checkCFG' => sub {
            my $cfg = shift;
            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (! _($self, 'entryPort')->get_chars(0, -1)) {
                push(@faults, 'Port');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'Telnet';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 23);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryIP')->set_text($$cfg{ip} // '');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_telnet.svg", 16, 16, 0),
        'escape' => ["\c]", "quit\n"]
    };

    $methods{'SFTP'} = {
        'installed' => sub {return 1;},
        'checkCFG' => sub {
            my $cfg = shift;
            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (! _($self, 'entryPort')->get_chars(0, -1)) {
                push(@faults, 'Port');
            }
            # TODO : Check if this nested "ifs" can be rewritten
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
            } elsif (_($self, 'rbCfgAuthPublicKey')->get_active()) {
                if (! _($self, 'fileCfgPublicKey')->get_filename()) {
                    push(@faults, 'Public Key File (Public Key authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'SFTP';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 22);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(1);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'alignUserPass')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(1);
            _($self, 'entryPassphrase')->set_text($$cfg{passphrase} // '');
            _($self, 'fileCfgPublicKey')->set_filename($$cfg{'public key'} // '');
            _($self, 'rbCfgAuthPublicKey')->set_active($$cfg{'auth type'} eq 'publickey');
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_sftp.svg", 16, 16, 0)
    };

    $methods{'FTP'} = {
        'installed' => sub {return 1;},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (! _($self, 'entryIP')->get_chars(0, -1)) {
                push(@faults, 'IP/Hostname');
            }
            if (! _($self, 'entryPort')->get_chars(0, -1)) {
                push(@faults, 'Port');
            }
            if (_($self, 'rbCfgAuthUserPass')->get_active()) {
                if (! _($self, 'entryUser')->get_chars(0, -1)) {
                    push(@faults, 'User (User/Password authentication method selected)');
                }
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $cfg = shift;

            my $method = 'FTP';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(1);
            _($self, 'framePort')->set_sensitive(1);
            _($self, 'entryPort')->set_value($method eq $$cfg{method} ? $$cfg{port} : 21);
            _($self, 'labelIP')->set_text('Host: ');
            _($self, 'entryIP')->set_property('tooltip-markup', 'IP or Hostname of the machine to connect to');
            _($self, 'entryUser')->set_text($$cfg{user} // '');
            _($self, 'entryPassword')->set_text($$cfg{pass} // '');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'vboxAuthMethod')->set_sensitive(1);
            _($self, 'entryUser')->set_sensitive(1);
            _($self, 'alignAuthMethod')->set_sensitive(1);
            _($self, 'rbCfgAuthUserPass')->set_active(1);
            _($self, 'rbCfgAuthUserPass')->set_active($$cfg{'auth type'} eq 'userpass');
            _($self, 'framePublicKey')->set_sensitive(0);
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'rbCfgAuthManual')->set_sensitive(1);
            _($self, 'rbCfgAuthManual')->set_active($$cfg{'auth type'} eq 'manual');
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_ftp.svg", 16, 16, 0)
    };

    $methods{'Generic Command'} = {
        'installed' => sub {return 1;},
        'checkCFG' => sub {
            my $cfg = shift;

            my @faults;

            if (_($self, 'entryIP')->get_chars(0, -1) eq '') {
                push(@faults, 'Full command line');
            }

            return @faults;
        },
        'updateGUI' => sub {
            my $method = 'Generic Command';
            my $pixbuf = $$self{_METHODS}{$method}{'icon'};

            _($self, 'imageMethod')->set_from_pixbuf($pixbuf);
            _($self, 'imageConnOptions')->set_from_pixbuf($pixbuf);
            #_($self, 'vboxVarious')->set_sensitive(0);
            _($self, 'labelIP')->set_text('Full command line: ');
            _($self, 'entryIP')->set_property('tooltip-markup', "Full command line to execute, example:\nfirefox http://www.google.es\nor\nxdg-open \$HOME/Pictures/mounaint.jpg\nor\n/bin/bash -login\netc...");
            _($self, 'framePort')->set_sensitive(0);
            _($self, 'entryPort')->set_value(0);
            _($self, 'entryUser')->set_text('');
            _($self, 'entryPassword')->set_text('');
            _($self, 'cbCfgAuthFallback')->set_sensitive(0);
            _($self, 'frameExpect')->set_sensitive(1);
            _($self, 'frameRemoteMacros')->set_sensitive(1);
            _($self, 'frameLocalMacros')->set_sensitive(1);
            _($self, 'frameVariables')->set_sensitive(1);
            _($self, 'frameTerminalOptions')->set_sensitive(1);
            _($self, 'alignAuthMethod')->set_sensitive(0);
            _($self, 'rbCfgAuthManual')->set_active(1);
            _($self, 'entryUser')->set_sensitive(0);
            _($self, 'entryPassphrase')->set_text('');
            _($self, 'fileCfgPublicKey')->unselect_all();
            _($self, 'labelConnOptions')->set_markup("<b>$method</b>");
            _($self, 'labelExpect')->set_sensitive(1);
            _($self, 'labelRemoteMacros')->set_sensitive(1);
            _($self, 'labelLocalMacros')->set_sensitive(1);
            _($self, 'labelVariables')->set_sensitive(1);
            _($self, 'labelTerminalOptions')->set_sensitive(1);
            _($self, 'labelCmdLineOptions')->set_markup(" <b>$method</b> command line options");
            _($self, 'cbAutossh')->set_sensitive(0);
            _($self, 'cbAutossh')->set_active(0);
        },
        'icon' => Gtk3::Gdk::Pixbuf->new_from_file_at_scale("$THEME_DIR/asbru_method_generic.svg", 16, 16, 0)
    };

    return %methods;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Methods — registry of supported connection protocols

=head1 SYNOPSIS

    use PAC::Methods;

    my %methods = PAC::Methods::registry($pacedit_self, $theme_dir);
    for my $name (sort keys %methods) {
        my $m = $methods{$name};
        my $rc = $m->{installed}->();           # 1 or error string
        next unless $rc eq '1' || $rc == 1;
        $m->{checkCFG}->($cfg);
        my @argv = $m->{cmd}->($cfg, $uuid);
    }

=head1 DESCRIPTION

Mechanical extraction of C<PACUtils::_getMethods> into its own module.
The function builds and returns a big hash describing every supported
protocol (RDP, VNC, SSH, SFTP, Serial, IBM 3270, Telnet, Cadaver,
Mosh, generic…). Each entry is a hashref with the uniform set of
callbacks listed in the module header.

PACUtils.pm keeps a 1-line proxy (C<_getMethods> → C<registry>) so
existing call sites in PACEdit, PACMain, asbru-cm, and tests continue
to work unchanged.

=head1 PUBLIC API

=over

=item registry($self, $theme_dir)

Returns the full registry as a Perl hash (NOT a hashref — list-context
return is intentional for compat with the legacy interface).

C<$self> is the C<PACEdit> instance whose Glade widgets are accessed
via the C<_($self, 'widgetName')> helper exported by L<PACUtils>.
C<$theme_dir> overrides the icon search path; the previous value
persists in the module across calls if not supplied.

=back

=head1 SEE ALSO

L<PACUtils>, L<PACEdit>, the per-protocol C<lib/method/PACMethod_*>
modules.

=cut
