package PAC::Config::SanityCheck;

###############################################################################
# PAC::Config::SanityCheck — legacy schema enforcement / migration.
#
# Mechanical extraction of PACUtils::_cfgSanityCheck (535 lines). Walks
# the config hash, fills in missing default keys, applies coercions,
# migrates older config layouts to the current shape.
#
# This is the LEGACY code that the new declarative PAC::Config::Schema
# is gradually meant to replace. For now they coexist:
#   - run() applies the legacy defaults / migrations
#   - PAC::Config::Schema::apply_defaults() handles the v6.5.0+ keys
#
# PACUtils keeps a 1-line proxy so the existing 4+ callsites
# (_readConfiguration, _saveConfiguration, _promptSetMasterPassword,
# tests) continue to work unchanged.
###############################################################################

use strict;
use warnings;
use utf8;

use Storable qw(dclone);

our $VERSION = '0.1.0';

# Globals from PACUtils referenced fully-qualified to avoid a circular
# 'use' at compile time. The original $CFG_DIR was a `my` lexical in
# PACUtils; we recover it from $ENV{ASBRU_CFG} which is the same source.
sub _appversion { return $PACUtils::APPVERSION // ''; }
sub _cfg_dir    { return $ENV{ASBRU_CFG} // ''; }

# run($cfg) — same signature and semantics as the legacy
# PACUtils::_cfgSanityCheck. Mutates $cfg in place; returns 1.
sub run {  ## no critic (ProhibitExcessComplexity)
    my $cfg = shift;

    defined $$cfg{'defaults'} or $$cfg{'defaults'} = {};

    $$cfg{'defaults'}{'version'} //= _appversion();
    $$cfg{'defaults'}{'config version'} //= 1;
    #$$cfg{'defaults'}{'config location'} //= $ENV{"ASBRU_CFG"};
    $$cfg{'defaults'}{'auto accept key'} //= 0;  # SECURITY: default OFF — auto-accepting host key changes enables MITM
    $$cfg{'defaults'}{'show screenshots'} //= 1;
    $$cfg{'defaults'}{'back color'} //= '#000000000000';
    $$cfg{'defaults'}{'close terminal on disconnect'} //= '';
    $$cfg{'defaults'}{'max retry on disconnect'} //= 50;
    $$cfg{'defaults'}{'close to tray'} //= 0;
    $$cfg{'defaults'}{'color black'} //= '#000000000000';
    $$cfg{'defaults'}{'color blue'} //=  '#34346565a4a4';
    $$cfg{'defaults'}{'color bright black'} //=  '#555557575353';
    $$cfg{'defaults'}{'color bright blue'} //=  '#72729f9fcfcf';
    $$cfg{'defaults'}{'color bright cyan'} //=  '#3434e2e2e2e2';
    $$cfg{'defaults'}{'color bright green'} //=  '#8a8ae2e23434';
    $$cfg{'defaults'}{'color bright magenta'} //=  '#adad7f7fa8a8';
    $$cfg{'defaults'}{'color bright red'} //=  '#efef29292929';
    $$cfg{'defaults'}{'color bright white'} //=  '#eeeeeeeeecec';
    $$cfg{'defaults'}{'color bright yellow'} //=  '#fcfce9e94f4f';
    $$cfg{'defaults'}{'color cyan'} //=  '#060698209a9a';
    $$cfg{'defaults'}{'color green'} //=  '#4e4e9a9a0606';
    $$cfg{'defaults'}{'color magenta'} //=  '#757550507b7b';
    $$cfg{'defaults'}{'color red'} //=  '#cccc00000000';
    $$cfg{'defaults'}{'color white'} //=  '#d3d3d7d7cfcf';
    $$cfg{'defaults'}{'color yellow'} //=  '#c4c4a0a00000';
    $$cfg{'defaults'}{'command prompt'} //= $PACUtils::DEFAULT_COMMAND_PROMPT;
    $$cfg{'defaults'}{'username prompt'} //= $PACUtils::DEFAULT_USERNAME_PROMPT;
    $$cfg{'defaults'}{'password prompt'} //= $PACUtils::DEFAULT_PASSWORD_PROMPT;
    $$cfg{'defaults'}{'hostkey changed prompt'} //= $PACUtils::DEFAULT_HOSTKEYCHANGED_PROMPT;
    $$cfg{'defaults'}{'press any key prompt'} //= $PACUtils::DEFAULT_PRESSANYKEY_PROMPT;
    $$cfg{'defaults'}{'remote host changed prompt'} //= $PACUtils::DEFAULT_REMOTEHOSTCHANGED_PROMPT;
    $$cfg{'defaults'}{'sudo prompt'} //= '[__PAC__SUDO__PROMPT__]';
    $$cfg{'defaults'}{'sudo password'} //= '<<ASK_PASS>>';
    $$cfg{'defaults'}{'sudo show password'} //= 0;
    $$cfg{'defaults'}{'cursor shape'} //= 'block';
    $$cfg{'defaults'}{'debug'} //= 0;
    $$cfg{'defaults'}{'tabs in main window'} //= 1;
    $$cfg{'defaults'}{'auto hide connections list'} //= 0;
    $$cfg{'defaults'}{'auto hide button bar'}     //= 0;
    $$cfg{'defaults'}{'hide on connect'} //= 0;
    $$cfg{'defaults'}{'force split tabs to 50%'} //= 0;
    $$cfg{'defaults'}{'open connections in tabs'} //= 1;
    $$cfg{'defaults'}{'proxy ip'} //= '';
    $$cfg{'defaults'}{'proxy pass'} //= '';
    $$cfg{'defaults'}{'proxy port'} //= 8080;
    $$cfg{'defaults'}{'proxy user'} //= '';
    $$cfg{'defaults'}{'shell binary'} //= $ENV{'SHELL'} // '/bin/bash';
    $$cfg{'defaults'}{'shell options'} //= ($ENV{'SHELL'} ? '' : '-login');
    $$cfg{'defaults'}{'shell directory'} //= $ENV{'HOME'};
    $$cfg{'defaults'}{'tabs position'} //= 'top';
    $$cfg{'defaults'}{'auto save'} //= 1;
    $$cfg{'defaults'}{'save on exit'} //= 0;
    $$cfg{'defaults'}{'start iconified'} //= 0;
    $$cfg{'defaults'}{'start maximized'} //= 0;
    $$cfg{'defaults'}{'start main maximized'} //= 0;
    $$cfg{'defaults'}{'start at session startup'} //= 0;
    $$cfg{'defaults'}{'remember main size'} //= 1;
    $$cfg{'defaults'}{'show commands box'} = defined $$cfg{'defaults'}{'show commands box'} ? ($$cfg{'defaults'}{'show commands box'} || '0') : 0;
    $$cfg{'defaults'}{'show global commands box'} //= 0;
    $$cfg{'defaults'}{'terminal backspace'} //= 'auto';
    $$cfg{'defaults'}{'terminal transparency'} //= 0;
    $$cfg{'defaults'}{'terminal support transparency'} //= $$cfg{'defaults'}{'terminal transparency'} > 0;
    $$cfg{'defaults'}{'terminal font'} //= 'Monospace 9';
    $$cfg{'defaults'}{'terminal character encoding'} //= 'UTF-8';
    $$cfg{'defaults'}{'terminal scrollback lines'} //= 5000;
    $$cfg{'defaults'}{'terminal windows hsize'} //= 800;
    $$cfg{'defaults'}{'terminal windows vsize'} //= 600;
    $$cfg{'defaults'}{'terminal show status bar'} //= 1;
    $$cfg{'defaults'}{'text color'} //= '#cc62cc62cc62';
    $$cfg{'defaults'}{'bold color'} //= $$cfg{'defaults'}{'text color'};
    $$cfg{'defaults'}{'bold color like text'} //= 1;
    $$cfg{'defaults'}{'connected color'} //= '#0CBA00'; # mid-green
    $$cfg{'defaults'}{'disconnected color'} //= '#FF0000'; # red
    $$cfg{'defaults'}{'new data color'} //= '#0088FF'; # blue
    $$cfg{'defaults'}{'timeout command'} //= 60;
    $$cfg{'defaults'}{'timeout connect'} //= 40;
    $$cfg{'defaults'}{'use bw icon'} //= 0;
    $$cfg{'defaults'}{'confirm exit'} //= 1;
    $$cfg{'defaults'}{'use proxy'} //= 0;
    $$cfg{'defaults'}{'use system proxy'} //= 1;
    $$cfg{'defaults'}{'save session logs'} //= 0;
    $$cfg{'defaults'}{'session log pattern'} //= '<UUID>_<NAME>_<DATE_Y><DATE_M><DATE_D>_<TIME_H><TIME_M><TIME_S>.txt';
    $$cfg{'defaults'}{'session logs folder'} //= _cfg_dir() . "/session_logs";
    $$cfg{'defaults'}{'session logs amount'} //= 10;
    $$cfg{'defaults'}{'screenshots external viewer'} //= '/usr/bin/xdg-open';
    $$cfg{'defaults'}{'screenshots use external viewer'}//= 0;
    $$cfg{'defaults'}{'sort groups first'} //= 1;
    $$cfg{'defaults'}{'word characters'} //= '-.:_/';
    $$cfg{'defaults'}{'show tray icon'} //= 1;
    $$cfg{'defaults'}{'unsplit disconnected terminals'} //= 0;
    $$cfg{'defaults'}{'confirm chains'} //= 1;
    $$cfg{'defaults'}{'skip first chain expect'} //= 1;
    $$cfg{'defaults'}{'enable tree lines'} //= 0;
    $$cfg{'defaults'}{'show tree titles'} //= 1;
    # option currently disabled
    $$cfg{'defaults'}{'check versions at start'} //= 0;
    $$cfg{'defaults'}{'show statistics'} //= 1;
    $$cfg{'defaults'}{'protected color'} //= '#FFB022'; #orange
    $$cfg{'defaults'}{'protected set'} //= 'background';
    if ($$cfg{'defaults'}{'version'} lt '4.5.0.1') {
        $$cfg{'defaults'}{'use gui password'} = 0;
        $$cfg{'defaults'}{'gui password'} = '';
    } else {
        $$cfg{'defaults'}{'use gui password'} //= 0;
        $$cfg{'defaults'}{'gui password'} //= '';
    }
    $$cfg{'defaults'}{'use gui password tray'} //= 0;
    $$cfg{'defaults'}{'autostart shell upon start'} //= 0;
    $$cfg{'defaults'}{'tree on right side'} //= 0;
    $$cfg{'defaults'}{'prevent mouse over show tree'} //= 1;
    $$cfg{'defaults'}{'start PAC tree on'} //= 'connections';
    $$cfg{'defaults'}{'show connections tooltips'} //= 0;
    $$cfg{'defaults'}{'hide connections submenu'} //= 0;
    $$cfg{'defaults'}{'tree font'} //= 'Normal';
    $$cfg{'defaults'}{'info font'} //= 'monospace';
    $$cfg{'defaults'}{'use login shell to connect'} //= 0;
    $$cfg{'defaults'}{'audible bell'} //= 0;
    $$cfg{'defaults'}{'append group name'} //= 1;
    $$cfg{'defaults'}{'when no more tabs'} //= 0;
    $$cfg{'defaults'}{'selection to clipboard'} //= 1;
    $$cfg{'defaults'}{'remove control chars'} //= 0;
    $$cfg{'defaults'}{'allow more instances'} //= 0;
    $$cfg{'defaults'}{'show favourites in unity'} //= 0;
    $$cfg{'defaults'}{'capture xterm title'} //= 0;
    $$cfg{'defaults'}{'tree overlay scrolling'} //= 1;

    $$cfg{'defaults'}{'global variables'} //= {};
    $$cfg{'defaults'}{'local commands'} //= [];
    $$cfg{'defaults'}{'remote commands'} //= [];
    $$cfg{'defaults'}{'auto cluster'} //= {};

    if (!defined $$cfg{'defaults'}{'keepass'}) {
        $$cfg{'defaults'}{'keepass'}{'database'} = '';
        $$cfg{'defaults'}{'keepass'}{'password'} = '';
        $$cfg{'defaults'}{'keepass'}{'use_keepass'} = 0;
    }

    $$cfg{'tmp'}{'changed'} = 0;

    $$cfg{'environments'}{'__PAC_SHELL__'}{'_protected'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'parent'} = '__PAC__ROOT__';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'name'} = "PACShell";
    $$cfg{'environments'}{'__PAC_SHELL__'}{'description'} = "A shell on the local machine";
    $$cfg{'environments'}{'__PAC_SHELL__'}{'title'} = 'Local';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'ip'} = 'bash';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'port'} = 22;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'user'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'pass'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'search pass on KPX'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'send slow'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'method'} = 'PACShell';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'auth fallback'} = 1;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'options'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'auth type'} = 'manual';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'public key'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'passphrase user'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'passphrase'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'use proxy'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'use proxy'} = '0';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'save session logs'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'session log pattern'} = 'PACShell_<DATE_Y><DATE_M><DATE_D>_<TIME_H><TIME_M><TIME_S>.txt';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'session logs folder'} = _cfg_dir() . "/session_logs";
    $$cfg{'environments'}{'__PAC_SHELL__'}{'session logs amount'} = 10;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'use prepend command'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'prepend command'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'use postpend command'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'postpend command'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'quote command'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'quotepost command'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'send string active'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'send string txt'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'send string intro'} = 1;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'send string every'} = 60;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'send string only when idle'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'embed'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'mac'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'autoreconnect'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'remove control chars'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'startup launch'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'startup script'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'startup script name'} = '';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'favourite'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'autossh'} = 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'cluster'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'variables'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'screenshots'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'local before'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'expect'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'local connected'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'macros'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'local after'} = [];
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'use tab back color'} //= 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'tab back color'} //= '#000000000000'; # Black
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'back color'} //= '#000000000000'; # Black
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'command prompt'} //= $PACUtils::DEFAULT_COMMAND_PROMPT;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'username prompt'} //= $PACUtils::DEFAULT_USERNAME_PROMPT;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'password prompt'} //= $PACUtils::DEFAULT_PASSWORD_PROMPT;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'cursor shape'} //= 'block';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'open in tab'} //= 1;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal font'} //= 'Monospace 9';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal backspace'} //= 'auto';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal select words'} //= '-.:_/';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal character encoding'} //= 'UTF-8';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal scrollback lines'} //= -2;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal transparency'} //= 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal window hsize'} //= 800;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'terminal window vsize'} //= 600;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'text color'} //= '#cc62cc62cc62';
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'bold color'} //= $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'text color'};
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'bold color like text'} //= 1;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'timeout command'} //= 40;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'timeout connect'} //= 40;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'use personal settings'} //= 0;
    $$cfg{'environments'}{'__PAC_SHELL__'}{'terminal options'}{'audible bell'} //= 0;

    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        if ($uuid =~ /^HASH/go) {
            delete $$cfg{'environments'}{$uuid};
            next;
        } elsif($uuid =~ /^_tmp_/go) {
            delete $$cfg{'environments'}{$uuid};
            next;
        } elsif ($uuid =~ /^pacshell_PID/go) {
            delete $$cfg{'environments'}{$uuid};
            next;
        } elsif (! $uuid) {
            delete $$cfg{'environments'}{$uuid};
            next;
        } elsif (! defined $$cfg{'environments'}{$uuid}{'name'} && $uuid ne '__PAC__ROOT__') {
            delete $$cfg{'environments'}{$uuid};
            next;
        } elsif ($$cfg{'environments'}{$uuid}{'_is_group'}) {
            my $name = $$cfg{'environments'}{$uuid}{'name'};
            my $description = $$cfg{'environments'}{$uuid}{'description'};
            my $children = dclone($$cfg{'environments'}{$uuid}{'children'} // {});
            my $parent = $$cfg{'environments'}{$uuid}{'parent'};
            my @screenshots = @{$$cfg{'environments'}{$uuid}{'screenshots'} // []};
            my $protected = $$cfg{'environments'}{$uuid}{'_protected'} // 0;
            delete $$cfg{'environments'}{$uuid};
            $$cfg{'environments'}{$uuid}{'_is_group'} = 1;
            $$cfg{'environments'}{$uuid}{'name'} = $name;
            $$cfg{'environments'}{$uuid}{'description'} = $description;
            $$cfg{'environments'}{$uuid}{'parent'} = $parent;
            $$cfg{'environments'}{$uuid}{'children'}  = $children;
            @{$$cfg{'environments'}{$uuid}{'screenshots'}} = @screenshots;
            $$cfg{'environments'}{$uuid}{'_protected'}  = $protected;

            next;
        }

        if (!defined $$cfg{'environments'}{$uuid}{'name'}) {
            next;
        }

        $$cfg{'environments'}{$uuid}{'_protected'} //= 0;
        $$cfg{'environments'}{$uuid}{'parent'} //= '__PAC__ROOT__';
        $$cfg{'environments'}{$uuid}{'description'} //= "Connection with '$$cfg{'environments'}{$uuid}{'name'}'";
        $$cfg{'environments'}{$uuid}{'title'} //= $$cfg{'environments'}{$uuid}{'name'};
        $$cfg{'environments'}{$uuid}{'ip'} //= '';
        $$cfg{'environments'}{$uuid}{'port'} = defined $$cfg{'environments'}{$uuid}{'port'} ? $$cfg{'environments'}{$uuid}{'port'} || '0' : 22;
        $$cfg{'environments'}{$uuid}{'user'} //= '';
        $$cfg{'environments'}{$uuid}{'pass'} //= '';
        $$cfg{'environments'}{$uuid}{'search pass on KPX'} //= 0;
        $$cfg{'environments'}{$uuid}{'KPX title regexp'} //= ".*$$cfg{'environments'}{$uuid}{'title'}.*";
        $$cfg{'environments'}{$uuid}{'send slow'} //= 0;
        $$cfg{'environments'}{$uuid}{'method'} //= 'SSH';
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*ssh.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'SSH';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*sftp.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'SFTP';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*telnet.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'Telnet';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*ftp.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'FTP';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*cu$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'Serial (cu)';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*remote-tty.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'Serial (remote-tty)';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*3270.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'IBM 3270/5250';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} eq 'RDP (Windows)') {
            $$cfg{'environments'}{$uuid}{'method'} = 'RDP (rdesktop)';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*vncviewer.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'VNC';
        }
        if ($$cfg{'environments'}{$uuid}{'method'} =~ /^.*generic.*$/go) {
            $$cfg{'environments'}{$uuid}{'method'} = 'Generic Command';
        }
        $$cfg{'environments'}{$uuid}{'auth fallback'} //= 1;
        $$cfg{'environments'}{$uuid}{'options'} //= '';
        if ($$cfg{'environments'}{$uuid}{'method'} eq 'SSH') {
            $$cfg{'environments'}{$uuid}{'options'} =~ s/(-[DLR])\s+(.*?)\/(.*?)\/(.*?)\/(.*?)/$1 $2:$3:$4:$5/go;
        }
        if ($$cfg{'environments'}{$uuid}{'options'} =~ s/\s+\-o\s+\"IdentityFile(\s+|\s*=\s*)(.+)\"//gio) {
            my $idfile = $2;
            $$cfg{'environments'}{$uuid}{'auth type'} = 'publickey';
            $$cfg{'environments'}{$uuid}{'passphrase user'} //= $$cfg{'environments'}{$uuid}{'user'} // '';
            $$cfg{'environments'}{$uuid}{'passphrase'} //= $$cfg{'environments'}{$uuid}{'pass'} // '';
            $$cfg{'environments'}{$uuid}{'public key'} = $idfile;
        }
        $$cfg{'environments'}{$uuid}{'auth type'} //= $$cfg{'environments'}{$uuid}{'manual'} // '0' ? 'manual' : 'userpass';
        $$cfg{'environments'}{$uuid}{'public key'} //= '';
        $$cfg{'environments'}{$uuid}{'passphrase user'} //= '';
        $$cfg{'environments'}{$uuid}{'passphrase'} //= '';
        $$cfg{'environments'}{$uuid}{'use proxy'} //= 0;
        $$cfg{'environments'}{$uuid}{'use proxy'} ||= '0';
        $$cfg{'environments'}{$uuid}{'proxy ip'} //= '';
        $$cfg{'environments'}{$uuid}{'proxy port'} //= 8080;
        $$cfg{'environments'}{$uuid}{'proxy user'} //= '';
        $$cfg{'environments'}{$uuid}{'proxy pass'} //= '';
        $$cfg{'environments'}{$uuid}{'save session logs'} //= 0;
        $$cfg{'environments'}{$uuid}{'session log pattern'} //= '<UUID>_<NAME>_<DATE_Y><DATE_M><DATE_D>_<TIME_H><TIME_M><TIME_S>.txt';
        $$cfg{'environments'}{$uuid}{'session logs folder'} //= _cfg_dir() . "/session_logs";
        $$cfg{'environments'}{$uuid}{'session logs amount'} //= 10;
        $$cfg{'environments'}{$uuid}{'use prepend command'} //= 0;
        $$cfg{'environments'}{$uuid}{'prepend command'} //= '';
        $$cfg{'environments'}{$uuid}{'use postpend command'} //= 0;
        $$cfg{'environments'}{$uuid}{'postpend command'} //= '';
        $$cfg{'environments'}{$uuid}{'quote command'} //= 0;
        $$cfg{'environments'}{$uuid}{'quotepost command'} //= 0;
        $$cfg{'environments'}{$uuid}{'send string active'} //= 0;
        $$cfg{'environments'}{$uuid}{'send string txt'} //= '';
        $$cfg{'environments'}{$uuid}{'send string intro'} //= 1;
        $$cfg{'environments'}{$uuid}{'send string every'} //= 60;
        $$cfg{'environments'}{$uuid}{'send string only when idle'} //= 0;
        $$cfg{'environments'}{$uuid}{'embed'} //= 0;
        $$cfg{'environments'}{$uuid}{'mac'} //= '';
        $$cfg{'environments'}{$uuid}{'autoreconnect'} //= 0;
        $$cfg{'environments'}{$uuid}{'startup launch'} //= 0;
        $$cfg{'environments'}{$uuid}{'startup script'} //= 0;
        $$cfg{'environments'}{$uuid}{'startup script name'} //= '';
        $$cfg{'environments'}{$uuid}{'favourite'} //= 0;
        $$cfg{'environments'}{$uuid}{'remove control chars'}//= 0;
        $$cfg{'environments'}{$uuid}{'autossh'} //= 0;
        $$cfg{'environments'}{$uuid}{'cluster'} //= [];
        $$cfg{'environments'}{$uuid}{'use sudo'} //= 0;

        if (! defined $$cfg{'environments'}{$uuid}{'variables'}) {
            $$cfg{'environments'}{$uuid}{'variables'} =[];
        } else {
            my $i = 0;
            foreach my $hash (@{$$cfg{'environments'}{$uuid}{'variables'}}) {
                if (! ref($hash)) {
                    delete $$cfg{'environments'}{$uuid}{'variables'}[$i];
                    $$cfg{'environments'}{$uuid}{'variables'}[$i]{'hide'} = 0;
                    $$cfg{'environments'}{$uuid}{'variables'}[$i]{'txt'} = $hash // '';
                } else {
                    $$hash{'hide'} //= 0;
                    $$hash{'txt'} //= '';
                }
                ++$i;
            }
        }

        if (! defined $$cfg{'environments'}{$uuid}{'screenshots'}) {
            $$cfg{'environments'}{$uuid}{'screenshots'} = [];
            if (defined $$cfg{'environments'}{$uuid}{'screenshot'}) {
                if (-f $$cfg{'environments'}{$uuid}{'screenshot'}) {
                    push(@{$$cfg{'environments'}{$uuid}{'screenshots'}}, $$cfg{'environments'}{$uuid}{'screenshot'});
                }
            }
            delete $$cfg{'environments'}{$uuid}{'screenshot'};
        } else {
            if (defined $$cfg{'environments'}{$uuid}{'screenshot'}) {
                delete $$cfg{'environments'}{$uuid}{'screenshot'};
            }
        }

        if (! defined $$cfg{'environments'}{$uuid}{'local before'}) {
            $$cfg{'environments'}{$uuid}{'local before'} = [];
        } else {
            my $i = 0;
            foreach my $hash (@{$$cfg{'environments'}{$uuid}{'local before'}}) {
                if (! ref($hash)) {
                    delete $$cfg{'environments'}{$uuid}{'local before'}[$i];
                    $$cfg{'environments'}{$uuid}{'local before'}[$i]{'default'} //= 1;
                    $$cfg{'environments'}{$uuid}{'local before'}[$i]{'ask'} = 1;
                    $$cfg{'environments'}{$uuid}{'local before'}[$i]{'command'} = $hash // '';
                } else {
                    $$hash{'ask'} //= 1;
                    $$hash{'default'} //= 1;
                    $$hash{'command'} //= '';
                }
                ++$i;
            }
        }

        if (! defined $$cfg{'environments'}{$uuid}{'expect'}) {
            $$cfg{'environments'}{$uuid}{'expect'} = [];
        } else {
            my $i = 0;
            foreach my $hash (@{$$cfg{'environments'}{$uuid}{'expect'}}) {
                if (! ref($hash)) {
                    delete $$cfg{'environments'}{$uuid}{'expect'}[$i];
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'active'} = 1;
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'expect'} = '';
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'send'} = '';
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'hidden'} = 0;
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'return'} = 1;
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'on_match'} = -1;
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'on_fail'} = -1;
                    $$cfg{'environments'}{$uuid}{'expect'}[$i]{'time_out'} = -1;
                } else {
                    $$hash{'active'} //= 1;
                    $$hash{'expect'} //= '';
                    $$hash{'hidden'} //= 0;
                    $$hash{'send'} //= '';
                    $$hash{'return'} //= 1;
                    $$hash{'on_match'} //= -1;
                    $$hash{'on_fail'} //= -1;
                    $$hash{'time_out'} //= -1;
                }
                ++$i;
            }
        }

        if (! defined $$cfg{'environments'}{$uuid}{'local connected'}) {
            $$cfg{'environments'}{$uuid}{'local connected'} = [];
        } else {
            my $i = 0;
            foreach my $hash (@{$$cfg{'environments'}{$uuid}{'local connected'}}) {
                if (! ref($hash)) {
                    delete $$cfg{'environments'}{$uuid}{'local connected'}[$i];
                    $$cfg{'environments'}{$uuid}{'local connected'}[$i]{'confirm'} = 0;
                    $$cfg{'environments'}{$uuid}{'local connected'}[$i]{'txt'} = $hash // '';
                } else {
                    $$hash{'confirm'} //= 0;
                    $$hash{'txt'} //= '';
                }
                ++$i;
            }
        }

        if (! defined $$cfg{'environments'}{$uuid}{'macros'}) {
            $$cfg{'environments'}{$uuid}{'macros'} = [];
        } else {
            my $i = 0;
            foreach my $hash (@{$$cfg{'environments'}{$uuid}{'macros'}}) {
                if (! ref($hash)) {
                    delete $$cfg{'environments'}{$uuid}{'macros'}[$i];
                    $$cfg{'environments'}{$uuid}{'macros'}[$i]{'confirm'} = 0;
                    $$cfg{'environments'}{$uuid}{'macros'}[$i]{'intro'} = 1;
                    $$cfg{'environments'}{$uuid}{'macros'}[$i]{'txt'} = $hash // '';
                } else {
                    $$hash{'confirm'} //= 0;
                    $$hash{'intro'} //= 1;
                    $$hash{'txt'} //= '';
                }
                ++$i;
            }
        }

        if (! defined $$cfg{'environments'}{$uuid}{'local after'}) {
            $$cfg{'environments'}{$uuid}{'local after'} = [];
        } else {
            my $i = 0;
            foreach my $hash (@{$$cfg{'environments'}{$uuid}{'local after'}}) {
                if (! ref($hash)) {
                    delete $$cfg{'environments'}{$uuid}{'local after'}[$i];
                    $$cfg{'environments'}{$uuid}{'local after'}[$i]{'default'} = 1;
                    $$cfg{'environments'}{$uuid}{'local after'}[$i]{'ask'} = 1;
                    $$cfg{'environments'}{$uuid}{'local after'}[$i]{'command'} = $hash // '';
                } else {
                    $$hash{'ask'} //= 1;
                    $$hash{'default'} //= 1;
                    $$hash{'command'} //= '';
                }
                ++$i;
            }
        }
        if (! defined $$cfg{'environments'}{$uuid}{'terminal options'}) {
            $$cfg{'environments'}{$uuid}{'terminal options'}{'use tab back color'} = 0;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'tab back color'} = '#000000000000'; # Black
            $$cfg{'environments'}{$uuid}{'terminal options'}{'back color'} = '#000000000000'; # Black
            $$cfg{'environments'}{$uuid}{'terminal options'}{'command prompt'} = $PACUtils::DEFAULT_COMMAND_PROMPT;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'username prompt'} = $PACUtils::DEFAULT_USERNAME_PROMPT;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'password prompt'} = $PACUtils::DEFAULT_PASSWORD_PROMPT;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'cursor shape'}  = 'block';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'open in tab'} = 1;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal font'} = 'Monospace 9';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal select words'} = '-.:_/';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal backspace'} = 'auto';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal character encoding'} = 'UTF-8';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal scrollback lines'} = -2;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal transparency'} = 0;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal window hsize'} = 800;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal window vsize'} = 600;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'text color'} = '#cc62cc62cc62';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'bold color'} = $$cfg{'environments'}{$uuid}{'terminal options'}{'text color'};
            $$cfg{'environments'}{$uuid}{'terminal options'}{'bold color like text'} = 1;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'timeout command'} = 40;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'timeout connect'} = 40;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'use personal settings'} = 0;
        } else {
            $$cfg{'environments'}{$uuid}{'terminal options'}{'use tab back color'} //= 0;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'tab back color'} //= '#000000000000'; # Black
            $$cfg{'environments'}{$uuid}{'terminal options'}{'back color'} //= '#000000000000'; # Black
            $$cfg{'environments'}{$uuid}{'terminal options'}{'command prompt'} //= $PACUtils::DEFAULT_COMMAND_PROMPT;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'username prompt'} //= $PACUtils::DEFAULT_USERNAME_PROMPT;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'password prompt'} //= $PACUtils::DEFAULT_PASSWORD_PROMPT;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'cursor shape'} //= 'block';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'open in tab'} //= 1;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal font'} //= 'Monospace 9';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal select words'} //= '-.:_/';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal backspace'} //= 'auto';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal character encoding'} //= 'UTF-8';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal scrollback lines'} //= -2;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal transparency'} //= 0;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal window hsize'} //= 800;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'terminal window vsize'} //= 600;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'text color'} //= '#cc62cc62cc62';
            $$cfg{'environments'}{$uuid}{'terminal options'}{'bold color'} //= $$cfg{'environments'}{$uuid}{'terminal options'}{'text color'};
            $$cfg{'environments'}{$uuid}{'terminal options'}{'bold color like text'} //= 1;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'timeout command'} //= 40;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'timeout connect'} //= 40;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'use personal settings'} //= 0;
            $$cfg{'environments'}{$uuid}{'terminal options'}{'audible bell'} //= 0;
        }
    }

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Config::SanityCheck — legacy schema enforcement and migration

=head1 SYNOPSIS

    use PAC::Config::SanityCheck;

    PAC::Config::SanityCheck::run(\%cfg);
    # %cfg now has all expected default keys, with legacy migrations
    # applied.

=head1 DESCRIPTION

Mechanical extraction of C<PACUtils::_cfgSanityCheck>. Walks the config
hash, fills in missing default keys, applies coercions for legacy
formats, and migrates older config layouts to the current shape.

This is the legacy code — gradually being replaced by the declarative
L<PAC::Config::Schema>. For now both coexist: this module handles
all keys that pre-date the schema, the schema handles everything new.

=head1 PUBLIC API

=over

=item run($cfg)

Mutates the cfg hashref in place to bring it into a known-good state.
Returns 1.

=back

=head1 SEE ALSO

L<PAC::Config::Schema>, L<PACUtils>.

=cut
