package PAC::WakeOnLan;

###############################################################################
# PAC::WakeOnLan — Magic-packet builder, sender, and the WoL dialog extracted
# from PACUtils.pm.
#
# Public API:
#   PAC::WakeOnLan::magic_packet($mac)
#       Pure: returns the 102-byte magic packet for $mac (XX:XX:XX:XX:XX:XX).
#       Dies on malformed MAC. Useful in tests.
#   PAC::WakeOnLan::send_magic_packet($mac, $ip, $port, $broadcast)
#       Pure (modulo OS): opens a UDP socket, sends the packet, returns
#       1 on success or dies. $broadcast=1 sends to 255.255.255.255 instead
#       of $ip.
#   PAC::WakeOnLan::_wakeOnLan($cfg, $uuid)
#       Legacy entry point — the modal Gtk dialog. Same signature as the
#       previous PACUtils::_wakeOnLan; PACUtils now delegates to this.
###############################################################################

use strict;
use warnings;
use utf8;

use Socket;
use Carp qw(croak);

use Gtk3;

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Pure helpers (testable without Gtk / network)
#-------------------------------------------------------------------------

# magic_packet($mac) -> 102-byte string (6×0xFF + 16×packed-MAC)
sub magic_packet {
    my $mac = shift // croak 'magic_packet: MAC required';
    croak "magic_packet: malformed MAC '$mac'"
        unless $mac =~ /^[\da-fA-F]{2}([:-][\da-fA-F]{2}){5}$/;
    (my $clean = $mac) =~ s/[:-]//g;
    return ("\xff" x 6) . (pack('H12', $clean) x 16);
}

# send_magic_packet($mac, $ip, $port, $broadcast) -> 1 (or die)
sub send_magic_packet {
    my ($mac, $ip, $port, $broadcast) = @_;
    $port //= 9;
    $broadcast //= 0;
    my $magic = magic_packet($mac);

    socket(my $s, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
        or croak "WoL: cannot create socket: $!";
    if ($broadcast) {
        setsockopt($s, SOL_SOCKET, SO_BROADCAST, 1)
            or croak "WoL: cannot set SO_BROADCAST: $!";
    }

    my ($size, $paddr, $ipaddr);
    if ($broadcast) {
        $size = 0;
        $paddr = sockaddr_in(0x2fff, INADDR_BROADCAST);
    } else {
        $size = length($magic);
        if ($ip) {
            $ipaddr = inet_aton($ip) or croak "WoL: unknown host: $ip";
        }
        $paddr = sockaddr_in($port, $ipaddr)
            or croak "WoL: sockaddr_in failed: $!";
    }

    send($s, $magic, $size, $paddr) or croak "WoL: send failed: $!";
    # Best-effort retries for unreliable UDP delivery.
    send($s, $magic, $size, $paddr) for 1 .. 2;
    if ($ipaddr) {
        send($s, $magic, $size, sockaddr_in($_, $ipaddr)) for (7, 7, 7, 9, 9, 9);
    }
    close $s;
    return 1;
}

#-------------------------------------------------------------------------
# Modal dialog (kept signature-compatible with the old PACUtils sub)
#-------------------------------------------------------------------------

sub _wakeOnLan {
    my $cfg = shift;
    my $uuid = shift;

    require Net::Ping;
    require Net::ARP;
    require Socket6;
    Socket6->import(qw(inet_ntoa));

    my $port = 9;
    my $ping_port = 7;

    my $ip = $$cfg{ip} // '';
    my $mac = ($$cfg{mac} // '00:00:00:00:00:00') || '00:00:00:00:00:00';

    if (defined $uuid) {
        $ip = PACUtils::_subst($ip, $PACMain::FUNCS{_MAIN}{_CFG}, $uuid);
    }
    my $packed_ip = gethostbyname($ip);
    if (defined $packed_ip) {
        $ip = inet_ntoa($packed_ip);
    }

    my %w;

    $w{window}{data} = Gtk3::Dialog->new_with_buttons(
        "$PACUtils::APPNAME (v$PACUtils::APPVERSION) : Wake On LAN",
        undef,
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok'
    );
    $w{window}{data}->set_default_response('ok');
    $w{window}{data}->set_position('center');
    $w{window}{data}->set_icon_name('asbru-app-big');
    $w{window}{data}->set_size_request(480, 0);
    $w{window}{data}->set_resizable(0);
    $w{window}{data}->set_transient_for($PACMain::FUNCS{_MAIN}{_GUI}{main});

    $w{window}{gui}{banner} = PACUtils::_createBanner('asbru-wol.svg', 'Wake On LAN');
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{banner}, 0, 1, 0);

    $w{window}{gui}{hbox} = Gtk3::Box->new('horizontal', 0);
    $w{window}{gui}{hbox}->set_margin_top(10);
    $w{window}{gui}{hbox}->set_margin_bottom(10);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{hbox}, 1, 1, 0);

    $w{window}{gui}{lblup} = Gtk3::Label->new();
    $w{window}{gui}{hbox}->pack_start($w{window}{gui}{lblup}, 1, 1, 0);
    $w{window}{gui}{lblup}->set_markup("<b>Enter the following data and press 'OK' to send Magic Packet:</b>");

    $w{window}{gui}{table} = Gtk3::Grid->new();
    $w{window}{gui}{table}->set_column_spacing(6);
    $w{window}{gui}{table}->set_row_spacing(4);
    $w{window}{gui}{table}->set_margin_top(10);
    $w{window}{gui}{table}->set_margin_bottom(10);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{table}, 1, 1, 0);

    $w{window}{gui}{lblmac} = Gtk3::Label->new();
    $w{window}{gui}{table}->attach($w{window}{gui}{lblmac}, 0, 0, 1, 1);
    $w{window}{gui}{lblmac}->set_text('MAC Address: ');

    $w{window}{gui}{entrymac} = Gtk3::Entry->new();
    $w{window}{gui}{entrymac}->set_hexpand(1);
    $w{window}{gui}{table}->attach($w{window}{gui}{entrymac}, 1, 0, 1, 1);
    $w{window}{gui}{entrymac}->set_text($mac);
    $w{window}{gui}{entrymac}->set_activates_default(1);
    $w{window}{gui}{entrymac}->grab_focus();

    $w{window}{gui}{iconmac} = Gtk3::Image->new_from_icon_name('dialog-error', 'menu');
    $w{window}{gui}{table}->attach($w{window}{gui}{iconmac}, 2, 0, 1, 1);

    $w{window}{gui}{lblip} = Gtk3::Label->new();
    $w{window}{gui}{table}->attach($w{window}{gui}{lblip}, 0, 1, 1, 1);
    $w{window}{gui}{lblip}->set_text('Host: ');

    $w{window}{gui}{entryip} = Gtk3::Entry->new();
    $w{window}{gui}{entryip}->set_hexpand(1);
    $w{window}{gui}{table}->attach($w{window}{gui}{entryip}, 1, 1, 1, 1);
    $w{window}{gui}{entryip}->set_text($ip);
    $w{window}{gui}{entryip}->set_sensitive(0);
    $w{window}{gui}{entryip}->set_activates_default(0);

    $w{window}{gui}{iconip} = Gtk3::Image->new_from_icon_name('emblem-ok', 'menu');
    $w{window}{gui}{table}->attach($w{window}{gui}{iconip}, 2, 1, 1, 1);

    $w{window}{gui}{lblport} = Gtk3::Label->new();
    $w{window}{gui}{table}->attach($w{window}{gui}{lblport}, 0, 2, 1, 1);
    $w{window}{gui}{lblport}->set_text('Port Number: ');

    $w{window}{gui}{entryport} = Gtk3::SpinButton->new_with_range(1, 65535, 1);
    $w{window}{gui}{entryport}->set_hexpand(1);
    $w{window}{gui}{table}->attach($w{window}{gui}{entryport}, 1, 2, 1, 1);
    $w{window}{gui}{entryport}->set_value($port);
    $w{window}{gui}{entryport}->set_activates_default(1);

    $w{window}{gui}{cbbroadcast} = Gtk3::CheckButton->new_with_label('Send to broadcast');
    $w{window}{gui}{cbbroadcast}->set_active(1);
    $w{window}{gui}{cbbroadcast}->set_sensitive($ip);
    $w{window}{gui}{hbox2} = Gtk3::Box->new('horizontal', 0);
    $w{window}{gui}{hbox2}->set_halign('center');
    $w{window}{gui}{hbox2}->set_margin_top(10);
    $w{window}{gui}{hbox2}->set_margin_bottom(10);
    $w{window}{gui}{hbox2}->pack_start($w{window}{gui}{cbbroadcast}, 1, 1, 0);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{hbox2}, 0, 1, 0);

    $w{window}{gui}{lblstatus} = Gtk3::Label->new();
    $w{window}{gui}{lblstatus}->set_margin_bottom(20);
    $w{window}{data}->get_content_area->pack_start($w{window}{gui}{lblstatus}, 0, 1, 0);
    $w{window}{gui}{lblstatus}->set_text("Checking MAC for '$ip' ...");

    $w{window}{data}->show_all();

    my $mac_re = qr/^[\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}$/;

    $w{window}{gui}{cbbroadcast}->signal_connect('toggled' => sub {
        $w{window}{gui}{entryport}->set_sensitive(!$w{window}{gui}{cbbroadcast}->get_active());
        return 0;
    });

    $w{window}{gui}{entrymac}->signal_connect('event' => sub {
        $w{window}{data}->get_action_area->foreach(sub {
            return 1 if $_[0]->get_label ne 'gtk-ok';
            my $valid = $w{window}{gui}{entrymac}->get_chars(0, -1) =~ $mac_re;
            $w{window}{gui}{iconmac}->set_from_icon_name($valid ? 'emblem-ok' : 'dialog-error', 'menu');
            $_[0]->set_sensitive($valid ? 1 : 0);
        });
        return 0;
    });

    # Try to resolve a remote host's MAC if we don't have one yet.
    if ($ip && ($mac eq '00:00:00:00:00:00')) {
        $w{window}{gui}{table}->set_sensitive(0);
        Gtk3::main_iteration while Gtk3::events_pending;
        my $PING = Net::Ping->new('tcp');
        $PING->tcp_service_check(1);
        $PING->port_number($ping_port);
        my $up = $PING->ping($ip, '1');
        $mac = Net::ARP::arp_lookup('', $ip);
        if (!$mac || $mac eq 'unknown' || $mac eq '00:00:00:00:00:00') {
            $up = $PING->ping($ip, '1');
            $mac = Net::ARP::arp_lookup('', $ip);
            $mac = $mac eq 'unknown' ? '00:00:00:00:00:00' : $mac;
        }
        $w{window}{gui}{iconip}->set_from_icon_name($up ? 'network-transmit-receive' : 'network-offline', 'menu');
        $w{window}{gui}{entrymac}->set_text($mac);
        $w{window}{gui}{entrymac}->select_region(0, length($mac));
        $w{window}{gui}{lblstatus}->set_text("'$ip' TCP port $ping_port seems to be " . ($up ? 'REACHABLE' : 'UNREACHABLE'));
        $w{window}{gui}{table}->set_sensitive(1);
        $w{window}{gui}{entrymac}->grab_focus();
        $w{window}{data}->get_action_area->foreach(sub {
            return 1 if $_[0]->get_label ne 'gtk-ok';
            $_[0]->set_sensitive($w{window}{gui}{entrymac}->get_chars(0, -1) =~ $mac_re ? 1 : 0);
        });
        Gtk3::main_iteration while Gtk3::events_pending;
    } elsif (!$ip) {
        $w{window}{gui}{entrymac}->set_text($mac);
        $w{window}{gui}{entrymac}->select_region(0, length($mac));
        $w{window}{gui}{lblstatus}->set_text('No IP/hostname to test reachability');
    } else {
        $w{window}{gui}{entrymac}->set_text($mac);
        $w{window}{gui}{entrymac}->select_region(0, length($mac));
        $w{window}{gui}{lblstatus}->set_text('Selected saved MAC');
    }

    $w{window}{gui}{entryport}->set_sensitive(!$w{window}{gui}{cbbroadcast}->get_active());

    my $ok = $w{window}{data}->run();
    $mac = $w{window}{gui}{entrymac}->get_chars(0, -1);
    $w{window}{data}->destroy();

    return 0 if $ok ne 'ok';

    $$cfg{mac} = $mac;
    my $broadcast = $w{window}{gui}{cbbroadcast}->get_active();

    eval {
        send_magic_packet($mac, $ip, $port, $broadcast);
    };
    if ($@) {
        PAC::Dialog::_wMessage($PACMain::FUNCS{_MAIN}{_GUI}{main},
            "ERROR: Sending magic packet to $ip (MAC: $mac) failed:\n$@");
        return $mac;
    }
    PAC::Dialog::_wMessage($PACMain::FUNCS{_MAIN}{_GUI}{main},
        "Wake On Lan 'Magic Packet'\nCORRECTLY sent to "
        . ($broadcast ? 'BROADCAST' : "IP: $ip") . "\n(MAC: $mac)");

    return $mac;
}

1;
