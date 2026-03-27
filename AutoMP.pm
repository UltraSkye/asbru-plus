package AutoMP;
use strict;
use warnings;

# Loaded via -MAutoMP before asbru-cm runs. Stubs interactive prompts and
# (when AUTOMP_DRIVE=1) drives the GUI through Preferences / About / etc.
# to allow unattended screenshots.
#
# Configuration via env vars:
#   AUTOMP_PWD=secret         password to feed to _wEnterValue
#   AUTOMP_CONFIRM=yes|no     answer for _wConfirm (default yes)
#   AUTOMP_DRIVE=1            after main loop starts, schedule GUI tour
#   AUTOMP_TOUR_SECS=12       length of GUI tour before quit

INIT {
    require PACUtils;
    require PACMain;
    no warnings 'redefine';
    my $pwd       = $ENV{AUTOMP_PWD}     // 'test12345';
    my $confirm   = ($ENV{AUTOMP_CONFIRM} // 'yes') eq 'yes' ? 1 : 0;
    my @responses = ($pwd, $pwd, $pwd);
    my $idx = 0;

    my $confirm_stub = sub {
        print STDERR "[AutoMP] _wConfirm -> ", ($confirm ? 'YES' : 'NO'), "\n";
        return $confirm;
    };
    my $enter_stub = sub {
        my $r = $responses[$idx++] // '';
        print STDERR "[AutoMP] _wEnterValue -> '$r'\n";
        return $r;
    };
    my $msg_stub = sub {
        my (undef, $msg) = @_;
        print STDERR "[AutoMP] _wMessage: " . ($msg // '') . "\n";
        return undef;
    };

    *PACUtils::_wConfirm    = $confirm_stub;
    *PACUtils::_wEnterValue = $enter_stub;
    *PACUtils::_wMessage    = $msg_stub;
    *PACMain::_wConfirm     = $confirm_stub;
    *PACMain::_wEnterValue  = $enter_stub;
    *PACMain::_wMessage     = $msg_stub;

    print STDERR "[AutoMP] hooks installed (pwd='$pwd' confirm=$confirm)\n";

    if ($ENV{AUTOMP_DRIVE}) {
        require Glib;
        my $tour_secs = $ENV{AUTOMP_TOUR_SECS} // 18;
        Glib::Timeout->add(2000, sub {
            print STDERR "[AutoMP] tour: opening preferences\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                $main->{_GUI}{configBtn}->clicked if $main && $main->{_GUI}{configBtn};
            };
            return 0;
        });
        Glib::Timeout->add(5000, sub {
            print STDERR "[AutoMP] tour: opening about\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                $main->{_GUI}{aboutBtn}->clicked if $main && $main->{_GUI}{aboutBtn};
            };
            return 0;
        });
        Glib::Timeout->add(8000, sub {
            print STDERR "[AutoMP] tour: opening edit on test connection\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                # Find a non-group connection in cfg, open edit on it
                my $cfg = $main->{_CFG};
                my $uuid;
                for my $k (keys %{$cfg->{environments}}) {
                    next if $k eq '__PAC__ROOT__';
                    next if $cfg->{environments}{$k}{_is_group};
                    $uuid = $k; last;
                }
                if ($uuid && $main->{_GUI}{connEditBtn}) {
                    print STDERR "[AutoMP] selecting $uuid\n";
                    require PACEdit;
                    if (!$main->{_EDIT}) {
                        $main->{_EDIT} = PACEdit->new($cfg, $main);
                    }
                    $main->{_EDIT}->show($uuid);
                }
            };
            print STDERR "[AutoMP] edit err: $@\n" if $@;
            return 0;
        });
        Glib::Timeout->add($tour_secs * 1000, sub {
            print STDERR "[AutoMP] tour: quit\n";
            Gtk3::main_quit() if Gtk3->can('main_quit');
            return 0;
        });
    }
}

1;
