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
        my $tour_secs = $ENV{AUTOMP_TOUR_SECS} // 30;

        # Step 1: open Preferences
        Glib::Timeout->add(2000, sub {
            print STDERR "[AutoMP] tour: open preferences\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                $main->{_GUI}{configBtn}->clicked if $main && $main->{_GUI}{configBtn};
            };
            return 0;
        });

        # Step 2: switch Preferences top notebook to Look and Feel tab
        Glib::Timeout->add(4500, sub {
            print STDERR "[AutoMP] tour: prefs -> Look and Feel\n";
            eval {
                my $cfg_obj = $PACMain::FUNCS{_CONFIG};
                if ($cfg_obj && $cfg_obj->{_GUI}{nbInOptions}) {
                    $cfg_obj->{_GUI}{nbInOptions}->set_current_page(1);
                }
            };
            return 0;
        });

        # Step 3: switch to Advanced
        Glib::Timeout->add(6500, sub {
            print STDERR "[AutoMP] tour: prefs -> Advanced\n";
            eval {
                my $cfg_obj = $PACMain::FUNCS{_CONFIG};
                if ($cfg_obj && $cfg_obj->{_GUI}{nbInOptions}) {
                    $cfg_obj->{_GUI}{nbInOptions}->set_current_page(2);
                }
            };
            return 0;
        });

        # Step 4: switch sidebar to Terminal Options
        Glib::Timeout->add(8500, sub {
            print STDERR "[AutoMP] tour: prefs sidebar -> Terminal Options\n";
            eval {
                my $cfg_obj = $PACMain::FUNCS{_CONFIG};
                if ($cfg_obj && $cfg_obj->{_GUI}{nbPreferences}) {
                    $cfg_obj->{_GUI}{nbPreferences}->set_current_page(1);
                }
            };
            return 0;
        });

        # Step 5: open Edit Connection on first non-group cfg item
        Glib::Timeout->add(11500, sub {
            print STDERR "[AutoMP] tour: open Edit Connection\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                my $cfg = $main->{_CFG};
                my $uuid;
                for my $k (keys %{$cfg->{environments}}) {
                    next if $k eq '__PAC__ROOT__';
                    next if $cfg->{environments}{$k}{_is_group};
                    $uuid = $k; last;
                }
                if ($uuid) {
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

        # Step 6: switch Edit Connection sidebar to Terminal Options
        Glib::Timeout->add(14500, sub {
            print STDERR "[AutoMP] tour: edit sidebar -> Terminal Options\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                my $edit = $main->{_EDIT};
                if ($edit && $edit->{_GUI}{nb}) {
                    $edit->{_GUI}{nb}->set_current_page($edit->{_GUI}{nb}->get_n_pages - 1);
                }
            };
            return 0;
        });

        # Step 7: open About
        Glib::Timeout->add(17500, sub {
            print STDERR "[AutoMP] tour: open about\n";
            eval {
                my $main = $PACMain::FUNCS{_MAIN};
                $main->{_GUI}{aboutBtn}->clicked if $main && $main->{_GUI}{aboutBtn};
            };
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
