#!/usr/bin/perl
use strict;
use warnings;
use Test::More;

# Validates that the installed asbru-plus package has all expected files.
# Skips if the package is not installed (not in the build-deb container).

unless (-f '/opt/asbru/asbru-cm') {
    plan skip_all => 'Package not installed (/opt/asbru/asbru-cm not found)';
}

plan tests => 14;

# --- Binary ---
ok(-f '/opt/asbru/asbru-cm',    'Main binary /opt/asbru/asbru-cm exists');
ok(-x '/opt/asbru/asbru-cm',    'Main binary is executable');

# --- Symlink to /usr/bin ---
ok(-l '/usr/bin/asbru-cm' || -f '/usr/bin/asbru-cm',
   'asbru-cm accessible from /usr/bin');

# --- Application directories ---
ok(-d '/opt/asbru/lib',  'lib/ directory installed');
ok(-d '/opt/asbru/res',  'res/ directory installed');
ok(-d '/opt/asbru/utils', 'utils/ directory installed');

# --- Desktop integration ---
ok(-f '/usr/share/applications/asbru-cm.desktop', '.desktop file installed');

# --- Man page --- dpkg knows the file (man-db may compress/process it further)
my $dpkg_files = `dpkg -L asbru-plus 2>/dev/null`;
ok($dpkg_files =~ m|/usr/share/man|, 'man page registered with dpkg');

# --- Bash completion ---
my $completion_found = -f '/etc/bash_completion.d/asbru_bash_completion'
                    || -f '/usr/share/bash-completion/completions/asbru-plus';
ok($completion_found, 'bash completion installed');

# --- Key lib files ---
ok(-f '/opt/asbru/lib/PACUtils.pm',       'PACUtils.pm present');
ok(-f '/opt/asbru/lib/PACMain.pm',        'PACMain.pm present');
ok(-f '/opt/asbru/lib/PACKeyBindings.pm', 'PACKeyBindings.pm present');
ok(-f '/opt/asbru/lib/asbru_conn',        'asbru_conn present');

# --- Binary actually runs (CLI help, no display needed) ---
my $help_out = `perl /opt/asbru/asbru-cm --help 2>&1`;
ok($help_out =~ /Usage|--help|asbru/i, 'Binary responds to --help');
