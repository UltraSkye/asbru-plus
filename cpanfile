# cpanfile — single source of truth for CPAN dependencies.
#
# Versions are pinned to what ships in the oldest supported distro
# (Debian Bullseye / Ubuntu 22.04 Jammy). Anything newer auto-satisfies.
# CI matrix verifies these on Perl 5.34, 5.38, 5.40.
#
# Install all deps locally with:
#     cpanm --installdeps .
# Or via system packages (preferred for production):
#     see README.md → Manual dependencies

requires 'perl', '5.030';

# ── Core runtime ──────────────────────────────────────────────────────
requires 'Carp',                 '1.50';
requires 'Encode',               '3.06';
requires 'Exporter',             '5.74';
requires 'Fcntl',                '1.13';
requires 'File::Basename',       '2.85';
requires 'File::Copy',           '2.34';
requires 'File::Spec',           '3.78';
requires 'File::Temp',           '0.2311';
requires 'File::stat',           '1.09';
requires 'FindBin',              '1.51';
requires 'Getopt::Long',         '2.52';
requires 'IO::Socket::INET',     '1.49';
requires 'IPC::Open2',           '1.05';
requires 'IPC::Open3',           '1.22';
requires 'List::Util',           '1.55';
requires 'POSIX',                '1.94';
requires 'Scalar::Util',         '1.55';
requires 'Socket',               '2.030';
requires 'Storable',             '3.21';
requires 'Sys::Hostname',        '1.23';
requires 'Time::HiRes',          '1.9764';

# ── Crypto ────────────────────────────────────────────────────────────
requires 'Crypt::CBC',           '2.36';
requires 'Crypt::Rijndael',      '1.16';
requires 'Digest::SHA',          '6.02';
requires 'Crypt::PBKDF2',        '0.161520';   # for vault KDF

# ── GTK3 stack ────────────────────────────────────────────────────────
requires 'Gtk3',                 '0.038';
requires 'Gtk3::SimpleList',     '0.21';
requires 'Glib::IO',             '0.51';
requires 'Glib::Object::Introspection', '0.045';

# ── Networking / SSH / WoL ────────────────────────────────────────────
requires 'Expect',               '1.35';
requires 'Net::ARP',             '1.0.10';
requires 'Net::Ping',            '2.74';
requires 'Socket6',              '0.29';

# ── Identifiers / config ──────────────────────────────────────────────
requires 'UUID::Tiny',           '1.04';
requires 'YAML',                 '1.30';

# ── Optional but commonly available ───────────────────────────────────
recommends 'Try::Tiny',          '0.31';
recommends 'BSD::Resource',      '1.2911';     # core-dump suppression

# ── Test-only ─────────────────────────────────────────────────────────
on 'test' => sub {
    requires 'Test::More',       '1.302183';
    requires 'Test::Exception',  '0.43';
    requires 'Devel::Cover',     '1.36';       # coverage tracking
};

# ── Develop-only (linters, formatters) ────────────────────────────────
on 'develop' => sub {
    requires 'Perl::Critic',     '1.140';
    requires 'Perl::Tidy',       '20210717';
    requires 'Test::Pod',        '1.52';
    requires 'Test::Pod::Coverage', '1.10';
};
