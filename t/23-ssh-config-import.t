#!/usr/bin/perl
# t/23-ssh-config-import.t — Tests for OpenSSH client config parser used by
# the "Import from ~/.ssh/config" feature.
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempfile);
use lib "$RealBin/../lib";
use PAC::Net::SshConfig;

# 1. Parser handles a typical config and skips wildcards/Match/Include.
my ($fh, $cfg) = tempfile(UNLINK => 1);
print $fh <<'CFG';
# Global defaults
Host *
  ServerAliveInterval 60
  IdentityFile ~/.ssh/id_rsa

Host bastion
  HostName bastion.example.com
  Port 2222
  User admin

Host web1 web1.example.com
  HostName 10.0.0.10
  User deploy
  IdentityFile /home/me/.ssh/deploy_rsa

Host db.example.com
  User dba

Host *.staging
  User stage

Match user root
  IdentityFile ~/.ssh/root_id

Include ~/.ssh/extra_config
CFG
close $fh;

my $hosts = PAC::Net::SshConfig::parse($cfg);
isa_ok($hosts, 'ARRAY', 'parse returns arrayref');
is(scalar @$hosts, 3, 'three importable Host entries (wildcards + Match dropped)');

my %by_alias = map { $_->{alias} => $_ } @$hosts;

ok(exists $by_alias{bastion}, 'bastion entry exists');
is($by_alias{bastion}{hostname}, 'bastion.example.com', 'bastion HostName');
is($by_alias{bastion}{port}, 2222, 'bastion Port');
is($by_alias{bastion}{user}, 'admin', 'bastion User');

ok(exists $by_alias{web1}, 'web1 entry exists (first alias from Host web1 web1.example.com)');
is($by_alias{web1}{hostname}, '10.0.0.10', 'web1 HostName');
is($by_alias{web1}{user}, 'deploy', 'web1 User');
is($by_alias{web1}{identity_file}, '/home/me/.ssh/deploy_rsa', 'web1 IdentityFile preserved');

ok(exists $by_alias{'db.example.com'}, 'db.example.com (no HostName) treated as alias');
ok(!exists $by_alias{'db.example.com'}{hostname}, 'no HostName field when not provided');

ok(!exists $by_alias{'*'}, 'wildcard host * skipped');
ok(!exists $by_alias{'*.staging'}, 'wildcard *.staging skipped');

# 2. importable() rejects empty/wildcard aliases
ok(!PAC::Net::SshConfig::importable({alias => ''}), 'empty alias not importable');
ok(!PAC::Net::SshConfig::importable({alias => '*'}), 'asterisk alias not importable');
ok(!PAC::Net::SshConfig::importable({alias => 'foo?'}), 'question-mark alias not importable');
ok( PAC::Net::SshConfig::importable({alias => 'host.example.com'}), 'plain alias importable');

# 3. parse() returns empty arrayref for missing file (no exception)
my $empty = PAC::Net::SshConfig::parse('/nonexistent/path/' . $$ . '/config');
is_deeply($empty, [], 'missing file returns empty arrayref');

# 4. Tilde expansion in IdentityFile uses $ENV{HOME}
local $ENV{HOME} = '/tmp/fakehome';
my ($fh2, $cfg2) = tempfile(UNLINK => 1);
print $fh2 "Host h\n  IdentityFile ~/key\n";
close $fh2;
my $h2 = PAC::Net::SshConfig::parse($cfg2);
is($h2->[0]{identity_file}, '/tmp/fakehome/key', 'tilde expanded against $ENV{HOME}');

done_testing();
