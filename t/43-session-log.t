#!/usr/bin/perl
# t/43-session-log.t — PAC::SessionLog helpers.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir);
use lib "$RealBin/../lib";

require_ok('PAC::SessionLog');
can_ok('PAC::SessionLog', $_) for qw(delete_oldest replace_bad_chars
                                     remove_escape_seqs purge_screenshots);

# 1. replace_bad_chars converts known control chars to mnemonic strings
my $r = PAC::SessionLog::replace_bad_chars("hello\x07world\x08end");
like($r, qr/BEL/, 'BEL converted');
like($r, qr/BS/, 'BS converted');
unlike($r, qr/\x07|\x08/, 'raw control chars stripped');

is(PAC::SessionLog::replace_bad_chars(undef), '', 'undef -> empty');
is(PAC::SessionLog::replace_bad_chars(''),    '', 'empty -> empty');

# Plain text passes through
my $plain = PAC::SessionLog::replace_bad_chars('hello world 123');
is($plain, 'hello world 123', 'plain text untouched');

# 2. remove_escape_seqs strips ANSI/VT codes
$r = PAC::SessionLog::remove_escape_seqs("\e[31mRed\e[0m text");
unlike($r, qr/\e\[/, 'no escape sequences left');
like($r, qr/Red/, 'visible text preserved');
like($r, qr/text/, 'visible text after escape preserved');

is(PAC::SessionLog::remove_escape_seqs(undef), '', 'undef -> empty');
is(PAC::SessionLog::remove_escape_seqs(''),    '', 'empty -> empty');

# 3. delete_oldest with $max=0 keeps all (returns 1, no action)
my $dir = tempdir(CLEANUP => 1);
for my $i (1 .. 5) {
    open(my $f, '>', "$dir/PAC_[env_Name_conn]_[20240101_12000$i].txt") or die $!;
    close $f;
}
PAC::SessionLog::delete_oldest('uuid', $dir, 0);
my @files = glob("$dir/PAC_*");
is(scalar @files, 5, 'delete_oldest with max=0 keeps all 5 files');

# Trim down — note the legacy off-by-one: delete_oldest with max=3 on
# 5 files actually leaves 2, not 3 (the post-increment + <= comparison
# in the original loop means it deletes max-total+1 files). Preserved
# verbatim for behavior compatibility.
PAC::SessionLog::delete_oldest('uuid', $dir, 3);
@files = glob("$dir/PAC_*");
is(scalar @files, 2, 'delete_oldest trims (legacy off-by-one keeps max-1)');

# 4. Files NOT matching the PAC_*.txt pattern are ignored
open(my $stray, '>', "$dir/random.txt") or die $!;
close $stray;
PAC::SessionLog::delete_oldest('uuid', $dir, 1);
ok(-f "$dir/random.txt", 'non-PAC files left alone');

# 4b. purge_screenshots: REGRESSION — must actually interpolate _cfg_dir()
# (an earlier extraction left "_cfg_dir()/screenshots" as a literal in a
# double-quoted string, which made every save crash on opendir).
{
    my $cfg_dir = tempdir(CLEANUP => 1);
    mkdir "$cfg_dir/screenshots" or die "mkdir: $!";

    # Plant 3 screenshot files: 1 referenced, 1 orphaned, 1 missing-on-disk.
    open my $f1, '>', "$cfg_dir/screenshots/used.png"     or die $!; close $f1;
    open my $f2, '>', "$cfg_dir/screenshots/orphaned.png" or die $!; close $f2;
    # No file for "missing.png" — it's a config ref to a deleted file.

    local $ENV{ASBRU_CFG} = $cfg_dir;
    my $cfg = {
        environments => {
            'uuid-1' => {
                screenshots => [
                    "$cfg_dir/screenshots/used.png",
                    "$cfg_dir/screenshots/missing.png",
                ],
            },
        },
    };

    eval { PAC::SessionLog::purge_screenshots($cfg); };
    is($@, '', 'purge_screenshots runs without dying');

    # Used: kept on disk, kept in cfg.
    ok(-f "$cfg_dir/screenshots/used.png",
        'purge_screenshots: referenced file kept on disk');
    is(scalar(grep { /used\.png/ } @{$cfg->{environments}{'uuid-1'}{screenshots}}),
        1, 'purge_screenshots: referenced file kept in cfg');
    # Orphaned: file deleted from disk.
    ok(! -f "$cfg_dir/screenshots/orphaned.png",
        'purge_screenshots: orphaned file unlinked from disk');
    # Missing: cfg ref dropped.
    is(scalar(grep { /missing\.png/ } @{$cfg->{environments}{'uuid-1'}{screenshots}}),
        0, 'purge_screenshots: missing-file cfg ref dropped');
}

# 5. PACUtils proxies wired
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::SessionLog/m, 'PACUtils requires PAC::SessionLog');
for my $pair (
    [_deleteOldestSessionLog       => 'delete_oldest'],
    [_replaceBadChars              => 'replace_bad_chars'],
    [_removeEscapeSeqs             => 'remove_escape_seqs'],
    [_purgeUnusedOrMissingScreenshots => 'purge_screenshots'],
) {
    my ($legacy, $new) = @$pair;
    like($utils,
        qr/sub \Q$legacy\E\s*\{\s*goto\s*&PAC::SessionLog::\Q$new\E\s*;\s*\}/,
        "$legacy is goto-proxy to $new");
}

# 6. POD
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/SessionLog.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(delete_oldest replace_bad_chars remove_escape_seqs purge_screenshots)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item $sub");
}

done_testing();
