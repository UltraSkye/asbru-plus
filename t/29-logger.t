#!/usr/bin/perl
# t/29-logger.t — PAC::Logger leveled diagnostics.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempfile tempdir);
use lib "$RealBin/../lib";

require_ok('PAC::Logger');

for my $sub (qw(fatal error warn info debug
                set_level current_level set_file log_file)) {
    can_ok('PAC::Logger', $sub);
}

# ── 1. STDERR output format is backward-compatible ──────────────────
my $stderr = capture_stderr(sub {
    PAC::Logger::error("vault unlock failed");
    PAC::Logger::warn("deprecated key 'foo'");
    PAC::Logger::info("loaded 5 items");
});
like($stderr, qr/^ERROR: vault unlock failed$/m, 'error: prefix + msg');
like($stderr, qr/^WARN: deprecated key 'foo'$/m, 'warn: prefix + msg');
like($stderr, qr/^INFO: loaded 5 items$/m,       'info: prefix + msg');

# ── 2. Level filter blocks lower-priority messages ──────────────────
PAC::Logger::set_level('WARN');
$stderr = capture_stderr(sub {
    PAC::Logger::error("kept");
    PAC::Logger::warn("kept-too");
    PAC::Logger::info("dropped");
    PAC::Logger::debug("dropped-too");
});
like($stderr,   qr/ERROR: kept/, 'WARN level: ERROR shown');
like($stderr,   qr/WARN: kept-too/, 'WARN level: WARN shown');
unlike($stderr, qr/INFO:/, 'WARN level: INFO suppressed');
unlike($stderr, qr/DEBUG:/, 'WARN level: DEBUG suppressed');

# Reset for further tests.
PAC::Logger::set_level('DEBUG');

# ── 3. set_level rejects unknown names ──────────────────────────────
eval { PAC::Logger::set_level('TRACE') };
like($@, qr/unknown level/, 'set_level rejects unknown name');

# ── 4. Numeric level accepted ───────────────────────────────────────
PAC::Logger::set_level(2);  # WARN
is(PAC::Logger::current_level(), 2, 'numeric level set');
PAC::Logger::set_level('DEBUG');

# ── 5. File sink: chmod 0600, timestamped, level-filtered ───────────
my $dir = tempdir(CLEANUP => 1);
my $log_path = "$dir/asbru.log";
PAC::Logger::set_file($log_path);
is(PAC::Logger::log_file(), $log_path, 'log_file() returns set path');

PAC::Logger::error("file-error-msg");
PAC::Logger::info("file-info-msg");

# Check perms
my $mode = (stat $log_path)[2] & 07777;
is($mode, 0600, 'log file chmod 0600');

# REGRESSION: the mode-0600 must come from a tightened umask wrapping
# the open(), not just from the trailing chmod — otherwise a process
# killed between open and chmod leaves a brand-new 0644 log on disk
# that subsequent appends silently extend (logs may contain credentials).
my $logger_src = do {
    open my $fh_src, '<', "$RealBin/../lib/PAC/Logger.pm" or die "open: $!";
    local $/; <$fh_src>;
};
like($logger_src,
    qr/umask\(0077\).*?\n\s*open\(my \$fh,\s*'>>'\s*,\s*\$path\)/s,
    'set_file: umask(0077) wraps the open (no TOCTOU)');

# Check contents
open(my $fh, '<', $log_path) or die "open: $!";
my $contents = do { local $/; <$fh> };
close $fh;
like($contents, qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} ERROR: file-error-msg$/m,
    'file: ISO timestamp + level + msg');
like($contents, qr/INFO: file-info-msg/, 'file: INFO line written');

# ── 6. Disable file sink ────────────────────────────────────────────
PAC::Logger::set_file(undef);
is(PAC::Logger::log_file(), undef, 'set_file(undef) clears the sink');

PAC::Logger::error("after-disable");
open($fh, '<', $log_path) or die "open: $!";
my $new_contents = do { local $/; <$fh> };
close $fh;
is($contents, $new_contents, 'no further file writes after disable');

# ── 7. Multi-arg join ───────────────────────────────────────────────
$stderr = capture_stderr(sub {
    PAC::Logger::warn("part-a", " ", "part-b ", 42);
});
like($stderr, qr/^WARN: part-a part-b 42$/m, 'multi-arg join');

# ── 8. Trailing newline is normalized (one, not two) ────────────────
$stderr = capture_stderr(sub {
    PAC::Logger::error("with-newline\n");
});
my @lines = split /\n/, $stderr;
my @err_lines = grep { /ERROR: with-newline/ } @lines;
is(scalar @err_lines, 1, 'trailing \n in input → single line out');

# ── 9. POD coverage ─────────────────────────────────────────────────
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Logger.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m, 'POD: NAME');
like($src, qr/^=head1 EMITTERS/m, 'POD: EMITTERS');
for my $sub (qw(set_level current_level set_file log_file
                fatal error warn info debug)) {
    like($src, qr/^=item \Q$sub\E/m, "POD =item for $sub");
}

done_testing();

#-------------------------------------------------------------------------
sub capture_stderr {
    my $code = shift;
    my $captured = '';
    open(my $save_err, '>&', STDERR) or die "dup STDERR: $!";
    close STDERR;
    open(STDERR, '>', \$captured) or die "redirect STDERR: $!";
    eval { $code->() };
    my $err = $@;
    close STDERR;
    open(STDERR, '>&', $save_err) or die "restore STDERR: $!";
    die $err if $err;
    return $captured;
}
