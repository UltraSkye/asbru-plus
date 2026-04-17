#!/usr/bin/perl
# t/55-dialog-bulkedit.t — PAC::Dialog::BulkEdit extraction surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $pm = "$RealBin/../lib/PAC/Dialog/BulkEdit.pm";
ok(-r $pm, 'PAC/Dialog/BulkEdit.pm exists');

my $src = do {
    open my $f, '<', $pm or die "open: $!";
    local $/; <$f>;
};

# Package + show
like($src, qr/^package PAC::Dialog::BulkEdit;/m, 'declares package');
like($src, qr/^sub show\b/m,                     'has show()');

# Globals properly qualified
like($src, qr/\$PACUtils::APPNAME/,    'reads $PACUtils::APPNAME');
like($src, qr/\$PACUtils::APPVERSION/, 'reads $PACUtils::APPVERSION');
like($src, qr/\$PACMain::APPICON/,     'reads $PACMain::APPICON');

# All bulk-edit fields present in the dialog construction
for my $field (qw(title ip port user pass passphrase expect send)) {
    like($src, qr/\Q'$field'\E/, "field '$field' present in dialog");
}

# Returns the (\\%list, \$level, \$cipher?) tuple
like($src, qr/return \\%list/, 'returns \\%list');
like($src, qr/rballlevel/,     'returns radio button level');
like($src, qr/cbCipher/,       'optionally returns cipher flag');

# $self argument removed
unlike($src, qr/^    my \$self = shift;/m, 'no leftover "my $self = shift"');
like($src, qr/argument removed in P4\/7/, 'P4/7 marker comment present');

# PACMain wrapper
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Dialog::BulkEdit/m,
    'PACMain requires PAC::Dialog::BulkEdit');
like($main, qr/sub _bulkEdit \{[^}]*PAC::Dialog::BulkEdit::show/s,
    '_bulkEdit wrapper calls show');
like($main, qr/^our \$APPICON\s*=/m, 'PACMain $APPICON promoted to our');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item show\b/m,      'POD =item show');

done_testing();
