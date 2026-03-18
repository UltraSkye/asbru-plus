#!/usr/bin/perl
# t/05-workflow-lint.t — Validate GitHub Actions workflow files
use strict;
use warnings;
use Test::More;
use File::Find;

my @workflows;
find(sub { push @workflows, $File::Find::name if /\.yml$/ }, '.github/workflows');
@workflows = sort @workflows;

plan tests => scalar(@workflows) * 3;

for my $wf (@workflows) {
    open my $fh, '<', $wf or BAIL_OUT("Cannot open $wf: $!");
    my $content = do { local $/; <$fh> };
    close $fh;

    # Must have 'on:' trigger
    like($content, qr/^on:/m, "$wf: has 'on:' trigger");

    # Must have 'jobs:' section
    like($content, qr/^jobs:/m, "$wf: has 'jobs:' section");

    # Must not reference old asbru-cm org secrets or old repo
    unlike($content,
        qr/asbru-cm\/asbru-cm\.git/,
        "$wf: does not reference upstream repo URL");
}
