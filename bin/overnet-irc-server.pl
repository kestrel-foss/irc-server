#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib grep { -d $_ } (
  "$FindBin::Bin/../lib",
  "$FindBin::Bin/../../core-perl/lib",
);

use Overnet::Program::IRC::Server;

my $server = Overnet::Program::IRC::Server->new;
my $ok = eval {
  $server->run;
  1;
};
my $error = $@;
die $error if !$ok && $error !~ /\A__shutdown__(?:\s+at\b.*)?\z/s;
