#!/usr/bin/env perl
use strict;
use warnings;

use FindBin;
use Getopt::Long qw(GetOptions);
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../core-perl/lib";
use lib "$FindBin::Bin/../../core-perl/local/lib/perl5";
use lib "$FindBin::Bin/../../relay-perl/lib";
use lib "$FindBin::Bin/../../relay-perl/local/lib/perl5";

use Overnet::Authority::HostedChannel::Relay qw(build_authoritative_relay);

my %opt = (
  host       => '127.0.0.1',
  port       => 7448,
  grant_kind => 14142,
  store_file => undef,
);
my $help = 0;

GetOptions(
  'host=s'       => \$opt{host},
  'port=i'       => \$opt{port},
  'relay-url=s'  => \$opt{relay_url},
  'grant-kind=i' => \$opt{grant_kind},
  'store-file=s' => \$opt{store_file},
  'help'         => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--host is required\n"
  unless defined $opt{host} && !ref($opt{host}) && length($opt{host});
die "--port must be a non-negative integer\n"
  unless defined $opt{port} && !ref($opt{port}) && $opt{port} =~ /\A\d+\z/;
die "--grant-kind must be a positive integer\n"
  unless defined $opt{grant_kind} && !ref($opt{grant_kind}) && $opt{grant_kind} =~ /\A[1-9]\d*\z/;
die "--store-file must be a non-empty string\n"
  if defined $opt{store_file} && (ref($opt{store_file}) || $opt{store_file} eq '');

$opt{relay_url} ||= sprintf('ws://%s:%d', $opt{host}, $opt{port});

my $relay = build_authoritative_relay(
  relay_url  => $opt{relay_url},
  grant_kind => $opt{grant_kind},
  (defined $opt{store_file} ? (store_file => $opt{store_file}) : ()),
);

$SIG{INT} = sub { $relay->stop };
$SIG{TERM} = sub { $relay->stop };

$relay->run($opt{host}, $opt{port});
exit 0;

sub _usage {
  return <<'USAGE';
Usage: overnet-irc-authority-relay.pl [options]

  --host HOST
  --port PORT
  --relay-url URL
  --grant-kind KIND
  --store-file PATH
  --help
USAGE
}
