#!/usr/bin/env perl
use strict;
use warnings;

use FindBin;
use Getopt::Long qw(GetOptionsFromArray);
use lib grep { -d $_ } (
  "$FindBin::Bin/../lib",
  "$FindBin::Bin/../../core-perl/lib",
);

use Overnet::Auth::Client;
use Overnet::Program::IRC::Auth::Helper;

if (@ARGV && $ARGV[0] eq '--help') {
  print _usage();
  exit 0;
}

my $command = shift @ARGV || '';
my %options = (
  interactive => 1,
  program_id  => 'irc.bridge',
  quote       => 1,
);
my $help = 0;

GetOptionsFromArray(
  \@ARGV,
  'auth-sock=s'        => \$options{auth_sock},
  'identity-id=s'      => \$options{identity_id},
  'program-id=s'       => \$options{program_id},
  'locator=s'          => \$options{locator},
  'service-identity-scheme=s' => \$options{service_identity_scheme},
  'service-identity-value=s'  => \$options{service_identity_value},
  'service-identity-display=s' => \$options{service_identity_display},
  'challenge=s'        => \$options{challenge},
  'scope=s'            => \$options{scope},
  'relay-url=s'        => \$options{relay_url},
  'delegate-pubkey=s'  => \$options{delegate_pubkey},
  'session-id=s'       => \$options{session_id},
  'expires-at=s'       => \$options{expires_at},
  'nick=s'             => \$options{nick},
  'line=s'             => \$options{line},
  'interactive!'       => \$options{interactive},
  'quote!'             => \$options{quote},
  'help'               => \$help,
) or die _usage();

if ($help || !$command) {
  print _usage();
  exit($help ? 0 : 1);
}

die _usage()
  unless $command eq 'auth' || $command eq 'delegate' || $command eq 'bridge';

my $client = Overnet::Auth::Client->new(
  (defined($options{auth_sock}) ? (endpoint => $options{auth_sock}) : ()),
);
if ($command eq 'bridge' && !defined($options{line})) {
  Overnet::Program::IRC::Auth::Helper->run(
    client  => $client,
    command => $command,
    input   => \*STDIN,
    output  => \*STDOUT,
    %options,
  );
}
else {
  print Overnet::Program::IRC::Auth::Helper->run(
    client  => $client,
    command => $command,
    %options,
  );
}

exit 0;

sub _usage {
  return <<'USAGE';
Usage:
  overnet-irc-auth.pl auth [options]
  overnet-irc-auth.pl delegate [options]
  overnet-irc-auth.pl bridge [options]

Auth-agent options:
  --auth-sock PATH
  --identity-id ID
  --program-id PROGRAM_ID
  --locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --interactive / --no-interactive

Auth options:
  --challenge CHALLENGE
  --scope IRC_SCOPE

Delegate options:
  --relay-url URL
  --scope IRC_SCOPE
  --delegate-pubkey PUBKEY
  --session-id ID
  --expires-at UNIX_TIMESTAMP
  --nick NICK

Bridge options:
  --line IRC_NOTICE_LINE
  --scope IRC_SCOPE
  If --line is omitted, read IRC lines continuously from stdin.

Shared output options:
  --quote
  --help
USAGE
}
