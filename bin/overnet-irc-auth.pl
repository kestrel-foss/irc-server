#!/usr/bin/env perl
use strict;
use warnings;

use FindBin;
use Getopt::Long qw(GetOptionsFromArray);
use JSON::PP qw(encode_json);
use MIME::Base64 qw(encode_base64);
use lib grep { -d $_ } (
  "$FindBin::Bin/../lib",
  "$FindBin::Bin/../../core-perl/lib",
);

use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;

my $command = shift @ARGV || '';
my %options = (
  quote => 1,
);
my $help = 0;

GetOptionsFromArray(
  \@ARGV,
  'privkey-file=s'     => \$options{privkey_file},
  'privkey-secret=s'   => \$options{privkey_secret},
  'privkey-stdin!'     => \$options{privkey_stdin},
  'challenge=s'        => \$options{challenge},
  'scope=s'            => \$options{scope},
  'relay-url=s'        => \$options{relay_url},
  'delegate-pubkey=s'  => \$options{delegate_pubkey},
  'session-id=s'       => \$options{session_id},
  'expires-at=s'       => \$options{expires_at},
  'nick=s'             => \$options{nick},
  'created-at=i'       => \$options{created_at},
  'quote!'             => \$options{quote},
  'help'               => \$help,
) or die _usage();

if ($help || !$command) {
  print _usage();
  exit($help ? 0 : 1);
}

die _usage()
  unless $command eq 'auth' || $command eq 'delegate';

my $secret_source_count = 0
  + (defined($options{privkey_file}) ? 1 : 0)
  + (defined($options{privkey_secret}) ? 1 : 0)
  + ($options{privkey_stdin} ? 1 : 0);
die "exactly one of --privkey-file, --privkey-secret, or --privkey-stdin is required\n"
  unless $secret_source_count == 1;

my $privkey_input;
if (defined $options{privkey_file}) {
  $privkey_input = $options{privkey_file};
} elsif (defined $options{privkey_secret}) {
  $privkey_input = $options{privkey_secret};
} else {
  local $/;
  $privkey_input = <STDIN>;
  die "no private key secret was provided on stdin\n"
    unless defined $privkey_input && length $privkey_input;
  $privkey_input =~ s/\s+\z//;
}

my $key = Overnet::Core::Nostr->load_key(privkey => $privkey_input);
my $event = $command eq 'auth'
  ? _build_auth_event($key, \%options)
  : _build_delegate_event($key, \%options);
my $payload = encode_base64(encode_json($event), '');

if ($options{quote}) {
  print sprintf(
    "/quote OVERNETAUTH %s %s\n",
    uc($command),
    $payload,
  );
} else {
  print "$payload\n";
}

exit 0;

sub _build_auth_event {
  my ($key, $options) = @_;

  die "--challenge is required\n"
    unless defined $options->{challenge} && !ref($options->{challenge}) && length($options->{challenge});
  die "--scope is required\n"
    unless defined $options->{scope} && !ref($options->{scope}) && length($options->{scope});

  my $event = Overnet::Authority::Delegation->create_auth_event(
    key        => $key,
    challenge  => $options->{challenge},
    scope      => $options->{scope},
    (defined($options->{created_at}) ? (created_at => $options->{created_at}) : ()),
  );
  return _require_event_hash($event);
}

sub _build_delegate_event {
  my ($key, $options) = @_;

  die "--relay-url is required\n"
    unless defined $options->{relay_url} && !ref($options->{relay_url}) && length($options->{relay_url});
  die "--scope is required\n"
    unless defined $options->{scope} && !ref($options->{scope}) && length($options->{scope});
  die "--delegate-pubkey is required\n"
    unless defined $options->{delegate_pubkey} && !ref($options->{delegate_pubkey}) && length($options->{delegate_pubkey});
  die "--session-id is required\n"
    unless defined $options->{session_id} && !ref($options->{session_id}) && length($options->{session_id});
  die "--expires-at is required\n"
    unless defined $options->{expires_at} && !ref($options->{expires_at}) && length($options->{expires_at});

  my $event = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $options->{relay_url},
    scope           => $options->{scope},
    delegate_pubkey => $options->{delegate_pubkey},
    session_id      => $options->{session_id},
    expires_at      => $options->{expires_at},
    (defined($options->{created_at}) ? (created_at => $options->{created_at}) : ()),
    (defined($options->{nick}) ? (nick => $options->{nick}) : ()),
  );
  return _require_event_hash($event);
}

sub _require_event_hash {
  my ($event) = @_;
  die ($event->{reason} || "unknown event construction error\n")
    if ref($event) eq 'HASH' && exists $event->{valid} && !$event->{valid};
  die "event builder did not return an event object\n"
    unless ref($event) eq 'HASH';
  return $event;
}

sub _usage {
  return <<'USAGE';
Usage:
  overnet-irc-auth.pl auth [options]
  overnet-irc-auth.pl delegate [options]

Secret source options (exactly one is required):
  --privkey-file PATH
  --privkey-secret SECRET
  --privkey-stdin

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

Shared options:
  --created-at UNIX_TIMESTAMP
  --quote
  --help
USAGE
}
