use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use JSON::PP qw(encode_json decode_json);
use MIME::Base64 qw(decode_base64);
use Socket qw(AF_UNIX PF_UNSPEC SOCK_STREAM);
use Test::More;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Auth::Client;
use Overnet::Auth::Daemon;
use Overnet::Program::IRC::Auth::Helper;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
my $scope = 'irc://irc.example.test/overnet';

{
  package t::irc_auth_daemon_e2e::FakeListener;

  sub new {
    my ($class, %args) = @_;
    return bless {
      queue => $args{queue} || [],
    }, $class;
  }

  sub accept {
    my ($self) = @_;
    return shift @{$self->{queue}};
  }

  sub close {
    return 1;
  }
}

subtest 'helper consumes artifacts from a daemon started from config' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path);
  my ($pid, $next_socket) = _start_daemon_from_config(
    config_file     => $config_file,
    endpoint        => $socket_path,
    max_connections => 3,
  );

  my $client = Overnet::Auth::Client->new(
    endpoint       => $socket_path,
    socket_factory => $next_socket,
  );
  my $identities = $client->identities_list;
  is $identities->{ok}, 1, 'identities.list succeeds against the daemon';
  is $identities->{result}{identities}[0]{identity_id}, 'default',
    'daemon loaded the configured identity';

  my $helper_client = Overnet::Auth::Client->new(
    endpoint       => $socket_path,
    socket_factory => $next_socket,
  );
  my $wire = Overnet::Program::IRC::Auth::Helper->run(
    client      => $helper_client,
    command     => 'auth',
    identity_id => 'default',
    challenge   => $challenge,
    scope       => $scope,
    interactive => 1,
    quote       => 1,
  );

  my ($payload) = $wire =~ qr{\A/quote OVERNETAUTH AUTH (\S+)\n\z};
  ok defined $payload, 'helper returns a paste-ready OVERNETAUTH AUTH line';

  my $event = decode_json(decode_base64($payload));
  is $event->{kind}, 22242, 'helper returned an auth event';
  is $event->{tags}[0][1], $scope, 'returned event preserves the IRC auth scope';
  is $event->{tags}[1][1], $challenge, 'returned event preserves the challenge';

  my $delegate_client = Overnet::Auth::Client->new(
    endpoint       => $socket_path,
    socket_factory => $next_socket,
  );
  my $delegate_wire = Overnet::Program::IRC::Auth::Helper->run(
    client           => $delegate_client,
    command          => 'delegate',
    identity_id      => 'default',
    relay_url        => 'ws://127.0.0.1:7448',
    scope            => $scope,
    delegate_pubkey  => ('f' x 64),
    session_id       => 'session-123',
    expires_at       => '1744304600',
    interactive      => 1,
    quote            => 1,
  );

  my ($delegate_payload) = $delegate_wire =~ qr{\A/quote OVERNETAUTH DELEGATE (\S+)\n\z};
  ok defined $delegate_payload, 'helper returns a paste-ready OVERNETAUTH DELEGATE line';

  my $delegate_event = decode_json(decode_base64($delegate_payload));
  is $delegate_event->{kind}, 14142, 'helper returned a delegate event';
  is_deeply $delegate_event->{tags}, [
    [ relay => 'ws://127.0.0.1:7448' ],
    [ server => $scope ],
    [ delegate => ('f' x 64) ],
    [ session => 'session-123' ],
    [ expires_at => '1744304600' ],
  ], 'returned delegate event preserves the expected tags';

  _wait_for_child($pid, 'daemon exits cleanly after the end-to-end flow');
};

done_testing;

sub _start_daemon_from_config {
  my (%args) = @_;
  my @client_sockets;
  my @server_sockets;
  my $endpoint = $args{endpoint};

  for (1 .. ($args{max_connections} || 1)) {
    socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
      or die "socketpair failed: $!";
    push @server_sockets, $server_socket;
    push @client_sockets, $client_socket;
  }

  my $pid = fork();
  die "fork failed: $!" unless defined $pid;
  if (!$pid) {
    my $listener = t::irc_auth_daemon_e2e::FakeListener->new(queue => \@server_sockets);
    my $daemon = Overnet::Auth::Daemon->new(
      config_file     => $args{config_file},
      endpoint        => $endpoint,
      max_connections => $args{max_connections},
      listen_factory  => sub { return $listener },
    );
    $daemon->run;
    exit 0;
  }

  my $next_socket = sub {
    my ($requested_endpoint) = @_;
    is $requested_endpoint, $endpoint, 'client requested the configured daemon endpoint';
    return shift @client_sockets;
  };

  return ($pid, $next_socket);
}

sub _wait_for_child {
  my ($pid, $name) = @_;
  waitpid($pid, 0);
  is $? >> 8, 0, $name;
}

sub _write_config {
  my ($path, $socket_path) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} encode_json({
    daemon => {
      endpoint => $socket_path,
    },
    identities => [
      {
        identity_id  => 'default',
        backend_type => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa',
        },
      },
    ],
    policies => [
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locator     => $scope,
        scope       => $scope,
        action      => 'session.authenticate',
      },
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locator     => $scope,
        scope       => $scope,
        action      => 'session.delegate',
      },
    ],
  })
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
}
