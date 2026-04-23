use strict;
use warnings;

use File::Spec;
use FindBin;
use JSON::PP qw(decode_json);
use MIME::Base64 qw(decode_base64);
use Test::More;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Program::IRC::Auth::Helper;

{
  package t::irc_auth_helper::FakeClient;

  sub new {
    my ($class, %args) = @_;
    return bless {
      response => $args{response},
      calls    => [],
    }, $class;
  }

  sub sessions_authorize {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.authorize',
      params => \%params,
    };
    return $self->{response};
  }

  sub calls {
    my ($self) = @_;
    return $self->{calls};
  }
}

subtest 'auth mode uses the auth agent and emits a paste-ready OVERNETAUTH AUTH line' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';
  my $event = {
    id         => ('a' x 64),
    pubkey     => ('b' x 64),
    created_at => 1744301000,
    kind       => 22242,
    tags       => [
      [ relay => $scope ],
      [ challenge => $challenge ],
    ],
    content => '',
    sig     => ('c' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => $event,
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'auth',
    identity_id => 'default',
    challenge   => $challenge,
    scope       => $scope,
    quote       => 1,
    interactive => 1,
  );

  my ($payload) = $output =~ qr{\A/quote OVERNETAUTH AUTH (\S+)\n\z};
  ok defined $payload, 'the helper prints a paste-ready OVERNETAUTH AUTH command';
  is_deeply decode_json(decode_base64($payload)), $event,
    'the helper preserves the signed auth event returned by the auth agent';

  is_deeply $client->calls, [
    {
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => [ $scope ],
        },
        scope       => $scope,
        action      => 'session.authenticate',
        interactive => JSON::PP::true,
        challenge   => {
          type  => 'opaque',
          value => $challenge,
        },
        artifacts => [
          {
            type => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [ relay => $scope ],
                [ challenge => $challenge ],
              ],
            },
          },
        ],
      },
    },
  ], 'auth mode sends the expected sessions.authorize request';
};

subtest 'delegate mode uses the auth agent and emits a paste-ready OVERNETAUTH DELEGATE line' => sub {
  my $scope = 'irc://irc.example.test/overnet';
  my $event = {
    id         => ('d' x 64),
    pubkey     => ('e' x 64),
    created_at => 1744301100,
    kind       => 14142,
    tags       => [
      [ relay => 'ws://127.0.0.1:7448' ],
      [ server => $scope ],
      [ delegate => ('f' x 64) ],
      [ session => 'session-123' ],
      [ expires_at => '1744304600' ],
      [ nick => 'alice' ],
    ],
    content => '',
    sig     => ('1' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => $event,
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client           => $client,
    command          => 'delegate',
    identity_id      => 'default',
    relay_url        => 'ws://127.0.0.1:7448',
    scope            => $scope,
    delegate_pubkey  => ('f' x 64),
    session_id       => 'session-123',
    expires_at       => '1744304600',
    nick             => 'alice',
    quote            => 1,
    interactive      => 1,
  );

  my ($payload) = $output =~ qr{\A/quote OVERNETAUTH DELEGATE (\S+)\n\z};
  ok defined $payload, 'the helper prints a paste-ready OVERNETAUTH DELEGATE command';
  is_deeply decode_json(decode_base64($payload)), $event,
    'the helper preserves the signed delegate event returned by the auth agent';

  is_deeply $client->calls, [
    {
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => [ $scope ],
        },
        scope       => $scope,
        action      => 'session.delegate',
        interactive => JSON::PP::true,
        artifacts   => [
          {
            type => 'nostr.event',
            params => {
              kind => 14142,
              tags => [
                [ relay => 'ws://127.0.0.1:7448' ],
                [ server => $scope ],
                [ delegate => ('f' x 64) ],
                [ session => 'session-123' ],
                [ expires_at => '1744304600' ],
                [ nick => 'alice' ],
              ],
            },
          },
        ],
      },
    },
  ], 'delegate mode sends the expected sessions.authorize request';
};

subtest 'bridge mode parses OVERNETAUTH CHALLENGE lines and requests auth artifacts' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('2' x 64),
              pubkey     => ('3' x 64),
              created_at => 1744301200,
              kind       => 22242,
              tags       => [
                [ relay => $scope ],
                [ challenge => $challenge ],
              ],
              content => '',
              sig     => ('4' x 128),
            },
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    line        => "-server- OVERNETAUTH CHALLENGE $challenge",
    quote       => 1,
    interactive => 1,
  );

  like $output, qr{\A/quote OVERNETAUTH AUTH \S+\n\z}, 'bridge mode emits an OVERNETAUTH AUTH command';
  is $client->calls->[0]{params}{action}, 'session.authenticate',
    'bridge mode maps challenge lines to session.authenticate';
  is $client->calls->[0]{params}{challenge}{value}, $challenge,
    'bridge mode extracts the challenge token';
};

subtest 'bridge mode parses OVERNETAUTH DELEGATE lines and requests delegate artifacts' => sub {
  my $scope = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('5' x 64),
              pubkey     => ('6' x 64),
              created_at => 1744301300,
              kind       => 14142,
              tags       => [
                [ relay => 'ws://127.0.0.1:7448' ],
                [ server => $scope ],
                [ delegate => $delegate_pubkey ],
                [ session => 'session-123' ],
                [ expires_at => '1744304600' ],
              ],
              content => '',
              sig     => ('7' x 128),
            },
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    line        => "-server- OVERNETAUTH DELEGATE $delegate_pubkey session-123 ws://127.0.0.1:7448 1744304600",
    quote       => 1,
    interactive => 1,
  );

  like $output, qr{\A/quote OVERNETAUTH DELEGATE \S+\n\z}, 'bridge mode emits an OVERNETAUTH DELEGATE command';
  is $client->calls->[0]{params}{action}, 'session.delegate',
    'bridge mode maps delegate lines to session.delegate';
  is_deeply $client->calls->[0]{params}{artifacts}[0]{params}{tags}, [
    [ relay => 'ws://127.0.0.1:7448' ],
    [ server => $scope ],
    [ delegate => $delegate_pubkey ],
    [ session => 'session-123' ],
    [ expires_at => '1744304600' ],
  ], 'bridge mode extracts the delegate parameters from the IRC line';
};

subtest 'auth mode forwards locator and service identity descriptors to the auth agent' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';
  my $locator = 'wss://relay.example.test/auth';
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('8' x 64),
              pubkey     => ('9' x 64),
              created_at => 1744301400,
              kind       => 22242,
              tags       => [
                [ relay => $scope ],
                [ challenge => $challenge ],
              ],
              content => '',
              sig     => ('a' x 128),
            },
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client                   => $client,
    command                  => 'auth',
    identity_id              => 'default',
    challenge                => $challenge,
    scope                    => $scope,
    locator                  => $locator,
    service_identity_scheme  => 'nostr.pubkey',
    service_identity_value   => ('b' x 64),
    service_identity_display => 'relay.example.test authority',
    interactive              => 1,
  );

  like $output, qr{\A\S+\n\z}, 'auth mode still returns a wire payload';
  is_deeply $client->calls->[0]{params}{service}, {
    locators => [ $locator ],
    service_identity => {
      scheme  => 'nostr.pubkey',
      value   => ('b' x 64),
      display => 'relay.example.test authority',
    },
  }, 'auth mode forwards locator and service identity descriptors';
};

subtest 'service identity flags require both scheme and value' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('c' x 64),
              pubkey     => ('d' x 64),
              created_at => 1744301500,
              kind       => 22242,
              tags       => [],
              content    => '',
              sig        => ('e' x 128),
            },
          },
        ],
      },
    },
  );

  my $error = eval {
    Overnet::Program::IRC::Auth::Helper->run(
      client                  => $client,
      command                 => 'auth',
      challenge               => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      scope                   => 'irc://irc.example.test/overnet',
      service_identity_scheme => 'nostr.pubkey',
      interactive             => 1,
    );
    1;
  } ? undef : $@;

  like $error, qr/--service-identity-scheme and --service-identity-value are required together/,
    'partial service identity descriptors are rejected';
  is scalar @{$client->calls}, 0, 'the auth agent is not called on invalid service identity input';
};

done_testing;
