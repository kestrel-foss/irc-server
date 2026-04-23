use strict;
use warnings;

use File::Spec;
use FindBin;
use JSON::PP qw(decode_json encode_json);
use MIME::Base64 qw(decode_base64 encode_base64);
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
      response  => $args{response},
      responses => $args{responses},
      calls     => [],
    }, $class;
  }

  sub sessions_authorize {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.authorize',
      params => \%params,
    };
    if (ref($self->{responses}) eq 'ARRAY' && @{$self->{responses}}) {
      return shift @{$self->{responses}};
    }
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

subtest 'bridge mode processes a continuous stdin stream and emits quote commands for matching lines only' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $client = t::irc_auth_helper::FakeClient->new(
    responses => [
      {
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
      {
        type   => 'response',
        id     => 'auth-2',
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
    ],
  );

  my $input = join '',
    ":server 001 alice :welcome\r\n",
    "-server- OVERNETAUTH CHALLENGE $challenge\r\n",
    ":server NOTICE alice :ignored\r\n",
    "-server- OVERNETAUTH DELEGATE $delegate_pubkey session-123 ws://127.0.0.1:7448 1744304600\r\n";
  my $output = '';
  open my $in, '<', \$input or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    input       => $in,
    output      => $out,
    quote       => 1,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  is $count, 2, 'bridge mode reports the number of emitted auth commands';
  like $output, qr{\A/quote OVERNETAUTH AUTH \S+\n/quote OVERNETAUTH DELEGATE \S+\n\z},
    'bridge mode emits one quote command per matching auth line';
  is scalar(@{$client->calls}), 2, 'only matching OVERNETAUTH lines reach the auth agent';
  is $client->calls->[0]{params}{challenge}{value}, $challenge, 'stream mode extracted the challenge';
  is $client->calls->[1]{params}{action}, 'session.delegate', 'stream mode extracted the delegate request';
};

subtest 'bridge mode returns zero for streams with no matching auth lines' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::PP::true,
      result => { artifacts => [] },
    },
  );

  my $input = ":server 001 alice :welcome\r\n:server NOTICE alice :ignored\r\n";
  my $output = '';
  open my $in, '<', \$input or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => 'irc://irc.example.test/overnet',
    input       => $in,
    output      => $out,
    quote       => 1,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  is $count, 0, 'bridge mode reports no generated commands';
  is $output, '', 'bridge mode stays silent for non-auth lines';
  is scalar(@{$client->calls}), 0, 'non-auth lines do not call the auth agent';
};

subtest 'bridge mode stream can emit payloads without /quote prefixes' => sub {
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

  my $input = "-server- OVERNETAUTH CHALLENGE $challenge\r\n";
  my $output = '';
  open my $in, '<', \$input or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    input       => $in,
    output      => $out,
    quote       => 0,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  is $count, 1, 'bridge mode reports one generated payload';
  unlike $output, qr{\A/quote },
    'bridge mode omits /quote when quote output is disabled';
  like $output, qr{\A\S+\n\z},
    'bridge mode still emits the auth payload on its own line';
};

subtest 'bridge mode processes SASL NOSTR AUTHENTICATE streams without relay delegation' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';
  my $auth_event = {
    id         => ('1' x 64),
    pubkey     => ('2' x 64),
    created_at => 1744301600,
    kind       => 22242,
    tags       => [
      [ relay => $scope ],
      [ challenge => $challenge ],
    ],
    content => '',
    sig     => ('3' x 128),
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
            value  => $auth_event,
          },
        ],
      },
    },
  );

  my $input = _authenticate_input_lines({
    challenge => $challenge,
    scope     => $scope,
  });
  my $output = '';
  open my $in, '<', \$input or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    input       => $in,
    output      => $out,
    quote       => 1,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  my @lines = grep { length } split /\n/, $output;
  ok @lines >= 1, 'sasl bridge emitted AUTHENTICATE lines';
  is $count, scalar(@lines), 'sasl bridge count matches emitted AUTHENTICATE lines';
  like $lines[0], qr{\A/quote AUTHENTICATE \S+\z}, 'sasl bridge emits AUTHENTICATE commands';

  my $response = _decode_authenticate_output($output);
  is_deeply $response, {
    auth_event => $auth_event,
  }, 'sasl bridge preserves the auth event in the response payload';

  is_deeply $client->calls, [
    {
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
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
  ], 'sasl bridge requests only the auth artifact when delegation is absent';
};

subtest 'bridge mode processes relay-backed SASL NOSTR AUTHENTICATE streams' => sub {
  my $challenge = '7cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $auth_event = {
    id         => ('4' x 64),
    pubkey     => ('5' x 64),
    created_at => 1744301700,
    kind       => 22242,
    tags       => [
      [ relay => $scope ],
      [ challenge => $challenge ],
    ],
    content => '',
    sig     => ('6' x 128),
  };
  my $delegate_event = {
    id         => ('7' x 64),
    pubkey     => ('8' x 64),
    created_at => 1744301800,
    kind       => 24142,
    tags       => [
      [ relay => 'ws://127.0.0.1:7448' ],
      [ server => $scope ],
      [ delegate => $delegate_pubkey ],
      [ session => 'session-123' ],
      [ expires_at => '1744304600' ],
    ],
    content => '',
    sig     => ('9' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    responses => [
      {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          artifacts => [
            {
              type   => 'nostr.event',
              format => 'nostr.event',
              value  => $auth_event,
            },
          ],
        },
      },
      {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::PP::true,
        result => {
          artifacts => [
            {
              type   => 'nostr.event',
              format => 'nostr.event',
              value  => $delegate_event,
            },
          ],
        },
      },
    ],
  );

  my $input = _authenticate_input_lines({
    challenge        => $challenge,
    scope            => $scope,
    relay_url        => 'ws://127.0.0.1:7448',
    grant_kind       => 24142,
    delegate_pubkey  => $delegate_pubkey,
    session_id       => 'session-123',
    expires_at       => '1744304600',
    padding          => ('x' x 700),
  });
  my $output = '';
  open my $in, '<', \$input or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    input       => $in,
    output      => $out,
    quote       => 0,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  my @lines = grep { length } split /\n/, $output;
  ok @lines >= 1, 'relay-backed sasl bridge emitted AUTHENTICATE lines';
  is $count, scalar(@lines), 'relay-backed sasl bridge count matches emitted AUTHENTICATE lines';
  like $lines[0], qr{\AAUTHENTICATE \S+\z}, 'relay-backed sasl bridge can emit raw AUTHENTICATE lines';
  unlike $lines[0], qr{\A/quote }, 'relay-backed sasl bridge omits /quote when disabled';

  my $response = _decode_authenticate_output($output);
  is_deeply $response, {
    auth_event     => $auth_event,
    delegate_event => $delegate_event,
  }, 'relay-backed sasl bridge preserves both returned events in the response payload';

  is scalar(@{$client->calls}), 2, 'relay-backed sasl bridge makes two auth-agent requests';
  is $client->calls->[0]{params}{action}, 'session.authenticate',
    'relay-backed sasl bridge requests auth first';
  is $client->calls->[0]{params}{challenge}{value}, $challenge,
    'relay-backed sasl bridge forwards the server challenge';
  is $client->calls->[1]{params}{action}, 'session.delegate',
    'relay-backed sasl bridge requests delegation second';
  is_deeply $client->calls->[1]{params}{artifacts}[0]{params}{tags}, [
    [ relay => 'ws://127.0.0.1:7448' ],
    [ server => $scope ],
    [ delegate => $delegate_pubkey ],
    [ session => 'session-123' ],
    [ expires_at => '1744304600' ],
  ], 'relay-backed sasl bridge forwards the delegate challenge parameters';
  is $client->calls->[1]{params}{artifacts}[0]{params}{kind}, 24142,
    'relay-backed sasl bridge honors grant_kind from the server challenge';
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

sub _authenticate_input_lines {
  my ($payload) = @_;
  my $encoded = encode_base64(encode_json($payload), '');
  my @chunks;
  while (length($encoded) > 400) {
    push @chunks, substr($encoded, 0, 400, '');
  }
  push @chunks, $encoded if length $encoded;

  return join '', map { ":server AUTHENTICATE $_\r\n" } @chunks;
}

sub _decode_authenticate_output {
  my ($output) = @_;
  my $payload = join '',
    map {
      my $line = $_;
      $line =~ s/\A\/quote\s+//;
      $line =~ s/\AAUTHENTICATE\s+//;
      $line eq '+' ? () : $line;
    }
    grep { length }
    split /\n/, $output;

  return decode_json(decode_base64($payload));
}

done_testing;
