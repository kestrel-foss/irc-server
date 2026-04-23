package Overnet::Program::IRC::Auth::Helper;

use strict;
use warnings;

use JSON::PP ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Overnet::Auth::Bridge::IRC;
use Overnet::Program::IRC::Renderer ();

sub run {
  my ($class, %args) = @_;
  my $command = $args{command} || '';

  if ($command eq 'auth') {
    return $class->_authorize_auth(%args);
  }
  if ($command eq 'delegate') {
    return $class->_authorize_delegate(%args);
  }
  if ($command eq 'bridge') {
    return $class->_bridge_stream(%args)
      unless defined($args{line}) && !ref($args{line}) && length($args{line});
    return $class->_bridge_line(%args);
  }

  die "unsupported command: $command\n";
}

sub _authorize_auth {
  my ($class, %args) = @_;
  my $artifact = $class->_authorize_auth_artifact(%args);
  return $class->_render_irc_artifact(
    artifact    => $artifact,
    irc_command => 'OVERNETAUTH AUTH',
    quote       => $args{quote},
  );
}

sub _authorize_auth_artifact {
  my ($class, %args) = @_;
  my $challenge = $args{challenge};
  my $scope = $args{scope};

  die "--challenge is required\n"
    unless defined $challenge && !ref($challenge) && length($challenge);
  die "--scope is required\n"
    unless defined $scope && !ref($scope) && length($scope);

  return $class->_authorize_artifact(
    %args,
    action      => 'session.authenticate',
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
  );
}

sub _authorize_delegate {
  my ($class, %args) = @_;
  my $artifact = $class->_authorize_delegate_artifact(%args);
  return $class->_render_irc_artifact(
    artifact    => $artifact,
    irc_command => 'OVERNETAUTH DELEGATE',
    quote       => $args{quote},
  );
}

sub _authorize_delegate_artifact {
  my ($class, %args) = @_;
  my $relay_url = $args{relay_url};
  my $scope = $args{scope};
  my $delegate_pubkey = $args{delegate_pubkey};
  my $session_id = $args{session_id};
  my $expires_at = $args{expires_at};

  die "--relay-url is required\n"
    unless defined $relay_url && !ref($relay_url) && length($relay_url);
  die "--scope is required\n"
    unless defined $scope && !ref($scope) && length($scope);
  die "--delegate-pubkey is required\n"
    unless defined $delegate_pubkey && !ref($delegate_pubkey) && length($delegate_pubkey);
  die "--session-id is required\n"
    unless defined $session_id && !ref($session_id) && length($session_id);
  die "--expires-at is required\n"
    unless defined $expires_at && !ref($expires_at) && length($expires_at);

  my @tags = (
    [ relay => $relay_url ],
    [ server => $scope ],
    [ delegate => $delegate_pubkey ],
    [ session => $session_id ],
    [ expires_at => $expires_at ],
  );
  push @tags, [ nick => $args{nick} ]
    if defined($args{nick}) && !ref($args{nick}) && length($args{nick});

  return $class->_authorize_artifact(
    %args,
    action      => 'session.delegate',
    artifacts   => [
      {
        type => 'nostr.event',
        params => {
          kind => defined($args{grant_kind}) ? $args{grant_kind} : 14142,
          tags => \@tags,
        },
      },
    ],
  );
}

sub _bridge_line {
  my ($class, %args) = @_;
  my $line = $args{line};

  die "--line is required\n"
    unless defined $line && !ref($line) && length($line);

  my $parsed = $class->_maybe_parse_bridge_line($line)
    or die "unsupported OVERNETAUTH bridge line\n";
  if ($parsed->{type} eq 'auth') {
    return $class->_authorize_auth(
      %args,
      challenge => $parsed->{challenge},
    );
  }

  return $class->_authorize_delegate(
    %args,
    relay_url       => $parsed->{relay_url},
    delegate_pubkey => $parsed->{delegate_pubkey},
    session_id      => $parsed->{session_id},
    expires_at      => $parsed->{expires_at},
  );
}

sub _bridge_stream {
  my ($class, %args) = @_;
  my $input = $args{input} || \*STDIN;
  my $output = $args{output} || \*STDOUT;
  my $count = 0;
  my %sasl_state;

  while (my $line = <$input>) {
    my $parsed = $class->_maybe_parse_bridge_line($line);
    if ($parsed) {
      my $wire = $parsed->{type} eq 'auth'
        ? $class->_authorize_auth(
            %args,
            line => undef,
            challenge => $parsed->{challenge},
          )
        : $class->_authorize_delegate(
            %args,
            line => undef,
            relay_url       => $parsed->{relay_url},
            delegate_pubkey => $parsed->{delegate_pubkey},
            session_id      => $parsed->{session_id},
            expires_at      => $parsed->{expires_at},
          );

      print {$output} $wire
        or die "write bridge output failed: $!";
      $count++;
      next;
    }

    if (my $chunk = $class->_maybe_parse_sasl_chunk($line)) {
      my @lines = $class->_consume_sasl_chunk(
        %args,
        state => \%sasl_state,
        chunk => $chunk->{chunk},
      );
      for my $wire (@lines) {
        print {$output} $wire
          or die "write bridge output failed: $!";
        $count++;
      }
      next;
    }

    my @flush = $class->_flush_sasl_chunk_state(
      %args,
      state => \%sasl_state,
    );
    for my $wire (@flush) {
      print {$output} $wire
        or die "write bridge output failed: $!";
      $count++;
    }
  }

  my @flush = $class->_flush_sasl_chunk_state(
    %args,
    state => \%sasl_state,
  );
  for my $wire (@flush) {
    print {$output} $wire
      or die "write bridge output failed: $!";
    $count++;
  }

  return $count;
}

sub _authorize_artifact {
  my ($class, %args) = @_;
  my $client = $args{client};
  die "client is required\n"
    unless $client && ref($client);

  my $scope = $args{scope};
  my $locator = defined($args{locator}) && !ref($args{locator}) && length($args{locator})
    ? $args{locator}
    : $scope;
  my $program_id = defined($args{program_id}) && !ref($args{program_id}) && length($args{program_id})
    ? $args{program_id}
    : 'irc.bridge';

  my $service = {
    locators => [ $locator ],
  };
  my $service_identity = _service_identity_descriptor(%args);
  $service->{service_identity} = $service_identity
    if $service_identity;

  my $response = $client->sessions_authorize(
    program_id   => $program_id,
    (defined($args{identity_id}) && !ref($args{identity_id}) && length($args{identity_id})
      ? (identity_id => $args{identity_id})
      : ()),
    service      => $service,
    scope        => $scope,
    action       => $args{action},
    interactive  => $args{interactive}
      ? JSON::PP::true
      : JSON::PP::false,
    (ref($args{challenge}) eq 'HASH' ? (challenge => $args{challenge}) : ()),
    artifacts    => $args{artifacts},
  );

  die _error_message($response)
    unless ref($response) eq 'HASH' && $response->{ok};
  die "auth agent did not return any artifacts\n"
    unless ref($response->{result}) eq 'HASH'
        && ref($response->{result}{artifacts}) eq 'ARRAY'
        && @{$response->{result}{artifacts}};

  return $response->{result}{artifacts}[0];
}

sub _maybe_parse_bridge_line {
  my ($class, $line) = @_;
  $line =~ s/\r?\n\z//;

  if ($line =~ /\bOVERNETAUTH\s+CHALLENGE\s+([0-9a-f]{64})\b/i) {
    return {
      type      => 'auth',
      challenge => lc $1,
    };
  }

  if ($line =~ /\bOVERNETAUTH\s+DELEGATE\s+([0-9a-f]{64})\s+(\S+)\s+(\S+)\s+(\d+)\b/i) {
    return {
      type            => 'delegate',
      delegate_pubkey => lc $1,
      session_id      => $2,
      relay_url       => $3,
      expires_at      => $4,
    };
  }

  return undef;
}

sub _maybe_parse_sasl_chunk {
  my ($class, $line) = @_;
  $line =~ s/\r?\n\z//;

  return undef
    unless $line =~ /\A(?::\S+\s+)?AUTHENTICATE\s+(\S+)\z/i;

  my $chunk = $1;
  return undef if uc($chunk) eq 'NOSTR';

  return {
    chunk => $chunk,
  };
}

sub _consume_sasl_chunk {
  my ($class, %args) = @_;
  my $state = $args{state} || {};
  my $chunk = $args{chunk};

  $state->{buffer} .= $chunk
    unless $chunk eq '+';

  return ()
    if $chunk ne '+'
      && length($chunk) == 400;

  return $class->_flush_sasl_chunk_state(%args);
}

sub _flush_sasl_chunk_state {
  my ($class, %args) = @_;
  my $state = $args{state} || {};
  my $buffer = delete $state->{buffer};

  return ()
    unless defined($buffer) && length($buffer);

  my $decoded = eval { decode_base64($buffer) };
  return ()
    unless defined $decoded;

  my $challenge_payload = eval { JSON::PP::decode_json($decoded) };
  return ()
    unless ref($challenge_payload) eq 'HASH';

  return $class->_render_sasl_response(
    %args,
    challenge_payload => $challenge_payload,
  );
}

sub _render_sasl_response {
  my ($class, %args) = @_;
  my $challenge_payload = $args{challenge_payload};

  my $challenge = $challenge_payload->{challenge};
  my $scope = $challenge_payload->{scope};
  return ()
    unless defined($challenge) && !ref($challenge) && length($challenge)
        && defined($scope) && !ref($scope) && length($scope);

  my %response = (
    auth_event => $class->_authorize_auth_artifact(
      %args,
      scope     => $scope,
      challenge => $challenge,
    )->{value},
  );

  my $delegate_required = grep { exists $challenge_payload->{$_} }
    qw(relay_url grant_kind delegate_pubkey session_id expires_at);
  if ($delegate_required) {
    die "malformed SASL NOSTR challenge payload\n"
      unless defined($challenge_payload->{relay_url}) && !ref($challenge_payload->{relay_url}) && length($challenge_payload->{relay_url})
          && defined($challenge_payload->{grant_kind}) && !ref($challenge_payload->{grant_kind}) && length($challenge_payload->{grant_kind})
          && defined($challenge_payload->{delegate_pubkey}) && !ref($challenge_payload->{delegate_pubkey}) && length($challenge_payload->{delegate_pubkey})
          && defined($challenge_payload->{session_id}) && !ref($challenge_payload->{session_id}) && length($challenge_payload->{session_id})
          && defined($challenge_payload->{expires_at}) && !ref($challenge_payload->{expires_at}) && length($challenge_payload->{expires_at});

    $response{delegate_event} = $class->_authorize_delegate_artifact(
      %args,
      scope            => $scope,
      relay_url        => $challenge_payload->{relay_url},
      grant_kind       => $challenge_payload->{grant_kind},
      delegate_pubkey  => $challenge_payload->{delegate_pubkey},
      session_id       => $challenge_payload->{session_id},
      expires_at       => $challenge_payload->{expires_at},
    )->{value};
  }

  my $payload = encode_base64(JSON::PP::encode_json(\%response), '');
  my $lines = Overnet::Program::IRC::Renderer::authenticate_payload_lines(
    payload => $payload,
  );

  return map {
    $args{quote}
      ? "/quote $_\n"
      : "$_\n"
  } @{$lines};
}

sub _render_irc_artifact {
  my ($class, %args) = @_;
  my $wire = Overnet::Auth::Bridge::IRC->encode_artifact(
    artifact => $args{artifact},
    protocol => 'irc',
    command  => $args{irc_command},
    encoding => 'base64-json',
  );

  return $args{quote}
    ? "/quote $wire->{command} $wire->{payload}\n"
    : "$wire->{payload}\n";
}

sub _service_identity_descriptor {
  my (%args) = @_;
  my $scheme = $args{service_identity_scheme};
  my $value = $args{service_identity_value};

  return undef
    unless defined($scheme) || defined($value) || defined($args{service_identity_display});

  die "--service-identity-scheme and --service-identity-value are required together\n"
    unless defined($scheme) && !ref($scheme) && length($scheme)
        && defined($value) && !ref($value) && length($value);

  my %descriptor = (
    scheme => $scheme,
    value  => $value,
  );
  $descriptor{display} = $args{service_identity_display}
    if defined($args{service_identity_display})
        && !ref($args{service_identity_display})
        && length($args{service_identity_display});

  return \%descriptor;
}

sub _error_message {
  my ($response) = @_;
  return "auth agent request failed\n"
    unless ref($response) eq 'HASH';
  return "auth agent request failed\n"
    unless ref($response->{error}) eq 'HASH';

  my $code = $response->{error}{code};
  my $message = $response->{error}{message};
  $code = defined($code) && !ref($code) && length($code) ? $code : 'unknown_error';
  $message = defined($message) && !ref($message) && length($message) ? $message : 'unknown auth-agent failure';
  return "$code: $message\n";
}

1;
