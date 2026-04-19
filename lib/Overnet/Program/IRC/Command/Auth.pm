package Overnet::Program::IRC::Command::Auth;

use strict;
use warnings;
use JSON::PP ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Renderer ();

our $VERSION = '0.001';

sub handle_cap {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $subcommand = defined $params[0] ? uc($params[0]) : '';
  my $client = $server->{clients}{$client_id}
    or return 0;
  my @supported = $server->_supported_capabilities;

  if ($subcommand eq 'LS') {
    $client->{cap_negotiation_active} = 1 if !$client->{registered};
    return $server->_send_client_line(
      $client_id,
      sprintf(':%s CAP * LS :%s', $server->{config}{server_name}, join(' ', @supported)),
    );
  }

  if ($subcommand eq 'REQ') {
    if (@params < 2 || !defined $params[1] || !length $params[1]) {
      $server->_send_need_more_params($client_id, 'CAP');
      return 1;
    }
    $client->{cap_negotiation_active} = 1 if !$client->{registered};

    my @requested = grep { defined($_) && length($_) } split /\s+/, $params[1];
    my %supported = map { $_ => 1 } @supported;
    if (@requested && !grep { !$supported{$_} } @requested) {
      $client->{capabilities}{$_} = 1 for @requested;
      $client->{capabilities}{'message-tags'} = 1
        if $client->{capabilities}{'server-time'}
          || $client->{capabilities}{'account-tag'};
      return $server->_send_client_line(
        $client_id,
        sprintf(':%s CAP * ACK :%s', $server->{config}{server_name}, join(' ', @requested)),
      );
    }

    return $server->_send_client_line(
      $client_id,
      sprintf(':%s CAP * NAK :%s', $server->{config}{server_name}, $params[1]),
    );
  }

  if ($subcommand eq 'END') {
    $client->{cap_negotiation_active} = 0;
    $server->_register_client_if_ready($client);
    return 1;
  }

  $server->_send_unknown_command($client_id, 'CAP');
  return 1;
}

sub handle_authenticate {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (!@params || !defined($params[0]) || !length($params[0])) {
    $server->_send_need_more_params($client_id, 'AUTHENTICATE');
    return 1;
  }

  my $argument = $params[0];
  if (!defined($client->{sasl_mechanism}) || !length($client->{sasl_mechanism})) {
    unless ($server->_client_has_capability($client, 'sasl')) {
      $server->_send_sasl_fail($client_id);
      return 1;
    }

    my $mechanism = uc $argument;
    unless ($mechanism eq 'NOSTR' && $server->_authority_profile eq 'nip29') {
      $server->_send_sasl_fail($client_id);
      return 1;
    }

    my $challenge_payload = start_sasl_nostr_exchange($server, $client);
    unless (ref($challenge_payload) eq 'HASH') {
      $server->_send_sasl_fail($client_id);
      return 1;
    }

    my $payload = encode_base64(JSON::PP::encode_json($challenge_payload), '');
    $server->_send_authenticate_payload($client_id, $payload);
    return 1;
  }

  if ($argument eq '*') {
    reset_sasl_state($server, $client);
    $server->_send_sasl_fail($client_id);
    return 1;
  }

  if ($argument eq '+') {
    return complete_sasl_exchange($server, $client_id);
  }

  $client->{sasl_buffer} .= $argument;
  return 1 if length($argument) == 400;
  return complete_sasl_exchange($server, $client_id);
}

sub handle_overnetauth {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'OVERNETAUTH');
    return 1;
  }

  my $subcommand = uc($params[0]);
  if ($subcommand eq 'CHALLENGE') {
    my $challenge = $server->_generate_authoritative_auth_challenge($client);
    $client->{authority_challenge} = $challenge;
    $server->_send_server_notice($client_id, "OVERNETAUTH CHALLENGE $challenge");
    return 1;
  }

  if ($subcommand eq 'AUTH') {
    if (@params < 2 || !defined $params[1] || !length $params[1]) {
      $server->_send_need_more_params($client_id, 'OVERNETAUTH');
      return 1;
    }

    my $decoded = eval { decode_base64($params[1]) };
    my $event_hash = eval { JSON::PP::decode_json($decoded) };
    unless (ref($event_hash) eq 'HASH') {
      $server->_send_server_notice($client_id, 'OVERNETAUTH AUTH requires a base64-encoded event object');
      return 1;
    }

    my $validation = validate_authoritative_auth_event(
      $server,
      challenge => $client->{authority_challenge},
      event     => $event_hash,
    );
    unless ($validation->{valid}) {
      my $reason = $validation->{reason} || '';
      my $message = $reason =~ /kind 22242/i
        ? 'OVERNETAUTH AUTH requires kind 22242'
        : $reason =~ /challenge/i
        ? 'OVERNETAUTH AUTH challenge does not match'
        : $reason =~ /relay scope/i
        ? 'OVERNETAUTH AUTH relay scope does not match'
        : 'OVERNETAUTH AUTH requires a valid signed Nostr event';
      $server->_send_server_notice($client_id, $message);
      return 1;
    }

    apply_authoritative_auth_validation($server, $client, $validation);
    delete $client->{authority_challenge};
    $server->_send_server_notice($client_id, 'OVERNETAUTH AUTH ' . $client->{authority_pubkey});
    return 1;
  }

  if ($subcommand eq 'DELEGATE') {
    unless ($server->_authority_relay_enabled) {
      $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires authority_relay');
      return 1;
    }
    unless (defined $client->{authority_pubkey} && !ref($client->{authority_pubkey}) && length($client->{authority_pubkey})) {
      $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires a prior AUTH');
      return 1;
    }

    if (@params == 1) {
      my $delegate = ensure_authoritative_delegate_offer($server, $client);
      $server->_send_server_notice(
        $client_id,
        join ' ',
          'OVERNETAUTH DELEGATE',
          $delegate->{delegate_pubkey},
          $delegate->{session_id},
          $delegate->{relay_url},
          $delegate->{expires_at},
      );
      return 1;
    }

    my $delegate_key = $client->{authority_delegate_key};
    my $delegate_session_id = $client->{authority_delegate_session_id};
    my $delegate_expires_at = $client->{authority_delegate_expires_at};
    unless (ref($delegate_key) eq 'Overnet::Core::Nostr::Key'
        && defined $delegate_session_id
        && !ref($delegate_session_id)
        && length($delegate_session_id)
        && defined $delegate_expires_at) {
      $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires a prior parameter request');
      return 1;
    }

    my $decoded = eval { decode_base64($params[1]) };
    my $event_hash = eval { JSON::PP::decode_json($decoded) };
    unless (ref($event_hash) eq 'HASH') {
      $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires a base64-encoded event object');
      return 1;
    }

    my $validation = accept_authoritative_delegate_event(
      $server,
      client          => $client,
      event_hash      => $event_hash,
      relay_url       => $server->_authority_relay_url,
      session_id      => $delegate_session_id,
      expires_at      => $delegate_expires_at,
      delegate_pubkey => $delegate_key->pubkey_hex,
      kind            => $server->_authority_grant_kind,
    );
    unless ($validation->{valid}) {
      my $reason = $validation->{reason} || '';
      my $message = $reason =~ /wrong event kind/i
        ? 'OVERNETAUTH DELEGATE uses the wrong event kind'
        : $reason =~ /authenticated user/i
        ? 'OVERNETAUTH DELEGATE pubkey does not match the authenticated user'
        : $reason =~ /relay does not match/i
        ? 'OVERNETAUTH DELEGATE relay does not match'
        : $reason =~ /server scope/i
        ? 'OVERNETAUTH DELEGATE server scope does not match'
        : $reason =~ /delegate pubkey/i
        ? 'OVERNETAUTH DELEGATE delegate pubkey does not match'
        : $reason =~ /session does not match/i
        ? 'OVERNETAUTH DELEGATE session does not match'
        : $reason =~ /expiration does not match/i
        ? 'OVERNETAUTH DELEGATE expiration does not match'
        : $reason =~ /relay publish failed/i
        ? 'OVERNETAUTH DELEGATE relay publish failed'
        : 'OVERNETAUTH DELEGATE requires a valid signed Nostr event';
      $server->_send_server_notice($client_id, $message);
      return 1;
    }
    $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE');
    return 1;
  }

  $server->_send_unknown_command($client_id, 'OVERNETAUTH');
  return 1;
}

sub start_sasl_nostr_exchange {
  my ($server, $client) = @_;
  return undef unless ref($client) eq 'HASH';

  my $challenge = $server->_generate_authoritative_auth_challenge($client);
  my %payload = (
    challenge => $challenge,
    scope     => $server->_authoritative_auth_scope,
  );

  if ($server->_authority_relay_enabled) {
    my $delegate = ensure_authoritative_delegate_offer($server, $client);
    return undef unless ref($delegate) eq 'HASH';
    @payload{qw(relay_url grant_kind delegate_pubkey session_id expires_at)} = (
      $delegate->{relay_url},
      $delegate->{grant_kind},
      $delegate->{delegate_pubkey},
      $delegate->{session_id},
      $delegate->{expires_at},
    );
  }

  $client->{authority_challenge} = $challenge;
  $client->{sasl_mechanism} = 'NOSTR';
  $client->{sasl_buffer} = '';
  $client->{sasl_challenge_payload} = \%payload;
  return \%payload;
}

sub complete_sasl_exchange {
  my ($server, $client_id) = @_;
  my $client = $server->{clients}{$client_id}
    or return 0;

  my $decoded = eval { decode_base64($client->{sasl_buffer} || '') };
  my $payload = eval { JSON::PP::decode_json($decoded) };
  unless (ref($payload) eq 'HASH') {
    reset_sasl_state($server, $client);
    $server->_send_sasl_fail($client_id);
    return 1;
  }

  my $challenge_payload = ref($client->{sasl_challenge_payload}) eq 'HASH'
    ? $client->{sasl_challenge_payload}
    : {};
  my $delegate_offer = $server->_authority_relay_enabled
    ? {
        key        => $client->{authority_delegate_key},
        session_id => $challenge_payload->{session_id},
        expires_at => $challenge_payload->{expires_at},
      }
    : undef;
  my $auth_validation = validate_authoritative_auth_event(
    $server,
    challenge => $challenge_payload->{challenge},
    event     => $payload->{auth_event},
  );
  unless ($auth_validation->{valid}) {
    reset_sasl_state($server, $client);
    $server->_send_sasl_fail($client_id);
    return 1;
  }

  apply_authoritative_auth_validation($server, $client, $auth_validation);
  if ($server->_authority_relay_enabled) {
    if (ref($delegate_offer) eq 'HASH') {
      $client->{authority_delegate_key} = $delegate_offer->{key}
        if ref($delegate_offer->{key}) eq 'Overnet::Core::Nostr::Key';
      $client->{authority_delegate_session_id} = $delegate_offer->{session_id}
        if defined $delegate_offer->{session_id};
      $client->{authority_delegate_expires_at} = $delegate_offer->{expires_at}
        if defined $delegate_offer->{expires_at};
    }
    unless (ref($payload->{delegate_event}) eq 'HASH') {
      clear_authoritative_binding($server, $client);
      reset_sasl_state($server, $client);
      $server->_send_sasl_fail($client_id);
      return 1;
    }
    my $delegate_result = accept_authoritative_delegate_event(
      $server,
      client          => $client,
      event_hash      => $payload->{delegate_event},
      relay_url       => $challenge_payload->{relay_url},
      session_id      => $challenge_payload->{session_id},
      expires_at      => $challenge_payload->{expires_at},
      delegate_pubkey => $challenge_payload->{delegate_pubkey},
      kind            => $challenge_payload->{grant_kind},
    );
    unless ($delegate_result->{valid}) {
      clear_authoritative_binding($server, $client);
      reset_sasl_state($server, $client);
      $server->_send_sasl_fail($client_id);
      return 1;
    }
  }

  reset_sasl_state($server, $client);
  $server->_send_sasl_success($client_id);
  $server->_register_client_if_ready($client);
  return 1;
}

sub reset_sasl_state {
  my ($server, $client) = @_;
  return 0 unless ref($client) eq 'HASH';
  delete $client->{sasl_mechanism};
  $client->{sasl_buffer} = '';
  delete $client->{sasl_challenge_payload};
  delete $client->{authority_challenge};
  return 1;
}

sub validate_authoritative_auth_event {
  my ($server, %args) = @_;
  my $challenge = $args{challenge};
  return {
    valid  => 0,
    reason => 'auth event challenge does not match',
  } unless defined $challenge && !ref($challenge) && length($challenge);

  return Overnet::Authority::Delegation->verify_auth_event(
    challenge => $challenge,
    scope     => $server->_authoritative_auth_scope,
    event     => $args{event},
  );
}

sub apply_authoritative_auth_validation {
  my ($server, $client, $validation) = @_;
  return 0 unless ref($client) eq 'HASH';
  return 0 unless ref($validation) eq 'HASH' && $validation->{valid};

  return set_authoritative_account(
    $server,
    $client,
    account => $validation->{pubkey},
  );
}

sub clear_authoritative_binding {
  my ($server, $client) = @_;
  return 0 unless ref($client) eq 'HASH';
  return set_authoritative_account($server, $client);
}

sub set_authoritative_account {
  my ($server, $client, %args) = @_;
  return 0 unless ref($client) eq 'HASH';

  my $old_account = _normalized_account($client->{authority_pubkey});
  my $new_account = _normalized_account($args{account});
  return 1
    if defined($old_account) && defined($new_account) && $old_account eq $new_account;
  return 1
    if !defined($old_account) && !defined($new_account);

  _send_account_notify($server, $client, $new_account)
    if ref($server);

  _clear_authoritative_delegate_state($server, $client);
  if (defined $new_account) {
    $client->{authority_pubkey} = $new_account;
  } else {
    delete $client->{authority_pubkey};
  }

  return 1;
}

sub _normalized_account {
  my ($account) = @_;
  return undef unless defined($account) && !ref($account) && length($account);
  return $account;
}

sub _send_account_notify {
  my ($server, $client, $new_account) = @_;
  return 1 unless ref($server) && ref($client) eq 'HASH';
  return 1 unless $client->{registered};
  return 1 unless defined($client->{nick}) && !ref($client->{nick}) && length($client->{nick});

  my %recipient_ids;
  for my $recipient_id ($server->_shared_client_ids_for_client($client->{id})) {
    next unless defined($recipient_id) && exists $server->{clients}{$recipient_id};
    my $recipient = $server->{clients}{$recipient_id};
    next unless ref($recipient) eq 'HASH' && $recipient->{registered};
    next unless $server->_client_has_capability($recipient, 'account-notify');
    $recipient_ids{$recipient_id} = 1;
  }
  return 1 unless %recipient_ids;

  my $line = Overnet::Program::IRC::Renderer::account_notify_line(
    nick     => $client->{nick},
    username => (
      defined($client->{username}) && !ref($client->{username}) && length($client->{username})
        ? $client->{username}
        : $client->{nick}
    ),
    host    => $server->_presentational_host_for_client($client),
    account => $new_account,
  );

  for my $recipient_id (sort { $a <=> $b } keys %recipient_ids) {
    $server->_send_client_line($recipient_id, $line);
  }

  return 1;
}

sub _clear_authoritative_delegate_state {
  my ($server, $client) = @_;
  return 0 unless ref($client) eq 'HASH';
  delete $client->{authority_delegate_key};
  delete $client->{authority_delegate_session_id};
  delete $client->{authority_delegate_expires_at};
  delete $client->{authority_delegate_event_id};
  delete $client->{authority_delegate_sequence};
  if (ref($server)) {
    delete $server->{authoritative_last_created_at}{$client->{id}};
    delete $server->{authoritative_delegate_sequences}{$client->{id}};
  }
  return 1;
}

sub ensure_authoritative_delegate_offer {
  my ($server, $client) = @_;
  return undef unless ref($client) eq 'HASH';

  if (!ref($client->{authority_delegate_key}) || ref($client->{authority_delegate_key}) ne 'Overnet::Core::Nostr::Key') {
    $client->{authority_delegate_key} = Overnet::Core::Nostr->generate_key;
  }
  if (!defined $client->{authority_delegate_session_id}
      || ref($client->{authority_delegate_session_id})
      || !length($client->{authority_delegate_session_id})) {
    $client->{authority_delegate_session_id} = $server->_generate_authoritative_delegate_session_id($client);
  }
  $client->{authority_delegate_expires_at} = int(time()) + 3600;

  return {
    relay_url       => $server->_authority_relay_url,
    grant_kind      => $server->_authority_grant_kind,
    delegate_pubkey => $client->{authority_delegate_key}->pubkey_hex,
    session_id      => $client->{authority_delegate_session_id},
    expires_at      => $client->{authority_delegate_expires_at},
  };
}

sub accept_authoritative_delegate_event {
  my ($server, %args) = @_;
  my $client = $args{client};
  return {
    valid  => 0,
    reason => 'delegation event pubkey does not match the authenticated user',
  } unless ref($client) eq 'HASH'
    && defined $client->{authority_pubkey}
    && !ref($client->{authority_pubkey})
    && $client->{authority_pubkey} =~ /\A[0-9a-f]{64}\z/;

  my $validation = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $client->{authority_pubkey},
    relay_url        => $args{relay_url},
    scope            => $server->_authoritative_auth_scope,
    delegate_pubkey  => $args{delegate_pubkey},
    session_id       => $args{session_id},
    expires_at       => $args{expires_at},
    kind             => $args{kind},
    event            => $args{event_hash},
  );
  return $validation unless $validation->{valid};

  my $publish = eval {
    $server->_request(
      method => 'nostr.publish_event',
      params => {
        relay_url => $args{relay_url},
        event     => $validation->{event},
      },
    );
  };
  if ($@ || ref($publish) ne 'HASH' || !$publish->{accepted}) {
    return {
      valid  => 0,
      reason => 'delegation relay publish failed',
    };
  }

  $client->{authority_delegate_event_id} = $validation->{event_id};
  $client->{authority_delegate_sequence} = 0;
  $server->{authoritative_last_created_at}{$client->{id}} = 0;
  $server->{authoritative_delegate_sequences}{$client->{id}} = 0;
  $server->_read_authoritative_grant_events(force => 1);
  return $validation;
}

1;
