package Overnet::Program::IRC::Server;

use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use IO::Handle;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL ();
use JSON::PP ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Overnet::Authority::HostedChannel;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Authority::Coordinator;
use Overnet::Program::IRC::Command::Auth;
use Overnet::Program::IRC::Command::Channel;
use Overnet::Program::IRC::Renderer;
use Time::HiRes qw(time);
use Overnet::Program::Protocol;
use Overnet::Program::TLSConfig;

our $VERSION = '0.001';
my $E2EE_DM_BODY_PREFIX = '+overnet-e2ee-v1 ';

sub new {
  my ($class, %args) = @_;

  my $protocol = $args{protocol} || Overnet::Program::Protocol->new;
  my $program_id = $args{program_id} || 'overnet.program.irc_server';
  my $program_version = exists $args{program_version} ? $args{program_version} : $VERSION;
  my $supported_protocol_versions = $args{supported_protocol_versions} || ['0.1'];

  die "protocol must be an Overnet::Program::Protocol instance\n"
    unless ref($protocol) && $protocol->isa('Overnet::Program::Protocol');
  die "program_id is required\n"
    unless defined $program_id && !ref($program_id) && length($program_id);
  die "program_version must be a non-empty string\n"
    if defined $program_version && (ref($program_version) || !length($program_version));
  die "supported_protocol_versions must be a non-empty array of strings\n"
    unless ref($supported_protocol_versions) eq 'ARRAY'
      && @{$supported_protocol_versions}
      && !grep { !defined($_) || ref($_) || !length($_) } @{$supported_protocol_versions};

  return bless {
    protocol                    => $protocol,
    program_id                  => $program_id,
    program_version             => $program_version,
    supported_protocol_versions => [ @{$supported_protocol_versions} ],
    next_request_id             => 1,
    pending_messages            => [],
    next_client_id              => 1,
    clients                     => {},
    channels                    => {},
    nick_to_client_id           => {},
    suppress_subscription_event_ids => {},
    subscription_event_origin_client_ids => {},
    rendered_subscription_event_ids => {},
    rendered_subscription_event_id_order => [],
    authoritative_last_created_at => {},
    authoritative_delegate_sequences => {},
    authoritative_subscription_channels => {},
    authoritative_discovered_channels => {},
    authoritative_grant_subscription_id => undef,
    authoritative_discovery_subscription_id => undef,
    inputs_processed            => 0,
    events_emitted              => 0,
    state_emitted               => 0,
    private_messages_emitted    => 0,
    capabilities_emitted        => 0,
  }, $class;
}

sub _is_shutdown_sentinel_error {
  my ($error) = @_;
  return 0 unless defined $error && !ref($error);
  return $error =~ /\A__shutdown__(?:\s+at\b.*)?\z/s ? 1 : 0;
}

sub run {
  my ($self) = @_;

  binmode(STDIN, ':raw');
  binmode(STDOUT, ':raw');
  binmode(STDERR, ':raw');
  STDOUT->autoflush(1);
  STDERR->autoflush(1);
  $SIG{PIPE} = 'IGNORE';

  $self->_send_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => $self->{program_id},
      supported_protocol_versions => $self->{supported_protocol_versions},
      (defined $self->{program_version}
        ? (program_version => $self->{program_version})
        : ()),
    )
  );

  while (!$self->{initialized} && !$self->{shutdown_complete}) {
    my $message = $self->_next_runtime_message;

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.init') {
      $self->_handle_runtime_init($message);
      next;
    }

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      next;
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      die "runtime fatal: " . ($message->{params}{code} || 'unknown') . "\n";
    }

    die "Unexpected message before runtime.init\n";
  }

  return 1 if $self->{shutdown_complete};

  my $ok = eval {
    $self->_run_server_loop;
    1;
  };
  my $error = $@;
  die $error if !$ok && !_is_shutdown_sentinel_error($error);
  return 1;
}

sub _handle_runtime_init {
  my ($self, $message) = @_;
  my $params = $message->{params} || {};

  my $loaded = eval {
    $self->_load_runtime_init($params);
    $self->_open_listen_socket;
    1;
  };
  if (!$loaded) {
    my $error = $@ || "Invalid runtime.init configuration\n";
    chomp $error;
    $self->_send_message(
      Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'program.operation_failed',
        message => $error,
      )
    );
    $self->_close_all_clients;
    $self->_close_listen_socket;
    return;
  }

  $self->_send_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $message->{id},
    )
  );

  $self->_send_message(Overnet::Program::Protocol::build_program_ready());

  my $opened = eval {
    $self->_open_adapter_session;
    $self->_ensure_authoritative_discovery_subscription;
    $self->_refresh_authoritative_discovery_cache;
    1;
  };
  if (!$opened) {
    my $error = $@ || "Failed to open IRC adapter session\n";
    chomp $error;
    return if _is_shutdown_sentinel_error($error);
    $self->_health(
      status  => 'failed',
      message => $error,
    );
    die "$error\n";
  }

  $self->_log(
    level   => 'info',
    message => 'runtime.init accepted',
    context => {
      instance_id => $self->{instance_id},
      adapter_id  => $self->{config}{adapter_id},
      network     => $self->{config}{network},
      listen_host => $self->{config}{listen_host},
      listen_port => $self->{config}{listen_port},
      server_name => $self->{config}{server_name},
    },
  );
  $self->_health(
    status  => 'ready',
    message => 'IRC server listening',
    details => {
      network           => $self->{config}{network},
      listen_host       => $self->{config}{listen_host},
      listen_port       => $self->{config}{listen_port},
      server_name       => $self->{config}{server_name},
      clients_connected => 0,
      joined_channels   => [],
      inputs_processed  => 0,
      events_emitted    => 0,
      state_emitted     => 0,
    },
  );
  $self->{initialized} = 1;
}

sub _handle_runtime_shutdown {
  my ($self, $message) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $message->{id},
    )
  );
  $self->{shutdown_complete} = 1;
}

sub _load_runtime_init {
  my ($self, $params) = @_;

  die "runtime.init params.instance_id is required\n"
    unless defined $params->{instance_id} && !ref($params->{instance_id}) && length($params->{instance_id});
  die "runtime.init params.config must be an object\n"
    unless ref($params->{config}) eq 'HASH';

  my $config = $params->{config};
  my $adapter_id = $config->{adapter_id};
  my $network = $config->{network};
  my $listen_host = exists $config->{listen_host} ? $config->{listen_host} : '127.0.0.1';
  my $listen_port = exists $config->{listen_port} ? $config->{listen_port} : 6667;
  my $listen_backlog = exists $config->{listen_backlog} ? $config->{listen_backlog} : 10;
  my $server_name = exists $config->{server_name} ? $config->{server_name} : 'overnet.irc.local';
  my $signing_key_file = $config->{signing_key_file};
  my $adapter_config = exists $config->{adapter_config} ? $config->{adapter_config} : {};
  my $authority_relay = exists $config->{authority_relay} ? $config->{authority_relay} : undef;
  my $tls = exists $config->{tls}
    ? Overnet::Program::TLSConfig->normalize(
        tls           => $config->{tls},
        implicit_mode => 'server',
      )
    : undef;

  die "config.adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "config.network is required\n"
    unless defined $network && !ref($network) && length($network);
  die "config.listen_host is required\n"
    unless defined $listen_host && !ref($listen_host) && length($listen_host);
  die "config.listen_port must be an integer between 0 and 65535\n"
    unless defined $listen_port && !ref($listen_port) && $listen_port =~ /\A(?:0|[1-9]\d{0,4})\z/ && $listen_port <= 65535;
  die "config.listen_backlog must be a positive integer\n"
    unless defined $listen_backlog && !ref($listen_backlog) && $listen_backlog =~ /\A[1-9]\d*\z/;
  die "config.server_name is required\n"
    unless defined $server_name && !ref($server_name) && length($server_name);
  die "config.signing_key_file is required\n"
    unless defined $signing_key_file && !ref($signing_key_file) && length($signing_key_file);
  die "config.adapter_config must be an object\n"
    unless ref($adapter_config) eq 'HASH';
  if (defined $authority_relay) {
    die "config.authority_relay must be an object\n"
      unless ref($authority_relay) eq 'HASH';
    die "config.authority_relay.url is required\n"
      unless defined $authority_relay->{url}
        && !ref($authority_relay->{url})
        && length($authority_relay->{url});
    if (exists $authority_relay->{poll_interval_ms}) {
      die "config.authority_relay.poll_interval_ms must be a positive integer\n"
        unless defined $authority_relay->{poll_interval_ms}
          && !ref($authority_relay->{poll_interval_ms})
          && $authority_relay->{poll_interval_ms} =~ /\A[1-9]\d*\z/;
    }
    if (exists $authority_relay->{query_timeout_ms}) {
      die "config.authority_relay.query_timeout_ms must be a positive integer\n"
        unless defined $authority_relay->{query_timeout_ms}
          && !ref($authority_relay->{query_timeout_ms})
          && $authority_relay->{query_timeout_ms} =~ /\A[1-9]\d*\z/;
    }
  }

  my $signing_key = Overnet::Core::Nostr->load_key(privkey => $signing_key_file);

  $self->{instance_id} = $params->{instance_id};
  $self->{config} = {
    adapter_id       => $adapter_id,
    network          => $network,
    listen_host      => $listen_host,
    listen_port      => 0 + $listen_port,
    listen_backlog   => 0 + $listen_backlog,
    server_name      => $server_name,
    signing_key_file => $signing_key_file,
    adapter_config   => { %{$adapter_config} },
    (defined $authority_relay
      ? (
        authority_relay => {
          url              => $authority_relay->{url},
          poll_interval_ms => exists $authority_relay->{poll_interval_ms}
            ? 0 + $authority_relay->{poll_interval_ms}
            : 250,
          query_timeout_ms => exists $authority_relay->{query_timeout_ms}
            ? 0 + $authority_relay->{query_timeout_ms}
            : 1_000,
        },
      )
      : ()),
    (defined $tls ? (tls => $tls) : ()),
  };
  $self->{signing_key} = $signing_key;
  $self->{tls_server_args} = defined $tls
    ? Overnet::Program::TLSConfig->server_start_args($tls)
    : undef;

  return 1;
}

sub _open_listen_socket {
  my ($self) = @_;

  my $listener = IO::Socket::INET->new(
    LocalAddr => $self->{config}{listen_host},
    LocalPort => $self->{config}{listen_port},
    Listen    => $self->{config}{listen_backlog},
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Failed to listen on $self->{config}{listen_host}:$self->{config}{listen_port}: $!\n";

  binmode($listener, ':raw');
  $listener->autoflush(1);

  $self->{listener_socket} = $listener;
  $self->{config}{listen_port} = $listener->sockport;
  return 1;
}

sub _open_adapter_session {
  my ($self) = @_;

  my $open = $self->_request(
    method => 'adapters.open_session',
    params => {
      adapter_id => $self->{config}{adapter_id},
      config     => $self->{config}{adapter_config},
    },
  );
  $self->{adapter_session_id} = $open->{adapter_session_id};
  return $self->{adapter_session_id};
}

sub _run_server_loop {
  my ($self) = @_;

  my $ok = eval {
    while (!$self->{shutdown_complete}) {
      my $drained = $self->_drain_pending_runtime_messages(max_messages => 8);
      last if $self->{shutdown_complete};

      my @handles = (\*STDIN);
      push @handles, $self->{listener_socket}
        if defined $self->{listener_socket};
      push @handles, map { $self->{clients}{$_}{socket} }
        sort keys %{$self->{clients}};

      my $selector = IO::Select->new(@handles);
      my @ready = $selector->can_read(0.1);
      if (!@ready) {
        $self->_maybe_poll_authoritative_relay;
        last if $self->{shutdown_complete};
        next;
      }

      for my $handle (@ready) {
        if ($self->_is_listener_socket($handle)) {
          $self->_accept_client;
          next;
        }

        if ($self->_is_runtime_stdin($handle)) {
          $self->_read_runtime_chunk;
          $self->_drain_pending_runtime_messages(max_messages => 8);
          last if $self->{shutdown_complete};
          next;
        }

        my $client_id = $self->_client_id_for_handle($handle);
        next unless defined $client_id;
        $self->_pump_client_socket($client_id);
        last if $self->{shutdown_complete};
      }
    }
    1;
  };
  my $error = $@;

  $self->_close_all_clients;
  $self->_close_listen_socket;
  die $error if !$ok && !_is_shutdown_sentinel_error($error);
  return 1;
}

sub _accept_client {
  my ($self) = @_;
  return 1 unless defined $self->{listener_socket};

  my $socket = $self->{listener_socket}->accept
    or die "Failed to accept IRC client connection: $!\n";

  binmode($socket, ':raw');
  $socket->autoflush(1);

  if (defined $self->{tls_server_args}) {
    my $upgraded = eval {
      IO::Socket::SSL->start_SSL(
        $socket,
        %{$self->{tls_server_args}},
      ) or die(IO::Socket::SSL::errstr() || "unknown TLS handshake failure");
    };
    if (!$upgraded) {
      my $error = $@ || "unknown TLS handshake failure";
      chomp $error;
      $self->_log(
        level   => 'warn',
        message => 'TLS handshake failed for IRC client connection',
        context => {
          error => $error,
        },
      );
      close $socket;
      return 1;
    }
    $socket = $upgraded;
  }

  my $client_id = 'client-' . $self->{next_client_id}++;
  $self->{clients}{$client_id} = {
    id              => $client_id,
    socket          => $socket,
    read_buffer     => '',
    registered      => 0,
    cap_negotiation_active => 0,
    capabilities    => {},
    nick            => undef,
    username        => undef,
    realname        => undef,
    dm_key          => undef,
    e2ee_pubkey     => undef,
    authority_pubkey => undef,
    authority_challenge => undef,
    sasl_mechanism  => undef,
    sasl_buffer     => '',
    sasl_challenge_payload => undef,
    joined_channels => {},
    peerhost        => eval { $socket->peerhost } || '',
    peerport        => eval { $socket->peerport } || 0,
  };

  return 1;
}

sub _pump_client_socket {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;

  my $bytes = sysread($client->{socket}, my $chunk, 4096);
  if (!defined $bytes) {
    die "Failed to read IRC client socket: $!\n"
      unless $!{EINTR};
    return 1;
  }

  if ($bytes == 0) {
    $self->_disconnect_client(
      $client_id,
      emit_quit => 0,
      reason    => 'client disconnected',
    );
    return 1;
  }

  my $probe_buffer = $client->{read_buffer} . $chunk;
  if (!defined $self->{tls_server_args} && $self->_looks_like_tls_client_hello($probe_buffer)) {
    $self->_log(
      level   => 'warn',
      message => 'TLS client hello received on plain IRC listener',
      context => {
        client_id => $client_id,
        peerhost  => $client->{peerhost},
        peerport  => $client->{peerport},
      },
    );
    $self->_disconnect_client(
      $client_id,
      emit_quit => 0,
      reason    => 'tls client hello on plain listener',
    );
    return 1;
  }

  $client->{read_buffer} = $probe_buffer;
  while ($client->{read_buffer} =~ s/\A([^\n]*\n)//) {
    my $line = $1;
    $line =~ s/\r?\n\z//;
    next unless length $line;
    $self->_handle_client_line($client_id, $line);
    last unless exists $self->{clients}{$client_id};
    last if $self->{shutdown_complete};
  }

  return 1;
}

sub _looks_like_tls_client_hello {
  my ($self, $buffer) = @_;
  return 0 unless defined $buffer;
  return 0 unless length($buffer) >= 3;

  my ($content_type, $major, $minor) = unpack('C3', substr($buffer, 0, 3));
  return 0 unless $content_type == 0x16;
  return 0 unless $major == 0x03;
  return 0 unless $minor >= 0x00 && $minor <= 0x04;
  return 1;
}

sub _handle_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  my $message = $self->_parse_irc_message($line);
  return 1 unless $message;

  my $command = $message->{command};
  my @params = @{$message->{params} || []};

  if ($command eq 'CAP') {
    return Overnet::Program::IRC::Command::Auth::handle_cap(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'NICK') {
    if (!@params || !defined $params[0] || !length $params[0]) {
      $self->_send_nonickname_given($client_id);
      return 1;
    }
    my $requested_nick = $params[0];

    if ($client->{registered}) {
      my $old_nick = $client->{nick};
      my $new_nick = $requested_nick;
      return 1 if defined $old_nick && $old_nick eq $new_nick;
      if ($self->_nick_in_use($new_nick, exclude_client_id => $client_id)) {
        $self->_send_nick_in_use($client_id, $new_nick);
        return 1;
      }

      my @shared_client_ids = $self->_shared_client_ids_for_client($client_id);
      $self->_send_line_to_client_ids(
        \@shared_client_ids,
        sprintf(':%s NICK :%s', $old_nick, $new_nick),
      );
      $self->_rename_client_channels(
        $client,
        old_nick => $old_nick,
        new_nick => $new_nick,
      );
      $self->_assign_client_nick($client_id, $new_nick);
      $self->_ensure_client_dm_subscription($client_id);
      $self->_emit_client_input(
        $client,
        {
          command  => 'NICK',
          nick     => $old_nick,
          new_nick => $new_nick,
        },
        suppress_render_event_types => {
          'irc.nick' => 1,
        },
      ) if defined $old_nick && length $old_nick;
      return 1;
    }

    if (defined $client->{nick}
        && defined $self->_nick_key($client->{nick})
        && defined $self->_nick_key($requested_nick)
        && $self->_nick_key($client->{nick}) eq $self->_nick_key($requested_nick)) {
      $self->_assign_client_nick($client_id, $requested_nick);
      $self->_register_client_if_ready($client);
      return 1;
    }

    if ($self->_nick_in_use($requested_nick, exclude_client_id => $client_id)) {
      $self->_send_nick_in_use($client_id, $requested_nick);
      return 1;
    }

    $self->_assign_client_nick($client_id, $requested_nick);
    $self->_register_client_if_ready($client);
    return 1;
  }

  if ($command eq 'USER') {
    return 1 if $client->{registered};
    if (@params < 4) {
      $self->_send_need_more_params($client_id, 'USER');
      return 1;
    }

    $client->{username} = $params[0];
    $client->{realname} = $params[3];
    $self->_register_client_if_ready($client);
    return 1;
  }

  if ($command eq 'PING') {
    my $token = defined $params[0] ? $params[0] : '';
    $self->_send_client_line($client_id, 'PONG :' . $token);
    return 1;
  }

  if ($command eq 'AUTHENTICATE') {
    return Overnet::Program::IRC::Command::Auth::handle_authenticate(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'QUIT') {
    my $reason = @params >= 1 ? $params[0] : undef;
    $self->_disconnect_client(
      $client_id,
      emit_quit => 1,
      reason    => $reason,
    );
    return 1;
  }

  if (!$client->{registered}) {
    if ($self->_command_requires_registration($command)) {
      $self->_send_not_registered($client_id);
      return 1;
    }

    $self->_send_unknown_command($client_id, $command);
    return 1;
  }

  if ($command eq 'OVERNETKEY') {
    if (!$self->_client_has_capability($client, 'overnet-e2ee')) {
      $self->_send_server_notice($client_id, 'OVERNETKEY requires CAP overnet-e2ee');
      return 1;
    }

    if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1] || !length $params[1]) {
      $self->_send_need_more_params($client_id, 'OVERNETKEY');
      return 1;
    }

    my $subcommand = uc($params[0]);
    if ($subcommand eq 'SET') {
      my $pubkey = lc $params[1];
      if ($pubkey !~ /\A[0-9a-f]{64}\z/) {
        $self->_send_server_notice($client_id, 'OVERNETKEY SET requires a 64-character lowercase hex pubkey');
        return 1;
      }

      $client->{e2ee_pubkey} = $pubkey;
      $self->_send_server_notice($client_id, "OVERNETKEY SET $pubkey");
      return 1;
    }

    if ($subcommand eq 'GET') {
      my $target_nick = $self->_canonical_current_nick($params[1]);
      if (!defined $target_nick) {
        $self->_send_no_such_nick($client_id, $params[1]);
        return 1;
      }

      my $target_client = $self->_client_for_current_nick($target_nick);
      my $pubkey = ref($target_client) eq 'HASH' ? ($target_client->{e2ee_pubkey} || '*') : '*';
      $self->_send_server_notice($client_id, "OVERNETKEY GET $target_nick $pubkey");
      return 1;
    }

    $self->_send_unknown_command($client_id, 'OVERNETKEY');
    return 1;
  }

  if ($command eq 'OVERNETAUTH') {
    return Overnet::Program::IRC::Command::Auth::handle_overnetauth(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'OVERNETCHANNEL') {
    return Overnet::Program::IRC::Command::Channel::handle_overnetchannel(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'USERHOST') {
    if (!@params) {
      $self->_send_need_more_params($client_id, 'USERHOST');
      return 1;
    }

    my @entries;
    my %seen;
    for my $nick (@params) {
      my $nick_key = $self->_nick_key($nick);
      next unless defined $nick_key;
      next if $seen{$nick_key}++;

      my $entry = $self->_userhost_entry_for_nick($nick);
      push @entries, $entry if defined $entry;
    }

    $self->_send_userhost_reply($client_id, \@entries);
    return 1;
  }

  if ($command eq 'WHO') {
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'WHO');
      return 1;
    }

    my $target = $params[0];
    if (!$self->_is_channel_name($target)) {
      $self->_send_no_such_channel($client_id, $target);
      return 1;
    }

    my $channel = $self->_client_joined_channel_name($client, $target);
    unless (defined $channel) {
      $self->_send_not_on_channel($client_id, $target);
      return 1;
    }

    $self->_send_who_list($client_id, $channel);
    return 1;
  }

  if ($command eq 'WHOIS') {
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'WHOIS');
      return 1;
    }

    my $target_nick = $params[0];
    my $entry = $self->_whois_entry_for_nick($target_nick);
    unless ($entry) {
      $self->_send_no_such_nick($client_id, $target_nick);
      return 1;
    }

    $self->_send_whois_reply($client_id, $entry);
    return 1;
  }

  if ($command eq 'MODE') {
    return Overnet::Program::IRC::Command::Channel::handle_mode(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'KICK') {
    return Overnet::Program::IRC::Command::Channel::handle_kick(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'INVITE') {
    return Overnet::Program::IRC::Command::Channel::handle_invite(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'JOIN') {
    return Overnet::Program::IRC::Command::Channel::handle_join(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'NAMES') {
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'NAMES');
      return 1;
    }
    my $channel_input = $params[0];
    if (!$self->_is_channel_name($channel_input)) {
      $self->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $self->_canonical_channel_name($channel_input);
    $self->_send_names_list($client_id, $channel, force => 1);
    return 1;
  }

  if ($command eq 'PART') {
    return Overnet::Program::IRC::Command::Channel::handle_part(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'PRIVMSG' || $command eq 'NOTICE') {
    return Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice(
      $self,
      $client_id,
      $command,
      \@params,
    );
  }

  if ($command eq 'TOPIC') {
    return Overnet::Program::IRC::Command::Channel::handle_topic(
      $self,
      $client_id,
      \@params,
    );
  }

  if ($command eq 'LUSERS') {
    $self->_send_lusers_reply($client_id);
    return 1;
  }

  if ($command eq 'LIST') {
    return Overnet::Program::IRC::Command::Channel::handle_list(
      $self,
      $client_id,
      \@params,
    );
  }

  $self->_send_unknown_command($client_id, $command);
  return 1;
}

sub _register_client_if_ready {
  my ($self, $client) = @_;
  return 0 if $client->{registered};
  return 0 unless defined $client->{nick} && length($client->{nick});
  return 0 unless defined $client->{username} && length($client->{username});
  return 0 if $client->{cap_negotiation_active};
  return 0 if defined $client->{sasl_mechanism} && length($client->{sasl_mechanism});

  $client->{registered} = 1;
  $client->{dm_key} ||= Overnet::Core::Nostr->generate_key;
  $self->_send_registration_prelude($client->{id});
  $self->_ensure_client_dm_subscription($client->{id});
  return 1;
}

sub _send_authenticate_payload {
  my ($self, $client_id, $payload) = @_;
  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::authenticate_payload_lines(
      payload => $payload,
    ),
  );
}

sub _send_sasl_success {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::sasl_success_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _send_sasl_fail {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::sasl_fail_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _command_requires_registration {
  my ($self, $command) = @_;
  return scalar grep { $_ eq ($command || '') } qw(JOIN PART PRIVMSG NOTICE TOPIC NAMES MODE KICK INVITE USERHOST WHO WHOIS LUSERS LIST OVERNETKEY OVERNETAUTH OVERNETCHANNEL);
}

sub _send_rendered_lines {
  my ($self, $client_id, $lines) = @_;
  return 0 unless ref($lines) eq 'ARRAY';

  my $sent = 0;
  for my $line (@{$lines}) {
    next unless defined $line && !ref($line);
    $self->_send_client_line($client_id, $line);
    $sent = 1;
  }

  return $sent ? 1 : 0;
}

sub _send_unknown_command {
  my ($self, $client_id, $command) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::unknown_command_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      command     => $command,
    ),
  );
}

sub _send_registration_prelude {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::registration_prelude_lines(
      server_name     => $self->{config}{server_name},
      nick            => $client->{nick},
      isupport_tokens => $self->_isupport_tokens,
    ),
  );
}

sub _send_nonickname_given {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::nonickname_given_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _send_not_registered {
  my ($self, $client_id) = @_;
  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::not_registered_line(
      server_name => $self->{config}{server_name},
    ),
  );
}

sub _send_need_more_params {
  my ($self, $client_id, $command) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::need_more_params_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      command     => $command,
    ),
  );
}

sub _send_server_notice {
  my ($self, $client_id, $text) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return 0 unless defined $client->{nick} && length($client->{nick});

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::server_notice_line(
      server_name => $self->{config}{server_name},
      nick        => $client->{nick},
      text        => $text,
    ),
  );
}

sub _send_no_such_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::no_such_nick_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      target_nick => $nick,
    ),
  );
}

sub _send_no_such_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::no_such_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_not_on_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::not_on_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_cannot_send_to_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::cannot_send_to_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_chan_op_privs_needed {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::chan_op_privs_needed_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_cannot_join_channel {
  my ($self, $client_id, $channel, %args) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::cannot_join_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
      reason      => $args{reason},
    ),
  );
}

sub _send_ban_list_entry {
  my ($self, $client_id, $channel, $ban_mask) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::ban_list_entry_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
      ban_mask    => $ban_mask,
    ),
  );
}

sub _send_end_of_ban_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::end_of_ban_list_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_exception_list_entry {
  my ($self, $client_id, $channel, $exception_mask) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::exception_list_entry_line(
      server_name    => $self->{config}{server_name},
      nick           => $self->_client_numeric_target($client),
      channel        => $channel,
      exception_mask => $exception_mask,
    ),
  );
}

sub _send_end_of_exception_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::end_of_exception_list_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_invite_exception_list_entry {
  my ($self, $client_id, $channel, $invite_exception_mask) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::invite_exception_list_entry_line(
      server_name           => $self->{config}{server_name},
      nick                  => $self->_client_numeric_target($client),
      channel               => $channel,
      invite_exception_mask => $invite_exception_mask,
    ),
  );
}

sub _send_end_of_invite_exception_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::end_of_invite_exception_list_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_inviting {
  my ($self, $client_id, $target_nick, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::inviting_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      target_nick => $target_nick,
      channel     => $channel,
    ),
  );
}

sub _send_channel_mode_is {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;
  my $channel_modes = '+n';
  my @mode_args;

  if (my $authoritative = $self->_derive_authoritative_channel_state($display_channel, force => 1)) {
    $channel_modes = $authoritative->{channel_modes}
      if defined $authoritative->{channel_modes}
        && !ref($authoritative->{channel_modes})
        && length($authoritative->{channel_modes});
    push @mode_args, $authoritative->{channel_key}
      if defined($authoritative->{channel_key}) && !ref($authoritative->{channel_key}) && length($authoritative->{channel_key});
    push @mode_args, $authoritative->{user_limit}
      if defined($authoritative->{user_limit}) && !ref($authoritative->{user_limit});
  }

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::channel_mode_is_line(
      server_name   => $self->{config}{server_name},
      nick          => $self->_client_numeric_target($client),
      channel       => $display_channel,
      channel_modes => $channel_modes,
      mode_args     => \@mode_args,
    ),
  );
}

sub _send_user_mode_is {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::user_mode_is_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _send_lusers_reply {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $target = $self->_client_numeric_target($client);
  my $registered_users = scalar grep { $self->{clients}{$_}{registered} } keys %{$self->{clients}};
  my $connected_clients = scalar keys %{$self->{clients}};
  my $channels = scalar keys %{$self->{channels}};

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::lusers_reply_lines(
      server_name      => $self->{config}{server_name},
      nick             => $target,
      registered_users => $registered_users,
      connected_clients => $connected_clients,
      channels         => $channels,
    ),
  );
}

sub _send_list_reply {
  my ($self, $client_id, $target) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick = $self->_client_numeric_target($client);

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::list_reply_lines(
      server_name => $self->{config}{server_name},
      nick        => $nick,
      entries     => [ $self->_list_entries($client, $target) ],
    ),
  );
}

sub _send_authoritative_invite_list_reply {
  my ($self, $client_id, $channel, $pending_invites) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick = $self->_client_numeric_target($client);
  my @lines = map {
    Overnet::Program::IRC::Renderer::authoritative_invite_list_entry_line(
      server_name  => $self->{config}{server_name},
      nick         => $nick,
      channel      => $channel,
      target_pubkey => $_->{target_pubkey},
      invite_code  => $_->{code},
    )
  } grep {
    ref($_) eq 'HASH'
      && defined($_->{target_pubkey}) && !ref($_->{target_pubkey}) && length($_->{target_pubkey})
      && defined($_->{code}) && !ref($_->{code}) && length($_->{code})
  } @{$pending_invites || []};

  push @lines, Overnet::Program::IRC::Renderer::end_of_authoritative_invite_list_line(
    server_name => $self->{config}{server_name},
    nick        => $nick,
    channel     => $channel,
  );

  return $self->_send_rendered_lines($client_id, \@lines);
}

sub _send_authoritative_join_request_list_reply {
  my ($self, $client_id, $channel, $pending_join_requests) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick = $self->_client_numeric_target($client);
  my @lines = map {
    Overnet::Program::IRC::Renderer::authoritative_join_request_list_entry_line(
      server_name    => $self->{config}{server_name},
      nick           => $nick,
      channel        => $channel,
      requester_pubkey => $_->{pubkey},
      actor_mask     => $_->{actor_mask},
    )
  } grep {
    ref($_) eq 'HASH'
      && defined($_->{pubkey}) && !ref($_->{pubkey}) && length($_->{pubkey})
  } @{$pending_join_requests || []};

  push @lines, Overnet::Program::IRC::Renderer::end_of_authoritative_join_request_list_line(
    server_name => $self->{config}{server_name},
    nick        => $nick,
    channel     => $channel,
  );

  return $self->_send_rendered_lines($client_id, \@lines);
}

sub _send_topic_reply {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  my $channel_key = $self->_channel_key($display_channel);
  return 0 unless defined $channel_key;
  my $target = $self->_client_numeric_target($client);

  if ($self->_is_authoritative_channel($display_channel)) {
    my $view = $self->_derive_authoritative_channel_view($display_channel);
    $view = $self->_derive_authoritative_channel_view($display_channel, force => 1)
      unless ref($view) eq 'HASH';
    $self->_sync_authoritative_topic_state_from_view($display_channel, $view);
    if (ref($view) eq 'HASH' && exists $view->{topic}) {
      return $self->_send_client_line($client_id,
        Overnet::Program::IRC::Renderer::topic_is_line(
          server_name => $self->{config}{server_name},
          nick        => $target,
          channel     => $display_channel,
          topic       => $view->{topic},
        ),
      );
    }

    return $self->_send_client_line($client_id,
      Overnet::Program::IRC::Renderer::no_topic_line(
        server_name => $self->{config}{server_name},
        nick        => $target,
        channel     => $display_channel,
      ),
    );
  }

  my $state = $self->{channels}{$channel_key}
    || $self->_channel_state($display_channel);

  if (defined $state->{topic_text} && !ref($state->{topic_text})) {
    return $self->_send_client_line($client_id,
      Overnet::Program::IRC::Renderer::topic_is_line(
        server_name => $self->{config}{server_name},
        nick        => $target,
        channel     => $display_channel,
        topic       => $state->{topic_text},
      ),
    );
  }

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::no_topic_line(
      server_name => $self->{config}{server_name},
      nick        => $target,
      channel     => $display_channel,
    ),
  );
}

sub _send_userhost_reply {
  my ($self, $client_id, $entries) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::userhost_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      entries     => $entries,
    ),
  );
}

sub _send_who_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::who_list_lines(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $display_channel,
      entries     => [ $self->_who_entries_for_channel($display_channel) ],
    ),
  );
}

sub _send_whois_reply {
  my ($self, $client_id, $entry) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return 0 unless ref($entry) eq 'HASH';

  my $target = $self->_client_numeric_target($client);
  my $display_nick = $entry->{nick};
  my $username = $entry->{username};
  my $host = $entry->{host};
  my $realname = $entry->{realname};

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::whois_reply_lines(
      server_name        => $self->{config}{server_name},
      nick               => $target,
      server_description => $self->_server_description,
      entry              => {
        nick     => $display_nick,
        username => $username,
        host     => $host,
        realname => $realname,
        (
          defined($entry->{account}) && !ref($entry->{account}) && length($entry->{account})
            ? (account => $entry->{account})
            : ()
        ),
      },
    ),
  );
}

sub _client_numeric_target {
  my ($self, $client) = @_;
  return '*'
    unless ref($client) eq 'HASH'
      && defined $client->{nick}
      && !ref($client->{nick})
      && length($client->{nick});
  return $client->{nick};
}

sub _irc_casefold {
  my ($self, $value) = @_;
  return undef unless defined $value && !ref($value);

  my $folded = $value;
  $folded =~ tr/A-Z[]\\^/a-z{}|~/;
  return $folded;
}

sub _nick_key {
  my ($self, $nick) = @_;
  return undef unless defined $nick && !ref($nick) && length($nick);
  return $self->_irc_casefold($nick);
}

sub _default_presentational_host {
  my ($self) = @_;
  return 'overnet.invalid';
}

sub _isupport_tokens {
  my ($self) = @_;
  return join ' ',
    'CASEMAPPING=rfc1459',
    'CHANTYPES=#&',
    'NETWORK=' . $self->{config}{network};
}

sub _supported_capabilities {
  my ($self) = @_;
  my @capabilities = ('message-tags', 'server-time', 'overnet-e2ee');
  if ($self->_authority_profile eq 'nip29') {
    push @capabilities, 'account-tag', 'account-notify', 'sasl';
  }
  return @capabilities;
}

sub _server_description {
  my ($self) = @_;
  return 'Overnet IRC';
}

sub _presentational_host_for_client {
  my ($self, $client) = @_;
  return $self->_default_presentational_host
    unless ref($client) eq 'HASH';
  return $client->{peerhost}
    if defined $client->{peerhost} && !ref($client->{peerhost}) && length($client->{peerhost});
  return $self->_default_presentational_host;
}

sub _canonical_current_nick {
  my ($self, $nick) = @_;
  my $key = $self->_nick_key($nick);
  return undef unless defined $key;

  my $client_id = $self->{nick_to_client_id}{$key};
  return undef unless defined $client_id && exists $self->{clients}{$client_id};
  return $self->{clients}{$client_id}{nick};
}

sub _client_for_current_nick {
  my ($self, $nick) = @_;
  my $key = $self->_nick_key($nick);
  return undef unless defined $key;

  my $client_id = $self->{nick_to_client_id}{$key};
  return undef unless defined $client_id && exists $self->{clients}{$client_id};
  return $self->{clients}{$client_id};
}

sub _client_has_capability {
  my ($self, $client, $capability) = @_;
  return 0 unless ref($client) eq 'HASH';
  return 0 unless defined $capability && !ref($capability) && length($capability);
  return $client->{capabilities}{$capability} ? 1 : 0;
}

sub _client_account_name {
  my ($self, $client) = @_;
  return undef unless ref($client) eq 'HASH';
  return undef unless defined($client->{authority_pubkey}) && !ref($client->{authority_pubkey}) && length($client->{authority_pubkey});
  return $client->{authority_pubkey};
}

sub _authority_profile {
  my ($self) = @_;
  return $self->{config}{adapter_config}{authority_profile} || '';
}

sub _authority_grant_kind {
  return 14142;
}

sub _authority_relay_config {
  my ($self) = @_;
  return $self->{config}{authority_relay};
}

sub _authority_relay_url {
  my ($self) = @_;
  my $config = $self->_authority_relay_config;
  return undef unless ref($config) eq 'HASH';
  return $config->{url};
}

sub _authority_relay_poll_interval_ms {
  my ($self) = @_;
  my $config = $self->_authority_relay_config;
  return undef unless ref($config) eq 'HASH';
  return $config->{poll_interval_ms};
}

sub _authority_relay_query_timeout_ms {
  my ($self) = @_;
  my $config = $self->_authority_relay_config;
  my $timeout_ms = ref($config) eq 'HASH'
    ? $config->{query_timeout_ms}
    : undef;
  $timeout_ms = 1_000
    unless defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/;
  return $timeout_ms;
}

sub _authority_relay_enabled {
  my ($self) = @_;
  my $url = $self->_authority_relay_url;
  return defined $url && !ref($url) && length($url) ? 1 : 0;
}

sub _authoritative_auth_scope {
  my ($self) = @_;
  return sprintf(
    'irc://%s/%s',
    $self->{config}{server_name},
    $self->{config}{network},
  );
}

sub _generate_authoritative_auth_challenge {
  my ($self, $client) = @_;
  return sha256_hex(join ':',
    time(),
    $$,
    rand(),
    (ref($client) eq 'HASH' ? ($client->{id} || '') : ''),
    (ref($client) eq 'HASH' ? ($client->{peerhost} || '') : ''),
    (ref($client) eq 'HASH' ? ($client->{peerport} || 0) : 0),
  );
}

sub _generate_authoritative_invite_code {
  my ($self, %args) = @_;
  return sha256_hex(join ':',
    time(),
    $$,
    rand(),
    ($args{channel} || ''),
    ($args{actor_pubkey} || ''),
    ($args{target_pubkey} || ''),
  );
}

sub _generate_authoritative_delegate_session_id {
  my ($self, $client) = @_;
  return sha256_hex(join ':',
    time(),
    $$,
    rand(),
    (ref($client) eq 'HASH' ? ($client->{id} || '') : ''),
    $self->{instance_id},
  );
}

sub _is_authoritative_channel {
  my ($self, $channel) = @_;
  return 0 unless $self->_authority_profile eq 'nip29';
  return 0 unless $self->_is_channel_name($channel);
  my $config = $self->{config}{adapter_config} || {};
  return 0 unless defined $config->{group_host}
    && !ref($config->{group_host})
    && length($config->{group_host});
  return 1;
}

sub _authoritative_group_binding {
  my ($self, $channel) = @_;
  return unless $self->_is_authoritative_channel($channel);

  my $canonical = $self->_canonical_channel_name($channel);
  return unless defined $canonical;

  my ($group_host, $group_id) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $self->{config}{network},
    session_config => $self->{config}{adapter_config},
    target         => $canonical,
  );
  return unless defined $group_host && defined $group_id;

  return ($group_host, $group_id);
}

sub _authoritative_nip29_stream_name {
  my ($self, $channel) = @_;
  my ($group_host, $group_id) = $self->_authoritative_group_binding($channel);
  return undef unless defined $group_host && defined $group_id;

  return join ':',
    'irc.authority.nip29',
    $self->{config}{network},
    $group_host,
    $group_id;
}

sub _authoritative_channels {
  my ($self) = @_;
  my %channels;
  my $channel_groups = $self->{config}{adapter_config}{channel_groups};
  if (ref($channel_groups) eq 'HASH') {
    for my $channel (sort keys %{$channel_groups}) {
      my $channel_key = $self->_channel_key($channel);
      next unless defined $channel_key;
      $channels{$channel_key} ||= $channel;
    }
  }
  for my $channel (sort keys %{$self->{authoritative_discovered_channels} || {}}) {
    my $channel_key = $self->_channel_key($channel);
    next unless defined $channel_key;
    $channels{$channel_key} ||= $channel;
  }
  for my $channel_key (keys %{$self->{channels} || {}}) {
    my $channel_name = $self->{channels}{$channel_key}{channel_name};
    next unless $self->_is_authoritative_channel($channel_name);
    $channels{$channel_key} ||= $channel_name;
  }
  return sort values %channels;
}

sub _authoritative_grant_subscription_id {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::authoritative_grant_subscription_id($self);
}

sub _authoritative_discovery_subscription_id {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::authoritative_discovery_subscription_id($self);
}

sub _authoritative_channel_subscription_ids {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::authoritative_channel_subscription_ids($self, $channel);
}

sub _ensure_authoritative_grant_subscription {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_grant_subscription($self);
}

sub _ensure_authoritative_discovery_subscription {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_discovery_subscription($self);
}

sub _ensure_authoritative_channel_subscription {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_channel_subscription($self, $channel);
}

sub _read_nostr_subscription_snapshot {
  my ($self, $subscription_id, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_nostr_subscription_snapshot($self, $subscription_id, %args);
}

sub _remember_authoritative_discovered_channel {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::remember_authoritative_discovered_channel($self, %args);
}

sub _forget_authoritative_discovered_channel {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::forget_authoritative_discovered_channel($self, $channel);
}

sub _record_authoritative_discovery_event {
  my ($self, $event) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::record_authoritative_discovery_event($self, $event);
}

sub _refresh_authoritative_discovery_cache {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_discovery_cache($self, %args);
}

sub _query_nostr_events {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::query_nostr_events($self, %args);
}

sub _read_authoritative_nip29_events_from_runtime {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_authoritative_nip29_events_from_runtime($self, $channel);
}

sub _load_authoritative_nip29_events {
  my ($self, $channel, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::load_authoritative_nip29_events($self, $channel, %args);
}

sub _refresh_authoritative_nip29_channel_cache {
  my ($self, $channel, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_nip29_channel_cache($self, $channel, %args);
}

sub _read_authoritative_nip29_events {
  my ($self, $channel, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_authoritative_nip29_events($self, $channel, %args);
}

sub _authoritative_channel_is_known {
  my ($self, $channel) = @_;
  return 0 unless $self->_is_authoritative_channel($channel);

  my $canonical = $self->_canonical_channel_name($channel);
  return 0 unless defined $canonical;

  return 1 if exists $self->{authoritative_discovered_channels}{$canonical};

  my $cache = $self->{authoritative_channel_cache}{$canonical};
  return 0 unless ref($cache) eq 'HASH';

  return 1 if ref($cache->{events}) eq 'ARRAY' && @{$cache->{events}};
  return 0;
}

sub _derive_authoritative_view_from_events {
  my ($self, $operation, $channel, $authoritative_events, %args) = @_;
  return undef unless defined $operation && !ref($operation) && length($operation);
  return undef unless $self->_is_authoritative_channel($channel);
  return undef unless ref($authoritative_events) eq 'ARRAY';

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => $operation,
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
          (defined $args{actor_pubkey} ? (actor_pubkey => $args{actor_pubkey}) : ()),
          (defined $args{actor_mask} ? (actor_mask => $args{actor_mask}) : ()),
          (ref($args{extra_input}) eq 'HASH' ? %{$args{extra_input}} : ()),
        },
      },
    );
  };
  return undef if $@;
  return undef unless ref($result->{view}) eq 'ARRAY' && @{$result->{view}};
  return $result->{view}[0];
}

sub _derive_authoritative_channel_view_from_events {
  my ($self, $channel, $authoritative_events, %args) = @_;
  return $self->_derive_authoritative_view_from_events(
    'authoritative_channel_view',
    $channel,
    $authoritative_events,
    %args,
  );
}

sub _derive_authoritative_join_admission_from_events {
  my ($self, $channel, $authoritative_events, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  return undef unless ref($authoritative_events) eq 'ARRAY';

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => 'authoritative_join_admission',
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
          (defined $args{actor_pubkey} ? (actor_pubkey => $args{actor_pubkey}) : ()),
          (defined $args{actor_mask} ? (actor_mask => $args{actor_mask}) : ()),
          (ref($args{extra_input}) eq 'HASH' ? %{$args{extra_input}} : ()),
        },
      },
    );
  };
  return undef if $@;
  return undef unless ref($result->{admission}) eq 'ARRAY' && @{$result->{admission}};
  return $result->{admission}[0];
}

sub _derive_authoritative_permission_from_events {
  my ($self, $operation, $channel, $authoritative_events, %args) = @_;
  return undef unless defined $operation && !ref($operation) && length($operation);
  return undef unless $self->_is_authoritative_channel($channel);
  return undef unless ref($authoritative_events) eq 'ARRAY';

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => $operation,
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
          (defined $args{actor_pubkey} ? (actor_pubkey => $args{actor_pubkey}) : ()),
          (defined $args{actor_mask} ? (actor_mask => $args{actor_mask}) : ()),
          (ref($args{extra_input}) eq 'HASH' ? %{$args{extra_input}} : ()),
        },
      },
    );
  };
  return undef if $@;
  return undef unless ref($result->{permission}) eq 'ARRAY' && @{$result->{permission}};
  return $result->{permission}[0];
}

sub _derive_authoritative_view {
  my ($self, $operation, $channel, %args) = @_;
  return undef unless defined $operation && !ref($operation) && length($operation);
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_view_from_events(
    $operation,
    $canonical,
    $cache->{events},
    %args,
  );
}

sub _authoritative_channel_state_from_view {
  my ($self, $view) = @_;
  return undef unless ref($view) eq 'HASH';

  return {
    operation         => 'authoritative_channel_state',
    authority_profile => $view->{authority_profile},
    object_type       => $view->{object_type},
    object_id         => $view->{object_id},
    group_host        => $view->{group_host},
    group_id          => $view->{group_id},
    group_ref         => $view->{group_ref},
    channel_modes     => $view->{channel_modes},
    (ref($view->{ban_masks}) eq 'ARRAY' ? (ban_masks => [ @{$view->{ban_masks}} ]) : ()),
    (ref($view->{exception_masks}) eq 'ARRAY' ? (exception_masks => [ @{$view->{exception_masks}} ]) : ()),
    (ref($view->{invite_exception_masks}) eq 'ARRAY' ? (invite_exception_masks => [ @{$view->{invite_exception_masks}} ]) : ()),
    (defined($view->{channel_key}) ? (channel_key => $view->{channel_key}) : ()),
    (defined($view->{user_limit}) ? (user_limit => $view->{user_limit}) : ()),
    (exists $view->{topic} ? (topic => $view->{topic}) : ()),
    (exists $view->{topic_actor_pubkey} ? (topic_actor_pubkey => $view->{topic_actor_pubkey}) : ()),
    ($view->{private} ? (private => 1) : ()),
    ($view->{restricted} ? (restricted => 1) : ()),
    ($view->{hidden} ? (hidden => 1) : ()),
    ($view->{tombstoned} ? (tombstoned => 1) : ()),
    supported_roles   => [ @{$view->{supported_roles} || []} ],
    members           => [
      map { +{
        pubkey                => $_->{pubkey},
        roles                 => [ @{$_->{roles} || []} ],
        presentational_prefix => $_->{presentational_prefix},
      } } @{$view->{members} || []}
    ],
    (ref($view->{retained_members}) eq 'ARRAY' ? (
      retained_members => [
        map { +{
          pubkey                => $_->{pubkey},
          roles                 => [ @{$_->{roles} || []} ],
          presentational_prefix => $_->{presentational_prefix},
        } } @{$view->{retained_members}}
      ],
    ) : ()),
  };
}

sub _derive_authoritative_channel_view {
  my ($self, $channel, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || !exists($cache->{view});
  if ($refresh) {
    my $old_view = $cache && ref($cache->{view}) eq 'HASH'
      ? $cache->{view}
      : undef;
    my $old_events = $cache && ref($cache->{events}) eq 'ARRAY'
      ? [ @{$cache->{events}} ]
      : [];
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
    if ($args{reconcile_pending_invites} && $self->_authority_relay_enabled) {
      $self->_reconcile_authoritative_pending_invites_from_refresh(
        channel    => $canonical,
        old_view   => $old_view,
        old_events => $old_events,
        new_view   => $cache->{view},
        new_events => $cache->{events},
      );
    }
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_channel_view_from_events(
    $canonical,
    $cache->{events},
    %args,
  ) if defined $args{actor_pubkey};

  return $cache->{view};
}

sub _derive_authoritative_ban_list_view {
  my ($self, $channel, %args) = @_;
  return $self->_derive_authoritative_view(
    'authoritative_ban_list_view',
    $channel,
    %args,
  );
}

sub _derive_authoritative_list_entry_view {
  my ($self, $channel, %args) = @_;
  return $self->_derive_authoritative_view(
    'authoritative_list_entry_view',
    $channel,
    %args,
  );
}

sub _derive_authoritative_join_admission {
  my ($self, $channel, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    my $old_view = $cache && ref($cache->{view}) eq 'HASH'
      ? $cache->{view}
      : undef;
    my $old_events = $cache && ref($cache->{events}) eq 'ARRAY'
      ? [ @{$cache->{events}} ]
      : [];
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
    if ($args{reconcile_pending_invites} && $self->_authority_relay_enabled) {
      $self->_reconcile_authoritative_pending_invites_from_refresh(
        channel    => $canonical,
        old_view   => $old_view,
        old_events => $old_events,
        new_view   => $cache->{view},
        new_events => $cache->{events},
      );
    }
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_join_admission_from_events(
    $canonical,
    $cache->{events},
    %args,
  );
}

sub _derive_authoritative_speak_permission {
  my ($self, $channel, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_permission_from_events(
    'authoritative_speak_permission',
    $canonical,
    $cache->{events},
    %args,
  );
}

sub _derive_authoritative_topic_permission {
  my ($self, $channel, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_permission_from_events(
    'authoritative_topic_permission',
    $canonical,
    $cache->{events},
    %args,
  );
}

sub _derive_authoritative_mode_write_permission {
  my ($self, $channel, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_permission_from_events(
    'authoritative_mode_write_permission',
    $canonical,
    $cache->{events},
    actor_pubkey => $args{actor_pubkey},
    extra_input  => {
      mode      => $args{mode},
      mode_args => ref($args{mode_args}) eq 'ARRAY' ? $args{mode_args} : [],
    },
  );
}

sub _derive_authoritative_channel_action_permission {
  my ($self, $channel, %args) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  my $cache = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache(
      $canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  return undef unless $cache && ref($cache->{events}) eq 'ARRAY';
  return $self->_derive_authoritative_permission_from_events(
    'authoritative_channel_action_permission',
    $canonical,
    $cache->{events},
    actor_pubkey => $args{actor_pubkey},
    extra_input  => {
      action => $args{action},
      (defined $args{target_pubkey} ? (target_pubkey => $args{target_pubkey}) : ()),
    },
  );
}

sub _authoritative_join_admission_is_populated {
  my ($self, $admission) = @_;
  return 0 unless ref($admission) eq 'HASH';
  return 1 if exists $admission->{allowed};
  return 1 if exists $admission->{member};
  return 1 if exists $admission->{present};
  return 1 if exists $admission->{invite_code};
  return 1 if exists $admission->{deleted};
  return 1 if exists $admission->{create_channel};
  return 1 if exists $admission->{auth_required};
  return 1 if exists $admission->{request_join};
  return 1 if exists $admission->{pending_request};
  return 1 if exists $admission->{reason};
  return 0;
}

sub _authoritative_permission_is_populated {
  my ($self, $permission) = @_;
  return 0 unless ref($permission) eq 'HASH';
  return 1 if exists $permission->{allowed};
  return 1 if exists $permission->{reason};
  return 1 if exists $permission->{roles};
  return 1 if exists $permission->{presentational_prefix};
  return 0;
}

sub _derive_authoritative_channel_state {
  my ($self, $channel, %args) = @_;
  my $view = $self->_derive_authoritative_channel_view($channel, %args);
  return $self->_authoritative_channel_state_from_view($view);
}

sub _sort_authoritative_events {
  my ($self, $events) = @_;
  my @decorated;
  my $index = 0;
  for my $event (@{$events || []}) {
    push @decorated, [ $index++, $event ];
  }
  return [
    map { $_->[1] } sort {
      ((($a->[1]{created_at}) || 0) <=> (($b->[1]{created_at}) || 0))
        || ($a->[0] <=> $b->[0])
    } @decorated
  ];
}

sub _read_authoritative_grant_events {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_authoritative_grant_events($self, %args);
}

sub _client_authoritative_pubkey {
  my ($self, $client) = @_;
  return undef unless ref($client) eq 'HASH';
  return undef unless defined $client->{authority_pubkey} && !ref($client->{authority_pubkey}) && length($client->{authority_pubkey});
  return $client->{authority_pubkey};
}

sub _effective_authoritative_actor_pubkey_from_event {
  my ($self, $event) = @_;
  return undef unless ref($event) eq 'HASH';

  my %tags = $self->_first_tag_values($event->{tags});
  return $tags{overnet_actor}
    if defined $tags{overnet_actor}
      && !ref($tags{overnet_actor})
      && $tags{overnet_actor} =~ /\A[0-9a-f]{64}\z/;
  return $event->{pubkey}
    if defined $event->{pubkey}
      && !ref($event->{pubkey})
      && $event->{pubkey} =~ /\A[0-9a-f]{64}\z/;
  return undef;
}

sub _authoritative_grant_nick_map {
  my ($self) = @_;
  my $cache = $self->{authoritative_grant_cache} ||= {};
  return $cache->{nick_by_pubkey}
    if ref($cache->{nick_by_pubkey}) eq 'HASH';

  my %nick_by_pubkey;
  for my $event (@{$self->_read_authoritative_grant_events}) {
    next unless ref($event) eq 'HASH';
    next unless ($event->{kind} || 0) == $self->_authority_grant_kind;
    next unless defined $event->{pubkey} && !ref($event->{pubkey}) && $event->{pubkey} =~ /\A[0-9a-f]{64}\z/;

    my %tags = $self->_first_tag_values($event->{tags});
    next unless defined $tags{relay} && $tags{relay} eq $self->_authority_relay_url;
    next if defined $tags{expires_at}
      && $tags{expires_at} =~ /\A\d+\z/
      && $tags{expires_at} < time();
    next unless defined $tags{nick} && !ref($tags{nick}) && length($tags{nick});

    my $current = $nick_by_pubkey{$event->{pubkey}};
    next if $current
      && (($current->{created_at} || 0) > ($event->{created_at} || 0));

    $nick_by_pubkey{$event->{pubkey}} = {
      nick       => $tags{nick},
      created_at => $event->{created_at} || 0,
    };
  }

  $cache->{nick_by_pubkey} = \%nick_by_pubkey;
  return $cache->{nick_by_pubkey};
}

sub _authoritative_nick_for_pubkey {
  my ($self, $pubkey) = @_;
  return undef unless defined $pubkey && !ref($pubkey) && $pubkey =~ /\A[0-9a-f]{64}\z/;

  for my $client_id (sort keys %{$self->{clients}}) {
    my $client = $self->{clients}{$client_id};
    next unless ref($client) eq 'HASH' && $client->{registered};
    next unless defined $client->{nick} && !ref($client->{nick}) && length($client->{nick});
    my $client_pubkey = $self->_client_authoritative_pubkey($client);
    next unless defined $client_pubkey && $client_pubkey eq $pubkey;
    return $client->{nick};
  }

  my $nick_map = $self->_authoritative_grant_nick_map;
  return undef unless ref($nick_map) eq 'HASH';
  return $nick_map->{$pubkey}{nick}
    if ref($nick_map->{$pubkey}) eq 'HASH';
  return undef;
}

sub _authoritative_member_for_pubkey {
  my ($self, $state, $pubkey, %args) = @_;
  return undef unless ref($state) eq 'HASH';
  return undef unless defined $pubkey && !ref($pubkey) && length($pubkey);
  my $field = defined $args{field} && !ref($args{field}) && length($args{field})
    ? $args{field}
    : 'members';

  for my $member (@{$state->{$field} || []}) {
    next unless ref($member) eq 'HASH';
    next unless defined $member->{pubkey};
    return $member if $member->{pubkey} eq $pubkey;
  }

  return undef;
}

sub _authoritative_roles_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  return () unless defined $pubkey;

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return () unless ref($state) eq 'HASH';
  my $member = $self->_authoritative_member_for_pubkey($state, $pubkey);
  return () unless ref($member) eq 'HASH';
  return @{$member->{roles} || []};
}

sub _authoritative_retained_roles_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  return () unless defined $pubkey;

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return () unless ref($state) eq 'HASH';
  my $member = $self->_authoritative_member_for_pubkey(
    $state,
    $pubkey,
    field => 'retained_members',
  );
  return () unless ref($member) eq 'HASH';
  return @{$member->{roles} || []};
}

sub _client_is_authoritative_operator {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.operator' } $self->_authoritative_roles_for_client($channel, $client);
}

sub _client_is_retained_authoritative_operator {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.operator' } $self->_authoritative_retained_roles_for_client($channel, $client);
}

sub _client_has_authoritative_voice {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.voice' } $self->_authoritative_roles_for_client($channel, $client);
}

sub _channel_mode_enabled {
  my ($self, $state, $mode_letter) = @_;
  return 0 unless ref($state) eq 'HASH';
  return 0 unless defined $mode_letter && !ref($mode_letter) && length($mode_letter) == 1;
  my $channel_modes = $state->{channel_modes} || '';
  return $channel_modes =~ /\Q$mode_letter\E/ ? 1 : 0;
}

sub _authoritative_channel_state_for_enforcement {
  my ($self, $channel) = @_;
  my $state = $self->_derive_authoritative_channel_state($channel);
  return $state if ref($state) eq 'HASH';
  return $self->_derive_authoritative_channel_state($channel, force => 1);
}

sub _channel_is_moderated_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return 0 unless ref($state) eq 'HASH';
  return 0 unless $self->_channel_mode_enabled($state, 'm');
  return 0 if $self->_client_is_authoritative_operator($channel, $client);
  return 0 if $self->_client_has_authoritative_voice($channel, $client);
  return 1;
}

sub _channel_is_topic_restricted_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return 0 unless ref($state) eq 'HASH';
  return 0 unless $self->_channel_mode_enabled($state, 't');
  return 0 if $self->_client_is_authoritative_operator($channel, $client);
  return 1;
}

sub _authoritative_group_metadata_from_state {
  my ($self, $state) = @_;
  return {
    closed           => $self->_channel_mode_enabled($state, 'i') ? 1 : 0,
    moderated        => $self->_channel_mode_enabled($state, 'm') ? 1 : 0,
    topic_restricted => $self->_channel_mode_enabled($state, 't') ? 1 : 0,
    ban_masks        => ref($state->{ban_masks}) eq 'ARRAY' ? [ @{$state->{ban_masks}} ] : [],
    (ref($state->{exception_masks}) eq 'ARRAY' && @{$state->{exception_masks}} ? (exception_masks => [ @{$state->{exception_masks}} ]) : ()),
    (ref($state->{invite_exception_masks}) eq 'ARRAY' && @{$state->{invite_exception_masks}} ? (invite_exception_masks => [ @{$state->{invite_exception_masks}} ]) : ()),
    (defined($state->{channel_key}) ? (channel_key => $state->{channel_key}) : ()),
    (defined($state->{user_limit}) ? (user_limit => $state->{user_limit}) : ()),
    ($state->{private} ? (private => 1) : ()),
    ($state->{restricted} ? (restricted => 1) : ()),
    ($state->{hidden} ? (hidden => 1) : ()),
    tombstoned       => $state->{tombstoned} ? 1 : 0,
    (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
  };
}

sub _authoritative_irc_mask_for_client {
  my ($self, $client) = @_;
  return undef unless ref($client) eq 'HASH';
  return undef unless defined $client->{nick} && !ref($client->{nick}) && length($client->{nick});

  my $username = defined $client->{username} && !ref($client->{username}) && length($client->{username})
    ? $client->{username}
    : $client->{nick};
  my $host = $self->_presentational_host_for_client($client);

  return Overnet::Authority::HostedChannel::irc_user_mask(
    nick => $client->{nick},
    user => $username,
    host => $host,
  );
}

sub _authoritative_topic_line_from_view {
  my ($self, $channel, $view) = @_;
  return undef unless ref($view) eq 'HASH';
  return undef unless exists $view->{topic};

  my $display_channel = $self->_canonical_channel_name($channel);
  return undef unless defined $display_channel;

  my $prefix = $self->{config}{server_name};
  if (defined $view->{topic_actor_pubkey}
      && !ref($view->{topic_actor_pubkey})
      && $view->{topic_actor_pubkey} =~ /\A[0-9a-f]{64}\z/) {
    $prefix = $self->_authoritative_nick_for_pubkey($view->{topic_actor_pubkey})
      || $prefix;
  }

  return sprintf(':%s TOPIC %s :%s', $prefix, $display_channel, $view->{topic});
}

sub _sync_authoritative_topic_state_from_view {
  my ($self, $channel, $view) = @_;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  my $channel_key = $self->_channel_key($display_channel);
  return 0 unless defined $channel_key;
  if (ref($view) eq 'HASH' && $view->{tombstoned}) {
    if (exists $self->{channels}{$channel_key}) {
      $self->{channels}{$channel_key}{topic_text} = undef;
      $self->{channels}{$channel_key}{topic_line} = undef;
    }
    return 1;
  }

  my $state = $self->_channel_state($display_channel);
  if (ref($view) eq 'HASH' && exists $view->{topic}) {
    $state->{topic_text} = $view->{topic};
    $state->{topic_line} = $self->_authoritative_topic_line_from_view($display_channel, $view);
  } else {
    $state->{topic_text} = undef;
    $state->{topic_line} = undef;
  }

  return 1;
}

sub _apply_authoritative_channel_tombstone {
  my ($self, $channel, %args) = @_;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  my $reason = defined($args{reason}) && !ref($args{reason}) && length($args{reason})
    ? $args{reason}
    : 'channel deleted';
  my $channel_key = $self->_channel_key($display_channel);
  return 0 unless defined $channel_key;

  $self->_forget_authoritative_discovered_channel($display_channel);

  my $state = $self->{channels}{$channel_key};
  unless (ref($state) eq 'HASH') {
    $self->_close_channel_subscription($display_channel);
    return 1;
  }

  my @client_ids = grep { exists $self->{clients}{$_} } sort keys %{$state->{members} || {}};
  for my $client_id (@client_ids) {
    my $client = $self->{clients}{$client_id};
    next unless ref($client) eq 'HASH';
    my $nick = defined $client->{nick} && !ref($client->{nick}) && length($client->{nick})
      ? $client->{nick}
      : $self->{config}{server_name};
    my $line = sprintf(':%s PART %s', $nick, $display_channel);
    $line .= ' :' . $reason;
    $self->_broadcast_channel_line($display_channel, $line);
    $self->_remove_client_from_channel(
      $client_id,
      $display_channel,
      nick => $nick,
    );
  }

  if (exists $self->{channels}{$channel_key}) {
    $self->_close_channel_subscription($display_channel);
    delete $self->{channels}{$channel_key};
  }

  return 1;
}

sub _authoritative_join_admission_for_client {
  my ($self, $channel, $client, %args) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  my $actor_mask = $self->_authoritative_irc_mask_for_client($client);
  my $join_key = $args{join_key};
  my $canonical = $self->_canonical_channel_name($channel);
  my $cache = defined $canonical ? $self->{authoritative_channel_cache}{$canonical} : undef;
  my $events = $self->_authority_relay_enabled
      && !(ref($cache) eq 'HASH' && ref($cache->{events}) eq 'ARRAY')
    ? $self->_read_authoritative_nip29_events($channel, force => 1)
    : $self->_read_authoritative_nip29_events($channel);
  $events = $self->_read_authoritative_nip29_events($channel, force => 1)
    if ref($events) eq 'ARRAY' && !@{$events} && $self->_authority_relay_enabled && ref($cache) eq 'HASH';
  if (ref($events) eq 'ARRAY' && !@{$events}) {
    if ($self->_authoritative_channel_is_known($channel)) {
      return {
        allowed       => 0,
        create_channel => 0,
        auth_required => 0,
        reason        => 'authoritative state unavailable',
      };
    }
    return {
      allowed      => $pubkey ? 1 : 0,
      create_channel => $pubkey ? 1 : 0,
      auth_required => $pubkey ? 0 : 1,
      reason       => '',
    };
  }

  my $admission = defined $pubkey
    ? $self->_derive_authoritative_join_admission(
        $channel,
        actor_pubkey              => $pubkey,
        actor_mask                => $actor_mask,
        (defined($join_key) ? (extra_input => { join_key => $join_key }) : ()),
        reconcile_pending_invites => 1,
      )
    : $self->_derive_authoritative_join_admission($channel);
  if (!$self->_authoritative_join_admission_is_populated($admission)) {
    $admission = defined $pubkey
      ? $self->_derive_authoritative_join_admission(
          $channel,
          force                     => 1,
          actor_pubkey              => $pubkey,
          actor_mask                => $actor_mask,
          (defined($join_key) ? (extra_input => { join_key => $join_key }) : ()),
          reconcile_pending_invites => 1,
        )
      : $self->_derive_authoritative_join_admission($channel, force => 1);
  }
  return {
    allowed => 0,
    auth_required => $pubkey ? 0 : 1,
    reason  => '',
  } unless $self->_authoritative_join_admission_is_populated($admission) || ref(
      $admission = (
        defined $pubkey
          ? do {
              my $view = $self->_derive_authoritative_channel_view(
                $channel,
                actor_pubkey              => $pubkey,
                actor_mask                => $actor_mask,
                reconcile_pending_invites => 1,
              );
              if (ref($view) ne 'HASH') {
                $view = $self->_derive_authoritative_channel_view(
                  $channel,
                  force                     => 1,
                  actor_pubkey              => $pubkey,
                  actor_mask                => $actor_mask,
                  reconcile_pending_invites => 1,
                );
              }
              if (ref($view) eq 'HASH' && ref($view->{admission}) eq 'HASH') {
                my $present = scalar grep {
                  ref($_) eq 'HASH'
                    && defined($_->{pubkey})
                    && $_->{pubkey} eq $pubkey
                } @{$view->{present_members} || []};
                +{
                  allowed => $view->{admission}{allowed} ? 1 : 0,
                  (defined $view->{admission}{member} ? (member => $view->{admission}{member} ? 1 : 0) : ()),
                  present => $present ? 1 : 0,
                  (defined $view->{admission}{invite_code} ? (invite_code => $view->{admission}{invite_code}) : ()),
                  (defined $view->{admission}{deleted} ? (deleted => $view->{admission}{deleted} ? 1 : 0) : ()),
                  (defined $view->{admission}{request_join} ? (request_join => $view->{admission}{request_join} ? 1 : 0) : ()),
                  (defined $view->{admission}{pending_request} ? (pending_request => $view->{admission}{pending_request} ? 1 : 0) : ()),
                  reason  => defined $view->{admission}{reason} ? $view->{admission}{reason} : '',
                };
              } elsif (ref($view) eq 'HASH' && $view->{tombstoned}) {
                +{
                  allowed => 0,
                  deleted => 1,
                  reason  => 'deleted',
                };
              } elsif (ref($view) eq 'HASH') {
                my $state = $self->_authoritative_channel_state_from_view($view);
                +{
                  allowed => $self->_channel_mode_enabled($state, 'i') ? 0 : 1,
                  present => 0,
                  reason  => $self->_channel_mode_enabled($state, 'i') ? '+i' : '',
                };
              } else {
                undef;
              }
            }
          : do {
              my $view = $self->_derive_authoritative_channel_view($channel);
              $view = $self->_derive_authoritative_channel_view($channel, force => 1)
                unless ref($view) eq 'HASH';
              if (ref($view) eq 'HASH' && $view->{tombstoned}) {
                +{
                  allowed => 0,
                  deleted => 1,
                  reason  => 'deleted',
                };
              } elsif (ref($view) eq 'HASH') {
                my $state = $self->_authoritative_channel_state_from_view($view);
                +{
                  allowed => $self->_channel_mode_enabled($state, 'i') ? 0 : 1,
                  present => 0,
                  reason  => $self->_channel_mode_enabled($state, 'i') ? '+i' : '',
                };
              } else {
                undef;
              }
            }
      )
    ) eq 'HASH';

  return {
    allowed => $admission->{allowed} ? 1 : 0,
    (defined $admission->{member} ? (member => $admission->{member} ? 1 : 0) : ()),
    (defined $admission->{present} ? (present => $admission->{present} ? 1 : 0) : ()),
    (defined $admission->{invite_code} ? (invite_code => $admission->{invite_code}) : ()),
    (defined $admission->{deleted} ? (deleted => $admission->{deleted} ? 1 : 0) : ()),
    (defined $admission->{create_channel} ? (create_channel => $admission->{create_channel} ? 1 : 0) : ()),
    (defined $admission->{auth_required} ? (auth_required => $admission->{auth_required} ? 1 : 0) : ()),
    (defined $admission->{request_join} ? (request_join => $admission->{request_join} ? 1 : 0) : ()),
    (defined $admission->{pending_request} ? (pending_request => $admission->{pending_request} ? 1 : 0) : ()),
    reason  => defined $admission->{reason} ? $admission->{reason} : '',
  };
}

sub _authoritative_speak_permission_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  return {
    allowed => $self->_channel_is_moderated_for_client($channel, $client) ? 0 : 1,
    reason  => $self->_channel_is_moderated_for_client($channel, $client) ? '+m' : '',
  } unless defined $pubkey;

  my $permission = $self->_derive_authoritative_speak_permission(
    $channel,
    actor_pubkey => $pubkey,
  );
  if (!$self->_authoritative_permission_is_populated($permission)) {
    $permission = $self->_derive_authoritative_speak_permission(
      $channel,
      force        => 1,
      actor_pubkey => $pubkey,
    );
  }

  return {
    allowed => $permission->{allowed} ? 1 : 0,
    reason  => defined $permission->{reason} ? $permission->{reason} : '',
  } if $self->_authoritative_permission_is_populated($permission)
    && (($permission->{reason} || '') ne 'authoritative state unavailable');

  return {
    allowed => $self->_channel_is_moderated_for_client($channel, $client) ? 0 : 1,
    reason  => $self->_channel_is_moderated_for_client($channel, $client) ? '+m' : '',
  };
}

sub _authoritative_topic_permission_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  return {
    allowed => $self->_channel_is_topic_restricted_for_client($channel, $client) ? 0 : 1,
    reason  => $self->_channel_is_topic_restricted_for_client($channel, $client) ? '+t' : '',
  } unless defined $pubkey;

  my $permission = $self->_derive_authoritative_topic_permission(
    $channel,
    actor_pubkey => $pubkey,
  );
  if (!$self->_authoritative_permission_is_populated($permission)) {
    $permission = $self->_derive_authoritative_topic_permission(
      $channel,
      force        => 1,
      actor_pubkey => $pubkey,
    );
  }

  return {
    allowed => $permission->{allowed} ? 1 : 0,
    reason  => defined $permission->{reason} ? $permission->{reason} : '',
  } if $self->_authoritative_permission_is_populated($permission)
    && (($permission->{reason} || '') ne 'authoritative state unavailable');

  return {
    allowed => $self->_channel_is_topic_restricted_for_client($channel, $client) ? 0 : 1,
    reason  => $self->_channel_is_topic_restricted_for_client($channel, $client) ? '+t' : '',
  };
}

sub _authoritative_mode_write_permission_for_client {
  my ($self, $channel, $client, %args) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  my $mode = $args{mode};
  my $mode_args = ref($args{mode_args}) eq 'ARRAY' ? $args{mode_args} : [];

  if (defined $pubkey) {
    my $permission = $self->_derive_authoritative_mode_write_permission(
      $channel,
      actor_pubkey => $pubkey,
      mode         => $mode,
      mode_args    => $mode_args,
    );
    if (!$self->_authoritative_permission_is_populated($permission)) {
      $permission = $self->_derive_authoritative_mode_write_permission(
        $channel,
        force       => 1,
        actor_pubkey => $pubkey,
        mode        => $mode,
        mode_args   => $mode_args,
      );
    }

    if ($self->_authoritative_permission_is_populated($permission)
        && (($permission->{reason} || '') ne 'authoritative state unavailable')) {
      return {
        allowed            => $permission->{allowed} ? 1 : 0,
        reason             => defined($permission->{reason}) ? $permission->{reason} : '',
        (defined $permission->{target_pubkey} ? (target_pubkey => $permission->{target_pubkey}) : ()),
        (ref($permission->{current_roles}) eq 'ARRAY' ? (current_roles => [ @{$permission->{current_roles}} ]) : ()),
        (defined $permission->{normalized_ban_mask} ? (normalized_ban_mask => $permission->{normalized_ban_mask}) : ()),
        (defined $permission->{normalized_exception_mask} ? (normalized_exception_mask => $permission->{normalized_exception_mask}) : ()),
        (defined $permission->{normalized_invite_exception_mask} ? (normalized_invite_exception_mask => $permission->{normalized_invite_exception_mask}) : ()),
        (defined $permission->{channel_key} ? (channel_key => $permission->{channel_key}) : ()),
        (defined $permission->{user_limit} ? (user_limit => $permission->{user_limit}) : ()),
        (ref($permission->{group_metadata}) eq 'HASH' ? (group_metadata => { %{$permission->{group_metadata}} }) : ()),
      };
    }
  }

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return {
    allowed => 0,
    reason  => 'state_unavailable',
  } unless ref($state) eq 'HASH';
  return {
    allowed => 0,
    reason  => 'deleted',
  } if $state->{tombstoned};
  return {
    allowed => 0,
    reason  => 'not_operator',
  } unless defined($pubkey) && $self->_client_is_authoritative_operator($channel, $client);

  my %permission = (
    allowed => 1,
    reason  => '',
  );
  if ($mode =~ /\A[+-][ov]\z/ && defined($mode_args->[0])) {
    my $target_pubkey = $mode_args->[0];
    my $member = $self->_authoritative_member_for_pubkey($state, $target_pubkey) || {};
    $permission{target_pubkey} = $target_pubkey;
    $permission{current_roles} = [ @{$member->{roles} || []} ];
  } elsif ($mode =~ /\A[+-][b]\z/ && defined($mode_args->[0])) {
    $permission{normalized_ban_mask} = $mode_args->[0];
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A[+-][e]\z/ && defined($mode_args->[0])) {
    $permission{normalized_exception_mask} = $mode_args->[0];
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A[+-][I]\z/ && defined($mode_args->[0])) {
    $permission{normalized_invite_exception_mask} = $mode_args->[0];
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A\+k\z/ && defined($mode_args->[0])) {
    $permission{channel_key} = $mode_args->[0];
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A-k\z/) {
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A\+l\z/ && defined($mode_args->[0])) {
    $permission{user_limit} = 0 + $mode_args->[0];
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A-l\z/) {
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } elsif ($mode =~ /\A[+-][imt]\z/) {
    $permission{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  }

  return \%permission;
}

sub _authoritative_channel_action_permission_for_client {
  my ($self, $channel, $client, %args) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  my $action = $args{action};

  if (defined $pubkey) {
    my $permission = $self->_derive_authoritative_channel_action_permission(
      $channel,
      actor_pubkey => $pubkey,
      action       => $action,
      (defined $args{target_pubkey} ? (target_pubkey => $args{target_pubkey}) : ()),
    );
    if (!$self->_authoritative_permission_is_populated($permission)) {
      $permission = $self->_derive_authoritative_channel_action_permission(
        $channel,
        force        => 1,
        actor_pubkey => $pubkey,
        action       => $action,
        (defined $args{target_pubkey} ? (target_pubkey => $args{target_pubkey}) : ()),
      );
    }

    if ($self->_authoritative_permission_is_populated($permission)
        && (($permission->{reason} || '') ne 'authoritative state unavailable')) {
      return {
        allowed       => $permission->{allowed} ? 1 : 0,
        reason        => defined($permission->{reason}) ? $permission->{reason} : '',
        (defined $permission->{target_pubkey} ? (target_pubkey => $permission->{target_pubkey}) : ()),
        (ref($permission->{group_metadata}) eq 'HASH' ? (group_metadata => { %{$permission->{group_metadata}} }) : ()),
      };
    }
  }

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return {
    allowed => 0,
    reason  => 'state_unavailable',
  } unless ref($state) eq 'HASH';

  if (($action || '') eq 'undelete') {
    return {
      allowed => 0,
      reason  => 'not_deleted',
    } unless $state->{tombstoned};
    return {
      allowed => 0,
      reason  => 'not_operator',
    } unless defined($pubkey) && $self->_client_is_retained_authoritative_operator($channel, $client);
    return {
      allowed        => 1,
      reason         => '',
      group_metadata => $self->_authoritative_group_metadata_from_state($state),
    };
  }

  return {
    allowed => 0,
    reason  => 'deleted',
  } if $state->{tombstoned};
  return {
    allowed => 0,
    reason  => 'not_operator',
  } unless defined($pubkey) && $self->_client_is_authoritative_operator($channel, $client);

  return {
    allowed        => 1,
    reason         => '',
    (defined $args{target_pubkey} ? (target_pubkey => $args{target_pubkey}) : ()),
    (($action || '') eq 'delete' ? (group_metadata => $self->_authoritative_group_metadata_from_state($state)) : ()),
  };
}

sub _authoritative_name_entries_for_channel {
  my ($self, $client, $channel, %args) = @_;
  return () unless ref($client) eq 'HASH';

  my $view = ref($args{view}) eq 'HASH'
    ? $args{view}
    : $self->_derive_authoritative_channel_view(
        $channel,
        ($args{force} ? (force => 1) : ()),
      );
  return () unless ref($view) eq 'HASH';
  my $state = $self->_authoritative_channel_state_from_view($view);
  my %present = map {
    ($_->{pubkey} => $_)
  } grep {
    ref($_) eq 'HASH' && defined($_->{pubkey})
  } @{$view->{present_members} || []};

  my $channel_key = $self->_channel_key($channel);
  return () unless defined $channel_key;
  my $channel_state = $self->{channels}{$channel_key}
    or return ();

  my @entries;
  my %seen;
  for my $client_id (sort keys %{$channel_state->{members} || {}}) {
    next unless exists $self->{clients}{$client_id};
    my $member_client = $self->{clients}{$client_id};
    next unless $member_client->{registered};
    next unless defined $member_client->{nick} && !ref($member_client->{nick}) && length($member_client->{nick});

    my $pubkey = $self->_client_authoritative_pubkey($member_client);
    my $member = defined $pubkey
      ? $self->_authoritative_member_for_pubkey($state, $pubkey)
      : undef;
    my $prefix = ref($member) eq 'HASH'
      ? ($member->{presentational_prefix} || '')
      : '';

    push @entries, {
      nick    => $member_client->{nick},
      display => $prefix . $member_client->{nick},
    };
    $seen{$member_client->{nick}} = 1;
  }

  for my $member (@{$state->{members} || []}) {
    next unless ref($member) eq 'HASH';
    next unless defined $member->{pubkey};
    next unless $present{$member->{pubkey}};
    my $nick = $self->_authoritative_nick_for_pubkey($member->{pubkey});
    next unless defined $nick && length($nick);
    next if $seen{$nick}++;

    push @entries, {
      nick    => $nick,
      display => ($member->{presentational_prefix} || '') . $nick,
    };
  }

  for my $nick ($self->_visible_nicks_for_channel($channel)) {
    next if $seen{$nick}++;
    push @entries, {
      nick    => $nick,
      display => $nick,
    };
  }

  if (!@entries && defined $self->_client_joined_channel_name($client, $channel)) {
    push @entries, {
      nick    => $client->{nick},
      display => $client->{nick},
    };
  }

  return map { $_->{display} }
    sort { $a->{nick} cmp $b->{nick} } @entries;
}

sub _handle_authoritative_part_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $reason = $args{reason};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  unless (defined $actor_pubkey) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH is required for authoritative PART');
    return 1;
  }

  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative PART');
    return 1;
  }

  my %input = (
    command      => 'PART',
    target       => $channel,
    actor_pubkey => $actor_pubkey,
    (defined $reason ? (text => $reason) : ()),
  );
  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
  }

  my $line = sprintf(':%s PART %s', $client->{nick}, $channel);
  $line .= ' :' . $reason
    if defined $reason && length $reason;
  $self->_broadcast_channel_line($channel, $line);
  $self->_remove_client_from_channel(
    $client_id,
    $channel,
    nick => $client->{nick},
  );
  return 1;
}

sub _handle_authoritative_topic_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $text = $args{text};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless ref($state) eq 'HASH';
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $self->_client_is_authoritative_operator($channel, $client);

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless defined $actor_pubkey;

  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative TOPIC');
    return 1;
  }

  my %input = (
    command        => 'TOPIC',
    target         => $channel,
    actor_pubkey   => $actor_pubkey,
    text           => $text,
    group_metadata => $self->_authoritative_group_metadata_from_state($state),
  );
  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
    $self->_refresh_authoritative_nip29_channel_cache($channel);
  }

  if (!$self->_authority_relay_enabled) {
    my $line = sprintf(':%s TOPIC %s :%s', $client->{nick}, $channel, $text);
    $self->_broadcast_channel_line($channel, $line);
    $self->_channel_state($channel)->{topic_text} = $text;
    $self->_channel_state($channel)->{topic_line} = $line;
  }
  return 1;
}

sub _handle_authoritative_delete_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action => 'delete',
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $group_metadata = ref($permission->{group_metadata}) eq 'HASH'
    ? $permission->{group_metadata}
    : undef;

  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative channel deletion');
    return 1;
  }

  my %input = (
    command        => 'DELETE',
    target         => $channel,
    actor_pubkey   => $actor_pubkey,
    group_metadata => $group_metadata,
  );
  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
    $self->_refresh_authoritative_nip29_channel_cache($channel);
  }

  $self->_send_server_notice($client_id, "OVERNETCHANNEL DELETE $channel");
  return 1;
}

sub _handle_authoritative_undelete_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action => 'undelete',
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'not_deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $group_metadata = ref($permission->{group_metadata}) eq 'HASH'
    ? $permission->{group_metadata}
    : undef;

  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative channel undeletion');
    return 1;
  }

  my %input = (
    command        => 'UNDELETE',
    target         => $channel,
    actor_pubkey   => $actor_pubkey,
    group_metadata => $group_metadata,
  );
  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
    $self->_refresh_authoritative_nip29_channel_cache($channel);
  }

  $self->_send_server_notice($client_id, "OVERNETCHANNEL UNDELETE $channel");
  return 1;
}

sub _handle_authoritative_mode_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my @params = @{$args{params} || []};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $mode = $params[1];
  return $self->_send_need_more_params($client_id, 'MODE')
    unless defined $mode && !ref($mode) && length($mode);

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless ref($state) eq 'HASH';

  if ($mode eq '+b' && (!defined($params[2]) || ref($params[2]) || !length($params[2]))) {
    my $ban_list_view = $self->_derive_authoritative_ban_list_view($channel);
    $ban_list_view = $self->_derive_authoritative_ban_list_view(
      $channel,
      force => 1,
    ) unless ref($ban_list_view) eq 'HASH';
    my $ban_masks = ref($ban_list_view) eq 'HASH' && ref($ban_list_view->{ban_masks}) eq 'ARRAY'
      ? $ban_list_view->{ban_masks}
      : $state->{ban_masks} || [];
    for my $ban_mask (@{$ban_masks}) {
      $self->_send_ban_list_entry($client_id, $channel, $ban_mask);
    }
    $self->_send_end_of_ban_list($client_id, $channel);
    return 1;
  }

  if ($mode eq '+e' && (!defined($params[2]) || ref($params[2]) || !length($params[2]))) {
    my $view = $self->_derive_authoritative_channel_view($channel);
    $view = $self->_derive_authoritative_channel_view($channel, force => 1)
      unless ref($view) eq 'HASH';
    for my $exception_mask (@{ref($view) eq 'HASH' && ref($view->{exception_masks}) eq 'ARRAY' ? $view->{exception_masks} : []}) {
      $self->_send_exception_list_entry($client_id, $channel, $exception_mask);
    }
    $self->_send_end_of_exception_list($client_id, $channel);
    return 1;
  }

  if ($mode eq '+I' && (!defined($params[2]) || ref($params[2]) || !length($params[2]))) {
    my $view = $self->_derive_authoritative_channel_view($channel);
    $view = $self->_derive_authoritative_channel_view($channel, force => 1)
      unless ref($view) eq 'HASH';
    for my $invite_exception_mask (@{ref($view) eq 'HASH' && ref($view->{invite_exception_masks}) eq 'ARRAY' ? $view->{invite_exception_masks} : []}) {
      $self->_send_invite_exception_list_entry($client_id, $channel, $invite_exception_mask);
    }
    $self->_send_end_of_invite_exception_list($client_id, $channel);
    return 1;
  }

  my @mode_args;
  my $mode_line = sprintf(':%s MODE %s %s', $client->{nick}, $channel, $mode);
  if ($mode =~ /\A[+-][ov]\z/) {
    return $self->_send_need_more_params($client_id, 'MODE')
      unless defined $params[2] && !ref($params[2]) && length($params[2]);

    my $target_nick = $self->_canonical_current_nick($params[2]);
    return $self->_send_no_such_nick($client_id, $params[2])
      unless defined $target_nick;
    my $target_client = $self->_client_for_current_nick($target_nick);
    return $self->_send_no_such_nick($client_id, $params[2])
      unless ref($target_client) eq 'HASH';
    my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
    return $self->_send_no_such_nick($client_id, $params[2])
      unless defined $target_pubkey;
    @mode_args = ($target_pubkey);
    $mode_line .= ' ' . $target_nick;
  } elsif ($mode =~ /\A[+-][beIklimt]\z/) {
    if ($mode =~ /\A[+-]b\z/) {
      return $self->_send_need_more_params($client_id, 'MODE')
        unless defined $params[2] && !ref($params[2]) && length($params[2]);
      @mode_args = ($params[2]);
      $mode_line .= ' ' . $params[2];
    } elsif ($mode =~ /\A[+-][eI]\z/) {
      return $self->_send_need_more_params($client_id, 'MODE')
        unless defined $params[2] && !ref($params[2]) && length($params[2]);
      @mode_args = ($params[2]);
      $mode_line .= ' ' . $params[2];
    } elsif ($mode =~ /\A\+k\z/) {
      return $self->_send_need_more_params($client_id, 'MODE')
        unless defined $params[2] && !ref($params[2]) && length($params[2]);
      @mode_args = ($params[2]);
      $mode_line .= ' ' . $params[2];
    } elsif ($mode =~ /\A\+l\z/) {
      return $self->_send_need_more_params($client_id, 'MODE')
        unless defined $params[2] && !ref($params[2]) && $params[2] =~ /\A[1-9][0-9]*\z/;
      @mode_args = ($params[2]);
      $mode_line .= ' ' . $params[2];
    }
  } else {
    $self->_send_unknown_command($client_id, 'MODE');
    return 1;
  }

  my $permission = $self->_authoritative_mode_write_permission_for_client(
    $channel,
    $client,
    mode      => $mode,
    mode_args => \@mode_args,
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my %input = (
    command      => 'MODE',
    target       => $channel,
    mode         => $mode,
    actor_pubkey => $actor_pubkey,
  );
  $input{target_pubkey} = $permission->{target_pubkey}
    if defined $permission->{target_pubkey};
  $input{current_roles} = [ @{$permission->{current_roles}} ]
    if ref($permission->{current_roles}) eq 'ARRAY';
  $input{group_metadata} = $permission->{group_metadata}
    if ref($permission->{group_metadata}) eq 'HASH';
  $input{ban_mask} = $permission->{normalized_ban_mask}
    if defined $permission->{normalized_ban_mask};
  $input{exception_mask} = $permission->{normalized_exception_mask}
    if defined $permission->{normalized_exception_mask};
  $input{invite_exception_mask} = $permission->{normalized_invite_exception_mask}
    if defined $permission->{normalized_invite_exception_mask};
  $input{channel_key} = $permission->{channel_key}
    if defined $permission->{channel_key};
  $input{user_limit} = $permission->{user_limit}
    if defined $permission->{user_limit};

  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative MODE');
    return 1;
  }

  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
  }
  $self->_broadcast_channel_line($channel, $mode_line);
  return 1;
}

sub _handle_authoritative_kick_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my @params = @{$args{params} || []};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $target_nick = $self->_canonical_current_nick($params[1]);
  return $self->_send_no_such_nick($client_id, $params[1])
    unless defined $target_nick;
  my $target_client = $self->_client_for_current_nick($target_nick);
  return $self->_send_no_such_nick($client_id, $params[1])
    unless ref($target_client) eq 'HASH';
  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  return $self->_send_no_such_nick($client_id, $params[1])
    unless defined $target_pubkey;

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action       => 'kick',
    target_pubkey => $target_pubkey,
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $reason = @params >= 3 ? $params[2] : undef;
  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative KICK');
    return 1;
  }

  my %input = (
    command       => 'KICK',
    target        => $channel,
    actor_pubkey  => $actor_pubkey,
    target_pubkey => $permission->{target_pubkey},
    (defined $reason ? (text => $reason) : ()),
  );
  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
  }

  my $line = sprintf(':%s KICK %s %s', $client->{nick}, $channel, $target_nick);
  $line .= ' :' . $reason
    if defined $reason && length $reason;
  $self->_broadcast_channel_line($channel, $line);
  $self->_remove_client_from_channel(
    $target_client->{id},
    $channel,
    nick => $target_client->{nick},
  );
  return 1;
}

sub _handle_authoritative_invite_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $target_nick_input = $args{target_nick};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $target_nick = $self->_canonical_current_nick($target_nick_input);
  return $self->_send_no_such_nick($client_id, $target_nick_input)
    unless defined $target_nick;
  my $target_client = $self->_client_for_current_nick($target_nick);
  return $self->_send_no_such_nick($client_id, $target_nick_input)
    unless ref($target_client) eq 'HASH';
  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  return $self->_send_no_such_nick($client_id, $target_nick_input)
    unless defined $target_pubkey;

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action        => 'invite',
    target_pubkey => $target_pubkey,
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $invite_code = $self->_generate_authoritative_invite_code(
    channel       => $channel,
    actor_pubkey  => $actor_pubkey,
    target_pubkey => $target_pubkey,
  );

  if ($self->_authority_relay_enabled && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative INVITE');
    return 1;
  }

  my %input = (
    command       => 'INVITE',
    target        => $channel,
    actor_pubkey  => $actor_pubkey,
    target_nick   => $target_nick,
    target_pubkey => $permission->{target_pubkey},
    invite_code   => $invite_code,
  );
  if ($self->_authority_relay_enabled) {
    unless ($self->_publish_authoritative_input($client, \%input)) {
      $self->_send_server_notice(
        $client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    return 1 unless $self->_emit_client_input($client, \%input);
  }

  $self->_send_inviting($client_id, $target_nick, $channel);
  $target_client->{authority_seen_invites}{$channel}{$invite_code} = 1;
  $self->_send_client_line(
    $target_client->{id},
    sprintf(':%s INVITE %s :%s', $client->{nick}, $target_nick, $channel),
  );
  return 1;
}

sub _handle_authoritative_invites_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action => 'list_invites',
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $view = $self->_derive_authoritative_channel_view(
    $channel,
    force => 1,
    (defined($actor_pubkey) ? (actor_pubkey => $actor_pubkey) : ()),
  );

  return $self->_send_authoritative_invite_list_reply(
    $client_id,
    $channel,
    ref($view) eq 'HASH' ? ($view->{pending_invites} || []) : [],
  );
}

sub _handle_authoritative_requests_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action => 'list_requests',
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || '') eq 'deleted');
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $permission->{allowed};

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $view = $self->_derive_authoritative_channel_view(
    $channel,
    force => 1,
    (defined($actor_pubkey) ? (actor_pubkey => $actor_pubkey) : ()),
  );

  return $self->_send_authoritative_join_request_list_reply(
    $client_id,
    $channel,
    ref($view) eq 'HASH' ? ($view->{pending_join_requests} || []) : [],
  );
}

sub _nick_in_use {
  my ($self, $nick, %args) = @_;
  my $key = $self->_nick_key($nick);
  return 0 unless defined $key;

  my $owner = $self->{nick_to_client_id}{$key};
  return 0 unless defined $owner;
  return 0 if defined $args{exclude_client_id} && $owner eq $args{exclude_client_id};
  return 1;
}

sub _assign_client_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $key = $self->_nick_key($nick);
  return 0 unless defined $key;

  if (defined $client->{nick} && length($client->{nick}) && $client->{nick} ne $nick) {
    $self->_release_client_nick(
      $client_id,
      nick => $client->{nick},
    );
  }

  $client->{nick} = $nick;
  $self->{nick_to_client_id}{$key} = $client_id;
  return 1;
}

sub _release_client_nick {
  my ($self, $client_id, %args) = @_;
  my $nick = defined $args{nick}
    ? $args{nick}
    : (
      exists $self->{clients}{$client_id}
        ? $self->{clients}{$client_id}{nick}
        : undef
    );
  my $key = $self->_nick_key($nick);
  return 0 unless defined $key;
  return 0 unless exists $self->{nick_to_client_id}{$key};
  return 0 unless $self->{nick_to_client_id}{$key} eq $client_id;

  delete $self->{nick_to_client_id}{$key};
  return 1;
}

sub _send_nick_in_use {
  my ($self, $client_id, $attempted_nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $target = $client->{registered} && defined $client->{nick} && length($client->{nick})
    ? $client->{nick}
    : '*';
  $self->_send_client_line($client_id,
    Overnet::Program::IRC::Renderer::nick_in_use_line(
      server_name    => $self->{config}{server_name},
      nick           => $target,
      attempted_nick => $attempted_nick,
    ),
  );
  return 1;
}

sub _emit_client_input {
  my ($self, $client, $input, %opts) = @_;
  my %payload = (
    %{$input},
    network    => $self->{config}{network},
    nick       => $input->{nick} || $client->{nick},
    created_at => $self->_next_authoritative_created_at($client),
  );
  if ($self->_authority_relay_enabled
      && $self->_is_authoritative_channel($payload{target})
      && $self->_client_has_authoritative_delegation($client)) {
    $payload{signing_pubkey} = $client->{authority_delegate_key}->pubkey_hex;
    $payload{authority_event_id} = $client->{authority_delegate_event_id};
    $payload{authority_sequence} = $self->_next_authoritative_delegate_sequence($client);
  }

  my $mapped = $self->_request(
    method => 'adapters.map_input',
    params => {
      adapter_session_id => $self->{adapter_session_id},
      input              => \%payload,
    },
  );
  $self->{inputs_processed}++;

  my $authoritative_result = $self->_handle_authoritative_mapped_result(
      client => $client,
      target => $payload{target},
      mapped => $mapped,
    );
  if ($authoritative_result) {
    return 1;
  }
  return 0 if defined $authoritative_result && $authoritative_result < 0;

  $self->_emit_mapped_result(
    $mapped,
    originating_client_id => $client->{id},
    suppress_render_event_types => $opts{suppress_render_event_types},
  );

  return 1;
}

sub _publish_authoritative_input {
  my ($self, $client, $input) = @_;
  return 0 unless ref($client) eq 'HASH';
  return 0 unless ref($input) eq 'HASH';
  delete $self->{authoritative_publish_error};

  my %payload = (
    %{$input},
    network    => $self->{config}{network},
    nick       => $input->{nick} || $client->{nick},
    created_at => $self->_next_authoritative_created_at($client),
  );
  if ($self->_authority_relay_enabled
      && $self->_is_authoritative_channel($payload{target})
      && $self->_client_has_authoritative_delegation($client)) {
    $payload{signing_pubkey} = $client->{authority_delegate_key}->pubkey_hex;
    $payload{authority_event_id} = $client->{authority_delegate_event_id};
    $payload{authority_sequence} = $self->_next_authoritative_delegate_sequence($client);
  }

  my $mapped = $self->_request(
    method => 'adapters.map_input',
    params => {
      adapter_session_id => $self->{adapter_session_id},
      input              => \%payload,
    },
  );
  $self->{inputs_processed}++;
  unless (ref($mapped) eq 'HASH') {
    $self->{authoritative_publish_error} = 'authoritative relay mapping failed';
    return 0;
  }

  my @events;
  push @events, $mapped->{event}
    if ref($mapped->{event}) eq 'HASH';
  push @events, grep { ref($_) eq 'HASH' } @{$mapped->{events}}
    if ref($mapped->{events}) eq 'ARRAY';
  unless (@events) {
    $self->{authoritative_publish_error} = 'authoritative relay mapping produced no event drafts';
    return 0;
  }

  for my $event (@events) {
    return 0 unless $self->_publish_authoritative_nip29_event(
      channel => $payload{target},
      client  => $client,
      event   => $event,
    );
  }

  return 1;
}

sub _client_has_authoritative_delegation {
  my ($self, $client) = @_;
  return 0 unless ref($client) eq 'HASH';
  return 0 unless $self->_authority_relay_enabled;
  return 0 unless ref($client->{authority_delegate_key}) eq 'Overnet::Core::Nostr::Key';
  return 0 unless defined $client->{authority_delegate_event_id}
    && !ref($client->{authority_delegate_event_id})
    && $client->{authority_delegate_event_id} =~ /\A[0-9a-f]{64}\z/;
  return 0 if defined $client->{authority_delegate_expires_at}
    && $client->{authority_delegate_expires_at} < time();
  return 1;
}

sub _next_authoritative_delegate_sequence {
  my ($self, $client) = @_;
  return undef unless ref($client) eq 'HASH';
  my $sequence_key = defined($client->{id}) && !ref($client->{id}) && length($client->{id})
    ? $client->{id}
    : undef;
  my $next = defined($sequence_key) && exists($self->{authoritative_delegate_sequences}{$sequence_key})
    ? $self->{authoritative_delegate_sequences}{$sequence_key}
    : exists($client->{authority_delegate_sequence})
    ? $client->{authority_delegate_sequence}
    : 0;
  $next++;
  $client->{authority_delegate_sequence} = $next;
  $self->{authoritative_delegate_sequences}{$sequence_key} = $next
    if defined $sequence_key;
  return $next;
}

sub _next_authoritative_created_at {
  my ($self, $client) = @_;
  my $now = int(time());
  return $now unless ref($client) eq 'HASH';

  my $key = defined($client->{id}) && !ref($client->{id}) && length($client->{id})
    ? $client->{id}
    : undef;
  return $now unless defined $key;

  my $last = $self->{authoritative_last_created_at}{$key} || 0;
  my $next = $now > $last ? $now : $last + 1;
  $self->{authoritative_last_created_at}{$key} = $next;
  return $next;
}

sub _publish_authoritative_nip29_event {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::publish_authoritative_nip29_event($self, %args);
}

sub _append_authoritative_nip29_event {
  my ($self, $channel, $event) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::append_authoritative_nip29_event($self, $channel, $event);
}

sub _is_authoritative_nip29_event {
  my ($self, %args) = @_;
  my $channel = $args{channel};
  my $event = $args{event};
  return 0 unless $self->_is_authoritative_channel($channel);
  return 0 unless ref($event) eq 'HASH';

  my $kind = $event->{kind};
  return 0 unless defined $kind && !ref($kind);
  return 0 unless $kind == 9000
    || $kind == 9001
    || $kind == 9002
    || $kind == 9009
    || $kind == 9021
    || $kind == 9022
    || $kind == 39000
    || $kind == 39001
    || $kind == 39002
    || $kind == 39003;

  my (undef, $group_id) = $self->_authoritative_group_binding($channel);
  return 0 unless defined $group_id;

  my %tags = $self->_first_tag_values($event->{tags});
  return 0 unless defined $tags{h} && $tags{h} eq $group_id;
  return 1;
}

sub _handle_authoritative_mapped_result {
  my ($self, %args) = @_;
  my $client = $args{client};
  my $channel = $args{target};
  my $mapped = $args{mapped};
  return 0 unless $self->_is_authoritative_channel($channel);
  return 0 unless ref($mapped) eq 'HASH';

  my @events;
  push @events, $mapped->{event}
    if ref($mapped->{event}) eq 'HASH';
  push @events, grep { ref($_) eq 'HASH' } @{$mapped->{events}}
    if ref($mapped->{events}) eq 'ARRAY';
  return 0 unless @events;
  return 0 if exists $mapped->{state} || exists $mapped->{capabilities};
  return 0 unless @events == grep {
    $self->_is_authoritative_nip29_event(
      channel => $channel,
      event   => $_,
    )
  } @events;

  for my $event (@events) {
    return -1 unless $self->_publish_authoritative_nip29_event(
      channel => $channel,
      client  => $client,
      event   => $event,
    );
  }

  return 1;
}

sub _maybe_poll_authoritative_relay {
  my ($self) = @_;
  return 1;
}

sub _has_authoritative_relay_poll_interest {
  my ($self) = @_;
  return 0;
}

sub _apply_authoritative_channel_cache_update {
  my ($self, %args) = @_;
  my $channel = $args{channel};
  my $event = $args{event};
  my $old_view = $args{old_view};
  my $new_view = $args{new_view};
  my $old_state = $args{old_state};
  my $new_state = $args{new_state};
  my $suppress_render = $args{suppress_render} ? 1 : 0;
  return 0 unless $self->_is_authoritative_channel($channel);
  return 0 unless ref($event) eq 'HASH';

  my %old_pending = map {
    ($_->{code} => $_)
  } grep {
    ref($_) eq 'HASH' && defined($_->{code})
  } @{ref($old_view) eq 'HASH' ? ($old_view->{pending_invites} || []) : []};
  my %new_pending = map {
    ($_->{code} => $_)
  } grep {
    ref($_) eq 'HASH' && defined($_->{code})
  } @{ref($new_view) eq 'HASH' ? ($new_view->{pending_invites} || []) : []};
  my %old_present = map {
    ($_->{pubkey} => $_)
  } grep {
    ref($_) eq 'HASH' && defined($_->{pubkey})
  } @{ref($old_view) eq 'HASH' ? ($old_view->{present_members} || []) : []};
  my %new_present = map {
    ($_->{pubkey} => $_)
  } grep {
    ref($_) eq 'HASH' && defined($_->{pubkey})
  } @{ref($new_view) eq 'HASH' ? ($new_view->{present_members} || []) : []};
  my $old_has_topic = ref($old_view) eq 'HASH' && exists $old_view->{topic} ? 1 : 0;
  my $new_has_topic = ref($new_view) eq 'HASH' && exists $new_view->{topic} ? 1 : 0;
  my $old_topic = $old_has_topic ? $old_view->{topic} : undef;
  my $new_topic = $new_has_topic ? $new_view->{topic} : undef;
  my $old_topic_actor = ref($old_view) eq 'HASH' && exists $old_view->{topic_actor_pubkey}
    ? $old_view->{topic_actor_pubkey}
    : undef;
  my $new_topic_actor = ref($new_view) eq 'HASH' && exists $new_view->{topic_actor_pubkey}
    ? $new_view->{topic_actor_pubkey}
    : undef;
  my $old_tombstoned = ref($old_view) eq 'HASH' && $old_view->{tombstoned} ? 1 : 0;
  my $new_tombstoned = ref($new_view) eq 'HASH' && $new_view->{tombstoned} ? 1 : 0;

  if ($new_tombstoned) {
    $self->_apply_authoritative_channel_tombstone(
      $channel,
      reason => 'channel deleted',
    ) unless $old_tombstoned;
    return 1;
  }

  if (!$suppress_render && ($event->{kind} || 0) == 9002) {
    my $actor_nick = $self->_authoritative_nick_for_pubkey(
      $self->_effective_authoritative_actor_pubkey_from_event($event)
    ) || $self->{config}{server_name};

    my %old_mode_flags = map { $_ => 1 } grep { /[imt]/ } split //, (($old_state->{channel_modes} || '') =~ s/^\+//r);
    my %new_mode_flags = map { $_ => 1 } grep { /[imt]/ } split //, (($new_state->{channel_modes} || '') =~ s/^\+//r);
    for my $mode_letter (qw(i m t)) {
      next if $old_mode_flags{$mode_letter} && $new_mode_flags{$mode_letter};
      next unless $old_mode_flags{$mode_letter} || $new_mode_flags{$mode_letter};
      $self->_broadcast_channel_line(
        $channel,
        sprintf(
          ':%s MODE %s %s%s',
          $actor_nick,
          $channel,
          $new_mode_flags{$mode_letter} ? '+' : '-',
          $mode_letter,
        ),
      );
    }

    my %old_ban_masks = map { $_ => 1 } @{ref($old_state->{ban_masks}) eq 'ARRAY' ? $old_state->{ban_masks} : []};
    my %new_ban_masks = map { $_ => 1 } @{ref($new_state->{ban_masks}) eq 'ARRAY' ? $new_state->{ban_masks} : []};
    for my $ban_mask (sort keys %new_ban_masks) {
      next if $old_ban_masks{$ban_mask};
      $self->_broadcast_channel_line(
        $channel,
        sprintf(':%s MODE %s +b %s', $actor_nick, $channel, $ban_mask),
      );
    }
    for my $ban_mask (sort keys %old_ban_masks) {
      next if $new_ban_masks{$ban_mask};
      $self->_broadcast_channel_line(
        $channel,
        sprintf(':%s MODE %s -b %s', $actor_nick, $channel, $ban_mask),
      );
    }
  }

  if (($event->{kind} || 0) == 9009) {
    my %tags = $self->_first_tag_values($event->{tags});
    return 1 unless defined $tags{code} && length($tags{code});
    return 1 if exists $old_pending{$tags{code}};
    return 1 unless exists $new_pending{$tags{code}};

    my $actor_pubkey = $self->_effective_authoritative_actor_pubkey_from_event($event);
    my $actor_nick = $self->_authoritative_nick_for_pubkey($actor_pubkey)
      || $self->{config}{server_name};

    for my $client_id (sort keys %{$self->{clients}}) {
      my $client = $self->{clients}{$client_id};
      next unless ref($client) eq 'HASH' && $client->{registered};
      next unless defined $client->{nick} && !ref($client->{nick}) && length($client->{nick});
      next unless $self->_client_authoritative_pubkey($client);
      next unless defined $tags{p} && $tags{p} eq $self->_client_authoritative_pubkey($client);
      next if $client->{authority_seen_invites}{$channel}{$tags{code}}++;

      $self->_send_client_line(
        $client_id,
        sprintf(':%s INVITE %s :%s', $actor_nick, $client->{nick}, $channel),
      );
    }
    return 1;
  }

  if ($old_has_topic != $new_has_topic
      || (($old_topic // '') ne ($new_topic // ''))
      || (($old_topic_actor // '') ne ($new_topic_actor // ''))) {
    $self->_sync_authoritative_topic_state_from_view($channel, $new_view);
    if ($new_has_topic) {
      my $line = $self->_authoritative_topic_line_from_view($channel, $new_view);
      $self->_broadcast_channel_line($channel, $line)
        if defined $line && length $line;
    }
  }

  my $channel_key = $self->_channel_key($channel);
  return 1 unless defined $channel_key;
  my $channel_state = $self->{channels}{$channel_key}
    or return 1;

  my %added_pubkeys = map {
    ($_ => 1)
  } grep {
    !$old_present{$_} && $new_present{$_}
  } keys %new_present;

  for my $pubkey (sort keys %added_pubkeys) {
    next unless ($event->{kind} || 0) == 9021;
    next unless (($self->_effective_authoritative_actor_pubkey_from_event($event) || '') eq $pubkey);

    my @local_client_ids = grep {
      my $client = $self->{clients}{$_};
      ref($client) eq 'HASH'
        && (($self->_client_authoritative_pubkey($client) || '') eq $pubkey)
    } sort keys %{$channel_state->{members} || {}};
    next if @local_client_ids;

    my $actor_nick = $self->_authoritative_nick_for_pubkey($pubkey)
      || $self->{config}{server_name};
    $self->_broadcast_channel_line(
      $channel,
      sprintf(':%s JOIN %s', $actor_nick, $channel),
    );
  }

  my %removed_pubkeys = map {
    ($_ => 1)
  } grep {
    $old_present{$_} && !$new_present{$_}
  } keys %old_present;

  for my $pubkey (sort keys %removed_pubkeys) {
    my @affected_client_ids = grep {
      my $client = $self->{clients}{$_};
      ref($client) eq 'HASH'
        && (($self->_client_authoritative_pubkey($client) || '') eq $pubkey)
    } sort keys %{$channel_state->{members} || {}};

    if (($event->{kind} || 0) == 9001) {
      my %tags = $self->_first_tag_values($event->{tags});
      next unless defined($tags{p}) && $tags{p} eq $pubkey;
      my $target_nick = @affected_client_ids
        ? $self->{clients}{$affected_client_ids[0]}{nick}
        : $self->_authoritative_nick_for_pubkey($pubkey);
      next unless defined $target_nick && length $target_nick;

      my $actor_nick = $self->_authoritative_nick_for_pubkey(
        $self->_effective_authoritative_actor_pubkey_from_event($event)
      ) || $self->{config}{server_name};
      my $reason = $event->{content};
      my $line = sprintf(':%s KICK %s %s', $actor_nick, $channel, $target_nick);
      $line .= ' :' . $reason
        if defined $reason && !ref($reason) && length($reason);
      $self->_broadcast_channel_line($channel, $line);

      for my $client_id (@affected_client_ids) {
        next unless exists $self->{clients}{$client_id};
        $self->_remove_client_from_channel(
          $client_id,
          $channel,
          nick => $self->{clients}{$client_id}{nick},
        );
      }
      next;
    }

    next unless ($event->{kind} || 0) == 9022;
    next unless (($self->_effective_authoritative_actor_pubkey_from_event($event) || '') eq $pubkey);

    my $actor_nick = @affected_client_ids
      ? $self->{clients}{$affected_client_ids[0]}{nick}
      : ($self->_authoritative_nick_for_pubkey($pubkey) || $self->{config}{server_name});
    my $reason = $event->{content};
    my $line = sprintf(':%s PART %s', $actor_nick, $channel);
    $line .= ' :' . $reason
      if defined $reason && !ref($reason) && length($reason);
    $self->_broadcast_channel_line($channel, $line);

    for my $client_id (@affected_client_ids) {
      next unless exists $self->{clients}{$client_id};
      $self->_remove_client_from_channel(
        $client_id,
        $channel,
        nick => $self->{clients}{$client_id}{nick},
      );
    }
    $channel_state = $self->{channels}{$channel_key}
      or return 1;
  }

  return 1;
}

sub _update_authoritative_channel_cache_with_event {
  my ($self, %args) = @_;
  my $channel = $args{channel};
  my $event = $args{event};
  my $suppress_render = $args{suppress_render} ? 1 : 0;
  return 0 unless $self->_is_authoritative_channel($channel);
  return 0 unless ref($event) eq 'HASH';

  my $canonical = $self->_canonical_channel_name($channel);
  return 0 unless defined $canonical;

  my $cache = $self->{authoritative_channel_cache}{$canonical} || {};
  my $old_view = $cache->{view};
  my $old_state = $cache->{state};
  my $event_id = defined($event->{id}) && !ref($event->{id}) && length($event->{id})
    ? $event->{id}
    : undef;
  my $new_cache;
  if (ref($cache->{events}) eq 'ARRAY') {
    my @events = @{$cache->{events}};
    my $already_cached = defined($event_id)
      ? grep { ref($_) eq 'HASH' && defined($_->{id}) && $_->{id} eq $event_id } @events
      : 0;
    if (!$already_cached) {
      push @events, $event;
    }
    my $sorted_events = $self->_sort_authoritative_events(\@events);
    my $new_view = $self->_derive_authoritative_channel_view_from_events($canonical, $sorted_events);
    $new_cache = $self->{authoritative_channel_cache}{$canonical} = {
      %{$cache},
      events       => $sorted_events,
      view         => $new_view,
      state        => $self->_authoritative_channel_state_from_view($new_view),
      refreshed_at => time(),
    };
    return 1 if $already_cached;
  } else {
    my $sorted_events = $self->_sort_authoritative_events([$event]);
    my $new_view = $self->_derive_authoritative_channel_view_from_events($canonical, $sorted_events);
    $new_cache = $self->{authoritative_channel_cache}{$canonical} = {
      %{$cache},
      events       => $sorted_events,
      view         => $new_view,
      state        => $self->_authoritative_channel_state_from_view($new_view),
      refreshed_at => time(),
    };
  }

  $self->_sync_authoritative_topic_state_from_view($canonical, $new_cache->{view});
  $self->_apply_authoritative_channel_cache_update(
    channel         => $canonical,
    event           => $event,
    old_view        => $old_view,
    new_view        => $new_cache->{view},
    old_state       => $old_state,
    new_state       => $new_cache->{state},
    suppress_render => $suppress_render,
  );

  return 1;
}

sub _reconcile_authoritative_pending_invites_from_refresh {
  my ($self, %args) = @_;
  my $channel = $args{channel};
  my $old_view = $args{old_view};
  my $old_events = $args{old_events};
  my $new_view = $args{new_view};
  my $new_events = $args{new_events};
  return 0 unless $self->_is_authoritative_channel($channel);
  return 0 unless ref($new_view) eq 'HASH';
  return 0 unless ref($old_events) eq 'ARRAY' && ref($new_events) eq 'ARRAY';

  my %old_ids = map {
    (defined($_->{id}) && !ref($_->{id}) && length($_->{id}))
      ? ($_->{id} => 1)
      : ()
  } grep { ref($_) eq 'HASH' } @{$old_events};

  my $count = 0;
  for my $event (@{$new_events}) {
    next unless ref($event) eq 'HASH';
    next unless ($event->{kind} || 0) == 9009;
    next unless defined($event->{id}) && !ref($event->{id}) && length($event->{id});
    next if $old_ids{$event->{id}};

    $count += $self->_apply_authoritative_channel_cache_update(
      channel   => $channel,
      event     => $event,
      old_view  => $old_view,
      new_view  => $new_view,
      old_state => $self->_authoritative_channel_state_from_view($old_view),
      new_state => $self->_authoritative_channel_state_from_view($new_view),
    ) || 0;
  }

  return $count;
}

sub _userhost_entry_for_nick {
  my ($self, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  return undef unless defined $nick_key;

  my $client_id = $self->{nick_to_client_id}{$nick_key};
  return undef unless defined $client_id && exists $self->{clients}{$client_id};
  my $client = $self->{clients}{$client_id};

  my $display_nick = $client->{nick};
  my $username = defined $client->{username} && !ref($client->{username}) && length($client->{username})
    ? $client->{username}
    : $display_nick;
  my $host = $self->_presentational_host_for_client($client);

  return sprintf('%s=+%s@%s', $display_nick, $username, $host);
}

sub _whois_entry_for_nick {
  my ($self, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  return undef unless defined $nick_key;

  my $client_id = $self->{nick_to_client_id}{$nick_key};
  return undef unless defined $client_id && exists $self->{clients}{$client_id};
  my $client = $self->{clients}{$client_id};

  return {
    nick     => $client->{nick},
    username => (
      defined $client->{username} && !ref($client->{username}) && length($client->{username})
        ? $client->{username}
        : $client->{nick}
    ),
    host     => $self->_presentational_host_for_client($client),
    realname => (
      defined $client->{realname} && !ref($client->{realname}) && length($client->{realname})
        ? $client->{realname}
        : $client->{nick}
    ),
    (defined($client->{authority_pubkey}) ? (account => $client->{authority_pubkey}) : ()),
  };
}

sub _who_entries_for_channel {
  my ($self, $channel) = @_;
  my @entries;

  for my $display_nick ($self->_visible_nicks_for_channel($channel)) {
    my $nick_key = $self->_nick_key($display_nick);
    next unless defined $nick_key;

    my $client_id = $self->{nick_to_client_id}{$nick_key};
    if (defined $client_id && exists $self->{clients}{$client_id}) {
      my $client = $self->{clients}{$client_id};
      push @entries, {
        nick     => $client->{nick},
        username => (
          defined $client->{username} && !ref($client->{username}) && length($client->{username})
            ? $client->{username}
            : $client->{nick}
        ),
        host     => $self->_presentational_host_for_client($client),
        realname => (
          defined $client->{realname} && !ref($client->{realname}) && length($client->{realname})
            ? $client->{realname}
            : $client->{nick}
        ),
      };
      next;
    }

    push @entries, {
      nick     => $display_nick,
      username => 'overnet',
      host     => $self->_default_presentational_host,
      realname => $display_nick,
    };
  }

  return @entries;
}

sub _list_entries {
  my ($self, $client, $target) = @_;
  $self->_refresh_authoritative_discovery_cache(refresh => 1)
    if $self->_authority_relay_enabled && $self->_authority_profile eq 'nip29';

  my %channels = map {
    $_ => 1
  } map {
    $self->{channels}{$_}{channel_name}
  } grep {
    ref($self->{channels}{$_}) eq 'HASH'
      && defined $self->{channels}{$_}{channel_name}
      && !ref($self->{channels}{$_}{channel_name})
      && length($self->{channels}{$_}{channel_name})
  } keys %{$self->{channels} || {}};
  for my $authoritative_channel ($self->_authoritative_channels) {
    $channels{$authoritative_channel} = 1;
  }
  my @channels = sort keys %channels;

  if (defined $target && length($target) && $self->_is_channel_name($target)) {
    my $target_key = $self->_channel_key($target);
    @channels = grep {
      defined $self->_channel_key($_) && $self->_channel_key($_) eq $target_key
    } @channels;
  }

  my @entries;
  for my $channel (sort @channels) {
    my $channel_key = $self->_channel_key($channel);
    next unless defined $channel_key;
    my $state = $self->{channels}{$channel_key};

    if ($self->_is_authoritative_channel($channel)) {
      my $actor_pubkey = ref($client) eq 'HASH'
        ? $self->_client_authoritative_pubkey($client)
        : undef;
      my $list_view = $self->_derive_authoritative_list_entry_view(
        $channel,
        force => 1,
        (defined($actor_pubkey) ? (actor_pubkey => $actor_pubkey) : ()),
      );
      my $view = $self->_derive_authoritative_channel_view(
        $channel,
        force => 1,
      );
      next unless ref($view) eq 'HASH' || ref($state) eq 'HASH';
      next if ref($list_view) eq 'HASH'
        && exists($list_view->{visible_in_list})
        && !$list_view->{visible_in_list};
      next if ref($view) eq 'HASH' && $view->{tombstoned};

      my $visible_users = ref($list_view) eq 'HASH'
        && defined($list_view->{visible_users})
        && !ref($list_view->{visible_users})
          ? $list_view->{visible_users}
        : ref($view) eq 'HASH' && ref($view->{present_members}) eq 'ARRAY'
        ? scalar(@{$view->{present_members}})
        : 0;
      if (!$visible_users && ref($state) eq 'HASH') {
        my %presented_nicks = map { $_ => 1 } $self->_visible_nicks_for_channel($channel);
        for my $client_id (keys %{$state->{members} || {}}) {
          next unless exists $self->{clients}{$client_id};
          my $client = $self->{clients}{$client_id};
          next unless ref($client) eq 'HASH';
          next unless $client->{registered};
          next unless defined $client->{nick} && !ref($client->{nick}) && length($client->{nick});
          $presented_nicks{$client->{nick}} = 1;
        }
        $visible_users = scalar(keys %presented_nicks);
      }

      my $display_channel = ref($list_view) eq 'HASH'
        && defined($list_view->{channel})
        && !ref($list_view->{channel})
        && length($list_view->{channel})
          ? $list_view->{channel}
        : ref($state) eq 'HASH'
        && defined $state->{channel_name}
        && !ref($state->{channel_name})
        && length($state->{channel_name})
          ? $state->{channel_name}
          : exists($self->{authoritative_discovered_channels}{$channel})
          ? $self->{authoritative_discovered_channels}{$channel}{channel_name}
          : $channel;
      my $topic = ref($list_view) eq 'HASH' && exists($list_view->{topic})
        ? $list_view->{topic}
        : ref($view) eq 'HASH' && exists($view->{topic})
        ? $view->{topic}
        : ref($state) eq 'HASH' && defined($state->{topic_text}) && !ref($state->{topic_text})
        ? $state->{topic_text}
        : '';

      push @entries, {
        channel       => $display_channel,
        visible_users => $visible_users,
        topic         => $topic,
      };
      next;
    }

    next unless ref($state) eq 'HASH';

    my %presented_nicks = map { $_ => 1 } $self->_visible_nicks_for_channel($state->{channel_name});
    for my $client_id (keys %{$state->{members} || {}}) {
      next unless exists $self->{clients}{$client_id};
      my $client = $self->{clients}{$client_id};
      next unless ref($client) eq 'HASH';
      next unless $client->{registered};
      next unless defined $client->{nick} && !ref($client->{nick}) && length($client->{nick});
      $presented_nicks{$client->{nick}} = 1;
    }

    push @entries, {
      channel       => $state->{channel_name},
      visible_users => scalar(keys %presented_nicks),
      topic         => (
        defined $state->{topic_text} && !ref($state->{topic_text})
          ? $state->{topic_text}
          : ''
      ),
    };
  }

  return @entries;
}

sub _ensure_channel_subscription {
  my ($self, $channel) = @_;
  my $state = $self->_channel_state($channel);
  return $state->{subscription_id}
    if defined $state->{subscription_id};

  my $subscription_id = 'channel:' . $self->_channel_object_id($channel);
  $self->_request(
    method => 'subscriptions.open',
    params => {
      subscription_id => $subscription_id,
      query           => {
        overnet_ot  => 'chat.channel',
        overnet_oid => $self->_channel_object_id($channel),
      },
    },
  );
  $state->{subscription_id} = $subscription_id;

  return $subscription_id;
}

sub _ensure_client_dm_subscription {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return undef;
  return undef unless $client->{registered};
  return undef unless defined $client->{nick} && length($client->{nick});

  my $object_id = $self->_dm_object_id($client->{nick});
  if (defined $client->{dm_subscription_id}
      && defined $client->{dm_object_id}
      && $client->{dm_object_id} eq $object_id) {
    return $client->{dm_subscription_id};
  }

  $self->_close_client_dm_subscription($client_id)
    if defined $client->{dm_subscription_id};

  my $subscription_id = 'dm:' . $client_id;
  $self->_request(
    method => 'subscriptions.open',
    params => {
      subscription_id => $subscription_id,
      query           => {
        overnet_ot  => 'chat.dm',
        overnet_oid => $object_id,
      },
    },
  );
  $client->{dm_subscription_id} = $subscription_id;
  $client->{dm_object_id} = $object_id;

  return $subscription_id;
}

sub _close_client_dm_subscription {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  return 1 unless defined $client->{dm_subscription_id};

  my $subscription_id = delete $client->{dm_subscription_id};
  delete $client->{dm_object_id};
  $self->_request(
    method => 'subscriptions.close',
    params => {
      subscription_id => $subscription_id,
    },
  );

  return 1;
}

sub _close_channel_subscription {
  my ($self, $channel) = @_;
  my $channel_key = $self->_channel_key($channel);
  return 1 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return 1;
  return 1 unless defined $state->{subscription_id};

  my $subscription_id = delete $state->{subscription_id};
  $self->_request(
    method => 'subscriptions.close',
    params => {
      subscription_id => $subscription_id,
    },
  );

  return 1;
}

sub _add_client_to_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $channel_key = $self->_channel_key($channel);
  return 0 unless defined $channel_key;
  my $state = $self->_channel_state($channel);
  $client->{joined_channels}{$channel_key} = $state->{channel_name};
  $state->{members}{$client_id} = 1;
  $self->_add_visible_nick($state->{channel_name}, $client->{nick});
  return 1;
}

sub _remove_client_from_channel {
  my ($self, $client_id, $channel, %opts) = @_;
  my $client = $self->{clients}{$client_id};
  my $channel_key = $self->_channel_key($channel);
  return 0 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return 0;
  my $nick = defined $opts{nick}
    ? $opts{nick}
    : ($client ? $client->{nick} : undef);

  delete $client->{joined_channels}{$channel_key}
    if $client;
  delete $state->{members}{$client_id};
  $self->_remove_visible_nick($state->{channel_name}, $nick);

  if (!keys %{$state->{members}}) {
    $self->_close_channel_subscription($state->{channel_name});
    delete $self->{channels}{$channel_key};
  }

  return 1;
}

sub _disconnect_client {
  my ($self, $client_id, %args) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  my $current_nick = $client->{nick};

  my @channels = sort values %{$client->{joined_channels} || {}};
  if ($args{emit_quit}) {
    my $line = sprintf(':%s QUIT', $client->{nick});
    $line .= ' :' . $args{reason}
      if defined $args{reason} && length $args{reason};
    $self->_send_line_to_client_ids(
      [ $self->_shared_client_ids_for_channels(\@channels, exclude_client_id => $client_id) ],
      $line,
    );

    for my $channel (@channels) {
      $self->_remove_client_from_channel(
        $client_id,
        $channel,
        nick => $client->{nick},
      );
    }

    for my $channel (@channels) {
      $self->_emit_client_input(
        $client,
        {
          command => 'QUIT',
          target  => $channel,
          (defined $args{reason} ? (text => $args{reason}) : ()),
        },
        suppress_render_event_types => {
          'chat.quit' => 1,
        },
      );
    }
  } else {
    for my $channel (@channels) {
      $self->_remove_client_from_channel(
        $client_id,
        $channel,
        nick => $client->{nick},
      );
    }
  }

  $self->_close_client_dm_subscription($client_id);
  $self->_release_client_nick(
    $client_id,
    nick => $current_nick,
  );

  close $client->{socket}
    if defined $client->{socket};
  delete $self->{authoritative_last_created_at}{$client_id};
  delete $self->{authoritative_delegate_sequences}{$client_id};
  delete $self->{clients}{$client_id};

  return 1;
}

sub _handle_subscription_event {
  my ($self, $params) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event($self, $params);
}

sub _handle_nostr_subscription_event {
  my ($self, $params) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::handle_nostr_subscription_event($self, $params);
}

sub _render_subscription_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $data = $args{data};
  return undef unless ref($data) eq 'HASH';

  if ($item_type eq 'private_message') {
    my $rumor = $data->{decrypted_rumor};
    if (ref($rumor) eq 'HASH') {
      my $content = $rumor->{content};
      return undef unless ref($content) eq 'HASH';

      return $self->_render_private_message_item(
        event_type => $data->{private_type},
        object_id  => $data->{object_id},
        provenance => $content->{provenance},
        body       => $content->{body},
      );
    }

    return $self->_render_opaque_private_message_item(
      event_type      => $data->{private_type},
      object_id       => $data->{object_id},
      sender_identity => $data->{sender_identity},
      transport       => $data->{transport},
    );
  }

  my $event = Overnet::Core::Nostr->event_from_wire($data);
  return undef unless $event;

  my %tags = $self->_first_tag_values($event->tags);
  my $content = eval { JSON::PP::decode_json($event->content) };
  return undef unless ref($content) eq 'HASH';
  my $provenance = $content->{provenance} || {};
  my $body = $content->{body} || {};
  my $event_type = $tags{overnet_et} || '';
  if (($tags{overnet_ot} || '') eq 'chat.channel') {
    my $channel = $self->_channel_name_from_object_id($tags{overnet_oid});
    return undef unless defined $channel;

    my $nick = $provenance->{external_identity};
    return undef unless defined $nick && !ref($nick) && length($nick);

    my $line;
    if ($item_type eq 'event' && $event_type eq 'chat.message') {
      return undef unless defined $body->{text} && !ref($body->{text});
      $line = sprintf(':%s PRIVMSG %s :%s', $nick, $channel, $body->{text});
    } elsif ($item_type eq 'event' && $event_type eq 'chat.notice') {
      return undef unless defined $body->{text} && !ref($body->{text});
      $line = sprintf(':%s NOTICE %s :%s', $nick, $channel, $body->{text});
    } elsif ($item_type eq 'state' && $event_type eq 'chat.topic') {
      return undef unless defined $body->{topic} && !ref($body->{topic});
      $line = sprintf(':%s TOPIC %s :%s', $nick, $channel, $body->{topic});
      $self->_channel_state($channel)->{topic_line} = $line;
      $self->_channel_state($channel)->{topic_text} = $body->{topic};
    } elsif ($item_type eq 'event' && $event_type eq 'chat.join') {
      $self->_add_visible_nick($channel, $nick);
      $line = sprintf(':%s JOIN %s', $nick, $channel);
    } elsif ($item_type eq 'event' && $event_type eq 'chat.part') {
      $self->_remove_visible_nick($channel, $nick);
      $line = sprintf(':%s PART %s', $nick, $channel);
      $line .= ' :' . $body->{reason}
        if defined $body->{reason} && !ref($body->{reason}) && length($body->{reason});
    } elsif ($item_type eq 'event' && $event_type eq 'chat.quit') {
      $self->_remove_visible_nick($channel, $nick);
      $line = sprintf(':%s QUIT', $nick);
      $line .= ' :' . $body->{reason}
        if defined $body->{reason} && !ref($body->{reason}) && length($body->{reason});
    } else {
      return undef;
    }

    my @client_ids = grep {
      exists $self->{clients}{$_}
        && $self->{clients}{$_}{registered}
        && defined $self->_client_joined_channel_name($self->{clients}{$_}, $channel)
    } sort keys %{$self->{clients}};
    return undef unless @client_ids;

    return {
      channel    => $channel,
      line       => $line,
      client_ids => \@client_ids,
    };
  }

  if (($tags{overnet_ot} || '') eq 'chat.dm' && $item_type eq 'event') {
    return $self->_render_private_message_item(
      event_type => $event_type,
      object_id  => $tags{overnet_oid},
      provenance => $provenance,
      body       => $body,
    );
  }

  if (($tags{overnet_ot} || '') eq 'irc.network' && $item_type eq 'event' && $event_type eq 'irc.nick') {
    my $network_object_id = 'irc:' . $self->{config}{network};
    return undef unless ($tags{overnet_oid} || '') eq $network_object_id;
    return undef unless defined $body->{old_nick} && !ref($body->{old_nick}) && length($body->{old_nick});
    return undef unless defined $body->{new_nick} && !ref($body->{new_nick}) && length($body->{new_nick});

    my @client_ids = $self->_shared_client_ids_for_nick($body->{old_nick});
    $self->_rename_visible_nick_everywhere(
      old_nick => $body->{old_nick},
      new_nick => $body->{new_nick},
    );
    return undef unless @client_ids;

    return {
      line       => sprintf(':%s NICK :%s', $body->{old_nick}, $body->{new_nick}),
      client_ids => \@client_ids,
    };
  }

  return undef;
}

sub _render_private_message_item {
  my ($self, %args) = @_;
  my $event_type = $args{event_type} || '';
  my $target_nick = $self->_dm_nick_from_object_id($args{object_id});
  return undef unless defined $target_nick;

  my $provenance = $args{provenance};
  return undef unless ref($provenance) eq 'HASH';
  my $nick = $provenance->{external_identity};
  return undef unless defined $nick && !ref($nick) && length($nick);

  my $body = $args{body};
  return undef unless ref($body) eq 'HASH';
  return undef unless defined $body->{text} && !ref($body->{text});

  my $display_target_nick = $self->_canonical_current_nick($target_nick) || $target_nick;
  my $line;
  if ($event_type eq 'chat.dm_message') {
    $line = sprintf(':%s PRIVMSG %s :%s', $nick, $display_target_nick, $body->{text});
  } elsif ($event_type eq 'chat.dm_notice') {
    $line = sprintf(':%s NOTICE %s :%s', $nick, $display_target_nick, $body->{text});
  } else {
    return undef;
  }

  my $target_key = $self->_nick_key($target_nick);
  return undef unless defined $target_key;
  my @client_ids = grep {
    exists $self->{clients}{$_}
      && $self->{clients}{$_}{registered}
      && defined $self->_nick_key($self->{clients}{$_}{nick})
      && $self->_nick_key($self->{clients}{$_}{nick}) eq $target_key
  } sort keys %{$self->{clients}};
  return undef unless @client_ids;

  return {
    line       => $line,
    client_ids => \@client_ids,
  };
}

sub _render_opaque_private_message_item {
  my ($self, %args) = @_;
  my $event_type = $args{event_type} || '';
  my $target_nick = $self->_dm_nick_from_object_id($args{object_id});
  return undef unless defined $target_nick;

  my $sender_identity = $args{sender_identity};
  return undef unless defined $sender_identity && !ref($sender_identity) && length($sender_identity);

  my $transport = $args{transport};
  return undef unless ref($transport) eq 'HASH';

  my $display_target_nick = $self->_canonical_current_nick($target_nick) || $target_nick;
  my $body = $self->_encode_e2ee_dm_body($transport);
  my $line;
  if ($event_type eq 'chat.dm_message') {
    $line = sprintf(':%s PRIVMSG %s :%s', $sender_identity, $display_target_nick, $body);
  } elsif ($event_type eq 'chat.dm_notice') {
    $line = sprintf(':%s NOTICE %s :%s', $sender_identity, $display_target_nick, $body);
  } else {
    return undef;
  }

  my $target_key = $self->_nick_key($target_nick);
  return undef unless defined $target_key;
  my @client_ids = grep {
    my $client = $self->{clients}{$_};
    exists $self->{clients}{$_}
      && $client->{registered}
      && defined $self->_nick_key($client->{nick})
      && $self->_nick_key($client->{nick}) eq $target_key
      && $self->_client_has_capability($client, 'overnet-e2ee')
      && defined $client->{e2ee_pubkey}
  } sort keys %{$self->{clients}};
  return undef unless @client_ids;

  return {
    line       => $line,
    client_ids => \@client_ids,
  };
}

sub _decode_e2ee_dm_body {
  my ($self, $body) = @_;
  return (undef, undef, 0)
    unless defined $body && !ref($body);
  return (undef, undef, 0)
    unless index($body, $E2EE_DM_BODY_PREFIX) == 0;

  my $encoded = substr($body, length($E2EE_DM_BODY_PREFIX));
  return (undef, 'Malformed overnet-e2ee body: missing transport payload', 1)
    unless defined $encoded && length($encoded);

  my $decoded = eval { decode_base64($encoded) };
  if ($@ || !defined $decoded || !length($decoded)) {
    return (undef, 'Malformed overnet-e2ee body: base64 decode failed', 1);
  }

  my $transport = eval { JSON::PP::decode_json($decoded) };
  if ($@ || ref($transport) ne 'HASH') {
    return (undef, 'Malformed overnet-e2ee body: transport JSON is invalid', 1);
  }

  return ($transport, undef, 1);
}

sub _encode_e2ee_dm_body {
  my ($self, $transport) = @_;
  die "transport must be an object\n"
    unless ref($transport) eq 'HASH';

  return $E2EE_DM_BODY_PREFIX . encode_base64(JSON::PP::encode_json($transport), '');
}

sub _emit_mapped_result {
  my ($self, $result, %opts) = @_;
  my $suppress = $opts{suppress_render_event_types} || {};
  my $originating_client_id = $opts{originating_client_id};

  for my $event (@{$result->{events} || []}) {
    my %candidate_tags = $self->_first_tag_values($event->{tags});
    if (($candidate_tags{overnet_ot} || '') eq 'chat.dm'
        && (($candidate_tags{overnet_et} || '') eq 'chat.dm_message'
          || ($candidate_tags{overnet_et} || '') eq 'chat.dm_notice')) {
      $self->_emit_private_message_candidate(
        $event,
        originating_client_id => $originating_client_id,
      );
      next;
    }

    my $signed = $self->_sign_candidate_event($event);
    my %tags = $self->_first_tag_values($signed->{tags});
    if ($suppress->{$tags{overnet_et} || ''}) {
      $self->{suppress_subscription_event_ids}{$signed->{id}} = 1;
    }
    if (defined $originating_client_id
        && ($tags{overnet_ot} || '') eq 'chat.channel'
        && (($tags{overnet_et} || '') eq 'chat.message'
          || ($tags{overnet_et} || '') eq 'chat.notice')) {
      $self->{subscription_event_origin_client_ids}{$signed->{id}} = $originating_client_id;
    }
    $self->_request(
      method => 'overnet.emit_event',
      params => { event => $signed },
    );
    $self->{events_emitted}++;
  }

  for my $state (@{$result->{state} || []}) {
    my $signed = $self->_sign_candidate_event($state);
    $self->_request(
      method => 'overnet.emit_state',
      params => { state => $signed },
    );
    $self->{state_emitted}++;
  }

  if (@{$result->{capabilities} || []}) {
    $self->_request(
      method => 'overnet.emit_capabilities',
      params => { capabilities => $result->{capabilities} },
    );
    $self->{capabilities_emitted} += scalar @{$result->{capabilities}};
  }

  return 1;
}

sub _emit_private_message_candidate {
  my ($self, $candidate, %opts) = @_;

  die "private-message candidate event must be an object\n"
    unless ref($candidate) eq 'HASH';

  my $originating_client_id = $opts{originating_client_id};
  die "originating_client_id is required for encrypted private messages\n"
    unless defined $originating_client_id && !ref($originating_client_id) && length($originating_client_id);

  my $sender = $self->{clients}{$originating_client_id}
    or die "Unknown originating_client_id for encrypted private message\n";
  die "Encrypted private-message sender must be registered\n"
    unless $sender->{registered};
  $sender->{dm_key} ||= Overnet::Core::Nostr->generate_key;

  my %tags = $self->_first_tag_values($candidate->{tags});
  my $private_type = $tags{overnet_et} || '';
  my $object_type = $tags{overnet_ot} || '';
  my $object_id = $tags{overnet_oid} || '';
  die "Encrypted private-message candidate must target chat.dm\n"
    unless $object_type eq 'chat.dm';
  die "Encrypted private-message candidate must be chat.dm_message or chat.dm_notice\n"
    unless $private_type eq 'chat.dm_message' || $private_type eq 'chat.dm_notice';

  my $content = eval { JSON::PP::decode_json($candidate->{content}) };
  die "Encrypted private-message candidate content must decode to an object\n"
    unless ref($content) eq 'HASH';

  my $body = $content->{body};
  die "Encrypted private-message candidate body must be an object\n"
    unless ref($body) eq 'HASH';
  die "Encrypted private-message candidate body.text must be a string\n"
    unless defined $body->{text} && !ref($body->{text});

  my $target_nick = $self->_dm_nick_from_object_id($object_id);
  die "Encrypted private-message candidate object_id must target an IRC nick\n"
    unless defined $target_nick;
  my $target_key = $self->_nick_key($target_nick);
  die "Encrypted private-message target nick is invalid\n"
    unless defined $target_key;
  my $target_client_id = $self->{nick_to_client_id}{$target_key};
  die "Encrypted private-message target nick is not connected\n"
    unless defined $target_client_id && exists $self->{clients}{$target_client_id};

  my $recipient = $self->{clients}{$target_client_id};
  die "Encrypted private-message recipient must be registered\n"
    unless $recipient->{registered};
  $recipient->{dm_key} ||= Overnet::Core::Nostr->generate_key;

  my $payload = {
    overnet_v    => $tags{overnet_v} || '0.1.0',
    private_type => $private_type,
    object_type  => $object_type,
    object_id    => $object_id,
    provenance   => $content->{provenance},
    body         => $body,
  };

  my $transport = Overnet::Core::Nostr->wrap_private_message(
    sender_key        => $sender->{dm_key},
    payload           => $payload,
    recipient_pubkeys => [ $recipient->{dm_key}->pubkey_hex ],
    skip_sender       => 1,
  );

  my $irc_command = $private_type eq 'chat.dm_notice' ? 'NOTICE' : 'PRIVMSG';
  my $result = $self->_request(
    method => 'overnet.emit_private_message',
    params => {
      message => {
        source => {
          protocol => 'irc',
          network  => $self->{config}{network},
          line     => sprintf(':%s %s %s :%s', $sender->{nick}, $irc_command, $recipient->{nick}, $body->{text}),
        },
        transport => {
          %{$transport->{transport}->to_hash},
          decrypted_rumor => $transport->{decrypted_rumor}->to_hash,
        },
      },
    },
  );
  $self->{private_messages_emitted}++;

  return $result;
}

sub _emit_opaque_private_message_transport {
  my ($self, %args) = @_;
  my $client = $args{client};
  my $command = $args{command} || '';
  my $target_nick = $args{target_nick};
  my $body_text = $args{body_text};
  my $transport = $args{transport};

  die "client is required for opaque private-message transport\n"
    unless ref($client) eq 'HASH';
  die "command must be PRIVMSG or NOTICE for opaque private-message transport\n"
    unless $command eq 'PRIVMSG' || $command eq 'NOTICE';
  die "target_nick is required for opaque private-message transport\n"
    unless defined $target_nick && !ref($target_nick) && length($target_nick);
  die "transport must be an object\n"
    unless ref($transport) eq 'HASH';
  die "body_text is required for opaque private-message transport\n"
    unless defined $body_text && !ref($body_text) && length($body_text);

  unless ($self->_client_has_capability($client, 'overnet-e2ee') && defined $client->{e2ee_pubkey}) {
    $self->_send_server_notice($client->{id}, 'E2EE direct messages require CAP overnet-e2ee and OVERNETKEY SET');
    return 0;
  }

  my $recipient = $self->_client_for_current_nick($target_nick);
  unless (ref($recipient) eq 'HASH'
      && $self->_client_has_capability($recipient, 'overnet-e2ee')
      && defined $recipient->{e2ee_pubkey}) {
    $self->_send_server_notice($client->{id}, 'Target nick is not E2EE-capable');
    return 0;
  }

  my $wrap = Overnet::Core::Nostr->event_from_wire($transport);
  if (!$wrap || !eval { $wrap->validate; 1 }) {
    $self->_send_server_notice($client->{id}, 'Malformed overnet-e2ee transport');
    return 0;
  }

  if ($wrap->kind != 1059) {
    $self->_send_server_notice($client->{id}, 'Opaque private-message transport must use kind 1059');
    return 0;
  }

  my @recipient_tags = grep {
    ref($_) eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p'
  } @{$wrap->tags || []};
  if (@recipient_tags != 1 || ($recipient_tags[0][1] || '') ne $recipient->{e2ee_pubkey}) {
    $self->_send_server_notice($client->{id}, 'Opaque private-message transport recipient does not match the target nick');
    return 0;
  }

  my $private_type = $command eq 'NOTICE' ? 'chat.dm_notice' : 'chat.dm_message';
  my $result = $self->_request(
    method => 'overnet.emit_private_message',
    params => {
      message => {
        source => {
          protocol => 'irc',
          network  => $self->{config}{network},
          line     => sprintf(':%s %s %s :%s', $client->{nick}, $command, $recipient->{nick}, $body_text),
        },
        private_type    => $private_type,
        object_type     => 'chat.dm',
        object_id       => $self->_dm_object_id($recipient->{nick}),
        sender_identity => $client->{nick},
        transport       => $wrap->to_hash,
      },
    },
  );
  $self->{private_messages_emitted}++;

  return $result;
}

sub _sign_candidate_event {
  my ($self, $candidate) = @_;

  die "candidate event must be an object\n"
    unless ref($candidate) eq 'HASH';
  die "candidate event kind is required\n"
    unless defined $candidate->{kind} && !ref($candidate->{kind});
  die "candidate event created_at is required\n"
    unless defined $candidate->{created_at} && !ref($candidate->{created_at});
  die "candidate event tags must be an array\n"
    unless ref($candidate->{tags}) eq 'ARRAY';
  die "candidate event content is required\n"
    unless defined $candidate->{content} && !ref($candidate->{content});

  return $self->{signing_key}->create_event_hash(
    kind       => $candidate->{kind},
    created_at => $candidate->{created_at},
    tags       => $candidate->{tags},
    content    => $candidate->{content},
  );
}

sub _request {
  my ($self, %args) = @_;
  my $method = $args{method};
  my $params = $args{params} || {};
  my @deferred_messages;

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "params must be an object\n"
    unless ref($params) eq 'HASH';

  my $restore_deferred = sub {
    return unless @deferred_messages;
    unshift @{$self->{pending_messages}}, @deferred_messages;
    @deferred_messages = ();
    return;
  };

  my $id = 'program-' . $self->{next_request_id}++;
  $self->_send_message(
    Overnet::Program::Protocol::build_request(
      id     => $id,
      method => $method,
      params => $params,
    )
  );

  while (1) {
    my $message = @{$self->{pending_messages}}
      ? shift @{$self->{pending_messages}}
      : $self->_next_runtime_message;

    if (($message->{type} || '') eq 'response') {
      $restore_deferred->();
      die "Unexpected response id while awaiting $method\n"
        unless ($message->{id} || '') eq $id;

      if ($message->{ok}) {
        return $message->{result} || {};
      }

      die "$method failed: " . ($message->{error}{code} || 'unknown') . ': '
        . ($message->{error}{message} || 'unknown error');
    }

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $restore_deferred->();
      $self->_handle_runtime_shutdown($message);
      die '__shutdown__';
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      $restore_deferred->();
      die "runtime fatal: " . ($message->{params}{code} || 'unknown');
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.subscription_event') {
      push @deferred_messages, $message;
      next;
    }

    $restore_deferred->();
    die "Unexpected message while awaiting response for $method\n";
  }
}

sub _read_runtime_chunk {
  my ($self) = @_;
  my $bytes = sysread(STDIN, my $chunk, 4096);
  die "unexpected EOF on runtime stdin\n"
    unless defined $bytes;
  die '__shutdown__'
    if $bytes == 0 && $self->{shutdown_complete};
  die "unexpected EOF on runtime stdin\n"
    if $bytes == 0;

  push @{$self->{pending_messages}}, @{$self->{protocol}->feed($chunk)};
  return $bytes;
}

sub _drain_pending_runtime_messages {
  my ($self, %args) = @_;
  my $max_messages = $args{max_messages};
  my $count = 0;

  while (@{$self->{pending_messages}}) {
    last if defined $max_messages && $count >= $max_messages;
    my $message = shift @{$self->{pending_messages}};
    $count++;

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      next;
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      die "runtime fatal: " . ($message->{params}{code} || 'unknown') . "\n";
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.subscription_event') {
      $self->_handle_subscription_event($message->{params} || {});
      next;
    }

    die "Unexpected runtime message in IRC server loop\n";
  }

  return $count;
}

sub _next_runtime_message {
  my ($self) = @_;

  while (!@{$self->{pending_messages}}) {
    $self->_read_runtime_chunk;
  }

  return shift @{$self->{pending_messages}};
}

sub _parse_irc_message {
  my ($self, $line) = @_;
  my %message = (
    raw_line => $line,
    params   => [],
  );

  if ($line =~ s/\A\@(\S+)\s+//) {
    $message{tags} = $self->_parse_irc_tags($1);
  }

  if ($line =~ s/\A:([^ ]+)\s+//) {
    my $prefix = $1;
    $message{prefix} = $prefix;
    if ($prefix =~ /\A([^!@]+)!([^@]+)\@(.+)\z/) {
      @message{qw(prefix_nick prefix_user prefix_host)} = ($1, $2, $3);
    } else {
      $message{prefix_nick} = $prefix;
    }
  }

  my ($command, $rest) = split(/ /, $line, 2);
  return undef unless defined $command && length $command;
  $message{command} = uc($command);
  $rest = '' unless defined $rest;

  while (length $rest) {
    $rest =~ s/\A +//;
    last unless length $rest;

    if ($rest =~ s/\A:(.*)\z//) {
      push @{$message{params}}, $1;
      last;
    }

    if ($rest =~ s/\A([^ ]+)//) {
      push @{$message{params}}, $1;
      next;
    }

    last;
  }

  return \%message;
}

sub _parse_irc_tags {
  my ($self, $raw) = @_;
  my %tags;
  for my $entry (split /;/, $raw) {
    my ($name, $value) = split /=/, $entry, 2;
    next unless defined $name && length $name;
    $tags{$name} = defined $value ? $value : '';
  }
  return \%tags;
}

sub _first_tag_values {
  my ($self, $tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _channel_object_id {
  my ($self, $channel) = @_;
  my $canonical = $self->_canonical_channel_name($channel);
  return undef unless defined $canonical;
  return 'irc:' . $self->{config}{network} . ':' . $canonical;
}

sub _dm_object_id {
  my ($self, $nick) = @_;
  return 'irc:' . $self->{config}{network} . ':dm:' . $nick;
}

sub _channel_key {
  my ($self, $channel) = @_;
  return undef unless $self->_is_channel_name($channel);
  return $self->_irc_casefold($channel);
}

sub _canonical_channel_name {
  my ($self, $channel) = @_;
  my $key = $self->_channel_key($channel);
  return undef unless defined $key;
  return $self->{channels}{$key}{channel_name}
    if exists $self->{channels}{$key}
      && defined $self->{channels}{$key}{channel_name}
      && length($self->{channels}{$key}{channel_name});
  return $channel;
}

sub _client_joined_channel_name {
  my ($self, $client, $channel) = @_;
  return undef unless ref($client) eq 'HASH';
  my $key = $self->_channel_key($channel);
  return undef unless defined $key;
  return $client->{joined_channels}{$key};
}

sub _channel_state {
  my ($self, $channel) = @_;
  my $key = $self->_channel_key($channel);
  return undef unless defined $key;

  return $self->{channels}{$key} ||= {
    channel_name  => $channel,
    members       => {},
    visible_nicks => {},
    topic_text    => undef,
  };
}

sub _add_visible_nick {
  my ($self, $channel, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  return 0 unless defined $nick_key;

  my $state = $self->_channel_state($channel);
  return 0 unless $state;
  $state->{visible_nicks}{$nick_key} ||= {
    count        => 0,
    display_nick => $nick,
  };
  $state->{visible_nicks}{$nick_key}{display_nick} = $nick;
  $state->{visible_nicks}{$nick_key}{count}++;
  return $state->{visible_nicks}{$nick_key}{count};
}

sub _remove_visible_nick {
  my ($self, $channel, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  return 0 unless defined $nick_key;
  my $channel_key = $self->_channel_key($channel);
  return 0 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return 0;
  return 0 unless exists $state->{visible_nicks}{$nick_key};

  $state->{visible_nicks}{$nick_key}{count}--;
  delete $state->{visible_nicks}{$nick_key}
    if $state->{visible_nicks}{$nick_key}{count} <= 0;
  return 1;
}

sub _rename_visible_nick {
  my ($self, $channel, %args) = @_;
  my $old_nick = $args{old_nick};
  my $new_nick = $args{new_nick};
  my $old_key = $self->_nick_key($old_nick);
  my $new_key = $self->_nick_key($new_nick);
  return 0 unless defined $old_key;
  return 0 unless defined $new_key;

  my $channel_key = $self->_channel_key($channel);
  return 0 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return 0;
  my $entry = delete $state->{visible_nicks}{$old_key}
    or return 0;
  my $count = $entry->{count} || 0;
  $state->{visible_nicks}{$new_key} ||= {
    count        => 0,
    display_nick => $new_nick,
  };
  $state->{visible_nicks}{$new_key}{count} += $count;
  $state->{visible_nicks}{$new_key}{display_nick} = $new_nick;
  return $count;
}

sub _rename_visible_nick_everywhere {
  my ($self, %args) = @_;
  my $count = 0;

  for my $channel (sort keys %{$self->{channels}}) {
    $count += $self->_rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub _rename_client_channels {
  my ($self, $client, %args) = @_;
  return 0 unless ref($client) eq 'HASH';

  my $count = 0;
  for my $channel (sort values %{$client->{joined_channels} || {}}) {
    $count += $self->_rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub _visible_nicks_for_channel {
  my ($self, $channel) = @_;
  my $channel_key = $self->_channel_key($channel);
  return () unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return ();

  return sort grep {
    defined $_ && length $_
  } map {
    $state->{visible_nicks}{$_}{display_nick}
  } grep {
    ($state->{visible_nicks}{$_}{count} || 0) > 0
  } keys %{$state->{visible_nicks} || {}};
}

sub _send_names_list {
  my ($self, $client_id, $channel, %opts) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  my @nicks;
  if ($self->_is_authoritative_channel($display_channel)) {
    $self->_refresh_authoritative_nip29_channel_cache(
      $display_channel,
      ($opts{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    ) if $opts{force} && ref($opts{view}) ne 'HASH';
    @nicks = $self->_authoritative_name_entries_for_channel(
      $client,
      $display_channel,
      force => $opts{force} ? 1 : 0,
      (ref($opts{view}) eq 'HASH' ? (view => $opts{view}) : ()),
    );
  }

  if (!@nicks) {
    @nicks = $self->_visible_nicks_for_channel($display_channel);
    my $client_present = scalar grep {
      defined $_
        && defined $client->{nick}
        && $_ eq $client->{nick}
    } @nicks;
    if (!$client_present && defined $self->_client_joined_channel_name($client, $display_channel)) {
      push @nicks, $client->{nick};
      @nicks = sort @nicks;
    }
  }

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::names_list_lines(
      server_name => $self->{config}{server_name},
      nick        => $client->{nick},
      channel     => $display_channel,
      names       => \@nicks,
    ),
  );
}

sub _send_join_bootstrap {
  my ($self, $client_id, $channel) = @_;
  if ($self->_is_authoritative_channel($channel)) {
    my $canonical = $self->_canonical_channel_name($channel);
    my $cache = defined $canonical
      ? $self->{authoritative_channel_cache}{$canonical}
      : undef;
    my $view = ref($cache) eq 'HASH' && ref($cache->{view}) eq 'HASH'
      ? $cache->{view}
      : $self->_derive_authoritative_channel_view($channel);
    $view = $self->_derive_authoritative_channel_view($channel, force => 1)
      unless ref($view) eq 'HASH';
    $self->_sync_authoritative_topic_state_from_view($channel, $view);
    my $line = $self->_authoritative_topic_line_from_view($channel, $view);
    $self->_send_client_line($client_id, $line)
      if defined $line && length $line;
    return $self->_send_names_list(
      $client_id,
      $channel,
      (ref($view) eq 'HASH' ? (view => $view) : ()),
    );
  }

  my $channel_key = $self->_channel_key($channel);
  return 0 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return 0;

  if (defined $state->{topic_line} && length $state->{topic_line}) {
    $self->_send_client_line($client_id, $state->{topic_line});
  }

  return $self->_send_names_list($client_id, $state->{channel_name});
}

sub _channel_name_from_object_id {
  my ($self, $object_id) = @_;
  return undef unless defined $object_id && !ref($object_id);

  my $prefix = 'irc:' . $self->{config}{network} . ':';
  return undef unless index($object_id, $prefix) == 0;

  my $channel = substr($object_id, length($prefix));
  return undef unless $self->_is_channel_name($channel);
  return $self->_canonical_channel_name($channel);
}

sub _dm_nick_from_object_id {
  my ($self, $object_id) = @_;
  return undef unless defined $object_id && !ref($object_id);

  my $prefix = 'irc:' . $self->{config}{network} . ':dm:';
  return undef unless index($object_id, $prefix) == 0;

  my $nick = substr($object_id, length($prefix));
  return undef unless $self->_is_nick_name($nick);
  return $nick;
}

sub _is_channel_name {
  my ($self, $value) = @_;
  return defined $value
    && !ref($value)
    && $value =~ /\A[#&][^\x00\x07\r\n ,:]+\z/
      ? 1
      : 0;
}

sub _is_nick_name {
  my ($self, $value) = @_;
  return defined $value
    && !ref($value)
    && $value =~ /\A[^\x00\x07\r\n ,:#&][^\x00\x07\r\n ,:]*\z/
      ? 1
      : 0;
}

sub _broadcast_channel_line {
  my ($self, $channel, $line) = @_;
  my $channel_key = $self->_channel_key($channel);
  return 0 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    or return 0;

  return $self->_send_line_to_client_ids(
    [ grep { exists $self->{clients}{$_} } sort keys %{$state->{members}} ],
    $line,
  );
}

sub _shared_client_ids_for_channels {
  my ($self, $channels, %args) = @_;
  my %client_ids;

  for my $channel (@{$channels || []}) {
    my $channel_key = $self->_channel_key($channel);
    next unless defined $channel_key;
    my $state = $self->{channels}{$channel_key}
      or next;
    for my $client_id (keys %{$state->{members} || {}}) {
      next if defined $args{exclude_client_id} && $client_id eq $args{exclude_client_id};
      next unless exists $self->{clients}{$client_id};
      next unless $self->{clients}{$client_id}{registered};
      $client_ids{$client_id} = 1;
    }
  }

  return sort keys %client_ids;
}

sub _shared_client_ids_for_client {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return ();
  my @channels = sort values %{$client->{joined_channels} || {}};
  return ($client_id) unless @channels;
  return $self->_shared_client_ids_for_channels(\@channels);
}

sub _shared_client_ids_for_nick {
  my ($self, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  return () unless defined $nick_key;

  my @channels = grep {
    exists $self->{channels}{$_}{visible_nicks}{$nick_key}
      && ($self->{channels}{$_}{visible_nicks}{$nick_key}{count} || 0) > 0
  } sort keys %{$self->{channels}};
  return $self->_shared_client_ids_for_channels(\@channels);
}

sub _send_line_to_client_ids {
  my ($self, $client_ids, $line) = @_;
  my $count = 0;

  for my $client_id (@{$client_ids || []}) {
    next unless exists $self->{clients}{$client_id};
    $self->_send_client_line($client_id, $line);
    $count++;
  }

  return $count;
}

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  $line = $self->_decorate_outbound_line_for_client($client, $line);
  my $payload = $line . "\r\n";
  my $offset = 0;
  while ($offset < length $payload) {
    my $written = syswrite($client->{socket}, $payload, length($payload) - $offset, $offset);
    if (!defined $written) {
      if ($!{EPIPE} || $!{ECONNRESET} || $!{ENOTCONN}) {
        $self->_disconnect_client($client_id);
        return 0;
      }
      die "failed to write IRC line: $!\n";
    }
    if ($written == 0) {
      $self->_disconnect_client($client_id);
      return 0;
    }
    $offset += $written;
  }

  return 1;
}

sub _decorate_outbound_line_for_client {
  my ($self, $client, $line) = @_;
  return $line unless defined $line && !ref($line) && length($line);
  return $line unless ref($client) eq 'HASH';
  return $line if $line =~ /\A:\S+\s+CAP\s/;
  return $line if $line =~ /\AAUTHENTICATE\s/;

  my @existing_tags;
  if ($line =~ s/\A\@([^ ]+)\s+//) {
    @existing_tags = grep { defined($_) && length($_) } split /;/, $1;
  }

  my @tags;
  push @tags, [ time => $self->_ircv3_server_time_tag ]
    if $self->_client_has_capability($client, 'server-time');
  if ($self->_client_has_capability($client, 'message-tags')
      && $self->_client_has_capability($client, 'account-tag')) {
    my $account = $self->_outbound_account_tag_for_line($line);
    push @tags, [ account => $account ]
      if defined($account) && !ref($account) && length($account);
  }

  return $line unless @tags
    && (
      $self->_client_has_capability($client, 'message-tags')
        || $self->_client_has_capability($client, 'server-time')
    );

  my %seen = map {
    my ($name) = split /=/, $_, 2;
    ($name => 1);
  } @existing_tags;
  my @merged = map { $_->[0] . '=' . $_->[1] }
    grep { !$seen{$_->[0]}++ } @tags;
  push @merged, @existing_tags;

  return $line unless @merged;
  return '@' . join(';', @merged) . ' ' . $line;
}

sub _outbound_account_tag_for_line {
  my ($self, $line) = @_;
  return undef unless defined $line && !ref($line) && length($line);
  return undef unless $line =~ /\A:([^ ]+)\s/;

  my $prefix = $1;
  my ($nick) = split /[!@]/, $prefix, 2;
  return undef unless defined $nick && !ref($nick) && length($nick);

  my $sender = $self->_client_for_current_nick($nick);
  return undef unless ref($sender) eq 'HASH';
  return $self->_client_account_name($sender);
}

sub _ircv3_server_time_tag {
  my ($self, $epoch) = @_;
  $epoch = time() unless defined $epoch;
  my ($sec, $min, $hour, $mday, $mon, $year) = gmtime($epoch);
  return sprintf(
    '%04d-%02d-%02dT%02d:%02d:%02d.000Z',
    $year + 1900,
    $mon + 1,
    $mday,
    $hour,
    $min,
    $sec,
  );
}

sub _close_all_clients {
  my ($self) = @_;
  for my $client_id (keys %{$self->{clients}}) {
    my $client = delete $self->{clients}{$client_id};
    $self->_release_client_nick(
      $client_id,
      nick => ($client ? $client->{nick} : undef),
    );
    close $client->{socket}
      if defined $client && defined $client->{socket};
  }
  $self->{channels} = {};
  $self->{nick_to_client_id} = {};
  $self->{authoritative_last_created_at} = {};
  $self->{authoritative_delegate_sequences} = {};
  return 1;
}

sub _close_listen_socket {
  my ($self) = @_;
  return 1 unless defined $self->{listener_socket};
  close delete $self->{listener_socket};
  return 1;
}

sub _is_listener_socket {
  my ($self, $handle) = @_;
  return defined $self->{listener_socket}
    && defined $handle
    && defined fileno($self->{listener_socket})
    && defined fileno($handle)
    && fileno($self->{listener_socket}) == fileno($handle)
      ? 1
      : 0;
}

sub _is_runtime_stdin {
  my ($self, $handle) = @_;
  return defined $handle
    && defined fileno($handle)
    && defined fileno(STDIN)
    && fileno($handle) == fileno(STDIN)
      ? 1
      : 0;
}

sub _client_id_for_handle {
  my ($self, $handle) = @_;
  return undef unless defined $handle && defined fileno($handle);

  for my $client_id (keys %{$self->{clients}}) {
    my $socket = $self->{clients}{$client_id}{socket};
    next unless defined $socket && defined fileno($socket);
    return $client_id if fileno($socket) == fileno($handle);
  }

  return undef;
}

sub _log {
  my ($self, %args) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_notification(
      method => 'program.log',
      params => {
        level   => $args{level} || 'info',
        message => $args{message} || '',
        (defined $args{context} ? (context => $args{context}) : ()),
      },
    )
  );
}

sub _health {
  my ($self, %args) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_notification(
      method => 'program.health',
      params => {
        status  => $args{status},
        (defined $args{message} ? (message => $args{message}) : ()),
        (defined $args{details} ? (details => $args{details}) : ()),
      },
    )
  );
}

sub _send_message {
  my ($self, $message) = @_;
  my $frame = $self->{protocol}->encode_message($message);
  my $offset = 0;
  while ($offset < length $frame) {
    my $written = syswrite(STDOUT, $frame, length($frame) - $offset, $offset);
    die "failed to write runtime protocol frame: $!\n"
      unless defined $written;
    $offset += $written;
  }

  return 1;
}

1;

=head1 NAME

Overnet::Program::IRC::Server - Supervised listening IRC server for Overnet

=head1 DESCRIPTION

Accepts IRC client connections, maps inbound IRC commands through the runtime
adapter service, signs candidate Overnet events with Net::Nostr, emits them
through the runtime validation boundary, and fans subscribed Overnet channel
items back out as IRC lines.

=cut
