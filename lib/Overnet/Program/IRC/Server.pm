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
use Overnet::Core::Nostr;
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
    inputs_processed            => 0,
    events_emitted              => 0,
    state_emitted               => 0,
    private_messages_emitted    => 0,
    capabilities_emitted        => 0,
  }, $class;
}

sub run {
  my ($self) = @_;

  binmode(STDIN, ':raw');
  binmode(STDOUT, ':raw');
  binmode(STDERR, ':raw');
  STDOUT->autoflush(1);
  STDERR->autoflush(1);

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

  $self->_run_server_loop;
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
    1;
  };
  if (!$opened) {
    my $error = $@ || "Failed to open IRC adapter session\n";
    chomp $error;
    return if $error eq '__shutdown__';
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

  while (!$self->{shutdown_complete}) {
    my $drained = $self->_drain_pending_runtime_messages;
    last if $self->{shutdown_complete};
    next if $drained;

    my @handles = (\*STDIN);
    push @handles, $self->{listener_socket}
      if defined $self->{listener_socket};
    push @handles, map { $self->{clients}{$_}{socket} }
      sort keys %{$self->{clients}};

    my $selector = IO::Select->new(@handles);
    my @ready = $selector->can_read(0.1);
    next unless @ready;

    for my $handle (@ready) {
      if ($self->_is_listener_socket($handle)) {
        $self->_accept_client;
        next;
      }

      if ($self->_is_runtime_stdin($handle)) {
        $self->_read_runtime_chunk;
        $self->_drain_pending_runtime_messages;
        last if $self->{shutdown_complete};
        next;
      }

      my $client_id = $self->_client_id_for_handle($handle);
      next unless defined $client_id;
      $self->_pump_client_socket($client_id);
      last if $self->{shutdown_complete};
    }
  }

  $self->_close_all_clients;
  $self->_close_listen_socket;
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
    capabilities    => {},
    nick            => undef,
    username        => undef,
    realname        => undef,
    dm_key          => undef,
    e2ee_pubkey     => undef,
    authority_pubkey => undef,
    authority_challenge => undef,
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

  $client->{read_buffer} .= $chunk;
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

sub _handle_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  my $message = $self->_parse_irc_message($line);
  return 1 unless $message;

  my $command = $message->{command};
  my @params = @{$message->{params} || []};

  if ($command eq 'CAP') {
    $self->_handle_cap_command($client_id, \@params);
    return 1;
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
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'OVERNETAUTH');
      return 1;
    }

    my $subcommand = uc($params[0]);
    if ($subcommand eq 'CHALLENGE') {
      my $challenge = $self->_generate_authoritative_auth_challenge($client);
      $client->{authority_challenge} = $challenge;
      $self->_send_server_notice($client_id, "OVERNETAUTH CHALLENGE $challenge");
      return 1;
    }

    if ($subcommand eq 'AUTH') {
      if (@params < 2 || !defined $params[1] || !length $params[1]) {
        $self->_send_need_more_params($client_id, 'OVERNETAUTH');
        return 1;
      }

      my $challenge = $client->{authority_challenge};
      unless (defined $challenge && !ref($challenge) && length($challenge)) {
        $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH requires a prior challenge');
        return 1;
      }

      my $decoded = eval { decode_base64($params[1]) };
      my $event_hash = eval { JSON::PP::decode_json($decoded) };
      unless (ref($event_hash) eq 'HASH') {
        $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH requires a base64-encoded event object');
        return 1;
      }

      my $event = Overnet::Core::Nostr->event_from_wire($event_hash);
      unless ($event && eval { $event->validate; 1 }) {
        $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH requires a valid signed Nostr event');
        return 1;
      }
      unless ($event->kind == 22242) {
        $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH requires kind 22242');
        return 1;
      }

      my %tags = $self->_first_tag_values($event->tags);
      unless (defined $tags{challenge} && $tags{challenge} eq $challenge) {
        $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH challenge does not match');
        return 1;
      }

      my $scope = $self->_authoritative_auth_scope;
      unless (defined $tags{relay} && $tags{relay} eq $scope) {
        $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH relay scope does not match');
        return 1;
      }

      $client->{authority_pubkey} = $event->pubkey;
      delete $client->{authority_challenge};
      $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH ' . $client->{authority_pubkey});
      return 1;
    }

    $self->_send_unknown_command($client_id, 'OVERNETAUTH');
    return 1;
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
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'MODE');
      return 1;
    }
    my $target = $params[0];
    if ($self->_is_nick_name($target)) {
      my $current_nick = $client->{nick};
      if (defined $current_nick
          && defined $self->_nick_key($current_nick)
          && defined $self->_nick_key($target)
          && $self->_nick_key($current_nick) eq $self->_nick_key($target)) {
        $self->_send_user_mode_is($client_id);
        return 1;
      }
    }

    if (!$self->_is_channel_name($target)) {
      $self->_send_no_such_channel($client_id, $target);
      return 1;
    }

    my $channel = $self->_client_joined_channel_name($client, $target);
    unless (defined $channel) {
      $self->_send_not_on_channel($client_id, $target);
      return 1;
    }

    if ($self->_is_authoritative_channel($channel)) {
      if (@params >= 2 && defined $params[1] && length $params[1]) {
        return $self->_handle_authoritative_mode_command(
          client_id => $client_id,
          channel   => $channel,
          params    => \@params,
        );
      }
    }

    $self->_send_channel_mode_is($client_id, $channel);
    return 1;
  }

  if ($command eq 'KICK') {
    if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1] || !length $params[1]) {
      $self->_send_need_more_params($client_id, 'KICK');
      return 1;
    }
    my $channel_input = $params[0];
    if (!$self->_is_channel_name($channel_input)) {
      $self->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $self->_client_joined_channel_name($client, $channel_input);
    unless (defined $channel) {
      $self->_send_not_on_channel($client_id, $channel_input);
      return 1;
    }

    if ($self->_is_authoritative_channel($channel)) {
      return $self->_handle_authoritative_kick_command(
        client_id => $client_id,
        channel   => $channel,
        params    => \@params,
      );
    }

    $self->_send_unknown_command($client_id, 'KICK');
    return 1;
  }

  if ($command eq 'INVITE') {
    if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1] || !length $params[1]) {
      $self->_send_need_more_params($client_id, 'INVITE');
      return 1;
    }

    my $target_nick = $params[0];
    my $channel_input = $params[1];
    if (!$self->_is_channel_name($channel_input)) {
      $self->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $self->_client_joined_channel_name($client, $channel_input);
    unless (defined $channel) {
      $self->_send_not_on_channel($client_id, $channel_input);
      return 1;
    }

    if ($self->_is_authoritative_channel($channel)) {
      return $self->_handle_authoritative_invite_command(
        client_id   => $client_id,
        channel     => $channel,
        target_nick => $target_nick,
      );
    }

    $self->_send_unknown_command($client_id, 'INVITE');
    return 1;
  }

  if ($command eq 'JOIN') {
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'JOIN');
      return 1;
    }
    my $channel_input = $params[0];
    if (!$self->_is_channel_name($channel_input)) {
      $self->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $self->_canonical_channel_name($channel_input);
    return 1 if defined $self->_client_joined_channel_name($client, $channel_input);
    my $authoritative_join;

    if ($self->_is_authoritative_channel($channel)) {
      $authoritative_join = $self->_authoritative_join_admission_for_client($channel, $client);
      unless ($authoritative_join->{allowed}) {
        $self->_send_cannot_join_channel(
          $client_id,
          $channel,
          reason => $authoritative_join->{reason},
        );
        return 1;
      }

      if (defined $authoritative_join->{invite_code}) {
        $self->_emit_client_input(
          $client,
          {
            command      => 'JOIN',
            target       => $channel,
            actor_pubkey => $self->_client_authoritative_pubkey($client),
            invite_code  => $authoritative_join->{invite_code},
          },
        );
      }
    }

    $self->_add_client_to_channel($client_id, $channel);
    $self->_ensure_channel_subscription($channel);
    $self->_broadcast_channel_line(
      $channel,
      sprintf(':%s JOIN %s', $client->{nick}, $channel),
    );
    $self->_send_join_bootstrap($client_id, $channel);
    if (!$self->_is_authoritative_channel($channel)) {
      $self->_emit_client_input(
        $client,
        {
          command => 'JOIN',
          target  => $channel,
        },
        suppress_render_event_types => {
          'chat.join' => 1,
        },
      );
    }
    return 1;
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
    $self->_send_names_list($client_id, $channel);
    return 1;
  }

  if ($command eq 'PART') {
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'PART');
      return 1;
    }
    my $channel_input = $params[0];
    if (!$self->_is_channel_name($channel_input)) {
      $self->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $self->_client_joined_channel_name($client, $channel_input);
    unless (defined $channel) {
      $self->_send_not_on_channel($client_id, $channel_input);
      return 1;
    }

    my $reason = @params >= 2 ? $params[1] : undef;
    my $line = sprintf(':%s PART %s', $client->{nick}, $channel);
    $line .= ' :' . $reason
      if defined $reason && length $reason;
    $self->_broadcast_channel_line($channel, $line);
    $self->_remove_client_from_channel($client_id, $channel);
    $self->_emit_client_input(
      $client,
      {
        command => 'PART',
        target  => $channel,
        (defined $reason ? (text => $reason) : ()),
      },
      suppress_render_event_types => {
        'chat.part' => 1,
      },
    );
    return 1;
  }

  if ($command eq 'PRIVMSG' || $command eq 'NOTICE') {
    if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1]) {
      $self->_send_need_more_params($client_id, $command);
      return 1;
    }
    my $target = $params[0];

    if ($self->_is_channel_name($target)) {
      my $channel = $self->_client_joined_channel_name($client, $target);
      unless (defined $channel) {
        $self->_send_not_on_channel($client_id, $target);
        return 1;
      }

      if ($self->_channel_is_moderated_for_client($channel, $client)) {
        $self->_send_cannot_send_to_channel($client_id, $channel);
        return 1;
      }

      $self->_emit_client_input(
        $client,
        {
          command => $command,
          target  => $channel,
          text    => $params[1],
        },
      );
      return 1;
    }

    if (!$self->_is_nick_name($target)) {
      $self->_send_no_such_nick($client_id, $target);
      return 1;
    }

    my $target_nick = $self->_canonical_current_nick($target);
    unless (defined $target_nick) {
      $self->_send_no_such_nick($client_id, $target);
      return 1;
    }

    my ($e2ee_transport, $e2ee_error, $is_e2ee) = $self->_decode_e2ee_dm_body($params[1]);
    if ($is_e2ee) {
      if (!defined $e2ee_transport) {
        $self->_send_server_notice($client_id, $e2ee_error);
        return 1;
      }

      $self->_emit_opaque_private_message_transport(
        client       => $client,
        command      => $command,
        target_nick  => $target_nick,
        body_text    => $params[1],
        transport    => $e2ee_transport,
      );
      return 1;
    }

    $self->_emit_client_input(
      $client,
      {
        command => $command,
        target  => $target_nick,
        text    => $params[1],
      },
    );
    return 1;
  }

  if ($command eq 'TOPIC') {
    if (@params < 1 || !defined $params[0] || !length $params[0]) {
      $self->_send_need_more_params($client_id, 'TOPIC');
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

    if (@params == 1) {
      $self->_send_topic_reply($client_id, $channel);
      return 1;
    }

    if ($self->_channel_is_topic_restricted_for_client($channel, $client)) {
      $self->_send_chan_op_privs_needed($client_id, $channel);
      return 1;
    }

    $self->_emit_client_input(
      $client,
      {
        command => $command,
        target  => $channel,
        text    => $params[1],
      },
    );
    return 1;
  }

  if ($command eq 'LUSERS') {
    $self->_send_lusers_reply($client_id);
    return 1;
  }

  if ($command eq 'LIST') {
    my $target = @params ? $params[0] : undef;
    $self->_send_list_reply($client_id, $target);
    return 1;
  }

  $self->_send_unknown_command($client_id, $command);
  return 1;
}

sub _register_client_if_ready {
  my ($self, $client) = @_;
  return 0 if $client->{registered};
  return 0 unless defined $client->{nick} && length($client->{nick});
  return 0 unless defined $client->{username} && length($client->{username});

  $client->{registered} = 1;
  $client->{dm_key} ||= Overnet::Core::Nostr->generate_key;
  $self->_send_registration_prelude($client->{id});
  $self->_ensure_client_dm_subscription($client->{id});
  return 1;
}

sub _handle_cap_command {
  my ($self, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $subcommand = defined $params[0] ? uc($params[0]) : '';
  my $client = $self->{clients}{$client_id}
    or return 0;
  my @supported = $self->_supported_capabilities;

  if ($subcommand eq 'LS') {
    return $self->_send_client_line(
      $client_id,
      sprintf(':%s CAP * LS :%s', $self->{config}{server_name}, join(' ', @supported)),
    );
  }

  if ($subcommand eq 'REQ') {
    if (@params < 2 || !defined $params[1] || !length $params[1]) {
      $self->_send_need_more_params($client_id, 'CAP');
      return 1;
    }

    my @requested = grep { defined($_) && length($_) } split /\s+/, $params[1];
    my %supported = map { $_ => 1 } @supported;
    if (@requested && !grep { !$supported{$_} } @requested) {
      $client->{capabilities}{$_} = 1 for @requested;
      return $self->_send_client_line(
        $client_id,
        sprintf(':%s CAP * ACK :%s', $self->{config}{server_name}, join(' ', @requested)),
      );
    }

    return $self->_send_client_line(
      $client_id,
      sprintf(':%s CAP * NAK :%s', $self->{config}{server_name}, $params[1]),
    );
  }

  return 1 if $subcommand eq 'END';

  $self->_send_unknown_command($client_id, 'CAP');
  return 1;
}

sub _command_requires_registration {
  my ($self, $command) = @_;
  return scalar grep { $_ eq ($command || '') } qw(JOIN PART PRIVMSG NOTICE TOPIC NAMES MODE KICK INVITE USERHOST WHO WHOIS LUSERS LIST OVERNETKEY OVERNETAUTH);
}

sub _send_unknown_command {
  my ($self, $client_id, $command) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 421 %s %s :Unknown command',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $command,
    ),
  );
}

sub _send_registration_prelude {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 001 %s :Welcome to Overnet IRC',
      $self->{config}{server_name},
      $client->{nick},
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 005 %s %s :are supported by this server',
      $self->{config}{server_name},
      $client->{nick},
      $self->_isupport_tokens,
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 422 %s :MOTD File is missing',
      $self->{config}{server_name},
      $client->{nick},
    ),
  );

  return 1;
}

sub _send_nonickname_given {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 431 %s :No nickname given',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
    ),
  );
}

sub _send_not_registered {
  my ($self, $client_id) = @_;
  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 451 * :You have not registered',
      $self->{config}{server_name},
    ),
  );
}

sub _send_need_more_params {
  my ($self, $client_id, $command) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 461 %s %s :Not enough parameters',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $command,
    ),
  );
}

sub _send_server_notice {
  my ($self, $client_id, $text) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return 0 unless defined $client->{nick} && length($client->{nick});

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s NOTICE %s :%s',
      $self->{config}{server_name},
      $client->{nick},
      $text,
    ),
  );
}

sub _send_no_such_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 401 %s %s :No such nick/channel',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $nick,
    ),
  );
}

sub _send_no_such_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 403 %s %s :No such channel',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $channel,
    ),
  );
}

sub _send_not_on_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 442 %s %s :You\'re not on that channel',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $channel,
    ),
  );
}

sub _send_cannot_send_to_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 404 %s %s :Cannot send to channel',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $channel,
    ),
  );
}

sub _send_chan_op_privs_needed {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 482 %s %s :You\'re not channel operator',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $channel,
    ),
  );
}

sub _send_cannot_join_channel {
  my ($self, $client_id, $channel, %args) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $reason = 'Cannot join channel';
  $reason .= ' (' . $args{reason} . ')'
    if defined $args{reason} && !ref($args{reason}) && length($args{reason});

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 473 %s %s :%s',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $channel,
      $reason,
    ),
  );
}

sub _send_inviting {
  my ($self, $client_id, $target_nick, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 341 %s %s %s',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $target_nick,
      $channel,
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

  if (my $authoritative = $self->_derive_authoritative_channel_state($display_channel)) {
    $channel_modes = $authoritative->{channel_modes}
      if defined $authoritative->{channel_modes}
        && !ref($authoritative->{channel_modes})
        && length($authoritative->{channel_modes});
  }

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 324 %s %s %s',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $display_channel,
      $channel_modes,
    ),
  );
}

sub _send_user_mode_is {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 221 %s +',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
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

  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 251 %s :There are %d users and 0 services on 1 server',
      $self->{config}{server_name},
      $target,
      $registered_users,
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 252 %s 0 :operator(s) online',
      $self->{config}{server_name},
      $target,
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 253 %s 0 :unknown connection(s)',
      $self->{config}{server_name},
      $target,
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 254 %s %d :channels formed',
      $self->{config}{server_name},
      $target,
      $channels,
    ),
  );
  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 255 %s :I have %d clients and 1 server',
      $self->{config}{server_name},
      $target,
      $connected_clients,
    ),
  );
}

sub _send_list_reply {
  my ($self, $client_id, $target) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick = $self->_client_numeric_target($client);

  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 321 %s Channel :Users Name',
      $self->{config}{server_name},
      $nick,
    ),
  );

  for my $entry ($self->_list_entries($target)) {
    $self->_send_client_line(
      $client_id,
      sprintf(
        ':%s 322 %s %s %d :%s',
        $self->{config}{server_name},
        $nick,
        $entry->{channel},
        $entry->{visible_users},
        $entry->{topic},
      ),
    );
  }

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 323 %s :End of /LIST',
      $self->{config}{server_name},
      $nick,
    ),
  );
}

sub _send_topic_reply {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  my $channel_key = $self->_channel_key($display_channel);
  return 0 unless defined $channel_key;
  my $state = $self->{channels}{$channel_key}
    || $self->_channel_state($display_channel);
  my $target = $self->_client_numeric_target($client);

  if (defined $state->{topic_text} && !ref($state->{topic_text}) && length($state->{topic_text})) {
    return $self->_send_client_line(
      $client_id,
      sprintf(
        ':%s 332 %s %s :%s',
        $self->{config}{server_name},
        $target,
        $display_channel,
        $state->{topic_text},
      ),
    );
  }

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 331 %s %s :No topic is set',
      $self->{config}{server_name},
      $target,
      $display_channel,
    ),
  );
}

sub _send_userhost_reply {
  my ($self, $client_id, $entries) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 302 %s :%s',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      join(' ', @{$entries || []}),
    ),
  );
}

sub _send_who_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  for my $entry ($self->_who_entries_for_channel($display_channel)) {
    $self->_send_client_line(
      $client_id,
      sprintf(
        ':%s 352 %s %s %s %s %s %s H :0 %s',
        $self->{config}{server_name},
        $self->_client_numeric_target($client),
        $display_channel,
        $entry->{username},
        $entry->{host},
        $self->{config}{server_name},
        $entry->{nick},
        $entry->{realname},
      ),
    );
  }

  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 315 %s %s :End of /WHO list.',
      $self->{config}{server_name},
      $self->_client_numeric_target($client),
      $display_channel,
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

  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 311 %s %s %s %s * :%s',
      $self->{config}{server_name},
      $target,
      $display_nick,
      $username,
      $host,
      $realname,
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 312 %s %s %s :%s',
      $self->{config}{server_name},
      $target,
      $display_nick,
      $self->{config}{server_name},
      $self->_server_description,
    ),
  );
  return $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 318 %s %s :End of /WHOIS list.',
      $self->{config}{server_name},
      $target,
      $display_nick,
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
  return ('overnet-e2ee');
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

sub _authority_profile {
  my ($self) = @_;
  return $self->{config}{adapter_config}{authority_profile} || '';
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

sub _is_authoritative_channel {
  my ($self, $channel) = @_;
  return 0 unless $self->_authority_profile eq 'nip29';
  return 0 unless $self->_is_channel_name($channel);

  my $canonical = $self->_canonical_channel_name($channel);
  my $channel_groups = $self->{config}{adapter_config}{channel_groups};
  return 0 unless ref($channel_groups) eq 'HASH';
  return exists $channel_groups->{$canonical} ? 1 : 0;
}

sub _authoritative_group_binding {
  my ($self, $channel) = @_;
  return unless $self->_is_authoritative_channel($channel);

  my $canonical = $self->_canonical_channel_name($channel);
  return unless defined $canonical;

  my $config = $self->{config}{adapter_config} || {};
  my $group_host = $config->{group_host};
  return unless defined $group_host && !ref($group_host) && length($group_host);

  my $channel_groups = $config->{channel_groups};
  return unless ref($channel_groups) eq 'HASH';
  return unless exists $channel_groups->{$canonical};

  my $binding = $channel_groups->{$canonical};
  my $group_id = ref($binding) eq 'HASH'
    ? $binding->{group_id}
    : $binding;
  return unless defined $group_id && !ref($group_id) && length($group_id);

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

sub _read_authoritative_nip29_events {
  my ($self, $channel) = @_;
  my $stream = $self->_authoritative_nip29_stream_name($channel);
  return [] unless defined $stream;

  my $result = eval {
    $self->_request(
      method => 'events.read',
      params => {
        stream => $stream,
      },
    );
  };
  return [] if $@;
  return [] unless ref($result->{entries}) eq 'ARRAY';

  return [
    map { $_->{event} }
    grep { ref($_) eq 'HASH' && ref($_->{event}) eq 'HASH' }
    @{$result->{entries}}
  ];
}

sub _derive_authoritative_channel_state {
  my ($self, $channel) = @_;
  return undef unless $self->_is_authoritative_channel($channel);
  my $authoritative_events = $self->_read_authoritative_nip29_events($channel);
  return undef unless @{$authoritative_events};

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => 'authoritative_channel_state',
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
        },
      },
    );
  };
  return undef if $@;
  return undef unless ref($result->{state}) eq 'ARRAY' && @{$result->{state}};
  return $result->{state}[0];
}

sub _client_authoritative_pubkey {
  my ($self, $client) = @_;
  return undef unless ref($client) eq 'HASH';
  return undef unless defined $client->{authority_pubkey} && !ref($client->{authority_pubkey}) && length($client->{authority_pubkey});
  return $client->{authority_pubkey};
}

sub _authoritative_member_for_pubkey {
  my ($self, $state, $pubkey) = @_;
  return undef unless ref($state) eq 'HASH';
  return undef unless defined $pubkey && !ref($pubkey) && length($pubkey);

  for my $member (@{$state->{members} || []}) {
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

  my $state = $self->_derive_authoritative_channel_state($channel);
  return () unless ref($state) eq 'HASH';
  my $member = $self->_authoritative_member_for_pubkey($state, $pubkey);
  return () unless ref($member) eq 'HASH';
  return @{$member->{roles} || []};
}

sub _client_is_authoritative_operator {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.operator' } $self->_authoritative_roles_for_client($channel, $client);
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

sub _channel_is_moderated_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_derive_authoritative_channel_state($channel);
  return 0 unless ref($state) eq 'HASH';
  return 0 unless $self->_channel_mode_enabled($state, 'm');
  return 0 if $self->_client_is_authoritative_operator($channel, $client);
  return 0 if $self->_client_has_authoritative_voice($channel, $client);
  return 1;
}

sub _channel_is_topic_restricted_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_derive_authoritative_channel_state($channel);
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
  };
}

sub _authoritative_pending_invite_for_pubkey {
  my ($self, $channel, $pubkey) = @_;
  return undef unless defined $pubkey && !ref($pubkey) && length($pubkey);

  my (undef, $group_id) = $self->_authoritative_group_binding($channel);
  return undef unless defined $group_id;

  my %pending;
  for my $event (@{$self->_read_authoritative_nip29_events($channel)}) {
    next unless ref($event) eq 'HASH';

    my %tags = $self->_first_tag_values($event->{tags});
    next unless defined $tags{h} && $tags{h} eq $group_id;

    if (($event->{kind} || 0) == 9009) {
      next unless defined $tags{code} && length($tags{code});
      next if defined $tags{p} && $tags{p} ne $pubkey;

      $pending{$tags{code}} = {
        code => $tags{code},
        (defined $tags{p} ? (target_pubkey => $tags{p}) : ()),
      };
      next;
    }

    if (($event->{kind} || 0) == 9021) {
      next unless defined $tags{code} && length($tags{code});
      next unless exists $pending{$tags{code}};
      next unless defined $event->{pubkey} && $event->{pubkey} eq $pubkey;

      delete $pending{$tags{code}};
    }
  }

  return (values %pending)[0];
}

sub _authoritative_join_admission_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_derive_authoritative_channel_state($channel);
  return {
    allowed => 0,
    reason  => '',
  } unless ref($state) eq 'HASH';

  my $pubkey = $self->_client_authoritative_pubkey($client);
  return {
    allowed => 0,
    reason  => $self->_channel_mode_enabled($state, 'i') ? '+i' : '',
  } unless defined $pubkey;

  my $member = $self->_authoritative_member_for_pubkey($state, $pubkey);
  return {
    allowed => 1,
    member  => 1,
  } if ref($member) eq 'HASH';

  my $invite = $self->_authoritative_pending_invite_for_pubkey($channel, $pubkey);
  return {
    allowed     => 1,
    invite_code => $invite->{code},
  } if ref($invite) eq 'HASH' && defined $invite->{code};

  return {
    allowed => 0,
    reason  => $self->_channel_mode_enabled($state, 'i') ? '+i' : '',
  };
}

sub _authoritative_name_entries_for_channel {
  my ($self, $client, $channel) = @_;
  return () unless ref($client) eq 'HASH';

  my $state = $self->_derive_authoritative_channel_state($channel);
  return () unless ref($state) eq 'HASH';

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

sub _handle_authoritative_mode_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel = $args{channel};
  my @params = @{$args{params} || []};
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $state = $self->_derive_authoritative_channel_state($channel);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless ref($state) eq 'HASH';
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $self->_client_is_authoritative_operator($channel, $client);

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless defined $actor_pubkey;

  my $mode = $params[1];
  return $self->_send_need_more_params($client_id, 'MODE')
    unless defined $mode && !ref($mode) && length($mode);

  my %input = (
    command      => 'MODE',
    target       => $channel,
    mode         => $mode,
    actor_pubkey => $actor_pubkey,
  );

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

    my $member = $self->_authoritative_member_for_pubkey($state, $target_pubkey) || {};
    $input{target_pubkey} = $target_pubkey;
    $input{current_roles} = [ @{$member->{roles} || []} ];
    $mode_line .= ' ' . $target_nick;
  } elsif ($mode =~ /\A[+-][imt]\z/) {
    $input{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  } else {
    $self->_send_unknown_command($client_id, 'MODE');
    return 1;
  }

  $self->_emit_client_input($client, \%input);
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

  my $state = $self->_derive_authoritative_channel_state($channel);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless ref($state) eq 'HASH';
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $self->_client_is_authoritative_operator($channel, $client);

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless defined $actor_pubkey;

  my $target_nick = $self->_canonical_current_nick($params[1]);
  return $self->_send_no_such_nick($client_id, $params[1])
    unless defined $target_nick;
  my $target_client = $self->_client_for_current_nick($target_nick);
  return $self->_send_no_such_nick($client_id, $params[1])
    unless ref($target_client) eq 'HASH';
  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  return $self->_send_no_such_nick($client_id, $params[1])
    unless defined $target_pubkey;

  my $reason = @params >= 3 ? $params[2] : undef;
  $self->_emit_client_input(
    $client,
    {
      command       => 'KICK',
      target        => $channel,
      actor_pubkey  => $actor_pubkey,
      target_pubkey => $target_pubkey,
      (defined $reason ? (text => $reason) : ()),
    },
  );

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

  my $state = $self->_derive_authoritative_channel_state($channel);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless ref($state) eq 'HASH';
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless $self->_client_is_authoritative_operator($channel, $client);

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  return $self->_send_chan_op_privs_needed($client_id, $channel)
    unless defined $actor_pubkey;

  my $target_nick = $self->_canonical_current_nick($target_nick_input);
  return $self->_send_no_such_nick($client_id, $target_nick_input)
    unless defined $target_nick;
  my $target_client = $self->_client_for_current_nick($target_nick);
  return $self->_send_no_such_nick($client_id, $target_nick_input)
    unless ref($target_client) eq 'HASH';
  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  return $self->_send_no_such_nick($client_id, $target_nick_input)
    unless defined $target_pubkey;

  my $invite_code = $self->_generate_authoritative_invite_code(
    channel       => $channel,
    actor_pubkey  => $actor_pubkey,
    target_pubkey => $target_pubkey,
  );

  $self->_emit_client_input(
    $client,
    {
      command       => 'INVITE',
      target        => $channel,
      actor_pubkey  => $actor_pubkey,
      target_nick   => $target_nick,
      target_pubkey => $target_pubkey,
      invite_code   => $invite_code,
    },
  );

  $self->_send_inviting($client_id, $target_nick, $channel);
  $self->_send_client_line(
    $target_client->{id},
    sprintf(':%s INVITE %s :%s', $client->{nick}, $target_nick, $channel),
  );
  return 1;
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
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 433 %s %s :Nickname is already in use',
      $self->{config}{server_name},
      $target,
      $attempted_nick,
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
    created_at => int(time()),
  );

  my $mapped = $self->_request(
    method => 'adapters.map_input',
    params => {
      adapter_session_id => $self->{adapter_session_id},
      input              => \%payload,
    },
  );
  $self->{inputs_processed}++;

  if ($self->_store_authoritative_mapped_result(
      target => $payload{target},
      mapped => $mapped,
    )) {
    return 1;
  }

  $self->_emit_mapped_result(
    $mapped,
    originating_client_id => $client->{id},
    suppress_render_event_types => $opts{suppress_render_event_types},
  );

  return 1;
}

sub _append_authoritative_nip29_event {
  my ($self, $channel, $event) = @_;
  return 0 unless ref($event) eq 'HASH';

  my $stream = $self->_authoritative_nip29_stream_name($channel);
  return 0 unless defined $stream;

  $self->_request(
    method => 'events.append',
    params => {
      stream => $stream,
      event  => $event,
    },
  );
  return 1;
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

sub _store_authoritative_mapped_result {
  my ($self, %args) = @_;
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
    $self->_append_authoritative_nip29_event($channel, $event);
  }

  return 1;
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
  my ($self, $target) = @_;
  my @channels = map {
    $self->{channels}{$_}{channel_name}
  } grep {
    ref($self->{channels}{$_}) eq 'HASH'
      && defined $self->{channels}{$_}{channel_name}
      && !ref($self->{channels}{$_}{channel_name})
      && length($self->{channels}{$_}{channel_name})
  } keys %{$self->{channels} || {}};

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
  delete $self->{clients}{$client_id};

  return 1;
}

sub _handle_subscription_event {
  my ($self, $params) = @_;
  return 0 unless ref($params) eq 'HASH';
  return 0 unless ($params->{item_type} || '') eq 'event'
    || ($params->{item_type} || '') eq 'state'
    || ($params->{item_type} || '') eq 'private_message';
  return 0 unless ref($params->{data}) eq 'HASH';

  my $data = $params->{data};
  if (defined $data->{id} && delete $self->{suppress_subscription_event_ids}{$data->{id}}) {
    return 0;
  }

  my $render = $self->_render_subscription_item(
    item_type => $params->{item_type},
    data      => $data,
  );
  return 0 unless $render;

  for my $client_id (@{$render->{client_ids}}) {
    $self->_send_client_line($client_id, $render->{line});
  }

  return scalar @{$render->{client_ids}};
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

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "params must be an object\n"
    unless ref($params) eq 'HASH';

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
      die "Unexpected response id while awaiting $method\n"
        unless ($message->{id} || '') eq $id;

      if ($message->{ok}) {
        return $message->{result} || {};
      }

      die "$method failed: " . ($message->{error}{code} || 'unknown') . ': '
        . ($message->{error}{message} || 'unknown error');
    }

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      die '__shutdown__';
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      die "runtime fatal: " . ($message->{params}{code} || 'unknown');
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.subscription_event') {
      $self->_handle_subscription_event($message->{params} || {});
      next;
    }

    die "Unexpected message while awaiting response for $method\n";
  }
}

sub _read_runtime_chunk {
  my ($self) = @_;
  my $bytes = sysread(STDIN, my $chunk, 4096);
  die "unexpected EOF on runtime stdin\n"
    unless defined $bytes && $bytes > 0;

  push @{$self->{pending_messages}}, @{$self->{protocol}->feed($chunk)};
  return $bytes;
}

sub _drain_pending_runtime_messages {
  my ($self) = @_;
  my $count = 0;

  while (@{$self->{pending_messages}}) {
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
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  return 0 unless defined $display_channel;

  my @nicks;
  if ($self->_is_authoritative_channel($display_channel)) {
    @nicks = $self->_authoritative_name_entries_for_channel($client, $display_channel);
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

  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 353 %s = %s :%s',
      $self->{config}{server_name},
      $client->{nick},
      $display_channel,
      join(' ', @nicks),
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 366 %s %s :End of /NAMES list.',
      $self->{config}{server_name},
      $client->{nick},
      $display_channel,
    ),
  );

  return 1;
}

sub _send_join_bootstrap {
  my ($self, $client_id, $channel) = @_;
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
