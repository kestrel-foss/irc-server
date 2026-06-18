package Overnet::Program::IRC::Command::Channel;

use strict;
use warnings;

our $VERSION = '0.001';

sub handle_overnetchannel {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};

  if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1] || !length $params[1]) {
    $server->_send_need_more_params($client_id, 'OVERNETCHANNEL');
    return 1;
  }

  my $subcommand = uc($params[0]);
  if ($subcommand eq 'DELETE') {
    my $channel_input = $params[1];
    unless ($server->_is_channel_name($channel_input)) {
      $server->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $server->_canonical_channel_name($channel_input);
    unless ($server->_is_authoritative_channel($channel)) {
      $server->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    return $server->_handle_authoritative_delete_command(
      client_id => $client_id,
      channel   => $channel,
    );
  }

  if ($subcommand eq 'UNDELETE') {
    my $channel_input = $params[1];
    unless ($server->_is_channel_name($channel_input)) {
      $server->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $channel = $server->_canonical_channel_name($channel_input);
    unless ($server->_is_authoritative_channel($channel)) {
      $server->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    return $server->_handle_authoritative_undelete_command(
      client_id => $client_id,
      channel   => $channel,
    );
  }

  if ($subcommand eq 'INVITES') {
    my $channel_input = $params[1];
    unless ($server->_is_channel_name($channel_input)) {
      $server->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $client = $server->{clients}{$client_id}
      or return 0;
    my $channel = $server->_client_joined_channel_name($client, $channel_input);
    unless (defined $channel) {
      $server->_send_not_on_channel($client_id, $channel_input);
      return 1;
    }

    return $server->_handle_authoritative_invites_command(
      client_id => $client_id,
      channel   => $channel,
    );
  }

  if ($subcommand eq 'REQUESTS') {
    my $channel_input = $params[1];
    unless ($server->_is_channel_name($channel_input)) {
      $server->_send_no_such_channel($client_id, $channel_input);
      return 1;
    }

    my $client = $server->{clients}{$client_id}
      or return 0;
    my $channel = $server->_client_joined_channel_name($client, $channel_input);
    unless (defined $channel) {
      $server->_send_not_on_channel($client_id, $channel_input);
      return 1;
    }

    return $server->_handle_authoritative_requests_command(
      client_id => $client_id,
      channel   => $channel,
    );
  }

  $server->_send_unknown_command($client_id, 'OVERNETCHANNEL');
  return 1;
}

sub handle_mode {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'MODE');
    return 1;
  }
  my $target = $params[0];
  if ($server->_is_nick_name($target)) {
    my $current_nick = $client->{nick};
    if (defined $current_nick
        && defined $server->_nick_key($current_nick)
        && defined $server->_nick_key($target)
        && $server->_nick_key($current_nick) eq $server->_nick_key($target)) {
      $server->_send_user_mode_is($client_id);
      return 1;
    }
  }

  if (!$server->_is_channel_name($target)) {
    $server->_send_no_such_channel($client_id, $target);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $target);
  unless (defined $channel) {
    $server->_send_not_on_channel($client_id, $target);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    if (@params >= 2 && defined $params[1] && length $params[1]) {
      return $server->_handle_authoritative_mode_command(
        client_id => $client_id,
        channel   => $channel,
        params    => \@params,
      );
    }
  }

  $server->_send_channel_mode_is($client_id, $channel);
  return 1;
}

sub handle_kick {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1] || !length $params[1]) {
    $server->_send_need_more_params($client_id, 'KICK');
    return 1;
  }
  my $channel_input = $params[0];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  unless (defined $channel) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    return $server->_handle_authoritative_kick_command(
      client_id => $client_id,
      channel   => $channel,
      params    => \@params,
    );
  }

  $server->_send_unknown_command($client_id, 'KICK');
  return 1;
}

sub handle_invite {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1] || !length $params[1]) {
    $server->_send_need_more_params($client_id, 'INVITE');
    return 1;
  }

  my $target_nick = $params[0];
  my $channel_input = $params[1];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  unless (defined $channel) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    return $server->_handle_authoritative_invite_command(
      client_id   => $client_id,
      channel     => $channel,
      target_nick => $target_nick,
    );
  }

  $server->_send_unknown_command($client_id, 'INVITE');
  return 1;
}

sub handle_join {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'JOIN');
    return 1;
  }
  my $channel_input = $params[0];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_canonical_channel_name($channel_input);
  my $already_joined = $server->_client_joined_channel_name($client, $channel_input);
  my $authoritative_join;

  if ($server->_is_authoritative_channel($channel)) {
    my $join_key = @params >= 2 && defined($params[1]) && !ref($params[1]) && length($params[1])
      ? $params[1]
      : undef;
    $authoritative_join = $server->_authoritative_join_admission_for_client(
      $channel,
      $client,
      (defined($join_key) ? (join_key => $join_key) : ()),
    );
    if (defined $already_joined) {
      if ($authoritative_join->{allowed} && $authoritative_join->{present}) {
        return 1;
      }
      $server->_remove_client_from_channel(
        $client_id,
        $channel,
        nick => $client->{nick},
      );
      $already_joined = undef;
    }
    unless ($authoritative_join->{allowed}) {
      if ($authoritative_join->{auth_required}) {
        $server->_send_server_notice($client_id, 'OVERNETAUTH AUTH is required for authoritative JOIN');
        return 1;
      }
      if ($authoritative_join->{deleted}) {
        $server->_send_no_such_channel($client_id, $channel);
        return 1;
      }
      if ($authoritative_join->{pending_request}) {
        $server->_send_server_notice($client_id, "Join request already pending for $channel");
        return 1;
      }
      if ($authoritative_join->{request_join}) {
        my $needs_authoritative_join_write = 1;
        if ($server->_authority_relay_enabled) {
          if ($needs_authoritative_join_write && !$server->_client_has_authoritative_delegation($client)) {
            $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative JOIN');
            return 1;
          }
          unless ($server->_publish_authoritative_input(
              $client,
              {
                command      => 'JOIN',
                target       => $channel,
                actor_pubkey => $server->_client_authoritative_pubkey($client),
                actor_mask   => $server->_authoritative_irc_mask_for_client($client),
                (defined $join_key ? (join_key => $join_key) : ()),
              },
            )) {
            $server->_send_server_notice(
              $client_id,
              $server->{authoritative_publish_error} || 'authoritative relay publish failed',
            );
            return 1;
          }
        } else {
          return 1 unless $server->_emit_client_input(
            $client,
            {
              command      => 'JOIN',
              target       => $channel,
              actor_pubkey => $server->_client_authoritative_pubkey($client),
              actor_mask   => $server->_authoritative_irc_mask_for_client($client),
              (defined $join_key ? (join_key => $join_key) : ()),
            },
          );
        }
        $server->_send_server_notice($client_id, "Join request submitted for $channel");
        return 1;
      }
      $server->_send_cannot_join_channel(
        $client_id,
        $channel,
        reason => $authoritative_join->{reason},
      );
      return 1;
    }

    if ($server->_authority_relay_enabled) {
      my $needs_authoritative_join_write = $authoritative_join->{create_channel}
        || defined($authoritative_join->{invite_code})
        || !$authoritative_join->{member}
        || !$authoritative_join->{present};
      if ($needs_authoritative_join_write && !$server->_client_has_authoritative_delegation($client)) {
        $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative JOIN');
        return 1;
      }
      if ($needs_authoritative_join_write) {
        unless ($server->_publish_authoritative_input(
            $client,
            {
              command        => 'JOIN',
              target         => $channel,
              actor_pubkey   => $server->_client_authoritative_pubkey($client),
              actor_mask     => $server->_authoritative_irc_mask_for_client($client),
              (defined $join_key ? (join_key => $join_key) : ()),
              (defined $authoritative_join->{invite_code} ? (invite_code => $authoritative_join->{invite_code}) : ()),
              ($authoritative_join->{create_channel} ? (create_channel => 1) : ()),
              ($authoritative_join->{create_channel} ? (group_metadata => { name => $channel }) : ()),
            },
          )) {
          $server->_send_server_notice(
            $client_id,
            $server->{authoritative_publish_error} || 'authoritative relay publish failed',
          );
          return 1;
        }
      }
    } else {
      my $needs_authoritative_join_emit = $authoritative_join->{create_channel}
        || defined($authoritative_join->{invite_code})
        || !$authoritative_join->{member}
        || !$authoritative_join->{present};
      if ($needs_authoritative_join_emit) {
        return 1 unless $server->_emit_client_input(
          $client,
          {
            command      => 'JOIN',
            target       => $channel,
            actor_pubkey => $server->_client_authoritative_pubkey($client),
            actor_mask   => $server->_authoritative_irc_mask_for_client($client),
            (defined $join_key ? (join_key => $join_key) : ()),
            (defined $authoritative_join->{invite_code} ? (invite_code => $authoritative_join->{invite_code}) : ()),
            ($authoritative_join->{create_channel} ? (create_channel => 1) : ()),
            ($authoritative_join->{create_channel} ? (group_metadata => { name => $channel }) : ()),
          },
        );
      }
    }
  }
  elsif (defined $already_joined) {
    return 1;
  }

  $server->_add_client_to_channel($client_id, $channel);
  $server->_broadcast_channel_line(
    $channel,
    sprintf(':%s JOIN %s', $client->{nick}, $channel),
  );
  $server->_send_join_bootstrap($client_id, $channel);
  $server->_ensure_channel_subscription($channel);
  $server->_ensure_authoritative_channel_subscription($channel)
    if $server->_authority_relay_enabled && $server->_is_authoritative_channel($channel);
  if (!$server->_is_authoritative_channel($channel)) {
    $server->_emit_client_input(
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

sub handle_part {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'PART');
    return 1;
  }
  my $channel_input = $params[0];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  unless (defined $channel) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return 1;
  }

  my $reason = @params >= 2 ? $params[1] : undef;
  if ($server->_is_authoritative_channel($channel)) {
    return $server->_handle_authoritative_part_command(
      client_id => $client_id,
      channel   => $channel,
      reason    => $reason,
    );
  }

  my $line = sprintf(':%s PART %s', $client->{nick}, $channel);
  $line .= ' :' . $reason
    if defined $reason && length $reason;
  $server->_broadcast_channel_line($channel, $line);
  $server->_remove_client_from_channel($client_id, $channel);
  $server->_emit_client_input(
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

sub handle_privmsg_or_notice {
  my ($server, $client_id, $command, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 2 || !defined $params[0] || !length $params[0] || !defined $params[1]) {
    $server->_send_need_more_params($client_id, $command);
    return 1;
  }
  my $target = $params[0];

  if ($server->_is_channel_name($target)) {
    my $channel = $server->_client_joined_channel_name($client, $target);
    unless (defined $channel) {
      $server->_send_not_on_channel($client_id, $target);
      return 1;
    }

    if ($server->_is_authoritative_channel($channel)) {
      my $permission = $server->_authoritative_speak_permission_for_client($channel, $client);
      unless ($permission->{allowed}) {
        $server->_send_cannot_send_to_channel($client_id, $channel);
        return 1;
      }
    } elsif ($server->_channel_is_moderated_for_client($channel, $client)) {
      $server->_send_cannot_send_to_channel($client_id, $channel);
      return 1;
    }

    $server->_emit_client_input(
      $client,
      {
        command => $command,
        target  => $channel,
        text    => $params[1],
      },
    );
    return 1;
  }

  if (!$server->_is_nick_name($target)) {
    $server->_send_no_such_nick($client_id, $target);
    return 1;
  }

  my $target_nick = $server->_canonical_current_nick($target);
  unless (defined $target_nick) {
    $server->_send_no_such_nick($client_id, $target);
    return 1;
  }

  my ($e2ee_transport, $e2ee_error, $is_e2ee) = $server->_decode_e2ee_dm_body($params[1]);
  if ($is_e2ee) {
    if (!defined $e2ee_transport) {
      $server->_send_server_notice($client_id, $e2ee_error);
      return 1;
    }

    $server->_emit_opaque_private_message_transport(
      client       => $client,
      command      => $command,
      target_nick  => $target_nick,
      body_text    => $params[1],
      transport    => $e2ee_transport,
    );
    return 1;
  }

  $server->_emit_client_input(
    $client,
    {
      command => $command,
      target  => $target_nick,
      text    => $params[1],
    },
  );
  return 1;
}

sub handle_topic {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'TOPIC');
    return 1;
  }
  my $target = $params[0];
  if (!$server->_is_channel_name($target)) {
    $server->_send_no_such_channel($client_id, $target);
    return 1;
  }
  my $channel = $server->_client_joined_channel_name($client, $target);
  unless (defined $channel) {
    $server->_send_not_on_channel($client_id, $target);
    return 1;
  }

  if (@params == 1) {
    $server->_send_topic_reply($client_id, $channel);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    my $permission = $server->_authoritative_topic_permission_for_client($channel, $client);
    unless ($permission->{allowed}) {
      if (($permission->{reason} || '') eq 'deleted') {
        $server->_send_no_such_channel($client_id, $channel);
      } else {
        $server->_send_chan_op_privs_needed($client_id, $channel);
      }
      return 1;
    }
    return $server->_handle_authoritative_topic_command(
      client_id => $client_id,
      channel   => $channel,
      text      => $params[1],
    );
  }

  if ($server->_channel_is_topic_restricted_for_client($channel, $client)) {
    $server->_send_chan_op_privs_needed($client_id, $channel);
    return 1;
  }

  $server->_emit_client_input(
    $client,
    {
      command => 'TOPIC',
      target  => $channel,
      text    => $params[1],
    },
  );
  return 1;
}

sub handle_list {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $target = @params ? $params[0] : undef;
  $server->_send_list_reply($client_id, $target);
  return 1;
}

1;
