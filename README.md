# Overnet IRC Server

This repo contains the Overnet-backed IRC server program and a small local demo client.

GitHub: <https://github.com/overnet-project/irc-server>

## Quick Start

Start the local demo server:

```bash
perl bin/overnet-irc-local-server.pl
```

That starts the real IRC server program under the Overnet runtime host and prints the port it bound to.

Then open two more terminals and connect two local accounts:

```bash
perl bin/overnet-irc-chat-client.pl --nick alice
perl bin/overnet-irc-chat-client.pl --nick bob
```

By default the client auto-joins `#overnet`. Plain text sends to the current target.

## Authenticated IRC

For authoritative IRC networks, start the local auth-agent daemon first:

```bash
overnet-auth-agent.pl --config-file ~/.config/overnet/auth-agent.json
```

Then point the helper at the auth socket either with `OVERNET_AUTH_SOCK`:

```bash
export OVERNET_AUTH_SOCK=/tmp/overnet-auth.sock
```

or explicitly with `--auth-sock`:

```bash
overnet-irc-auth.pl auth --auth-sock /tmp/overnet-auth.sock --scope irc://irc.example.test/overnet --challenge <challenge>
```

The normal manual flow is:

```bash
overnet-irc-auth.pl auth --scope irc://irc.example.test/overnet --challenge <challenge>
overnet-irc-auth.pl delegate --scope irc://irc.example.test/overnet --relay-url ws://127.0.0.1:7448 --delegate-pubkey <delegate_pubkey> --session-id <session_id> --expires-at <expires_at>
```

If you already have the full IRC notice line, bridge mode can translate it directly:

```bash
overnet-irc-auth.pl bridge --scope irc://irc.example.test/overnet --line '-server- OVERNETAUTH CHALLENGE <challenge>'
```

For client or ZNC scripting, bridge mode also works as a continuous stdin/stdout filter. It reads IRC lines from stdin, ignores non-`OVERNETAUTH` lines, and emits one `/quote OVERNETAUTH ...` command on stdout for each matching auth line:

```bash
some-irc-line-source | overnet-irc-auth.pl bridge --scope irc://irc.example.test/overnet
```

## Client Commands

```text
/help
/join #channel
/target <target>
/msg <target> <text>
/notice <target> <text>
/topic <channel> <text>
/names [channel]
/part [channel] [reason]
/nick <newnick>
/raw <line>
/quit [reason]
```

## Notes

- The demo server defaults to `127.0.0.1:16667`.
- It auto-creates a Nostr signing key under the local state directory unless you pass `--signing-key-file`.
- The local demo client is intentionally small. It is a convenience terminal client for exercising the Overnet IRC server, not a full IRC client.
- `overnet-irc-auth.pl` uses the local auth agent. It does not read raw private keys directly.

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [core-perl](https://github.com/overnet-project/core-perl)
- [relay-perl](https://github.com/overnet-project/relay-perl)
- [adapter-irc-perl](https://github.com/overnet-project/adapter-irc-perl)
