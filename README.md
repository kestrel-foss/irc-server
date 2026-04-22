# Overnet IRC Server

This repo contains the Overnet-backed IRC server program and a small local demo client.

GitHub: <https://github.com/overnet-project/irc-server>

## Quick Start

Start the local demo server:

```bash
/home/_73/.local/bin/plx perl -Ilib -I../core-perl/lib -I../core-perl/local/lib/perl5 bin/overnet-irc-local-server.pl
```

That starts the real IRC server program under the Overnet runtime host and prints the port it bound to.

Then open two more terminals and connect two local accounts:

```bash
/home/_73/.local/bin/plx perl -Ilib -I../core-perl/local/lib/perl5 bin/overnet-irc-chat-client.pl --nick alice
/home/_73/.local/bin/plx perl -Ilib -I../core-perl/local/lib/perl5 bin/overnet-irc-chat-client.pl --nick bob
```

By default the client auto-joins `#overnet`. Plain text sends to the current target.

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

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [core-perl](https://github.com/overnet-project/core-perl)
- [relay-perl](https://github.com/overnet-project/relay-perl)
- [adapter-irc-perl](https://github.com/overnet-project/adapter-irc-perl)
