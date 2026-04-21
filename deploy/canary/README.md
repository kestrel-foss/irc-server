# Overnet Canary IRC Topology

This canary deployment expects two relays and one IRC server.

- `relay-a` and `relay-b` each run an authoritative IRC relay with persisted stores.
- the IRC server points at the primary authority relay URL and relies on relay sync for catch-up.
- TLS cert and key paths live in the IRC env example so the single IRC server can terminate TLS directly.

Each service writes a health file. Use those health files for local smoke checks before admitting real canary users.
