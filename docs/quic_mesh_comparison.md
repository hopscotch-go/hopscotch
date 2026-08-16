# QUIC vs the mesh

QUIC is a transport: TLS 1.3, stream mux, connection IDs (path can change), UDP. It moves bytes between two sockets.

It does not:

- discover nodes
- decide who may talk
- route a packet through a third node

hopscotch splits it this way:

| Layer | Mechanism |
|---|---|
| Identity | ed25519 key; NodeID = SHA-256(pubkey); same key in the QUIC cert |
| Membership | Configured `peers` + inbound dials (mesh CA on the handshake) |
| Transport | QUIC on a reachable underlay `ip:port` |
| Overlay routing | Hop-count distance-vector over live sessions; named ping floods |

WireGuard is encryption + cryptokey routing (AllowedIPs → peer key). You still need a way to learn keys and endpoints. Tailscale’s coordination server is one way. hopscotch uses explicit peers plus route ads on the session graph.

ULA (`fd00::/8`) can be the *overlay* address derived from NodeID. The QUIC handshake still needs a routable underlay endpoint, or a relay.
