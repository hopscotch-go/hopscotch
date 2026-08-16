# Kademlia discovery

hopscotch locates nodes with Kademlia, not a coordination server and not peer-exchange gossip.

## Identity

Each node has an ed25519 key pair. The TLS certificate on the QUIC handshake is that key, so the transport already proves who you are.

```
NodeID = SHA-256(public key)     # 256-bit Kademlia ID
ULA    = fd + NodeID bits        # overlay IPv6; routed when TUN is up
```

Anyone can recompute NodeID from the public key. That is the opposite of Tailscale, where `100.x` / `fd7a:115c:a1e0::` are assigned by a directory.

## Trust

Three independent questions:

- **Who is this?** the leaf ed25519 public key (`NodeID = SHA-256(pubkey)`).
- **What is it called?** optional mesh names in the CA-signed cert (`hopscotch ca sign --name foo`). Multiple `--name`s are aliases for the same key (SAN list). The same name on two keys is a CA mistake; do not do that. Names are read from the verified leaf, never from `hello`.
- **May they join?** only if the peer cert chains to the mesh CA (`--ca`). Self-signed keys are rejected.

Sign a node key once (`hopscotch ca sign`). Distribute `ca.crt` to every node. Keep `ca.key` off the mesh members if you can: anyone with it can mint new members and names.

## Distance

```
distance(a, b) = a XOR b
```

Closer means a smaller XOR. The routing table is 256 k-buckets (k = 20). Bucket *i* holds contacts whose XOR with us has its first 1-bit at position *i*.

A contact is `(NodeID, endpoints)`. An endpoint is `udp:host:port` or `tcp:host:port`. The address is underlay (how to dial). The ID is identity (who it is).

## Underlay

QUIC runs on one `net.PacketConn` mux. A node may listen on several backends at once; each accepted hop is attached to that mux.

| Backend | Hop | Datagrams |
|---|---|---|
| `udp` (default) | one UDP socket per listen address; sessions keyed by `udp:host:port` | one packet = one datagram |
| `tcp` | one TCP connection per neighbor | 32-bit big-endian length, then payload (max 1 MiB) |

`--listen` is repeatable (`--listen udp:… --listen tcp:…`), or a list under `listen` in YAML. Dial picks a dialer from the endpoint prefix in `peers` or FIND_NODE. You can listen on UDP only and still dial a TCP peer.

## RPCs

Over the QUIC control stream:

| Message | Role |
|---|---|
| `hello` | once per connection: optional advertise of dialable endpoints (`udp:host:port`, `tcp:host:port`). Dial-only nodes send none. |
| `ping` / `pong` | liveness on one QUIC session |
| `echo` / `echo_ok` | named ping; forwarded across existing sessions |
| `find_node(target)` | return up to k contacts closest to `target` |
| `find_nodes` | the reply |

No full-list dump. A peer only ever hands you nodes that are XOR-close to the ID you asked about.

A second channel on the same QUIC connection carries overlay IPv6 as DATAGRAM frames. That is the TUN data plane. It does not use these RPC types.

## Iterative lookup

To find `T` (including `T = self` at join):

1. From the local table, take the k closest IDs to `T`.
2. Query α = 3 of those that have not been queried, in parallel.
3. Insert every returned contact into the table.
4. Repeat until a round yields nobody closer.

Cost is O(log n) hops. After lookup(self), the table holds neighbors in ID space. QUIC sessions are only the configured `peers` plus inbound connections; learned contacts are not auto-dialed. Named `echo` walks that session graph (so foo can ping baz through bar).

## Bootstrap contacts

Kademlia still needs a reachable underlay address to enter the graph. That is `peers` in the node YAML (or `--peers`), a list of hops, not a registry. After FIND_NODE(self), those nodes are just contacts.

```yaml
peers:
  - 127.0.0.1:4433
  - tcp:192.168.1.10:4433
  - addr: udp:192.168.1.10:4433
    pubkey: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

`pubkey` is optional; when present it pins the TLS key for that address (64 hex chars of the ed25519 public key, not NodeID).

ULA-only hosts cannot be dialed from the public Internet. They can join if they can *originate* QUIC to a reachable contact; others will not be able to call back unless some node has a global address or a relay exists. Relays are not implemented.

## What this is not

- Not PEX/gossip (nobody sends “here is everyone I know”).
- Not Tailscale’s netmap (no central list of overlay IPs).
- Not a general internet VPN. Overlay TUN carries IPv6 ULAs over existing QUIC sessions (exact neighbor ULA, else greedy XOR). Named ping (`echo`) is a separate flood of the session graph.
