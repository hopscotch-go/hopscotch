# How hopscotch routing works

This tutorial traces a packet (and a named ping) from origin to destination.

hopscotch has **several planes**. Mixing them up is the usual source of confusion:

| Plane | What moves | Where the next hop comes from |
|---|---|---|
| **Underlay** | QUIC over UDP/TCP | Configured `peers` + inbound dials |
| **Overlay** | IPv6 ULAs (TUN / ICMP / TCP) | **Distance-vector RIB** (hop count over live sessions) |
| **Named echo** | `echo` control RPCs | Session-graph flood (not the RIB) |

There is no DHT. You join by dialing YAML `peers`; routes propagate over those sessions.

```
                    ┌──────────────────────────────────────────────┐
   ping6 dst.hopscotch │  overlay IPv6 (QUIC DATAGRAM)               │
   ──────────────────►│  nextHop = RIB[dst] → session                │
                      └──────────────────────────────────────────────┘
                                      │ rides
                                      ▼
                      ┌──────────────────────────────────────────────┐
   peers / inbound    │  underlay QUIC sessions                      │
   ──────────────────►│  (the only edges that forward)               │
                      └──────────────────────────────────────────────┘
                                      ▲
                      ┌───────────────┴────────────────────────────────┐
   Type:"routes"      │  distance-vector ads (ULA + hop metric)        │
   on control stream  │  split horizon; refresh on change + timer      │
                      └────────────────────────────────────────────────┘
```

---

## Identities and addresses

Each node has an ed25519 key. From that key:

```
NodeID = SHA-256(pubkey)          # session / cert identity
ULA    = fd00::/8 bits from ID    # overlay IPv6
name   = URI SAN hopscotch:foo    # from the CA-signed cert
```

- **NodeID** keys live QUIC sessions after TLS.
- **ULA** is for overlay packets and RIB destinations.
- **name** is for humans and `hopscotch ping` / DNS (`foo.hopscotch`).

### Exit nodes

An `exit: true` node advertises DV destinations `::/0` and `0.0.0.0/0` and SNATs internet traffic. Clients set `exit_node: <name>` to use that exit. Host `/1`+`/1` defaults are installed **only after** the client has learned a DV default and can next-hop the exit ULA (so a half-up mesh does not blackhole Wi‑Fi). They are torn down if that path is lost. Non-loopback underlay peer IPs are pinned via the physical Wi‑Fi/Ethernet gateway (not utun) — including on dial by hub nodes sharing the host — so QUIC to remote exits is not captured by `/1` (`127.0.0.1` stays on lo0). Internet packets are **encapsulated** in an outer mesh IPv6 header (dst = exit ULA, next-header 4 or 41) so relays stay pure ULA forwarders. There are no mesh IPv4 identities — only plumbing CGNAT addresses on the TUN for kernel sourcing. If the process is killed without `Close`, remove leftovers with `sudo route delete -inet 0.0.0.0/1` (and `128.0.0.0/1`, `::/1`, `8000::/1`).

See [public_key_routing_diagram.md](public_key_routing_diagram.md) for how this differs from SSH / Tailscale.

---

## Building the session graph (underlay)

A **session** is one QUIC connection to a neighbor, keyed by NodeID after TLS.

How sessions appear:

1. You list a hop under `peers:` and the node dials it, or
2. Someone dials you (inbound).

By default every node binds an ephemeral listen address (`127.0.0.1:0` unless you set listens explicitly). Set `NoListen` only for a pure dial-only process that must never accept.

Example hub (`examples/hub/`):

```
foo ──► bar ◄── baz
```

Live sessions start as `{foo—bar}` and `{baz—bar}`. Overlay routes then propagate so foo learns `baz ULA → via bar (metric 2)`.

Diamond (`examples/diamond/`) fans src across many parallel chains that meet at dst. Only edges with an open session forward; DV picks a shortest hop-count path.

---

## Distance-vector overlay (`internal/node/route.go`)

Simple hop-count DV over live sessions — enough for closed CA meshes without inventing extra peer edges.

### What each node stores

| Field | Meaning |
|---|---|
| RIB key | destination **ULA** string |
| `next` | neighbor **NodeID** (session to use) |
| `metric` | hop count (`0` = self, `1` = direct peer, …); `≥16` = infinity |

### When routes update

| Event | Action |
|---|---|
| Session up | Install peer’s ULA at metric 1; exchange full tables |
| `Type:"routes"` from peer | Bellman–Ford update (`metric_peer + 1`); keep direct peer at 1 |
| Session down | Delete every RIB entry whose `next` was that peer; re-advertise |
| Timer (~15s) | Re-advertise full table (healing) |

**Split horizon:** do not advertise to neighbor N any destination learned *via* N.

**Implicit withdraw:** if a peer’s update omits a dest previously learned from them (other than their own ULA), drop that entry.

### `nextHop`

```
RIB[dst] → session(next)   // if next ≠ ingress
else exact ULA session match among neighbors  // convergence race
else nil → ICMPv6 Destination Unreachable
```

Never forward back to the ingress session.

---

## Trace 1: overlay packet (`ping6 dst.hopscotch`)

Assume foo has `--tun` (gateway), bar and baz are mesh members, and DNS already resolved `baz.hopscotch` to baz’s ULA.

### Step A — leave the host

1. Kernel sends an IPv6 ICMP echo toward baz’s ULA into foo’s TUN (`fd00::/8` route).
2. foo’s `tunLoop` reads the packet and calls `handlePacket` / `handleIPv6`.

### Step B — local delivery vs forward

On each node, for destination ULA `D`:

1. If `D` is the DNS resolver ULA → answer DNS in-process (not forwarded).
2. If `D` equals **this** node’s ULA → deliver to the local TUN, or answer ICMP echo in-process when `gateway: false`.
3. Otherwise → `nextHop` from the RIB and send.

**Hop Limit:** when the packet arrived from a peer, if Hop Limit ≤ 1, send ICMPv6 Time Exceeded; else decrement. Backstop only — DV + split horizon is the loop prevention.

### Hub walk

On foo (RIB: baz → via bar, metric 2) → bar → baz (local).

### Wire format

Overlay IPv6 rides QUIC **DATAGRAM** frames when it fits; otherwise a unidirectional stream. Control messages (`echo`, `routes`) stay on the control stream.

---

## Trace 2: named ping (`hopscotch ping … baz`)

Uses the `echo` RPC on the QUIC control stream — a **bounded flood** of the session graph, not the RIB. Path may differ from traceroute.

---

## Trace 3: overlay traceroute (`hopscotch traceroute …`)

Probes overlay IPv6 with rising Hop Limit. Same forwarding as `ping6` (RIB).

| Reply | Meaning |
|---|---|
| `time_exceeded` | TTL expired at that hop |
| `echo_reply` | Destination answered |
| `dest_unreach` | No RIB entry (not converged / partition) |
| `*` | Probe timeout |

---

## Cycle example (ring + spur)

```
foo → bar → baz → buzz → bar
                   ↓
                 bizz → mid1 → mid2 → mid3 → blaz
```

Boot peers only. After DV converges, foo’s metric to blaz is the spur length. Prefer the **cycle mesh** compound (separate processes) to read per-node logs.

---

## Sessions vs routes

| | QUIC session | RIB entry |
|---|---|---|
| Created by | dial / accept | `routes` ads + session up |
| Used for overlay? | Transport edge | **Yes** (`nextHop`) |
| Shown in status as | `connected=` | `routes=` |

Status like `connected=8 routes=12` means eight live sessions and twelve known overlay destinations.

---

## Failure modes

| Symptom | Likely cause |
|---|---|
| DNS works, `ping6` blackholes | No RIB entry; hop limit; partition |
| `hopscotch ping` works, traceroute fails | Flood vs RIB; routes not converged yet |
| traceroute `dest_unreach` | No route at that hop |
| Time Exceeded on a short path | Hop Limit too low, or stale RIB before withdraw |

---

## Try it

```bash
./hopscotch ping --config examples/hub/foo.yaml baz

go run ./examples/diamond/mesh
./hopscotch traceroute --config examples/.local/diamond/src.yaml dst

go run ./examples/cycle
./hopscotch traceroute --config examples/cycle/foo.yaml blaz
```

---

## Code map

| Concern | Location |
|---|---|
| Overlay forward + hop limit + unreachable | `internal/node/packet.go` |
| Distance-vector RIB + `routes` ads | `internal/node/route.go` |
| Overlay traceroute | `internal/node/traceroute.go` |
| Named echo flood | `internal/node/echo.go` |
| Session establish / control dispatch | `internal/node/node.go` |
| Route wire type | `internal/proto/proto.go` |
