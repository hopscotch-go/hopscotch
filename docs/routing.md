# How hopscotch routing works

This tutorial traces a packet (and a named ping) from origin to destination, and names the algorithms at each step.

hopscotch has **several planes**. Mixing them up is the usual source of confusion:

| Plane | What moves | Where the next hop comes from |
|---|---|---|
| **Underlay** | QUIC over UDP/TCP | Configured `peers` + inbound dials; optionally **dial-on-demand** when overlay is stuck |
| **Discovery** | `FIND_NODE` RPCs | Kademlia XOR distance on NodeIDs |
| **Overlay** | IPv6 ULAs (TUN / ICMP / TCP) | Exact → XOR **progress** → (origin or `NoDialCloser`) greedy among live sessions |
| **Named echo** | `echo` control RPCs | Session-graph walk (fan-out, not XOR) |

Kademlia contacts are address hints. They do not carry traffic until a QUIC session exists.

**Default mode:** when progress has no next hop, overlay may **dial** a closer/exact contact (`ensureCloserSessions`) and open a new session.

**`NoDialCloser` mode** (cycle example): never dial from overlay. Sessions stay on the boot peer graph. If progress fails, `nextHop` falls back to greedy XOR among *existing* neighbors so packets can still walk a long spur.

```
                    ┌──────────────────────────────────────────────┐
   ping6 dst.hopscotch │  overlay IPv6 (QUIC DATAGRAM)               │
   ──────────────────►│  nextHop: exact → self-progress →           │
                      │  from-progress → origin/NoDialCloser greedy │
                      └──────────────────────────────────────────────┘
                                      │ rides
                                      ▼
                      ┌──────────────────────────────────────────────┐
   peers / inbound /  │  underlay QUIC sessions                      │
   dial-on-demand*    │  (the only edges that forward)               │
   ──────────────────►│  *skipped when NoDialCloser                  │
                      └──────────────────────────────────────────────┘
                                      ▲
                      ┌───────────────┴────────────────────────────────┐
   FIND_NODE          │  Kademlia table (contacts + addrs)             │
   ──────────────────►│  harvested when stuck; dial opens session*     │
                      └────────────────────────────────────────────────┘
```

---

## Identities and addresses

Each node has an ed25519 key. From that key:

```
NodeID = SHA-256(pubkey)          # 256-bit Kademlia ID
ULA    = fd00::/8 bits from ID    # overlay IPv6 (many-to-one vs full NodeID)
name   = URI SAN hopscotch:foo    # from the CA-signed cert
```

- **NodeID** is for discovery (`FIND_NODE`, k-buckets).
- **ULA** is for overlay packets (`ping6`, TCP through the TUN, traceroute probes).
- **name** is for humans and `hopscotch ping` / DNS (`foo.hopscotch`).

Anyone can recompute NodeID and ULA from the public key. There is no directory assigning addresses. You cannot invert a ULA back to a unique NodeID; dial-on-demand finds contacts whose **ULA** matches or is XOR-near the destination.

See [kademlia.md](../kademlia.md) for buckets and iterative lookup, and [public_key_routing_diagram.md](public_key_routing_diagram.md) for how this differs from SSH / Tailscale.

---

## Building the session graph (underlay)

A **session** is one QUIC connection to a neighbor, keyed by NodeID after TLS.

How sessions appear:

1. You list a hop under `peers:` and the node dials it, or
2. Someone dials you (inbound), or
3. Overlay gets stuck and **dial-on-demand** opens a session to a Kademlia contact (often the destination itself) — **unless** `NoDialCloser` is set.

By default every node binds an ephemeral listen address (`127.0.0.1:0` unless you set listens explicitly). Set `NoListen` only for a pure dial-only process that must never accept. Without a listen port, other nodes cannot dial you for an exact ULA match.

`NoDialCloser` is the switch for “pretend these nodes are on isolated machines and only configured peers can reach them.” Boot peers still dial each other; overlay never opens extra sessions from DHT contacts. That matters on shared loopback demos: without it, foo can learn mid2’s advertise addr and dial a shortcut that is not in the intended topology.

Example hub (`examples/hub/`):

```
foo ──► bar ◄── baz
```

- foo’s YAML peers bar; baz’s YAML peers bar.
- Live sessions start as `{foo—bar}` and `{baz—bar}`. foo may later dial baz directly if progress through bar is not enough.

Diamond (`examples/diamond/`) fans src across many parallel chains that meet at dst. Still: only edges with an open session forward.

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
3. Otherwise → pick a next hop and send.

**Hop Limit:** when the packet arrived from a peer (not from the local TUN), if Hop Limit ≤ 1, send ICMPv6 Time Exceeded; else decrement Hop Limit. That is a backstop. Loop *prevention* is XOR progress (below), not Hop Limit alone.

**Loop detector:** each forward updates a short-lived flow sighting (`internal/node/loop.go`). If the same flow is forwarded again on the same ingress→egress edge with a *lower* Hop Limit, the node logs `overlay loop` and increments `OverlayLoopCount()`. That should stay near zero when progress rules apply (default mode). With `NoDialCloser` greedy fallback, adversarial ULAs can still re-enter a ring; the detector + Hop Limit are the backstops.

### Step C — `nextHop` (priority order)

Among live sessions, skipping the ingress peer `from`:

| Priority | Rule | When | Why |
|---|---|---|---|
| 1 | **Exact** — peer ULA == destination | always | Deliver to the node that owns `D` |
| 2 | **Self-progress** — peer XOR-closer to `D` than **this node** | always | Distance-to-dest decreases → no multi-way cycles |
| 3 | **From-progress** — peer XOR-closer to `D` than the **ingress** peer | always | Spur hop can win vs where the packet came from |
| 4 | **Origin greedy** — closest neighbor by XOR | `from == nil` only | Spoke can enter via a hub that is not closer to `D` than the spoke |
| 5 | **Peer-only greedy** — closest neighbor by XOR | `NoDialCloser` and still stuck | Walk the existing session graph without dialing a DHT shortcut |

Distance is byte-wise XOR of the 16-byte IPv6 addresses (`identity.CloserULA`). Smaller XOR wins.

```go
// internal/node/packet.go — simplified
// exact → bestSelf → bestFrom → (if origin || NoDialCloser) bestAny → nil
```

What happens after `nextHop`:

| `nextHop` result | Default (`NoDialCloser=false`) | `NoDialCloser=true` |
|---|---|---|
| non-nil | forward | forward |
| nil | run dial-on-demand, retry `nextHop` once; still nil → `dest_unreach` | no dial; immediate `dest_unreach` (rare if any non-ingress neighbor exists — rule 5 usually fills it) |

#### Why rule 5 exists

Progress (rules 2–3) alone + peer-only sessions often **blackholes** on a ring junction. Example at buzz with sessions to bar, baz, and bizz, packet from bar toward blaz:

- Neither baz nor bizz may be XOR-closer to blaz than buzz (self-progress) or than bar (from-progress).
- Default mode would dial a closer DHT contact (maybe blaz or mid2) — that *works*, but adds sessions outside the boot topology.
- With `NoDialCloser`, dial is forbidden, so without rule 5 buzz would send `dest_unreach` forever.
- Rule 5 picks the XOR-closest remaining neighbor (often bizz toward the spur) so traceroute can continue along live peers only.

Rule 5 is **not** global shortest-path. It is local greedy on the current session list. On normal cycle keys that usually walks `…→buzz→bizz→mid*→blaz`. On adversarially keyed rings it can prefer the ring again; Hop Limit expires the probe and the loop detector may fire.

### Step C2 — dial-on-demand (`ensureCloserSessions`)

Only when `NoDialCloser` is false and `nextHop` returned nil (`internal/node/dial_closer.go`):

1. `FIND_NODE` harvest through live peers (hint derived from the destination ULA’s embedded NodeID bits).
2. Prefer table contacts whose ULA **equals** the destination (exact match after dial).
3. Also consider contacts XOR-closer than self, then nearest-by-ULA contacts.
4. Dial (short wait; longer wait for an exact ULA match), then retry `nextHop`.

Background `lookup` + dial continues so later packets may succeed even if this one got `dest_unreach`.

On a shared underlay (everyone on `127.0.0.1`), this is how **foo→mid2** appeared: FIND_NODE returned mid2’s advertise port, dial succeeded, and greedy/progress then preferred that new session. `NoDialCloser` disables that path.
### Hub walk

On foo with only a session to bar (origin):

- Destination = baz’s ULA → rule 4 sends to bar (only neighbor).

On bar with sessions to foo and baz:

- Exact match to baz → send to baz.

On baz:

- Destination is local → ICMP echo reply; reply uses the same `nextHop` rules toward foo.

### Step D — wire format

Overlay IPv6 rides the same QUIC connection as control RPCs, on **DATAGRAM** frames when it fits; otherwise a unidirectional stream. Control messages (`echo`, `FIND_NODE`) stay on the control stream. The data plane does not use those RPC types.

### End-to-end picture (hub)

```
host ping6 baz.hopscotch
        │
        ▼
   foo TUN ──quic datagram──► bar ──quic datagram──► baz TUN / in-process ICMP
        ▲                                              │
        └────────────── echo reply path ───────────────┘
```

Path length in hops = number of QUIC sessions crossed. Hop Limit in the IPv6 header drops by one at each *forwarding* node (not at the origin TUN inject).

### What XOR does on a diamond

At **src**, with sessions to eight path heads and destination = dst’s ULA:

- No exact session to dst.
- Self-progress keeps only heads closer to dst than src, then picks the closest.
- That is local greedy **with progress**, not a global shortest path.

Later hops along a chain usually have two neighbors (prev and next). Progress often forces the forward direction; if neither improves: dial-closer (default), peer-only greedy (`NoDialCloser`), or `dest_unreach`.

Named echo (below) may take a *different* path because it fans out.

---

## Trace 2: named ping (`hopscotch ping … baz`)

```bash
./hopscotch ping --config examples/hub/foo.yaml baz
```

This talks to foo’s **control socket**, then uses the `echo` RPC on the QUIC control stream. It does **not** use the TUN or overlay `nextHop`.

### Algorithm

1. Origin creates `echo{name=baz, ttl=128, origin=self, rpc=…}` and calls `dispatchEcho`.
2. `dispatchEcho`:
   - If a live session’s peer **has that name** → send only there.
   - Else → send a copy to **every** session except the one the message came from (fan-out).
3. Intermediate node:
   - If this node has the name → reply `echo_ok` with accumulated `path`.
   - Else decrement TTL, append own name to `path`, remember who to reply through, `dispatchEcho` again.
4. Duplicate `(origin, rpc)` is ignored (stops some loops).
5. TTL exhausted → `echo_err`.

So named echo is a **bounded flood of the session graph**, not greedy XOR. It can succeed even when overlay traceroute shows `dest_unreach` or (historically) a cycle.

Hub walk:

```
foo ──echo──► bar ──echo──► baz
foo ◄─echo_ok─ bar ◄─echo_ok─ baz
         path = [bar, baz]
```

---

## Trace 3: overlay traceroute (`hopscotch traceroute …`)

```bash
./hopscotch traceroute --config examples/.local/cycle/foo.yaml blaz
```

Same control socket as ping, but probes **overlay IPv6** (ICMPv6 echoes with Hop Limit 1…N). Same forwarding rules as `ping6`.

### How to read the output

Each line is a **new probe**, not one packet continuing:

| Reply | Meaning |
|---|---|
| `time_exceeded` | This TTL expired at that node — normal way to discover an intermediate hop |
| `echo_reply` | Destination answered — path complete |
| `dest_unreach` | That node had no next hop after rules (and dial, if allowed, did not help) — stuck, not a cycle |
| `*` | No ICMP came back within the probe timeout |

Example success on the cycle spur (`NoDialCloser`):

```
 1  bar   time_exceeded
 2  buzz  time_exceeded     # bar may skip baz when it has a direct buzz session
 3  bizz  time_exceeded
 4  mid1  time_exceeded
 5  mid2  time_exceeded
 6  mid3  time_exceeded
 7  blaz  echo_reply
reached blaz
```

If you instead see `dest_unreach` repeating from **buzz**, the running nodes are likely an older build without peer-only greedy (rule 5), or progress failed and dial was disabled with no usable neighbor. Restart the cycle example after rebuilding.

Repeated `time_exceeded` from the same ring names under rising TTL suggests a forward cycle. Check `OverlayLoopCount` / `overlay loop` logs.

---

## Cycle example (ring + spur)

`examples/cycle/` builds:

```
foo → bar → baz → buzz → bar     (ring)
                   ↓
                 bizz → mid1 → mid2 → mid3 → blaz   (spur)
```

Every node sets `NoDialCloser: true`. Intended session degrees stay on the boot edges (foo=1, bar=3, buzz=3, …, blaz=1). Overlay must not invent foo→mid2.

### How overlay behaves here

1. **Progress first** (rules 2–3) — same as production meshes. Blocks the old naive cycle where buzz always preferred bar under bad ULAs *when a progress hop exists*.
2. **No dial-on-demand** — FIND_NODE may still fill the Kademlia table, but stuck overlay never dials those contacts.
3. **Peer-only greedy** (rule 5) — when progress has no candidate, pick the XOR-closest live neighbor other than ingress. That is what lets buzz hand off to bizz / mid* without opening a shortcut session.

Typical traceroute path (session hops, not named-echo flood):

```
foo → bar → buzz → bizz → mid1 → mid2 → mid3 → blaz
```

(`baz` may be skipped if bar already has a session to buzz on the ring.)

Named echo still fans out and can report a different `path=…`; that is expected.

### What went wrong historically

| Behavior | Cause |
|---|---|
| traceroute jumps to mid2 / blaz early; `foo` peer count grows | Dial-on-demand opened DHT sessions across loopback |
| traceroute stuck at buzz with `dest_unreach` | `NoDialCloser` + progress-only (no rule 5 yet) |
| ring `time_exceeded` repeats under `-force-loop` | Adversarial ULAs + greedy; use Hop Limit / loop detector |

- Launch **cycle** or `go run ./examples/cycle`.
- `-force-loop` regenerates certs until ULAs match the *old* risky XOR preferences — regression tooling, not a guarantee of a live loop with current rules.
- Compare `hopscotch traceroute` (overlay) vs `hopscotch ping` (flood).
---

## Discovery vs forwarding

When a node joins it dials `peers`, then often runs `FIND_NODE(self)` so its Kademlia table fills with XOR-near contacts.

| | Kademlia contact | QUIC session |
|---|---|---|
| Created by | `FIND_NODE` replies, hello advertise | dial / accept / dial-on-demand |
| Used for overlay / echo? | Address hint (and dial target when stuck) | **Yes** |
| Shown in status as | `contact` / table size | `connected` |

Status lines like `table=40 connected=8` mean: forty IDs known in the DHT table, eight live QUIC sessions. Overlay and named echo only move on the eight. With dial-on-demand enabled, a ninth can appear when overlay is stuck; with `NoDialCloser`, `connected` stays on boot/inbound peers only.

---

## Failure modes worth knowing

| Symptom | Likely cause |
|---|---|
| DNS works, `ping6` blackholes | No session path; hop limit; middle node `dest_unreach`; dial-closer failed |
| `hopscotch ping` fails, overlay works | Echo TTL / fan-out / control socket |
| `hopscotch ping` works, `ping6` / traceroute fails | Overlay progress/dial/greedy path differs from flood |
| traceroute `time_exceeded` then `echo_reply` | **Normal** — intermediates vs destination |
| traceroute repeating `time_exceeded` names | Possible forward cycle (investigate `OverlayLoopCount`) |
| traceroute `dest_unreach` / note “stuck at …” | No usable neighbor after rules; or dial disabled/failed |
| Unexpected shortcut hop (e.g. foo→mid2) | Dial-on-demand; set `NoDialCloser` for peer-only demos |
| `overlay loop` logs / `OverlayLoopCount()>0` | Same edge re-used with decreasing Hop Limit |
| `duplicate` then stuck | Peer restarted; newer builds replace the old session |
| `table>0` but `connected=0` | DHT knows addrs but nothing dialed them yet |

---

## Try it

Hub (three processes):

```bash
# launch "foo → bar ← baz (tun)" or run the three configs
./hopscotch ping --config examples/hub/foo.yaml baz
ping6 baz.hopscotch   # with foo --tun
```

Long chain / diamond / cycle:

```bash
go run ./examples/chain
./hopscotch ping --config examples/.local/chain/head.yaml n99

go run ./examples/diamond
./hopscotch ping --config examples/.local/diamond/src.yaml dst

rm -rf examples/.local/cycle   # optional: fresh keys
go run ./examples/cycle
./hopscotch traceroute --config examples/.local/cycle/foo.yaml blaz
./hopscotch ping --config examples/.local/cycle/foo.yaml blaz

# pathological XOR keying only (should still not circulate):
go run ./examples/cycle -force-loop
```

Compare diamond’s logged `xor_prefer_head=…` (overlay choice at src) with the echo `path=…` (whichever flood branch answered first).

---

## Code map

| Concern | Location |
|---|---|
| Overlay forward + hop limit + unreachable | `internal/node/packet.go` (`handleIPv6`, `nextHop`) |
| Dial closer / exact on local minimum | `internal/node/dial_closer.go` |
| Overlay loop detection | `internal/node/loop.go` |
| Overlay traceroute | `internal/node/traceroute.go`, `hopscotch traceroute` |
| ULA XOR compare | `internal/identity/identity.go` (`CloserULA`) |
| Named echo flood | `internal/node/echo.go` |
| Default listen / `NoListen` / `NoDialCloser` | `internal/node/node.go` (`New`), cycle example |
| Kademlia table / FIND_NODE | `internal/kademlia/`, `internal/node/node.go` (`lookup`, `queryFindNode`) |
| Session establish | `internal/node/node.go` (`dial`, `establish`) |

For the DHT details (buckets, α-parallel iterative lookup), read [kademlia.md](../kademlia.md) next.
