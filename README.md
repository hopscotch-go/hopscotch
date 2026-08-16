# hopscotch

A private mesh of CA-named nodes. Dial one member; hop to the others by name.

Node identity is an ed25519 key; NodeID is SHA-256 of the public key. Overlay IPv6 is derived from that ID. With `tun: true` (or `--tun`), a kernel TUN carries packets for those addresses across the session graph.

Membership is a mesh CA. Every node presents a CA-signed certificate on the QUIC handshake; self-signed peers are rejected.

A node joins by dialing hops listed as `peers` in its config (or `--peers`). Overlay paths are learned by hop-count distance-vector ads over those sessions. There is no DHT.

```bash
go build -o hopscotch .

./hopscotch --config examples/hub/foo.yaml
```

Flags still work if you do not want a file:

```bash
./hopscotch ca init --key ca.key --cert ca.crt
./hopscotch ca sign --ca-key ca.key --ca-cert ca.crt --identity a.pem --out a.crt --name foo
./hopscotch ca sign --ca-key ca.key --ca-cert ca.crt --identity b.pem --out b.crt --name bar --name laptop

./hopscotch --ca ca.crt --cert a.crt --identity a.pem --listen udp:127.0.0.1:4433 --listen tcp:127.0.0.1:4433
./hopscotch --ca ca.crt --cert b.crt --identity b.pem --listen 127.0.0.1:4434 --peers peers.txt
```

YAML (paths are relative to the file):

```yaml
identity: ../.local/foo.pem
ca: ../.local/ca.crt
cert: ../.local/foo.crt
control: ../.local/foo.sock
peers:
  - udp:127.0.0.1:4434
  # or pin the TLS key:
  # - addr: udp:127.0.0.1:4434
  #   pubkey: <64 hex chars of the ed25519 public key>
```

Startup logs `pubkey` (64 hex chars — that is what belongs in `peers[].pubkey`) and `identity` (NodeID, SHA-256 of that key).

`--name` is written into the cert as a URI SAN (`hopscotch:foo`). Repeat it for aliases on the same key. After TLS, every node that trusts `ca.crt` sees the same names. Do not issue the same name on two different keys. Keep `ca.key` offline; nodes only need `ca.crt`.

See [docs/routing.md](docs/routing.md) for overlay packets and named ping hop-by-hop. [docs/](docs/) also has short notes on public keys vs overlay IPs and what QUIC does not do.

## Three-node hub

`examples/hub/` is **foo → bar ← baz**. bar listens on `127.0.0.1:4434`; foo and baz dial bar (neither listens). QUIC sessions stay on those edges; routes propagate so foo can reach baz’s ULA via bar. `.vscode/launch.json` starts bar, baz, and foo. On a second machine, point baz’s `peers` at bar’s reachable address and run with `--tun` (gateway defaults true there).

```bash
./hopscotch ca bootstrap --dir examples/.local --node foo --node bar --node baz
./hopscotch --config examples/hub/bar.yaml
./hopscotch --config examples/hub/baz.yaml
./hopscotch --config examples/hub/foo.yaml
```

With that running, ping baz from foo (the command talks to foo’s control socket, and foo forwards through bar):

```bash
./hopscotch ping --config examples/hub/foo.yaml baz
```

## 100-node chain

`examples/chain/` runs **n00 ← n01 ← … ← n99** in one process (each node dials the previous). Launch **chain-100** from `.vscode/launch.json`, or:

```bash
go run ./examples/chain
./hopscotch ping --config examples/.local/chain/head.yaml n99
```

## Diamond

`examples/diamond/` is a multi-path DAG: **src** fans out across `-width` parallel chains of `-depth` nodes each, which meet at **dst**. Default is `6×8 + src/dst = 50` nodes.

**Real processes** (one `hopscotch` OS process per node): launch **Diamond: 50 mesh**, or:

```bash
go build -o hopscotch .
go run ./examples/diamond/mesh
./hopscotch traceroute --config examples/.local/diamond/src.yaml dst
./hopscotch ping --config examples/.local/diamond/src.yaml dst
```

Logs are prefixed with the node name in one terminal. **Diamond: 50 in-process** is the same topology in a single process (faster bring-up).


## Cycle (ring + spur)

`examples/cycle/` is a session ring with a long side branch:

```
foo → bar → baz → buzz → bar
                   ↓
                 bizz → mid1 → mid2 → mid3 → blaz
```

**Separate processes** (one terminal per node — preferred for reading logs): launch **Cycle: mesh** in `.vscode/launch.json`. Then:

```bash
./hopscotch traceroute --config examples/cycle/foo.yaml blaz
./hopscotch ping --config examples/cycle/foo.yaml blaz
```

**In-process** (single process): launch **Cycle: in-process**, or `go run ./examples/cycle`.


## Overlay TUN

Each NodeID maps to a ULA (`fd00::/8`). `--tun` (or `tun: true` in YAML) creates a TUN and assigns it. Overlay packets ride QUIC datagrams when they fit, otherwise a unidirectional stream. Next hop comes from a **hop-count distance-vector** table over live sessions (advertised on the control stream). No route → Destination Unreachable. Hop limit remains a backstop. TCP SYNs have MSS clamped to the overlay.

### Userspace stack (no root)

`--userspace` (or `userspace: true`) attaches a gVisor IPv6 stack bound to the node ULA. Outbound packets enter the same overlay forward path as TUN traffic. Use `Node.DialTCP` / `ListenTCP` for in-process TCP over the mesh without a kernel NIC or root.

```bash
./hopscotch --config examples/hub/foo.yaml --userspace
```

TUN and userspace can run together: the host uses the TUN; in-process dials use the stack.

One hopscotch per machine is the host overlay NIC (`gateway` defaults true): it installs an unscoped `fd00::/8` route and overlay DNS so ordinary programs resolve `name.hopscotch` and send through the TUN.

```bash
ping6 baz.hopscotch
```

Names are answered in-process (not forwarded): AAAA, and NODATA for A. On macOS the stub is `127.0.0.1` on an ephemeral UDP port plus `/etc/resolver/hopscotch` (the `port` is written into the file). That file is only for the `hopscotch` zone; it does not install a global search domain, so other VPN short names (Tailscale MagicDNS) keep working. On Linux it is `fd00::53` via systemd-resolved on the TUN, with search domain `hopscotch`. `ca bootstrap` writes `examples/.local/hosts` as a seed of name → ULA. `--tun` needs root:

```bash
sudo ./hopscotch --config examples/hub/foo.yaml --tun
```

The TUN debugger config runs `dlv` via `sudo` (`asRoot`). To approve that with Touch ID in the integrated terminal, [enable Touch ID for sudo](https://derflounder.wordpress.com/2017/11/17/enabling-touch-id-authorization-for-sudo-on-macos-high-sierra/).

foo is the host overlay NIC (`--tun`, gateway default true). Extra hopscotch processes on the same machine stay `gateway: false` so their ULAs are not local. They answer ICMP echo in-process. A second machine running baz with `--tun` owns `fd00::/8` there; `ping6 foo` and `ping6 bar` enter that TUN.

`hopscotch ping` is the named control-plane echo and does not use the TUN.

Generated keys, certs, sockets, and the hosts file live in `examples/.local/` (gitignored).
