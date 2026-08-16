# hopscotch

A private mesh of CA-named nodes. Dial one member; hop to the others by name.

Node identity is an ed25519 key; NodeID is SHA-256 of the public key. Overlay IPv6 is derived from that ID. With `tun: true` (or `--tun`), a kernel TUN carries packets for those addresses across the session graph.

Membership is a mesh CA. Every node presents a CA-signed certificate on the QUIC handshake; self-signed peers are rejected.

A node joins by dialing hops listed as `peers` in its config (or `--peers`). After that, FIND_NODE walks the XOR metric. There is no peer-list gossip.

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

See [kademlia.md](kademlia.md) for the lookup. [docs/](docs/) has short notes on public keys vs overlay IPs and what QUIC does not do.

## Three-node line

`examples/hub/` is **foo → bar → baz**. bar listens on `127.0.0.1:4434`; foo dials bar; bar dials baz on `127.0.0.1:4435`. QUIC sessions stay on those edges (learned FIND_NODE contacts are not auto-dialed). `.vscode/launch.json` starts bar and foo. Run baz in another terminal (or on a second machine: listen `udp:0.0.0.0:4434` and point bar’s `peers` at it).

```bash
./hopscotch ca bootstrap --dir examples/.local --node foo --node bar --node baz
./hopscotch --config examples/hub/baz.yaml
./hopscotch --config examples/hub/bar.yaml
./hopscotch --config examples/hub/foo.yaml
```

With that running, ping baz from foo (the command talks to foo’s control socket, and foo forwards through bar):

```bash
./hopscotch ping --config examples/hub/foo.yaml baz
```

## Overlay TUN

Each NodeID maps to a ULA (`fd00::/8`). `--tun` (or `tun: true` in YAML) creates a TUN and assigns it. Overlay packets ride QUIC datagrams when they fit, otherwise a unidirectional stream. Next hop is the session whose peer ULA equals the destination, otherwise the remaining neighbor with the closest ULA (XOR). One next hop, not a flood. Hop limit stops loops; expired packets get ICMPv6 Time Exceeded. TCP SYNs have MSS clamped to the overlay.

One hopscotch per machine is the host overlay NIC (`gateway` defaults true): it installs an unscoped `fd00::/8` route and overlay DNS so ordinary programs resolve shortnames and send through the TUN.

```bash
ping6 baz
# or: ping baz.hopscotch
```

Names are answered in-process (not forwarded): AAAA, and NODATA for A. On macOS the stub is `127.0.0.1` on an ephemeral UDP port plus `/etc/resolver` (`port` is written into the file). On Linux it is `fd00::53` via systemd-resolved on the TUN. The search domain is `hopscotch`, so `ping6 baz` becomes `baz.hopscotch`. `ca bootstrap` writes `examples/.local/hosts` as a seed of name → ULA. `--tun` needs root:

```bash
sudo ./hopscotch --config examples/hub/foo.yaml --tun
```

The TUN debugger config runs `dlv` via `sudo` (`asRoot`). To approve that with Touch ID in the integrated terminal, [enable Touch ID for sudo](https://derflounder.wordpress.com/2017/11/17/enabling-touch-id-authorization-for-sudo-on-macos-high-sierra/).

foo is the host overlay NIC (`--tun`, gateway default true). Extra hopscotch processes on the same machine stay `gateway: false` so their ULAs are not local. They answer ICMP echo in-process. A second machine running baz with `--tun` owns `fd00::/8` there; `ping6 foo` and `ping6 bar` enter that TUN.

`hopscotch ping` is the named control-plane echo and does not use the TUN.

Generated keys, certs, sockets, and the hosts file live in `examples/.local/` (gitignored).
