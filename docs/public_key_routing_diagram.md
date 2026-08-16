# Keys: SSH vs mesh

Same object (a public key). Different jobs.

## SSH

The server has a list of public keys (`authorized_keys`). The client proves it holds the matching private key. That answers **may this principal get a shell?** It does not name a network location.

## Mesh / WireGuard / Tailscale

The public key is the **peer identity**. Overlay IPs (`100.x`, `fd7a:…`) are labels a directory binds to that key. Cryptokey routing is **IP → key**. DERP uses the key as a mailbox name and never sees the overlay IP.

## hopscotch

The public key *is* how you compute the overlay address:

```
NodeID = SHA-256(pubkey)
ULA    = fd00::/8 bits from NodeID
```

You reach someone by dialing a configured underlay `peers` address (QUIC + mesh CA). Overlay packets then follow the distance-vector table over live sessions. There is no DHT lookup for NodeIDs.
