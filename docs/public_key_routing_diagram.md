# Keys: SSH vs mesh vs Kademlia

Same object (a public key). Three jobs.

## SSH

The server has a list of public keys (`authorized_keys`). The client proves it holds the matching private key. That answers **may this principal get a shell?** It does not name a network location.

## Mesh / WireGuard / Tailscale

The public key is the **peer identity**. Overlay IPs (`100.x`, `fd7a:…`) are labels a directory binds to that key. Cryptokey routing is **IP → key**. DERP uses the key as a mailbox name and never sees the overlay IP.

## hopscotch

The public key *is* how you compute the address in ID space:

```
NodeID = SHA-256(pubkey)
```

FIND_NODE talks about NodeIDs. The underlay `ip:port` is only a contact hint so QUIC can dial. If that hint goes stale, lookup runs again.
