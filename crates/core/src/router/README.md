# router

Sans-IO port of the C++ proxy socket routing (`bsd/proxy_socket*.cpp`,
`ephemeral_port_pool.cpp`, the proxied-fd paths of `bsd_mitm_service.cpp`).
The shell turns each bsd:u call on a game socket into one `Router::on_*` call
and acts on the `Decision` / `RecvDecision`; the relay receive thread calls
`on_proxy_data`. Blocking (recv `Wait`, poll/select waits, the 1 s cap) and
waking waiters stay in the shell. When a bsd:u session ends the shell calls
`on_session_closed` (the C++ `~BsdMitmService` cleanup).

## Deliberate differences from the C++ (each pinned by a test)

- setsockopt on a proxy accepts int options (SO_REUSEADDR, SO_RCVBUF, ...);
  the C++ falls through into the SO_RCVTIMEO case and answers EINVAL.
- Broadcasts (incl. the relay's 192.168.0.255) reach every socket on the
  port; the C++ also required the socket's IP to share the destination's /16.
- poll/select report a socket readable after shutdown(SHUT_RD) (recv
  returns 0 at once); the C++ only looked at the queue.
- Pending datagrams go to a socket by port and IP (or broadcast), and also on
  an implicit bind (connect/sendto); the C++ matched by port only, on bind().
- At most 128 AF_INET fds are tracked at once (the C++ map is unbounded).

Static memory: `size_of::<Router>()` = 145,232 bytes (8 x ~16.5 KB sockets,
8 KB pending ring, 128 tracked fds, 2 KB UDP port bitset).

## Adding TCP (ProxyConnect / ProxyConnectReply / ProxyDisconnect, accept)

What grows, and nothing else should need to:

- `Decision`: new variants `EmitConnect(ProxyConnectRequest)` (connect),
  `EmitConnectReply(ProxyConnectResponse)` (accepted connection) and
  `EmitDisconnect(ProxyDisconnectMessage)` (close of a connected TCP socket);
  `on_connect` returns `EmitConnect` + a new `Decision::Pending` for the
  blocking wait (`RecvDecision::Wait`-style, 4 s like Ryujinx) / EINPROGRESS.
- `on_close` returns the disconnect to emit instead of `bool`.
- New methods: `on_listen`, `on_accept` (returns the new socket's key/peer),
  `on_proxy_connect(&ProxyConnectRequest)` (queue on a listening socket),
  `on_proxy_connect_reply(&ProxyConnectResponse)` (finish a connecting socket),
  `on_proxy_disconnect(&ProxyDisconnectMessage)` (EOF on the stream).
- `ProxySocket` gains a state enum (`Connecting`, `Connected`, `Listening`)
  and a small accept queue; its `rx` ring is reused as a byte stream
  (records concatenated, `on_recv` reads across record boundaries).
- `Router` gains `tcp_ports: PortPool`; `create_bound`, `on_close` and
  `reset` pick the pool by socket type.
- `on_bind` / `on_connect` / `on_sendto` drop their `SOCK_DGRAM` gates;
  `on_proxy_data` stops dropping `ProtocolType::Tcp` and matches the socket's
  protocol; `Meta` (ring.rs) gets a protocol byte for the pending ring.
- `emit` fills `protocol` from the socket instead of always UDP.
