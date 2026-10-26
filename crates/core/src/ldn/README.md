# ldn: the `ldn:u` session, sans-IO

`Session` is one `ICommunicationService` (one per `CreateUserLocalCommunicationService`).
It owns the LDN state, the relay link handshake, request waits, network info
fix-ups and the idle timeout. It does no I/O: the shell (crates/sys) calls it
and carries out the `Action`s it emits. Times are milliseconds from any
monotonic clock (`now: u64`).

## Shell contract

1. **Drain after every call.** After every `Session` method that takes `&mut self`,
   loop `next_action()` until `None` and perform each action in order. The outbox
   holds 12 actions; logs are dropped first, but anything else is lost if the
   shell lets actions pile up across calls.
2. **Actions**
   - `Send { id, payload }`: write `LdnHeader(id, payload.len())` + payload to the relay.
   - `StateChanged`: signal the game's state-change event.
   - `ProxyConfig { ip, mask }`: our virtual IP for the proxy-socket router.
   - `RelayConnect`: open the WSS transport. With `Conn` (which sends Initialize and swallows the
     reply itself) call `on_relay_ready(now, id, mac)` once `Conn` is Ready, with its `session()`;
     `on_relay_open(now)` is only for a shell that lets the session do the handshake. Call
     `on_relay_closed(now)` if the transport fails to come up.
   - `RelayDisconnect`: close the transport and reset the router. Do not call
     `on_relay_closed` for a close the session asked for.
   - `Log { level, text }`: log it.
   - `ReplyReady`: the pending request finished; `take_reply()` gives its result.
3. **Requests that wait on the relay** (`scan`, `create_network[_private]`,
   `connect[_private]`, `reject`) return `Ok(Pending)` or an immediate `Err`.
   On `Pending`, keep the IPC request open, and until `ReplyReady` feed relay packets to
   `on_packet` and call `poll(now)` by `next_deadline()`. Then answer the IPC
   call with `take_reply()`. For Scan, copy `scan_results()` into the game's
   buffer and return their count; for Connect/Create, nothing else.
   Do not call other IPC entry points while a request is pending (Horizon
   serialises a session's IPC anyway). `finalize` cancels a pending request
   without a reply.
4. **Relay packets**: every decoded packet goes to `on_packet(type, payload, now)`.
   This includes Ping: the session echoes the relay's pings, so the shell must not.
   A `Some(ProxyDataIn)` return is game data for the router. The update and log
   extensions (0xC0..=0xC4) are ignored here; route them before or after.
5. **Transport closed** without being asked: `on_relay_closed(now)`. In a room
   the session resumes it (`is_resuming()`): it emits `RelayConnect` again, keeps
   its state, network info and IP, and on the new link sends `Resume` (0xC5: the
   old link's session id + the room id); the relay answers ProxyConfig + Connected
   with the same node and IP. The game is not told. While resuming, the shell keeps
   the router (the game's proxy sockets) and drops the game's datagrams. A refused
   Resume or `RESUME_MS` without one ends it as before resuming existed: the room is
   lost (Ryujinx `OnDisconnected`) and `RelayDisconnect` closes the link. Outside a
   room it emits no `RelayDisconnect`, so the shell resets the router itself.
6. **Timers**: call `poll(now)` at `next_deadline()`. When nothing is pending,
   that is only the idle timeout, which closes the link 6 s after leaving a room.
7. **GetIpv4Address**: `get_ipv4_address()`; `None` means use nifm.
8. **Real wireless bypass** is the shell's: it decides before creating a `Session`.
   As the C++ (`ldn_route.hpp` `UseRelay`), the relay serves a game unless LDN is
   disabled in the config, the console has no IP (nifm), or the real-wireless
   button (ZR) is held at launch. Unlike the C++, `ldn:u` is only taken over for
   games in `gamelist.txt` (the list that also gates the bsd:u proxy routing).

IPC buffers map to arguments: the game's `ScanFilter` is `ScanFilterFull`.
ScanPrivate is `scan`. `GetNetworkInfoLatestUpdate` is `network_info()` plus
`get_network_info_latest_update(n)`, and the shell zeroes entries past 8.

## Timeouts

| What | ms |
|---|---|
| Transport open, then Initialize reply | 5000 each |
| CreateNetwork / Connect | 5000 |
| CreateNetworkPrivate / ConnectPrivate | 4000 |
| Scan | 1000 |
| Reject | 6000 |
| Idle after leaving a room | 6000 |
| Resume a room after its link dropped (relay holds the node 15–25 s) | 12000 |

## Results

- **Scan:** always Ok. On a timeout, the results that arrived are kept. On a
  relay error or no link, the results are empty.
- **Create:** any failure is `InvalidState`, and the state goes back to AccessPoint.
- **Connect:**
  - a relay NetworkError maps through `connect_failure` (Ryujinx codes);
  - a timeout is `ConnectTimeout`;
  - no relay link is `DeviceNotAvailable`.
- **Reject:** `InvalidState` on a NetworkError or a timeout.
- **NetworkError code 1** (PortUnreachable) is informational and never ends a wait.
- **Reject reason 0** (None) counts as no reason: the Disconnect that follows
  reports DestroyedByUser (station) or DestroyedBySystem (host).

## Deliberate differences from the C++ module

Pinned by tests.

- Losing the relay link while in a room leaves the room (state back to
  Station/AccessPoint, reason DestroyedByUser/DestroyedBySystem), like Ryujinx.
  The C++ kept the game in a room the relay had already dropped.
- A Connected that answers a request that already failed is answered with a
  Disconnect; the C++ adopted it and left a phantom room behind.
- SyncNetwork outside a room is ignored (the C++ refilled the cleared info).
- Channel 0 becomes 6 in scan results and SyncNetwork too, not only in Connected.
- The idle timeout never drops the link under a pending request (C++: mid-Scan).
- The virtual IP is forgotten with the link (C++ returned the old one after a reconnect).
