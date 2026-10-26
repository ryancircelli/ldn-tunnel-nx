# IPC server threading

## The rule we need

A blocking bsd:u call on a socket we don't proxy (Recv, RecvFrom, Accept,
Poll, Select on a real fd) must never stall:

- other bsd:u sessions, from the same game or another one;
- ldn:u, which the game calls from other threads while one of them sits in Recv;
- ldnt:cfg, the overlay's config service.

This includes the ShouldMitm query session, which sm calls synchronously
whenever any process opens bsd:u. If the bsd:u thread is blocked, sm is
blocked too.

## What nx gives us

nx's `ServerManager` (vendor/nx, `src/ipc/server.rs`) is one single-threaded
wait loop:

- it holds its objects as `Rc<Mutex<dyn ISessionObject>>`, so it is not `Send`;
- it waits on all of its handles at once;
- before our patches it handled each request to completion. A forwarded
  request was a blocking `svcSendSyncRequest`, so one game thread in `recv()`
  froze every session in that manager;
- it serves the MitM query session from the same manager as the MitM sessions.

## Options considered

1. **N managers sharing one port.** Each accepted session belongs to whichever
   manager accepted it, and its clones (CloneCurrentObject) stay on that
   manager's thread. One blocked call still freezes that thread's share of the
   sessions plus every clone. This makes stalls rarer but does not remove them.
2. **A multi-threaded nx manager**, like Atmosphere's thread pool. Every
   `Rc` in nx's server becomes an `Arc` and every object must be `Send`, which
   is a large patch to nx's API. It still stalls once more calls block than
   there are threads, which is the reason the C++ module needs 3 threads and a
   32-session limit for bsd:u. Per-session threads were also rejected: about 32
   stacks would not fit in the memory or the thread budget.
3. **Never block a server thread (chosen).** Nothing that can wait runs inline:
   - Forwarded calls go out with `svcSendAsyncRequestWithUserBuffer`.
   - Waits on proxied sockets become a wait on an event with a deadline.
   - The request is parked, the loop keeps serving every other session, and the
     request is re-dispatched when its event signals or its deadline passes.

   This makes the number of threads independent of the number of blocked
   calls. It needs a small nx patch, not a re-architecture
   (docs/nx-patches/0003).

On top of option 3, each service gets its **own manager on its own thread**
(`server::spawn`): ldn:u, bsd:u and ldnt:cfg. That way a bug or a slow path in
one service cannot stall the others, and sm's ShouldMitm query for bsd:u is
only ever behind bsd:u requests, which never block.

## How a request flows (bsd:u)

1. The manager receives a request, then the wrapper
   (`BsdMitmService::try_handle_request_by_id`) runs:
   - It snapshots the TLS message.
   - It dispatches to the handler (`bsd/service.rs`).
2. **Forward (most calls, and any undeclared command).** The handler returns
   `ResultShouldForwardToSession`, then `Forward::start` (`forward.rs`):
   - It copies the message into a page-aligned buffer.
   - It copies the X (pointer) data out of the manager's shared pointer buffer
     and points the descriptors at the copy. The real service reads that data
     when *it* receives the request, and by then our pointer buffer may hold
     another request.
   - It tags the pid with 0xFFFE.
   - It points the receive list at a per-request buffer.
   - It sends the request asynchronously, and the wrapper sets
     `ctx.defer = { wait: async event, deadline: none }`.

   The manager then stores the message and pointer buffer and does not reply.
3. When the async event signals, the manager clears it and re-dispatches. The
   wrapper finds the in-flight forward for that session:
   - It copies the reply into TLS.
   - It runs post-actions: it records the fd from Socket, and it closes our copy
     of RegisterClient's transfer memory.
   - It returns Ok, and the manager replies.

   The reply's X descriptors point into the forward's receive buffer, so that
   buffer is kept until the next dispatch on the object.
4. **Proxied wait** (Recv/RecvFrom/Read on an empty ring; Poll/Select with no
   ready fd and a non-zero timeout):
   - The handler fixes the deadline at the first dispatch (`waits`, by session
     handle) and defers on the router's rx event.
   - The manager clears that event before re-dispatching *everyone* waiting on
     it, and each handler re-checks. So a datagram that arrives after a check
     always re-signals, and sessions sharing the event never lose a wakeup.
5. **Mixed Poll/Select** (real fds and proxied fds in one call):
   - The real fds are polled through the forward session with timeout 0. This
     is a short synchronous call: bsd answers it without waiting.
   - The proxied fds are checked through the router.
   - If nothing is ready, the request defers on the rx event with a 10 ms slice,
     so the real fds are re-polled at least every 10 ms until the deadline.
     This matches the C++ 20 ms slicing, at half the latency.

## Stall analysis

| What blocks | Who waits | Who is *not* affected |
|---|---|---|
| Real Recv/Accept/Poll/Select inside the real bsd:u | that game thread (its session has one request outstanding, as with the real service) | every other bsd:u session; ldn:u; ldnt:cfg; sm's ShouldMitm query |
| Proxied wait | that game thread | everyone else |
| Mixed wait | that game thread; the bsd:u loop spends one timeout-0 bsd call per 10 ms slice | everyone else (bounded extra latency of one short call) |
| QueryPointerBufferSize / CloneCurrentObject on a MitM session | those are synchronous calls to the real bsd:u control path, which answers without waiting | n/a (short) |
| A slow router call | bsd:u thread only | ldn:u, ldnt:cfg (separate threads) |

The remaining synchronous calls on the bsd:u thread are all of the
"answer immediately" kind:

- timeout-0 poll/select;
- QueryPointerBufferSize;
- CloneCurrentObject;
- AtmosphereAcknowledgeMitmSession to sm.

Limits:

- **Wait handles.** svcWaitSynchronization takes at most 64 handles. The
  bsd:u manager waits on:
  - its port;
  - the query session;
  - every session;
  - one async event per in-flight forward;
  - the rx event.

  That is about 2 + 2×sessions + 1, so cap bsd:u at about 30 sessions. The
  patched `prepare_wait_handles` stops at 64 rather than overflowing, but
  nothing enforces the cap yet. **TODO:** pass the session count to
  `register_mitm_service_server` once nx takes one; its sm registration
  currently has no limit for MitM.
- **Memory.** Each in-flight forward holds one 4 KiB page, plus the X copy,
  plus a 4 KiB receive buffer. That is about 8–12 KiB × in-flight calls, from
  the 1 MiB heap.
- A forward abandoned by a dying client leaks its buffers, because the kernel
  may still write them (`Forward`'s Drop).

## What only hardware can prove

- That `svcSendAsyncRequestWithUserBuffer` accepts a buffer in our heap. The
  heap is a static in .bss, so its memory state is CodeData, and the call
  needs a state that allows IPC user buffers. If it doesn't, the heap (or a
  page pool) must come from `svcMapPhysicalMemory` / `svcSetHeapSize` memory.
- How the kernel reports an async failure. We read it as an all-zero header
  followed by the result, from Horizon's `MessageBuffer::SetAsyncResult`.
- The MitM pid tag and receive-list rewrite against the real bsd:u.
- Whether a deferred session whose client closes signals exactly once (we
  close it on that signal).
- That bsd ignores a negative fd in Poll.
