# On-screen notifications

Short toasts while a game runs and the overlay is closed: update staged / updated, online play on/off
at game start, and relay connected / lost / reconnected. Shown by Ultrahand (owner's decision).
Core logic: `crates/core/src/notify.rs`. Shell and overlay work: section 3.

## 1. Ultrahand's mechanism (verified from source)

**A sysmodule drops a JSON file into `sdmc:/config/ultrahand/notifications/`; whichever overlay
nx-ovlloader has loaded (the Ultrahand menu by default, hidden while a game runs) picks it up within
300 ms, shows it, and deletes the file.** There is no service or event. Ultrahand calls these "API
Notifications" (they were called "External Notifications" in v2.2.7–v2.2.9).

| Item | Fact | Source |
|---|---|---|
| Introduced | Ultrahand **v2.1.0** (2025-09-17): "External json calls … written to `/config/ultrahand/notifications/<PROGRAM_ID>-<UNIQUE_ID>.notify` … allows any program, including sys modules, to interface with the notification prompts." Overlays must use libultrahand ≥ 2.1.0 to show them. | [release v2.1.0](https://github.com/ppkantorski/Ultrahand-Overlay/releases/tag/v2.1.0) |
| Format extended | **v2.3.0** (2026-03-13) added `title`, `duration`, `alignment`, `split_type`, `show_time`, icons, multi-slot display (Max Slots, default 4) and the per-app mute flag. | [release v2.3.0](https://github.com/ppkantorski/Ultrahand-Overlay/releases/tag/v2.3.0) |
| Path | `sdmc:/config/ultrahand/notifications/` (`NOTIFICATIONS_PATH`) | [global_vars.cpp L64 @v2.5.3](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libultra/source/global_vars.cpp#L64) |
| File name | `{APP_ID}-{UNIQUE}.notify`. Must end in `.notify`; the part before the **first `-`** is the app id. libultrahand's own writer uses `appID + "-" + systemTick + ".notify"`. | [json_funcs.cpp L319 @v2.5.3](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libultra/source/json_funcs.cpp#L319) |
| Format | UTF-8 JSON object. `text` (string, required, non-empty), optional `title` (string), `font_size` (8–48; default 26, or 24 with a title), `duration` (ms, clamped 500–30000; 0 = until dismissed; default 4000), `priority` (default 20; higher first, then oldest mtime), `alignment` (`left`/`center`/`right`), `split_type` (`word`/`char`), `show_time` (`"false"` hides the timestamp next to the title). Unknown keys are ignored. | [tesla.hpp L14723–14897 @v2.5.3](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libtesla/include/tesla.hpp#L14723) |
| One-shot | The file is removed when its toast is evicted/expires (`evictSlot_NoLock`). A file that does not parse as JSON is skipped (retried next scan), not deleted. | [tesla.hpp L12971 @v2.5.3](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libtesla/include/tesla.hpp#L12971) |
| Global switch | `[ultrahand] notifications=` in Ultrahand's config.ini, **default true** (menu label "API Notifications"; also toggled by holding MINUS 4 s when the hotkey option is on). While on, `sdmc:/config/ultrahand/flags/NOTIFICATIONS.flag` exists; while off, Ultrahand **deletes every `.notify` file unread**. | [Ultrahand main.cpp L1747, L7862 @v2.5.3](https://github.com/ppkantorski/Ultrahand-Overlay/blob/v2.5.3/source/main.cpp#L1747), [tesla.hpp L14898](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libtesla/include/tesla.hpp#L14898) |
| Startup toast is separate | `startup_notification` (default true) is a different toggle. The owner seeing the boot toast proves the hidden overlay draws toasts over games; it does **not** prove API notifications are on. | [main.cpp L1745 @v2.5.3](https://github.com/ppkantorski/Ultrahand-Overlay/blob/v2.5.3/source/main.cpp#L1745) |
| Per-app mute | If `sdmc:/config/ultrahand/flags/notifications/{APP_ID}.flag` exists, that app's files are deleted unshown. | [tesla.hpp L14788](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libtesla/include/tesla.hpp#L14787) |
| Icon | Optional `sdmc:/config/ultrahand/assets/notifications/{APP_ID}.rgba`, 50×50, **2 bytes/pixel** (`NOTIF_ICON_BYTES = 50*50*2`, i.e. RGBA4444, although the release notes say "RGBA"). | [global_vars.cpp L65](https://github.com/ppkantorski/libultrahand/blob/v2.5.3/libultra/source/global_vars.cpp#L65), tesla.hpp `NOTIF_ICON_BYTES` |
| Limits | Box 448×88 px, word-wrapped, "only 4 lines can be displayed" (release notes; the renderer buffers 10). Up to `max_notifications` toasts at once (default 4, max 8; 4 with 4 MB overlay heap); scanning takes one new file per 300 ms tick when slots are busy; in-memory queue 30. No rate limit or text-length check: our side keeps toasts rare and short. | v2.3.0 notes; tesla.hpp `NOTIF_WIDTH`, `MAX_VISIBLE`, `MAX_NOTIFS` |

Versions in play:

- **Console:** tested with **Ultrahand v2.5.3** (with nx-ovlloader v2.0.2). Ultrahand and libultrahand
  share version numbers; v2.5.3 of both supports the full
  format above.
- **Our overlay:** the C++ reference overlay pins libultrahand at `f053eaa` (2026-01-12, between v2.2.7 and
  v2.2.8; 223 commits behind v2.5.3). While *our* `.ovl` is the loaded overlay, its own copy of the scanner shows
  the toasts. That older scanner reads `text`, `font_size` (clamped 1–34), `priority` only, a fixed 2.5 s
  duration, one at a time; `title`/`duration` are ignored, so the same file works on both. Recommendation: bump
  the overlay's submodule to the v2.5.3 tag when it is re-pointed, so toasts look the same either way.
- **Tesla Menu** (the alternative overlay menu) has no such scanner: files stay on the SD card unread
  (see the stale-file rule below).
- **Neither the C++ module nor its overlay writes any Ultrahand notification today** (grep for `.notify` /
  `ultrahand/notifications` in the ryu_ldn_nx sysmodule and overlay sources: no hits).

Not verified (needs the console): that the hidden Ultrahand menu shows API toasts over a running game
(the code path is the same background loop that draws the startup toast). (The toast text uses a plain
hyphen, not an em dash, because the shared font may not draw U+2014.)

Alternatives, for the record (from general knowledge, not re-verified here). Horizon has a system
overlay-notification channel (`ovln:snd`/`ovln:rcv`) behind the system's own toasts (low battery and the
like), drawn by the overlay applet. Its message formats are undocumented and not known to carry custom
text, so it is not a practical route. A tiny always-on overlay of our own
cannot coexist with Ultrahand: nx-ovlloader keeps exactly one overlay loaded. Ultrahand's file drop
needs no new process, works for everyone who installs the recommended menu, and users already know
how to mute it.

## 2. Core logic (`crates/core/src/notify.rs`)

```rust
let mut n = Notifier::new(cfg.notifications);   // NotifyConfig { updates, game_start, connection }
n.on_event(Event::GameStarted { pid, mode: LdnMode::Online }, now_ms);
n.on_event(Event::Relay { up: true }, now_ms);
while let Some(toast) = n.poll(now_ms) { shell_write(toast) }  // Toast { category, text: heapless::String<64> }
n.set_config(NotifyConfig::from_bits(bits));    // from SetNotifyFlags
```

Events: `UpdateStaged`, `UpdatedTo(&str)`, `GameStarted { pid, mode: Online | Bypass | Disabled }`,
`GameExited { pid }`, `Relay { up }`. Rules:

- Updates: "Update ready - restart ldn-tunnel in the overlay" once per boot when staged; "Updated to <version>" once
  (the shell sends `UpdatedTo` only on the first boot of a new build). Checks/downloads produce nothing.
- Game start: one toast per pid ("Online play on" / "Off (real wireless)" / "Off (disabled)"). The shell sends
  `GameStarted` only for whitelisted titles, when the game opens ldn:u.
- Connection: only during an `Online` game session (from `GameStarted` until `GameExited` for that pid). A
  relay state is announced once it has held 5 s, measured from the later of the last change and the session
  start (so "Connected" never lands on the game-start toast). Connected → Connection lost → Reconnected; a
  flap shorter than 5 s collapses to nothing; "down" before the first connect of a session is silent.
- Toggles filter at `poll`; transitions while muted are tracked but never replayed.
- `Toast::write_json` renders the file body (escaped, ≤ 256 bytes); `notify::file_name(seq)` gives
  `420000004C444E54-<seq>.notify` (program id, no `-`, from `ident.rs`).

`config::Config` embeds it as `notifications`; config.ini section (written by the serializer, see
`dist/config.ini`):

```ini
[notifications]
updates = 1
game_start = 1
connection = 1
```

## 3. Shell and overlay design (not built yet)

### Shell (crates/sys)

- Call `poll(now)` once per second from an existing loop (the relay client thread is enough); events come from
  the ldn:u MITM (`GameStarted` on ldn:u open, `GameExited` on session close / process exit), the relay client
  (`Relay`) and the updater (`UpdateStaged`, `UpdatedTo` at boot).
- For each toast: if `sdmc:/config/ultrahand/notifications/` does not exist, drop it (Ultrahand not
  installed; never create Ultrahand's folders). Otherwise write `Toast::write_json` bytes to
  `notifications/<file_name(seq)>.tmp`, then rename to `<file_name(seq)>` (the scanner ignores non-`.notify`
  names, so it never sees a half-written file). `seq` is a wrapping per-boot counter seeded from the system
  tick so names never repeat across boots.
- Stale files: at boot, delete our own leftover `420000004C444E54-*.notify` files (they were never shown, e.g.
  Tesla Menu or API notifications off). Before writing a Connection toast, delete the previous Connection file
  if it is still there: an unshown "Connection lost" must not pop up after "Reconnected".
- No check of `NOTIFICATIONS.flag` is needed: when it is off, Ultrahand deletes our files itself.
- Optional: ship a 50×50 RGBA4444 icon as `config/ultrahand/assets/notifications/420000004C444E54.rgba` in the
  install zip.

### cfg IPC (`ldnt:cfg`, owned by the ldn-ifaces helper; proposal only)

| Id | Command | In | Out |
|---|---|---|---|
| 28 | `GetNotifyFlags` | — | `u32` bitmask: bit 0 updates, bit 1 game_start, bit 2 connection (`NotifyConfig::bits`) |
| 29 | `SetNotifyFlags` | `u32` bitmask | — ; applies at once (`Notifier::set_config`), in memory until `SaveConfig` (13) persists `[notifications]` |

Unknown bits are ignored on set and returned as zero on get.

### Overlay

A "Notifications" submenu with three toggle items (Updates, Game start, Connection). On open:
`GetNotifyFlags`; on each toggle: `SetNotifyFlags(new_bits)` then `SaveConfig`, the same pattern the existing
debug/LDN toggles use. One footer line: "Shown by Ultrahand (API Notifications must be on)".
