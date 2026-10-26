# Moving a console from ryu_ldn_nx or ldn_mitm to ldn-tunnel

Install ldn-tunnel over the old module (the invite zip or the release zip) and restart twice. Nothing has
to be removed by hand.

## First boot (built into the module)

Before registering any service, the module scans `sdmc:/atmosphere/contents/` for known LDN MITM
modules and disables each one that is enabled:

| module      | program id         | action                                         |
|-------------|--------------------|------------------------------------------------|
| ryu_ldn_nx  | 4200000000000010   | rename `flags/boot2.flag` → `flags/boot2.flag.ldn-tunnel-disabled` |
| ldn_mitm    | 4200000000000010 (same id, older project) | same rename                  |
| any other `contents/<id>/mitm.lst` or `toolbox.json` naming `ldn:u` | log only, do not touch |

Rename, never delete. The old module is still loaded on this boot (both start from boot2), so
ldn-tunnel does **not** register `ldn:u`/`bsd:u` and shows "Restart once to finish setup" in the overlay.
The next boot is clean. To go back, delete `atmosphere/contents/420000004C444E54/flags/boot2.flag` and
rename the old module's `boot2.flag.ldn-tunnel-disabled` back to `boot2.flag`.
