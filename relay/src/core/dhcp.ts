// Port of LdnServer Network/VirtualDhcp.cs: one per game, plain data so it can
// be stored in SQLite as JSON and rebuilt on wake.
import type { AddressEntry } from "./codec/types.ts";
import { hex } from "./relay.ts";

const NETWORK_BASE = 0x0a720000; // 10.114.0.0
export const NETWORK_MASK = 0xffff0000; // 255.255.0.0
const INV_MASK = ~NETWORK_MASK >>> 0;
export const BROADCAST = (NETWORK_BASE | INV_MASK) >>> 0; // 10.114.255.255

export interface Dhcp {
  next: number;
  taken: number[];
  /** Reserved entries from CreateAccessPointPrivate's AddressList, up to the first zero IP. */
  reserved: { ip: number; mac: string }[];
}

export function newDhcp(config: AddressEntry[] = []): Dhcp {
  const reserved: Dhcp["reserved"] = [];
  for (const a of config) {
    if (a.ipv4_address === 0) break;
    reserved.push({ ip: a.ipv4_address, mac: hex(a.mac_address) });
  }
  return { next: NETWORK_BASE + 1, taken: reserved.map((r) => r.ip), reserved };
}

const valid = (ip: number) => ip !== NETWORK_BASE && ip !== BROADCAST;

function cycle(d: Dhcp) {
  do d.next = (NETWORK_BASE | ((d.next + 1) & INV_MASK)) >>> 0;
  while (!valid(d.next));
}

export function requestIp(d: Dhcp, mac: Uint8Array): number {
  const m = hex(mac);
  const r = d.reserved.find((x) => x.mac === m);
  if (r) return r.ip;
  // ponytail: linear scan of taken IPs; at most 8 players per game.
  while (d.taken.includes(d.next)) cycle(d);
  const ip = d.next;
  d.taken.push(ip);
  cycle(d);
  return ip;
}

export function returnIp(d: Dhcp, ip: number) {
  if (d.reserved.some((r) => r.ip === ip)) return;
  d.taken = d.taken.filter((x) => x !== ip);
}
