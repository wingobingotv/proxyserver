import { BlockList, isIP } from "node:net";

/** IP / CIDR allowlist ("203.0.113.7", "198.51.100.0/24", "2001:db8::/48"). Empty list = no restriction. */
export type IpMatcher = { readonly empty: boolean; matches(ip: string | undefined): boolean };

const MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

export function parseIpEntry(entry: string): { address: string; prefix: number; family: 4 | 6 } | null {
  const [address, prefixText] = entry.trim().split("/");
  if (!address) return null;
  const family = isIP(address);
  if (family === 0) return null;
  const max = family === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? max : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return null;
  return { address, prefix, family: family as 4 | 6 };
}

export function ipMatcher(entries: readonly string[]): IpMatcher {
  const list = new BlockList();
  let count = 0;
  for (const raw of entries) {
    const e = parseIpEntry(raw);
    if (!e) throw new Error(`invalid IP or CIDR "${raw}"`);
    list.addSubnet(e.address, e.prefix, e.family === 4 ? "ipv4" : "ipv6");
    count += 1;
  }
  return {
    empty: count === 0,
    matches(ip) {
      if (count === 0) return true;
      if (!ip) return false;
      const plain = MAPPED.exec(ip)?.[1] ?? ip;
      const family = isIP(plain);
      if (family === 0) return false;
      return list.check(plain, family === 4 ? "ipv4" : "ipv6");
    },
  };
}
