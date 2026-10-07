import { BlockList, isIP, type LookupFunction } from "node:net";
import dns from "node:dns";

/**
 * Destination policy for every outbound connection (provider APIs and the
 * Player API). Only hosts declared in trusted configuration are contacted,
 * and the address a hostname resolves to is checked at connect time — the
 * connection uses exactly the address that was checked, so a DNS answer
 * that changes between check and connect (rebinding) cannot slip through.
 */
export type DestinationPolicy = {
  /** Lower-case hostnames this destination may use. */
  allowedHosts: ReadonlySet<string>;
  /** Port every request must use (from the configured base URL). */
  port: number;
  /** `https:` always; `http:` only when explicitly allowed (non-production). */
  allowHttp: boolean;
  /** RFC 1918 / ULA / CGNAT. Loopback, link-local and metadata stay blocked regardless. */
  allowPrivateNetwork: boolean;
};

export const BLOCKED_DESTINATION = "WBP_BLOCKED_DESTINATION";

export class BlockedDestinationError extends Error {
  readonly code = BLOCKED_DESTINATION;
  constructor(reason: string) {
    super(`destination blocked: ${reason}`);
    this.name = "BlockedDestinationError";
  }
}

function list(v4: Array<[string, number]>, v6: Array<[string, number]>): BlockList {
  const bl = new BlockList();
  for (const [net, prefix] of v4) bl.addSubnet(net, prefix, "ipv4");
  for (const [net, prefix] of v6) bl.addSubnet(net, prefix, "ipv6");
  return bl;
}

/** Never reachable, whatever the configuration says. */
const ALWAYS_BLOCKED = list(
  [
    ["0.0.0.0", 8],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16], // link-local, incl. cloud metadata 169.254.169.254
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4], // multicast
    ["240.0.0.0", 4], // reserved + broadcast
  ],
  [
    ["::", 96], // unspecified, loopback, IPv4-compatible
    ["64:ff9b::", 96], // NAT64 can embed any IPv4
    ["64:ff9b:1::", 48],
    ["100::", 64],
    ["2001::", 23], // Teredo and protocol assignments
    ["2001:db8::", 32],
    ["2002::", 16], // 6to4 can embed any IPv4
    ["fe80::", 10],
    ["fec0::", 10],
    ["ff00::", 8],
  ],
);

/** Private networks: blocked unless the destination explicitly allows them. */
const PRIVATE = list(
  [
    ["10.0.0.0", 8],
    ["100.64.0.0", 10], // CGNAT, incl. 100.100.100.200 metadata
    ["172.16.0.0", 12],
    ["192.168.0.0", 16],
  ],
  [["fc00::", 7]], // ULA, incl. fd00:ec2::254 metadata
);

const MAPPED_V4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;
const MAPPED_V4_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i;

/** `::ffff:a.b.c.d` / `::ffff:7f00:1` → `a.b.c.d`; anything else unchanged. */
function unmapIPv4(ip: string): string {
  const dotted = MAPPED_V4.exec(ip);
  if (dotted) return dotted[1]!;
  const hex = MAPPED_V4_HEX.exec(ip);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return ip;
}

/** Why an address is not allowed, or null when it is. */
export function blockedReason(address: string, allowPrivateNetwork: boolean): string | null {
  const ip = unmapIPv4(address.replace(/^\[|\]$/g, "").split("%")[0]!);
  const family = isIP(ip);
  if (family === 0) return "not an IP address";
  const type = family === 4 ? "ipv4" : "ipv6";
  if (ALWAYS_BLOCKED.check(ip, type)) return `reserved address ${ip}`;
  if (!allowPrivateNetwork && PRIVATE.check(ip, type)) return `private address ${ip}`;
  return null;
}

function defaultPort(protocol: string): number {
  return protocol === "http:" ? 80 : 443;
}

export function urlPort(url: URL): number {
  return url.port ? Number(url.port) : defaultPort(url.protocol);
}

/** Throws unless `url` is a destination this policy permits. Used before every request. */
export function assertAllowedUrl(url: URL, policy: DestinationPolicy): void {
  if (url.protocol !== "https:" && !(policy.allowHttp && url.protocol === "http:")) {
    throw new BlockedDestinationError(`protocol ${url.protocol} not allowed`);
  }
  if (url.username || url.password) throw new BlockedDestinationError("credentials in URL");
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!policy.allowedHosts.has(host)) throw new BlockedDestinationError(`host ${host} is not configured`);
  if (urlPort(url) !== policy.port) throw new BlockedDestinationError(`port ${urlPort(url)} not allowed`);
  if (isIP(host)) {
    const reason = blockedReason(host, policy.allowPrivateNetwork);
    if (reason) throw new BlockedDestinationError(reason);
  }
}

type Resolved = { address: string; family: number };
export type Resolver = (hostname: string) => Promise<Resolved[]>;

const systemResolver: Resolver = (hostname) => dns.promises.lookup(hostname, { all: true, verbatim: true });

/**
 * `lookup` for the socket layer: resolves, rejects the whole answer if any
 * address is blocked, and hands the socket only checked addresses.
 */
export function safeLookup(policy: DestinationPolicy, resolver: Resolver = systemResolver): LookupFunction {
  return (hostname, options, callback) => {
    const host = hostname.toLowerCase();
    const fail = (err: NodeJS.ErrnoException) => callback(err, "", 0);
    if (!policy.allowedHosts.has(host)) {
      fail(new BlockedDestinationError(`host ${host} is not configured`));
      return;
    }
    resolver(host)
      .then((answers) => {
        const wanted = options.family === 4 || options.family === 6 ? answers.filter((a) => a.family === options.family) : answers;
        if (wanted.length === 0) {
          const err: NodeJS.ErrnoException = new Error(`no address for ${host}`);
          err.code = "ENOTFOUND";
          fail(err);
          return;
        }
        for (const a of wanted) {
          const reason = blockedReason(a.address, policy.allowPrivateNetwork);
          if (reason) {
            fail(new BlockedDestinationError(`${host} resolved to ${reason}`));
            return;
          }
        }
        if (options.all) {
          (callback as unknown as (err: null, addresses: Resolved[]) => void)(null, wanted);
        } else {
          const first = wanted[0]!;
          callback(null, first.address, first.family);
        }
      })
      .catch((err: NodeJS.ErrnoException) => fail(err));
  };
}

export function hostOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
}

/**
 * Policy for one configured base URL: that host and port only. Requests are
 * always built from the base URL, so no other host is ever needed.
 */
export function policyFor(baseUrl: URL, options: { allowHttp: boolean; allowPrivateNetwork: boolean }): DestinationPolicy {
  return {
    allowedHosts: new Set([hostOf(baseUrl)]),
    port: urlPort(baseUrl),
    allowHttp: options.allowHttp,
    allowPrivateNetwork: options.allowPrivateNetwork,
  };
}
