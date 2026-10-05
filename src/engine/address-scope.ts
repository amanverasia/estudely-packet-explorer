// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Reviewed IANA special-purpose prefixes (2025-10-09) and IPv6 address space
// allocation class (2025-10-23).

export interface ParsedIpAddress {
  version: 4 | 6;
  /** Unsigned words, most significant first (1 for IPv4, 4 for IPv6). */
  words: number[];
}

interface PrefixEntry extends ParsedIpAddress {
  bits: number;
  label: string;
  globallyReachable: boolean;
}

/** Parse strict dotted-decimal IPv4 and compressed or expanded IPv6 literals. */
export function parseIpAddress(address: string): ParsedIpAddress | null {
  const v4 = parseIpv4(address);
  if (v4 !== null) return { version: 4, words: [v4] };
  if (!address.includes(':') || address.includes('%')) return null;

  let input = address.toLowerCase();
  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    if (lastColon < 0) return null;
    const tail = parseIpv4(input.slice(lastColon + 1));
    if (tail === null) return null;
    input = `${input.slice(0, lastColon + 1)}${(tail >>> 16).toString(16)}:${(tail & 0xffff).toString(16)}`;
  }

  const halves = input.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const hextets = [...left, ...Array(missing).fill('0'), ...right];
  if (hextets.length !== 8 || hextets.some((part) => !/^[\da-f]{1,4}$/.test(part))) return null;
  const words: number[] = [];
  for (let i = 0; i < hextets.length; i += 2) {
    words.push(parseInt(hextets[i], 16) * 0x1_0000 + parseInt(hextets[i + 1], 16));
  }
  return { version: 6, words };
}

function parseIpv4(address: string): number | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (!match) return null;
  const bytes = match.slice(1).map(Number);
  if (bytes.some((byte) => byte > 255)) return null;
  return bytes[0] * 0x1_00_00_00 + bytes[1] * 0x1_00_00 + bytes[2] * 0x100 + bytes[3];
}

function prefix(address: string, bits: number, label: string, globallyReachable: boolean): PrefixEntry {
  const parsed = parseIpAddress(address);
  if (!parsed) throw new Error(`Invalid built-in IP prefix: ${address}`);
  return { ...parsed, bits, label, globallyReachable };
}

// Names and reachability flags are from the IANA IPv4 and IPv6 Special-Purpose
// Address Registries. “N/A”, expired, and false entries are ineligible for
// local country/ASN lookups. The 224/4 multicast row comes from the IANA IPv4
// Multicast registry (snapshot 2026-08-20); ff00::/8 is in the IPv6 Address
// Space registry. More-specific prefixes override broader entries.
const SPECIAL_PREFIXES: PrefixEntry[] = [
  prefix('0.0.0.0', 8, 'this network', false),
  prefix('0.0.0.0', 32, 'unspecified', false),
  prefix('10.0.0.0', 8, 'private', false),
  prefix('100.64.0.0', 10, 'shared (CGNAT)', false),
  prefix('127.0.0.0', 8, 'loopback', false),
  prefix('169.254.0.0', 16, 'link-local', false),
  prefix('172.16.0.0', 12, 'private', false),
  prefix('192.0.0.0', 24, 'IETF protocol assignments', false),
  prefix('192.0.0.0', 29, 'IPv4 service continuity', false),
  prefix('192.0.0.8', 32, 'IPv4 dummy address', false),
  prefix('192.0.0.9', 32, 'Port Control Protocol anycast', true),
  prefix('192.0.0.10', 32, 'Traversal Using Relays anycast', true),
  prefix('192.0.0.170', 32, 'NAT64/DNS64 discovery', false),
  prefix('192.0.0.171', 32, 'NAT64/DNS64 discovery', false),
  prefix('192.0.2.0', 24, 'documentation', false),
  prefix('192.31.196.0', 24, 'AS112-v4', true),
  prefix('192.52.193.0', 24, 'AMT', true),
  prefix('192.88.99.0', 24, 'deprecated 6to4 relay anycast', false),
  prefix('192.88.99.2', 32, '6a44 relay anycast', false),
  prefix('192.168.0.0', 16, 'private', false),
  prefix('192.175.48.0', 24, 'AS112 direct delegation', true),
  prefix('198.18.0.0', 15, 'benchmarking', false),
  prefix('198.51.100.0', 24, 'documentation', false),
  prefix('203.0.113.0', 24, 'documentation', false),
  prefix('224.0.0.0', 4, 'multicast', false),
  prefix('240.0.0.0', 4, 'reserved', false),
  prefix('255.255.255.255', 32, 'broadcast', false),

  prefix('::', 128, 'unspecified', false),
  prefix('::1', 128, 'loopback', false),
  prefix('::ffff:0:0', 96, 'IPv4-mapped', false),
  prefix('64:ff9b::', 96, 'IPv4/IPv6 translation', true),
  prefix('64:ff9b:1::', 48, 'local IPv4/IPv6 translation', false),
  prefix('100::', 64, 'discard-only', false),
  prefix('100:0:0:1::', 64, 'dummy IPv6 prefix', false),
  prefix('2001::', 23, 'IETF protocol assignments', false),
  prefix('2001::', 32, 'Teredo', false),
  prefix('2001:1::1', 128, 'Port Control Protocol anycast', true),
  prefix('2001:1::2', 128, 'Traversal Using Relays anycast', true),
  prefix('2001:1::3', 128, 'DNS-SD anycast', true),
  prefix('2001:2::', 48, 'benchmarking', false),
  prefix('2001:3::', 32, 'AMT', true),
  prefix('2001:4:112::', 48, 'AS112-v6', true),
  prefix('2001:10::', 28, 'deprecated ORCHID', false),
  prefix('2001:20::', 28, 'ORCHIDv2', true),
  prefix('2001:30::', 28, 'Drone Remote ID entity tags', true),
  prefix('2001:db8::', 32, 'documentation', false),
  prefix('2002::', 16, '6to4', false),
  prefix('2620:4f:8000::', 48, 'AS112 direct delegation', true),
  prefix('3fff::', 20, 'documentation', false),
  prefix('5f00::', 16, 'SRv6 segment identifiers', false),
  prefix('fc00::', 7, 'unique local', false),
  prefix('fe80::', 10, 'link-local', false),
  prefix('ff00::', 8, 'multicast', false),
].sort((a, b) => b.bits - a.bits);

function matchesPrefix(address: ParsedIpAddress, entry: PrefixEntry): boolean {
  if (address.version !== entry.version) return false;
  const wholeWords = Math.floor(entry.bits / 32);
  const remainingBits = entry.bits % 32;
  for (let i = 0; i < wholeWords; i++) if (address.words[i] !== entry.words[i]) return false;
  if (remainingBits === 0) return true;
  const mask = (0xffff_ffff << (32 - remainingBits)) >>> 0;
  return ((address.words[wholeWords] & mask) >>> 0) === ((entry.words[wholeWords] & mask) >>> 0);
}

function matchingPrefix(address: ParsedIpAddress): PrefixEntry | undefined {
  // The list is ordered by descending prefix length, so the first match wins.
  return SPECIAL_PREFIXES.find((entry) => matchesPrefix(address, entry));
}

function isIpv6GlobalUnicast(address: ParsedIpAddress): boolean {
  if (address.version !== 6) return false;
  // IANA's IPv6 Address Space registry labels 2000::/3 Global Unicast.
  return (address.words[0] >>> 29) === 1;
}

/** True only for ordinary globally-unicast space or an IANA entry marked true. */
export function isGloballyReachable(address: string): boolean {
  const parsed = parseIpAddress(address);
  if (!parsed) return false;
  const entry = matchingPrefix(parsed);
  if (entry) return entry.globallyReachable;
  return parsed.version === 4 || isIpv6GlobalUnicast(parsed);
}

/** Human-readable range description, independent of lookup eligibility. */
export function addressScope(address: string): string {
  const parsed = parseIpAddress(address);
  if (!parsed) return 'unknown';
  const entry = matchingPrefix(parsed);
  if (entry) return entry.label;
  if (parsed.version === 6 && !isIpv6GlobalUnicast(parsed)) return 'reserved';
  return parsed.version === 4 ? 'public' : 'global';
}
