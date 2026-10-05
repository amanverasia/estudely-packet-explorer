// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { AnalysisModel, CaptureInfo, Conversation, ProtoStat } from './types';

export type ComparisonSource = {
  capture: Pick<CaptureInfo, 'fileName' | 'analyzedBytes' | 'partial' | 'packetCount' | 'duration'>;
  hosts: { addr: string; names: string[]; protocols: string[] }[];
  topProtocols: Pick<ProtoStat, 'proto' | 'packets' | 'bytes'>[];
  conversations: Pick<Conversation, 'transport' | 'a' | 'aPort' | 'b' | 'bPort' | 'packetsAB' | 'bytesAB' | 'packetsBA' | 'bytesBA' | 'start' | 'end' | 'firstFrame' | 'appProtocol' | 'protocols'>[];
};

export type ChangeStatus = 'new' | 'missing' | 'changed' | 'same';

export interface ChangeCounts {
  new: number;
  missing: number;
  changed: number;
  same: number;
}

export interface HostChange {
  key: string;
  address: string;
  status: ChangeStatus;
  beforeNames: string[];
  afterNames: string[];
  beforeProtocols: string[];
  afterProtocols: string[];
}

export interface ProtocolChange {
  key: string;
  protocol: string;
  status: ChangeStatus;
  before: Pick<ProtoStat, 'packets' | 'bytes'> | null;
  after: Pick<ProtoStat, 'packets' | 'bytes'> | null;
}

export interface ConversationSummary {
  packets: number;
  bytes: number;
  duration: number;
  appProtocol: string;
  protocols: string[];
}

export interface ConversationChange {
  key: string;
  transport: Conversation['transport'];
  endpointA: string;
  endpointB: string;
  status: ChangeStatus;
  before: ConversationSummary | null;
  after: ConversationSummary | null;
}

export interface CaptureComparison {
  before: ComparisonSource['capture'];
  after: ComparisonSource['capture'];
  hosts: HostChange[];
  protocols: ProtocolChange[];
  conversations: ConversationChange[];
}

function normalizeAddress(address: string): string {
  const lower = address.toLowerCase();
  if (!lower.includes(':')) return lower;
  try {
    const host = new URL(`http://[${lower}]/`).hostname;
    return host.slice(1, -1);
  } catch {
    return lower;
  }
}

function stringSet(values: string[]): string[] {
  const byKey = new Map<string, string>();
  for (const value of values) {
    const key = value.toLowerCase();
    if (!byKey.has(key)) byKey.set(key, value);
  }
  return [...byKey.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value);
}

function sameStrings(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value, i) => value.toLowerCase() === b[i].toLowerCase());
}

function status<T>(before: T | null, after: T | null, same: (a: T, b: T) => boolean): ChangeStatus {
  if (before === null) return 'new';
  if (after === null) return 'missing';
  return same(before, after) ? 'same' : 'changed';
}

function hostNames(host: ComparisonSource['hosts'][number]): string[] {
  return stringSet(host.names);
}

function hostProtocols(host: ComparisonSource['hosts'][number]): string[] {
  return stringSet(host.protocols);
}

function protocolMap(source: ComparisonSource): Map<string, { proto: string; packets: number; bytes: number }> {
  return new Map(source.topProtocols.map((stat) => [stat.proto.toLowerCase(), stat]));
}

interface Endpoint {
  address: string;
  port: number | null;
}

function endpointKey(endpoint: Endpoint): string {
  return JSON.stringify([normalizeAddress(endpoint.address), endpoint.port]);
}

function endpointLabel(endpoint: Endpoint): string {
  const address = normalizeAddress(endpoint.address);
  const host = address.includes(':') ? `[${address}]` : address;
  return endpoint.port === null ? host : `${host}:${endpoint.port}`;
}

function conversationIdentity(conversation: ComparisonSource['conversations'][number]): {
  key: string;
  endpointA: string;
  endpointB: string;
} {
  const endpoints: Endpoint[] = [
    { address: conversation.a, port: conversation.aPort },
    { address: conversation.b, port: conversation.bPort },
  ];
  endpoints.sort((a, b) => endpointKey(a).localeCompare(endpointKey(b)));
  return {
    key: JSON.stringify([conversation.transport, endpointKey(endpoints[0]), endpointKey(endpoints[1])]),
    endpointA: endpointLabel(endpoints[0]),
    endpointB: endpointLabel(endpoints[1]),
  };
}

function conversationGroups(source: ComparisonSource): Map<string, ComparisonSource['conversations']> {
  const groups = new Map<string, ComparisonSource['conversations']>();
  for (const conversation of [...source.conversations].sort((a, b) => a.start - b.start || a.firstFrame - b.firstFrame)) {
    const { key } = conversationIdentity(conversation);
    const group = groups.get(key) ?? [];
    group.push(conversation);
    groups.set(key, group);
  }
  return groups;
}

function conversationSummary(conversation: ComparisonSource['conversations'][number]): ConversationSummary {
  return {
    packets: conversation.packetsAB + conversation.packetsBA,
    bytes: conversation.bytesAB + conversation.bytesBA,
    duration: Math.max(0, conversation.end - conversation.start),
    appProtocol: conversation.appProtocol,
    protocols: stringSet(conversation.protocols),
  };
}

/** Retain only the compact data needed for the second pass and final comparison. */
export function comparisonSource(model: AnalysisModel): ComparisonSource {
  return {
    capture: {
      fileName: model.capture.fileName,
      analyzedBytes: model.capture.analyzedBytes,
      partial: model.capture.partial,
      packetCount: model.capture.packetCount,
      duration: model.capture.duration,
    },
    hosts: model.hosts.map((host) => ({ addr: host.addr, names: host.names.map((name) => name.name), protocols: host.protocols })),
    topProtocols: model.topProtocols.map(({ proto, packets, bytes }) => ({ proto, packets, bytes })),
    conversations: model.conversations.map((conversation) => ({
      transport: conversation.transport,
      a: conversation.a, aPort: conversation.aPort, b: conversation.b, bPort: conversation.bPort,
      packetsAB: conversation.packetsAB, bytesAB: conversation.bytesAB,
      packetsBA: conversation.packetsBA, bytesBA: conversation.bytesBA,
      start: conversation.start, end: conversation.end, firstFrame: conversation.firstFrame,
      appProtocol: conversation.appProtocol, protocols: conversation.protocols,
    })),
  };
}

function sameConversation(a: ConversationSummary, b: ConversationSummary): boolean {
  return a.packets === b.packets && a.bytes === b.bytes && Math.abs(a.duration - b.duration) < 0.000001
    && a.appProtocol.toLowerCase() === b.appProtocol.toLowerCase() && sameStrings(a.protocols, b.protocols);
}

export function compareCaptures(before: ComparisonSource, after: ComparisonSource): CaptureComparison {
  const beforeHosts = new Map(before.hosts.map((host) => [normalizeAddress(host.addr), host]));
  const afterHosts = new Map(after.hosts.map((host) => [normalizeAddress(host.addr), host]));
  const hosts = [...new Set([...beforeHosts.keys(), ...afterHosts.keys()])].sort().map((address): HostChange => {
    const a = beforeHosts.get(address) ?? null;
    const b = afterHosts.get(address) ?? null;
    const beforeNames = a ? hostNames(a) : [];
    const afterNames = b ? hostNames(b) : [];
    const beforeProtocols = a ? hostProtocols(a) : [];
    const afterProtocols = b ? hostProtocols(b) : [];
    return {
      key: address,
      address,
      status: status(a, b, () => sameStrings(beforeNames, afterNames) && sameStrings(beforeProtocols, afterProtocols)),
      beforeNames,
      afterNames,
      beforeProtocols,
      afterProtocols,
    };
  });

  const beforeProtocols = protocolMap(before);
  const afterProtocols = protocolMap(after);
  const protocols = [...new Set([...beforeProtocols.keys(), ...afterProtocols.keys()])].sort().map((key): ProtocolChange => {
    const a = beforeProtocols.get(key) ?? null;
    const b = afterProtocols.get(key) ?? null;
    return {
      key,
      protocol: b?.proto ?? a!.proto,
      status: status(a, b, (x, y) => x.packets === y.packets && x.bytes === y.bytes),
      before: a ? { packets: a.packets, bytes: a.bytes } : null,
      after: b ? { packets: b.packets, bytes: b.bytes } : null,
    };
  });

  const beforeConversations = conversationGroups(before);
  const afterConversations = conversationGroups(after);
  const conversations: ConversationChange[] = [];
  for (const key of [...new Set([...beforeConversations.keys(), ...afterConversations.keys()])].sort()) {
    const aGroup = beforeConversations.get(key) ?? [];
    const bGroup = afterConversations.get(key) ?? [];
    const representative = bGroup[0] ?? aGroup[0];
    const identity = conversationIdentity(representative);
    for (let i = 0; i < Math.max(aGroup.length, bGroup.length); i++) {
      const a = aGroup[i] ?? null;
      const b = bGroup[i] ?? null;
      const beforeSummary = a ? conversationSummary(a) : null;
      const afterSummary = b ? conversationSummary(b) : null;
      conversations.push({
        key: `${key}:${i + 1}`,
        transport: representative.transport,
        endpointA: identity.endpointA,
        endpointB: identity.endpointB,
        status: status(beforeSummary, afterSummary, sameConversation),
        before: beforeSummary,
        after: afterSummary,
      });
    }
  }

  return { before: before.capture, after: after.capture, hosts, protocols, conversations };
}

export function countChanges(rows: { status: ChangeStatus }[]): ChangeCounts {
  const counts: ChangeCounts = { new: 0, missing: 0, changed: 0, same: 0 };
  for (const row of rows) counts[row.status]++;
  return counts;
}
