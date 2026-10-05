// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import type { AnalysisModel } from '../src/engine/types';
import { summaryJson } from '../src/app/download';

function fixtureModel(): AnalysisModel {
  return {
    capture: {
      fileName: 'private-capture.pcap', fileSize: 100, analyzedBytes: 100, partial: false,
      fileType: 'pcap', linkType: 'Ethernet', packetCount: 5, startEpoch: '1780000000.123',
      duration: 2, timestampDigits: 6, nonMonotonicTimestamps: 0,
      interfaces: [{ id: 0, linkType: 'Ethernet', name: 'private-interface', packets: 5 }],
      wireBytes: 500, capturedBytes: 500, truncatedPackets: 0, malformedPackets: 0,
      expertErrorPackets: 0, fragmentPackets: 0, retransmissions: 0, outOfOrder: 0,
      lostSegments: 0, duplicateAcks: 0, incomplete: null, warnings: [],
      engine: { wireshark: '4.4', wiregasm: '1.9' }, analysisMs: 20,
    },
    filterIndex: { hostAddresses: ['10.0.0.7'] } as AnalysisModel['filterIndex'],
    protocolHierarchy: [{ proto: 'TCP', packets: 5, bytes: 500 }],
    topProtocols: [{ proto: 'TCP', packets: 5, bytes: 500 }],
    timeline: { origin: 0, end: 2, binSeconds: 1, bins: 2, series: [{ key: 'TCP', packets: [3, 2], bytes: [300, 200] }] },
    hosts: [{ addr: '10.0.0.7', macs: [{ mac: '00:11:22:33:44:55' }], arpMacs: ['00:11:22:33:44:55'], names: [{ name: 'device.private' }] } as AnalysisModel['hosts'][number]],
    conversations: [{ a: '10.0.0.7', b: '10.0.0.8', aPort: 51000, bPort: 443 } as AnalysisModel['conversations'][number]],
    dns: [{ client: '10.0.0.7', server: '10.0.0.8', qname: 'private.example', answers: [{ name: 'private.example', value: '10.0.0.8' }] } as AnalysisModel['dns'][number]],
    http: [{ host: 'private.example', uri: '/private/path', userAgent: 'private-agent', requestHeaders: ['Authorization: Bearer private-token'], responseHeaders: ['Set-Cookie: private-cookie'], location: 'https://private.example/redirect' } as AnalysisModel['http'][number]],
    tls: [{ sni: 'private.example', certificates: [{ subject: 'CN=Private Person', serial: 'private-serial', commonName: 'Private Person', san: ['private.example'], sha256: 'private-fingerprint' }] } as AnalysisModel['tls'][number]],
    arp: [{ mac: '00:11:22:33:44:55', ip: '10.0.0.7', targetIp: '10.0.0.8' } as AnalysisModel['arp'][number]],
    arpBindings: [{ ip: '10.0.0.7', macs: ['00:11:22:33:44:55'] } as AnalysisModel['arpBindings'][number]],
    dhcp: [{ clientMac: '00:11:22:33:44:55', hostname: 'private-host', requestedIp: '10.0.0.7', assignedIp: '10.0.0.7', dnsServers: ['10.0.0.8'], subnetMask: '255.255.255.0', leaseTime: 86400 } as AnalysisModel['dhcp'][number]],
    icmp: [{ src: '10.0.0.7', dst: '10.0.0.8' } as AnalysisModel['icmp'][number]],
    ssh: [{ clientVersion: 'SSH-2.0-private-client', serverVersion: 'SSH-2.0-private-server' } as AnalysisModel['ssh'][number]],
    quic: [{ client: '10.0.0.7', server: '10.0.0.8', sni: 'private.example' } as AnalysisModel['quic'][number]],
    unsupported: { httpPortsUndecoded: [], encryptedConversations: 1, quicConversations: 0, http2Packets: 0, httpWithGaps: [] },
  } as unknown as AnalysisModel;
}

describe('JSON exports', () => {
  it('uses an aggregate allowlist that omits capture and endpoint identifiers', () => {
    const model = fixtureModel();
    const json = summaryJson(model);
    const result = JSON.parse(json);

    expect(result.export).toMatchObject({ schemaVersion: 2, mode: 'aggregate' });
    expect(result.capture).toMatchObject({ packetCount: 5, interfaceCount: 1, wireBytes: 500 });
    expect(result.recordCounts).toMatchObject({ hosts: 1, conversations: 1, dns: 1, http: 1 });
    expect(result.capture).not.toHaveProperty('fileName');
    expect(result.capture).not.toHaveProperty('startEpoch');
    expect(result).not.toHaveProperty('hosts');
    expect(result).not.toHaveProperty('timeline');
    for (const value of ['private-capture.pcap', '10.0.0.7', 'private.example', '/private/path', 'private-token']) {
      expect(json).not.toContain(value);
    }
  });

  it('redacts known sensitive fields in a fresh detailed JSON object without mutating the model', () => {
    const model = fixtureModel();
    const before = structuredClone(model);
    const result = JSON.parse(summaryJson(model, { mode: 'detailed' }));
    const json = JSON.stringify(result);

    expect(result.export).toMatchObject({ mode: 'detailed', redaction: 'known sensitive fields replaced with [REDACTED]' });
    expect(result.hosts[0].addr).toBe('[REDACTED]');
    expect(result.http[0].requestHeaders).toBe('[REDACTED]');
    expect(result).not.toHaveProperty('filterIndex');
    expect(result.export.neverIncluded).toContain('Reassembled TCP/UDP stream payloads');
    for (const value of ['10.0.0.7', '00:11:22:33:44:55', 'private.example', '/private/path', 'private-agent', 'private-token', 'private-fingerprint', 'private-capture.pcap', '255.255.255.0', '86400']) {
      expect(json).not.toContain(value);
    }
    expect(model).toEqual(before);
  });

  it('allows an explicitly unredacted detailed export and discloses what it contains', () => {
    const result = JSON.parse(summaryJson(fixtureModel(), { mode: 'detailed', redactSensitive: false }));

    expect(result.export.redaction).toBe('not applied');
    expect(result.hosts[0].addr).toBe('10.0.0.7');
    expect(result.http[0].requestHeaders).toContain('Authorization: Bearer private-token');
    expect(result.dhcp[0].subnetMask).toBe('255.255.255.0');
    expect(result.export.sensitiveData).toContain('HTTP hosts, request paths, locations, user-agent strings, and headers');
    expect(result.export.redactionLimits).toContain('not anonymization');
  });
});
