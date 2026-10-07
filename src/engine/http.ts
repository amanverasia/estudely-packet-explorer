// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Pairs HTTP/1 and HTTP/2 records into exchanges.
import type { Conversation, HttpExchange } from './types';
import type { RawHttp, RawPacket } from './records';

export function correlateHttp(
  rawHttp: RawHttp[], pkt: (frame: number) => RawPacket | undefined, segs: (frame: number) => number[],
  convOfFrame: (frame: number) => number | null, conversations: Conversation[],
): HttpExchange[] {
  const http: HttpExchange[] = [];
  const pendingHttp = new Map<number, HttpExchange[]>();
  const pendingHttp2 = new Map<string, HttpExchange[]>();
  const requestExchangeByFrame = new Map<number, HttpExchange[]>();
  const requestByResponseFrame = new Map<number, number[]>();
  const http2Key = (stream: number, id: number) => `${stream}:${id}`;
  for (const h of rawHttp) {
    if (h.kind === 'req' && h.responseIn !== null) {
      const frames = requestByResponseFrame.get(h.responseIn) ?? [];
      if (!frames.includes(h.frame)) frames.push(h.frame);
      requestByResponseFrame.set(h.responseIn, frames);
    }
  }
  for (const h of rawHttp) {
    const p = pkt(h.frame);
    if (!p) continue;
    const convId = convOfFrame(h.frame);
    const stream = p.tcpStream;
    const frames = segs(h.frame);
    if (h.kind === 'req') {
      const ex: HttpExchange = {
        id: http.length, stream, http2StreamId: h.http2StreamId, convId, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        method: h.method, host: h.host, uri: h.uri, version: h.version, userAgent: h.userAgent, requestHeaders: h.headers,
        requestFrame: h.frame, requestTime: p.t, requestContentType: h.contentType, status: null, phrase: null,
        responseVersion: null, responseHeaders: [], contentType: null, contentLength: null, serverHeader: null,
        location: null, responseFrame: null, responseTime: null, state: 'no response seen', pairingWarning: null, decrypted: false, frames: [...frames],
      };
      http.push(ex);
      const sameFrame = requestExchangeByFrame.get(h.frame) ?? [];
      sameFrame.push(ex);
      requestExchangeByFrame.set(h.frame, sameFrame);
      if (stream !== null) {
        const q = h.http2StreamId === null
          ? pendingHttp.get(stream) ?? []
          : pendingHttp2.get(http2Key(stream, h.http2StreamId)) ?? [];
        q.push(ex);
        if (h.http2StreamId === null) pendingHttp.set(stream, q);
        else pendingHttp2.set(http2Key(stream, h.http2StreamId), q);
      }
    } else {
      // 1xx interim responses (except 101 Switching Protocols) do not complete a request.
      const interim = h.code !== null && h.code >= 100 && h.code < 200 && h.code !== 101;
      const q = stream === null ? undefined : h.http2StreamId === null
        ? pendingHttp.get(stream)
        : pendingHttp2.get(http2Key(stream, h.http2StreamId));
      const fifoCandidate = q?.[0];
      const reverseLinks = requestByResponseFrame.get(h.frame) ?? [];
      const linkedFrames = h.requestIn === null ? reverseLinks : [h.requestIn];
      const linkedExchange = linkedFrames
        .flatMap((frame) => requestExchangeByFrame.get(frame) ?? [])
        .find((candidate) => candidate.responseFrame === null
          && (stream === null || candidate.stream === stream)
          && candidate.http2StreamId === h.http2StreamId);
      const linkedFrame = h.requestIn ?? linkedExchange?.requestFrame ?? reverseLinks[0] ?? null;
      let ex: HttpExchange | undefined = linkedFrame === null ? fifoCandidate : linkedExchange;
      const pairingWarnings: string[] = [];
      if (h.requestIn !== null && reverseLinks.length > 0 && !reverseLinks.includes(h.requestIn)) {
        pairingWarnings.push(`Wireshark's request_in link points to packet ${h.requestIn}, but the request's response_in link points to packet${reverseLinks.length === 1 ? '' : 's'} ${reverseLinks.join(', ')}.`);
      }
      if (linkedFrame !== null && !ex) {
        pairingWarnings.push(`Wireshark links this response to request packet ${linkedFrame}, which is not an available request in the matching stream.`);
      }
      if (linkedFrame !== null && ex && fifoCandidate && ex !== fifoCandidate) {
        pairingWarnings.push(`Wireshark links this response to request packet ${ex.requestFrame}, while stream-order pairing would use packet ${fifoCandidate.requestFrame}.`);
      }
      if (ex && pairingWarnings.length) {
        ex.pairingWarning = [...new Set([...(ex.pairingWarning ? [ex.pairingWarning] : []), ...pairingWarnings])].join(' ');
      }
      if (!ex || interim) {
        if (interim && ex) {
          ex.frames.push(...frames);
          continue;
        }
        ex = {
          id: http.length, stream, http2StreamId: h.http2StreamId, convId, client: p.dst, clientPort: p.dport, server: p.src, serverPort: p.sport,
          method: null, host: null, uri: null, version: null, userAgent: null, requestHeaders: [], requestFrame: null,
          requestTime: null, requestContentType: null, status: null, phrase: null, responseVersion: null, responseHeaders: [],
          contentType: null, contentLength: null, serverHeader: null, location: null, responseFrame: null, responseTime: null,
          state: 'response without request', pairingWarning: pairingWarnings.length ? pairingWarnings.join(' ') : null, decrypted: false, frames: [],
        };
        http.push(ex);
      } else {
        ex.state = 'complete';
        if (q) {
          const pairedIndex = q.indexOf(ex);
          if (pairedIndex >= 0) q.splice(pairedIndex, 1);
        }
      }
      ex.status = h.code;
      ex.phrase = h.phrase;
      ex.responseVersion = h.version;
      ex.responseHeaders = h.headers;
      ex.contentType = h.contentType;
      ex.contentLength = h.contentLength;
      ex.serverHeader = h.server;
      ex.location = h.location;
      ex.responseFrame = h.frame;
      ex.responseTime = p.t;
      ex.frames.push(...frames);
    }
  }
  for (const exchange of http) {
    exchange.frames = [...new Set(exchange.frames)].sort((a, b) => a - b);
    if (exchange.convId !== null) conversations[exchange.convId].records.http++;
  }
  return http;
}
