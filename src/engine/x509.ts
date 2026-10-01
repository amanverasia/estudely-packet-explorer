// Minimal X.509 (DER) reader for certificates observed in cleartext TLS
// handshakes. It extracts display fields only and never validates trust.
import type { Certificate } from './types';

interface Node {
  tag: number;
  start: number; // content start
  end: number; // content end
  constructed: boolean;
}

class DerError extends Error {}

function readNode(b: Uint8Array, pos: number, limit: number): Node {
  if (pos + 2 > limit) throw new DerError('truncated DER header');
  const tag = b[pos];
  let len = b[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw new DerError('unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i];
    p += n;
  }
  if (p + len > limit) throw new DerError('DER element exceeds buffer');
  return { tag, start: p, end: p + len, constructed: (tag & 0x20) !== 0 };
}

function children(b: Uint8Array, n: Node): Node[] {
  const out: Node[] = [];
  let p = n.start;
  while (p < n.end) {
    const c = readNode(b, p, n.end);
    out.push(c);
    p = c.end;
  }
  return out;
}

function oid(b: Uint8Array, n: Node): string {
  const parts: number[] = [];
  let v = 0;
  for (let i = n.start; i < n.end; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      if (parts.length === 0) {
        parts.push(v < 80 ? Math.floor(v / 40) : 2, v < 80 ? v % 40 : v - 80);
      } else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

function text(b: Uint8Array, n: Node): string {
  const bytes = b.subarray(n.start, n.end);
  if (n.tag === 0x1e) {
    // BMPString (UTF-16BE)
    let s = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    return s;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

const ATTR: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
};

const ALG: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.2.1': 'EC', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
};

function name(b: Uint8Array, n: Node): { dn: string; cn: string | null } {
  const parts: string[] = [];
  let cn: string | null = null;
  for (const rdn of children(b, n)) {
    for (const atv of children(b, rdn)) {
      const [t, v] = children(b, atv);
      if (!t || !v) continue;
      const o = oid(b, t);
      const key = ATTR[o] ?? o;
      const val = text(b, v);
      if (key === 'CN' && cn === null) cn = val;
      parts.push(`${key}=${val}`);
    }
  }
  return { dn: parts.join(', '), cn };
}

function time(b: Uint8Array, n: Node): string {
  const s = text(b, n);
  // UTCTime YYMMDDHHMMSSZ / GeneralizedTime YYYYMMDDHHMMSSZ
  const m = n.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/.exec(s);
  if (!m) return s;
  let year = Number(m[1]);
  if (n.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return `${year}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6] ?? '00'} UTC`;
}

function ip(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join('.');
  if (bytes.length === 16) {
    const g: string[] = [];
    for (let i = 0; i < 16; i += 2) g.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    return g.join(':');
  }
  return hex(bytes);
}

export function hexToBytes(h: string): Uint8Array {
  const clean = h.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function parseCertificate(der: Uint8Array, frame: number, index: number): Certificate {
  const cert: Certificate = {
    frame, index, subject: null, issuer: null, commonName: null, serial: null, notBefore: null, notAfter: null,
    san: [], signatureAlgorithm: null, publicKeyAlgorithm: null, sha256: null, error: null,
  };
  try {
    const top = readNode(der, 0, der.length);
    const [tbs, sigAlg] = children(der, top);
    if (sigAlg) {
      const [o] = children(der, sigAlg);
      if (o) cert.signatureAlgorithm = ALG[oid(der, o)] ?? oid(der, o);
    }
    let f = children(der, tbs);
    if (f[0] && f[0].tag === 0xa0) f = f.slice(1); // explicit version
    const [serial, , issuer, validity, subject, spki, ...rest] = f;
    cert.serial = hex(der.subarray(serial.start, serial.end)).replace(/^00(?=[89a-f])/, '');
    const iss = name(der, issuer);
    cert.issuer = iss.dn;
    const sub = name(der, subject);
    cert.subject = sub.dn;
    cert.commonName = sub.cn;
    const [nb, na] = children(der, validity);
    cert.notBefore = time(der, nb);
    cert.notAfter = time(der, na);
    const [algSeq] = children(der, spki);
    const [algOid] = children(der, algSeq);
    cert.publicKeyAlgorithm = ALG[oid(der, algOid)] ?? oid(der, algOid);
    for (const r of rest) {
      if (r.tag !== 0xa3) continue;
      const [exts] = children(der, r);
      for (const ext of children(der, exts)) {
        const parts = children(der, ext);
        if (oid(der, parts[0]) !== '2.5.29.17') continue;
        const octets = parts[parts.length - 1];
        const seq = readNode(der, octets.start, octets.end);
        for (const gn of children(der, seq)) {
          const body = der.subarray(gn.start, gn.end);
          if (gn.tag === 0x82) cert.san.push(new TextDecoder().decode(body));
          else if (gn.tag === 0x87) cert.san.push(ip(body));
        }
      }
    }
  } catch (e) {
    cert.error = e instanceof Error ? e.message : String(e);
  }
  return cert;
}

export async function fingerprint(der: Uint8Array): Promise<string | null> {
  try {
    const digest = await crypto.subtle.digest('SHA-256', der as Uint8Array<ArrayBuffer>);
    return hex(new Uint8Array(digest)).replace(/(..)(?!$)/g, '$1:');
  } catch {
    return null;
  }
}
