// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { fingerprint, hexToBytes, parseCertificate } from '../src/engine/x509';

// Self-signed P-256 certificate (openssl) with DNS and IP subject alternative names.
const CERT_HEX = '308201df30820185a0030201020214189ffc7a73300ecddd018ca4dbe23e85d8c184d1300a06082a8648ce3d040302302f3115301306035504030c0c746573742e6578616d706c6531163014060355040a0c0d4573747564656c792054657374301e170d3236313032393130353233375a170d3336313032363130353233375a302f3115301306035504030c0c746573742e6578616d706c6531163014060355040a0c0d4573747564656c7920546573743059301306072a8648ce3d020106082a8648ce3d03010703420004d6e13b6d54fbeb611938c9c442b430392e3110500becf8789ebf841c0f771c32a03ada327678b18082a6e08e4592f62560a486b000cc2bb5da0295f7ec230c83a37f307d301d0603551d0e0416041499ed06981472ab685d1dc90c332bede32f3c4bcf301f0603551d2304183016801499ed06981472ab685d1dc90c332bede32f3c4bcf300f0603551d130101ff040530030101ff302a0603551d1104233021820c746573742e6578616d706c65820b616c742e6578616d706c658704c0000207300a06082a8648ce3d040302034800304502200d16aa9e73fb9a6dc0129db5a29aebb4eba856e5938f740dbd6f776552ea2f0f022100fd1fb0f19ccde3832119427d7573a1b02848990adea076d1c8d10a72acd0956b';

describe('hexToBytes', () => {
  it('ignores separators and case', () => {
    expect(Array.from(hexToBytes('0A:ff 10'))).toEqual([0x0a, 0xff, 0x10]);
  });

  it('drops a trailing odd nibble instead of inventing a byte', () => {
    expect(Array.from(hexToBytes('abc'))).toEqual([0xab]);
    expect(hexToBytes('').length).toBe(0);
  });
});

describe('parseCertificate', () => {
  const der = hexToBytes(CERT_HEX);

  it('reads identity, validity, algorithms and alternative names', () => {
    const cert = parseCertificate(der, 7, 2);
    expect(cert.error).toBeNull();
    expect(cert).toMatchObject({
      frame: 7,
      index: 2,
      commonName: 'test.example',
      subject: 'CN=test.example, O=Estudely Test',
      issuer: 'CN=test.example, O=Estudely Test',
      publicKeyAlgorithm: 'EC',
      signatureAlgorithm: 'ecdsa-with-SHA256',
    });
    expect(cert.notBefore).toMatch(/^2026-10-29 \d\d:\d\d:\d\d UTC$/);
    expect(cert.notAfter).toMatch(/^2036-10-26 \d\d:\d\d:\d\d UTC$/);
    expect(cert.serial).toBe('189ffc7a73300ecddd018ca4dbe23e85d8c184d1');
    expect(cert.san).toEqual(['test.example', 'alt.example', '192.0.2.7']);
  });

  it('computes a colon-separated SHA-256 fingerprint', async () => {
    expect(await fingerprint(der)).toBe('19:F4:AB:FE:51:C4:8E:03:98:4A:2B:78:18:5F:AB:5A:79:0B:2F:C4:B0:E7:6B:1B:BF:60:59:79:D8:89:B1:DB'.toLowerCase());
  });

  it('reports an error rather than throwing on truncated input', () => {
    for (const cut of [0, 1, 3, 20, der.length >> 1, der.length - 1]) {
      const cert = parseCertificate(der.subarray(0, cut), 1, 0);
      expect(cert.error).toEqual(expect.any(String));
      expect(cert.san).toEqual([]);
    }
  });

  it('reports an error for garbage that is not a certificate', () => {
    expect(parseCertificate(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x05]), 1, 0).error).not.toBeNull();
    expect(parseCertificate(new Uint8Array([0xff, 0xff, 0xff, 0xff]), 1, 0).error).not.toBeNull();
  });
});
