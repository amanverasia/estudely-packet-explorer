import { useMemo } from 'react';
import type { TlsSession } from '../../engine/types';
import { BarList } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Note, Panel, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { absTime, endpoint, num } from '../format';

/** "TLS 1.3 (0x0304)" -> "TLS 1.3" */
const short = (s: string | null | undefined) => (s ? s.replace(/\s*\(0x[0-9a-f]+\)$/i, '') : null);

export function Tls() {
  const { model, openDrawer } = useApp();
  const stats = useMemo(() => {
    const count = (f: (t: TlsSession) => string | null) => {
      const m = new Map<string, number>();
      for (const t of model.tls) { const k = f(t); if (k !== null) m.set(k, (m.get(k) ?? 0) + 1); }
      return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    };
    return {
      sni: count((t) => t.sni ?? (t.clientHelloFrame !== null ? '(no SNI sent)' : null)),
      versions: count((t) => short(t.negotiated?.version) ?? null),
      ciphers: count((t) => short(t.negotiated?.cipherSuite) ?? null),
      alpn: count((t) => (t.negotiated ? t.negotiated.alpn ?? '(none selected)' : null)),
      noSh: model.tls.filter((t) => t.clientHelloFrame !== null && t.serverHelloFrame === null).length,
      certs: model.tls.filter((t) => t.certificateStatus === 'decoded').length,
      encryptedCerts: model.tls.filter((t) => t.certificateStatus === 'encrypted (TLS 1.3)').length,
      quic: model.tls.filter((t) => t.carrier === 'QUIC').length,
    };
  }, [model.tls]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const open = (t: TlsSession) => openDrawer({ title: `TLS ${t.sni ?? endpoint(t.server, t.serverPort)}`, frames: t.frames, focus: t.clientHelloFrame ?? t.serverHelloFrame ?? undefined, summary: <TlsSummary t={t} /> });

  const columns: Column<TlsSession>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (t) => t.clientHelloTime, render: (t) => <span className="mono">{absTime(model.capture.startEpoch, t.clientHelloTime, digits)}</span> },
    { key: 'client', header: 'Client', width: 'minmax(140px, 1fr)', value: (t) => t.client, render: (t) => <Addr addr={t.client} /> },
    { key: 'server', header: 'Server', width: 'minmax(170px, 1.2fr)', value: (t) => endpoint(t.server, t.serverPort), render: (t) => <span className="mono">{endpoint(t.server, t.serverPort)}</span> },
    { key: 'sni', header: 'SNI (requested name)', width: 'minmax(180px, 1.6fr)', value: (t) => t.sni },
    { key: 'carrier', header: 'Over', width: '64px', value: (t) => t.carrier },
    { key: 'offered', header: 'Versions offered', width: 'minmax(120px, 1fr)', value: (t) => (t.offered ? (t.offered.supportedVersions.length ? t.offered.supportedVersions.map(short).join(', ') : `${short(t.offered.legacyVersion)} (field only)`) : null) },
    { key: 'version', header: 'Negotiated', width: '96px', value: (t) => short(t.negotiated?.version), render: (t) => (t.negotiated ? short(t.negotiated.version) : <span className="muted">no ServerHello</span>) },
    { key: 'alpnOff', header: 'ALPN offered', width: 'minmax(110px, 1fr)', value: (t) => t.offered?.alpn.join(', ') },
    { key: 'alpn', header: 'ALPN selected', width: '100px', value: (t) => t.negotiated?.alpn },
    { key: 'cipher', header: 'Cipher suite', width: 'minmax(220px, 2fr)', value: (t) => short(t.negotiated?.cipherSuite) },
    { key: 'cert', header: 'Certificate', width: 'minmax(170px, 1.4fr)', value: (t) => t.certificates[0]?.commonName ?? t.certificateStatus,
      render: (t) => (t.certificates.length ? t.certificates[0].commonName ?? t.certificates[0].subject : <span className="muted">{t.certificateStatus}</span>) },
    { key: 'frames', header: 'Packets', width: '90px', value: (t) => t.frames.join(' '), render: (t) => <FramesLink frames={t.frames} onOpen={() => open(t)} /> },
  ];

  return (
    <>
      <ViewHead title="TLS">
        Handshake details visible without decryption. “Offered” values come from the client's ClientHello; “negotiated” values come from the server's ServerHello. Application data stays encrypted.
      </ViewHead>
      <Note>Certificates are shown only when they were sent in cleartext (TLS 1.2 and earlier). In TLS 1.3 and QUIC the certificate is encrypted. No decryption keys are used and nothing is looked up online; certificate trust is not checked.</Note>
      {!model.tls.length ? (
        <div className="panel empty"><strong>No TLS handshakes were decoded.</strong>Handshakes that happened before the capture started, or on ports Wireshark does not associate with TLS, will not appear.</div>
      ) : (
        <>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="Handshakes" value={num(model.tls.length)} small={stats.quic ? `${num(stats.quic)} over QUIC` : undefined} />
            <Fact label="Distinct SNI names" value={num(stats.sni.filter((s) => !s.key.startsWith('(')).length)} />
            <Fact label="No ServerHello seen" value={num(stats.noSh)} />
            <Fact label="Certificates decoded" value={num(stats.certs)} small="sessions" />
            <Fact label="Certificate encrypted" value={num(stats.encryptedCerts)} small="sessions" />
          </dl>
          <div className="grid-2">
            <Panel title="Server names requested" sub="SNI in ClientHello"><BarList items={stats.sni} limit={10} /></Panel>
            <Panel title="Negotiated versions" sub="From ServerHello"><BarList items={stats.versions} limit={6} color="var(--s7)" emptyText="No ServerHello decoded." /></Panel>
            <Panel title="Negotiated cipher suites" sub="From ServerHello"><BarList items={stats.ciphers} limit={8} color="var(--s3)" emptyText="No ServerHello decoded." /></Panel>
            <Panel title="Application protocol selected" sub="ALPN in ServerHello"><BarList items={stats.alpn} limit={6} color="var(--s2)" emptyText="No ServerHello decoded." /></Panel>
          </div>
          <section className="panel">
            <DataTable label="TLS handshakes" exportName="tls" rows={model.tls} columns={columns} rowKey={(t) => t.id} onRowClick={open} searchPlaceholder="Search SNI, addresses, versions, ciphers" />
          </section>
        </>
      )}
    </>
  );
}

function TlsSummary({ t }: { t: TlsSession }) {
  return (
    <section style={{ display: 'grid', gap: 12 }}>
      <dl className="kv">
        <dt>Client</dt><dd className="mono">{endpoint(t.client, t.clientPort)}</dd>
        <dt>Server</dt><dd className="mono">{endpoint(t.server, t.serverPort)}</dd>
        <dt>Carried over</dt><dd>{t.carrier}{t.stream !== null ? ` stream ${t.stream}` : ''}</dd>
        <dt>SNI</dt><dd>{t.sni ?? (t.clientHelloFrame === null ? 'unavailable (ClientHello not captured)' : 'not sent')}</dd>
      </dl>
      <div className="grid-2">
        <div>
          <h3 style={{ marginBottom: 6 }}>Offered by client</h3>
          {t.offered ? (
            <dl className="kv">
              <dt>Packet</dt><dd>#{t.clientHelloFrame}</dd>
              <dt>Version field</dt><dd>{t.offered.legacyVersion ?? 'unavailable'}</dd>
              <dt>supported_versions</dt><dd>{t.offered.supportedVersions.join(', ') || 'extension not sent'}</dd>
              <dt>ALPN</dt><dd>{t.offered.alpn.join(', ') || 'not sent'}</dd>
              <dt>Cipher suites</dt><dd>{t.offered.cipherSuites.length} offered</dd>
            </dl>
          ) : <p className="muted">ClientHello not captured.</p>}
        </div>
        <div>
          <h3 style={{ marginBottom: 6 }}>Negotiated by server</h3>
          {t.negotiated ? (
            <dl className="kv">
              <dt>Packet</dt><dd>#{t.serverHelloFrame}</dd>
              <dt>Version</dt><dd>{t.negotiated.version ?? 'unavailable'}<br /><span className="muted">from the {t.negotiated.versionSource}</span></dd>
              <dt>ALPN</dt><dd>{t.negotiated.alpn ?? 'none selected'}</dd>
              <dt>Cipher suite</dt><dd>{t.negotiated.cipherSuite ?? 'unavailable'}</dd>
            </dl>
          ) : <p className="muted">No ServerHello was captured for this handshake.</p>}
        </div>
      </div>
      {t.offered && t.offered.cipherSuites.length > 0 && (
        <details>
          <summary>All {t.offered.cipherSuites.length} offered cipher suites</summary>
          <pre className="headers">{t.offered.cipherSuites.join('\n')}</pre>
        </details>
      )}
      <div>
        <h3 style={{ marginBottom: 6 }}>Certificates</h3>
        {t.certificates.length ? t.certificates.map((c) => (
          <dl className="kv" key={c.index} style={{ marginBottom: 10 }}>
            <dt>#{c.index + 1} subject</dt><dd>{c.subject ?? 'unavailable'}</dd>
            <dt>Issuer</dt><dd>{c.issuer ?? 'unavailable'}</dd>
            <dt>Valid</dt><dd>{c.notBefore ?? '?'} to {c.notAfter ?? '?'}</dd>
            <dt>Names (SAN)</dt><dd>{c.san.join(', ') || 'none'}</dd>
            <dt>Serial</dt><dd className="mono">{c.serial ?? '—'}</dd>
            <dt>Key / signature</dt><dd>{c.publicKeyAlgorithm ?? '?'} / {c.signatureAlgorithm ?? '?'}</dd>
            <dt>SHA-256</dt><dd className="mono" style={{ fontSize: 11 }}>{c.sha256 ?? 'unavailable'}</dd>
            {c.error && <><dt>Parse note</dt><dd>Partially decoded: {c.error}</dd></>}
          </dl>
        )) : <p className="muted">{t.certificateStatus === 'encrypted (TLS 1.3)' ? 'The certificate was sent encrypted (TLS 1.3 / QUIC), so it is not visible.' : 'No Certificate message was captured.'}</p>}
      </div>
    </section>
  );
}
