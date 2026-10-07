// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useRef } from 'react';

export const CAPTURE_ACCEPT = '.pcap,.pcapng,.cap,.pcap.gz,.pcapng.gz,.ntar,.dmp,.erf,.snoop,application/vnd.tcpdump.pcap';

export function FileChoice({ label, file, onChange, accept, disabled, primary, showStatus = true }: {
  label: string;
  file: File | null;
  onChange: (file: File | null) => void;
  accept: string;
  disabled?: boolean;
  primary?: boolean;
  /** Immediate-open pickers do not keep a selected file to describe. */
  showStatus?: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <div className="file-choice">
      <button type="button" className={`btn${primary ? ' primary' : ''}`} disabled={disabled} onClick={() => ref.current?.click()}>
        {file ? 'Replace file' : label}
      </button>
      <input ref={ref} type="file" hidden aria-label={label} accept={accept} disabled={disabled}
        onChange={(e) => { onChange(e.target.files?.[0] ?? null); e.target.value = ''; }} />
      {showStatus && (file ? (
        <>
          <span className="file-choice-name" title={file.name}>{file.name}</span>
          <button type="button" className="btn small ghost" disabled={disabled} onClick={() => onChange(null)}>Clear</button>
        </>
      ) : (
        <span className="muted">No file selected</span>
      ))}
    </div>
  );
}
