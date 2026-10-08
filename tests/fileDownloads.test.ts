// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { beginFileDownload, endFileDownload, fileDownloadDisabled, fileDownloadLabel, idleFileDownloads } from '../src/app/views/fileDownloads';

const first = 'eo:http_6';
const second = 'eo:http_7';

describe('per-row file downloads', () => {
  it('does not disable the other Download button while one save is in progress', () => {
    const saving = beginFileDownload(idleFileDownloads(), first);
    expect(fileDownloadDisabled(saving, first)).toBe(true);
    expect(fileDownloadLabel(saving, first)).toBe('Saving…');
    expect(fileDownloadDisabled(saving, second)).toBe(false);
    expect(fileDownloadLabel(saving, second)).toBe('Download');
  });

  it('keeps a second save working without clearing the first row', () => {
    const both = beginFileDownload(beginFileDownload(idleFileDownloads(), first), second);
    expect(fileDownloadDisabled(both, first)).toBe(true);
    expect(fileDownloadDisabled(both, second)).toBe(true);
    expect(both.busy.size).toBe(2);
  });

  it('records a failure on the row that failed and clears only that busy state', () => {
    const both = beginFileDownload(beginFileDownload(idleFileDownloads(), first), second);
    const failed = endFileDownload(both, first, 'synthetic failure');
    expect(fileDownloadDisabled(failed, first)).toBe(false);
    expect(fileDownloadLabel(failed, first)).toBe('Download');
    expect(failed.errors.get(first)).toBe('synthetic failure');
    expect(fileDownloadDisabled(failed, second)).toBe(true);
    expect(failed.errors.has(second)).toBe(false);
    const retried = beginFileDownload(failed, first);
    expect(retried.errors.has(first)).toBe(false);
    expect(fileDownloadDisabled(retried, first)).toBe(true);
    expect(fileDownloadDisabled(retried, second)).toBe(true);
  });

  it('returns a finished row to Download without dropping another row error', () => {
    const savingSecond = beginFileDownload(idleFileDownloads(), second);
    const failedFirst = endFileDownload(beginFileDownload(savingSecond, first), first, 'kept');
    const done = endFileDownload(failedFirst, second, null);
    expect(done.busy.size).toBe(0);
    expect(done.errors.get(first)).toBe('kept');
    expect(fileDownloadDisabled(done, second)).toBe(false);
    expect(fileDownloadLabel(done, second)).toBe('Download');
  });
});
