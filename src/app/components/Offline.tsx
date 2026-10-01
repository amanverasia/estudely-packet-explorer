// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Offline copy status (start screen) and the "new version" prompt.
import { bytes } from '../format';
import { applyUpdate, usePwa } from '../pwa';

export function OfflineStatus() {
  const { offline } = usePwa();
  let text: string;
  switch (offline.kind) {
    case 'unsupported': text = 'This browser cannot keep an offline copy; the app needs the network to load.'; break;
    case 'installing': text = 'Saving the app and the Wireshark engine on this device so it works offline…'; break;
    case 'error': text = `No offline copy: ${offline.message}`; break;
    case 'ready': text = `Available offline. The app and engine${offline.usage !== null ? ` use ${bytes(offline.usage)} of` : ' are kept in'} this browser's storage; captures are never stored.`; break;
  }
  return <div data-testid="offline-status"><h3>Offline</h3>{text}</div>;
}

export function UpdateBanner({ captureOpen }: { captureOpen: boolean }) {
  const { updateWaiting, updatedElsewhere } = usePwa();
  if (!updateWaiting && !updatedElsewhere) return null;
  return (
    <div className="note info update-banner" role="status">
      <div>
        <b>{updateWaiting ? 'A new version is available.' : 'The app was updated in another tab.'}</b>
        {captureOpen && ' Reloading closes the open capture.'}
      </div>
      <button className="btn" onClick={() => (updateWaiting ? applyUpdate() : location.reload())}>
        {updateWaiting ? 'Reload to update' : 'Reload'}
      </button>
    </div>
  );
}
