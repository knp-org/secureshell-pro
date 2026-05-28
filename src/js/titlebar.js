// ═══════════════════════════════════════════════════════════
// Custom title bar — frameless window controls
// ═══════════════════════════════════════════════════════════

function getWindow() {
    return window.__TAURI__?.window?.getCurrentWindow?.() ?? null;
}

async function updateMaximizeButton(btn) {
    if (!btn) return;
    const win = getWindow();
    if (!win?.isMaximized) return;
    try {
        const maximized = await win.isMaximized();
        btn.classList.toggle('is-maximized', maximized);
        btn.setAttribute('aria-label', maximized ? 'Restore' : 'Maximize');
    } catch {
        btn.classList.remove('is-maximized');
        btn.setAttribute('aria-label', 'Maximize');
    }
}

export function initTitlebar() {
    const win = getWindow();
    if (!win) return;

    const dragEl = document.querySelector('.titlebar-drag');
    const minBtn = document.getElementById('win-minimize');
    const maxBtn = document.getElementById('win-maximize');
    const closeBtn = document.getElementById('win-close');

    if (dragEl) {
        dragEl.addEventListener('pointerdown', (e) => {
            if (e.button !== 0) return;
            if (e.target.closest('.titlebar-controls')) return;
            if (win.startDragging) {
                win.startDragging().catch(() => {});
            }
        });
        dragEl.addEventListener('dblclick', () => {
            win.toggleMaximize().then(() => updateMaximizeButton(maxBtn)).catch(() => {});
        });
    }

    minBtn?.addEventListener('click', () => {
        win.minimize().catch(() => {});
    });

    maxBtn?.addEventListener('click', () => {
        win.toggleMaximize().then(() => updateMaximizeButton(maxBtn)).catch(() => {});
    });

    closeBtn?.addEventListener('click', () => {
        win.close().catch(() => {});
    });

    updateMaximizeButton(maxBtn);

    if (win.onResized) {
        win.onResized(() => updateMaximizeButton(maxBtn));
    }
}
