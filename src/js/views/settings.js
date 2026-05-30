// ═══════════════════════════════════════════════════════════
// Settings View
//
// Renders the four settings sections using shared helpers.
// Each section is a self-contained config → HTML pipeline.
// ═══════════════════════════════════════════════════════════

import { icons }     from '../utils/icons.js';
import { showToast } from '../components/toast.js';
import { renderCustomSelect, initCustomSelect } from '../components/custom-select.js';
import {
    applyAccent,
    getCurrentAccentId,
    getAccentTerminalCursor,
    renderAccentSwatches,
} from '../utils/accent-themes.js';
import * as api      from '../api.js';
import { showConfirm } from '../components/modal.js';

// ─── Section builders ──────────────────────────────────────

function lanSyncSection() {
    return `
        <div class="settings-section">
            <h3>${icons.cloud()} LAN Sync</h3>
            <p class="settings-section-desc">
                Sync connections and SSH keys with your Android app over Wi-Fi.
                Pair once by scanning a QR; secrets stay end-to-end encrypted.
            </p>
            <div class="setting-row">
                <div class="setting-label">
                    <span class="title">Paired devices</span>
                    <span class="desc" id="lan-peers-summary">Loading…</span>
                </div>
                <button class="btn btn-primary btn-sm" id="set-pair-device">Pair new device</button>
            </div>
            <div id="lan-peers-list" class="lan-peers-list"></div>
        </div>`;
}

function securitySection() {
    return `
        <div class="settings-section">
            <h3>${icons.lock()} Security</h3>
            <div class="setting-row">
                <div class="setting-label">
                    <span class="title">Master Password</span>
                    <span class="desc">Protect your encrypted keystore</span>
                </div>
                <button class="btn btn-secondary btn-sm" id="set-change-pwd">Change Password</button>
            </div>
        </div>`;
}

function appearanceSection() {
    const themeOpts = [
        { value: 'dark',  text: 'Dark' },
        { value: 'light', text: 'Light' },
    ];
    const fontOpts = [10,11,12,13,14,15,16,18,20].map(s => ({ value: String(s), text: `${s}px` }));
    return `
        <div class="settings-section">
            <h3>${icons.sun()} Appearance</h3>
            <div class="setting-row">
                <div class="setting-label">
                    <span class="title">Theme</span>
                    <span class="desc">Application color scheme</span>
                </div>
                ${renderCustomSelect('set-theme', themeOpts, 'dark')}
            </div>
            <div class="setting-row">
                <div class="setting-label">
                    <span class="title">Font Size</span>
                    <span class="desc">Terminal and UI font size</span>
                </div>
                ${renderCustomSelect('set-fontsize', fontOpts, '14', 'csel--sm')}
            </div>
            <div class="setting-row setting-row--accent">
                <div class="setting-label">
                    <span class="title">Accent color</span>
                    <span class="desc">Buttons, links, and highlights</span>
                </div>
                <div class="accent-swatches" id="accent-swatches" role="group" aria-label="Accent color">
                    ${renderAccentSwatches('gold')}
                </div>
            </div>
        </div>`;
}


function aboutSection() {
    return `
        <div class="settings-section">
            <h3>${icons.info()} About</h3>
            <div class="setting-row">
                <div class="setting-label">
                    <span class="title">SecureShell</span>
                    <span class="desc">Encrypted SSH connection manager</span>
                </div>
                <span class="version-info" id="app-version">v…</span>
            </div>
        </div>`;
}

// ─── Event wiring ──────────────────────────────────────────

async function bindEvents() {
    document.getElementById('set-change-pwd')?.addEventListener('click', openChangePasswordModal);
    document.getElementById('set-pair-device')?.addEventListener('click', openPairingModal);
    refreshPeers();

    const versionEl = document.getElementById('app-version');
    if (versionEl) {
        window.__TAURI__?.app?.getVersion?.().then(v => { versionEl.textContent = `v${v}`; });
    }

    // Load saved settings and apply
    const savedTheme  = await api.getSetting('theme');
    const savedFont   = await api.getSetting('font_size');
    const savedAccent = await api.getSetting('accent');

    const themeSel = initCustomSelect('set-theme', async (v) => {
        await api.setSetting('theme', v);
        applyTheme(v);
        showToast(`Theme set to ${v}`, 'success');
    });
    if (themeSel && savedTheme) themeSel.setValue(savedTheme, true);

    const fontSel = initCustomSelect('set-fontsize', async (v) => {
        await api.setSetting('font_size', v);
        applyFontSize(parseInt(v, 10));
        showToast(`Font size set to ${v}px`, 'success');
    });
    if (fontSel && savedFont) fontSel.setValue(savedFont, true);

    bindAccentSwatches();
}

function syncAccentSwatchUI(id) {
    const wrap = document.getElementById('accent-swatches');
    if (!wrap) return;
    wrap.querySelectorAll('.accent-swatch').forEach(btn => {
        const on = btn.dataset.accent === id;
        btn.classList.toggle('is-selected', on);
        btn.setAttribute('aria-pressed', String(on));
    });
}

function bindAccentSwatches() {
    const wrap = document.getElementById('accent-swatches');
    if (!wrap) return;

    syncAccentSwatchUI(getCurrentAccentId());

    wrap.querySelectorAll('.accent-swatch').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.accent;
            if (!id || id === getCurrentAccentId()) return;
            applyAccent(id);
            await api.setSetting('accent', id);
            syncAccentSwatchUI(id);
            showToast(`Accent set to ${btn.title}`, 'success');
        });
    });
}

async function refreshPeers() {
    try {
        const peers = await api.peersList();
        const summaryEl = document.getElementById('lan-peers-summary');
        const listEl    = document.getElementById('lan-peers-list');
        if (!summaryEl || !listEl) return;
        if (peers.length === 0) {
            summaryEl.textContent = 'No devices paired';
            listEl.innerHTML = '';
            return;
        }
        summaryEl.textContent = `${peers.length} paired`;
        listEl.innerHTML = peers.map(p => {
            const isAndroidCompanion = p.pk_hex === 'android-companion';
            return `
            <div class="lan-peer-row" data-id="${escAttr(p.id)}">
                <div>
                    <div class="lan-peer-label">${escHtml(p.label)}</div>
                    <div class="lan-peer-sub">${escHtml(p.id)} · ${isAndroidCompanion ? 'sync from Android' : `last sync ${p.last_synced_at ? new Date(p.last_synced_at).toLocaleString() : 'never'}`}</div>
                </div>
                <div class="lan-peer-actions">
                    <button class="btn btn-primary btn-sm" data-sync="${escAttr(p.id)}" ${isAndroidCompanion ? 'disabled title="Start sync from the Android app"' : ''}>Sync now</button>
                    <button class="btn btn-ghost btn-sm"   data-remove="${escAttr(p.id)}">Remove</button>
                </div>
            </div>
        `;
        }).join('');
        listEl.querySelectorAll('[data-sync]').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.dataset.sync;
                btn.disabled = true;
                btn.textContent = 'Syncing…';
                try {
                    const r = await api.syncNow(id);
                    showToast(`Synced with ${r.peer_label} (pulled ${r.pulled}, pushed ${r.pushed})`, 'success');
                } catch (err) {
                    showToast('Sync failed: ' + err, 'error');
                }
                btn.disabled = false;
                btn.textContent = 'Sync now';
                refreshPeers();
            });
        });
        listEl.querySelectorAll('[data-remove]').forEach(btn => {
            btn.addEventListener('click', async () => {
                const ok = await showConfirm({
                    title: 'Remove device',
                    message: 'Remove this paired device?',
                    confirmText: 'Remove',
                    danger: true,
                });
                if (!ok) return;
                await api.peerRemove(btn.dataset.remove);
                refreshPeers();
            });
        });
    } catch (err) {
        console.error('peers list:', err);
    }
}

async function openPairingModal() {
    let invite;
    try {
        invite = await api.pairingStart();
    } catch (err) {
        showToast('Failed to start pairing: ' + err, 'error');
        return;
    }

    const overlay = document.createElement('div');
    overlay.className = 'pair-overlay';
    overlay.innerHTML = `
        <div class="pair-modal">
            <h3>Pair a new device</h3>
            <p class="pair-desc">Scan this QR code with the Android app, then confirm the 6-digit code matches on both devices.</p>
            <div class="pair-qr">${invite.qr_svg}</div>
            <div class="pair-meta">
                <span>IP</span><code>${escHtml(invite.ip)}</code>
                <span>Port</span><code>${invite.port}</code>
            </div>
            <div class="pair-status" id="pair-status">Waiting for Android device…</div>
            <div class="pair-actions">
                <button class="btn btn-secondary" id="pair-cancel">Cancel</button>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    let stopped = false;
    const statusEl = overlay.querySelector('#pair-status');
    const actionsEl = overlay.querySelector('.pair-actions');

    const finish = async (confirmed) => {
        stopped = true;
        try {
            if (confirmed === null) {
                await api.pairingCancel();
            } else {
                await api.pairingConfirm(confirmed);
            }
        } catch {}
        overlay.remove();
        refreshPeers();
    };

    overlay.querySelector('#pair-cancel').addEventListener('click', () => finish(null));

    // Poll status every 800ms
    while (!stopped) {
        await new Promise(r => setTimeout(r, 800));
        let s;
        try { s = await api.pairingStatus(); } catch { continue; }
        if (stopped) break;
        if (s.state === 'awaiting_confirmation') {
            statusEl.innerHTML = `
                <div class="pair-sas">${escHtml(s.sas)}</div>
                <div class="pair-sas-sub">Confirm this matches the code on Android</div>
            `;
            actionsEl.innerHTML = `
                <button class="btn btn-danger" id="pair-no">Don't match</button>
                <button class="btn btn-primary" id="pair-yes">Match — pair</button>
            `;
            overlay.querySelector('#pair-yes').addEventListener('click', () => finish(true));
            overlay.querySelector('#pair-no').addEventListener('click',  () => finish(false));
            break; // stop polling; wait for user
        } else if (s.state === 'failed') {
            statusEl.textContent = 'Failed: ' + s.reason;
            actionsEl.innerHTML = `<button class="btn btn-secondary" id="pair-close">Close</button>`;
            overlay.querySelector('#pair-close').addEventListener('click', () => finish(null));
            break;
        }
    }
}

// ─── Change master password ────────────────────────────────

function openChangePasswordModal() {
    const overlay = document.createElement('div');
    overlay.className = 'pair-overlay';
    overlay.innerHTML = `
        <div class="pair-modal cpw-modal">
            <h3>Change Master Password</h3>
            <p class="pair-desc">
                Re-encrypts every saved password and private key under your new password.
                <strong>It cannot be recovered if you lose it.</strong>
            </p>
            <form class="cpw-form" autocomplete="off">
                <label class="cpw-field">
                    <span>Current password</span>
                    <input type="password" name="current" autocomplete="current-password" />
                </label>
                <label class="cpw-field">
                    <span>New password</span>
                    <input type="password" name="next" autocomplete="new-password" />
                </label>
                <label class="cpw-field">
                    <span>Confirm new password</span>
                    <input type="password" name="confirm" autocomplete="new-password" />
                </label>
                <div class="cpw-error" id="cpw-error"></div>
                <div class="pair-actions">
                    <button type="button" class="btn btn-secondary" id="cpw-cancel">Cancel</button>
                    <button type="submit" class="btn btn-primary cpw-submit-btn" id="cpw-submit">
                        <svg class="cpw-spinner" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.55"/></svg>
                        <svg class="cpw-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                        <span class="cpw-submit-label">Change password</span>
                    </button>
                </div>
            </form>
        </div>`;
    document.body.appendChild(overlay);

    const form     = overlay.querySelector('.cpw-form');
    const current  = overlay.querySelector('input[name="current"]');
    const next     = overlay.querySelector('input[name="next"]');
    const confirm  = overlay.querySelector('input[name="confirm"]');
    const errEl       = overlay.querySelector('#cpw-error');
    const submitEl    = overlay.querySelector('#cpw-submit');
    const submitLabel = submitEl.querySelector('.cpw-submit-label');

    const close = () => overlay.remove();
    overlay.querySelector('#cpw-cancel').addEventListener('click', close);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    current.focus();

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errEl.textContent = '';
        if (!current.value)              { errEl.textContent = 'Enter your current password'; return; }
        if (next.value.length < 8)       { errEl.textContent = 'New password must be at least 8 characters'; return; }
        if (next.value !== confirm.value){ errEl.textContent = 'New passwords do not match'; return; }
        if (next.value === current.value){ errEl.textContent = 'New password must differ from the current one'; return; }

        submitEl.disabled = true;
        submitEl.classList.add('is-loading');
        submitLabel.textContent = 'Re-encrypting…';
        await new Promise(r => setTimeout(r, 30));
        try {
            await api.vaultChangePassword(current.value, next.value);
            submitEl.classList.remove('is-loading');
            submitEl.classList.add('is-success');
            submitLabel.textContent = 'Done';
            await new Promise(r => setTimeout(r, 600));
            close();
            showToast('Master password changed', 'success');
        } catch (err) {
            submitEl.classList.remove('is-loading');
            errEl.textContent = String(err);
            submitEl.disabled = false;
            submitLabel.textContent = 'Change password';
            current.select();
        }
    });
}

function escHtml(s){ return (s ?? '').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escAttr(s){ return (s ?? '').toString().replace(/&/g,'&amp;').replace(/"/g,'&quot;'); }

// ─── Theme & Font helpers ──────────────────────────────────

const LIGHT_TERMINAL_THEME = {
    background: '#fefefe',
    foreground: '#1c1917',
    cursor: '#b45309',
    selectionBackground: 'rgba(180, 83, 9, 0.15)',
    black: '#1c1917',
    red: '#dc2626',
    green: '#16a34a',
    yellow: '#b45309',
    blue: '#2563eb',
    magenta: '#9333ea',
    cyan: '#0891b2',
    white: '#f5f5f4',
    brightBlack: '#44403c',
    brightRed: '#ef4444',
    brightGreen: '#22c55e',
    brightYellow: '#d97706',
    brightBlue: '#3b82f6',
    brightMagenta: '#a855f7',
    brightCyan: '#06b6d4',
    brightWhite: '#fafaf9',
};

const DARK_TERMINAL_THEME = {
    background: '#0a0a0c',
    foreground: '#cdd6f4',
    cursor: '#eab308',
    selectionBackground: 'rgba(234, 179, 8, 0.3)',
    black: '#1e1e2e',
    red: '#f38ba8',
    green: '#a6e3a1',
    yellow: '#f9e2af',
    blue: '#89b4fa',
    magenta: '#f5c2e7',
    cyan: '#94e2d5',
    white: '#bac2de',
};

export function getTerminalTheme() {
    const base = document.documentElement.dataset.theme === 'light'
        ? { ...LIGHT_TERMINAL_THEME }
        : { ...DARK_TERMINAL_THEME };
    base.cursor = getAccentTerminalCursor();
    const accentDim = getComputedStyle(document.documentElement).getPropertyValue('--accent-dim').trim();
    if (accentDim) base.selectionBackground = accentDim;
    return base;
}

export function getTerminalFontSize() {
    return parseInt(document.documentElement.dataset.fontSize || '14', 10);
}

function applyTheme(theme) {
    if (theme === 'light') {
        document.documentElement.dataset.theme = 'light';
    } else {
        delete document.documentElement.dataset.theme;
    }
    applyAccent(getCurrentAccentId());
    window.dispatchEvent(new CustomEvent('appearance-changed'));
}

function applyFontSize(size) {
    document.documentElement.dataset.fontSize = String(size);
    window.dispatchEvent(new CustomEvent('appearance-changed'));
}

export async function loadAppearanceSettings() {
    try {
        const theme = await api.getSetting('theme');
        const fontSize = await api.getSetting('font_size');
        const accent = await api.getSetting('accent');
        if (theme) {
            if (theme === 'light') {
                document.documentElement.dataset.theme = 'light';
            } else {
                delete document.documentElement.dataset.theme;
            }
        }
        if (accent) applyAccent(accent);
        if (fontSize) applyFontSize(parseInt(fontSize, 10));
    } catch {}
}

// ─── Public entry ──────────────────────────────────────────

export function render(container) {
    container.innerHTML = `
        <div class="settings-container">
            <h2>Settings</h2>
            ${lanSyncSection()}
            ${securitySection()}
            ${appearanceSection()}
            ${aboutSection()}
        </div>
    `;
    bindEvents();
}
