import * as api from '../api.js';
import { escHtml, escAttr, generateId } from '../utils/helpers.js';
import { showToast } from '../components/toast.js';
import { showConfirm, showPrompt } from '../components/modal.js';

let container = null;
let sessionId = null;
let activeTransfers = 0;
let showHidden = { local: false, remote: false };
let filterQuery = { local: '', remote: '' };

const state = {
    local:  { path: '', entries: [], selected: new Set(), history: [], historyIdx: -1 },
    remote: { path: '', entries: [], selected: new Set(), history: [], historyIdx: -1 },
};

let contextMenu = null;
let contextMenuDismiss = null;
let actionsDropdown = null;
let actionsDropdownDismiss = null;

let currentTransferId = null;
let progressListenerBound = false;

// ─── Helpers ──────────────────────────────────────────────

function formatSize(bytes) {
    if (bytes === 0) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const val = bytes / Math.pow(1024, i);
    return `${val < 10 && i > 0 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
}

function formatPerms(mode) {
    const chars = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx'];
    const u = (mode >> 6) & 7, g = (mode >> 3) & 7, o = mode & 7;
    return `${chars[u]}${chars[g]}${chars[o]}`;
}

function formatDate(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    const month = d.getMonth() + 1;
    const day = d.getDate();
    const year = d.getFullYear();
    const h = d.getHours();
    const m = d.getMinutes();
    const ampm = h >= 12 ? 'PM' : 'AM';
    const h12 = h % 12 || 12;
    return `${month}/${day}/${year}, ${h12}:${String(m).padStart(2, '0')} ${ampm}`;
}

function fileKind(entry) {
    if (entry.is_dir) return 'folder';
    if (entry.is_symlink) return 'symlink';
    const ext = entry.name.includes('.') ? entry.name.split('.').pop().toLowerCase() : '';
    return ext || 'file';
}

function joinPath(base, name) {
    if (base.endsWith('/')) return base + name;
    return base + '/' + name;
}

function parentPath(p) {
    if (p === '/' || !p) return '/';
    const parts = p.replace(/\/+$/, '').split('/');
    parts.pop();
    return parts.join('/') || '/';
}

function pathSegments(p) {
    if (!p || p === '/') return [{ name: '/', path: '/' }];
    const parts = p.split('/').filter(Boolean);
    const segs = [{ name: '/', path: '/' }];
    let acc = '';
    for (const part of parts) {
        acc += '/' + part;
        segs.push({ name: part, path: acc });
    }
    return segs;
}

function fileIconHtml(entry) {
    if (entry.is_dir) {
        return '<span class="sftp-file-icon is-dir"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg></span>';
    }
    if (entry.is_symlink) {
        return '<span class="sftp-file-icon is-symlink"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></span>';
    }
    return '<span class="sftp-file-icon is-file"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>';
}

function findEntryByPath(side, path) {
    return state[side].entries.find(e => e.path === path) || null;
}

function getFilteredEntries(side) {
    let entries = state[side].entries;
    if (!showHidden[side]) {
        entries = entries.filter(e => !e.name.startsWith('.'));
    }
    const q = filterQuery[side]?.toLowerCase();
    if (q) {
        entries = entries.filter(e => e.name.toLowerCase().includes(q));
    }
    return entries;
}

function getSelectedEntry(side) {
    const sel = state[side].selected;
    if (sel.size !== 1) return null;
    const path = sel.values().next().value;
    return findEntryByPath(side, path);
}

// ─── History ──────────────────────────────────────────────

function pushHistory(side, path) {
    const s = state[side];
    if (s.history[s.historyIdx] === path) return;
    s.history = s.history.slice(0, s.historyIdx + 1);
    s.history.push(path);
    s.historyIdx = s.history.length - 1;
}

function canGoBack(side) { return state[side].historyIdx > 0; }
function canGoForward(side) { return state[side].historyIdx < state[side].history.length - 1; }

function goBack(side) {
    if (!canGoBack(side)) return;
    state[side].historyIdx--;
    navigateTo(side, state[side].history[state[side].historyIdx], true);
}
function goForward(side) {
    if (!canGoForward(side)) return;
    state[side].historyIdx++;
    navigateTo(side, state[side].history[state[side].historyIdx], true);
}

// ─── Transfer Progress ────────────────────────────────────

function setTransferBusy(busy) {
    if (busy) activeTransfers++;
    else activeTransfers = Math.max(0, activeTransfers - 1);
}

function showProgressOverlay(title, filename) {
    const overlay = container?.querySelector('.sftp-transfer-overlay');
    if (!overlay) return;
    overlay.style.display = 'flex';
    overlay.innerHTML = `
        <div class="sftp-transfer-card">
            <div class="sftp-transfer-title">${escHtml(title)}…</div>
            <div class="sftp-transfer-filename" title="${escAttr(filename)}">${escHtml(filename)}</div>
            <div class="sftp-progress-bg"><div class="sftp-progress-bar" style="width:0%"></div></div>
            <div class="sftp-transfer-stats">
                <span class="sftp-transfer-percent">0%</span>
                <span class="sftp-transfer-bytes">0 B</span>
            </div>
        </div>
    `;
}

function updateProgressOverlay(percentage, bytesTransferred, totalBytes) {
    const overlay = container?.querySelector('.sftp-transfer-overlay');
    if (!overlay) return;
    const bar = overlay.querySelector('.sftp-progress-bar');
    const pct = overlay.querySelector('.sftp-transfer-percent');
    const bytes = overlay.querySelector('.sftp-transfer-bytes');
    if (bar) bar.style.width = `${percentage}%`;
    if (pct) pct.textContent = `${percentage.toFixed(1)}%`;
    if (bytes) bytes.textContent = totalBytes > 0 ? `${formatSize(bytesTransferred)} / ${formatSize(totalBytes)}` : formatSize(bytesTransferred);
}

function hideProgressOverlay() {
    const overlay = container?.querySelector('.sftp-transfer-overlay');
    if (overlay) { overlay.style.display = 'none'; overlay.innerHTML = ''; }
}

function setupProgressListener() {
    if (progressListenerBound) return;
    const tauriEvent = window.__TAURI__?.event;
    if (tauriEvent) {
        tauriEvent.listen('sftp-progress', (event) => {
            const { transferId, bytesTransferred, totalBytes, percentage } = event.payload;
            if (transferId === currentTransferId) {
                updateProgressOverlay(percentage, bytesTransferred, totalBytes);
            }
        });
        progressListenerBound = true;
    }
}

// ─── Actions Dropdown ─────────────────────────────────────

function closeActionsDropdown() {
    if (actionsDropdownDismiss) {
        document.removeEventListener('pointerdown', actionsDropdownDismiss, true);
        document.removeEventListener('keydown', actionsDropdownDismiss);
        actionsDropdownDismiss = null;
    }
    if (actionsDropdown) {
        actionsDropdown.remove();
        actionsDropdown = null;
    }
}

function showActionsDropdown(anchorEl, side) {
    closeActionsDropdown();
    closeContextMenu();

    const entry = getSelectedEntry(side);
    const hasSelection = !!entry;
    const isConnected = !!sessionId;
    const hidden = showHidden[side];

    const menu = document.createElement('div');
    menu.className = 'sftp-context-menu sftp-actions-dropdown';
    menu.innerHTML = `
        ${hasSelection && isConnected ? `<button type="button" data-action="copy-to-target">Copy to target directory</button>` : ''}
        ${hasSelection ? `<button type="button" data-action="rename">Rename</button>` : ''}
        ${hasSelection ? `<button type="button" class="danger" data-action="delete">Delete</button>` : ''}
        ${hasSelection && isConnected ? `<div class="sftp-context-divider"></div>` : ''}
        <button type="button" data-action="refresh">Refresh</button>
        <button type="button" data-action="new-folder">New Folder</button>
        <button type="button" data-action="toggle-hidden">${hidden ? 'Hide Hidden Files' : 'Show Hidden Files'}</button>
        ${hasSelection ? `<button type="button" data-action="permissions">Edit Permissions</button>` : ''}
        <button type="button" data-action="select-all">Select All</button>
        <div class="sftp-context-divider"></div>
        <button type="button" class="danger" data-action="close-menu">Close</button>
    `;

    document.body.appendChild(menu);
    actionsDropdown = menu;

    const rect = anchorEl.getBoundingClientRect();
    const menuRect = menu.getBoundingClientRect();
    let left = rect.right - menuRect.width;
    let top = rect.bottom + 4;
    if (left < 8) left = 8;
    if (top + menuRect.height > window.innerHeight - 8) top = rect.top - menuRect.height - 4;
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;

    menu.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        closeActionsDropdown();

        switch (action) {
            case 'copy-to-target': handleCopyToTarget(side, entry); break;
            case 'rename':         handleRename(side, entry); break;
            case 'delete':         handleDelete(side, entry); break;
            case 'refresh':        refreshPane(side); break;
            case 'new-folder':     handleNewFolder(side); break;
            case 'toggle-hidden':  handleToggleHidden(side); break;
            case 'permissions':    handlePermissions(side, entry); break;
            case 'select-all':     handleSelectAll(side); break;
            case 'close-menu':     break;
        }
    });

    actionsDropdownDismiss = (e) => {
        if (e.type === 'keydown') { if (e.key === 'Escape') closeActionsDropdown(); return; }
        if (actionsDropdown && !actionsDropdown.contains(e.target) && !anchorEl.contains(e.target)) closeActionsDropdown();
    };
    setTimeout(() => {
        document.addEventListener('pointerdown', actionsDropdownDismiss, true);
        document.addEventListener('keydown', actionsDropdownDismiss);
    }, 0);
}

// ─── Context Menu ─────────────────────────────────────────

function closeContextMenu() {
    if (contextMenuDismiss) {
        document.removeEventListener('pointerdown', contextMenuDismiss, true);
        document.removeEventListener('keydown', contextMenuDismiss);
        contextMenuDismiss = null;
    }
    if (contextMenu) { contextMenu.remove(); contextMenu = null; }
}

function showContextMenu(x, y, side, entry) {
    closeContextMenu();
    closeActionsDropdown();

    const isConnected = !!sessionId;
    const hasEntry = !!entry;
    const targetLabel = side === 'local' ? 'Remote' : 'Local';

    const menu = document.createElement('div');
    menu.className = 'sftp-context-menu';
    menu.innerHTML = `
        ${hasEntry ? `
            <button type="button" data-action="open">Open</button>
            <button type="button" data-action="open-with">Open with…</button>
            ${isConnected ? `<button type="button" data-action="copy-to-target">Copy to ${escHtml(targetLabel)} directory</button>` : ''}
            <button type="button" data-action="rename">Rename</button>
            <button type="button" class="danger" data-action="delete">Delete</button>
            <div class="sftp-context-divider"></div>
        ` : ''}
        <button type="button" data-action="refresh">Refresh</button>
        <button type="button" data-action="new-folder">New Folder</button>
        ${hasEntry ? `<button type="button" data-action="permissions">Edit Permissions</button>` : ''}
    `;

    document.body.appendChild(menu);
    contextMenu = menu;

    const rect = menu.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - rect.width - 8))}px`;
    menu.style.top = `${Math.max(8, Math.min(y, window.innerHeight - rect.height - 8))}px`;

    menu.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        closeContextMenu();
        switch (action) {
            case 'open':           handleOpen(side, entry); break;
            case 'open-with':      handleOpenWith(side, entry); break;
            case 'copy-to-target': handleCopyToTarget(side, entry); break;
            case 'rename':         handleRename(side, entry); break;
            case 'delete':         handleDelete(side, entry); break;
            case 'refresh':        refreshPane(side); break;
            case 'new-folder':     handleNewFolder(side); break;
            case 'permissions':    handlePermissions(side, entry); break;
        }
    });

    contextMenuDismiss = (e) => {
        if (e.type === 'keydown') { if (e.key === 'Escape') closeContextMenu(); return; }
        if (contextMenu && !contextMenu.contains(e.target)) closeContextMenu();
    };
    setTimeout(() => {
        document.addEventListener('pointerdown', contextMenuDismiss, true);
        document.addEventListener('keydown', contextMenuDismiss);
    }, 0);
}

// ─── Actions ──────────────────────────────────────────────

async function handleOpen(side, entry) {
    if (!entry) return;
    if (entry.is_dir) { navigateTo(side, entry.path); return; }
    try {
        const content = side === 'remote' ? await api.sftpReadFile(sessionId, entry.path) : await api.localReadFile(entry.path);
        showFilePreview(entry.name, content);
    } catch (err) { showToast(`Cannot open: ${err}`, 'error'); }
}

function handleOpenWith(side, entry) {
    if (!entry) return;
    if (entry.is_dir) { navigateTo(side, entry.path); return; }
    showToast('Open with external application is not yet supported', 'info');
}

function handleCopyToTarget(side, entry) {
    if (!entry || !sessionId || activeTransfers > 0) return;
    const targetSide = side === 'local' ? 'remote' : 'local';
    const targetPath = state[targetSide].path;
    const label = side === 'local' ? 'Uploading' : 'Downloading';
    const transferId = generateId();
    currentTransferId = transferId;
    showProgressOverlay(label, entry.name);
    setTransferBusy(true);

    (async () => {
        try {
            const dest = joinPath(targetPath, entry.name);
            if (entry.is_dir) {
                if (side === 'local') await api.sftpUploadDir(sessionId, entry.path, dest, transferId);
                else await api.sftpDownloadDir(sessionId, entry.path, dest, transferId);
            } else {
                if (side === 'local') await api.sftpUpload(sessionId, entry.path, dest, transferId);
                else await api.sftpDownload(sessionId, entry.path, dest, transferId);
            }
            await new Promise(r => setTimeout(r, 300));
            showToast(`"${entry.name}" transferred`, 'success');
            refreshPane(targetSide);
        } catch (err) { showToast(`Transfer failed: ${err}`, 'error'); }
        finally {
            hideProgressOverlay();
            setTransferBusy(false);
            if (currentTransferId === transferId) currentTransferId = null;
        }
    })();
}

function handleRename(side, entry) {
    if (!entry) return;
    const pane = container.querySelector(`.sftp-pane[data-side="${side}"]`);
    const item = pane?.querySelector(`.sftp-file-item[data-path="${CSS.escape(entry.path)}"]`);
    if (!item) return;
    const nameEl = item.querySelector('.sftp-file-name-text');
    const original = entry.name;
    nameEl.innerHTML = `<input type="text" class="sftp-rename-input" value="${escAttr(original)}" />`;
    const input = nameEl.querySelector('input');
    input.focus();
    input.select();
    let committed = false;
    const commit = async () => {
        if (committed) return;
        committed = true;
        const newName = input.value.trim();
        if (!newName || newName === original) { nameEl.textContent = original; return; }
        const dir = parentPath(entry.path);
        try {
            if (side === 'remote') await api.sftpRename(sessionId, entry.path, joinPath(dir, newName));
            else await api.localRename(entry.path, joinPath(dir, newName));
            showToast(`Renamed to "${newName}"`, 'success');
            refreshPane(side);
        } catch (err) { showToast(`Rename failed: ${err}`, 'error'); nameEl.textContent = original; }
    };
    input.addEventListener('blur', commit, { once: true });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
        if (e.key === 'Escape') { input.value = original; input.blur(); }
    });
}

async function handleDelete(side, entry) {
    if (!entry) return;
    const ok = await showConfirm({ title: 'Delete', message: `Are you sure you want to delete "${entry.name}"?`, confirmText: 'Delete', danger: true });
    if (!ok) return;
    try {
        if (side === 'remote') await api.sftpDelete(sessionId, entry.path, entry.is_dir);
        else await api.localDelete(entry.path);
        showToast(`Deleted "${entry.name}"`, 'success');
        refreshPane(side);
    } catch (err) { showToast(`Delete failed: ${err}`, 'error'); }
}

async function handleNewFolder(side) {
    const name = await showPrompt({ title: 'New Folder', placeholder: 'Folder name', confirmText: 'Create' });
    if (!name?.trim()) return;
    const fullPath = joinPath(state[side].path, name.trim());
    try {
        if (side === 'remote') await api.sftpMkdir(sessionId, fullPath);
        else await api.localMkdir(fullPath);
        showToast(`Created folder "${name.trim()}"`, 'success');
        refreshPane(side);
    } catch (err) { showToast(`Failed to create folder: ${err}`, 'error'); }
}

function handleToggleHidden(side) {
    showHidden[side] = !showHidden[side];
    renderFileList(side);
}

function handleSelectAll(side) {
    const entries = getFilteredEntries(side);
    state[side].selected = new Set(entries.map(e => e.path));
    renderFileList(side);
}

function handlePermissions(side, entry) {
    if (!entry) return;
    showPermissionsModal(side, entry);
}

// ─── Permissions Modal ────────────────────────────────────

function showPermissionsModal(side, entry) {
    const mode = entry.permissions & 0o777;
    const overlay = document.createElement('div');
    overlay.className = 'sftp-preview-overlay';
    const bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
    const labels = ['Owner', 'Group', 'Others'];
    const cols = ['Read', 'Write', 'Execute'];
    let gridHtml = '<span></span>';
    cols.forEach(c => { gridHtml += `<span class="perm-header">${c}</span>`; });
    for (let row = 0; row < 3; row++) {
        gridHtml += `<span class="perm-label">${labels[row]}</span>`;
        for (let col = 0; col < 3; col++) {
            const bit = bits[row * 3 + col];
            gridHtml += `<label><input type="checkbox" data-bit="${bit}"${(mode & bit) ? ' checked' : ''} /></label>`;
        }
    }
    overlay.innerHTML = `
        <div class="sftp-permissions-modal">
            <h3>Permissions — ${escHtml(entry.name)}</h3>
            <div class="sftp-perm-grid">${gridHtml}</div>
            <div class="sftp-perm-octal"><label>Octal:</label><input type="text" class="perm-octal-input" value="${mode.toString(8).padStart(3, '0')}" maxlength="4" /></div>
            <div class="sftp-perm-actions">
                <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
                <button type="button" class="btn btn-primary" data-action="apply">Apply</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    const octalInput = overlay.querySelector('.perm-octal-input');
    const checkboxes = overlay.querySelectorAll('input[data-bit]');
    const syncOctal = () => { let v = 0; checkboxes.forEach(cb => { if (cb.checked) v |= parseInt(cb.dataset.bit, 10); }); octalInput.value = v.toString(8).padStart(3, '0'); };
    const syncChecks = () => { const v = parseInt(octalInput.value, 8) || 0; checkboxes.forEach(cb => { cb.checked = !!(v & parseInt(cb.dataset.bit, 10)); }); };
    checkboxes.forEach(cb => cb.addEventListener('change', syncOctal));
    octalInput.addEventListener('input', syncChecks);
    const cleanup = () => { overlay.removeEventListener('click', onClick); overlay.remove(); };
    const onClick = async (e) => {
        const action = e.target.closest('[data-action]')?.dataset.action;
        if (action === 'cancel' || e.target === overlay) { cleanup(); return; }
        if (action === 'apply') {
            const newMode = parseInt(octalInput.value, 8);
            if (isNaN(newMode)) { showToast('Invalid permission value', 'error'); return; }
            try {
                if (side === 'remote') await api.sftpChmod(sessionId, entry.path, newMode);
                else await api.localChmod(entry.path, newMode);
                showToast('Permissions updated', 'success');
                cleanup(); refreshPane(side);
            } catch (err) { showToast(`chmod failed: ${err}`, 'error'); }
        }
    };
    overlay.addEventListener('click', onClick);
}

// ─── File Preview ─────────────────────────────────────────

function showFilePreview(name, content) {
    const overlay = document.createElement('div');
    overlay.className = 'sftp-preview-overlay';
    overlay.innerHTML = `
        <div class="sftp-preview-modal">
            <div class="sftp-preview-header"><h4>${escHtml(name)}</h4><button class="sftp-preview-close" title="Close">&times;</button></div>
            <div class="sftp-preview-body"><pre>${escHtml(content)}</pre></div>
        </div>
    `;
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.querySelector('.sftp-preview-close').addEventListener('click', close, { once: true });
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); }, { once: true });
}

// ─── Navigation & Listing ─────────────────────────────────

async function navigateTo(side, path, skipHistory) {
    const pane = container?.querySelector(`.sftp-pane[data-side="${side}"]`);
    const listEl = pane?.querySelector('.sftp-file-list');
    if (!listEl) return;
    listEl.innerHTML = '<div class="sftp-loading">Loading…</div>';
    try {
        const entries = side === 'remote' ? await api.sftpListDir(sessionId, path) : await api.localListDir(path);
        state[side].path = path;
        state[side].entries = entries;
        state[side].selected = new Set();
        if (!skipHistory) pushHistory(side, path);
        renderBreadcrumb(side);
        renderFileList(side);
        updateNavButtons(side);
    } catch (err) {
        listEl.innerHTML = `<div class="sftp-empty-state"><h3>Error</h3><p>${escHtml(err)}</p></div>`;
    }
}

function refreshPane(side) {
    if (state[side].path) navigateTo(side, state[side].path, true);
}

function renderBreadcrumb(side) {
    const pane = container?.querySelector(`.sftp-pane[data-side="${side}"]`);
    const bcEl = pane?.querySelector('.sftp-breadcrumb');
    if (!bcEl) return;
    const segs = pathSegments(state[side].path);
    bcEl.innerHTML = segs.map((seg, i) => {
        const isLast = i === segs.length - 1;
        const icon = i === 0 ? '' : '<span class="sftp-file-icon is-dir" style="margin-right:2px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg></span>';
        const sep = i > 0 ? '<span class="sftp-bc-sep"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg></span>' : '';
        return `${sep}<button class="sftp-bc-segment${isLast ? ' active' : ''}" data-path="${escAttr(seg.path)}">${icon}${escHtml(seg.name)}</button>`;
    }).join('');
}

function updateNavButtons(side) {
    const pane = container?.querySelector(`.sftp-pane[data-side="${side}"]`);
    if (!pane) return;
    const back = pane.querySelector('[data-nav="back"]');
    const fwd = pane.querySelector('[data-nav="forward"]');
    if (back) back.disabled = !canGoBack(side);
    if (fwd) fwd.disabled = !canGoForward(side);
}

function renderFileList(side) {
    const pane = container?.querySelector(`.sftp-pane[data-side="${side}"]`);
    const listEl = pane?.querySelector('.sftp-file-list');
    const statusEl = pane?.querySelector('.sftp-pane-status');
    if (!listEl) return;

    const entries = getFilteredEntries(side);
    const currentPath = state[side].path;
    const sel = state[side].selected;
    const parts = [];

    if (currentPath !== '/') {
        parts.push(`<div class="sftp-file-item parent-dir" data-path="${escAttr(parentPath(currentPath))}" data-is-dir="true">
            <span class="sftp-file-icon is-dir"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="15 18 9 12 15 6"/></svg></span>
            <span class="sftp-file-name"><span class="sftp-file-name-text">..</span></span>
            <span class="sftp-file-date"></span>
            <span class="sftp-file-size"></span>
            <span class="sftp-file-kind"></span>
        </div>`);
    }

    for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        const selected = sel.has(e.path) ? ' selected' : '';
        parts.push(`<div class="sftp-file-item${selected}" data-path="${escAttr(e.path)}" data-is-dir="${e.is_dir}" data-name="${escAttr(e.name)}">
            ${fileIconHtml(e)}
            <span class="sftp-file-name"><span class="sftp-file-name-text">${escHtml(e.name)}</span><span class="sftp-file-perms">${formatPerms(e.permissions)}</span></span>
            <span class="sftp-file-date">${formatDate(e.modified)}</span>
            <span class="sftp-file-size">${e.is_dir ? '—' : formatSize(e.size)}</span>
            <span class="sftp-file-kind">${fileKind(e)}</span>
        </div>`);
    }

    if (entries.length === 0) {
        parts.length = 0;
        parts.push('<div class="sftp-empty-state"><h3>Empty directory</h3></div>');
    }

    listEl.innerHTML = parts.join('');

    if (statusEl) {
        const dirs = entries.filter(e => e.is_dir).length;
        const files = entries.length - dirs;
        statusEl.textContent = `${dirs} folder${dirs !== 1 ? 's' : ''}, ${files} file${files !== 1 ? 's' : ''}`;
    }
}

// ─── Event Delegation ─────────────────────────────────────

function updateSelectedClasses(side) {
    const pane = container?.querySelector(`.sftp-pane[data-side="${side}"]`);
    if (!pane) return;
    const sel = state[side].selected;
    pane.querySelectorAll('.sftp-file-item').forEach(item => {
        const path = item.dataset.path;
        if (sel.has(path)) {
            item.classList.add('selected');
        } else {
            item.classList.remove('selected');
        }
    });
}

function bindPaneEventDelegation() {
    container.querySelectorAll('.sftp-pane').forEach(pane => {
        const side = pane.dataset.side;
        const listEl = pane.querySelector('.sftp-file-list');
        if (!listEl) return;

        let lastClickPath = null;
        let lastClickTime = 0;

        listEl.addEventListener('click', (e) => {
            const item = e.target.closest('.sftp-file-item');
            if (!item || e.target.closest('.sftp-rename-input')) return;
            const path = item.dataset.path;
            const now = Date.now();

            if (lastClickPath === path && now - lastClickTime < 400) {
                lastClickPath = null;
                lastClickTime = 0;
                if (item.dataset.isDir === 'true') navigateTo(side, path);
                else { const entry = findEntryByPath(side, path); if (entry) handleOpen(side, entry); }
                return;
            }

            lastClickPath = path;
            lastClickTime = now;

            if (e.ctrlKey || e.metaKey) {
                if (state[side].selected.has(path)) state[side].selected.delete(path);
                else state[side].selected.add(path);
            } else {
                state[side].selected = new Set([path]);
            }
            updateSelectedClasses(side);
        });

        listEl.addEventListener('contextmenu', (e) => {
            e.preventDefault(); e.stopPropagation();
            const item = e.target.closest('.sftp-file-item');
            if (item) {
                const path = item.dataset.path;
                if (!state[side].selected.has(path)) {
                    state[side].selected = new Set([path]);
                    updateSelectedClasses(side);
                }
                showContextMenu(e.clientX, e.clientY, side, findEntryByPath(side, path));
            } else {
                showContextMenu(e.clientX, e.clientY, side, null);
            }
        });

        // Breadcrumb clicks
        const bcEl = pane.querySelector('.sftp-breadcrumb');
        bcEl?.addEventListener('click', (e) => {
            const seg = e.target.closest('.sftp-bc-segment');
            if (seg && seg.dataset.path) navigateTo(side, seg.dataset.path);
        });

        // Filter
        const filterInput = pane.querySelector('.sftp-filter-input');
        filterInput?.addEventListener('input', () => { filterQuery[side] = filterInput.value; renderFileList(side); });

        // Actions button
        const actionsBtn = pane.querySelector('.sftp-actions-btn');
        actionsBtn?.addEventListener('click', () => showActionsDropdown(actionsBtn, side));

        // Nav buttons
        pane.querySelector('[data-nav="back"]')?.addEventListener('click', () => goBack(side));
        pane.querySelector('[data-nav="forward"]')?.addEventListener('click', () => goForward(side));
    });
}

// ─── Connection ───────────────────────────────────────────

async function connectToHost(conn) {
    const sid = generateId();
    const statusEl = container.querySelector('.sftp-connect-state');
    if (statusEl) statusEl.innerHTML = '<div class="sftp-loading">Connecting…</div>';
    try {
        const home = await api.sftpConnect({
            session_id: sid, host: conn.host, port: conn.port,
            username: conn.username, password: conn.password ?? null, key_id: conn.key_id ?? null,
        });
        sessionId = sid;
        showHidden = { local: false, remote: false };
        filterQuery = { local: '', remote: '' };
        container.innerHTML = renderConnectedLayout(conn);
        bindToolbar();
        bindPaneEventDelegation();
        const localHome = await api.localHomeDir();
        await Promise.all([ navigateTo('local', localHome), navigateTo('remote', home) ]);
    } catch (err) {
        showToast(`SFTP connection failed: ${err}`, 'error');
        if (statusEl) { statusEl.innerHTML = renderDisconnectedState(); bindConnectActions(); }
    }
}

async function disconnect() {
    if (sessionId) { try { await api.sftpDisconnect(sessionId); } catch {} }
    sessionId = null; activeTransfers = 0;
    state.local = { path: '', entries: [], selected: new Set(), history: [], historyIdx: -1 };
    state.remote = { path: '', entries: [], selected: new Set(), history: [], historyIdx: -1 };
    container.innerHTML = renderDisconnectedLayout();
    bindConnectActions();
}

// ─── Host Picker ──────────────────────────────────────────

async function showHostPicker() {
    let hosts;
    try { hosts = await api.getConnections(); }
    catch (err) { showToast(`Failed to load hosts: ${err}`, 'error'); return; }
    if (hosts.length === 0) { showToast('No saved hosts. Add one in the Hosts view first.', 'info'); return; }

    const overlay = document.createElement('div');
    overlay.className = 'sftp-hosts-modal-overlay';
    overlay.innerHTML = `
        <div class="sftp-hosts-modal">
            <div class="modal-header"><h3>Connect via SFTP</h3><button class="btn-close-modal">&times;</button></div>
            <div class="modal-body">
                <input type="text" class="modal-search" placeholder="Search hosts…" />
                <div class="sftp-hosts-list">
                    ${hosts.map(h => `<div class="sftp-modal-host-item" data-id="${escAttr(h.id)}">
                        <div class="sftp-modal-host-name">${escHtml(h.name)}</div>
                        <div class="sftp-modal-host-detail">${escHtml(h.username)}@${escHtml(h.host)}:${h.port}</div>
                    </div>`).join('')}
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.querySelector('.btn-close-modal').addEventListener('click', close, { once: true });
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    const searchInput = overlay.querySelector('.modal-search');
    overlay.querySelector('.sftp-hosts-list').addEventListener('click', (e) => {
        const item = e.target.closest('.sftp-modal-host-item');
        if (!item) return;
        const host = hosts.find(h => h.id === item.dataset.id);
        if (host) { close(); connectToHost(host); }
    });
    searchInput.addEventListener('input', () => {
        const q = searchInput.value.toLowerCase();
        overlay.querySelectorAll('.sftp-modal-host-item').forEach(el => { el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none'; });
    });
    searchInput.focus();
}

// ─── Layout ───────────────────────────────────────────────

function renderPaneHtml(side, label) {
    const labelClass = side === 'local' ? 'local' : 'remote';
    return `
        <div class="sftp-pane" data-side="${side}">
            <div class="sftp-pane-toolbar">
                <span class="sftp-pane-label ${labelClass}">${label}</span>
                <div class="sftp-pane-toolbar-spacer"></div>
                <div class="sftp-filter-wrap">
                    <svg class="sftp-filter-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
                    <input type="text" class="sftp-filter-input" placeholder="Filter" />
                </div>
                <button type="button" class="sftp-actions-btn">Actions <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6 9 12 15 18 9"/></svg></button>
            </div>
            <div class="sftp-pane-nav">
                <button class="sftp-nav-btn" data-nav="back" title="Back" disabled>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
                </button>
                <button class="sftp-nav-btn" data-nav="forward" title="Forward" disabled>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 6 15 12 9 18"/></svg>
                </button>
                <div class="sftp-breadcrumb"></div>
            </div>
            <div class="sftp-file-list-header">
                <span></span><span>Name</span><span>Date Modified</span><span>Size</span><span>Kind</span>
            </div>
            <div class="sftp-file-list"></div>
            <div class="sftp-pane-status">—</div>
        </div>
    `;
}

function renderDisconnectedState() {
    return `
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="9" y1="13" x2="15" y2="13"/></svg>
        <h3>SFTP File Browser</h3>
        <p>Connect to a remote host to browse and transfer files between local and remote file systems.</p>
        <div class="sftp-connect-actions"><button type="button" class="btn btn-primary" id="sftp-connect-btn">Connect to Host</button></div>
    `;
}

function renderDisconnectedLayout() {
    return `<div class="sftp-view-container"><div class="sftp-connect-state">${renderDisconnectedState()}</div></div>`;
}

function renderConnectedLayout(conn) {
    return `
        <div class="sftp-view-container">
            <div class="sftp-panes">
                ${renderPaneHtml('local', 'Local')}
                ${renderPaneHtml('remote', conn.name || 'Remote')}
            </div>
            <div class="sftp-transfer-overlay" style="display:none"></div>
            <div class="sftp-global-toolbar">
                <span class="sftp-connection-info">${escHtml(conn.username)}@${escHtml(conn.host)}:${conn.port}</span>
                <div class="sftp-toolbar-spacer"></div>
                <button type="button" class="sftp-toolbar-btn" id="sftp-btn-disconnect">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    Disconnect
                </button>
            </div>
        </div>
    `;
}

function bindToolbar() {
    container.querySelector('#sftp-btn-disconnect')?.addEventListener('click', disconnect);
}

function bindConnectActions() {
    container.querySelector('#sftp-connect-btn')?.addEventListener('click', showHostPicker);
}

// ─── Public API ───────────────────────────────────────────

export function render(containerEl) {
    container = containerEl;
    container.innerHTML = renderDisconnectedLayout();
    bindConnectActions();
    setupProgressListener();
}

export function refresh() {
    if (sessionId && activeTransfers === 0) { refreshPane('local'); refreshPane('remote'); }
}

export async function connectFromHost(conn) { await connectToHost(conn); }
