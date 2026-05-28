// ═══════════════════════════════════════════════════════════
// SSH Keys View — full-page card grid + action menu + edit modal
// ═══════════════════════════════════════════════════════════

import * as api from '../api.js';
import { escHtml, escAttr, generateId, now } from '../utils/helpers.js';
import { renderFields, readFieldValue, hydrateSelects } from '../components/form-builder.js';
import { openEntityEditModal } from '../components/edit-modal.js';
import { renderFolderSections } from '../components/folder-grid.js';
import { renderCardGridPageShell, bindCardGridPageHeader, renderCardGridEmpty } from '../components/card-grid-page.js';
import { showToast } from '../components/toast.js';
import { icons } from '../utils/icons.js';

let container = null;
let items = [];
let filterQuery = '';
let selectMap = new Map();
let actionMenuEl = null;
let actionMenuDismiss = null;

// ─── List rendering ─────────────────────────────────────────

function renderCard(key, index) {
    const meta = key.fingerprint
        || (key.public_key ? 'Public key stored' : 'No fingerprint');

    return `
        <div class="host-card key-card" data-id="${key.id}" style="animation-delay:${index * 30}ms">
            <div class="host-card-body">
                <div class="host-card-top">
                    <span class="host-card-name">${escHtml(key.label)}</span>
                    <span class="host-card-badges">
                        <span class="key-card-type-badge">${escHtml(key.key_type.toUpperCase())}</span>
                    </span>
                </div>
                <div class="host-card-endpoint key-card-meta" title="${escAttr(meta)}">${escHtml(meta)}</div>
            </div>
        </div>`;
}

function renderListItems(list) {
    return renderFolderSections({
        items: list,
        folders: [],
        renderCard,
    });
}

function filterItems(list, q) {
    if (!q) return list;
    const lower = q.toLowerCase();
    return list.filter(k => {
        const haystack = [k.label, k.key_type, k.fingerprint, k.public_key];
        return haystack.some(f => f && String(f).toLowerCase().includes(lower));
    });
}

function renderList() {
    const listEl = container?.querySelector('[data-role="list"]');
    if (!listEl) return;

    const filtered = filterItems(items, filterQuery);

    if (filtered.length === 0) {
        listEl.innerHTML = renderCardGridEmpty({
            icon: icons.key(48),
            hasItems: items.length > 0,
            emptyText: 'No SSH keys yet.<br>Click <strong>+</strong> to add one.',
            searchEmptyText: 'No results found.',
            extraClass: 'keys-empty',
        });
        return;
    }

    listEl.innerHTML = renderListItems(filtered);
    bindCardClicks(listEl);
}

// ─── Action menu ───────────────────────────────────────────

function closeActionMenu() {
    if (actionMenuDismiss) {
        document.removeEventListener('pointerdown', actionMenuDismiss, true);
        document.removeEventListener('keydown', actionMenuDismiss);
        actionMenuDismiss = null;
    }
    if (actionMenuEl) {
        actionMenuEl.remove();
        actionMenuEl = null;
    }
}

function positionMenu(menu, x, y) {
    menu.style.display = 'flex';
    const rect = menu.getBoundingClientRect();
    const maxX = window.innerWidth - rect.width - 8;
    const maxY = window.innerHeight - rect.height - 8;
    menu.style.left = `${Math.max(8, Math.min(x, maxX))}px`;
    menu.style.top  = `${Math.max(8, Math.min(y, maxY))}px`;
}

function showKeyActionMenu(x, y, key) {
    closeActionMenu();

    const menu = document.createElement('div');
    menu.className = 'host-action-menu';
    menu.setAttribute('role', 'menu');
    menu.innerHTML = `
        <div class="host-action-menu-title">${escHtml(key.label)}</div>
        <button type="button" data-action="edit">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            Edit key
        </button>
    `;

    document.body.appendChild(menu);
    actionMenuEl = menu;

    menu.querySelector('[data-action="edit"]').addEventListener('click', (e) => {
        e.stopPropagation();
        closeActionMenu();
        openEditModal(key, false);
    });

    positionMenu(menu, x, y);

    actionMenuDismiss = (e) => {
        if (e.type === 'keydown') {
            if (e.key === 'Escape') closeActionMenu();
            return;
        }
        if (actionMenuEl && !actionMenuEl.contains(e.target)) {
            closeActionMenu();
        }
    };
    setTimeout(() => {
        document.addEventListener('pointerdown', actionMenuDismiss, true);
        document.addEventListener('keydown', actionMenuDismiss);
    }, 0);
}

function bindCardClicks(listEl) {
    listEl.querySelectorAll('.host-card').forEach(card => {
        card.addEventListener('dblclick', (e) => {
            e.preventDefault();
            const key = items.find(k => k.id === card.dataset.id);
            if (!key) return;
            closeActionMenu();
            openEditModal(key, false);
        });

        card.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const key = items.find(k => k.id === card.dataset.id);
            if (!key) return;
            showKeyActionMenu(e.clientX, e.clientY, key);
        });
    });
}

// ─── Edit modal ────────────────────────────────────────────

function buildFormFields(key) {
    return renderFields([
        { id: 'key-label', label: 'Label', value: key.label, placeholder: 'My Server Key' },
        {
            id: 'key-type', label: 'Key Type', type: 'select', value: key.key_type,
            options: [
                { value: 'ed25519', text: 'Ed25519' },
                { value: 'rsa',     text: 'RSA' },
                { value: 'ecdsa',   text: 'ECDSA' },
            ],
        },
        { id: 'key-private', label: 'Private Key', type: 'textarea', value: key.private_key ?? '', placeholder: 'Paste private key or leave blank to generate...' },
        { id: 'key-public',  label: 'Public Key',  type: 'textarea', value: key.public_key ?? '',  placeholder: 'Paste public key...' },
    ]);
}

function readForm(original) {
    return {
        ...original,
        label:       readFieldValue('key-label'),
        key_type:    readFieldValue('key-type'),
        private_key: readFieldValue('key-private') || null,
        public_key:  readFieldValue('key-public')  || null,
    };
}

function validateForm(key) {
    if (!key.label) return 'Label is required';
    return null;
}

function newItemTemplate() {
    return {
        id: generateId(), label: '', key_type: 'ed25519',
        public_key: null, private_key: null, fingerprint: null,
        created_at: now(), synced: false,
    };
}

function openEditModal(key, isNew) {
    closeActionMenu();

    openEntityEditModal({
        title: isNew ? 'New SSH key' : 'Edit SSH key',
        fieldsHtml: buildFormFields(key),
        showDelete: !isNew,
        onMount(panel) {
            selectMap = hydrateSelects(panel);
            return () => {
                selectMap.forEach(ctrl => ctrl.destroy?.());
                selectMap.clear();
            };
        },
        async onSave() {
            const updated = readForm(key);
            const err = validateForm(updated);
            if (err) {
                showToast(err, 'error');
                return false;
            }
            try {
                await api.saveKey(updated);
                showToast(`Key "${updated.label}" saved`, 'success');
                await loadData();
                return true;
            } catch (e) {
                showToast(`Failed to save: ${e}`, 'error');
                return false;
            }
        },
        async onDelete() {
            try {
                await api.deleteKey(key.id);
                showToast('SSH key deleted', 'success');
                await loadData();
                return true;
            } catch (e) {
                showToast(`Failed to delete: ${e}`, 'error');
                return false;
            }
        },
    });
}

// ─── Data & mount ──────────────────────────────────────────

async function loadData() {
    let dbKeys = await api.getKeys();
    try {
        const detectedKeys = await api.detectKeys();
        let addedNew = false;
        for (const dKey of detectedKeys) {
            const exists = dbKeys.some(k =>
                k.label === dKey.label
                || (k.private_key && dKey.private_key && k.private_key === dKey.private_key));
            if (!exists) {
                await api.saveKey(dKey);
                addedNew = true;
            }
        }
        if (addedNew) {
            dbKeys = await api.getKeys();
        }
    } catch (err) {
        console.error('Failed to auto-detect keys:', err);
    }

    items = dbKeys.sort((a, b) => (a.label || '').localeCompare(b.label || ''));
    renderList();
}

export function render(containerEl) {
    container = containerEl;
    container.innerHTML = renderCardGridPageShell({
        pageClass: 'keys-page',
        headerClass: 'keys-page-header',
        title: 'SSH Keys',
        searchPlaceholder: 'Search keys...',
        addTitle: 'Add SSH key',
        listClass: 'keys-page-list hosts-list',
    });
    bindCardGridPageHeader(container, {
        onAdd: () => openEditModal(newItemTemplate(), true),
        onSearchChange: (q) => {
            filterQuery = q;
            renderList();
        },
    });
    loadData();
}

export function refresh() {
    if (container) loadData();
}
