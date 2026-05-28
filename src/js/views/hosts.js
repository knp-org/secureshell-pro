// ═══════════════════════════════════════════════════════════
// Hosts View — full-page list + action menu + edit modal
// ═══════════════════════════════════════════════════════════

import * as api from '../api.js';
import { escHtml, escAttr, generateId, now } from '../utils/helpers.js';
import { renderFields, readFieldValue, hydrateSelects } from '../components/form-builder.js';
import { openEntityEditModal } from '../components/edit-modal.js';
import { createFolderCollapse, renderFolderSections } from '../components/folder-grid.js';
import { renderCardGridPageShell, bindCardGridPageHeader, renderCardGridEmpty } from '../components/card-grid-page.js';
import { showToast } from '../components/toast.js';
import { icons } from '../utils/icons.js';
import * as terminalView from './terminal.js';

let container = null;
let items = [];
let filterQuery = '';
let availableKeys = [];
let hostFolders = [];
let selectMap = new Map();
let actionMenuEl = null;
let actionMenuDismiss = null;

const ORDER_SETTING = 'hosts_order';
const PINNED_SETTING = 'hosts_pinned';
const HOST_FOLDER_ICON = 'host-folder';
const PINNED_FOLDER_ID = '__pinned__';
const folderCollapse = createFolderCollapse();
let pinnedIds = [];

// ─── Folders ───────────────────────────────────────────────

function findFolder(id) {
    if (!id) return null;
    return hostFolders.find(folder => folder.id === id) || null;
}

function folderKey(conn) {
    return conn.group_id || '';
}

function isPinned(conn) {
    return pinnedIds.includes(conn.id);
}

async function loadPinnedIds() {
    try {
        const raw = await api.getSetting(PINNED_SETTING);
        if (!raw) return [];
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter(x => typeof x === 'string') : [];
    } catch { return []; }
}

function savePinnedIds(ids) {
    return api.setSetting(PINNED_SETTING, JSON.stringify(ids)).catch(err => {
        console.error('save pinned hosts failed:', err);
    });
}

async function togglePin(conn) {
    const wasPinned = isPinned(conn);
    const next = wasPinned
        ? pinnedIds.filter(id => id !== conn.id)
        : [...pinnedIds, conn.id];
    pinnedIds = next;
    await savePinnedIds(next);
    renderList();
    showToast(wasPinned ? `"${conn.name}" unpinned` : `"${conn.name}" pinned`, 'success');
}

function applyPinnedOrder(list) {
    const indexOf = new Map(pinnedIds.map((id, i) => [id, i]));
    return [...list].sort((a, b) => {
        const ai = indexOf.has(a.id) ? indexOf.get(a.id) : Number.MAX_SAFE_INTEGER;
        const bi = indexOf.has(b.id) ? indexOf.get(b.id) : Number.MAX_SAFE_INTEGER;
        if (ai !== bi) return ai - bi;
        return (a.name || '').localeCompare(b.name || '');
    });
}

async function loadHostFolders() {
    const groups = await api.getGroups();
    hostFolders = groups
        .filter(group => group.icon === HOST_FOLDER_ICON)
        .sort((a, b) => a.name.localeCompare(b.name));
}

async function createHostFolder(name) {
    const trimmed = name.trim();
    if (!trimmed) return null;
    const existing = hostFolders.find(f => f.name.toLowerCase() === trimmed.toLowerCase());
    if (existing) return existing;

    const folder = {
        id: generateId(),
        name: trimmed,
        parent_id: null,
        icon: HOST_FOLDER_ICON,
        color: null,
        created_at: now(),
    };
    await api.saveGroup(folder);
    hostFolders = [...hostFolders, folder].sort((a, b) => a.name.localeCompare(b.name));
    return folder;
}

// ─── List rendering ────────────────────────────────────────

function pinIcon(size = 12) {
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M16 3l4 4-9 9H7v-4L16 3zM5 21h6v-2H5v2z"/></svg>`;
}

function renderCard(conn, index) {
    return `
        <div class="host-card${isPinned(conn) ? ' is-pinned' : ''}" data-id="${conn.id}" style="animation-delay:${index * 30}ms">
            <span class="host-card-drag" title="Drag to reorder">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/></svg>
            </span>
            <div class="host-card-body">
                <div class="host-card-top">
                    <span class="host-card-name">${escHtml(conn.name)}</span>
                    <span class="host-card-badges">
                        ${isPinned(conn) ? `<span class="host-pin-badge" title="Pinned">${pinIcon(11)}</span>` : ''}
                        <span class="host-card-status"></span>
                    </span>
                </div>
                <div class="host-card-endpoint" title="${escAttr(conn.username)}@${escAttr(conn.host)}:${conn.port}">${escHtml(conn.username)}@${escHtml(conn.host)}:${conn.port}</div>
            </div>
        </div>`;
}

function renderPinnedSection(pinnedList) {
    if (pinnedList.length === 0) return '';
    const folderDomId = PINNED_FOLDER_ID;
    return `
        <div class="host-folder-section host-pinned-section" data-folder-id="${escAttr(folderDomId)}">
            <div class="host-folder-header" data-toggle-folder="${escAttr(folderDomId)}">
                <span class="host-folder-arrow">▾</span>
                <span class="host-folder-pin">${pinIcon(12)}</span>
                <span class="host-folder-name">Pinned</span>
                <span class="host-folder-count">${pinnedList.length}</span>
            </div>
            <div class="host-folder-items host-pinned-items" data-reorder-scope="pinned">
                ${pinnedList.map((item, i) => renderCard(item, i)).join('')}
            </div>
        </div>
    `;
}

function renderFolderList(unpinnedList, wrapFlatGrid = false) {
    return renderFolderSections({
        items: unpinnedList,
        folders: hostFolders,
        renderCard,
        getGroupId: folderKey,
        wrapFlatGrid,
        flatItemsClass: wrapFlatGrid ? 'host-folder-items hosts-unpinned-items' : 'host-folder-items',
        sectionItemsAttrs: 'data-reorder-scope="folder"',
    });
}

function renderListItems(list) {
    const pinnedList = applyPinnedOrder(list.filter(c => isPinned(c)));
    const unpinnedList = list.filter(c => !isPinned(c));
    return renderPinnedSection(pinnedList) + renderFolderList(unpinnedList, pinnedList.length > 0);
}

function filterItems(list, q) {
    if (!q) return list;
    const lower = q.toLowerCase();
    return list.filter(c => {
        const haystack = [c.name, c.host, c.username, findFolder(c.group_id)?.name ?? ''];
        return haystack.some(f => f && f.toLowerCase().includes(lower));
    });
}

function renderList() {
    const listEl = container?.querySelector('[data-role="list"]');
    if (!listEl) return;

    const filtered = filterItems(items, filterQuery);

    if (filtered.length === 0) {
        listEl.innerHTML = renderCardGridEmpty({
            icon: icons.server(48),
            hasItems: items.length > 0,
            emptyText: 'No connections yet.<br>Click <strong>+</strong> to add your first host.',
            searchEmptyText: 'No results found.',
        });
        return;
    }

    listEl.innerHTML = renderListItems(filtered);

    if (listEl.querySelector('.host-folder-section')) folderCollapse.bind(listEl);
    wireDragReorder(listEl, filtered, filterQuery);
    bindCardClicks(listEl);
}

// ─── Action menu (left click) ──────────────────────────────

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

function showHostActionMenu(x, y, conn) {
    closeActionMenu();

    const menu = document.createElement('div');
    menu.className = 'host-action-menu';
    menu.setAttribute('role', 'menu');
    menu.innerHTML = `
        <div class="host-action-menu-title">${escHtml(conn.name)}</div>
        <button type="button" data-action="connect">${icons.terminal(14)} Connect</button>
        <button type="button" data-action="edit">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            Edit connection
        </button>
        <button type="button" data-action="pin">${pinIcon(14)} ${isPinned(conn) ? 'Unpin' : 'Pin'}</button>
    `;

    document.body.appendChild(menu);
    actionMenuEl = menu;

    menu.querySelector('[data-action="connect"]').addEventListener('click', (e) => {
        e.stopPropagation();
        closeActionMenu();
        terminalView.startConnection(conn);
    });

    menu.querySelector('[data-action="edit"]').addEventListener('click', (e) => {
        e.stopPropagation();
        closeActionMenu();
        openEditModal(conn, false);
    });

    menu.querySelector('[data-action="pin"]').addEventListener('click', (e) => {
        e.stopPropagation();
        closeActionMenu();
        togglePin(conn);
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
        // Single click — intentionally no action (avoids fighting double-click).

        card.addEventListener('dblclick', (e) => {
            if (e.target.closest('.host-card-drag')) return;
            e.preventDefault();
            const conn = items.find(c => c.id === card.dataset.id);
            if (!conn) return;
            closeActionMenu();
            terminalView.startConnection(conn);
        });

        // Right-click: Connect / Edit menu (left-click is double-click to connect only).
        card.addEventListener('contextmenu', (e) => {
            if (e.target.closest('.host-card-drag')) return;
            e.preventDefault();
            e.stopPropagation();
            const conn = items.find(c => c.id === card.dataset.id);
            if (!conn) return;
            showHostActionMenu(e.clientX, e.clientY, conn);
        });
    });
}

// ─── Edit modal ────────────────────────────────────────────

function buildFormFields(conn) {
    return renderFields([
        { id: 'host-name', label: 'Label', value: conn.name, placeholder: 'My Server' },
        {
            id: 'host-folder', label: 'Folder', type: 'select', value: conn.group_id ?? '',
            options: [
                { value: '', text: 'Unfiled' },
                ...hostFolders.map(folder => ({ value: folder.id, text: folder.name })),
            ],
        },
        [
            { id: 'host-host', label: 'Host / IP', value: conn.host, placeholder: '192.168.1.100' },
            { id: 'host-port', label: 'Port', type: 'number', value: conn.port, placeholder: '22', style: 'max-width:120px' },
        ],
        { id: 'host-user', label: 'Username', value: conn.username, placeholder: 'root' },
        {
            id: 'host-auth', label: 'Authentication', type: 'select', value: conn.auth_method,
            options: [
                { value: 'password',       text: 'Password' },
                { value: 'key',            text: 'SSH Key' },
                { value: 'key_passphrase', text: 'SSH Key + Passphrase' },
            ],
        },
        { id: 'host-password', label: 'Password / Passphrase', type: 'password', value: conn.password ?? '', placeholder: 'Enter password or key passphrase' },
        {
            id: 'host-key', label: 'SSH Key', type: 'select', value: conn.key_id ?? '',
            options: [
                { value: '', text: '-- Select a Key --' },
                ...availableKeys.map(k => ({ value: k.id, text: k.label })),
            ],
        },
    ]) + `
        <div class="host-folder-create">
            <input type="text" id="host-new-folder-name" placeholder="New folder name" autocomplete="off" />
            <button type="button" class="btn btn-secondary btn-sm" id="host-create-folder">Add folder</button>
        </div>`;
}

function bindHostFolderControls(panel) {
    const folderCtrl = selectMap.get('host-folder');
    const nameEl = panel.querySelector('#host-new-folder-name');
    const createBtn = panel.querySelector('#host-create-folder');
    if (!folderCtrl || !nameEl || !createBtn) return;

    const create = async () => {
        try {
            const folder = await createHostFolder(nameEl.value);
            if (!folder) {
                nameEl.focus();
                return;
            }
            folderCtrl.addOption(folder.id, folder.name);
            folderCtrl.setValue(folder.id);
            nameEl.value = '';
            showToast(`Folder "${folder.name}" ready`, 'success');
        } catch (err) {
            showToast('Failed to create folder: ' + err, 'error');
        }
    };

    createBtn.addEventListener('click', create);
    nameEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            create();
        }
    });
}

function toggleAuthFields() {
    const pwdGroup = document.getElementById('host-password')?.closest('.form-group');
    const keyGroup = document.getElementById('host-key')?.closest('.form-group');
    if (!pwdGroup || !keyGroup) return;

    const method = readFieldValue('host-auth');
    if (method === 'password') {
        pwdGroup.style.display = 'block';
        keyGroup.style.display = 'none';
        document.getElementById('host-password').placeholder = 'Enter password';
    } else if (method === 'key') {
        pwdGroup.style.display = 'none';
        keyGroup.style.display = 'block';
    } else if (method === 'key_passphrase') {
        pwdGroup.style.display = 'block';
        keyGroup.style.display = 'block';
        document.getElementById('host-password').placeholder = 'Enter key passphrase';
    }
}

function readForm(original) {
    return {
        ...original,
        name:        readFieldValue('host-name'),
        host:        readFieldValue('host-host'),
        port:        parseInt(readFieldValue('host-port'), 10) || 22,
        username:    readFieldValue('host-user'),
        auth_method: readFieldValue('host-auth'),
        password:    readFieldValue('host-password') || null,
        key_id:      readFieldValue('host-key') || null,
        group_id:    readFieldValue('host-folder') || null,
        updated_at:  now(),
    };
}

function validateForm(conn) {
    if (!conn.name)     return 'Label is required';
    if (!conn.host)     return 'Host/IP is required';
    if (!conn.username) return 'Username is required';
    if (conn.auth_method === 'password' && !conn.password) {
        return 'Password is required for password authentication';
    }
    if ((conn.auth_method === 'key' || conn.auth_method === 'key_passphrase') && !conn.key_id) {
        return 'Please select an SSH key';
    }
    if (conn.auth_method === 'key_passphrase' && !conn.password) {
        return 'Passphrase is required for key+passphrase authentication';
    }
    return null;
}

function newItemTemplate() {
    return {
        id: generateId(), name: '', host: '', port: 22,
        username: '', auth_method: 'password', password: '',
        key_id: null, group_id: null, tags: [], color: null,
        last_connected: null, created_at: now(), updated_at: now(), synced: false,
    };
}

function openEditModal(conn, isNew) {
    closeActionMenu();

    openEntityEditModal({
        title: isNew ? 'New connection' : 'Edit connection',
        fieldsHtml: buildFormFields(conn),
        showDelete: !isNew,
        onMount(panel) {
            selectMap = hydrateSelects(panel, {
                'host-auth': () => toggleAuthFields(),
            });
            toggleAuthFields();
            bindHostFolderControls(panel);
            return () => {
                selectMap.forEach(ctrl => ctrl.destroy?.());
                selectMap.clear();
            };
        },
        async onSave() {
            const updated = readForm(conn);
            const err = validateForm(updated);
            if (err) {
                showToast(err, 'error');
                return false;
            }
            try {
                await api.saveConnection(updated);
                showToast(`Connection "${updated.name}" saved`, 'success');
                await loadData();
                return true;
            } catch (e) {
                showToast(`Failed to save: ${e}`, 'error');
                return false;
            }
        },
        async onDelete() {
            try {
                await api.deleteConnection(conn.id);
                showToast('Connection deleted', 'success');
                await loadData();
                return true;
            } catch (e) {
                showToast(`Failed to delete: ${e}`, 'error');
                return false;
            }
        },
    });
}

// ─── Drag-to-reorder ───────────────────────────────────────

async function loadOrder() {
    try {
        const raw = await api.getSetting(ORDER_SETTING);
        if (!raw) return [];
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter(x => typeof x === 'string') : [];
    } catch { return []; }
}

function saveOrder(ids) {
    return api.setSetting(ORDER_SETTING, JSON.stringify(ids)).catch(err => {
        console.error('save hosts order failed:', err);
    });
}

function applyOrder(list, order) {
    const indexOf = new Map(order.map((id, i) => [id, i]));
    return [...list].sort((a, b) => {
        const ai = indexOf.has(a.id) ? indexOf.get(a.id) : Number.MAX_SAFE_INTEGER;
        const bi = indexOf.has(b.id) ? indexOf.get(b.id) : Number.MAX_SAFE_INTEGER;
        if (ai !== bi) return ai - bi;
        return (a.name || '').localeCompare(b.name || '');
    });
}

function wireDragReorder(listEl, filtered, filter) {
    if (filter) return;

    let drag = null;
    let rafId = 0;
    let lastX = 0, lastY = 0;
    let currentTarget = null;
    let currentAbove  = null;

    const findTargetCard = (x, y, excludeId, scopeEl) => {
        let el = document.elementFromPoint(x, y);
        while (el && !el.classList?.contains('host-card')) el = el.parentElement;
        if (!el || el.dataset.id === excludeId) return null;
        if (scopeEl && !scopeEl.contains(el)) return null;
        return el;
    };

    const setDropMarker = (target, above) => {
        if (currentTarget && currentTarget !== target) {
            currentTarget.classList.remove('drop-above', 'drop-below');
        }
        if (target && (target !== currentTarget || above !== currentAbove)) {
            target.classList.remove('drop-above', 'drop-below');
            target.classList.add(above ? 'drop-above' : 'drop-below');
        }
        currentTarget = target;
        currentAbove  = above;
    };

    const renderFrame = () => {
        rafId = 0;
        if (!drag) return;
        const x = lastX - drag.offsetX;
        const y = lastY - drag.offsetY;
        drag.ghostEl.style.transform = `translate3d(${x}px, ${y}px, 0)`;

        const target = findTargetCard(lastX, lastY, drag.id, drag.scopeEl);
        if (!target) {
            setDropMarker(null, null);
            return;
        }
        const r = target.getBoundingClientRect();
        const above = lastY < r.top + r.height / 2;
        setDropMarker(target, above);
    };

    const onPointerMove = (e) => {
        if (!drag) return;
        e.preventDefault();
        lastX = e.clientX;
        lastY = e.clientY;
        if (!rafId) rafId = requestAnimationFrame(renderFrame);
    };

    const onPointerUp = (e) => {
        if (!drag) return;
        if (rafId) { cancelAnimationFrame(rafId); rafId = 0; }

        const sourceEl = drag.sourceEl;
        const scopeEl  = drag.scopeEl;
        const target = currentTarget || findTargetCard(e.clientX, e.clientY, drag.id, scopeEl);
        const above  = target
            ? (currentAbove ?? (e.clientY < target.getBoundingClientRect().top + target.getBoundingClientRect().height / 2))
            : false;

        const fromId = drag.id;
        const toId   = target?.dataset.id;

        drag.ghostEl.remove();
        sourceEl.classList.remove('is-dragging');
        if (currentTarget) currentTarget.classList.remove('drop-above', 'drop-below');
        currentTarget = null;
        currentAbove  = null;

        window.removeEventListener('pointermove',   onPointerMove);
        window.removeEventListener('pointerup',     onPointerUp);
        window.removeEventListener('pointercancel', onPointerUp);
        drag = null;

        if (!toId || fromId === toId) return;

        const pinnedContainer = sourceEl.closest('.host-pinned-items');
        if (pinnedContainer) {
            const visible = filtered.filter(c => isPinned(c)).map(c => c.id);
            let order = pinnedIds.filter(id => visible.includes(id));
            const fromIdx = order.indexOf(fromId);
            const toIdx = order.indexOf(toId);
            if (fromIdx < 0 || toIdx < 0) return;
            const [removed] = order.splice(fromIdx, 1);
            const insertAt = order.indexOf(toId) + (above ? 0 : 1);
            order.splice(insertAt, 0, removed);
            pinnedIds = [...order, ...pinnedIds.filter(id => !visible.includes(id))];
            savePinnedIds(pinnedIds);
            renderList();
            return;
        }

        const fromIdx = items.findIndex(i => i.id === fromId);
        if (fromIdx < 0) return;
        const moved = items[fromIdx];
        const toItem = items.find(i => i.id === toId);
        if (isPinned(moved) || isPinned(toItem)) return;
        if (!toItem || folderKey(moved) !== folderKey(toItem)) return;

        const [removed] = items.splice(fromIdx, 1);
        const insertAt = items.findIndex(i => i.id === toId) + (above ? 0 : 1);
        items.splice(insertAt, 0, removed);
        saveOrder(items.map(i => i.id));
        renderList();
    };

    listEl.querySelectorAll('.host-card-drag').forEach(handle => {
        handle.addEventListener('pointerdown', (e) => {
            if (e.button !== 0) return;
            e.preventDefault();
            e.stopPropagation();
            closeActionMenu();
            const card = handle.closest('.host-card');
            if (!card) return;
            const rect = card.getBoundingClientRect();

            const ghost = card.cloneNode(true);
            ghost.classList.add('host-card-ghost');
            ghost.style.width  = rect.width + 'px';
            ghost.style.transform = `translate3d(${rect.left}px, ${rect.top}px, 0)`;
            document.body.appendChild(ghost);

            card.classList.add('is-dragging');
            drag = {
                id: card.dataset.id,
                sourceEl: card,
                scopeEl: card.closest('.host-folder-items, .hosts-list'),
                ghostEl: ghost,
                offsetX: e.clientX - rect.left,
                offsetY: e.clientY - rect.top,
            };
            lastX = e.clientX;
            lastY = e.clientY;
            window.addEventListener('pointermove',   onPointerMove);
            window.addEventListener('pointerup',     onPointerUp);
            window.addEventListener('pointercancel', onPointerUp);
        });
    });
}

// ─── Data & mount ──────────────────────────────────────────

async function loadData() {
    const [keys, , loadedPinned] = await Promise.all([
        api.getKeys(),
        loadHostFolders(),
        loadPinnedIds(),
    ]);
    availableKeys = keys;
    const conns = await api.getConnections();
    const connIds = new Set(conns.map(c => c.id));
    pinnedIds = loadedPinned.filter(id => connIds.has(id));
    if (pinnedIds.length !== loadedPinned.length) {
        savePinnedIds(pinnedIds);
    }
    const order = await loadOrder();
    items = applyOrder(conns, order);
    renderList();
}

export function render(containerEl) {
    container = containerEl;
    container.innerHTML = renderCardGridPageShell({
        pageClass: 'hosts-page',
        headerClass: 'hosts-page-header',
        title: 'Hosts',
        searchPlaceholder: 'Search hosts...',
        addTitle: 'Add connection',
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
