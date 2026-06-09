// ═══════════════════════════════════════════════════════════
// Snippets View — full-page card grid + action menu + edit modal
// ═══════════════════════════════════════════════════════════

import * as api from '../api.js';
import { escHtml, escAttr, generateId, now } from '../utils/helpers.js';
import { renderFields, readFieldValue, hydrateSelects } from '../components/form-builder.js';
import { openEntityEditModal } from '../components/edit-modal.js';
import { createFolderCollapse, renderFolderSections } from '../components/folder-grid.js';
import { renderCardGridPageShell, bindCardGridPageHeader, renderCardGridEmpty } from '../components/card-grid-page.js';
import { TagInput } from '../components/tag-input.js';
import { showToast } from '../components/toast.js';
import { icons } from '../utils/icons.js';
import { extractSnippetVars, formatSnippetVar, normalizeSnippetVarName } from '../utils/snippet-vars.js';
import { runSnippetCommand } from './terminal.js';

let container = null;
let items = [];
let filterQuery = '';
let availableHosts = [];
let snippetFolders = [];
let tagInput = null;
let selectMap = new Map();
let actionMenuEl = null;
let actionMenuDismiss = null;

const SNIPPET_FOLDER_ICON = 'snippet-folder';
const folderCollapse = createFolderCollapse();

// ─── Folders ───────────────────────────────────────────────

function findFolder(id) {
    if (!id) return null;
    return snippetFolders.find(folder => folder.id === id) || null;
}

function getHostNames(ids = []) {
    const idSet = new Set(ids || []);
    return availableHosts
        .filter(host => idSet.has(host.id))
        .map(host => host.name || host.host);
}

async function loadSnippetFolders() {
    const groups = await api.getGroups();
    snippetFolders = groups
        .filter(group => group.icon === SNIPPET_FOLDER_ICON)
        .sort((a, b) => a.name.localeCompare(b.name));
}

async function createSnippetFolder(name) {
    const trimmed = name.trim();
    if (!trimmed) return null;
    const existing = snippetFolders.find(f => f.name.toLowerCase() === trimmed.toLowerCase());
    if (existing) return existing;

    const folder = {
        id: generateId(),
        name: trimmed,
        parent_id: null,
        icon: SNIPPET_FOLDER_ICON,
        color: null,
        created_at: now(),
    };
    await api.saveGroup(folder);
    snippetFolders = [...snippetFolders, folder].sort((a, b) => a.name.localeCompare(b.name));
    return folder;
}

// ─── List rendering ─────────────────────────────────────────

function renderCard(snip, index) {
    const folder = findFolder(snip.group_id);
    const hostNames = getHostNames(snip.connection_ids);
    const tags = snip.tags || [];
    const meta = [
        folder ? `<span class="tag tag-folder">${escHtml(folder.name)}</span>` : '',
        ...hostNames.map(h => `<span class="tag tag-host">${escHtml(h)}</span>`),
        ...tags.map(t => `<span class="tag">${escHtml(t)}</span>`),
    ].filter(Boolean).join('');

    return `
        <div class="host-card snippet-card" data-id="${snip.id}" style="animation-delay:${index * 30}ms">
            <span class="host-card-drag" title="Drag to reorder">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/></svg>
            </span>
            <div class="host-card-body">
                <div class="host-card-top">
                    <span class="host-card-name">${escHtml(snip.label)}</span>
                </div>
                <div class="host-card-endpoint snippet-card-cmd" title="${escAttr(snip.command)}">${escHtml(snip.command)}</div>
                <div class="snippet-card-tags">${meta}</div>
            </div>
        </div>`;
}

function renderListItems(list) {
    return renderFolderSections({
        items: list,
        folders: snippetFolders,
        renderCard,
    });
}

function filterItems(list, q) {
    if (!q) return list;
    const lower = q.toLowerCase();
    return list.filter(s => {
        const haystack = [
            s.label,
            s.command,
            s.description,
            findFolder(s.group_id)?.name ?? '',
            ...getHostNames(s.connection_ids),
            ...(s.tags || []),
        ];
        return haystack.some(f => f && String(f).toLowerCase().includes(lower));
    });
}

function renderList() {
    const listEl = container?.querySelector('[data-role="list"]');
    if (!listEl) return;

    const filtered = filterItems(items, filterQuery);

    if (filtered.length === 0) {
        listEl.innerHTML = renderCardGridEmpty({
            icon: icons.terminal(48),
            hasItems: items.length > 0,
            emptyText: 'No snippets yet.<br>Click <strong>+</strong> to save your first command.',
            searchEmptyText: 'No results found.',
            extraClass: 'snippets-empty',
        });
        return;
    }

    listEl.innerHTML = renderListItems(filtered);

    if (listEl.querySelector('.host-folder-section')) folderCollapse.bind(listEl);
    wireDragReorder(listEl, filtered, filterQuery);
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

function showSnippetActionMenu(x, y, snip) {
    closeActionMenu();

    const menu = document.createElement('div');
    menu.className = 'host-action-menu';
    menu.setAttribute('role', 'menu');
    menu.innerHTML = `
        <div class="host-action-menu-title">${escHtml(snip.label)}</div>
        <button type="button" data-action="run">${icons.terminal(14)} Run in terminal</button>
        <button type="button" data-action="edit">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            Edit snippet
        </button>
    `;

    document.body.appendChild(menu);
    actionMenuEl = menu;

    menu.querySelector('[data-action="run"]').addEventListener('click', (e) => {
        e.stopPropagation();
        closeActionMenu();
        runSnippet(snip);
    });

    menu.querySelector('[data-action="edit"]').addEventListener('click', (e) => {
        e.stopPropagation();
        closeActionMenu();
        openEditModal(snip, false);
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

function runSnippet(snip) {
    document.getElementById('nav-terminal')?.click();
    runSnippetCommand(snip.command);
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
        let origEl = el;
        while (el && !el.classList?.contains('host-card') && !el.classList?.contains('host-folder-header')) {
            el = el.parentElement;
        }
        if (!el) {
            let section = origEl?.closest('.host-folder-section');
            if (!section) {
                const list = origEl?.closest('.hosts-list, .host-folder-items');
                if (list) {
                    const sections = list.querySelectorAll('.host-folder-section');
                    if (sections.length > 0) section = sections[sections.length - 1];
                }
            }
            if (section) {
                let cards = Array.from(section.querySelectorAll('.host-card')).filter(c => c.dataset.id !== excludeId);
                if (cards.length > 0) return cards[cards.length - 1];
                return section.querySelector('.host-folder-header');
            }
            const list = origEl?.closest('.hosts-list, .host-folder-items');
            if (list) {
                let cards = Array.from(list.querySelectorAll('.host-card')).filter(c => c.dataset.id !== excludeId);
                if (cards.length > 0) return cards[cards.length - 1];
            }
            return null;
        }
        if (el.classList.contains('host-card') && el.dataset.id === excludeId) return null;
        if (scopeEl && !scopeEl.contains(el)) return null;
        return el;
    };

    const setDropMarker = (target, above) => {
        if (currentTarget && currentTarget !== target) {
            currentTarget.classList.remove('drop-above', 'drop-below');
        }
        if (target && target.classList.contains('host-card')) {
            if (target !== currentTarget || above !== currentAbove) {
                target.classList.remove('drop-above', 'drop-below');
                target.classList.add(above ? 'drop-above' : 'drop-below');
            }
        } else if (target && target.classList.contains('host-folder-header')) {
            if (target !== currentTarget) {
                target.classList.add('drop-above');
            }
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
        let above = false;
        if (target.classList.contains('host-card')) {
            const r = target.getBoundingClientRect();
            above = lastY < r.top + r.height / 2;
        }
        setDropMarker(target, above);
    };

    const onPointerMove = (e) => {
        if (!drag) return;
        e.preventDefault();
        lastX = e.clientX;
        lastY = e.clientY;
        if (!rafId) rafId = requestAnimationFrame(renderFrame);
    };

    const onPointerUp = async (e) => {
        if (!drag) return;
        if (rafId) { cancelAnimationFrame(rafId); rafId = 0; }

        const sourceEl = drag.sourceEl;
        const scopeEl  = drag.scopeEl;
        const target = currentTarget || findTargetCard(e.clientX, e.clientY, drag.id, scopeEl);
        let above = currentAbove;
        if (target && target.classList.contains('host-card') && currentAbove == null) {
            above = e.clientY < target.getBoundingClientRect().top + target.getBoundingClientRect().height / 2;
        }

        const fromId = drag.id;

        drag.ghostEl.remove();
        sourceEl.classList.remove('is-dragging');
        if (currentTarget) currentTarget.classList.remove('drop-above', 'drop-below');
        currentTarget = null;
        currentAbove  = null;

        window.removeEventListener('pointermove',   onPointerMove);
        window.removeEventListener('pointerup',     onPointerUp);
        window.removeEventListener('pointercancel', onPointerUp);
        drag = null;

        if (!target) return;

        let changed = false;

        if (target.classList.contains('host-folder-header')) {
            let targetGroupId = target.closest('.host-folder-section')?.dataset.folderId;
            if (targetGroupId === '__unfiled__') targetGroupId = null;

            const fromIdx = items.findIndex(i => i.id === fromId);
            if (fromIdx >= 0) {
                const [removed] = items.splice(fromIdx, 1);
                removed.group_id = targetGroupId;
                const folderItems = items.filter(i => (i.group_id || null) === targetGroupId);
                if (folderItems.length > 0) {
                    const lastItem = folderItems[folderItems.length - 1];
                    const insertAt = items.findIndex(i => i.id === lastItem.id) + 1;
                    items.splice(insertAt, 0, removed);
                } else {
                    items.push(removed);
                }
                changed = true;
            }
        } else if (target.classList.contains('host-card')) {
            const toId = target.dataset.id;
            if (fromId === toId) return;

            const fromIdx = items.findIndex(i => i.id === fromId);
            if (fromIdx >= 0) {
                const removed = items[fromIdx];
                const toItem = items.find(i => i.id === toId);
                if (toItem) {
                    items.splice(fromIdx, 1);
                    removed.group_id = toItem.group_id;
                    const insertAt = items.findIndex(i => i.id === toId) + (above ? 0 : 1);
                    items.splice(insertAt, 0, removed);
                    changed = true;
                }
            }
        }

        if (changed) {
            let toSave = [];
            let globalOrder = 0;
            for (let s of items) {
                let sChanged = false;
                if ((s.sort_order || 0) !== globalOrder) {
                    s.sort_order = globalOrder;
                    sChanged = true;
                }
                if (s.id === fromId) {
                    sChanged = true;
                }
                if (sChanged) {
                    s.updated_at = now();
                    toSave.push(s);
                }
                globalOrder++;
            }

            for (let s of toSave) {
                await api.saveSnippet(s);
            }
            renderList();
        }
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
                scopeEl: card.closest('.hosts-list'), 
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

function bindCardClicks(listEl) {
    listEl.querySelectorAll('.host-card').forEach(card => {
        card.addEventListener('dblclick', (e) => {
            if (e.target.closest('.host-card-drag')) return;
            e.preventDefault();
            const snip = items.find(s => s.id === card.dataset.id);
            if (!snip) return;
            closeActionMenu();
            runSnippet(snip);
        });

        card.addEventListener('contextmenu', (e) => {
            if (e.target.closest('.host-card-drag')) return;
            e.preventDefault();
            e.stopPropagation();
            const snip = items.find(s => s.id === card.dataset.id);
            if (!snip) return;
            showSnippetActionMenu(e.clientX, e.clientY, snip);
        });
    });
}

// ─── Edit modal ────────────────────────────────────────────

function buildFormFields(snip) {
    return renderFields([
        { id: 'cmd-label',   label: 'Label',       value: snip.label,             placeholder: 'Restart Nginx' },
        { id: 'cmd-command', label: 'Command',      type: 'textarea', value: snip.command, placeholder: 'sudo systemctl restart nginx' },
        { id: 'cmd-desc',    label: 'Description',  value: snip.description ?? '', placeholder: 'Optional note...' },
        {
            id: 'cmd-folder', label: 'Folder', type: 'select', value: snip.group_id ?? '',
            options: [
                { value: '', text: 'Unfiled' },
                ...snippetFolders.map(folder => ({ value: folder.id, text: folder.name })),
            ],
        },
    ]) + `
        <div class="snippet-folder-create">
            <input type="text" id="cmd-new-folder-name" placeholder="New folder name" autocomplete="off" />
            <button type="button" class="btn btn-secondary btn-sm" id="cmd-create-folder">Add folder</button>
        </div>
        <div class="snippet-var-builder">
            <div class="snippet-var-row">
                <input type="text" id="cmd-var-name" placeholder="variable_name" autocomplete="off" />
                <button type="button" class="btn btn-secondary btn-sm" id="cmd-insert-var">Insert variable</button>
            </div>
            <div class="snippet-var-preview" id="cmd-var-preview"></div>
        </div>
        <div class="form-group">
            <label>Hosts</label>
            <div class="snippet-host-picker" id="cmd-host-picker">
                ${availableHosts.length
                    ? availableHosts.map(host => `
                        <label class="snippet-host-option">
                            <input type="checkbox" value="${escAttr(host.id)}" ${(snip.connection_ids || []).includes(host.id) ? 'checked' : ''} />
                            <span>${escHtml(host.name || host.host)}</span>
                            <small>${escHtml(host.username || '')}@${escHtml(host.host || '')}</small>
                        </label>
                    `).join('')
                    : '<div class="snippet-host-empty">No saved hosts yet.</div>'}
            </div>
        </div>
        <div class="form-group"><label>Tags</label><div id="cmd-tags-container"></div></div>`;
}

function bindSnippetFolderControls(panel) {
    const folderCtrl = selectMap.get('cmd-folder');
    const nameEl = panel.querySelector('#cmd-new-folder-name');
    const createBtn = panel.querySelector('#cmd-create-folder');
    if (!folderCtrl || !nameEl || !createBtn) return;

    const create = async () => {
        try {
            const folder = await createSnippetFolder(nameEl.value);
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

function bindSnippetVariableControls(panel) {
    const commandEl = panel.querySelector('#cmd-command');
    const nameEl = panel.querySelector('#cmd-var-name');
    const insertBtn = panel.querySelector('#cmd-insert-var');
    const previewEl = panel.querySelector('#cmd-var-preview');
    if (!commandEl || !nameEl || !insertBtn || !previewEl) return;

    const renderPreview = () => {
        const vars = extractSnippetVars(commandEl.value);
        previewEl.innerHTML = vars.length
            ? vars.map(v => `<span class="snippet-var-chip">{{${v}}}</span>`).join('')
            : '<span class="snippet-var-empty">Variables use {{name}} and are prompted before running.</span>';
    };

    const insertVariable = () => {
        const token = formatSnippetVar(nameEl.value);
        if (!token) {
            nameEl.focus();
            return;
        }
        const start = commandEl.selectionStart ?? commandEl.value.length;
        const end = commandEl.selectionEnd ?? commandEl.value.length;
        commandEl.setRangeText(token, start, end, 'end');
        nameEl.value = '';
        commandEl.focus();
        renderPreview();
    };

    insertBtn.addEventListener('click', insertVariable);
    nameEl.addEventListener('input', () => {
        const normalized = normalizeSnippetVarName(nameEl.value);
        if (nameEl.value !== normalized) nameEl.value = normalized;
    });
    nameEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            insertVariable();
        }
    });
    commandEl.addEventListener('input', renderPreview);
    renderPreview();
}

function readForm(original) {
    return {
        ...original,
        label:       readFieldValue('cmd-label'),
        command:     readFieldValue('cmd-command'),
        description: readFieldValue('cmd-desc') || null,
        group_id:    readFieldValue('cmd-folder') || null,
        connection_ids: Array.from(document.querySelectorAll('#cmd-host-picker input:checked')).map(el => el.value),
        tags:        tagInput ? tagInput.getTags() : original.tags,
        updated_at:  now(),
    };
}

function validateForm(snip) {
    if (!snip.label || !snip.command) return 'Label and Command are required';
    return null;
}

function newItemTemplate() {
    return {
        id: generateId(), label: '', command: '', description: null,
        tags: [], connection_ids: [], group_id: null,
        created_at: now(), updated_at: now(), synced: false, sort_order: 0,
    };
}

function openEditModal(snip, isNew) {
    closeActionMenu();

    openEntityEditModal({
        title: isNew ? 'New snippet' : 'Edit snippet',
        fieldsHtml: buildFormFields(snip),
        showDelete: !isNew,
        onMount(panel) {
            selectMap = hydrateSelects(panel);
            const tagsContainer = panel.querySelector('#cmd-tags-container');
            tagInput = new TagInput(tagsContainer, snip.tags || []);
            bindSnippetVariableControls(panel);
            bindSnippetFolderControls(panel);
            return () => {
                selectMap.forEach(ctrl => ctrl.destroy?.());
                selectMap.clear();
                tagInput = null;
            };
        },
        async onSave() {
            const updated = readForm(snip);
            const err = validateForm(updated);
            if (err) {
                showToast(err, 'error');
                return false;
            }
            try {
                await api.saveSnippet(updated);
                showToast(`Snippet "${updated.label}" saved`, 'success');
                await loadData();
                return true;
            } catch (e) {
                showToast(`Failed to save: ${e}`, 'error');
                return false;
            }
        },
        async onDelete() {
            try {
                await api.deleteSnippet(snip.id);
                showToast('Snippet deleted', 'success');
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
    const [hosts] = await Promise.all([
        api.getConnections(),
        loadSnippetFolders(),
    ]);
    availableHosts = hosts;
    items = await api.getSnippets();
    items.sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0) || (a.label || '').localeCompare(b.label || ''));
    renderList();
}

export function render(containerEl) {
    container = containerEl;
    container.innerHTML = renderCardGridPageShell({
        pageClass: 'snippets-page',
        headerClass: 'snippets-page-header',
        title: 'Snippets',
        searchPlaceholder: 'Search snippets...',
        addTitle: 'Add snippet',
        listClass: 'snippets-page-list hosts-list',
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
