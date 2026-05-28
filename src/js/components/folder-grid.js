// ═══════════════════════════════════════════════════════════
// Folder Grid — collapsible folder sections for card grids
// ═══════════════════════════════════════════════════════════

import { escHtml, escAttr } from '../utils/helpers.js';

/**
 * @param {Array<{ group_id?: string|null }>} list
 * @param {Array<{ id: string }>} folders
 */
export function shouldUseFolderSections(list, folders) {
    return folders.length > 0 || list.some(item => item.group_id);
}

/** Per-view folder collapse state. */
export function createFolderCollapse() {
    const collapsed = new Set();

    return {
        collapsed,
        bind(listEl) {
            bindFolderToggles(listEl, collapsed);
        },
    };
}

/**
 * @param {HTMLElement} listEl
 * @param {Set<string>} collapsedFolders
 */
export function bindFolderToggles(listEl, collapsedFolders) {
    listEl.querySelectorAll('[data-toggle-folder]').forEach(header => {
        header.addEventListener('click', (e) => {
            e.stopPropagation();
            const folderId = header.dataset.toggleFolder;
            const section = header.closest('.host-folder-section');
            if (!section) return;
            if (collapsedFolders.has(folderId)) {
                collapsedFolders.delete(folderId);
                section.classList.remove('collapsed');
            } else {
                collapsedFolders.add(folderId);
                section.classList.add('collapsed');
            }
        });
        const folderId = header.dataset.toggleFolder;
        if (collapsedFolders.has(folderId)) {
            header.closest('.host-folder-section')?.classList.add('collapsed');
        }
    });
}

/**
 * @typedef {Object} RenderFolderSectionsOptions
 * @property {Array} items
 * @property {Array<{ id: string, name: string }>} folders
 * @property {(item: *, index: number) => string} renderCard
 * @property {(item: *) => string} [getGroupId]
 * @property {boolean} [wrapFlatGrid]
 * @property {string} [flatItemsClass]
 * @property {string} [sectionItemsAttrs] — extra attributes on .host-folder-items
 */

/**
 * @param {RenderFolderSectionsOptions} options
 * @returns {string}
 */
export function renderFolderSections({
    items,
    folders,
    renderCard,
    getGroupId = (item) => item.group_id || '',
    wrapFlatGrid = false,
    flatItemsClass = 'host-folder-items',
    sectionItemsAttrs = '',
}) {
    if (!shouldUseFolderSections(items, folders)) {
        const cards = items.map((item, i) => renderCard(item, i)).join('');
        if (!cards) return '';
        if (wrapFlatGrid) {
            return `<div class="${flatItemsClass}">${cards}</div>`;
        }
        return cards;
    }

    const groups = new Map();
    items.forEach(item => {
        const key = getGroupId(item);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(item);
    });

    const orderedFolders = [
        ...folders.filter(folder => (groups.get(folder.id)?.length ?? 0) > 0),
        ...(groups.has('') && folders.length > 0 ? [{ id: '', name: 'Unfiled' }] : []),
    ];

    const known = new Set(orderedFolders.map(folder => folder.id));
    groups.forEach((_, key) => {
        if (!known.has(key)) {
            orderedFolders.push({ id: key, name: 'Missing folder' });
        }
    });

    const itemsAttr = sectionItemsAttrs ? ` ${sectionItemsAttrs}` : '';

    return orderedFolders.map(folder => {
        const folderItems = groups.get(folder.id) || [];
        const folderDomId = folder.id || '__unfiled__';
        return `
            <div class="host-folder-section" data-folder-id="${escAttr(folderDomId)}">
                <div class="host-folder-header" data-toggle-folder="${escAttr(folderDomId)}">
                    <span class="host-folder-arrow">▾</span>
                    <span class="host-folder-name">${escHtml(folder.name)}</span>
                    <span class="host-folder-count">${folderItems.length}</span>
                </div>
                <div class="host-folder-items"${itemsAttr}>
                    ${folderItems.map((item, i) => renderCard(item, i)).join('')}
                </div>
            </div>
        `;
    }).join('');
}
