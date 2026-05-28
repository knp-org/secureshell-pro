// ═══════════════════════════════════════════════════════════
// Card Grid Page — shared full-page shell (header + list)
// ═══════════════════════════════════════════════════════════

import { icons } from '../utils/icons.js';

/**
 * @typedef {Object} CardGridPageShellOptions
 * @property {string} pageClass
 * @property {string} headerClass
 * @property {string} [toolbarClass] — defaults to headerClass with -header replaced by -toolbar
 * @property {string} title
 * @property {string} searchPlaceholder
 * @property {string} addTitle
 * @property {string} [listClass]
 */

/**
 * @param {CardGridPageShellOptions} options
 * @returns {string}
 */
export function renderCardGridPageShell({
    pageClass,
    headerClass,
    toolbarClass,
    title,
    searchPlaceholder,
    addTitle,
    listClass = 'hosts-page-list hosts-list',
}) {
    const toolbar = toolbarClass ?? headerClass.replace(/-header$/, '-toolbar');
    return `
        <div class="${pageClass}">
            <header class="${headerClass}">
                <h2>${title}</h2>
                <div class="${toolbar}">
                    <div class="search-box">
                        ${icons.search()}
                        <input type="text" data-role="search" placeholder="${searchPlaceholder}" autocomplete="off" />
                    </div>
                    <button type="button" class="btn-add" data-action="add" title="${addTitle}">+</button>
                </div>
            </header>
            <div class="${listClass}" data-role="list"></div>
        </div>
    `;
}

/**
 * @param {HTMLElement} container
 * @param {{ onAdd: () => void, onSearchChange: (query: string) => void }} handlers
 */
export function bindCardGridPageHeader(container, { onAdd, onSearchChange }) {
    container.querySelector('[data-action="add"]')?.addEventListener('click', onAdd);
    container.querySelector('[data-role="search"]')?.addEventListener('input', (e) => {
        onSearchChange(e.target.value.trim());
    });
}

/**
 * @param {{ icon: string, hasItems: boolean, emptyText: string, searchEmptyText: string, extraClass?: string }} options
 * @returns {string}
 */
export function renderCardGridEmpty({
    icon,
    hasItems,
    emptyText,
    searchEmptyText,
    extraClass = '',
}) {
    const extra = extraClass ? ` ${extraClass}` : '';
    return `
        <div class="hosts-empty${extra}">
            ${icon}
            <p>${hasItems ? searchEmptyText : emptyText}</p>
        </div>`;
}
