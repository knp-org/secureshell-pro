// ═══════════════════════════════════════════════════════════
// ListDetailView — Generic two-panel CRUD component
//
// Every view (hosts, snippets, keys) follows the same pattern:
//   LEFT:  searchable list of cards
//   RIGHT: detail / edit form
//
// This component extracts that shared skeleton so each view
// only needs to supply the parts that differ (via a config).
// ═══════════════════════════════════════════════════════════

import { icons }                      from '../utils/icons.js';
import { escHtml, escAttr, generateId, now } from '../utils/helpers.js';
import { showToast }                  from './toast.js';

/**
 * @typedef {Object} ListDetailConfig
 * @property {string}   title            — panel heading ("Hosts", "Snippets", …)
 * @property {string}   searchPlaceholder
 * @property {string}   emptyIcon        — SVG string for empty-state illustration
 * @property {string}   emptyTextAll     — shown when dataset is truly empty
 * @property {string}   emptyTextSearch  — shown when filter yields nothing
 * @property {string}   emptyDetailText  — right panel placeholder
 * @property {string}   listPanelClass   — CSS class on left panel wrapper
 * @property {string}   listClass        — CSS class on the card container
 * @property {string}   detailPanelClass — CSS class on right panel wrapper
 * @property {Function} loadItems        — async () => Item[]
 * @property {Function} saveItem         — async (item) => void
 * @property {Function} deleteItem       — async (id)   => void
 * @property {Function} renderCard       — (item, selected) => cardHTML string
 * @property {Function} [renderListItems]— (items, selectedId) => list HTML string
 * @property {Function} filterItem       — (item, query) => boolean
 * @property {Function} buildFormFields  — (item, isNew) => formInnerHTML
 * @property {Function} readForm         — (original) => updatedItem
 * @property {Function} validateForm     — (item) => string|null  (error msg or null)
 * @property {Function} newItemTemplate  — () => Item
 * @property {string}   entityName       — "Connection" / "Snippet" / etc. for toasts
 * @property {Function} [getItemLabel]   — (item) => string  for toast messages
 */

export class ListDetailView {
    /** @param {ListDetailConfig} config */
    constructor(config) {
        this.cfg        = config;
        this.items      = [];
        this.selectedId = null;
        this.isNew      = false;
        this.container  = null;
    }

    // ─── Public entry ──────────────────────────────────────

    /** Mount into the given container element. */
    render(container) {
        this.container = container;
        container.innerHTML = `
            <div class="${this.cfg.listPanelClass}">
                <div class="panel-header">
                    <h2>
                        ${this.cfg.title}
                        <button class="btn-add" data-action="add" title="Add ${this.cfg.entityName}">+</button>
                    </h2>
                    <div class="search-box">
                        ${icons.search()}
                        <input type="text" data-role="search" placeholder="${this.cfg.searchPlaceholder}" />
                    </div>
                </div>
                <div class="${this.cfg.listClass}" data-role="list"></div>
            </div>
            <div class="${this.cfg.detailPanelClass}" data-role="detail">
                ${this._emptyDetail()}
            </div>
        `;

        // Bind top-level events (delegated)
        this._qs('[data-action="add"]').addEventListener('click', () => this._startNew());
        this._qs('[data-role="search"]').addEventListener('input', e => this._renderList(e.target.value));

        this._load();
    }

    refresh() {
        this._load();
    }

    // ─── Data ──────────────────────────────────────────────

    async _load() {
        try   { this.items = await this.cfg.loadItems(); }
        catch { this.items = []; }
        this._renderList();
    }

    // ─── List rendering ────────────────────────────────────

    _renderList(filter = '') {
        const listEl   = this._qs('[data-role="list"]');
        const filtered = this.items.filter(item => this.cfg.filterItem(item, filter));

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div class="hosts-empty">
                    ${this.cfg.emptyIcon}
                    <p>${this.items.length === 0 ? this.cfg.emptyTextAll : this.cfg.emptyTextSearch}</p>
                </div>`;
            return;
        }

        listEl.innerHTML = this.cfg.renderListItems
            ? this.cfg.renderListItems(filtered, this.selectedId)
            : filtered.map((item, i) => this.cfg.renderCard(item, item.id === this.selectedId, i)).join('');

        // Delegate clicks on cards
        listEl.querySelectorAll('[data-id]').forEach(card => {
            card.addEventListener('click', () => this._select(card.dataset.id));
            card.addEventListener('dblclick', () => {
                const item = this.items.find(i => i.id === card.dataset.id);
                if (item && this.cfg.onItemDoubleClick) {
                    this.cfg.onItemDoubleClick(item);
                }
            });
        });

        // Let the view wire post-render behavior (e.g. drag-to-reorder).
        if (this.cfg.onListRendered) {
            this.cfg.onListRendered(listEl, filtered, filter);
        }
    }

    /** Replace the current items array (used by drag-to-reorder). */
    setItems(items) {
        this.items = items;
        this._refreshListSelection();
    }

    // ─── Selection / New ───────────────────────────────────

    _select(id) {
        this.selectedId = id;
        this.isNew      = false;
        const item = this.items.find(i => i.id === id);
        if (item) this._renderDetail(item);
        this._refreshListSelection();
    }

    _startNew() {
        this.isNew      = true;
        this.selectedId = null;
        const item = this.cfg.newItemTemplate();
        this._renderDetail(item);
        this._refreshListSelection();
    }

    _refreshListSelection() {
        const q = this._qs('[data-role="search"]')?.value || '';
        this._renderList(q);
    }

    // ─── Detail / Form ─────────────────────────────────────

    _renderDetail(item) {
        const panel = this._qs('[data-role="detail"]');
        const label = this.isNew ? `New ${this.cfg.entityName}` : `Edit ${this.cfg.entityName}`;

        panel.innerHTML = `
            <div class="detail-header">
                <h3>${label}</h3>
                ${!this.isNew ? '<button class="btn btn-danger btn-sm" data-action="delete">Delete</button>' : ''}
            </div>
            <div class="detail-form">
                ${this.cfg.buildFormFields(item, this.isNew)}
                <div class="form-actions">
                    <button class="btn btn-primary" data-action="save">
                        ${icons.save()} Save
                    </button>
                    <button class="btn btn-secondary" data-action="cancel">Cancel</button>
                </div>
            </div>
        `;

        // Bind form actions
        panel.querySelector('[data-action="save"]').addEventListener('click', () => this._save(item));
        panel.querySelector('[data-action="cancel"]').addEventListener('click', () => this._cancel());

        const delBtn = panel.querySelector('[data-action="delete"]');
        if (delBtn) delBtn.addEventListener('click', () => this._delete(item.id));

        // Let the view config do any post-render wiring (e.g. tag input listeners)
        if (this.cfg.onFormRendered) {
            this.cfg.onFormRendered(panel, item, this.isNew);
        }

        // Auto-focus first empty input
        setTimeout(() => {
            const first = panel.querySelector('.detail-form input:not([type=hidden])');
            if (first && !first.value) first.focus();
        }, 80);
    }

    async _save(original) {
        const updated = this.cfg.readForm(original);
        const err     = this.cfg.validateForm(updated);
        if (err) { showToast(err, 'error'); return; }

        try {
            await this.cfg.saveItem(updated);
            const label = this.cfg.getItemLabel?.(updated) ?? updated.label ?? updated.name ?? '';
            showToast(`${this.cfg.entityName} "${label}" saved`, 'success');
            this.selectedId = updated.id;
            this.isNew      = false;
            await this._load();
            this._select(updated.id);
        } catch (e) {
            showToast(`Failed to save: ${e}`, 'error');
        }
    }

    async _delete(id) {
        try {
            await this.cfg.deleteItem(id);
            showToast(`${this.cfg.entityName} deleted`, 'success');
            this.selectedId = null;
            this._cancel();
            await this._load();
        } catch (e) {
            showToast(`Failed to delete: ${e}`, 'error');
        }
    }

    _cancel() {
        this.isNew = false;
        this._qs('[data-role="detail"]').innerHTML = this._emptyDetail();
    }

    // ─── Helpers ───────────────────────────────────────────

    _emptyDetail() {
        return `<div class="detail-empty">${this.cfg.emptyIcon}
            <p>${this.cfg.emptyDetailText}</p></div>`;
    }

    _qs(sel) { return this.container.querySelector(sel); }
}

// Re-export helpers so views can import from a single place
export { escHtml, escAttr, generateId, now };
