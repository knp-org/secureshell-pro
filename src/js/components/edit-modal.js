// ═══════════════════════════════════════════════════════════
// Entity Edit Modal — shared dialog shell for grid views
// ═══════════════════════════════════════════════════════════

import { icons } from '../utils/icons.js';

/**
 * @typedef {Object} EntityEditModalOptions
 * @property {string} title — dialog heading
 * @property {string} fieldsHtml — inner form markup
 * @property {boolean} [showDelete]
 * @property {(panel: HTMLElement, overlay: HTMLElement) => (void|(() => void))} [onMount]
 * @property {() => Promise<boolean>} onSave — return true to close
 * @property {() => Promise<boolean>} [onDelete]
 */

/**
 * @param {EntityEditModalOptions} options
 * @returns {{ close: () => void, panel: HTMLElement, overlay: HTMLElement }}
 */
export function openEntityEditModal({
    title,
    fieldsHtml,
    showDelete = false,
    onMount,
    onSave,
    onDelete,
}) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay entity-edit-overlay';
    overlay.innerHTML = `
        <div class="modal entity-edit-modal" role="dialog" aria-modal="true">
            <div class="entity-edit-modal-header">
                <h3>${title}</h3>
                ${showDelete ? '<button type="button" class="btn btn-danger btn-sm" data-action="delete">Delete</button>' : ''}
            </div>
            <div class="entity-edit-modal-body detail-form">
                ${fieldsHtml}
            </div>
            <div class="modal-actions entity-edit-modal-actions">
                <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
                <button type="button" class="btn btn-primary" data-action="save">${icons.save()} Save</button>
            </div>
        </div>
    `;

    const panel = overlay.querySelector('.entity-edit-modal-body');
    let cleanup = () => {};

    const close = () => {
        cleanup();
        overlay.remove();
    };

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) close();
    });

    document.body.appendChild(overlay);

    if (onMount) {
        const result = onMount(panel, overlay);
        if (typeof result === 'function') cleanup = result;
    }

    overlay.querySelector('[data-action="cancel"]').addEventListener('click', close);

    overlay.querySelector('[data-action="save"]').addEventListener('click', async () => {
        if (await onSave(panel)) close();
    });

    const delBtn = overlay.querySelector('[data-action="delete"]');
    if (delBtn && onDelete) {
        delBtn.addEventListener('click', async () => {
            if (await onDelete(panel)) close();
        });
    }

    setTimeout(() => {
        const first = panel.querySelector('input:not([type=hidden]):not([type=checkbox])');
        if (first && !first.value) first.focus();
    }, 80);

    return { close, panel, overlay };
}
