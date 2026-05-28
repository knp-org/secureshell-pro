// ═══════════════════════════════════════════════════════════
// Form Builder — declarative form-field HTML generation
//
// Instead of hand-writing <div class="form-group"><label>…
// in every view, describe your fields as data and let this
// module emit the HTML.
// ═══════════════════════════════════════════════════════════

import { escHtml, escAttr } from '../utils/helpers.js';
import { renderCustomSelect, initCustomSelect } from './custom-select.js';

/**
 * @typedef {Object} FieldDef
 * @property {string}  id           — element id
 * @property {string}  label        — label text
 * @property {string}  [type]       — 'text' | 'number' | 'password' | 'select' | 'textarea'
 * @property {string}  [placeholder]
 * @property {*}       [value]      — current value
 * @property {{value:string,text:string}[]} [options] — for select
 * @property {string}  [style]      — inline style on the form-group
 */

/**
 * Render a single form field as an HTML string.
 * @param {FieldDef} f
 * @returns {string}
 */
export function renderField(f) {
    const type  = f.type ?? 'text';
    const style = f.style ? ` style="${f.style}"` : '';
    let inner;

    switch (type) {
        case 'select':
            inner = renderCustomSelect(f.id, f.options || [], String(f.value ?? ''));
            break;

        case 'textarea':
            inner = `<textarea id="${f.id}" placeholder="${escAttr(f.placeholder ?? '')}">${escHtml(f.value ?? '')}</textarea>`;
            break;

        default:
            inner = `<input type="${type}" id="${f.id}" value="${escAttr(f.value ?? '')}" placeholder="${escAttr(f.placeholder ?? '')}" />`;
    }

    return `<div class="form-group"${style}><label>${escHtml(f.label)}</label>${inner}</div>`;
}

/**
 * Render an array of fields.  Supports rows — pass sub-arrays
 * for fields that should sit side-by-side:
 *
 *   renderFields([
 *     { id:'name', label:'Name' },
 *     [                              // ← row
 *       { id:'host', label:'Host' },
 *       { id:'port', label:'Port', style:'max-width:120px' }
 *     ],
 *   ])
 *
 * @param {(FieldDef|FieldDef[])[]} fields
 * @returns {string}
 */
export function renderFields(fields) {
    return fields.map(f => {
        if (Array.isArray(f)) {
            return `<div class="form-row">${f.map(renderField).join('')}</div>`;
        }
        return renderField(f);
    }).join('');
}

/**
 * Read the current value from a rendered field by its id.
 * Works for native inputs AND custom selects.
 * @param {string} id
 * @returns {string}
 */
export function readFieldValue(id) {
    const el = document.getElementById(id);
    if (!el) return '';
    if (el.classList.contains('csel')) return el.dataset.value ?? '';
    return el.value.trim();
}

/**
 * Hydrate all custom selects rendered by renderFields.
 * Call this after inserting the HTML into the DOM.
 * @param {HTMLElement} container
 * @param {Object<string, (value:string)=>void>} [listeners] — id → onChange
 * @returns {Map<string, ReturnType<typeof initCustomSelect>>}
 */
export function hydrateSelects(container, listeners = {}) {
    const map = new Map();
    container.querySelectorAll('.csel').forEach(el => {
        const ctrl = initCustomSelect(el, listeners[el.id] || null);
        if (ctrl) map.set(el.id, ctrl);
    });
    return map;
}
