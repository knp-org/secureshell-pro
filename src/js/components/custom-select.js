// ═══════════════════════════════════════════════════════════
// CustomSelect — div-based dropdown replacement
//
// Native <select> dropdown panels are OS-rendered and ignore
// CSS theming on Linux (WebKitGTK).  This component gives
// full visual control while exposing the same .value interface
// that readFieldValue() expects.
// ═══════════════════════════════════════════════════════════

import { escHtml, escAttr } from '../utils/helpers.js';

/**
 * Render the static HTML for a custom select.
 * @param {string} id          — element id (used by readFieldValue, etc.)
 * @param {{value:string, text:string}[]} options
 * @param {string} [selected]  — initial value
 * @param {string} [extraClass]
 * @returns {string}
 */
export function renderCustomSelect(id, options, selected = '', extraClass = '') {
    const items = options.map(o =>
        `<div class="csel-item${o.value === selected ? ' active' : ''}" data-value="${escAttr(o.value)}">${escHtml(o.text)}</div>`
    ).join('');
    const label = options.find(o => o.value === selected)?.text ?? '';
    return `
        <div class="csel ${extraClass}" id="${id}" data-value="${escAttr(selected)}" tabindex="0">
            <div class="csel-trigger">
                <span class="csel-value">${escHtml(label)}</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg>
            </div>
            <div class="csel-dropdown">${items}</div>
        </div>`;
}

/**
 * Hydrate a rendered custom select — attach click handlers,
 * return a controller object.
 *
 * @param {string} id
 * @param {((value:string)=>void)|null} [onChange]
 * @returns {{ getValue:()=>string, setValue:(v:string,silent?:boolean)=>void, addOption:(value:string,text:string)=>void, el:HTMLElement }|null}
 */
export function initCustomSelect(idOrEl, onChange = null) {
    const el = typeof idOrEl === 'string'
        ? document.getElementById(idOrEl)
        : idOrEl;
    if (!el) return null;

    const trigger  = el.querySelector('.csel-value');
    const dropdown = el.querySelector('.csel-dropdown');
    let items      = el.querySelectorAll('.csel-item');

    function setValue(v, silent = false) {
        el.dataset.value = v;
        items.forEach(item => {
            const active = item.dataset.value === v;
            item.classList.toggle('active', active);
            if (active) trigger.textContent = item.textContent;
        });
        if (!silent && onChange) onChange(v);
    }

    function getValue() {
        return el.dataset.value ?? '';
    }

    function addOption(value, text) {
        const exists = dropdown.querySelector(`[data-value="${CSS.escape(value)}"]`);
        if (exists) return;
        const item = document.createElement('div');
        item.className = 'csel-item';
        item.dataset.value = value;
        item.textContent = text;
        item.addEventListener('click', onItemClick);
        dropdown.appendChild(item);
        items = el.querySelectorAll('.csel-item');
    }

    function onItemClick(e) {
        e.stopPropagation();
        setValue(e.currentTarget.dataset.value);
        el.classList.remove('open');
    }

    const onRootClick = (e) => {
        if (!el.contains(e.target)) el.classList.remove('open');
    };

    el.addEventListener('click', (e) => {
        e.stopPropagation();
        document.querySelectorAll('.csel.open').forEach(s => { if (s !== el) s.classList.remove('open'); });
        el.classList.toggle('open');
    });

    items.forEach(item => item.addEventListener('click', onItemClick));

    // Defer so the opening click does not immediately close the panel.
    document.addEventListener('click', onRootClick);

    return {
        getValue,
        setValue,
        addOption,
        el,
        destroy() {
            document.removeEventListener('click', onRootClick);
        },
    };
}

/**
 * Read the current value of a custom select by id.
 * Works as a drop-in for the native el.value pattern.
 * @param {string} id
 * @returns {string}
 */
export function readCustomSelectValue(id) {
    const el = document.getElementById(id);
    if (!el) return '';
    if (el.classList.contains('csel')) return el.dataset.value ?? '';
    return el.value ?? '';
}
