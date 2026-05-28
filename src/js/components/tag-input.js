// ═══════════════════════════════════════════════════════════
// TagInput — Reusable tag / pill input component
//
// Usage:
//   const ti = new TagInput(containerEl, ['nginx','deploy']);
//   ti.getTags();  // → ['nginx','deploy','newTag']
// ═══════════════════════════════════════════════════════════

import { escHtml, escAttr } from '../utils/helpers.js';

export class TagInput {
    /**
     * @param {HTMLElement} container — the element to render into
     * @param {string[]}    initial  — starting tags
     */
    constructor(container, initial = []) {
        this.container = container;
        this.tags      = [...initial];
        this._render();
    }

    /** @returns {string[]} current tag list */
    getTags() {
        return [...this.tags];
    }

    // ─── Internal ──────────────────────────────────────────

    _render() {
        this.container.innerHTML = `
            <div class="tags-input-wrap" data-role="tag-wrap">
                ${this.tags.map(t => this._tagHtml(t)).join('')}
                <input type="text" data-role="tag-input" placeholder="Add tag + Enter" />
            </div>
        `;

        const input = this.container.querySelector('[data-role="tag-input"]');

        input.addEventListener('keydown', e => {
            if (e.key === 'Enter' && input.value.trim()) {
                e.preventDefault();
                this._addTag(input.value.trim().toLowerCase());
                input.value = '';
            }
        });

        this.container.querySelectorAll('[data-action="remove-tag"]').forEach(btn => {
            btn.addEventListener('click', () => this._removeTag(btn.dataset.tag));
        });
    }

    _addTag(tag) {
        if (!this.tags.includes(tag)) {
            this.tags.push(tag);
            this._render();
        }
    }

    _removeTag(tag) {
        this.tags = this.tags.filter(t => t !== tag);
        this._render();
    }

    _tagHtml(tag) {
        return `<span class="tag">${escHtml(tag)}<span class="tag-remove" data-action="remove-tag" data-tag="${escAttr(tag)}">×</span></span>`;
    }
}
