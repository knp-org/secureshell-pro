// ═══════════════════════════════════════════════════════════
// Shared Utility Helpers
// ═══════════════════════════════════════════════════════════

/**
 * Generate a UUID v4 string.
 * @returns {string}
 */
export function generateId() {
    return crypto.randomUUID
        ? crypto.randomUUID()
        : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
              const r = (Math.random() * 16) | 0;
              return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
          });
}

/**
 * Current UTC timestamp in ISO-8601 format.
 * @returns {string}
 */
export function now() {
    return new Date().toISOString();
}

/**
 * Escape HTML entities for safe insertion into innerHTML.
 * @param {*} s
 * @returns {string}
 */
export function escHtml(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Escape a string for use inside an HTML attribute value.
 * @param {*} s
 * @returns {string}
 */
export function escAttr(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;');
}
