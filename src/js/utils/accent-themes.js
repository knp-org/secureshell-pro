// ═══════════════════════════════════════════════════════════
// Accent color presets — applied via CSS custom properties
// ═══════════════════════════════════════════════════════════

/** @typedef {{ label: string, swatch: string, dark: Record<string, string>, light: Record<string, string>, terminalCursor: { dark: string, light: string } }} AccentPreset */

/** @type {Record<string, AccentPreset>} */
export const ACCENT_PRESETS = {
    gold: {
        label: 'Gold',
        swatch: '#eab308',
        terminalCursor: { dark: '#eab308', light: '#b45309' },
        dark: {
            '--accent': '#eab308',
            '--accent-hover': '#facc15',
            '--accent-dim': 'rgba(234, 179, 8, 0.15)',
            '--accent-glow': 'rgba(234, 179, 8, 0.25)',
            '--accent-secondary': '#ca8a04',
            '--border-active': 'rgba(234, 179, 8, 0.4)',
            '--bg-selected': 'rgba(234, 179, 8, 0.12)',
            '--shadow-glow': '0 0 24px rgba(234, 179, 8, 0.12)',
            '--gradient': 'linear-gradient(135deg, #facc15 0%, #eab308 50%, #ca8a04 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #eab308, #ca8a04)',
        },
        light: {
            '--accent': '#b45309',
            '--accent-hover': '#d97706',
            '--accent-dim': 'rgba(180, 83, 9, 0.08)',
            '--accent-glow': 'rgba(180, 83, 9, 0.12)',
            '--accent-secondary': '#92400e',
            '--border-active': 'rgba(180, 83, 9, 0.5)',
            '--bg-selected': 'rgba(202, 138, 4, 0.1)',
            '--shadow-glow': '0 0 20px rgba(180, 83, 9, 0.06)',
            '--gradient': 'linear-gradient(135deg, #d97706 0%, #b45309 50%, #92400e 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #b45309, #92400e)',
        },
    },
    amber: {
        label: 'Amber',
        swatch: '#f59e0b',
        terminalCursor: { dark: '#f59e0b', light: '#d97706' },
        dark: {
            '--accent': '#f59e0b',
            '--accent-hover': '#fbbf24',
            '--accent-dim': 'rgba(245, 158, 11, 0.15)',
            '--accent-glow': 'rgba(245, 158, 11, 0.25)',
            '--accent-secondary': '#d97706',
            '--border-active': 'rgba(245, 158, 11, 0.4)',
            '--bg-selected': 'rgba(245, 158, 11, 0.12)',
            '--shadow-glow': '0 0 24px rgba(245, 158, 11, 0.12)',
            '--gradient': 'linear-gradient(135deg, #fbbf24 0%, #f59e0b 50%, #d97706 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #f59e0b, #d97706)',
        },
        light: {
            '--accent': '#d97706',
            '--accent-hover': '#f59e0b',
            '--accent-dim': 'rgba(217, 119, 6, 0.1)',
            '--accent-glow': 'rgba(217, 119, 6, 0.14)',
            '--accent-secondary': '#b45309',
            '--border-active': 'rgba(217, 119, 6, 0.45)',
            '--bg-selected': 'rgba(245, 158, 11, 0.1)',
            '--shadow-glow': '0 0 20px rgba(217, 119, 6, 0.08)',
            '--gradient': 'linear-gradient(135deg, #f59e0b 0%, #d97706 50%, #b45309 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #d97706, #b45309)',
        },
    },
    orange: {
        label: 'Orange',
        swatch: '#f97316',
        terminalCursor: { dark: '#f97316', light: '#ea580c' },
        dark: {
            '--accent': '#f97316',
            '--accent-hover': '#fb923c',
            '--accent-dim': 'rgba(249, 115, 22, 0.15)',
            '--accent-glow': 'rgba(249, 115, 22, 0.25)',
            '--accent-secondary': '#ea580c',
            '--border-active': 'rgba(249, 115, 22, 0.4)',
            '--bg-selected': 'rgba(249, 115, 22, 0.12)',
            '--shadow-glow': '0 0 24px rgba(249, 115, 22, 0.12)',
            '--gradient': 'linear-gradient(135deg, #fb923c 0%, #f97316 50%, #ea580c 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #f97316, #ea580c)',
        },
        light: {
            '--accent': '#ea580c',
            '--accent-hover': '#f97316',
            '--accent-dim': 'rgba(234, 88, 12, 0.1)',
            '--accent-glow': 'rgba(234, 88, 12, 0.14)',
            '--accent-secondary': '#c2410c',
            '--border-active': 'rgba(234, 88, 12, 0.45)',
            '--bg-selected': 'rgba(249, 115, 22, 0.1)',
            '--shadow-glow': '0 0 20px rgba(234, 88, 12, 0.08)',
            '--gradient': 'linear-gradient(135deg, #f97316 0%, #ea580c 50%, #c2410c 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #ea580c, #c2410c)',
        },
    },
    rose: {
        label: 'Rose',
        swatch: '#f43f5e',
        terminalCursor: { dark: '#fb7185', light: '#e11d48' },
        dark: {
            '--accent': '#f43f5e',
            '--accent-hover': '#fb7185',
            '--accent-dim': 'rgba(244, 63, 94, 0.15)',
            '--accent-glow': 'rgba(244, 63, 94, 0.25)',
            '--accent-secondary': '#e11d48',
            '--border-active': 'rgba(244, 63, 94, 0.4)',
            '--bg-selected': 'rgba(244, 63, 94, 0.12)',
            '--shadow-glow': '0 0 24px rgba(244, 63, 94, 0.12)',
            '--gradient': 'linear-gradient(135deg, #fb7185 0%, #f43f5e 50%, #e11d48 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #f43f5e, #e11d48)',
        },
        light: {
            '--accent': '#e11d48',
            '--accent-hover': '#f43f5e',
            '--accent-dim': 'rgba(225, 29, 72, 0.08)',
            '--accent-glow': 'rgba(225, 29, 72, 0.12)',
            '--accent-secondary': '#be123c',
            '--border-active': 'rgba(225, 29, 72, 0.45)',
            '--bg-selected': 'rgba(244, 63, 94, 0.1)',
            '--shadow-glow': '0 0 20px rgba(225, 29, 72, 0.08)',
            '--gradient': 'linear-gradient(135deg, #f43f5e 0%, #e11d48 50%, #be123c 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #e11d48, #be123c)',
        },
    },
    violet: {
        label: 'Violet',
        swatch: '#8b5cf6',
        terminalCursor: { dark: '#a78bfa', light: '#7c3aed' },
        dark: {
            '--accent': '#8b5cf6',
            '--accent-hover': '#a78bfa',
            '--accent-dim': 'rgba(139, 92, 246, 0.15)',
            '--accent-glow': 'rgba(139, 92, 246, 0.25)',
            '--accent-secondary': '#7c3aed',
            '--border-active': 'rgba(139, 92, 246, 0.4)',
            '--bg-selected': 'rgba(139, 92, 246, 0.12)',
            '--shadow-glow': '0 0 24px rgba(139, 92, 246, 0.12)',
            '--gradient': 'linear-gradient(135deg, #a78bfa 0%, #8b5cf6 50%, #7c3aed 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #8b5cf6, #7c3aed)',
        },
        light: {
            '--accent': '#7c3aed',
            '--accent-hover': '#8b5cf6',
            '--accent-dim': 'rgba(124, 58, 237, 0.08)',
            '--accent-glow': 'rgba(124, 58, 237, 0.12)',
            '--accent-secondary': '#6d28d9',
            '--border-active': 'rgba(124, 58, 237, 0.45)',
            '--bg-selected': 'rgba(139, 92, 246, 0.1)',
            '--shadow-glow': '0 0 20px rgba(124, 58, 237, 0.08)',
            '--gradient': 'linear-gradient(135deg, #8b5cf6 0%, #7c3aed 50%, #6d28d9 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #7c3aed, #6d28d9)',
        },
    },
    blue: {
        label: 'Blue',
        swatch: '#3b82f6',
        terminalCursor: { dark: '#60a5fa', light: '#2563eb' },
        dark: {
            '--accent': '#3b82f6',
            '--accent-hover': '#60a5fa',
            '--accent-dim': 'rgba(59, 130, 246, 0.15)',
            '--accent-glow': 'rgba(59, 130, 246, 0.25)',
            '--accent-secondary': '#2563eb',
            '--border-active': 'rgba(59, 130, 246, 0.4)',
            '--bg-selected': 'rgba(59, 130, 246, 0.12)',
            '--shadow-glow': '0 0 24px rgba(59, 130, 246, 0.12)',
            '--gradient': 'linear-gradient(135deg, #60a5fa 0%, #3b82f6 50%, #2563eb 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #3b82f6, #2563eb)',
        },
        light: {
            '--accent': '#2563eb',
            '--accent-hover': '#3b82f6',
            '--accent-dim': 'rgba(37, 99, 235, 0.08)',
            '--accent-glow': 'rgba(37, 99, 235, 0.12)',
            '--accent-secondary': '#1d4ed8',
            '--border-active': 'rgba(37, 99, 235, 0.45)',
            '--bg-selected': 'rgba(59, 130, 246, 0.1)',
            '--shadow-glow': '0 0 20px rgba(37, 99, 235, 0.08)',
            '--gradient': 'linear-gradient(135deg, #3b82f6 0%, #2563eb 50%, #1d4ed8 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #2563eb, #1d4ed8)',
        },
    },
    cyan: {
        label: 'Cyan',
        swatch: '#06b6d4',
        terminalCursor: { dark: '#22d3ee', light: '#0891b2' },
        dark: {
            '--accent': '#06b6d4',
            '--accent-hover': '#22d3ee',
            '--accent-dim': 'rgba(6, 182, 212, 0.15)',
            '--accent-glow': 'rgba(6, 182, 212, 0.25)',
            '--accent-secondary': '#0891b2',
            '--border-active': 'rgba(6, 182, 212, 0.4)',
            '--bg-selected': 'rgba(6, 182, 212, 0.12)',
            '--shadow-glow': '0 0 24px rgba(6, 182, 212, 0.12)',
            '--gradient': 'linear-gradient(135deg, #22d3ee 0%, #06b6d4 50%, #0891b2 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #06b6d4, #0891b2)',
        },
        light: {
            '--accent': '#0891b2',
            '--accent-hover': '#06b6d4',
            '--accent-dim': 'rgba(8, 145, 178, 0.08)',
            '--accent-glow': 'rgba(8, 145, 178, 0.12)',
            '--accent-secondary': '#0e7490',
            '--border-active': 'rgba(8, 145, 178, 0.45)',
            '--bg-selected': 'rgba(6, 182, 212, 0.1)',
            '--shadow-glow': '0 0 20px rgba(8, 145, 178, 0.08)',
            '--gradient': 'linear-gradient(135deg, #06b6d4 0%, #0891b2 50%, #0e7490 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #0891b2, #0e7490)',
        },
    },
    emerald: {
        label: 'Emerald',
        swatch: '#10b981',
        terminalCursor: { dark: '#34d399', light: '#059669' },
        dark: {
            '--accent': '#10b981',
            '--accent-hover': '#34d399',
            '--accent-dim': 'rgba(16, 185, 129, 0.15)',
            '--accent-glow': 'rgba(16, 185, 129, 0.25)',
            '--accent-secondary': '#059669',
            '--border-active': 'rgba(16, 185, 129, 0.4)',
            '--bg-selected': 'rgba(16, 185, 129, 0.12)',
            '--shadow-glow': '0 0 24px rgba(16, 185, 129, 0.12)',
            '--gradient': 'linear-gradient(135deg, #34d399 0%, #10b981 50%, #059669 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #10b981, #059669)',
        },
        light: {
            '--accent': '#059669',
            '--accent-hover': '#10b981',
            '--accent-dim': 'rgba(5, 150, 105, 0.08)',
            '--accent-glow': 'rgba(5, 150, 105, 0.12)',
            '--accent-secondary': '#047857',
            '--border-active': 'rgba(5, 150, 105, 0.45)',
            '--bg-selected': 'rgba(16, 185, 129, 0.1)',
            '--shadow-glow': '0 0 20px rgba(5, 150, 105, 0.08)',
            '--gradient': 'linear-gradient(135deg, #10b981 0%, #059669 50%, #047857 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #059669, #047857)',
        },
    },
    lime: {
        label: 'Lime',
        swatch: '#84cc16',
        terminalCursor: { dark: '#a3e635', light: '#65a30d' },
        dark: {
            '--accent': '#84cc16',
            '--accent-hover': '#a3e635',
            '--accent-dim': 'rgba(132, 204, 22, 0.15)',
            '--accent-glow': 'rgba(132, 204, 22, 0.25)',
            '--accent-secondary': '#65a30d',
            '--border-active': 'rgba(132, 204, 22, 0.4)',
            '--bg-selected': 'rgba(132, 204, 22, 0.12)',
            '--shadow-glow': '0 0 24px rgba(132, 204, 22, 0.12)',
            '--gradient': 'linear-gradient(135deg, #a3e635 0%, #84cc16 50%, #65a30d 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #84cc16, #65a30d)',
        },
        light: {
            '--accent': '#65a30d',
            '--accent-hover': '#84cc16',
            '--accent-dim': 'rgba(101, 163, 13, 0.1)',
            '--accent-glow': 'rgba(101, 163, 13, 0.14)',
            '--accent-secondary': '#4d7c0f',
            '--border-active': 'rgba(101, 163, 13, 0.45)',
            '--bg-selected': 'rgba(132, 204, 22, 0.1)',
            '--shadow-glow': '0 0 20px rgba(101, 163, 13, 0.08)',
            '--gradient': 'linear-gradient(135deg, #84cc16 0%, #65a30d 50%, #4d7c0f 100%)',
            '--gradient-btn': 'linear-gradient(135deg, #65a30d, #4d7c0f)',
        },
    },
};

const ACCENT_VAR_KEYS = Object.keys(ACCENT_PRESETS.gold.dark);

/** @returns {string} */
export function getCurrentAccentId() {
    const id = document.documentElement.dataset.accent;
    return id && ACCENT_PRESETS[id] ? id : 'gold';
}

/**
 * @param {string} id
 * @param {{ persist?: boolean }} [options]
 */
export function applyAccent(id) {
    const accentId = ACCENT_PRESETS[id] ? id : 'gold';
    const preset = ACCENT_PRESETS[accentId];
    const isLight = document.documentElement.dataset.theme === 'light';
    const vars = isLight ? preset.light : preset.dark;
    const root = document.documentElement;

    root.dataset.accent = accentId;

    if (accentId === 'gold') {
        for (const key of ACCENT_VAR_KEYS) {
            root.style.removeProperty(key);
        }
    } else {
        for (const key of ACCENT_VAR_KEYS) {
            root.style.setProperty(key, vars[key]);
        }
    }

    window.dispatchEvent(new CustomEvent('appearance-changed'));
    return preset;
}

/** Terminal cursor color for current theme + accent */
export function getAccentTerminalCursor() {
    const id = getCurrentAccentId();
    const preset = ACCENT_PRESETS[id] || ACCENT_PRESETS.gold;
    const isLight = document.documentElement.dataset.theme === 'light';
    return isLight ? preset.terminalCursor.light : preset.terminalCursor.dark;
}

export function renderAccentSwatches(selectedId) {
    return Object.entries(ACCENT_PRESETS).map(([id, preset]) => `
        <button
            type="button"
            class="accent-swatch${id === selectedId ? ' is-selected' : ''}"
            data-accent="${id}"
            title="${preset.label}"
            aria-label="${preset.label} accent"
            aria-pressed="${id === selectedId}"
            style="--swatch-color: ${preset.swatch}"
        ></button>
    `).join('');
}
