// ═══════════════════════════════════════════════════════════
// SecureShell Pro — App Entry Point
// ═══════════════════════════════════════════════════════════

import * as hostsView from './views/hosts.js';
import * as terminalView from './views/terminal.js';
import * as commandsView from './views/commands.js';
import * as keysView from './views/keys.js';
import * as sftpView from './views/sftp.js';
import * as settingsView from './views/settings.js';
import { ensureUnlocked } from './views/vault-gate.js';
import { initTitlebar } from './titlebar.js';
import * as api from './api.js';

const views = {
    hosts:    { module: hostsView,    container: null, rendered: false },
    terminal: { module: terminalView, container: null, rendered: false },
    commands: { module: commandsView, container: null, rendered: false },
    keys:     { module: keysView,     container: null, rendered: false },
    sftp:     { module: sftpView,     container: null, rendered: false },
    settings: { module: settingsView, container: null, rendered: false },
};

let currentView = 'hosts';

async function init() {
    // Apply saved theme/font before first paint
    await settingsView.loadAppearanceSettings();

    initTitlebar();

    // Gate the entire app behind the vault unlock screen.
    try {
        await ensureUnlocked();
    } catch (err) {
        console.error('Vault gate failed:', err);
        return;
    }

    // Get containers
    views.hosts.container    = document.getElementById('view-hosts');
    views.terminal.container = document.getElementById('view-terminal');
    views.commands.container = document.getElementById('view-commands');
    views.keys.container     = document.getElementById('view-keys');
    views.sftp.container     = document.getElementById('view-sftp');
    views.settings.container = document.getElementById('view-settings');

    // Sidebar nav
    document.querySelectorAll('.nav-btn[data-view]').forEach(btn => {
        btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    // Lock button — clear the in-memory master key and force re-unlock.
    document.getElementById('nav-lock')?.addEventListener('click', async () => {
        try { await api.vaultLock(); } catch (err) { console.error('lock failed:', err); }
        // Hard reload so cached view data (with decrypted fields) is discarded
        // and the unlock gate is shown again.
        window.location.reload();
    });

    // Render initial view
    switchView('hosts');

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Reload (Ctrl/Cmd+R or F5) — Tauri 2 doesn't wire this by default.
        if ((e.ctrlKey || e.metaKey) && (e.key === 'r' || e.key === 'R')) {
            e.preventDefault();
            window.location.reload();
            return;
        }
        if (e.key === 'F5') {
            e.preventDefault();
            window.location.reload();
            return;
        }
        if (e.ctrlKey || e.metaKey) {
            switch (e.key) {
                case '1': e.preventDefault(); switchView('hosts'); break;
                case '2': e.preventDefault(); switchView('terminal'); break;
                case '3': e.preventDefault(); switchView('commands'); break;
                case '4': e.preventDefault(); switchView('keys'); break;
                case '5': e.preventDefault(); switchView('sftp'); break;
                case ',': e.preventDefault(); switchView('settings'); break;
            }
        }
    });

    // Disable default context menu entirely to prepare for custom context menus
    document.addEventListener('contextmenu', (e) => {
        e.preventDefault();
    });
}

function switchView(name) {
    if (!views[name]) return;

    // Update active states
    currentView = name;
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.nav-btn[data-view="${name}"]`)?.classList.add('active');

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    views[name].container.classList.add('active');

    // Lazy-render views
    if (!views[name].rendered) {
        views[name].module.render(views[name].container);
        views[name].rendered = true;
    } else if (views[name].module.refresh) {
        // If already rendered, call refresh to sync data (e.g. snippets)
        views[name].module.refresh();
    }
}

// Export switchView helper for other modules to use (e.g. going to terminal)
export { switchView };
export { terminalView };
export { sftpView };

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

