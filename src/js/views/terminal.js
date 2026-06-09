// ═══════════════════════════════════════════════════════════
// Terminal View — xterm.js session manager with tabs + snippets sidebar
// ═══════════════════════════════════════════════════════════

import * as api from '../api.js';
import { clipboardReadText, clipboardWriteText } from '../utils/clipboard.js';
import { showToast } from '../components/toast.js';
import { extractSnippetVars, replaceSnippetVars } from '../utils/snippet-vars.js';
import { getTerminalTheme, getTerminalFontSize } from './settings.js';

// Active terminal sessions mapping: sessionId -> { term, fitAddon, hostInfo, tabEl }
const activeSessions = new Map();
let currentSessionId = null;
let eventListenersBound = false;
let snippetsCache = [];
let snippetFolders = [];
let hostsCache = [];
let isRendered = false;
const SNIPPET_FOLDER_ICON = 'snippet-folder';
const sidebarCollapsed = new Set();

const LOCAL_HOST_INFO = {
    id: '__local__',
    name: 'Local',
    host: 'localhost',
    isLocal: true,
};

// Lazy-loaded xterm modules (loaded on first use, not at import time)
let Terminal = null;
let FitAddon = null;

async function loadXterm() {
    if (Terminal) return;
    const xtermMod = await import('../../assets/xterm/xterm.mjs');
    const fitMod   = await import('../../assets/xterm/addon-fit.mjs');
    Terminal = xtermMod.Terminal;
    FitAddon = fitMod.FitAddon;
}

export function render(container) {
    if (isRendered) return;
    renderSkeleton(container);
    isRendered = true;
}

export function refresh() {
    loadSnippets();
}

function renderSkeleton(container) {
    container.innerHTML = `
        <div class="terminal-view-container">
            <div class="terminal-tabs-bar">
                <div class="terminal-tabs" id="terminal-tabs-list"></div>
                <button class="btn-toggle-snippets" id="btn-toggle-snippets" title="Toggle Snippets">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                    <span>Snippets</span>
                </button>
            </div>
            <div class="terminal-main-area">
                <!-- Terminal Workspace -->
                <div class="terminal-workspace" id="terminal-workspace">
                    <div class="terminal-empty-state" id="terminal-empty-state">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                            <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                        </svg>
                        <h3>No Active Sessions</h3>
                        <p>Open a <strong>local shell</strong> or connect to a host from <strong>Hosts</strong>.</p>
                        <div class="terminal-empty-actions">
                            <button type="button" class="btn btn-primary" id="btn-empty-local">Local shell</button>
                            <button type="button" class="btn btn-secondary" id="btn-empty-ssh">SSH host…</button>
                        </div>
                    </div>
                </div>
                <!-- Snippets Sidebar -->
                <div class="snippets-sidebar" id="snippets-sidebar">
                    <div class="snippets-sidebar-header">
                        <h4>Snippets</h4>
                        <input type="text" class="snippets-search" id="snippets-search" placeholder="Search..." />
                    </div>
                    <div class="snippets-list" id="snippets-list"></div>
                </div>
            </div>
            
            <!-- Hosts Modal Overlay -->
            <div class="terminal-hosts-modal-overlay" id="terminal-hosts-modal" style="display: none;">
                <div class="terminal-hosts-modal">
                    <div class="modal-header">
                        <h3>Select Host to Connect</h3>
                        <button class="btn-close-modal" id="btn-close-hosts-modal">&times;</button>
                    </div>
                    <div class="modal-body">
                        <input type="text" class="modal-search" id="modal-hosts-search" placeholder="Search hosts..." />
                        <div class="modal-hosts-list" id="modal-hosts-list">
                            <div class="empty-msg">Loading hosts...</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.getElementById('btn-toggle-snippets').addEventListener('click', (e) => {
        const sidebar = document.getElementById('snippets-sidebar');
        const isOpen = sidebar.classList.toggle('open');
        e.currentTarget.classList.toggle('active', isOpen);
        // Refit active terminal when sidebar toggles
        setTimeout(() => refitCurrentSession(), 200);
    });

    document.getElementById('snippets-search').addEventListener('input', (e) => {
        renderSnippetsList(e.target.value);
    });

    document.getElementById('btn-close-hosts-modal').addEventListener('click', closeHostsModal);

    document.getElementById('btn-empty-local')?.addEventListener('click', () => startLocalShell());
    document.getElementById('btn-empty-ssh')?.addEventListener('click', () => openHostsModal());

    document.getElementById('modal-hosts-search').addEventListener('input', (e) => {
        renderModalHosts(e.target.value);
    });

    renderTabs();
    loadSnippets();
    setupGlobalEventListeners();
}

// ─── Snippets ──────────────────────────────────────────────

async function loadSnippets() {
    try {
        const [snippets, groups] = await Promise.all([
            api.getSnippets(),
            api.getGroups(),
        ]);
        snippetsCache = snippets;
        snippetFolders = groups.filter(group => group.icon === SNIPPET_FOLDER_ICON);
    } catch {
        snippetsCache = [];
        snippetFolders = [];
    }
    renderSnippetsList();
}

function renderSnippetsList(filter = '') {
    const listEl = document.getElementById('snippets-list');
    if (!listEl) return;

    const q = filter.toLowerCase();
    const currentHostId = activeSessions.get(currentSessionId)?.hostInfo?.id ?? null;
    const visible = snippetsCache.filter(s => {
        const mappedHosts = s.connection_ids || [];
        return !currentHostId || mappedHosts.length === 0 || mappedHosts.includes(currentHostId);
    });
    const filtered = visible.filter(s => {
        if (!q) return true;
        const folder = findSnippetFolder(s.group_id)?.name ?? '';
        return [s.label, s.command, folder, ...(s.tags || [])].some(value =>
            value.toLowerCase().includes(q)
        );
    });

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div class="snippets-empty">
                <p>${snippetsCache.length === 0 ? 'No snippets saved yet.<br>Add some in the Snippets tab.' : 'No matching snippets for this host.'}</p>
            </div>`;
        return;
    }

    listEl.innerHTML = renderGroupedSnippetList(filtered);

    listEl.querySelectorAll('.snippet-item').forEach(el => {
        el.addEventListener('click', () => {
            const cmd = el.dataset.cmd;
            runSnippetCommand(cmd);
        });
    });

    listEl.querySelectorAll('[data-toggle-folder]').forEach(header => {
        header.addEventListener('click', () => {
            const folderId = header.dataset.toggleFolder;
            const section = header.closest('.snippet-folder-section');
            if (!section) return;
            if (sidebarCollapsed.has(folderId)) {
                sidebarCollapsed.delete(folderId);
                section.classList.remove('collapsed');
            } else {
                sidebarCollapsed.add(folderId);
                section.classList.add('collapsed');
            }
        });
    });
}

function renderGroupedSnippetList(snippets) {
    const groups = new Map();
    snippets.forEach(snippet => {
        const key = snippet.group_id || '';
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(snippet);
    });

    const orderedFolders = [
        ...snippetFolders.filter(folder => groups.has(folder.id)),
        ...(groups.has('') ? [{ id: '', name: 'Unfiled' }] : []),
    ];

    const known = new Set(orderedFolders.map(folder => folder.id));
    groups.forEach((_, key) => {
        if (!known.has(key)) orderedFolders.push({ id: key, name: 'Missing folder' });
    });

    return orderedFolders.map(folder => {
        const folderId = folder.id || '__unfiled__';
        const folderItems = groups.get(folder.id) || [];
        return `
            <div class="snippet-folder-section${sidebarCollapsed.has(folderId) ? ' collapsed' : ''}" data-folder-id="${escAttr(folderId)}">
                <div class="snippet-folder-header" data-toggle-folder="${escAttr(folderId)}">
                    <span class="snippet-folder-arrow">▾</span>
                    <span class="snippet-folder-name">${escHtml(folder.name)}</span>
                    <span class="snippet-folder-count">${folderItems.length}</span>
                </div>
                <div class="snippet-folder-items">
                    ${folderItems.map(renderSnippetItem).join('')}
                </div>
            </div>
        `;
    }).join('');
}

function renderSnippetItem(s) {
    const mappedCount = (s.connection_ids || []).length;
    return `
        <div class="snippet-item" data-cmd="${escAttr(s.command)}" title="Click to run: ${escAttr(s.command)}">
            <div class="snippet-item-label">
                <span>${escHtml(s.label)}</span>
                ${mappedCount ? `<small>${mappedCount} host${mappedCount === 1 ? '' : 's'}</small>` : ''}
            </div>
            <code class="snippet-item-cmd">${escHtml(s.command)}</code>
        </div>
    `;
}

function findSnippetFolder(id) {
    return snippetFolders.find(folder => folder.id === id) || null;
}

export async function runSnippetCommand(command) {
    if (!currentSessionId) {
        showToast('No active terminal session', 'error');
        return;
    }

    let finalCmd = command;
    const vars = extractSnippetVars(command);
    if (vars.length > 0) {
        const values = await promptSnippetVars(vars);
        if (!values) return; // user cancelled
        finalCmd = replaceSnippetVars(command, values);
    }

    api.sshWrite(currentSessionId, finalCmd + '\n').then(() => {
        showToast(`Running: ${finalCmd.substring(0, 40)}${finalCmd.length > 40 ? '...' : ''}`, 'success');
    }).catch(err => {
        showToast('Failed to send command: ' + err, 'error');
    });
}

function promptSnippetVars(vars) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'snippet-vars-overlay';
        overlay.innerHTML = `
            <div class="snippet-vars-modal">
                <h3>Fill snippet variables</h3>
                <form class="snippet-vars-form">
                    ${vars.map(v => `
                        <label>
                            <span>${escHtml(v)}</span>
                            <input type="text" name="${escAttr(v)}" autocomplete="off" />
                        </label>
                    `).join('')}
                    <div class="snippet-vars-actions">
                        <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
                        <button type="submit" class="btn btn-primary">Run</button>
                    </div>
                </form>
            </div>
        `;
        document.body.appendChild(overlay);
        const form = overlay.querySelector('form');
        const firstInput = form.querySelector('input');
        if (firstInput) firstInput.focus();

        const close = (result) => {
            document.removeEventListener('keydown', onKey);
            overlay.remove();
            resolve(result);
        };

        function onKey(e) {
            if (e.key === 'Escape') close(null);
        }

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const values = {};
            vars.forEach(v => { values[v] = form.elements[v].value; });
            close(values);
        });
        overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => close(null));
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(null); });
        document.addEventListener('keydown', onKey);
    });
}

// ─── Clipboard → PTY ───────────────────────────────────────

async function pasteIntoSession(sessionId) {
    try {
        const text = await clipboardReadText();
        if (text) {
            const processedText = text.replace(/\r?\n/g, '\r');
            await api.sshWrite(sessionId, processedText);
        }
    } catch (err) {
        showToast('Paste failed: ' + err, 'error');
    }
}

function pasteTextIntoSession(sessionId, text) {
    if (!text) return;
    const processedText = text.replace(/\r?\n/g, '\r');
    api.sshWrite(sessionId, processedText).catch(err => {
        showToast('Paste failed: ' + err, 'error');
    });
}

// ─── Terminal Click Menu ───────────────────────────────────

let clickMenuEl = null;

function getClickMenu() {
    if (clickMenuEl && document.body.contains(clickMenuEl)) return clickMenuEl;
    clickMenuEl = document.createElement('div');
    clickMenuEl.className = 'terminal-click-menu';
    clickMenuEl.style.display = 'none';
    clickMenuEl.innerHTML = `
        <button type="button" data-action="copy">Copy</button>
        <button type="button" data-action="paste">Paste</button>
    `;
    document.body.appendChild(clickMenuEl);

    // Dismiss on outside interaction
    document.addEventListener('mousedown', (e) => {
        if (clickMenuEl.style.display !== 'none' && !clickMenuEl.contains(e.target)) {
            clickMenuEl.style.display = 'none';
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') clickMenuEl.style.display = 'none';
    });
    return clickMenuEl;
}

function showClickMenu(x, y, term, sessionId) {
    const menu = getClickMenu();
    const copyBtn = menu.querySelector('[data-action="copy"]');
    const pasteBtn = menu.querySelector('[data-action="paste"]');

    copyBtn.disabled = !term.hasSelection();

    copyBtn.onclick = async () => {
        const sel = term.getSelection();
        if (sel) {
            try {
                await clipboardWriteText(sel);
                showToast('Copied to clipboard', 'success');
            } catch (err) {
                showToast('Copy failed: ' + err, 'error');
            }
        }
        menu.style.display = 'none';
    };

    pasteBtn.onclick = async () => {
        await pasteIntoSession(sessionId);
        menu.style.display = 'none';
    };

    menu.style.display = 'flex';
    // Position, keeping menu within viewport
    const rect = menu.getBoundingClientRect();
    const maxX = window.innerWidth - rect.width - 4;
    const maxY = window.innerHeight - rect.height - 4;
    menu.style.left = Math.max(4, Math.min(x, maxX)) + 'px';
    menu.style.top  = Math.max(4, Math.min(y, maxY)) + 'px';
}

function attachClickMenu(termDiv, term, sessionId) {
    // Show menu after a left-click selection completes
    termDiv.addEventListener('mouseup', (e) => {
        if (e.button !== 0) return;
        if (!term.hasSelection()) return;
        // Defer so xterm finalizes the selection first
        setTimeout(() => {
            if (term.hasSelection()) showClickMenu(e.clientX, e.clientY, term, sessionId);
        }, 0);
    });

    // Also support right-click as a context menu
    termDiv.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        showClickMenu(e.clientX, e.clientY, term, sessionId);
    });
}

function escHtml(s) { return (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function escAttr(s) { return (s ?? '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }

// ─── Terminal sessions (SSH + local) ───────────────────────

function tabTitle(hostInfo) {
    if (hostInfo?.isLocal) return 'Local';
    return hostInfo?.name || hostInfo?.host || 'Session';
}

async function createTerminalSession(hostInfo, { connectingMessage, connect }) {
    try {
        await loadXterm();
    } catch (err) {
        showToast('Failed to load terminal: ' + err, 'error');
        return;
    }

    const sessionId = crypto.randomUUID();

    let workspace = document.getElementById('terminal-workspace');
    if (!workspace) {
        const navTerminal = document.getElementById('nav-terminal');
        if (navTerminal) navTerminal.click();
        await new Promise(r => setTimeout(r, 100));
        workspace = document.getElementById('terminal-workspace');
        if (!workspace) {
            showToast('Terminal view failed to initialize', 'error');
            return;
        }
    }

    // Hide empty state
    const emptyState = document.getElementById('terminal-empty-state');
    if (emptyState) emptyState.style.display = 'none';

    // Create term container
    const termDiv = document.createElement('div');
    termDiv.className = 'terminal-container';
    termDiv.id = `term-container-${sessionId}`;
    termDiv.style.display = 'none';
    workspace.appendChild(termDiv);

    // Initialize xterm.js
    const term = new Terminal({
        cursorBlink: true,
        fontSize: getTerminalFontSize(),
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, "Courier New", monospace',
        theme: getTerminalTheme(),
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(termDiv);

    attachClickMenu(termDiv, term, sessionId);

    // Browser paste (Ctrl+V) — uses clipboardData, no async permission prompt
    termDiv.addEventListener('paste', (e) => {
        const text = e.clipboardData?.getData('text/plain');
        if (text) {
            e.preventDefault();
            pasteTextIntoSession(sessionId, text);
        }
    });

    term.onSelectionChange(() => {
        const sel = term.getSelection();
        if (sel) clipboardWriteText(sel).catch(() => {});
    });

    // Ctrl/Cmd+Shift+C/V and Ctrl/Cmd+V paste; swallow before xterm sends to PTY
    term.attachCustomKeyEventHandler((e) => {
        if (e.type !== 'keydown') return true;
        const mod = e.ctrlKey || e.metaKey;
        if (!mod) return true;

        if (e.shiftKey && (e.key === 'C' || e.key === 'c')) {
            const sel = term.getSelection();
            if (sel) {
                clipboardWriteText(sel)
                    .then(() => showToast('Copied', 'success'))
                    .catch(err => showToast('Copy failed: ' + err, 'error'));
            }
            return false;
        }

        if (e.key === 'V' || e.key === 'v') {
            pasteIntoSession(sessionId);
            return false;
        }

        return true;
    });

    // Handle user keyboard input → send to PTY
    term.onData(async (data) => {
        try { await api.sshWrite(sessionId, data); }
        catch (err) { console.error('SSH write error:', err); }
    });

    // Handle terminal resize → resize PTY
    term.onResize(async (size) => {
        try { await api.sshResize(sessionId, size.rows, size.cols); }
        catch (err) { console.error('SSH resize error:', err); }
    });

    // Handle window resize → refit terminal
    const handleResize = () => {
        if (currentSessionId === sessionId) {
            try { fitAddon.fit(); } catch {}
        }
    };
    window.addEventListener('resize', handleResize);

    activeSessions.set(sessionId, {
        term, fitAddon, hostInfo, termDiv, resizeHandler: handleResize,
        status: 'connecting',
    });

    // Show the terminal immediately so user sees the connecting message
    switchSession(sessionId);

    // Switch to terminal view
    const navTerminal = document.getElementById('nav-terminal');
    if (navTerminal) navTerminal.click();

    if (connectingMessage) {
        term.write(`\x1b[1;33m${connectingMessage}\x1b[0m\r\n`);
    }

    try {
        await connect(sessionId);
        const sess = activeSessions.get(sessionId);
        if (sess) sess.status = 'connected';
    } catch (err) {
        term.write(`\r\n\x1b[1;31mFailed: ${err}\x1b[0m\r\n`);
        showToast(String(err), 'error');
        const sess = activeSessions.get(sessionId);
        if (sess) sess.status = 'dead';
    }

    renderTabs();
    loadSnippets();
}

/** Start a new SSH connection and create its terminal tab. */
export async function startConnection(conn) {
    return createTerminalSession(
        { ...conn, isLocal: false },
        {
            connectingMessage: `Connecting to ${conn.username}@${conn.host}:${conn.port}...`,
            connect: (sessionId) => api.sshConnect({
                session_id: sessionId,
                host: conn.host,
                port: conn.port,
                username: conn.username,
                password: conn.password || null,
                key_id: conn.key_id || null,
            }),
        },
    );
}

/** Start a local shell in a new terminal tab. */
export async function startLocalShell() {
    return createTerminalSession(LOCAL_HOST_INFO, {
        connectingMessage: 'Starting local shell...',
        connect: (sessionId) => api.localShellConnect({ session_id: sessionId }),
    });
}

function refitCurrentSession() {
    if (!currentSessionId) return;
    const sess = activeSessions.get(currentSessionId);
    if (sess) {
        try { sess.fitAddon.fit(); } catch {}
    }
}

function switchSession(sessionId) {
    currentSessionId = sessionId;

    activeSessions.forEach((sess, id) => {
        if (id === sessionId) {
            sess.termDiv.style.display = 'block';
            setTimeout(() => {
                try { sess.fitAddon.fit(); } catch {}
                sess.term.focus();
            }, 50);
        } else {
            sess.termDiv.style.display = 'none';
        }
    });

    renderTabs();
    renderSnippetsList(document.getElementById('snippets-search')?.value || '');
}

async function reconnectSession(sessionId) {
    const sess = activeSessions.get(sessionId);
    if (!sess || sess.hostInfo.isLocal) return;
    const conn = sess.hostInfo;
    sess.status = 'connecting';
    sess.term.write(`\r\n\x1b[1;33mReconnecting to ${conn.username}@${conn.host}:${conn.port}...\x1b[0m\r\n`);
    renderTabs();
    try {
        await api.sshConnect({
            session_id: sessionId,
            host: conn.host,
            port: conn.port,
            username: conn.username,
            password: conn.password || null,
            key_id:   conn.key_id || null,
        });
        sess.status = 'connected';
    } catch (err) {
        sess.term.write(`\r\n\x1b[1;31mReconnect failed: ${err}\x1b[0m\r\n`);
        showToast(`Reconnect failed: ${err}`, 'error');
        sess.status = 'dead';
    }
    renderTabs();
    renderSnippetsList(document.getElementById('snippets-search')?.value || '');
}

function closeSession(sessionId) {
    const sess = activeSessions.get(sessionId);
    if (!sess) return;

    api.sshDisconnect(sessionId).catch(console.error);
    window.removeEventListener('resize', sess.resizeHandler);
    sess.term.dispose();
    sess.termDiv.remove();
    activeSessions.delete(sessionId);

    if (currentSessionId === sessionId) {
        currentSessionId = activeSessions.size > 0 ? activeSessions.keys().next().value : null;
    }

    if (activeSessions.size === 0) {
        const emptyState = document.getElementById('terminal-empty-state');
        if (emptyState) emptyState.style.display = 'flex';
    } else if (currentSessionId) {
        switchSession(currentSessionId);
    }

    renderTabs();
    renderSnippetsList(document.getElementById('snippets-search')?.value || '');
}

function renderTabs() {
    const tabsList = document.getElementById('terminal-tabs-list');
    if (!tabsList) return;

    const addBtns = `
        <button type="button" class="btn-add-tab btn-local-tab" title="Local shell">⌂</button>
        <button type="button" class="btn-add-tab btn-ssh-tab" title="SSH session">+</button>`;

    const tabsHtml = Array.from(activeSessions.entries()).map(([id, sess]) => {
        const status = sess.status || 'connected';
        const isLocal = !!sess.hostInfo.isLocal;
        const reconnect = status === 'dead' && !isLocal
            ? `<span class="tab-reconnect" data-reconnect-id="${id}" title="Reconnect">↻</span>`
            : '';
        return `
        <div class="terminal-tab status-${status}${isLocal ? ' terminal-tab-local' : ''} ${id === currentSessionId ? 'active' : ''}" data-id="${id}">
            <span class="tab-status-dot"></span>
            <span class="tab-title">${escHtml(tabTitle(sess.hostInfo))}</span>
            ${reconnect}
            <span class="tab-close" data-close-id="${id}">×</span>
        </div>`;
    }).join('');

    tabsList.innerHTML = tabsHtml + addBtns;

    tabsList.querySelectorAll('.terminal-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const closeBtn = e.target.closest('[data-close-id]');
            const reconnectBtn = e.target.closest('[data-reconnect-id]');
            if (closeBtn) {
                e.stopPropagation();
                closeSession(closeBtn.dataset.closeId);
            } else if (reconnectBtn) {
                e.stopPropagation();
                reconnectSession(reconnectBtn.dataset.reconnectId);
            } else {
                switchSession(tab.dataset.id);
            }
        });
    });

    tabsList.querySelector('.btn-local-tab')?.addEventListener('click', () => startLocalShell());
    tabsList.querySelector('.btn-ssh-tab')?.addEventListener('click', () => openHostsModal());
}

function setupGlobalEventListeners() {
    if (eventListenersBound) return;
    eventListenersBound = true;

    const tauriEvent = window.__TAURI__?.event;
    if (!tauriEvent) {
        console.warn('Tauri event API not available');
        return;
    }

    window.addEventListener('appearance-changed', () => {
        const theme = getTerminalTheme();
        const fontSize = getTerminalFontSize();
        activeSessions.forEach((sess) => {
            sess.term.options.theme = theme;
            sess.term.options.fontSize = fontSize;
            sess.termDiv.style.background = theme.background;
            try { sess.fitAddon.fit(); } catch {}
        });
    });

    tauriEvent.listen('ssh-output', (event) => {
        const { sessionId, data } = event.payload;
        const sess = activeSessions.get(sessionId);
        if (sess) sess.term.write(data);
    });

    tauriEvent.listen('ssh-closed', (event) => {
        const sessionId = event.payload;
        const sess = activeSessions.get(sessionId);
        if (sess) {
            sess.term.write('\r\n\x1b[1;31mSession ended.\x1b[0m\r\n');
            sess.status = 'dead';
            renderTabs();
            showToast(sess.hostInfo.isLocal ? 'Local shell closed' : 'SSH session closed', 'info');
        }
    });
}

// ─── Hosts Modal ───────────────────────────────────────────

async function openHostsModal() {
    const modal = document.getElementById('terminal-hosts-modal');
    if (modal) modal.style.display = 'flex';
    
    try {
        hostsCache = await api.getConnections();
        renderModalHosts();
        const search = document.getElementById('modal-hosts-search');
        if (search) search.focus();
    } catch (err) {
        showToast('Failed to load hosts', 'error');
    }
}

function closeHostsModal() {
    const modal = document.getElementById('terminal-hosts-modal');
    if (modal) modal.style.display = 'none';
    const search = document.getElementById('modal-hosts-search');
    if (search) search.value = '';
}

function renderModalHosts(filter = '') {
    const listEl = document.getElementById('modal-hosts-list');
    if (!listEl) return;

    const q = filter.toLowerCase();
    const filtered = hostsCache.filter(h => 
        !q || (h.name || '').toLowerCase().includes(q) || (h.host || '').toLowerCase().includes(q)
    );

    const localItem = `
        <div class="modal-host-item modal-host-item-local" data-local="1">
            <div class="modal-host-name">Local shell</div>
            <div class="modal-host-detail">Interactive shell on this machine</div>
        </div>`;

    if (filtered.length === 0) {
        listEl.innerHTML = localItem + `<div class="empty-msg">No hosts found.</div>`;
        bindModalHostItems(listEl);
        return;
    }

    listEl.innerHTML = localItem + filtered.map(h => `
        <div class="modal-host-item" data-id="${h.id}">
            <div class="modal-host-name">${escAttr(h.name || h.host)}</div>
            <div class="modal-host-detail">${escAttr(h.username)}@${escAttr(h.host)}:${h.port}</div>
        </div>
    `).join('');

    bindModalHostItems(listEl);
}

function bindModalHostItems(listEl) {
    listEl.querySelectorAll('.modal-host-item').forEach(item => {
        item.addEventListener('click', () => {
            if (item.dataset.local) {
                closeHostsModal();
                startLocalShell();
                return;
            }
            const host = hostsCache.find(h => h.id === item.dataset.id);
            if (host) {
                closeHostsModal();
                startConnection(host);
            }
        });
    });
}
