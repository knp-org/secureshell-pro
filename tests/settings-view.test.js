// Renders the real Settings view against a stub IPC layer.
//
// bindEvents() wires every control in one pass, so a single bad reference in
// it — a helper that was renamed or removed — throws before the rest is bound
// and silently leaves the whole pane inert: peers stuck on "Loading…", theme,
// font size and accent all dead. `node --check` cannot see that, which is how
// it once shipped. These tests fail loudly instead.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Window } from 'happy-dom';

const window = new Window();
globalThis.window = window;
globalThis.document = window.document;
globalThis.localStorage = window.localStorage;
globalThis.getComputedStyle = window.getComputedStyle.bind(window);

const settings = { theme: 'dark', font_size: '14', accent: 'gold' };
const invoked = [];

// api.js destructures invoke once at module load, so the function identity has
// to stay put; tests swap the handler behind it instead.
let handle = async () => null;
window.__TAURI__ = {
    core: {
        invoke: async (command, args = {}) => {
            invoked.push(command);
            return handle(command, args);
        },
    },
};

const defaultHandler = async (command, args = {}) => {
    switch (command) {
        case 'peers_list':
            return [{
                id: 'ab12cd34',
                pk_hex: 'ab12cd34'.repeat(8),
                label: 'host-laptop',
                paired_at: '2026-09-24T12:00:00Z',
                last_synced_at: null,
            }];
        case 'get_setting':  return settings[args.key] ?? null;
        case 'set_setting':  settings[args.key] = args.value; return null;
        default:             return null;
    }
};
handle = defaultHandler;

document.body.innerHTML = '<div id="toast-container"></div><div id="view"></div>';
const { render } = await import('../src/js/views/settings.js');

// bindEvents is async and fires refreshPeers without awaiting it, so give both
// a turn of the event loop to settle before asserting.
const settle = () => new Promise(resolve => setTimeout(resolve, 0));

before(async () => {
    render(document.getElementById('view'));
    await settle();
    await settle();
});

test('every control bindEvents touches is wired, not just the first', () => {
    for (const id of ['set-change-pwd', 'set-pair-device', 'set-join-device', 'set-reset-vault']) {
        assert.ok(document.getElementById(id), `${id} missing from the rendered view`);
    }
    // Reached only if bindEvents ran past its listener block.
    assert.ok(invoked.includes('peers_list'), 'refreshPeers never ran');
    assert.ok(invoked.includes('get_setting'), 'saved settings were never loaded');
});

test('paired devices replace the loading placeholder', () => {
    const summary = document.getElementById('lan-peers-summary');
    assert.notEqual(summary.textContent.trim(), 'Loading…');
    assert.equal(summary.textContent.trim(), '1 paired');
    assert.ok(document.querySelector('[data-sync="ab12cd34"]'), 'no Sync now button');
    assert.ok(document.querySelector('[data-remove="ab12cd34"]'), 'no Remove button');
});

test('a peer label cannot inject markup into the device list', async () => {
    const label = '<img src=x onerror="globalThis.compromised=true">';
    handle = async (command) =>
        command === 'peers_list'
            ? [{ id: 'ff00', pk_hex: 'ff00', label, paired_at: '', last_synced_at: null }]
            : null;
    render(document.getElementById('view'));
    await settle();
    await settle();
    assert.equal(document.querySelector('.lan-peers-list img'), null);
    assert.equal(document.querySelector('.lan-peer-label').textContent, label);
    assert.notEqual(globalThis.compromised, true);
});

after(() => window.close());
