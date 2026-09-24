import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { Window } from 'happy-dom';

const window = new Window();
globalThis.document = window.document;
document.body.innerHTML = '<div id="toast-container"></div>';
const { showToast } = await import('../src/js/components/toast.js');
const { showConfirm, showPrompt } = await import('../src/js/components/modal.js');
const malicious = '<img src=x onerror="globalThis.compromised=true">';

test('remote filenames remain text in notifications', () => {
    showToast(malicious, 'success', 1);
    const toast = document.querySelector('.toast');
    assert.equal(toast.lastElementChild.textContent, malicious);
    assert.equal(toast.querySelector('img'), null);
});

test('confirmation displays untrusted messages without creating elements', async () => {
    const result = showConfirm({ title: malicious, message: malicious, confirmText: malicious });
    const modal = document.querySelector('.modal-overlay');
    assert.equal(modal.querySelector('img'), null);
    assert.equal(modal.querySelector('p').textContent, malicious);
    modal.querySelector('[data-action="cancel"]').click();
    assert.equal(await result, false);
});

test('prompt preserves quoted values and cannot inject attributes', async () => {
    const value = '" autofocus onfocus="alert(1)';
    const result = showPrompt({ title: malicious, message: malicious, placeholder: value, defaultValue: value });
    const modal = document.querySelector('.modal-overlay');
    const input = modal.querySelector('input');
    assert.equal(modal.querySelector('img'), null);
    assert.equal(input.value, value);
    assert.equal(input.getAttribute('onfocus'), null);
    modal.querySelector('[data-action="confirm"]').click();
    assert.equal(await result, value);
});

after(() => window.happyDOM.abort());

test('Enter on the focused Cancel button cannot confirm trust or replacement', async () => {
    const result = showConfirm({ title: 'Trust server?', message: 'Fingerprint' });
    const modal = document.querySelector('.modal-overlay');
    const cancel = modal.querySelector('[data-action="cancel"]');
    assert.equal(document.activeElement, cancel);
    cancel.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    cancel.click();
    assert.equal(await result, false);
});
