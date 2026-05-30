// Vault unlock / create-master-password gate.
// Renders a full-screen overlay before the rest of the app boots.

import * as api from '../api.js';

export async function ensureUnlocked() {
    const status = await api.vaultStatus();
    if (status.unlocked) return;

    return new Promise((resolve) => {
        const isFirstTime = !status.initialized;
        const overlay = document.createElement('div');
        overlay.className = 'vault-gate-overlay';
        overlay.innerHTML = renderHtml(isFirstTime);
        document.body.appendChild(overlay);

        // Wire eye-toggle for every password input.
        overlay.querySelectorAll('.vault-gate-input-wrap').forEach(wrap => {
            const input = wrap.querySelector('input');
            const btn   = wrap.querySelector('.vault-gate-eye');
            btn.addEventListener('click', () => {
                const showing = input.type === 'text';
                input.type = showing ? 'password' : 'text';
                btn.classList.toggle('is-showing', !showing);
            });
        });

        const form    = overlay.querySelector('form');
        const card    = overlay.querySelector('.vault-gate-card');
        const pwInput = overlay.querySelector('input[name="pw"]');
        const pw2     = overlay.querySelector('input[name="pw2"]');
        const errEl   = overlay.querySelector('.vault-gate-error');
        const submitBtn = overlay.querySelector('button[type="submit"]');
        const submitLabel = submitBtn.querySelector('.vault-gate-submit-label');

        pwInput.focus();

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            errEl.textContent = '';
            const pw = pwInput.value;
            if (!pw) { errEl.textContent = 'Password required'; return; }
            if (isFirstTime) {
                if (pw.length < 8) { errEl.textContent = 'Use at least 8 characters'; return; }
                if (pw !== pw2.value) { errEl.textContent = 'Passwords do not match'; return; }
            }

            submitBtn.disabled = true;
            submitBtn.classList.add('is-loading');
            submitLabel.textContent = isFirstTime ? 'Encrypting…' : 'Unlocking…';
            // Yield to the browser so it can paint the spinner before the
            // Argon2 IPC call starts (even async Tauri calls can starve the
            // render pipeline on the first microtask tick).
            await new Promise(r => setTimeout(r, 30));
            try {
                if (isFirstTime) {
                    await api.vaultInit(pw);
                } else {
                    await api.vaultUnlock(pw);
                }
                // Brief unlock animation before resolving.
                submitBtn.classList.remove('is-loading');
                submitBtn.classList.add('is-success');
                card.classList.add('is-unlocked');
                submitLabel.textContent = isFirstTime ? 'Vault created' : 'Unlocked';
                await new Promise(r => setTimeout(r, 550));
                overlay.classList.add('is-leaving');
                await new Promise(r => setTimeout(r, 220));
                overlay.remove();
                resolve();
            } catch (err) {
                submitBtn.classList.remove('is-loading');
                card.classList.add('shake');
                setTimeout(() => card.classList.remove('shake'), 400);
                errEl.textContent = String(err);
                submitBtn.disabled = false;
                submitLabel.textContent = isFirstTime ? 'Create vault' : 'Unlock';
                pwInput.select();
            }
        });
    });
}

function renderHtml(isFirstTime) {
    const pwField = (name, autocomplete) => `
        <div class="vault-gate-input-wrap">
            <input type="password" name="${name}" autocomplete="${autocomplete}" />
            <button type="button" class="vault-gate-eye" aria-label="Toggle password visibility">
                <svg class="eye-open"  width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 19c-7 0-11-7-11-7a19.77 19.77 0 0 1 5.06-5.94M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 7 11 7a19.66 19.66 0 0 1-3.17 4.06M1 1l22 22"/><path d="M14.12 14.12A3 3 0 1 1 9.88 9.88"/></svg>
            </button>
        </div>
    `;

    const spinner = `
        <svg class="vault-gate-spinner" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.2-8.55"/>
        </svg>
    `;
    const check = `
        <svg class="vault-gate-check" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
        </svg>
    `;

    if (isFirstTime) {
        return `
            <div class="vault-gate-card">
                <div class="vault-gate-icon vault-gate-icon-lock">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <rect class="lock-body"  x="3" y="11" width="18" height="11" rx="2"/>
                        <path  class="lock-shackle" d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                </div>
                <h1>Create Master Password</h1>
                <p class="vault-gate-sub">
                    Your SSH passwords and private keys will be encrypted with this password
                    using Argon2id + AES-256-GCM. <strong>It cannot be recovered if you lose it.</strong>
                    The same password unlocks the vault on Android.
                </p>
                <form class="vault-gate-form" autocomplete="off">
                    <label>
                        <span>Master password</span>
                        ${pwField('pw', 'new-password')}
                    </label>
                    <label>
                        <span>Confirm</span>
                        ${pwField('pw2', 'new-password')}
                    </label>
                    <div class="vault-gate-error"></div>
                    <button type="submit" class="btn btn-primary">
                        ${spinner}${check}
                        <span class="vault-gate-submit-label">Create vault</span>
                    </button>
                </form>
            </div>
        `;
    }
    return `
        <div class="vault-gate-card">
            <div class="vault-gate-icon vault-gate-icon-lock">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <rect class="lock-body"   x="3" y="11" width="18" height="11" rx="2"/>
                    <path  class="lock-shackle" d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
            </div>
            <h1>Unlock Vault</h1>
            <p class="vault-gate-sub">Enter your master password to decrypt SSH credentials.</p>
            <form class="vault-gate-form" autocomplete="off">
                <label>
                    <span>Master password</span>
                    ${pwField('pw', 'current-password')}
                </label>
                <div class="vault-gate-error"></div>
                <button type="submit" class="btn btn-primary">
                    ${spinner}${check}
                    <span class="vault-gate-submit-label">Unlock</span>
                </button>
            </form>
        </div>
    `;
}
