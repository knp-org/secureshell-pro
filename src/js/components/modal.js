export function showConfirm({ title, message, confirmText = 'Delete', cancelText = 'Cancel', danger = false }) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-dialog-header">
                    <h3>${title}</h3>
                </div>
                <div class="modal-dialog-body">
                    <p>${message}</p>
                </div>
                <div class="modal-dialog-footer">
                    <button type="button" class="btn btn-secondary" data-action="cancel">${cancelText}</button>
                    <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-action="confirm">${confirmText}</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        const close = (result) => {
            overlay.remove();
            resolve(result);
        };

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) close(false);
            const action = e.target.closest('[data-action]')?.dataset.action;
            if (action === 'confirm') close(true);
            if (action === 'cancel') close(false);
        });
        overlay.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') close(false);
            if (e.key === 'Enter') close(true);
        });
        overlay.querySelector('[data-action="cancel"]').focus();
    });
}

export function showPrompt({ title, message = '', placeholder = '', defaultValue = '', confirmText = 'OK', cancelText = 'Cancel' }) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-dialog-header">
                    <h3>${title}</h3>
                </div>
                <div class="modal-dialog-body">
                    ${message ? `<p>${message}</p>` : ''}
                    <input type="text" class="modal-dialog-input" placeholder="${placeholder}" value="${defaultValue.replace(/"/g, '&quot;')}" />
                </div>
                <div class="modal-dialog-footer">
                    <button type="button" class="btn btn-secondary" data-action="cancel">${cancelText}</button>
                    <button type="button" class="btn btn-primary" data-action="confirm">${confirmText}</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        const input = overlay.querySelector('.modal-dialog-input');
        input.focus();
        input.select();

        const close = (result) => {
            overlay.remove();
            resolve(result);
        };

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) close(null);
            const action = e.target.closest('[data-action]')?.dataset.action;
            if (action === 'confirm') close(input.value);
            if (action === 'cancel') close(null);
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); close(input.value); }
            if (e.key === 'Escape') close(null);
        });
    });
}
