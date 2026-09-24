// ═══════════════════════════════════════════════════════════
// Toast Notification System
// ═══════════════════════════════════════════════════════════

const container = document.getElementById('toast-container');

export function showToast(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
    const iconEl = document.createElement('span');
    iconEl.textContent = icon;
    const messageEl = document.createElement('span');
    messageEl.textContent = String(message);
    toast.append(iconEl, messageEl);

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 200);
    }, duration);
}
