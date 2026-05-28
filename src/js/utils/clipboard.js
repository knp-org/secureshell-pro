// Clipboard helpers — WebView blocks navigator.clipboard.readText on Linux/Tauri.

const { invoke } = window.__TAURI__?.core ?? {};

export async function clipboardReadText() {
    if (invoke) {
        try {
            return await invoke('clipboard_read_text');
        } catch {
            /* fall through */
        }
    }
    if (navigator.clipboard?.readText) {
        return navigator.clipboard.readText();
    }
    throw new Error('Clipboard read is not available');
}

export async function clipboardWriteText(text) {
    if (invoke) {
        try {
            await invoke('clipboard_write_text', { text });
            return;
        } catch {
            /* fall through */
        }
    }
    if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        return;
    }
    throw new Error('Clipboard write is not available');
}
