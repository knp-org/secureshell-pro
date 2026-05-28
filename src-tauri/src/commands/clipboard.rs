use arboard::Clipboard;

#[tauri::command]
pub fn clipboard_read_text() -> Result<String, String> {
    Clipboard::new()
        .map_err(|e| format!("Clipboard unavailable: {}", e))?
        .get_text()
        .map_err(|e| format!("Failed to read clipboard: {}", e))
}

#[tauri::command]
pub fn clipboard_write_text(text: String) -> Result<(), String> {
    Clipboard::new()
        .map_err(|e| format!("Clipboard unavailable: {}", e))?
        .set_text(text)
        .map_err(|e| format!("Failed to write clipboard: {}", e))
}
