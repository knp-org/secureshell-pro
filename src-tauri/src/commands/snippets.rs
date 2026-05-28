use tauri::State;

use crate::db::models::Snippet;
use crate::db::Database;

#[tauri::command]
pub fn get_snippets(db: State<'_, Database>) -> Result<Vec<Snippet>, String> {
    db.get_all_snippets()
}

#[tauri::command]
pub fn save_snippet(db: State<'_, Database>, snippet: Snippet) -> Result<(), String> {
    db.save_snippet(&snippet)
}

#[tauri::command]
pub fn delete_snippet(db: State<'_, Database>, id: String) -> Result<(), String> {
    db.delete_snippet(&id)
}
