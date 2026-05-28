use tauri::State;

use crate::db::models::Group;
use crate::db::Database;

#[tauri::command]
pub fn get_groups(db: State<'_, Database>) -> Result<Vec<Group>, String> {
    db.get_all_groups()
}

#[tauri::command]
pub fn save_group(db: State<'_, Database>, group: Group) -> Result<(), String> {
    db.save_group(&group)
}

#[tauri::command]
pub fn delete_group(db: State<'_, Database>, id: String) -> Result<(), String> {
    db.delete_group(&id)
}
