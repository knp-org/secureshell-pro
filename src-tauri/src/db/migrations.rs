use rusqlite::Connection;

fn column_exists(conn: &Connection, table: &str, col: &str) -> bool {
    let sql = format!("PRAGMA table_info({})", table);
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rows = stmt.query_map([], |r| r.get::<_, String>(1));
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            if r == col { return true; }
        }
    }
    false
}

fn add_deleted_at(conn: &Connection, table: &str) -> Result<(), rusqlite::Error> {
    if !column_exists(conn, table, "deleted_at") {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN deleted_at TEXT", table),
            [],
        )?;
    }
    Ok(())
}

/// Run all database migrations
pub fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS connections (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            host            TEXT NOT NULL,
            port            INTEGER DEFAULT 22,
            username        TEXT NOT NULL,
            auth_method     TEXT NOT NULL DEFAULT 'password',
            password        TEXT,
            key_id          TEXT,
            group_id        TEXT,
            tags            TEXT DEFAULT '[]',
            color           TEXT,
            last_connected  TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            synced          INTEGER DEFAULT 0,
            FOREIGN KEY (group_id) REFERENCES groups(id)
        );

        CREATE TABLE IF NOT EXISTS groups (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            parent_id       TEXT,
            icon            TEXT,
            color           TEXT,
            created_at      TEXT NOT NULL,
            FOREIGN KEY (parent_id) REFERENCES groups(id)
        );

        CREATE TABLE IF NOT EXISTS snippets (
            id              TEXT PRIMARY KEY,
            label           TEXT NOT NULL,
            command         TEXT NOT NULL,
            description     TEXT,
            tags            TEXT DEFAULT '[]',
            connection_ids  TEXT DEFAULT '[]',
            group_id        TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            synced          INTEGER DEFAULT 0,
            FOREIGN KEY (group_id) REFERENCES groups(id)
        );

        CREATE TABLE IF NOT EXISTS ssh_keys (
            id              TEXT PRIMARY KEY,
            label           TEXT NOT NULL,
            key_type        TEXT NOT NULL,
            public_key      TEXT,
            private_key     TEXT,
            fingerprint     TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            synced          INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS settings (
            key             TEXT PRIMARY KEY,
            value           TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sync_log (
            id              TEXT PRIMARY KEY,
            table_name      TEXT NOT NULL,
            record_id       TEXT NOT NULL,
            action          TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            synced          INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS vault_meta (
            id          INTEGER PRIMARY KEY CHECK(id = 1),
            kdf         TEXT NOT NULL,
            salt        TEXT NOT NULL,
            m_cost      INTEGER NOT NULL,
            t_cost      INTEGER NOT NULL,
            p_cost      INTEGER NOT NULL,
            verifier    TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            updated_at  TEXT
        );
        "
    )?;

    // Tombstones for sync (idempotent — only adds if missing).
    add_deleted_at(conn, "connections")?;
    add_deleted_at(conn, "ssh_keys")?;
    add_deleted_at(conn, "snippets")?;
    add_deleted_at(conn, "groups")?;

    if !column_exists(conn, "snippets", "group_id") {
        let _ = conn.execute("ALTER TABLE snippets ADD COLUMN group_id TEXT", []);
    }

    // vault_meta gained updated_at after v1.
    if !column_exists(conn, "vault_meta", "updated_at") {
        let _ = conn.execute("ALTER TABLE vault_meta ADD COLUMN updated_at TEXT", []);
    }

    // ssh_keys gained updated_at so master-password re-encryption (and edits)
    // propagate over sync. Backfill existing rows from created_at.
    if !column_exists(conn, "ssh_keys", "updated_at") {
        let _ = conn.execute("ALTER TABLE ssh_keys ADD COLUMN updated_at TEXT", []);
        let _ = conn.execute("UPDATE ssh_keys SET updated_at = created_at WHERE updated_at IS NULL", []);
    }

    Ok(())
}
