//! SQLite persistence for scenarios, runs (results), drafts and a computation
//! dedup table keyed by (input_fingerprint, rules are inside input).

use crate::engine::RunResult;
use crate::model::{EditSet, ScenarioInput};
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct ScenarioRow {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub input_json: String,
    pub input_fingerprint: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: i64,
    pub scenario_id: String,
    pub trace_fingerprint: String,
    pub status: String,
    pub result_json: String,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS scenarios (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                parent_id TEXT REFERENCES scenarios(id),
                input_json TEXT NOT NULL,
                input_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS computations (
                input_fingerprint TEXT PRIMARY KEY,
                scenario_id TEXT NOT NULL,
                trace_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                computed_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT NOT NULL REFERENCES scenarios(id),
                trace_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS drafts (
                id TEXT PRIMARY KEY,
                base_scenario_id TEXT NOT NULL REFERENCES scenarios(id),
                label TEXT NOT NULL,
                edits_json TEXT NOT NULL,
                base_revision INTEGER NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn upsert_scenario(
        &self,
        id: &str,
        name: &str,
        parent_id: Option<&str>,
        _input: &ScenarioInput,
        input_json: &str,
        fingerprint: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scenarios (id, name, parent_id, input_json, input_fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, input_json=excluded.input_json,
                 input_fingerprint=excluded.input_fingerprint",
            params![id, name, parent_id, input_json, fingerprint],
        )?;
        Ok(())
    }

    pub fn get_scenario(&self, id: &str) -> rusqlite::Result<Option<ScenarioRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, parent_id, input_json, input_fingerprint, created_at
             FROM scenarios WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(ScenarioRow {
                id: r.get(0)?,
                name: r.get(1)?,
                parent_id: r.get(2)?,
                input_json: r.get(3)?,
                input_fingerprint: r.get(4)?,
                created_at: r.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_scenarios(&self) -> rusqlite::Result<Vec<ScenarioRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, parent_id, input_json, input_fingerprint, created_at
             FROM scenarios ORDER BY created_at, name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ScenarioRow {
                id: r.get(0)?,
                name: r.get(1)?,
                parent_id: r.get(2)?,
                input_json: r.get(3)?,
                input_fingerprint: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Dedup: a (input fingerprint) maps to exactly one computation result.
    pub fn lookup_computation(&self, input_fp: &str) -> rusqlite::Result<Option<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT scenario_id, trace_fingerprint FROM computations WHERE input_fingerprint = ?1",
        )?;
        let mut rows = stmt.query(params![input_fp])?;
        if let Some(r) = rows.next()? {
            Ok(Some((r.get(0)?, r.get(1)?)))
        } else {
            Ok(None)
        }
    }

    pub fn save_run(&self, scenario_id: &str, result: &RunResult) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        let status = format!("{:?}", result.status).to_lowercase();
        let result_json = serde_json::to_string(result).expect("result serializes");
        conn.execute(
            "INSERT INTO runs (scenario_id, trace_fingerprint, status, result_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![scenario_id, result.trace_fingerprint, status, result_json],
        )?;
        let run_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO computations (input_fingerprint, scenario_id, trace_fingerprint, status)
             VALUES (
               (SELECT input_fingerprint FROM scenarios WHERE id = ?1), ?1, ?2, ?3)
             ON CONFLICT(input_fingerprint) DO UPDATE SET
               trace_fingerprint=excluded.trace_fingerprint, status=excluded.status",
            params![scenario_id, result.trace_fingerprint, status],
        )?;
        Ok(run_id)
    }

    pub fn latest_run(&self, scenario_id: &str) -> rusqlite::Result<Option<RunRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, scenario_id, trace_fingerprint, status, result_json
             FROM runs WHERE scenario_id = ?1 ORDER BY id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![scenario_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(RunRow {
                id: r.get(0)?,
                scenario_id: r.get(1)?,
                trace_fingerprint: r.get(2)?,
                status: r.get(3)?,
                result_json: r.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn save_draft(
        &self,
        id: &str,
        base_scenario_id: &str,
        label: &str,
        edits: &EditSet,
        base_revision: i64,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let edits_json = serde_json::to_string(edits).expect("edits serialize");
        conn.execute(
            "INSERT INTO drafts (id, base_scenario_id, label, edits_json, base_revision)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET label=excluded.label, edits_json=excluded.edits_json,
                 base_revision=excluded.base_revision, updated_at=datetime('now')",
            params![id, base_scenario_id, label, edits_json, base_revision],
        )?;
        Ok(())
    }

    pub fn list_drafts(&self) -> rusqlite::Result<Vec<(String, String, String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, base_scenario_id, label, base_revision FROM drafts ORDER BY updated_at",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.collect()
    }
}
