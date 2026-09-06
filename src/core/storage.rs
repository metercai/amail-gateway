//! SQLite storage layer — connection pool, schema, and CRUD operations.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use tracing::debug;

use crate::core::errors::{AppError, AppResult};
use crate::core::whitelist::{is_whitelisted_wildcard, WhitelistCache};

/// Global database handle — set once at startup.

// ── Database Pool ──────────────────────────────────────────────────────

/// Thread-safe, cloneable database handle backed by an `r2d2_sqlite` connection pool.
#[derive(Clone)]
pub struct Database {
    pool: Pool<SqliteConnectionManager>,
    pub whitelist_cache: Arc<WhitelistCache>,
    /// Domain lookup cache.
    pub domain_cache: Arc<RwLock<HashMap<String, (Instant, Option<SystemDomainRecord>)>>>,
}

impl Database {
    pub fn open<P: AsRef<Path>>(
        path: P,
        pool_size: u32,
        encryption_key: Option<&str>,
    ) -> AppResult<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Set restrictive file permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path_ref.exists() {
                let mut perms = std::fs::metadata(path_ref)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path_ref, perms)?;
            }
        }

        let manager = SqliteConnectionManager::file(path_ref);

        // Set SQLCipher key as the first operation on each connection.
        let manager = if let Some(key) = encryption_key {
            // Escape single quotes in the key to prevent SQL injection.
            // Key is derived via HMAC-SHA256 (hex-encoded), so quotes are
            // extremely unlikely, but defense-in-depth is appropriate here.
            let safe_key = key.replace('\'', "''");
            let key_owned = safe_key;
            manager.with_init(move |conn| {
                conn.execute_batch(&format!("PRAGMA key = '{}';", key_owned))?;
                Ok(())
            })
        } else {
            manager
        };

        let pool = r2d2::Pool::builder()
            .max_size(pool_size)
            .build(manager)
            .map_err(|e| AppError::Internal(format!("Failed to create connection pool: {}", e)))?;

        {
            let conn = pool.get().map_err(|e| {
                AppError::Internal(format!("Failed to get connection from pool: {}", e))
            })?;

            // Auto-detect unencrypted DB and rekey in-place.
            if encryption_key.is_some() {
                if let Err(e) = init_connection(&conn) {
                    if format!("{}", e).contains("file is not a database") {
                        tracing::warn!(
                            "DB appears unencrypted — migrating to encrypted (one-time). \
                             This happens on first restart after admin key provisioning."
                        );
                        drop(conn);
                        migrate_to_encrypted(path_ref, encryption_key.unwrap())?;
                        let manager2 = SqliteConnectionManager::file(path_ref);
                        let key2 = encryption_key.unwrap().to_string();
                        let manager2 = manager2.with_init(move |conn| {
                            conn.execute_batch(&format!("PRAGMA key = '{}';", key2))?;
                            Ok(())
                        });
                        let pool2 = r2d2::Pool::builder()
                            .max_size(pool_size)
                            .build(manager2)
                            .map_err(|e| {
                                AppError::Internal(format!(
                                    "Failed to create connection pool after rekey: {}",
                                    e
                                ))
                            })?;
                        let conn2 = pool2.get().map_err(|e| {
                            AppError::Internal(format!(
                                "Failed to get connection after rekey: {}",
                                e
                            ))
                        })?;
                        init_connection(&conn2)?;
                        return Ok(Self {
                            pool: pool2,
                            whitelist_cache: Arc::new(WhitelistCache::new()),
                            domain_cache: Arc::new(RwLock::new(HashMap::new())),
                        });
                    }
                    return Err(e);
                }
            } else {
                init_connection(&conn)?;
            }
        }

        Ok(Self {
            pool,
            whitelist_cache: Arc::new(WhitelistCache::new()),
            domain_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn call<F, R>(&self, f: F) -> AppResult<R>
    where
        F: FnOnce(&Connection) -> AppResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| {
                tracing::error!(operation="pool_connection_error", error = %e, "Pool connection error");
                AppError::Internal(format!("Pool error: {}", e))
            })?;
            f(&conn)
        })
        .await
        .map_err(|e| {
            tracing::error!(operation="blocking_task_join_error", error = %e, "Blocking task join error");
            AppError::Internal(format!("Blocking task failed: {}", e))
        })?
    }

    /// Execute a closure inside a SQLite transaction.
    /// Automatically commits on success, rolls back on error.
    pub async fn call_tx<F, R>(&self, f: F) -> AppResult<R>
    where
        F: FnOnce(&Transaction<'_>) -> AppResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|e| {
                tracing::error!(operation="pool_connection_error", error = %e, "Pool connection error");
                AppError::Internal(format!("Pool error: {}", e))
            })?;
            let tx = conn.transaction().map_err(|e| {
                AppError::Internal(format!("Transaction begin failed: {}", e))
            })?;
            let result = f(&tx)?;
            tx.commit().map_err(|e| {
                AppError::Internal(format!("Transaction commit failed: {}", e))
            })?;
            Ok(result)
        })
        .await
        .map_err(|e| {
            tracing::error!(operation="blocking_task_join_error", error = %e, "Blocking task join error");
            AppError::Internal(format!("Blocking task failed: {}", e))
        })?
    }
}

fn init_connection(conn: &Connection) -> AppResult<()> {
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    run_migrations(conn)?;
    check_schema_version(conn)?;
    Ok(())
}

/// Encrypt a plaintext database with SQLCipher.
fn migrate_to_encrypted(path: &Path, key: &str) -> AppResult<()> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!("PRAGMA key = '';"))?; // open in plaintext mode explicitly
    conn.execute_batch(&format!("PRAGMA rekey = '{}';", key))?;
    drop(conn);
    tracing::info!("Database encrypted successfully with SQLCipher");
    Ok(())
}

const SCHEMA_VERSION: i64 = 1;

/// Retention window (days) for `delivered` pending_deliveries rows, kept as an
/// audit trail before purge.
const DELIVERED_AUDIT_RETENTION_DAYS: i64 = 7;

fn check_schema_version(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);",
    )?;
    let current: i64 = conn
        .query_row(
            "SELECT COALESCE((SELECT version FROM _schema_version WHERE id=1), 0)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if current == 0 {
        conn.execute(
            "INSERT INTO _schema_version (id, version) VALUES (1, ?1)",
            params![SCHEMA_VERSION],
        )?;
        tracing::info!(
            operation = "schema_init",
            version = SCHEMA_VERSION,
            "Database schema initialized"
        );
    } else if current != SCHEMA_VERSION {
        return Err(crate::core::errors::AppError::Config(format!(
            "Database schema version mismatch: DB has v{}, program expects v{}. Please migrate or reset the database.",
            current, SCHEMA_VERSION
        )));
    }
    Ok(())
}

fn run_migrations(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "

        CREATE TABLE IF NOT EXISTS system_domains (
            id             TEXT PRIMARY KEY,
            system_id      TEXT NOT NULL,
            domain_addr    TEXT NOT NULL UNIQUE,
            webhook_url    TEXT,
            webhook_secret TEXT,
            is_active      INTEGER NOT NULL DEFAULT 1,
            created_at     TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_system_domains_system ON system_domains(system_id);

        INSERT OR IGNORE INTO system_domains (id, system_id, domain_addr) VALUES ('dom_admin', 'admin', 'admin.relay');

        CREATE TABLE IF NOT EXISTS domain_addr_meta (
            email_address   TEXT PRIMARY KEY,
            system_id       TEXT NOT NULL,
            manager_address TEXT NOT NULL DEFAULT '',
            agent_signature TEXT NOT NULL DEFAULT '',
            agent_persona   TEXT NOT NULL DEFAULT '',
            is_active       INTEGER NOT NULL DEFAULT 1,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_domain_addr_meta_system ON domain_addr_meta(system_id);

        CREATE TABLE IF NOT EXISTS whitelists (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id  TEXT NOT NULL,
            domain_addr TEXT NOT NULL,
            direction  TEXT NOT NULL DEFAULT 'all' CHECK(direction IN ('from','to','all')),
            value      TEXT NOT NULL,
            description TEXT,
            is_active  INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            category   TEXT NOT NULL DEFAULT 'system',
            api_key_id INTEGER,
            UNIQUE(system_id, domain_addr, value)
        );
        CREATE INDEX IF NOT EXISTS idx_whitelists_lookup ON whitelists(system_id, domain_addr, direction, is_active);

        -- Board group whitelist: board_email -> member addresses, built
        -- from member invite/change notifications (X-Board-Members header).
        -- check_whitelisted consults this to auto-allow board members.
        CREATE TABLE IF NOT EXISTS board_whitelists (
            board_email TEXT NOT NULL,
            member_addr TEXT NOT NULL,
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (board_email, member_addr)
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id     TEXT NOT NULL,
            domain_addr   TEXT NOT NULL,
            key_hash      TEXT NOT NULL UNIQUE,
            key_prefix    TEXT NOT NULL,
            scopes       TEXT NOT NULL DEFAULT '[\"agent\"]',
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at    TEXT,
            last_used_at  TEXT,
            category      TEXT NOT NULL DEFAULT 'system',
            activation_code_hash TEXT,
            activation_expires_at TEXT,
            claimed_at    TEXT,
            UNIQUE(system_id, domain_addr)
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_lookup ON api_keys(domain_addr, is_active);

        -- Remaining tables
        CREATE TABLE IF NOT EXISTS activation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT NOT NULL UNIQUE, code_prefix TEXT NOT NULL,
            code_cipher TEXT,
            code_type TEXT NOT NULL CHECK(code_type IN ('address','product')),
            product_id TEXT, system_id TEXT,
            domain TEXT, email_address TEXT,
            claimed INTEGER NOT NULL DEFAULT 0,
            claimed_at TEXT, claimed_by TEXT, expires_at TEXT,
            is_frozen INTEGER NOT NULL DEFAULT 0,
            is_shipped INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_activation_lookup ON activation_codes(claimed, is_frozen);
        CREATE INDEX IF NOT EXISTS idx_activation_codes_system ON activation_codes(system_id);
        CREATE INDEX IF NOT EXISTS idx_activation_codes_domain ON activation_codes(domain);

        CREATE TABLE IF NOT EXISTS agent_state (
            agent_addr  TEXT NOT NULL,
            state_key   TEXT NOT NULL,
            state_value TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            UNIQUE(agent_addr, state_key)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_state_lookup ON agent_state(agent_addr, state_key);

        CREATE TABLE IF NOT EXISTS pending_deliveries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id   TEXT NOT NULL,
            domain_addr TEXT NOT NULL,
            email       TEXT NOT NULL,
            headers     TEXT NOT NULL,
            payload     TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pending_system ON pending_deliveries(system_id, created_at);

        -- Email tables
        CREATE TABLE IF NOT EXISTS attachment_permissions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            attachment_id TEXT NOT NULL,
            user_email    TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(attachment_id, user_email)
        );
        CREATE INDEX IF NOT EXISTS idx_attachment_perm ON attachment_permissions(attachment_id, user_email);

        CREATE TABLE IF NOT EXISTS emails (
            id              TEXT PRIMARY KEY,
            -- Born state is 'readying' (preparing). The app always passes the
            -- status explicitly via insert_email(); this DEFAULT only matters
            -- for direct-DB scripts and documents the lifecycle:
            -- readying → (trigger claim) sending | (recovery flip) ready → sending.
            status          TEXT NOT NULL DEFAULT 'readying',
            system_id       TEXT NOT NULL,
            direction       TEXT NOT NULL CHECK(direction IN ('inbound', 'outbound')),
            sender          TEXT NOT NULL,
            recipients      TEXT NOT NULL,
            endpoints       TEXT,
            subject         TEXT NOT NULL DEFAULT '',
            body            TEXT NOT NULL,
            headers         TEXT,
            attachments     TEXT,
            send_count      INTEGER NOT NULL DEFAULT 0,
            last_sent_at    TEXT NOT NULL DEFAULT (datetime('now')),
            next_retry_at   TEXT,
            -- DEFAULT 5 here is a safety net for direct DB scripts;
            -- the application always passes max_attempts explicitly via
            -- insert_email(). The config default is config::default_max_attempts() = 3.
            max_attempts    INTEGER NOT NULL DEFAULT 5,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            sender_signature  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_emails_scheduler ON emails(next_retry_at, send_count);
        CREATE INDEX IF NOT EXISTS idx_emails_system ON emails(system_id);
        CREATE INDEX IF NOT EXISTS idx_emails_system_date ON emails(system_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);

        CREATE TABLE IF NOT EXISTS attachments_meta (
            id           TEXT PRIMARY KEY,
            filename     TEXT NOT NULL,
            content_type TEXT,
            sender_email TEXT NOT NULL,
            mail_id      TEXT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_attachments_meta_created ON attachments_meta(created_at);",
    )?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SystemRecord {
    pub id: String,
    pub admin_email: String,
    pub limits_config: Option<String>,

    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct SystemDomainRecord {
    pub id: String,
    pub system_id: String,
    pub domain: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct PendingDeliveryRecord {
    pub id: i64,
    pub system_id: String,
    pub domain_addr: String,
    pub email: String,
    pub headers: String,
    pub payload: String,
    pub status: String,
    pub created_at: String,
}

fn system_domain_row(r: &rusqlite::Row) -> rusqlite::Result<SystemDomainRecord> {
    Ok(SystemDomainRecord {
        id: r.get(0)?,
        system_id: r.get(1)?,
        domain: r.get(2)?,
        webhook_url: r.get(3)?,
        webhook_secret: r.get(4)?,
        is_active: r.get::<_, i32>(5)? != 0,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

/// Per-agent metadata: manager address, signature, persona.
#[derive(Debug, Clone)]
pub struct DomainAddrMetaRecord {
    pub email_address: String,
    pub system_id: String,
    pub manager_address: String,
    pub agent_signature: String,
    pub agent_persona: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

fn domain_addr_meta_row(r: &rusqlite::Row) -> rusqlite::Result<DomainAddrMetaRecord> {
    Ok(DomainAddrMetaRecord {
        email_address: r.get(0)?,
        system_id: r.get(1)?,
        manager_address: r.get::<_, String>(2).unwrap_or_default(),
        agent_signature: r.get::<_, String>(3).unwrap_or_default(),
        agent_persona: r.get::<_, String>(4).unwrap_or_default(),
        is_active: r.get::<_, i32>(5)? != 0,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

// ── Agent state ──────────────────────

fn agent_state_row(r: &rusqlite::Row) -> rusqlite::Result<(String, String, String)> {
    Ok((
        r.get::<_, String>(0)?, // state_key
        r.get::<_, String>(1)?, // state_value
        r.get::<_, String>(2)?, // updated_at
    ))
}

impl Database {
    pub async fn agent_state_get(
        &self,
        agent_addr: &str,
        state_key: &str,
    ) -> AppResult<Option<(String, String)>> {
        let (agent_addr, state_key) = (agent_addr.to_string(), state_key.to_string());
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT state_key, state_value, updated_at FROM agent_state WHERE agent_addr = ?1 AND state_key = ?2"
            )?;
            let mut rows = stmt.query_map(params![agent_addr, state_key], agent_state_row)?;
            match rows.next() {
                Some(Ok((key, value, _))) => Ok(Some((key, value))),
                Some(Err(e)) => Err(e.into()),
                None => Ok(None),
            }
        }).await
    }

    pub async fn agent_state_put(
        &self,
        agent_addr: &str,
        state_key: &str,
        state_value: &str,
    ) -> AppResult<()> {
        let (agent_addr, state_key, state_value) = (
            agent_addr.to_string(),
            state_key.to_string(),
            state_value.to_string(),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO agent_state (agent_addr, state_key, state_value, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(agent_addr, state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at",
                params![agent_addr, state_key, state_value, now],
            )?;
            Ok(())
        }).await
    }

    pub async fn agent_state_delete(&self, agent_addr: &str, state_key: &str) -> AppResult<()> {
        let (agent_addr, state_key) = (agent_addr.to_string(), state_key.to_string());
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM agent_state WHERE agent_addr = ?1 AND state_key = ?2",
                params![agent_addr, state_key],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn insert_system_domain(
        &self,
        id: &str,
        system_id: &str,
        domain: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
    ) -> AppResult<SystemDomainRecord> {
        let (id, system_id, domain) = (id.to_string(), system_id.to_string(), domain.to_string());
        let (webhook_url, webhook_secret) = (
            webhook_url.map(String::from),
            webhook_secret.map(String::from),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let domain_for_cache = domain.clone();
        let record = self.call(move |conn| {
            conn.execute(
                "INSERT INTO system_domains (id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
                params![id, system_id, domain, webhook_url, webhook_secret, now],
            )?;
            Ok(SystemDomainRecord {
                id, system_id, domain,
                webhook_url, webhook_secret,
                is_active: true, created_at: now.clone(), updated_at: now,
            })
        }).await?;
        // ── Invalidate domain cache ──
        // Without this, a prior cache-miss (None) would be served stale for up to 30s.
        if let Ok(mut cache) = self.domain_cache.write() {
            cache.remove(&domain_for_cache);
        }
        Ok(record)
    }

    pub async fn get_system_domain(&self, id: &str) -> AppResult<Option<SystemDomainRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE id = ?1",
                params![id],
                system_domain_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn get_system_domain_by_domain(
        &self,
        domain: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let domain = domain.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE domain_addr = ?1",
                params![domain],
                system_domain_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Fetch an ACTIVE system-domain record by domain name.
    /// Used by webhook delivery resolution — deactivated domains must not
    /// receive email (AUDIT-1 P2-4).
    pub async fn get_active_system_domain_by_domain(
        &self,
        domain: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let domain = domain.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE domain_addr = ?1 AND is_active = 1",
                params![domain],
                system_domain_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn list_system_domains(&self, system_id: &str) -> AppResult<Vec<SystemDomainRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE system_id = ?1",
            )?;
            let rows = stmt.query_map(params![system_id], system_domain_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn update_system_domain(
        &self,
        id: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
        is_active: Option<bool>,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let (id, wu, ws) = (
            id.to_string(),
            webhook_url.map(String::from),
            webhook_secret.map(String::from),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            let affected = conn.execute(
                "UPDATE system_domains SET webhook_url = ?1, webhook_secret = ?2, is_active = COALESCE(?3, is_active), updated_at = ?4 WHERE id = ?5",
                params![wu, ws, is_active.map(|a| a as i32), now, id],
            )?;
            if affected == 0 { return Ok(None); }
            let updated = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE id = ?1",
                params![id],
                system_domain_row,
            )?;
            Ok(Some(updated))
        }).await
    }

    pub async fn delete_system_domain(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let id_for_cache = id.clone();
        self.call(move |conn| {
            conn.execute("DELETE FROM system_domains WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await?;
        // Evict any cached copy of the deleted record. Cache keys are the raw
        // query strings callers pass in, so match on the stored id rather than
        // a possibly-differently-cased domain to be format-agnostic.
        if let Ok(mut cache) = self.domain_cache.write() {
            cache.retain(|_, (_, rec)| rec.as_ref().map(|r| r.id != id_for_cache).unwrap_or(true));
        }
        Ok(())
    }

    /// Atomically rename an agent address `old` → `new` across every
    /// referencing table, inheriting all server-side resources:
    ///
    /// - `system_domains`/`domain_addr_meta` rows are re-keyed in place
    ///   (webhook/secret/manager/signature/persona ride along — same row);
    /// - `api_keys.domain_addr` is re-pointed — the agent's key itself is
    ///   untouched, so the agent keeps working under the new address with
    ///   the same credential (no re-activation);
    /// - `whitelists` (domain_addr AND value sides), `agent_state`
    ///   (agent_addr and address-embedded state keys), `boards.board_email`,
    ///   `board_members.email`, `tasks.assignee/reviewer/created_by`,
    ///   `task_events.actor` are migrated via copy-new/delete-old so a
    ///   pre-existing new-key row wins (INSERT OR IGNORE semantics);
    /// - mail history (`emails`, snapshots) is untouched — those are
    ///   immutable string snapshots of the old identity.
    ///
    /// The whole migration runs in one `execute_batch` (single implicit
    /// transaction): any failure rolls back everything.
    ///
    /// Caller must already have validated: `old` exists and belongs to the
    /// requesting system, `new` is not registered anywhere, `new` is on the
    /// same bare domain as `old`, `new`'s local part is legal, and no
    /// `board_members` row already carries `new` (member merge is refused).
    pub async fn rename_agent_address_refs(&self, old: &str, new: &str) -> AppResult<()> {
        // Defense-in-depth: address components are strictly bounded so no
        // quoting/escaping hazards can reach the batch text.
        let safe = |s: &str| -> bool {
            !s.is_empty()
                && s.len() <= 255
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'-' | b'_' | b'+' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'/' | b'=' | b'?' | b'^' | b'`' | b'{' | b'|' | b'}' | b'~' | b'!'))
        };
        assert!(safe(old) && safe(new), "rename addresses must be bounded atext/no-quote strings");
        let old = old.to_string();
        let new = new.to_string();

        self.call(move |conn| {
            let batch = format!(
                r#"
BEGIN;
-- domain_addr_meta: re-key in place (PK update; caller pre-checked new absent)
UPDATE domain_addr_meta SET email_address = '{new}' WHERE email_address = '{old}';
-- api_keys: re-point the agent key (key material untouched)
UPDATE api_keys SET domain_addr = '{new}' WHERE domain_addr = '{old}';
-- system_domains: re-key in place (webhook/secret ride along)
UPDATE system_domains SET domain_addr = '{new}' WHERE domain_addr = '{old}';
-- whitelists, domain_addr side: copy to new key then drop old rows
INSERT OR IGNORE INTO whitelists(system_id,domain_addr,direction,value,description,is_active,created_at,category,api_key_id)
  SELECT system_id,'{new}',direction,value,description,is_active,created_at,category,api_key_id
  FROM whitelists WHERE domain_addr = '{old}';
DELETE FROM whitelists WHERE domain_addr = '{old}';
-- whitelists, value side (other agents' rows pointing at the old address):
-- copy with the value rewritten, then drop the originals.
INSERT OR IGNORE INTO whitelists(system_id,domain_addr,direction,value,description,is_active,created_at,category,api_key_id)
  SELECT system_id,domain_addr,direction,'{new}',description,is_active,created_at,category,api_key_id
  FROM whitelists WHERE value = '{old}' AND domain_addr <> '{old}';
DELETE FROM whitelists WHERE value = '{old}' AND domain_addr <> '{old}';
-- whitelists rows already re-keyed above whose value was also the old
-- address (agent <-> manager bidirectional entries on the renamed address)
UPDATE whitelists SET value = '{new}' WHERE domain_addr = '{new}' AND value = '{old}';
-- agent_state: agent_addr side + state keys embedding the address
-- (profile:/summary:/…:{old} → …:{new}); copy then drop.
INSERT OR IGNORE INTO agent_state(agent_addr,state_key,state_value,created_at,updated_at)
  SELECT CASE WHEN agent_addr = '{old}' THEN '{new}' ELSE agent_addr END,
         replace(state_key,'{old}','{new}'), state_value, created_at, updated_at
  FROM agent_state WHERE agent_addr = '{old}' OR state_key LIKE '%{old}%';
DELETE FROM agent_state WHERE agent_addr = '{old}';
DELETE FROM agent_state WHERE agent_addr <> '{old}' AND state_key LIKE '%{old}%';
-- boards + members + tasks + events (same library DB)
UPDATE boards SET board_email = '{new}' WHERE board_email = '{old}';
INSERT OR IGNORE INTO board_members(email,role,display_name,board_token,board_id,joined_at,domains,capability_snapshot)
  SELECT '{new}',role,display_name,board_token,board_id,joined_at,domains,capability_snapshot
  FROM board_members WHERE email = '{old}';
UPDATE tasks SET assignee = '{new}' WHERE assignee = '{old}';
UPDATE tasks SET reviewer = '{new}' WHERE reviewer = '{old}';
UPDATE tasks SET created_by = '{new}' WHERE created_by = '{old}';
UPDATE task_events SET actor = '{new}' WHERE actor = '{old}';
DELETE FROM board_members WHERE email = '{old}';
COMMIT;
"#,
            );
            if let Err(e) = conn.execute_batch(&batch) {
                // Any statement failed mid-batch: the implicit transaction
                // opened by BEGIN is still open — roll it back so the
                // pooled connection never leaks a half-applied migration.
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e.into());
            }
            Ok(())
        })
        .await
    }

    /// Get the webhook config for a domain.
    // get_webhook_for_domain moved to AdvancedStorage (queries systems table)

    /// Get a system domain record by domain name (uses cache).
    pub async fn get_system_domain_by_name(
        &self,
        domain: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        // Check cache for positive hits only — never cache None
        // (security critical: domain deletions/creations must be visible immediately)
        {
            let cache = self
                .domain_cache
                .read()
                .map_err(|_| AppError::Internal("domain cache lock poisoned".into()))?;
            if let Some((ts, record)) = cache.get(domain) {
                if ts.elapsed() < std::time::Duration::from_secs(30) && record.is_some() {
                    return Ok(record.clone());
                }
            }
        }
        let result = self.get_system_domain_by_domain(domain).await?;
        // Cache positive hits only
        if result.is_some() {
            if let Ok(mut cache) = self.domain_cache.write() {
                let len = cache.len();
                if len > 1000 {
                    cache.retain(|_, (ts, _)| ts.elapsed() < std::time::Duration::from_secs(60));
                }
                cache.insert(domain.to_string(), (Instant::now(), result.clone()));
            }
        }
        Ok(result)
    }

    // ═══════════════════════════════════════════════════════════════════
    //  DOMAIN ADDR META — per-agent-address metadata
    // ═══════════════════════════════════════════════════════════════════

    /// Insert or replace an agent metadata row.
    pub async fn upsert_domain_addr_meta(
        &self,
        email: &str,
        system_id: &str,
        manager_address: Option<&str>,
        agent_signature: Option<&str>,
        agent_persona: Option<&str>,
    ) -> AppResult<DomainAddrMetaRecord> {
        let (email, system_id) = (email.to_lowercase(), system_id.to_string());
        let (ma, sig, persona) = (
            manager_address.unwrap_or("").to_string(),
            agent_signature.unwrap_or("").to_string(),
            agent_persona.unwrap_or("").to_string(),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO domain_addr_meta (email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)
                 ON CONFLICT(email_address) DO UPDATE SET
                   system_id = excluded.system_id,
                   manager_address = excluded.manager_address,
                   agent_signature = excluded.agent_signature,
                   agent_persona = excluded.agent_persona,
                   updated_at = excluded.updated_at",
                params![email, system_id, ma, sig, persona, now],
            )?;
            Ok(DomainAddrMetaRecord {
                email_address: email,
                system_id,
                manager_address: ma,
                agent_signature: sig,
                agent_persona: persona,
                is_active: true,
                created_at: now.clone(),
                updated_at: now,
            })
        }).await
    }

    /// Get agent metadata by email address.
    pub async fn get_domain_addr_meta(
        &self,
        email: &str,
    ) -> AppResult<Option<DomainAddrMetaRecord>> {
        let email = email.to_lowercase();
        self.call(move |conn| {
            conn.query_row(
                "SELECT email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at
                 FROM domain_addr_meta WHERE email_address = ?1",
                params![email],
                domain_addr_meta_row,
            ).optional().map_err(Into::into)
        }).await
    }

    /// List all agent metadata rows for a system.
    pub async fn list_domain_addr_meta_by_system(
        &self,
        system_id: &str,
    ) -> AppResult<Vec<DomainAddrMetaRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at
                 FROM domain_addr_meta WHERE system_id = ?1",
            )?;
            let rows = stmt.query_map(params![system_id], domain_addr_meta_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }).await
    }

    /// Delete agent metadata by email address.
    pub async fn delete_domain_addr_meta(&self, email: &str) -> AppResult<()> {
        let email = email.to_lowercase();
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM domain_addr_meta WHERE email_address = ?1",
                params![email],
            )?;
            Ok(())
        })
        .await
    }
}

#[derive(Debug, Clone)]
pub struct WhitelistRecord {
    pub id: i64,
    pub system_id: String,
    pub domain_addr: String,
    pub direction: String,
    pub value: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub category: String,
    pub api_key_id: Option<i64>,
}

fn whitelist_row(r: &rusqlite::Row) -> rusqlite::Result<WhitelistRecord> {
    Ok(WhitelistRecord {
        id: r.get(0)?,
        system_id: r.get(1)?,
        domain_addr: r.get(2)?,
        direction: r.get(3)?,
        value: r.get(4)?,
        description: r.get(5)?,
        is_active: r.get::<_, i32>(6)? != 0,
        created_at: r.get(7)?,
        category: r.get(8)?,
        api_key_id: r.get(9)?,
    })
}

impl Database {
    pub async fn insert_whitelist(
        &self,
        system_id: &str,
        domain_addr: &str,
        direction: &str,
        value: &str,
        category: &str,
        api_key_id: Option<i64>,
        description: Option<&str>,
    ) -> AppResult<WhitelistRecord> {
        debug!(
            operation = "insert_whitelist",
            system_id = %system_id,
            domain = %domain_addr,
            direction = %direction,
            value = %value,
            "Whitelist entry inserted"
        );
        let (system_id, domain_addr, direction, value) = (
            system_id.to_string(),
            domain_addr.to_string(),
            direction.to_string(),
            value.to_string(),
        );
        let category = category.to_string();
        let description = description.map(String::from);
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
             conn.execute(
                 // Recreate = overwrite: direction is a one-of-three choice
                 // (to/from/all) per (system_id, domain_addr, value), so a
                 // later create with a different direction replaces the
                 // existing rule (last write wins). AUDIT-1 P2-7 originally
                 // froze direction on conflict, but that made a second
                 // direction un-persistable (4.3c: 'to' row existed, 'from'
                 // create hit the conflict and silently kept 'to').
                 "INSERT INTO whitelists (system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8) ON CONFLICT(system_id, domain_addr, value) DO UPDATE SET direction=excluded.direction, is_active=1, description=CASE WHEN excluded.description IS NOT NULL THEN excluded.description ELSE description END",
                 params![system_id, domain_addr, direction, value, description, now, category, api_key_id],
             )?;
            let id = conn.last_insert_rowid();
            Ok(WhitelistRecord {
                id, system_id, domain_addr, direction, value, description, is_active: true, created_at: now,
                category, api_key_id,
            })
        }).await
    }

    pub async fn get_whitelist(
        &self,
        system_id: &str,
        domain_addr: &str,
        value: &str,
    ) -> AppResult<Option<WhitelistRecord>> {
        let (system_id, domain_addr, value) = (
            system_id.to_string(),
            domain_addr.to_string(),
            value.to_string(),
        );
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE system_id = ?1 AND domain_addr = ?2 AND value = ?3 LIMIT 1",
                params![system_id, domain_addr, value],
                whitelist_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Look up a whitelist entry by its primary key ID (used for cache invalidation on delete).
    pub async fn get_whitelist_by_id(&self, id: i64) -> AppResult<Option<WhitelistRecord>> {
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE id = ?1 LIMIT 1",
                params![id],
                whitelist_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn list_whitelists(&self, system_id: &str) -> AppResult<Vec<WhitelistRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE system_id = ?1",
            )?;
            let rows = stmt.query_map(params![system_id], whitelist_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn update_whitelist(
        &self,
        id: i64,
        is_active: Option<bool>,
        direction: Option<String>,
    ) -> AppResult<Option<WhitelistRecord>> {
        debug!(
            operation = "update_whitelist",
            id = %id,
            is_active = ?is_active,
            direction = ?direction,
            "Whitelist entry updated"
        );
        self.call(move |conn| {
            let current = conn.query_row(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE id = ?1",
                params![id],
                whitelist_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            if let Some(a) = is_active { record.is_active = a; }
            if let Some(ref d) = direction { record.direction = d.clone(); }
            conn.execute(
                "UPDATE whitelists SET is_active = ?1, direction = COALESCE(?2, direction) WHERE id = ?3",
                params![record.is_active as i32, direction, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    pub async fn delete_whitelist(&self, id: i64) -> AppResult<()> {
        debug!(
            operation = "delete_whitelist",
            id = %id,
            "Whitelist entry deleted"
        );
        self.call(move |conn| {
            conn.execute("DELETE FROM whitelists WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
    }

    /// Delete a whitelist entry by domain_addr and value (for manager commands).
    /// Returns Ok(()) even if no matching entry was found.
    pub async fn delete_whitelist_by_domain_and_value(
        &self,
        domain_addr: &str,
        value: &str,
    ) -> AppResult<()> {
        let (domain_addr, value) = (domain_addr.to_string(), value.to_string());
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM whitelists WHERE domain_addr = ?1 AND value = ?2",
                params![domain_addr, value],
            )?;
            Ok(())
        })
        .await
    }

    /// Count whitelist entries for a specific api_key (agent scope).
    pub async fn count_whitelist_entries_by_api_key(
        &self,
        system_id: &str,
        api_key_id: i64,
    ) -> AppResult<i64> {
        let (system_id,) = (system_id.to_string(),);
        self.call(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM whitelists WHERE system_id = ?1 AND api_key_id = ?2 AND category = 'agent'",
                params![system_id, api_key_id],
                |r| r.get(0),
            )?;
            Ok(count)
        }).await
    }

    /// P0: Count active whitelist entries for (system, domain, directions).
    /// Used to distinguish "empty whitelist = open" from "non-empty whitelist = restrictive".
    /// Pre-generated branches for 1-3 directions to avoid dynamic SQL allocation.
    pub async fn count_whitelist_entries(
        &self,
        system_id: &str,
        domain: &str,
        directions: &[&str],
    ) -> AppResult<i64> {
        let (system_id, domain) = (system_id.to_string(), domain.to_string());
        let dirs: Vec<String> = directions.iter().map(|d| d.to_string()).collect();
        self.call(move |conn| {
            let count: i64 = match dirs.len() {
                1 => conn.query_row(
                    "SELECT COUNT(*) FROM whitelists WHERE system_id=?1 AND domain_addr=?2 AND direction=?3 AND is_active=1",
                    params![system_id, domain, dirs[0]], |r| r.get(0),
                )?,
                2 => conn.query_row(
                    "SELECT COUNT(*) FROM whitelists WHERE system_id=?1 AND domain_addr=?2 AND direction IN (?3,?4) AND is_active=1",
                    params![system_id, domain, dirs[0], dirs[1]], |r| r.get(0),
                )?,
                _ => conn.query_row(
                    "SELECT COUNT(*) FROM whitelists WHERE system_id=?1 AND domain_addr=?2 AND direction IN (?3,?4,?5) AND is_active=1",
                    params![system_id, domain, dirs[0], dirs[1], dirs.get(2).cloned().unwrap_or_default()], |r| r.get(0),
                )?,
            };
            Ok(count)
        }).await
    }

    /// Check if a value is whitelisted for a given domain+system+direction.
    /// direction: "from" (sender check), "to" (recipient check), or "all" (both)
    ///
    /// Fetches all active wildcard patterns from the whitelist table and matches
    /// `value` against them using the in-memory `WhitelistCache`. When no active
    /// entries exist for the scope, the answer is **deny** (returns `false`).
    /// Whether `member_addr` is a member of the board `board_email`
    /// (board group whitelist, populated by invite notifications).
    pub async fn is_board_member(&self, board_email: &str, member_addr: &str) -> AppResult<bool> {
        let be = board_email.to_string();
        let ma = member_addr.to_string();
        self.call(move |conn| {
            let n: i64 = conn.query_row(
                "SELECT count(*) FROM board_whitelists WHERE board_email = ?1 AND member_addr = ?2",
                rusqlite::params![be, ma],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
        .await
    }

    /// Replace the member list of a board (full sync from notification).
    pub async fn replace_board_members(&self, board_email: &str, members: &[String]) -> AppResult<usize> {
        let be = board_email.to_string();
        let members: Vec<String> = members.to_vec();
        self.call(move |conn| {
            conn.execute("DELETE FROM board_whitelists WHERE board_email = ?1", [&be])?;
            let mut n = 0;
            for m in &members {
                n += conn.execute(
                    "INSERT OR IGNORE INTO board_whitelists (board_email, member_addr) VALUES (?1, ?2)",
                    rusqlite::params![be, m],
                )?;
            }
            Ok(n)
        })
        .await
    }

    pub async fn is_whitelisted(
        &self,
        system_id: &str,
        domain_addr: &str,
        value: &str,
        direction: &str,
    ) -> AppResult<bool> {
        let (system_id, domain_addr, value, direction) = (
            system_id.to_string(),
            domain_addr.to_string(),
            value.to_string(),
            direction.to_string(),
        );
        let cache = Arc::clone(&self.whitelist_cache);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT value FROM whitelists \
                 WHERE system_id = ?1 AND domain_addr = ?2 \
                   AND (direction = ?3 OR direction = 'all') \
                   AND is_active = 1",
            )?;
            let patterns: Vec<String> = stmt
                .query_map(params![system_id, domain_addr, direction], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;

            if patterns.is_empty() {
                return Ok(false);
            }
            Ok(is_whitelisted_wildcard(&patterns, &value, cache.as_ref()))
        })
        .await
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub system_id: String,
    pub email_address: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub category: String,
    pub activation_code_hash: Option<String>,
    pub activation_expires_at: Option<String>,
    pub claimed_at: Option<String>,
}

pub fn api_key_row(r: &rusqlite::Row) -> rusqlite::Result<ApiKeyRecord> {
    Ok(ApiKeyRecord {
        id: r.get(0)?,
        system_id: r.get(1)?,
        email_address: r.get(2)?,
        key_hash: r.get(3)?,
        key_prefix: r.get(4)?,
        scopes: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        is_active: r.get::<_, i32>(6)? != 0,
        created_at: r.get(7)?,
        expires_at: r.get(8)?,
        last_used_at: r.get(9)?,
        category: r.get(10)?,
        activation_code_hash: r.get(11)?,
        activation_expires_at: r.get(12)?,
        claimed_at: r.get(13)?,
    })
}

impl Database {
    pub async fn insert_api_key(
        &self,
        system_id: &str,
        email_address: &str,
        key_hash: &str,
        key_prefix: &str,
        scopes: &[String],
        expires_at: Option<&str>,
        category: &str,
    ) -> AppResult<ApiKeyRecord> {
        let (system_id, email_address, key_hash, key_prefix) = (
            system_id.to_string(),
            email_address.to_string(),
            key_hash.to_string(),
            key_prefix.to_string(),
        );
        let scopes_json = serde_json::to_string(scopes)
            .map_err(|e| AppError::Internal(format!("serde_json::to_string failed: {e}")))?;
        let scopes_vec = scopes.to_vec();
        let expires_at_owned = expires_at.map(String::from);
        let category = category.to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO api_keys (system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, NULL, ?8)",
                params![system_id, email_address, key_hash, key_prefix, scopes_json, now, expires_at_owned, category],
            )?;
            let id = conn.last_insert_rowid();
            Ok(ApiKeyRecord {
                id, system_id, email_address, key_hash, key_prefix,
                scopes: scopes_vec,
                is_active: true, created_at: now,
                expires_at: expires_at_owned, last_used_at: None,
                category,
                activation_code_hash: None,
                activation_expires_at: None,
                claimed_at: None,
            })
        }).await
    }

    pub async fn lookup_api_key(&self, id: &str) -> AppResult<Option<ApiKeyRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1 AND is_active = 1 LIMIT 1",
                params![id],
                api_key_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn list_api_keys(&self) -> AppResult<Vec<ApiKeyRecord>> {
        self.call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys",
            )?;
            let rows = stmt.query_map((), api_key_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn get_api_key(&self, id: i64) -> AppResult<Option<ApiKeyRecord>> {
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1",
                params![id],
                api_key_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn update_api_key(
        &self,
        id: i64,
        scopes: Option<Vec<String>>,
        is_active: Option<bool>,
    ) -> AppResult<Option<ApiKeyRecord>> {
        let scopes_vec = scopes;
        self.call_tx(move |conn| {
            let current = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1",
                params![id],
                api_key_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            if let Some(s) = scopes_vec {
                record.scopes = s;
            }
            if let Some(a) = is_active { record.is_active = a; }
            let scopes_json = serde_json::to_string(&record.scopes).map_err(|e| AppError::Internal(format!("serde_json::to_string failed: {}", e)))?;
            conn.execute(
                "UPDATE api_keys SET scopes = ?1, is_active = ?2 WHERE id = ?3",
                params![scopes_json, record.is_active as i32, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    pub async fn delete_api_key(&self, id: i64) -> AppResult<()> {
        self.call(move |conn| {
            conn.execute("DELETE FROM api_keys WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
    }

    /// Rotate an API key: update the key_hash and key_prefix.
    pub async fn rotate_api_key(
        &self,
        id: i64,
        new_key_hash: &str,
        new_key_prefix: &str,
    ) -> AppResult<Option<ApiKeyRecord>> {
        let (new_key_hash, new_key_prefix) = (new_key_hash.to_string(), new_key_prefix.to_string());
        self.call_tx(move |conn| {
            let current = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1",
                params![id],
                api_key_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            record.key_hash = new_key_hash;
            record.key_prefix = new_key_prefix;
            conn.execute(
                "UPDATE api_keys SET key_hash = ?1, key_prefix = ?2 WHERE id = ?3",
                params![record.key_hash, record.key_prefix, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    /// List API keys filtered by system_id and category.
    pub async fn list_api_keys_by_system(
        &self,
        system_id: &str,
        category: &str,
    ) -> AppResult<Vec<ApiKeyRecord>> {
        let (system_id, category) = (system_id.to_string(), category.to_string());
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE system_id = ?1 AND category = ?2",
            )?;
            let rows = stmt.query_map(params![system_id, category], api_key_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Look up an API key by email address.
    pub async fn get_api_key_by_email(&self, email: &str) -> AppResult<Option<ApiKeyRecord>> {
        let email = email.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE domain_addr = ?1 AND is_active = 1 LIMIT 1",
                params![email],
                api_key_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Update `last_used_at` for an API key (best-effort observability).
    pub async fn touch_api_key_last_used(&self, id: i64) -> AppResult<()> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
            Ok(())
        })
        .await
    }

    /// Candidate keys for signature verification, by caller identity.
    ///
    /// Identity is the key's `domain_addr` (address-scoped keys) or its
    /// `system_id` (system-level keys). An empty identity (caller does not
    /// know its system yet — e.g. the frontend login path) matches all
    /// active, unexpired keys so the server can identify the key from the
    /// HMAC match itself.
    ///
    /// The returned `key_hash` (= sha256 of the raw key) is the HMAC secret:
    /// the client derives the same value offline, so the raw key never
    /// crosses the wire (see docs/API-SIGNATURE-PROTOCOL.md).
    pub async fn list_api_keys_by_identity(&self, identity: &str) -> AppResult<Vec<ApiKeyRecord>> {
        let identity = identity.to_string();
        self.call(move |conn| {
            let mut results = Vec::new();
            if identity.is_empty() {
                let mut stmt = conn.prepare(
                    "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                )?;
                let rows = stmt.query_map([], api_key_row)?;
                for row in rows { results.push(row?); }
                return Ok(results);
            }
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) AND (domain_addr = ?1 OR system_id = ?1)",
            )?;
            let rows = stmt.query_map(params![identity], api_key_row)?;
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Verify an API key hash exists and is active.
    /// Returns the full ApiKeyRecord if valid, None if invalid/expired/deactivated.
    pub async fn verify_api_key(&self, key_hash: &str) -> AppResult<Option<ApiKeyRecord>> {
        let key_hash = key_hash.to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            let row = conn.query_row(
                // Use strftime with RFC 3339 format for date comparison.
                // datetime('now') produces "YYYY-MM-DD HH:MM:SS" (space-separated),
                // while expires_at may be stored in RFC 3339 with T separator,
                // which makes same-day comparison unreliable.
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE key_hash = ?1 AND is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) LIMIT 1",
                params![key_hash],
                api_key_row,
            ).optional()?;
            if let Some(ref record) = row {
                // Update last_used_at on successful verification (best-effort)
                // Use Chrono RFC 3339 format consistent with created_at and other tables.
                let _ = conn.execute(
                    "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                    params![now, record.id],
                );
            }
            Ok(row)
        }).await
    }

    /// Connection pool accessor for cross-edition consumers (aimail-advanced
    /// AdvancedStorage wraps the base pool). Not dead code — consumed
    /// cross-crate, which the compiler cannot see from this crate alone.
    #[allow(dead_code)]
    pub fn raw_pool(&self) -> Pool<SqliteConnectionManager> {
        self.pool.clone()
    }

    // ── Activation Codes ──────────────────────────────────────────────

    /// Insert a new activation code. Returns the row ID.
    pub async fn insert_activation_code(
        &self,
        code_hash: &str,
        code_prefix: &str,
        code_type: &str,
        system_id: &str,
        domain: &str,
        email_address: &str,
        expires_at: Option<&str>,
    ) -> AppResult<i64> {
        let (code_hash, code_prefix, code_type, system_id, domain, email_address) = (
            code_hash.to_string(),
            code_prefix.to_string(),
            code_type.to_string(),
            system_id.to_string(),
            domain.to_string(),
            email_address.to_string(),
        );
        let expires = expires_at.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO activation_codes (code_hash, code_prefix, code_type, system_id, domain, email_address, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![code_hash, code_prefix, code_type, system_id, domain, email_address, expires, now],
            )?;
            Ok(conn.last_insert_rowid())
        }).await
    }

    /// Look up an unclaimed, non-frozen, non-expired activation code.
    /// Returns (system_id, email_address) if valid, or None.
    pub async fn lookup_activation_code(
        &self,
        code_hash: &str,
    ) -> AppResult<Option<(String, String)>> {
        let code_hash = code_hash.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT system_id, email_address FROM activation_codes
                 WHERE code_hash = ?1 AND claimed = 0 AND is_frozen = 0
                 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            )?;
            let mut rows = stmt.query(params![code_hash])?;
            if let Some(row) = rows.next()? {
                Ok(Some((
                    row.get(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                )))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Mark an activation code as claimed.
    pub async fn claim_activation_code(&self, code_hash: &str, claimed_by: &str) -> AppResult<()> {
        let (code_hash, claimed_by) = (code_hash.to_string(), claimed_by.to_string());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "UPDATE activation_codes SET claimed = 1, claimed_at = ?2, claimed_by = ?3
                 WHERE code_hash = ?1 AND claimed = 0",
                params![code_hash, now, claimed_by],
            )?;
            Ok(())
        })
        .await
    }

    /// Delete an activation code after use (base edition: no accumulation).
    pub async fn delete_activation_code(&self, code_hash: &str) -> AppResult<()> {
        let code_hash = code_hash.to_string();
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM activation_codes WHERE code_hash = ?1",
                params![code_hash],
            )?;
            Ok(())
        })
        .await
    }

    // Pending deliveries (pull mode — aimail-bridge long-poll)
    pub async fn insert_pending_delivery(
        &self,
        system_id: &str,
        domain_addr: &str,
        email: &str,
        headers_json: &str,
        payload_json: &str,
    ) -> AppResult<i64> {
        let sid = system_id.to_string();
        let da = domain_addr.to_string();
        let em = email.to_string();
        let hdrs = headers_json.to_string();
        let pl = payload_json.to_string();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO pending_deliveries (system_id, domain_addr, email, headers, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sid, da, em, hdrs, pl],
            )?;
            Ok(conn.last_insert_rowid())
        }).await
    }

    pub async fn list_pending_deliveries(
        &self,
        system_id: &str,
        limit: i64,
        domains: Option<&[String]>,
    ) -> AppResult<Vec<PendingDeliveryRecord>> {
        let sid = system_id.to_string();
        let domain_filter = domains.map(|d| d.to_vec());
        self.call(move |conn| {
            let mut sql =
                "SELECT id, system_id, domain_addr, email, headers, payload, status, created_at
                 FROM pending_deliveries
                 WHERE system_id = ?1"
                    .to_string();
            if let Some(ref domains) = domain_filter {
                if !domains.is_empty() {
                    let mut conditions: Vec<String> = Vec::new();
                    for _ in domains.iter() {
                        // Parameterized LIKE: value is bound, never interpolated
                        // (AUDIT-1 P1-1: raw format! allowed SQL injection via
                        // malicious domain strings from authenticated clients).
                        // Placeholders: ?1=system_id, ?2=limit, ?3+ = LIKE values.
                        conditions.push(format!("domain_addr LIKE ?{}", conditions.len() + 3));
                    }
                    sql.push_str(&format!(" AND ({})", conditions.join(" OR ")));
                }
            }
            sql.push_str(" ORDER BY created_at ASC LIMIT ?2");
            let mut stmt = conn.prepare(&sql)?;
            // Build param list: system_id, limit, then one LIKE value per domain
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
                vec![Box::new(sid.clone()), Box::new(limit)];
            if let Some(ref domains) = domain_filter {
                for d in domains.iter() {
                    params.push(Box::new(format!("%@{}", d)));
                }
            }
            let rows = stmt.query_map(
                rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
                |r| {
                    Ok(PendingDeliveryRecord {
                        id: r.get(0)?,
                        system_id: r.get(1)?,
                        domain_addr: r.get(2)?,
                        email: r.get(3)?,
                        headers: r.get(4)?,
                        payload: r.get(5)?,
                        status: r.get(6)?,
                        created_at: r.get(7)?,
                    })
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::core::errors::AppError::from(e))
        })
        .await
    }

    pub async fn ack_deliveries(&self, ids: &[i64]) -> AppResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let id_list = ids.to_vec();
        self.call(move |conn| {
            let placeholders: Vec<String> =
                (1..=id_list.len()).map(|i| format!("?{}", i)).collect();
            let sql = format!(
                "DELETE FROM pending_deliveries WHERE id IN ({})",
                placeholders.join(",")
            );
            let count = conn.execute(&sql, rusqlite::params_from_iter(id_list.iter()))?;
            Ok(count)
        })
        .await
    }

    pub async fn cleanup_deliveries(&self, ttl_hours: u64) -> AppResult<()> {
        let ttl = ttl_hours as i64;
        let delivered_cutoff = format!("-{} days", DELIVERED_AUDIT_RETENTION_DAYS);
        self.call(move |conn| {
            // Clean delivered entries older than the audit retention window
            conn.execute(
                "DELETE FROM pending_deliveries WHERE status = 'delivered' AND created_at < datetime('now', ?1)",
                [&delivered_cutoff],
            )?;
            // Clean stale pending entries older than configured TTL
            let ttl_sql = format!("-{} hours", ttl);
            let deleted = conn.execute(
                "DELETE FROM pending_deliveries WHERE status = 'pending' AND created_at < datetime('now', ?1)",
                [&ttl_sql],
            )?;
            if deleted > 0 {
                tracing::info!(count = deleted, ttl_hours = ttl_hours,
                    "Cleaned stale pending deliveries");
            }
            Ok(())
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db() -> Database {
        temp_db_with_path().0
    }

    fn temp_db_with_path() -> (Database, std::path::PathBuf) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("amailgw-test-{}", ts));
        std::fs::create_dir_all(&dir).unwrap();
        // Database::open expects the SQLite FILE path (like main.rs passes
        // config.storage.db_path() = <dir>/aimail.db), not a directory.
        let path = dir.join("aimail.db");
        let db = Database::open(&path, 4, None).unwrap();
        (db, path)
    }

    #[tokio::test]
    async fn pending_domains_filter_is_parameterized() {
        // AUDIT-1 P1-1: a malicious domain string must be treated as a literal
        // LIKE pattern, never spliced into SQL.
        let db = temp_db();
        db.insert_pending_delivery(
            "sys1", "agent@good.test", "agent@good.test", "{}", "{}",
        )
        .await
        .unwrap();
        db.insert_pending_delivery(
            "sys1", "agent@evil.com", "agent@evil.com", "{}", "{}",
        )
        .await
        .unwrap();

        // Injection attempt: closes the LIKE, ORs a tautology, comments out the rest.
        let evil = "x' OR '1'='1";
        let rows = db
            .list_pending_deliveries("sys1", 50, Some(&[evil.to_string()]))
            .await
            .unwrap();
        // No rows match the literal pattern "%@x' OR '1'='1" → empty.
        assert!(rows.is_empty(), "injection must not return rows");

        // Normal filter still works.
        let rows = db
            .list_pending_deliveries("sys1", 50, Some(&["good.test".to_string()]))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].email, "agent@good.test");
    }

    #[tokio::test]
    async fn active_domain_query_excludes_deactivated() {
        // AUDIT-1 P2-4
        let db = temp_db();
        db.insert_system_domain("d1", "sys1", "active.test", Some("http://a"), None)
            .await
            .unwrap();
        db.insert_system_domain("d2", "sys1", "dead.test", Some("http://d"), None)
            .await
            .unwrap();
        db.update_system_domain("d2", None, None, Some(false))
            .await
            .unwrap();

        assert!(db
            .get_active_system_domain_by_domain("active.test")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .get_active_system_domain_by_domain("dead.test")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn whitelist_conflict_overwrites_direction() {
        // Recreate = overwrite: direction is one of (to/from/all) per
        // (system_id, domain_addr, value); a later create with a different
        // direction replaces the existing rule (last write wins). This is
        // what makes the to→from→all sequence (category-4 4.3a/4.3c/4.3d)
        // work — previously the frozen-direction behavior (AUDIT-1 P2-7)
        // made a second direction un-persistable.
        let db = temp_db();
        db.insert_whitelist("sys1", "a@x.com", "from", "v@y.com", "system", None, None)
            .await
            .unwrap();
        db.insert_whitelist("sys1", "a@x.com", "to", "v@y.com", "system", None, None)
            .await
            .unwrap();
        let rec = db
            .get_whitelist("sys1", "a@x.com", "v@y.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.direction, "to", "later create overwrites direction");
        // Single row, not two.
        let n: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM whitelists WHERE system_id='sys1' AND domain_addr='a@x.com' AND value='v@y.com'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(n, 1, "one row per (system_id, domain_addr, value)");
    }

    #[tokio::test]
    async fn endpoint_status_update_targets_existing_keys() {
        // Regression: a broken json_set path (`$.\"dom\".status` containing a
        // literal backslash) matched no key and instead created a garbage
        // key — the original endpoint stayed "pending" forever, so
        // check_all_endpoints_completed never returned true and webhook
        // delivery was retried indefinitely (re-running interceptors,
        // re-creating boards, rotating member tokens).
        let db = temp_db();
        let endpoints = r#"{"orch@y.com":{"url":"http://a","status":"pending"},"ver@y.com":{"url":"http://b","status":"pending"}}"#;
        db.insert_email(
            "e1", "sys1", "outbound", "s@x.com", "r@y.com",
            "subj", "body", Some(endpoints), None, None, 3,
        )
        .await
        .unwrap();

        assert!(
            !db.check_all_endpoints_completed("e1").await.unwrap(),
            "both pending → not all completed"
        );

        assert!(
            db.update_email_endpoint_status("e1", "orch@y.com", "success").await.unwrap(),
            "known endpoint key must match"
        );
        assert!(
            !db.check_all_endpoints_completed("e1").await.unwrap(),
            "one endpoint still pending → not all completed"
        );

        assert!(db.update_email_endpoint_status("e1", "ver@y.com", "success").await.unwrap());
        assert!(
            db.check_all_endpoints_completed("e1").await.unwrap(),
            "all endpoints success → completed"
        );

        // No garbage key: the endpoints column must contain exactly the two
        // original domains (the old bug created a `\"orch@y.com` key and left
        // the real ones pending).
        let rec = db.get_email("e1").await.unwrap().unwrap();
        let v: serde_json::Value =
            serde_json::from_str(rec.endpoints.as_deref().unwrap()).unwrap();
        let obj = v.as_object().expect("endpoints is a JSON object");
        assert_eq!(obj.len(), 2, "no garbage keys in endpoints JSON");
        assert!(obj.contains_key("orch@y.com"));
        assert!(obj.contains_key("ver@y.com"));
    }

    #[tokio::test]
    async fn endpoint_status_update_creates_key_from_null_endpoints() {
        // Regression: pull-mode (bridge) domains build NO endpoint key at
        // insert time, so `endpoints` is NULL. SQLite `json_set(NULL, ...)`
        // returns NULL — the success mark was lost,
        // check_all_endpoints_completed stayed false, and the scheduler
        // treated the successful delivery as a failure, retrying to
        // max_attempts and re-inserting a pending delivery on every pass
        // (the 3x delivery storm). COALESCE(endpoints, '{}') makes the
        // success mark land and the email complete on first delivery.
        let db = temp_db();
        db.insert_email(
            "e1", "sys1", "inbound", "ext@x.com", "agent@pull.test",
            "subj", "body", None, None, None, 3,
        )
        .await
        .unwrap();

        assert!(
            !db.check_all_endpoints_completed("e1").await.unwrap(),
            "NULL endpoints → not completed (nothing delivered yet)"
        );

        assert!(
            db.update_email_endpoint_status("e1", "pull.test", "success").await.unwrap(),
            "NULL endpoints must gain the key, not stay NULL"
        );
        assert!(
            db.check_all_endpoints_completed("e1").await.unwrap(),
            "success mark must make the email complete"
        );

        // The key landed with the right status and nothing else.
        let rec = db.get_email("e1").await.unwrap().unwrap();
        let v: serde_json::Value =
            serde_json::from_str(rec.endpoints.as_deref().unwrap()).unwrap();
        let obj = v.as_object().expect("endpoints is a JSON object");
        assert_eq!(obj.len(), 1);
        assert_eq!(
            obj["pull.test"]["status"].as_str(),
            Some("success"),
            "status written under the domain key"
        );
    }

    // ── readying → ready → sending state machine ────────────────────
    //
    // The flake this guards: a tick batch used to see a freshly-inserted
    // inbound email (born `ready`) before its attachments were saved, and
    // delivered a payload with an empty attachment list. Now every email is
    // born `readying` and the tick only ever reads `ready`, so the race is
    // structurally impossible. These tests pin each invariant down.

    #[tokio::test]
    async fn born_state_is_readying() {
        // Invariant 1: every insert lands in `readying`, never `ready`.
        let db = temp_db();
        db.insert_email("born1", "sys1", "inbound", "a@x.com",
            "{}", "s", "b", None, None, None, 3).await.unwrap();
        let rec = db.get_email("born1").await.unwrap().unwrap();
        assert_eq!(rec.status, "readying");
    }

    #[tokio::test]
    async fn readying_invisible_to_tick_and_overlimit() {
        // Invariant 2 (the flake fix): the tick (Flow 2) and the overlimit
        // fetch (Flow 1) only read `ready`. A born `readying` email is
        // invisible to both, so a half-prepared payload can never be
        // delivered early. Once flipped to `ready`, the tick sees it.
        let db = temp_db();
        db.insert_email("inv1", "sys1", "inbound", "a@x.com",
            "{}", "s", "b", None, None, None, 3).await.unwrap();
        assert!(db.get_pending_retry_emails(10).await.unwrap().is_empty(),
            "tick must not see a readying email");
        assert!(db.get_overlimit_emails(10).await.unwrap().is_empty(),
            "overlimit fetch must not see a readying email");

        // Flip to ready (what crash recovery / retry fallback do) → visible.
        assert!(db.flip_readying_to_ready("inv1").await.unwrap());
        assert_eq!(db.get_pending_retry_emails(10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn claim_ready_accepts_readying_and_ready() {
        // Invariant 3: the trigger claims from either state via CAS.
        // `readying` (first delivery) and `ready` (recovery / retry
        // fallback) are both claimable; a second claim must fail
        // (single-delivery guarantee).
        let db = temp_db();
        db.insert_email("c1", "sys1", "inbound", "a@x.com",
            "{}", "s", "b", None, None, None, 3).await.unwrap();
        let first = db.claim_ready("c1").await.unwrap();
        assert!(first.is_some(), "trigger must claim a readying email");
        assert_eq!(first.unwrap().status, "sending");
        assert!(db.claim_ready("c1").await.unwrap().is_none(),
            "double claim must fail — single delivery");

        // A `ready` email (retry fallback) is claimable too; `sending` is not.
        db.insert_email("c2", "sys1", "inbound", "a@x.com",
            "{}", "s", "b", None, None, None, 3).await.unwrap();
        db.flip_readying_to_ready("c2").await.unwrap();
        assert!(db.claim_ready("c2").await.unwrap().is_some());
        assert!(db.claim_ready("c2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn flip_readying_is_cas() {
        // Invariant 4: the crash-recovery flip is a no-op once a trigger has
        // already claimed the email (flip-vs-claim race resolves safely).
        let db = temp_db();
        db.insert_email("f1", "sys1", "inbound", "a@x.com",
            "{}", "s", "b", None, None, None, 3).await.unwrap();
        assert!(db.claim_ready("f1").await.unwrap().is_some());
        assert!(!db.flip_readying_to_ready("f1").await.unwrap(),
            "flip must not resurrect a claimed email");
    }

    #[tokio::test]
    async fn ready_retry_relands_in_ready_not_readying() {
        // Invariant 5: a failed delivery falls back to `ready` (with a
        // backoff), never back to `readying` — so a retry is always
        // tick-claimable and can never re-enter the hidden birth state.
        let db = temp_db();
        db.insert_email("r1", "sys1", "inbound", "a@x.com",
            "{}", "s", "b", None, None, None, 3).await.unwrap();
        db.claim_ready("r1").await.unwrap(); // trigger → sending
        let rec = db.update_email_ready_retry("r1", 1, "2099-01-01T00:00:00Z")
            .await.unwrap().unwrap();
        assert_eq!(rec.status, "ready");
        // Past-due retry is visible to the tick.
        db.update_email_ready_retry("r1", 1, "2000-01-01T00:00:00Z")
            .await.unwrap().unwrap();
        assert_eq!(db.get_pending_retry_emails(10).await.unwrap().len(), 1);
    }

    /// Seed the board tables the migration touches (Database::open only
    /// creates the core schema; board tables are created by the board module).
    fn seed_board_tables(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS boards (
                id TEXT PRIMARY KEY, short_id TEXT UNIQUE NOT NULL,
                board_email TEXT NOT NULL, goal TEXT, status TEXT DEFAULT 'active',
                output_task_id TEXT, plan_version TEXT, plan_text TEXT,
                plan_confirmed_at TEXT, criteria_version TEXT, criteria_text TEXT,
                criteria_confirmed_at TEXT, created_at TEXT, completed_at TEXT, system_id TEXT
            );
            CREATE TABLE IF NOT EXISTS board_members (
                email TEXT PRIMARY KEY, role TEXT NOT NULL, display_name TEXT NOT NULL,
                board_token TEXT, board_id TEXT REFERENCES boards(id), joined_at TEXT,
                domains TEXT, capability_snapshot TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, short_id TEXT NOT NULL, board_id TEXT REFERENCES boards(id),
                title TEXT, body TEXT, status TEXT DEFAULT 'todo',
                assignee TEXT REFERENCES board_members(email), reviewer TEXT,
                parent_ids TEXT DEFAULT '[]', tags TEXT DEFAULT '[]', summary TEXT DEFAULT '',
                metadata TEXT, created_by TEXT, created_at TEXT, updated_at TEXT,
                completed_at TEXT, cancelled_at TEXT, deadline TEXT
            );
            CREATE TABLE IF NOT EXISTS task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT REFERENCES tasks(id),
                event_type TEXT, actor TEXT, payload TEXT, created_at TEXT
            );",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn rename_agent_address_migrates_all_references() {
        let (db, path) = temp_db_with_path();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            seed_board_tables(&conn);
            conn.execute_batch(
                "INSERT INTO system_domains(id,system_id,domain_addr,webhook_url,webhook_secret)
                   VALUES('d1','shared-sys1','old.agent@shared.example','http://hook','sec');
                 INSERT INTO domain_addr_meta(email_address,system_id,manager_address,agent_signature,agent_persona)
                   VALUES('old.agent@shared.example','shared-sys1','mgr@example.com','sig','persona');
                 INSERT INTO api_keys(system_id,domain_addr,key_hash,key_prefix,scopes,category)
                   VALUES('shared-sys1','old.agent@shared.example','hash123','pref','[\"agent\"]','agent');
                 INSERT INTO whitelists(system_id,domain_addr,direction,value,description,category)
                   VALUES('shared-sys1','old.agent@shared.example','all','mgr@example.com','agent-side','system'),
                         ('shared-sys1','other.agent@shared.example','all','old.agent@shared.example','peer-side','system');
                 INSERT INTO agent_state(agent_addr,state_key,state_value)
                   VALUES('old.agent@shared.example','profile:old.agent@shared.example','{\"name\":\"Old\"}');
                 INSERT INTO boards(id,short_id,board_email,goal) VALUES('b1','b1','old.agent@shared.example','g');
                 INSERT INTO board_members(email,role,display_name,board_token,board_id,domains)
                   VALUES('old.agent@shared.example','owner','Old Agent','tok','b1','[\"b1\"]');
                 INSERT INTO tasks(id,short_id,board_id,title,assignee,reviewer,created_by)
                   VALUES('t1','t1','b1','x','old.agent@shared.example','old.agent@shared.example','old.agent@shared.example');
                 INSERT INTO task_events(task_id,event_type,actor,payload)
                   VALUES('t1','comment','old.agent@shared.example','{}');",
            )
            .unwrap();
        }

        db.rename_agent_address_refs("old.agent@shared.example", "new.agent@shared.example")
            .await
            .unwrap();

        let conn = rusqlite::Connection::open(&path).unwrap();
        // system_domains: re-keyed, webhook rides along
        let row: (String, String) = conn
            .query_row(
                "SELECT domain_addr, webhook_secret FROM system_domains WHERE id='d1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            ("new.agent@shared.example".to_string(), "sec".to_string())
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM system_domains WHERE domain_addr='old.agent@shared.example'"
            ),
            0
        );
        // domain_addr_meta re-keyed with manager/signature intact
        let meta: (String, String) = conn
            .query_row(
                "SELECT manager_address, agent_signature FROM domain_addr_meta WHERE email_address='new.agent@shared.example'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(meta, ("mgr@example.com".to_string(), "sig".to_string()));
        // api_keys: re-pointed, key material untouched
        let key: (String, String) = conn
            .query_row(
                "SELECT domain_addr, key_hash FROM api_keys WHERE key_prefix='pref'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            key,
            (
                "new.agent@shared.example".to_string(),
                "hash123".to_string()
            )
        );
        // whitelists both sides migrated, no orphans
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE domain_addr='new.agent@shared.example' AND value='mgr@example.com'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE domain_addr='other.agent@shared.example' AND value='new.agent@shared.example'"
            ),
            1
        );
        assert_eq!(
            count_rows(&conn, "SELECT COUNT(*) FROM whitelists WHERE value='old.agent@shared.example'"),
            0
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE domain_addr='old.agent@shared.example'"
            ),
            0
        );
        // agent_state: addr re-keyed + embedded state key rewritten
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM agent_state WHERE agent_addr='new.agent@shared.example' AND state_key='profile:new.agent@shared.example'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM agent_state WHERE agent_addr='old.agent@shared.example'"
            ),
            0
        );
        // boards/members/tasks/events all follow
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM boards WHERE board_email='new.agent@shared.example'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM board_members WHERE email='new.agent@shared.example' AND role='owner' AND board_token='tok'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM board_members WHERE email='old.agent@shared.example'"
            ),
            0
        );
        let t: (String, String) = conn
            .query_row("SELECT assignee, reviewer FROM tasks WHERE id='t1'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            t,
            (
                "new.agent@shared.example".to_string(),
                "new.agent@shared.example".to_string()
            )
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM task_events WHERE actor='new.agent@shared.example'"
            ),
            1
        );
    }

    fn count_rows(conn: &rusqlite::Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }
}
