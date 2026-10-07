import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Durable state: callback deliveries and internal-auth nonces.
 *
 * SQLite in WAL mode with `synchronous = FULL`: a callback is on disk before
 * the provider gets an answer. The proxy runs as a single instance (its
 * value is one fixed egress IP), so an embedded database is enough; every
 * state change is a single conditional UPDATE, so even two processes on the
 * same file cannot both deliver one callback at the same time.
 */

export type CallbackStatus = "validated" | "forwarding" | "delivered" | "retry_pending" | "failed";
export type FailureKind = "rejected" | "exhausted";

export type CallbackRecord = {
  id: string;
  provider: string;
  dedupeKey: string;
  reference: string | null;
  requestId: string;
  receivedAt: number;
  sourceIp: string | null;
  method: string;
  contentType: string | null;
  payloadHash: string;
  /** Encrypted body, query and forwarded headers; null once purged. */
  payloadEnc: string | null;
  destination: string;
  status: CallbackStatus;
  failureKind: FailureKind | null;
  attempts: number;
  duplicateCount: number;
  lastError: string | null;
  lastHttpStatus: number | null;
  responseStatus: number | null;
  /** Encrypted backend response body. */
  responseEnc: string | null;
  responseContentType: string | null;
  nextAttemptAt: number | null;
  lockUntil: number | null;
  deliveredAt: number | null;
  updatedAt: number;
};

export type NewCallback = Pick<
  CallbackRecord,
  | "id"
  | "provider"
  | "dedupeKey"
  | "reference"
  | "requestId"
  | "receivedAt"
  | "sourceIp"
  | "method"
  | "contentType"
  | "payloadHash"
  | "payloadEnc"
  | "destination"
  | "nextAttemptAt"
>;

type Row = {
  id: string;
  provider: string;
  dedupe_key: string;
  reference: string | null;
  request_id: string;
  received_at: number;
  source_ip: string | null;
  method: string;
  content_type: string | null;
  payload_hash: string;
  payload_enc: string | null;
  destination: string;
  status: CallbackStatus;
  failure_kind: FailureKind | null;
  attempts: number;
  duplicate_count: number;
  last_error: string | null;
  last_http_status: number | null;
  response_status: number | null;
  response_enc: string | null;
  response_content_type: string | null;
  next_attempt_at: number | null;
  lock_until: number | null;
  delivered_at: number | null;
  updated_at: number;
};

const toRecord = (r: Row): CallbackRecord => ({
  id: r.id,
  provider: r.provider,
  dedupeKey: r.dedupe_key,
  reference: r.reference,
  requestId: r.request_id,
  receivedAt: r.received_at,
  sourceIp: r.source_ip,
  method: r.method,
  contentType: r.content_type,
  payloadHash: r.payload_hash,
  payloadEnc: r.payload_enc,
  destination: r.destination,
  status: r.status,
  failureKind: r.failure_kind,
  attempts: r.attempts,
  duplicateCount: r.duplicate_count,
  lastError: r.last_error,
  lastHttpStatus: r.last_http_status,
  responseStatus: r.response_status,
  responseEnc: r.response_enc,
  responseContentType: r.response_content_type,
  nextAttemptAt: r.next_attempt_at,
  lockUntil: r.lock_until,
  deliveredAt: r.delivered_at,
  updatedAt: r.updated_at,
});

const MIGRATIONS: string[] = [
  `CREATE TABLE callbacks (
     id TEXT PRIMARY KEY,
     provider TEXT NOT NULL,
     dedupe_key TEXT NOT NULL,
     reference TEXT,
     request_id TEXT NOT NULL,
     received_at INTEGER NOT NULL,
     source_ip TEXT,
     method TEXT NOT NULL,
     content_type TEXT,
     payload_hash TEXT NOT NULL,
     payload_enc TEXT,
     destination TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('validated','forwarding','delivered','retry_pending','failed')),
     failure_kind TEXT CHECK (failure_kind IS NULL OR failure_kind IN ('rejected','exhausted')),
     attempts INTEGER NOT NULL DEFAULT 0,
     duplicate_count INTEGER NOT NULL DEFAULT 0,
     last_error TEXT,
     last_http_status INTEGER,
     response_status INTEGER,
     response_enc TEXT,
     response_content_type TEXT,
     next_attempt_at INTEGER,
     lock_until INTEGER,
     delivered_at INTEGER,
     updated_at INTEGER NOT NULL,
     UNIQUE (provider, dedupe_key)
   );
   CREATE INDEX idx_callbacks_due ON callbacks (status, next_attempt_at);
   CREATE INDEX idx_callbacks_reference ON callbacks (provider, reference);
   CREATE INDEX idx_callbacks_received ON callbacks (received_at);
   CREATE TABLE nonces (
     key_id TEXT NOT NULL,
     nonce TEXT NOT NULL,
     expires_at INTEGER NOT NULL,
     PRIMARY KEY (key_id, nonce)
   );
   CREATE INDEX idx_nonces_expires ON nonces (expires_at);`,
];

export class Store {
  private readonly db: Database.Database;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("busy_timeout = 5000");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)");
    const row = this.db.prepare("SELECT MAX(version) AS v FROM schema_migrations").get() as { v: number | null };
    const current = row.v ?? 0;
    MIGRATIONS.forEach((sql, i) => {
      const version = i + 1;
      if (version <= current) return;
      this.db.transaction(() => {
        this.db.exec(sql);
        this.db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(version, Date.now());
      })();
    });
  }

  ping(): boolean {
    return (this.db.prepare("SELECT 1 AS ok").get() as { ok: number }).ok === 1;
  }

  close(): void {
    this.db.close();
  }

  // ---- callbacks -------------------------------------------------------

  /** Stores a new callback, or returns the one already stored under the same dedupe key. */
  insertCallback(rec: NewCallback): { inserted: true; record: CallbackRecord } | { inserted: false; record: CallbackRecord } {
    const now = rec.receivedAt;
    const result = this.db
      .prepare(
        `INSERT INTO callbacks (id, provider, dedupe_key, reference, request_id, received_at, source_ip, method, content_type,
           payload_hash, payload_enc, destination, status, attempts, next_attempt_at, updated_at)
         VALUES (@id, @provider, @dedupeKey, @reference, @requestId, @receivedAt, @sourceIp, @method, @contentType,
           @payloadHash, @payloadEnc, @destination, 'validated', 0, @nextAttemptAt, @now)
         ON CONFLICT (provider, dedupe_key) DO NOTHING`,
      )
      .run({ ...rec, now });
    if (result.changes === 1) return { inserted: true, record: this.getCallback(rec.id)! };
    this.db
      .prepare("UPDATE callbacks SET duplicate_count = duplicate_count + 1, updated_at = ? WHERE provider = ? AND dedupe_key = ?")
      .run(now, rec.provider, rec.dedupeKey);
    return { inserted: false, record: this.findByDedupe(rec.provider, rec.dedupeKey)! };
  }

  getCallback(id: string): CallbackRecord | null {
    const row = this.db.prepare("SELECT * FROM callbacks WHERE id = ?").get(id) as Row | undefined;
    return row ? toRecord(row) : null;
  }

  findByDedupe(provider: string, dedupeKey: string): CallbackRecord | null {
    const row = this.db.prepare("SELECT * FROM callbacks WHERE provider = ? AND dedupe_key = ?").get(provider, dedupeKey) as Row | undefined;
    return row ? toRecord(row) : null;
  }

  /**
   * Takes the delivery lock. Succeeds for a record waiting to be delivered,
   * or one whose previous lock expired (process died mid-delivery).
   */
  claim(id: string, now: number, lockUntil: number): boolean {
    const result = this.db
      .prepare(
        `UPDATE callbacks SET status = 'forwarding', lock_until = ?, attempts = attempts + 1, updated_at = ?
         WHERE id = ? AND (status IN ('validated', 'retry_pending') OR (status = 'forwarding' AND lock_until < ?))`,
      )
      .run(lockUntil, now, id, now);
    return result.changes === 1;
  }

  markDelivered(id: string, r: { httpStatus: number; responseEnc: string | null; contentType: string | null; now: number }): void {
    this.db
      .prepare(
        `UPDATE callbacks SET status = 'delivered', failure_kind = NULL, last_error = NULL, last_http_status = ?, response_status = ?,
           response_enc = ?, response_content_type = ?, delivered_at = ?, next_attempt_at = NULL, lock_until = NULL, updated_at = ?
         WHERE id = ? AND status = 'forwarding'`,
      )
      .run(r.httpStatus, r.httpStatus, r.responseEnc, r.contentType, r.now, r.now, id);
  }

  markRetry(id: string, r: { error: string; httpStatus: number | null; nextAttemptAt: number; now: number }): void {
    this.db
      .prepare(
        `UPDATE callbacks SET status = 'retry_pending', last_error = ?, last_http_status = ?, next_attempt_at = ?, lock_until = NULL, updated_at = ?
         WHERE id = ? AND status = 'forwarding'`,
      )
      .run(r.error, r.httpStatus, r.nextAttemptAt, r.now, id);
  }

  markFailed(
    id: string,
    r: { kind: FailureKind; error: string; httpStatus: number | null; responseEnc: string | null; contentType: string | null; now: number },
  ): void {
    this.db
      .prepare(
        `UPDATE callbacks SET status = 'failed', failure_kind = ?, last_error = ?, last_http_status = ?, response_status = ?,
           response_enc = ?, response_content_type = ?, next_attempt_at = NULL, lock_until = NULL, updated_at = ?
         WHERE id = ? AND status = 'forwarding'`,
      )
      .run(r.kind, r.error, r.httpStatus, r.httpStatus, r.responseEnc, r.contentType, r.now, id);
  }

  /**
   * Puts a failed callback back in the queue with a fresh attempt budget
   * (provider redelivery after exhaustion, or an operator's redeliver).
   */
  rearm(id: string, now: number, options: { includeRejected: boolean }): boolean {
    const kinds = options.includeRejected ? "('rejected','exhausted')" : "('exhausted')";
    const result = this.db
      .prepare(
        `UPDATE callbacks SET status = 'retry_pending', failure_kind = NULL, attempts = 0, next_attempt_at = ?, lock_until = NULL, updated_at = ?
         WHERE id = ? AND status = 'failed' AND failure_kind IN ${kinds} AND payload_enc IS NOT NULL`,
      )
      .run(now, now, id);
    return result.changes === 1;
  }

  /** Ids ready for a delivery attempt, oldest first. */
  dueCallbacks(now: number, limit: number): string[] {
    const rows = this.db
      .prepare(
        `SELECT id FROM callbacks
         WHERE (status IN ('validated', 'retry_pending') AND next_attempt_at <= ?)
            OR (status = 'forwarding' AND lock_until < ?)
         ORDER BY COALESCE(next_attempt_at, received_at) ASC
         LIMIT ?`,
      )
      .all(now, now, limit) as Array<{ id: string }>;
    return rows.map((r) => r.id);
  }

  listCallbacks(filter: { provider?: string; status?: CallbackStatus; reference?: string; limit: number; before?: number }): CallbackRecord[] {
    const where: string[] = [];
    const args: Array<string | number> = [];
    if (filter.provider) {
      where.push("provider = ?");
      args.push(filter.provider);
    }
    if (filter.status) {
      where.push("status = ?");
      args.push(filter.status);
    }
    if (filter.reference) {
      where.push("reference = ?");
      args.push(filter.reference);
    }
    if (filter.before) {
      where.push("received_at < ?");
      args.push(filter.before);
    }
    const sql = `SELECT * FROM callbacks ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY received_at DESC LIMIT ?`;
    return (this.db.prepare(sql).all(...args, filter.limit) as Row[]).map(toRecord);
  }

  countsByStatus(): Array<{ provider: string; status: CallbackStatus; count: number }> {
    return this.db.prepare("SELECT provider, status, COUNT(*) AS count FROM callbacks GROUP BY provider, status").all() as Array<{
      provider: string;
      status: CallbackStatus;
      count: number;
    }>;
  }

  /** Clears stored payloads of finished callbacks older than `before`; the delivery record itself is kept. */
  purgePayloads(before: number): number {
    return this.db
      .prepare(
        `UPDATE callbacks SET payload_enc = NULL, response_enc = NULL
         WHERE received_at < ? AND status IN ('delivered', 'failed') AND (payload_enc IS NOT NULL OR response_enc IS NOT NULL)`,
      )
      .run(before).changes;
  }

  // ---- nonces ----------------------------------------------------------

  /** Records a nonce; false when it was already used (replay). */
  rememberNonce(keyId: string, nonce: string, expiresAt: number): boolean {
    const result = this.db
      .prepare("INSERT INTO nonces (key_id, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT (key_id, nonce) DO NOTHING")
      .run(keyId, nonce, expiresAt);
    return result.changes === 1;
  }

  purgeNonces(now: number): number {
    return this.db.prepare("DELETE FROM nonces WHERE expires_at < ?").run(now).changes;
  }
}
