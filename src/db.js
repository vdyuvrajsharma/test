const { Pool } = require('pg');

const DEFAULT_POOL_CONFIG = {
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30_000)
};

function createMemoryPool() {
  const { newDb } = require('pg-mem');
  const db = newDb({ autoCreateForeignKeyIndices: true });
  const adapter = db.adapters.createPg();
  return new adapter.Pool();
}

function createPool() {
  if (process.env.DATABASE_URL) {
    return new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PG_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      ...DEFAULT_POOL_CONFIG
    });
  }
  return createMemoryPool();
}

const pool = createPool();

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('super_admin', 'examiner', 'proctor', 'examinee')),
      password_hash TEXT,
      access_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, email)
    );

    CREATE TABLE IF NOT EXISTS exams (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      title TEXT NOT NULL,
      start_at TIMESTAMPTZ NOT NULL,
      end_at TIMESTAMPTZ NOT NULL,
      duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
      negative_marking NUMERIC NOT NULL DEFAULT 0,
      sections_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (end_at > start_at)
    );

    CREATE TABLE IF NOT EXISTS attempts (
      id TEXT PRIMARY KEY,
      exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      tenant_id TEXT NOT NULL,
      examinee_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      started_at TIMESTAMPTZ NOT NULL,
      ends_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('in_progress', 'submitted', 'graded')),
      answers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      events_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      heartbeats_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      warnings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      auto_score_json JSONB,
      subjective_score NUMERIC NOT NULL DEFAULT 0,
      rubric_scores_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      exam_snapshot_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS proctor_snapshots (
      id TEXT PRIMARY KEY,
      attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
      captured_at TIMESTAMPTZ NOT NULL,
      mime_type TEXT NOT NULL,
      image_data_base64 TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_id TEXT,
      tenant_id TEXT,
      action TEXT NOT NULL,
      payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, role);
    CREATE INDEX IF NOT EXISTS idx_exams_tenant_owner ON exams(tenant_id, owner_id);
    CREATE INDEX IF NOT EXISTS idx_attempts_exam ON attempts(exam_id);
    CREATE INDEX IF NOT EXISTS idx_attempts_examinee ON attempts(examinee_id, status);
    CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_logs(tenant_id, created_at DESC);
  `);
}

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  pool,
  initSchema,
  withTransaction
};
