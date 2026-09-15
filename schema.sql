-- KalmPass schema.
--
-- There is no readable data in these tables. Two independent layers stand
-- between a database dump and anybody's passwords:
--
--   1. Client layer. Item contents are AES-256-GCM encrypted in the browser
--      under a vault key that is itself wrapped by a key derived from the
--      account's master password. That password never leaves the device, so the
--      server cannot decrypt this layer even in principle.
--
--   2. Server envelope. Everything the client hands over is encrypted again by
--      the Worker under SERVER_KEY, a Cloudflare secret that is never stored in
--      D1. A leaked database alone is opaque bytes.
--
-- Columns suffixed `_enc` are envelope ciphertext, base64(iv || ct).
-- Columns suffixed `_index` are keyed blind indexes (HMAC under SERVER_KEY):
-- they permit exact-match lookup and nothing else.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id                     TEXT    PRIMARY KEY,

  -- The address itself is not recoverable from the index, so the database
  -- cannot be mined for a customer list or cross-referenced against a breach
  -- corpus. `email_enc` is the only copy, and it needs SERVER_KEY to read.
  email_index            TEXT    NOT NULL UNIQUE,
  email_enc              TEXT    NOT NULL,

  -- HMAC(pepper, PBKDF2(auth_key, server_salt)). `auth_key` is an HKDF branch
  -- of the master key, deliberately unrelated to the encryption branch, so even
  -- recovering it would not decrypt anything.
  auth_hash              TEXT    NOT NULL,
  server_salt            TEXT    NOT NULL,
  kdf_iterations         INTEGER NOT NULL,

  -- The vault key, wrapped two ways. Either route opens the vault; neither can
  -- be opened by us. This is what makes recovery possible without escrow.
  protected_key          TEXT    NOT NULL,  -- wrapped by the master password
  recovery_wrap          TEXT,              -- wrapped by the Recovery Key
  recovery_hash          TEXT,              -- verifier for the Recovery Key
  recovery_salt          TEXT,
  recovery_created_at    INTEGER,

  email_verified         INTEGER NOT NULL DEFAULT 0,
  status                 TEXT    NOT NULL DEFAULT 'active',  -- active | suspended

  -- Billing. The Stripe ids are stored encrypted and indexed separately, so a
  -- database leak does not hand over a mapping of customers to subscriptions.
  plan                   TEXT    NOT NULL DEFAULT 'free',    -- free | pro
  plan_status            TEXT,                               -- active | past_due | canceled | trialing
  plan_period_end        INTEGER,
  stripe_customer_index  TEXT,
  stripe_customer_enc    TEXT,
  stripe_subscription_enc TEXT,

  totp_enabled           INTEGER NOT NULL DEFAULT 0,
  totp_secret_enc        TEXT,
  totp_backup_enc        TEXT,

  created_at             INTEGER NOT NULL,
  updated_at             INTEGER NOT NULL,
  last_login_at          INTEGER
);

CREATE INDEX IF NOT EXISTS idx_users_stripe ON users (stripe_customer_index);

CREATE TABLE IF NOT EXISTS items (
  id          TEXT    PRIMARY KEY,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- envelope(AES-GCM(vault_key, padded_item_json)). Names, URLs, usernames and
  -- notes all live inside the blob, and the client pads to a 256-byte boundary
  -- first, so the stored length discloses nothing about the contents either.
  data        TEXT    NOT NULL,

  revision    INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  deleted_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_items_user ON items (user_id, updated_at);

-- Session tokens are 256-bit random values; only HMAC(pepper, token) is stored,
-- so the table cannot be used to mint a session even with full read access.
CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT    PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope         TEXT    NOT NULL DEFAULT 'full',  -- full | recovery

  -- HMAC(pepper, device id). The client generates a random id once and keeps it,
  -- so signing in again on the same machine replaces that machine's session
  -- rather than consuming another slot against the plan. Hashed like everything
  -- else, so the table cannot be read as a list of somebody's machines.
  device_index  TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  absolute_end  INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  label_enc     TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions (user_id, device_index);

-- One-shot links sent by email. Same treatment as sessions: the raw token goes
-- in the email and only its HMAC is kept here.
CREATE TABLE IF NOT EXISTS tokens (
  id          TEXT    PRIMARY KEY,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL,  -- verify_email | reset_account
  payload_enc TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens (user_id, kind);

-- A security log the account holder can read: sign-ins, password changes,
-- recovery, billing. Addresses are stored as blind indexes, so the log is
-- useful to its owner without becoming a location history for anyone else.
CREATE TABLE IF NOT EXISTS audit (
  id         TEXT    PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL,
  at         INTEGER NOT NULL,
  detail_enc TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit (user_id, at);

-- Login throttling, keyed by blind index of email and of client IP separately,
-- so a flood from one address cannot lock a different account out.
CREATE TABLE IF NOT EXISTS throttle (
  key           TEXT    PRIMARY KEY,
  fails         INTEGER NOT NULL DEFAULT 0,
  first_fail_at INTEGER NOT NULL,
  locked_until  INTEGER
);

-- Passkeys that can unlock a vault.
--
-- A passkey here is not used to sign a WebAuthn assertion for the server to
-- verify. It is used for its PRF output: a deterministic secret the
-- authenticator will only produce for this origin, after the user has proved
-- themselves to the device. That secret is split like the Recovery Key is, so
-- what lands in this table is another wrapped copy of the vault key and a
-- verifier, neither of which the server can open.
CREATE TABLE IF NOT EXISTS passkeys (
  id               TEXT    PRIMARY KEY,
  user_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- HMAC(pepper, credential id), so the table cannot be correlated against a
  -- credential seen anywhere else.
  credential_index TEXT    NOT NULL UNIQUE,
  credential_enc   TEXT    NOT NULL,

  auth_hash        TEXT    NOT NULL,
  server_salt      TEXT    NOT NULL,
  -- envelope(AES-GCM(passkey enc branch, vault key)).
  wrapped_key      TEXT    NOT NULL,

  label_enc        TEXT,
  created_at       INTEGER NOT NULL,
  last_used_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys (user_id);
