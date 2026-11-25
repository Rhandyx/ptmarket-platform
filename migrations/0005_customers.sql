-- 0005 — customers (global; RLS forçado com ZERO políticas e ZERO grants: fechada até ao épico identity).
-- Rollback mental: DROP TABLE customers;  (índice cai com a tabela.)

CREATE TABLE customers (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    email         VARCHAR(255),
    name          VARCHAR(255),
    phone         VARCHAR(50),
    nif           VARCHAR(20),
    password_hash TEXT, -- Argon2id PHC; NULL = só passkey
    passkeys      JSONB       NOT NULL DEFAULT '[]',
    consents      JSONB       NOT NULL DEFAULT '{}',
    anonymized_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (email IS NOT NULL OR anonymized_at IS NOT NULL)
);

CREATE UNIQUE INDEX customers_email_lower_key ON customers (lower(email));

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;
