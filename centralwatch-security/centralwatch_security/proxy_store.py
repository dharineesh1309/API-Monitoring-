"""Persistent PostgreSQL storage for CentralWatch proxy configuration.

The database never receives a plaintext upstream API key. Secrets are encrypted
in the application with AES-256-GCM (or AWS KMS when configured) before they are
written, and the service ID is authenticated as associated data so encrypted values
cannot be swapped between service records unnoticed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import asyncpg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("centralwatch_security.proxy_store")

_CIPHER_VERSION = 1
_NONCE_BYTES = 12


class ProxyStoreError(RuntimeError):
    """Raised when proxy configuration storage cannot be used safely."""


class _SecretCipher:
    """Envelope encryption for managed upstream secrets with AES-256-GCM or AWS KMS."""

    def __init__(self, encoded_key: str, kms_key_id: str | None = None) -> None:
        self.kms_key_id = kms_key_id or os.environ.get("AWS_KMS_KEY_ID")
        self.use_kms = bool(self.kms_key_id)
        self.encoded_key = encoded_key
        if not encoded_key and not self.use_kms:
            raise ProxyStoreError("PROXY_SECRET_ENCRYPTION_KEY is required.")
        if encoded_key:
            try:
                self._key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise ProxyStoreError(
                    "PROXY_SECRET_ENCRYPTION_KEY must be a URL-safe base64 value."
                ) from exc
            if len(self._key) != 32:
                raise ProxyStoreError(
                    "PROXY_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes."
                )
            self._cipher = AESGCM(self._key)
        else:
            self._key = None
            self._cipher = None

    def encrypt(self, service_name: str, secret: str) -> bytes:
        if self.use_kms:
            try:
                import boto3
                kms = boto3.client("kms")
                res = kms.encrypt(
                    KeyId=self.kms_key_id,
                    Plaintext=secret.encode("utf-8"),
                    EncryptionContext={"service": service_name},
                )
                return bytes([2]) + res["CiphertextBlob"]
            except Exception as exc:
                logger.warning("AWS KMS encrypt failed (%s); falling back to AESGCM", exc)

        if not self._cipher:
            raise ProxyStoreError("No encryption cipher initialized.")
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._cipher.encrypt(
            nonce,
            secret.encode("utf-8"),
            service_name.encode("utf-8"),
        )
        return bytes([_CIPHER_VERSION]) + nonce + ciphertext

    def decrypt(self, service_name: str, envelope: bytes) -> str:
        if not envelope:
            raise ProxyStoreError(f"Missing encrypted secret payload for {service_name}.")
        version = envelope[0]

        if version == 2 and self.use_kms:
            try:
                import boto3
                kms = boto3.client("kms")
                res = kms.decrypt(
                    CiphertextBlob=envelope[1:],
                    EncryptionContext={"service": service_name},
                )
                return res["Plaintext"].decode("utf-8")
            except Exception as exc:
                logger.warning("AWS KMS decrypt failed (%s); attempting AESGCM fallback", exc)

        if not self._cipher:
            raise ProxyStoreError("No encryption cipher initialized.")
        if version != _CIPHER_VERSION:
            raise ProxyStoreError(f"Unsupported encrypted secret format for {service_name}.")

        nonce = envelope[1 : 1 + _NONCE_BYTES]
        ciphertext = envelope[1 + _NONCE_BYTES :]
        if len(nonce) != _NONCE_BYTES or not ciphertext:
            raise ProxyStoreError(f"Invalid encrypted secret payload for {service_name}.")
        try:
            plaintext = self._cipher.decrypt(
                nonce,
                ciphertext,
                service_name.encode("utf-8"),
            )
            return plaintext.decode("utf-8")
        except InvalidTag as exc:
            raise ProxyStoreError(
                f"Could not decrypt API key for {service_name}. Check PROXY_SECRET_ENCRYPTION_KEY."
            ) from exc


def _json_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProxyStoreError("Stored proxy configuration contains an invalid list value.")
    return value


class PostgresProxyStore:
    """Async PostgreSQL repository for proxy services, roles, and audit trail."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        encryption_key: str,
        kms_key_id: str | None = None,
    ) -> None:
        if not password:
            raise ProxyStoreError("PROXY_DB_PASSWORD is required.")
        self._connection_options = {
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password,
        }
        self.encryption_key = encryption_key
        self._cipher = _SecretCipher(encryption_key, kms_key_id=kms_key_id)
        self._pool: asyncpg.Pool | None = None
        self._quarantined_ips: set[str] = set()

    @classmethod
    def from_environment(cls) -> "PostgresProxyStore":
        try:
            port = int(os.environ.get("PROXY_DB_PORT", "5432"))
        except ValueError as exc:
            raise ProxyStoreError("PROXY_DB_PORT must be an integer.") from exc
        return cls(
            host=os.environ.get("PROXY_DB_HOST", "127.0.0.1"),
            port=port,
            database=os.environ.get("PROXY_DB_NAME", "centralwatch"),
            user=os.environ.get("PROXY_DB_USER", "centralwatch"),
            password=os.environ.get("PROXY_DB_PASSWORD", ""),
            encryption_key=os.environ.get("PROXY_SECRET_ENCRYPTION_KEY", ""),
            kms_key_id=os.environ.get("AWS_KMS_KEY_ID"),
        )

    @property
    def _active_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ProxyStoreError("The proxy configuration database is not connected.")
        return self._pool

    async def start(
        self,
        default_services: dict[str, dict[str, Any]],
        default_roles: dict[str, dict[str, Any]],
    ) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            **self._connection_options,
            min_size=2,
            max_size=10,
            command_timeout=15.0,
        )
        async with self._active_pool.acquire() as connection:
            async with connection.transaction():
                # 1. Roles table
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_roles (
                        role_name TEXT PRIMARY KEY,
                        allowed_services JSONB NOT NULL,
                        allowed_methods JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                # 2. Services table
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_services (
                        service_name TEXT PRIMARY KEY,
                        base_url TEXT NOT NULL,
                        encrypted_api_key BYTEA NOT NULL,
                        allowed_ips JSONB NOT NULL,
                        role_name TEXT NOT NULL REFERENCES proxy_roles(role_name),
                        token_hash TEXT NOT NULL,
                        token_hint TEXT NOT NULL,
                        auth_type TEXT NOT NULL,
                        timeout_seconds DOUBLE PRECISION NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                # Schema migrations for production columns
                await connection.execute(
                    """
                    ALTER TABLE proxy_services ADD COLUMN IF NOT EXISTS encrypted_api_key_secondary BYTEA;
                    ALTER TABLE proxy_services ADD COLUMN IF NOT EXISTS rate_limit_rpm INT DEFAULT 120;
                    ALTER TABLE proxy_services ADD COLUMN IF NOT EXISTS monthly_budget_usd NUMERIC(10, 2) DEFAULT 100.00;
                    ALTER TABLE proxy_services ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
                    ALTER TABLE proxy_services ADD COLUMN IF NOT EXISTS encrypted_token BYTEA;
                    ALTER TABLE proxy_roles ADD COLUMN IF NOT EXISTS encrypted_token BYTEA;
                    ALTER TABLE proxy_roles ADD COLUMN IF NOT EXISTS token_hash TEXT;
                    ALTER TABLE proxy_roles ADD COLUMN IF NOT EXISTS token_hint TEXT;
                    """
                )
                # 3. Tamper-evident Audit Logs
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_audit_logs (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        action TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        actor_email TEXT,
                        client_ip TEXT,
                        service_name TEXT,
                        details JSONB NOT NULL,
                        signature TEXT NOT NULL
                    )
                    """
                )
                # 4. Persistent Proxy Usage History
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_usage_history (
                        request_id TEXT PRIMARY KEY,
                        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        service_name TEXT NOT NULL,
                        method TEXT NOT NULL,
                        path TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        token_hint TEXT,
                        role_name TEXT,
                        status_code INT NOT NULL,
                        outcome TEXT NOT NULL,
                        duration_ms DOUBLE PRECISION NOT NULL,
                        bytes_in INT DEFAULT 0,
                        bytes_out INT DEFAULT 0,
                        tokens_used INT DEFAULT 0,
                        estimated_cost_usd DOUBLE PRECISION DEFAULT 0.0
                    )
                    """
                )
                # 5. Quarantined IPs table
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proxy_quarantined_ips (
                        ip_address TEXT PRIMARY KEY,
                        reason TEXT NOT NULL,
                        blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        blocked_by TEXT NOT NULL DEFAULT 'firewall_auto_defense',
                        attempts INT DEFAULT 1,
                        status TEXT NOT NULL DEFAULT 'BLOCKED'
                    )
                    """
                )

                quarantine_rows = await connection.fetch("SELECT ip_address FROM proxy_quarantined_ips WHERE status = 'BLOCKED'")
                self._quarantined_ips = {r["ip_address"] for r in quarantine_rows}

                for role_name, role in default_roles.items():
                    access_token = f"cw_role_{secrets.token_urlsafe(24)}"
                    encrypted = self._cipher.encrypt(f"role:{role_name}", access_token)
                    token_hash = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
                    token_hint = f"...{access_token[-6:]}"
                    await connection.execute(
                        """
                        INSERT INTO proxy_roles (role_name, allowed_services, allowed_methods, encrypted_token, token_hash, token_hint)
                        VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, $6)
                        ON CONFLICT (role_name) DO UPDATE SET
                            encrypted_token = COALESCE(proxy_roles.encrypted_token, EXCLUDED.encrypted_token),
                            token_hash = COALESCE(proxy_roles.token_hash, EXCLUDED.token_hash),
                            token_hint = COALESCE(proxy_roles.token_hint, EXCLUDED.token_hint)
                        """,
                        role_name,
                        json.dumps(role["allowed_services"]),
                        json.dumps(role["allowed_methods"]),
                        encrypted,
                        token_hash,
                        token_hint,
                    )
                for service_name, service in default_services.items():
                    encrypted = self._cipher.encrypt(service_name, service["api_key"])
                    await connection.execute(
                        """
                        INSERT INTO proxy_services (
                            service_name, base_url, encrypted_api_key, allowed_ips,
                            role_name, token_hash, token_hint, auth_type, timeout_seconds
                        ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
                        ON CONFLICT (service_name) DO NOTHING
                        """,
                        service_name,
                        service["base_url"],
                        encrypted,
                        json.dumps(service["allowed_ips"]),
                        service["role_name"],
                        service["token_hash"],
                        service["token_hint"],
                        service.get("auth_type", "bearer"),
                        float(service.get("timeout_seconds", 10.0)),
                    )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def ping(self) -> None:
        await self._active_pool.fetchval("SELECT 1")

    # ----------------------------------------------------------------------- Services
    async def list_services(self) -> list[dict[str, Any]]:
        rows = await self._active_pool.fetch(
            """
            SELECT service_name, base_url, encrypted_api_key, encrypted_api_key_secondary,
                   allowed_ips, role_name, token_hash, token_hint, auth_type, timeout_seconds,
                   rate_limit_rpm, monthly_budget_usd, token_expires_at
            FROM proxy_services
            ORDER BY service_name
            """
        )
        return [self._service_from_row(row) for row in rows]

    async def get_service(self, service_name: str) -> dict[str, Any] | None:
        row = await self._active_pool.fetchrow(
            """
            SELECT service_name, base_url, encrypted_api_key, encrypted_api_key_secondary,
                   allowed_ips, role_name, token_hash, token_hint, auth_type, timeout_seconds,
                   rate_limit_rpm, monthly_budget_usd, token_expires_at, encrypted_token
            FROM proxy_services
            WHERE service_name = $1
            """,
            service_name,
        )
        return self._service_from_row(row) if row else None

    def _service_from_row(self, row: asyncpg.Record) -> dict[str, Any]:
        service_name = row["service_name"]
        primary_key = self._cipher.decrypt(service_name, bytes(row["encrypted_api_key"]))
        secondary_key = None
        if row.get("encrypted_api_key_secondary"):
            try:
                secondary_key = self._cipher.decrypt(service_name, bytes(row["encrypted_api_key_secondary"]))
            except Exception:
                secondary_key = None

        return {
            "service_name": service_name,
            "base_url": row["base_url"],
            "api_key": primary_key,
            "api_key_secondary": secondary_key,
            "allowed_ips": _json_list(row["allowed_ips"]),
            "role_name": row["role_name"],
            "token_hash": row["token_hash"],
            "token_hint": row["token_hint"],
            "auth_type": row["auth_type"],
            "timeout_seconds": float(row["timeout_seconds"]),
            "rate_limit_rpm": row.get("rate_limit_rpm") or 120,
            "monthly_budget_usd": float(row.get("monthly_budget_usd") or 100.0),
            "token_expires_at": row.get("token_expires_at"),
            "encrypted_token": bytes(row["encrypted_token"]) if row.get("encrypted_token") else None,
        }

    def encrypt_role_token(self, role_name: str, token: str) -> bytes:
        return self._cipher.encrypt(f"role:{role_name}", token)

    def decrypt_role_token(self, role_name: str, envelope: bytes) -> str:
        return self._cipher.decrypt(f"role:{role_name}", envelope)

    def encrypt_service_token(self, service_name: str, token: str) -> bytes:
        return self._cipher.encrypt(f"token:{service_name}", token)

    def decrypt_service_token(self, service_name: str, envelope: bytes) -> str:
        return self._cipher.decrypt(f"token:{service_name}", envelope)

    async def upsert_service(self, service: dict[str, Any]) -> None:
        service_name = service["service_name"]
        encrypted = self._cipher.encrypt(service_name, service["api_key"])
        encrypted_secondary = None
        if service.get("api_key_secondary"):
            encrypted_secondary = self._cipher.encrypt(service_name, service["api_key_secondary"])

        encrypted_token = service.get("encrypted_token")
        if not encrypted_token and service.get("raw_token"):
            encrypted_token = self.encrypt_service_token(service_name, service["raw_token"])

        await self._active_pool.execute(
            """
            INSERT INTO proxy_services (
                service_name, base_url, encrypted_api_key, encrypted_api_key_secondary,
                allowed_ips, role_name, token_hash, token_hint, auth_type, timeout_seconds,
                rate_limit_rpm, monthly_budget_usd, token_expires_at, encrypted_token
            ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (service_name) DO UPDATE SET
                base_url = EXCLUDED.base_url,
                encrypted_api_key = EXCLUDED.encrypted_api_key,
                encrypted_api_key_secondary = EXCLUDED.encrypted_api_key_secondary,
                allowed_ips = EXCLUDED.allowed_ips,
                role_name = EXCLUDED.role_name,
                token_hash = EXCLUDED.token_hash,
                token_hint = EXCLUDED.token_hint,
                auth_type = EXCLUDED.auth_type,
                timeout_seconds = EXCLUDED.timeout_seconds,
                rate_limit_rpm = EXCLUDED.rate_limit_rpm,
                monthly_budget_usd = EXCLUDED.monthly_budget_usd,
                token_expires_at = EXCLUDED.token_expires_at,
                encrypted_token = COALESCE(EXCLUDED.encrypted_token, proxy_services.encrypted_token),
                updated_at = NOW()
            """,
            service_name,
            service["base_url"],
            encrypted,
            encrypted_secondary,
            json.dumps(service["allowed_ips"]),
            service["role_name"],
            service["token_hash"],
            service["token_hint"],
            service.get("auth_type", "bearer"),
            float(service.get("timeout_seconds", 10.0)),
            int(service.get("rate_limit_rpm", 120)),
            float(service.get("monthly_budget_usd", 100.0)),
            service.get("token_expires_at"),
            encrypted_token,
        )

    async def update_service_token(
        self, service_name: str, token_hash: str, token_hint: str, expires_at: datetime | None = None
    ) -> bool:
        result = await self._active_pool.execute(
            """
            UPDATE proxy_services
            SET token_hash = $2, token_hint = $3, token_expires_at = $4, updated_at = NOW()
            WHERE service_name = $1
            """,
            service_name,
            token_hash,
            token_hint,
            expires_at,
        )
        return result == "UPDATE 1"

    # ----------------------------------------------------------------------- Roles
    async def list_roles(self) -> list[dict[str, Any]]:
        rows = await self._active_pool.fetch(
            """
            SELECT role_name, allowed_services, allowed_methods, encrypted_token, token_hash, token_hint
            FROM proxy_roles
            ORDER BY role_name
            """
        )
        return [self._role_from_row(row) for row in rows]

    async def get_role(self, role_name: str) -> dict[str, Any] | None:
        row = await self._active_pool.fetchrow(
            """
            SELECT role_name, allowed_services, allowed_methods, encrypted_token, token_hash, token_hint
            FROM proxy_roles
            WHERE role_name = $1
            """,
            role_name,
        )
        return self._role_from_row(row) if row else None

    async def get_role_by_token_hash(self, token_hash: str) -> dict[str, Any] | None:
        row = await self._active_pool.fetchrow(
            """
            SELECT role_name, allowed_services, allowed_methods, encrypted_token, token_hash, token_hint
            FROM proxy_roles
            WHERE token_hash = $1
            """,
            token_hash,
        )
        return self._role_from_row(row) if row else None

    @staticmethod
    def _role_from_row(row: asyncpg.Record) -> dict[str, Any]:
        return {
            "role_name": row["role_name"],
            "allowed_services": _json_list(row["allowed_services"]),
            "allowed_methods": _json_list(row["allowed_methods"]),
            "encrypted_token": bytes(row["encrypted_token"]) if row.get("encrypted_token") else None,
            "token_hash": row.get("token_hash"),
            "token_hint": row.get("token_hint", "unavailable"),
        }

    async def upsert_role(self, role: dict[str, Any]) -> None:
        encrypted_token = role.get("encrypted_token")
        token_hash = role.get("token_hash")
        token_hint = role.get("token_hint")
        await self._active_pool.execute(
            """
            INSERT INTO proxy_roles (role_name, allowed_services, allowed_methods, encrypted_token, token_hash, token_hint)
            VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, $6)
            ON CONFLICT (role_name) DO UPDATE SET
                allowed_services = EXCLUDED.allowed_services,
                allowed_methods = EXCLUDED.allowed_methods,
                encrypted_token = COALESCE(EXCLUDED.encrypted_token, proxy_roles.encrypted_token),
                token_hash = COALESCE(EXCLUDED.token_hash, proxy_roles.token_hash),
                token_hint = COALESCE(EXCLUDED.token_hint, proxy_roles.token_hint),
                updated_at = NOW()
            """,
            role["role_name"],
            json.dumps(role["allowed_services"]),
            json.dumps(role["allowed_methods"]),
            encrypted_token,
            token_hash,
            token_hint,
        )

    # ----------------------------------------------------------------------- Audit Trail (Tamper-Evident)
    def _sign_audit_entry(self, timestamp_iso: str, action: str, actor_id: str, service_name: str | None, details_json: str) -> str:
        key = self.encryption_key.encode("utf-8") if self.encryption_key else b"centralwatch-audit-default-secret"
        msg = f"{timestamp_iso}|{action}|{actor_id}|{service_name or ''}|{details_json}".encode("utf-8")
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    async def record_audit_log(
        self,
        action: str,
        actor_id: str,
        actor_email: str | None,
        client_ip: str | None,
        service_name: str | None,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        details_json = json.dumps(details, sort_keys=True)
        signature = self._sign_audit_entry(now.isoformat(), action, actor_id, service_name, details_json)

        await self._active_pool.execute(
            """
            INSERT INTO proxy_audit_logs (
                timestamp, action, actor_id, actor_email, client_ip, service_name, details, signature
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
            """,
            now,
            action,
            actor_id,
            actor_email,
            client_ip,
            service_name,
            details_json,
            signature,
        )
        return {
            "timestamp": now.isoformat(),
            "action": action,
            "actor_id": actor_id,
            "service_name": service_name,
            "signature": signature,
        }

    async def list_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self._active_pool.fetch(
            """
            SELECT id, timestamp, action, actor_id, actor_email, client_ip, service_name, details, signature
            FROM proxy_audit_logs
            ORDER BY timestamp DESC
            LIMIT $1
            """,
            limit,
        )
        results = []
        for r in rows:
            ts_iso = r["timestamp"].isoformat()
            details_str = json.dumps(json.loads(r["details"]) if isinstance(r["details"], str) else r["details"], sort_keys=True)
            expected_sig = self._sign_audit_entry(ts_iso, r["action"], r["actor_id"], r["service_name"], details_str)
            tampered = not hmac.compare_digest(expected_sig, r["signature"])
            results.append({
                "id": r["id"],
                "timestamp": ts_iso,
                "action": r["action"],
                "actor_id": r["actor_id"],
                "actor_email": r["actor_email"],
                "client_ip": r["client_ip"],
                "service_name": r["service_name"],
                "details": json.loads(r["details"]) if isinstance(r["details"], str) else r["details"],
                "signature": r["signature"],
                "verified": not tampered,
            })
        return results

    # ----------------------------------------------------------------------- Usage History & Multi-Worker State
    async def record_usage_event(self, record: dict[str, Any]) -> None:
        try:
            await self._active_pool.execute(
                """
                INSERT INTO proxy_usage_history (
                    request_id, timestamp, service_name, method, path, client_ip,
                    token_hint, role_name, status_code, outcome, duration_ms,
                    bytes_in, bytes_out, tokens_used, estimated_cost_usd
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (request_id) DO NOTHING
                """,
                record["request_id"],
                datetime.fromisoformat(record["timestamp"]),
                record["service_name"],
                record["method"],
                record["path"],
                record["client_ip"],
                record.get("token_hint"),
                record.get("role_name"),
                record["status_code"],
                record["outcome"],
                record["duration_ms"],
                record.get("bytes_in", 0),
                record.get("bytes_out", 0),
                record.get("tokens_used", 0),
                record.get("estimated_cost_usd", 0.0),
            )
        except Exception as exc:
            logger.debug("Failed to record persistent usage event: %s", exc)

    async def list_usage_history(
        self, limit: int = 100, service_name: str | None = None, outcome: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM proxy_usage_history"
        conditions = []
        params: list[Any] = []
        if service_name:
            params.append(service_name)
            conditions.append(f"service_name = ${len(params)}")
        if outcome:
            params.append(outcome)
            conditions.append(f"outcome = ${len(params)}")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        params.append(limit)
        query += f" ORDER BY timestamp DESC LIMIT ${len(params)}"

        rows = await self._active_pool.fetch(query, *params)
        return [
            {
                "request_id": r["request_id"],
                "timestamp": r["timestamp"].isoformat(),
                "service_name": r["service_name"],
                "method": r["method"],
                "path": r["path"],
                "client_ip": r["client_ip"],
                "token_hint": r["token_hint"],
                "role_name": r["role_name"],
                "status_code": r["status_code"],
                "outcome": r["outcome"],
                "duration_ms": r["duration_ms"],
                "bytes_in": r["bytes_in"],
                "bytes_out": r["bytes_out"],
                "tokens_used": r["tokens_used"],
                "estimated_cost_usd": r["estimated_cost_usd"],
            }
            for r in rows
        ]

    # ----------------------------------------------------------------------- Key Rotation & Re-encryption
    async def rotate_master_encryption_key(self, new_encoded_key: str) -> int:
        """Re-encrypt all stored credentials with a new master encryption key."""
        new_cipher = _SecretCipher(new_encoded_key)
        re_encrypted = 0
        async with self._active_pool.acquire() as connection:
            async with connection.transaction():
                services = await connection.fetch("SELECT * FROM proxy_services FOR UPDATE")
                for s in services:
                    service_name = s["service_name"]
                    old_primary = self._cipher.decrypt(service_name, bytes(s["encrypted_api_key"]))
                    new_encrypted_primary = new_cipher.encrypt(service_name, old_primary)

                    new_encrypted_secondary = None
                    if s["encrypted_api_key_secondary"]:
                        old_secondary = self._cipher.decrypt(service_name, bytes(s["encrypted_api_key_secondary"]))
                        new_encrypted_secondary = new_cipher.encrypt(service_name, old_secondary)

                    await connection.execute(
                        """
                        UPDATE proxy_services
                        SET encrypted_api_key = $2, encrypted_api_key_secondary = $3, updated_at = NOW()
                        WHERE service_name = $1
                        """,
                        service_name,
                        new_encrypted_primary,
                        new_encrypted_secondary,
                    )
                    re_encrypted += 1

        self.encryption_key = new_encoded_key
        self._cipher = new_cipher
        logger.info("Successfully re-encrypted %d services with rotated master key", re_encrypted)
        return re_encrypted

    # ----------------------------------------------------------------------- Quarantined IPs
    def is_ip_quarantined(self, ip_address: str) -> bool:
        return ip_address in self._quarantined_ips

    async def quarantine_ip(
        self,
        ip_address: str,
        reason: str = "Repeated security violations",
        blocked_by: str = "firewall_auto_defense",
        attempts: int = 1,
    ) -> dict[str, Any]:
        async with self._active_pool.acquire() as connection:
            await connection.execute(
                """
                INSERT INTO proxy_quarantined_ips (ip_address, reason, blocked_at, blocked_by, attempts, status)
                VALUES ($1, $2, NOW(), $3, $4, 'BLOCKED')
                ON CONFLICT (ip_address) DO UPDATE SET
                    attempts = proxy_quarantined_ips.attempts + EXCLUDED.attempts,
                    blocked_at = NOW(),
                    reason = EXCLUDED.reason,
                    status = 'BLOCKED'
                """,
                ip_address,
                reason,
                blocked_by,
                attempts,
            )
        self._quarantined_ips.add(ip_address)
        logger.warning("IP %s quarantined by %s (reason: %s)", ip_address, blocked_by, reason)
        return {
            "ip_address": ip_address,
            "reason": reason,
            "blocked_by": blocked_by,
            "status": "BLOCKED",
        }

    async def unblock_ip(self, ip_address: str) -> bool:
        async with self._active_pool.acquire() as connection:
            result = await connection.execute(
                "DELETE FROM proxy_quarantined_ips WHERE ip_address = $1",
                ip_address,
            )
        self._quarantined_ips.discard(ip_address)
        logger.info("IP %s unblocked by administrator", ip_address)
        return result.endswith("1")

    async def list_quarantined_ips(self) -> list[dict[str, Any]]:
        async with self._active_pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT ip_address, reason, blocked_at, blocked_by, attempts, status
                FROM proxy_quarantined_ips
                ORDER BY blocked_at DESC
                """
            )
        return [
            {
                "ip_address": r["ip_address"],
                "reason": r["reason"],
                "blocked_at": r["blocked_at"].isoformat(),
                "blocked_by": r["blocked_by"],
                "attempts": r["attempts"],
                "status": r["status"],
            }
            for r in rows
        ]
