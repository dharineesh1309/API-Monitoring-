"""Persistent PostgreSQL storage for CentralWatch proxy configuration.

The database never receives a plaintext upstream API key. Secrets are encrypted
in the application with AES-256-GCM before they are written, and the service ID
is authenticated as associated data so encrypted values cannot be swapped
between service records unnoticed.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import asyncpg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_CIPHER_VERSION = 1
_NONCE_BYTES = 12


class ProxyStoreError(RuntimeError):
    """Raised when proxy configuration storage cannot be used safely."""


class _SecretCipher:
    """Small versioned envelope for encrypting managed upstream secrets."""

    def __init__(self, encoded_key: str) -> None:
        if not encoded_key:
            raise ProxyStoreError("PROXY_SECRET_ENCRYPTION_KEY is required.")
        try:
            key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ProxyStoreError(
                "PROXY_SECRET_ENCRYPTION_KEY must be a URL-safe base64 value."
            ) from exc
        if len(key) != 32:
            raise ProxyStoreError(
                "PROXY_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes."
            )
        self._cipher = AESGCM(key)

    def encrypt(self, service_name: str, secret: str) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._cipher.encrypt(
            nonce,
            secret.encode("utf-8"),
            service_name.encode("utf-8"),
        )
        return bytes([_CIPHER_VERSION]) + nonce + ciphertext

    def decrypt(self, service_name: str, envelope: bytes) -> str:
        if not envelope or envelope[0] != _CIPHER_VERSION:
            raise ProxyStoreError(
                f"Unsupported encrypted secret format for proxy service {service_name}."
            )
        nonce = envelope[1 : 1 + _NONCE_BYTES]
        ciphertext = envelope[1 + _NONCE_BYTES :]
        if len(nonce) != _NONCE_BYTES or not ciphertext:
            raise ProxyStoreError(
                f"Invalid encrypted secret payload for proxy service {service_name}."
            )
        try:
            plaintext = self._cipher.decrypt(
                nonce,
                ciphertext,
                service_name.encode("utf-8"),
            )
        except InvalidTag as exc:
            raise ProxyStoreError(
                f"Could not decrypt the API key for proxy service {service_name}. "
                "Check PROXY_SECRET_ENCRYPTION_KEY."
            ) from exc
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProxyStoreError(
                f"The decrypted API key for proxy service {service_name} is invalid."
            ) from exc


def _json_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProxyStoreError("Stored proxy configuration contains an invalid list value.")
    return value


class PostgresProxyStore:
    """Async PostgreSQL repository for proxy services and roles."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        encryption_key: str,
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
        self._cipher = _SecretCipher(encryption_key)
        self._pool: asyncpg.Pool | None = None

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
        self._pool = await asyncpg.create_pool(
            **self._connection_options,
            min_size=1,
            max_size=5,
            command_timeout=10,
        )
        async with self._active_pool.acquire() as connection:
            async with connection.transaction():
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
                for role_name, role in default_roles.items():
                    await connection.execute(
                        """
                        INSERT INTO proxy_roles (role_name, allowed_services, allowed_methods)
                        VALUES ($1, $2::jsonb, $3::jsonb)
                        ON CONFLICT (role_name) DO NOTHING
                        """,
                        role_name,
                        json.dumps(role["allowed_services"]),
                        json.dumps(role["allowed_methods"]),
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

    async def list_services(self) -> list[dict[str, Any]]:
        rows = await self._active_pool.fetch(
            """
            SELECT service_name, base_url, encrypted_api_key, allowed_ips,
                   role_name, token_hash, token_hint, auth_type, timeout_seconds
            FROM proxy_services
            ORDER BY service_name
            """
        )
        return [self._service_from_row(row) for row in rows]

    async def get_service(self, service_name: str) -> dict[str, Any] | None:
        row = await self._active_pool.fetchrow(
            """
            SELECT service_name, base_url, encrypted_api_key, allowed_ips,
                   role_name, token_hash, token_hint, auth_type, timeout_seconds
            FROM proxy_services
            WHERE service_name = $1
            """,
            service_name,
        )
        return self._service_from_row(row) if row else None

    def _service_from_row(self, row: asyncpg.Record) -> dict[str, Any]:
        service_name = row["service_name"]
        return {
            "service_name": service_name,
            "base_url": row["base_url"],
            "api_key": self._cipher.decrypt(service_name, bytes(row["encrypted_api_key"])),
            "allowed_ips": _json_list(row["allowed_ips"]),
            "role_name": row["role_name"],
            "token_hash": row["token_hash"],
            "token_hint": row["token_hint"],
            "auth_type": row["auth_type"],
            "timeout_seconds": float(row["timeout_seconds"]),
        }

    async def upsert_service(self, service: dict[str, Any]) -> None:
        service_name = service["service_name"]
        encrypted = self._cipher.encrypt(service_name, service["api_key"])
        await self._active_pool.execute(
            """
            INSERT INTO proxy_services (
                service_name, base_url, encrypted_api_key, allowed_ips,
                role_name, token_hash, token_hint, auth_type, timeout_seconds
            ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
            ON CONFLICT (service_name) DO UPDATE SET
                base_url = EXCLUDED.base_url,
                encrypted_api_key = EXCLUDED.encrypted_api_key,
                allowed_ips = EXCLUDED.allowed_ips,
                role_name = EXCLUDED.role_name,
                token_hash = EXCLUDED.token_hash,
                token_hint = EXCLUDED.token_hint,
                auth_type = EXCLUDED.auth_type,
                timeout_seconds = EXCLUDED.timeout_seconds,
                updated_at = NOW()
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

    async def update_service_token(self, service_name: str, token_hash: str, token_hint: str) -> bool:
        result = await self._active_pool.execute(
            """
            UPDATE proxy_services
            SET token_hash = $2, token_hint = $3, updated_at = NOW()
            WHERE service_name = $1
            """,
            service_name,
            token_hash,
            token_hint,
        )
        return result == "UPDATE 1"

    async def list_roles(self) -> list[dict[str, Any]]:
        rows = await self._active_pool.fetch(
            """
            SELECT role_name, allowed_services, allowed_methods
            FROM proxy_roles
            ORDER BY role_name
            """
        )
        return [self._role_from_row(row) for row in rows]

    async def get_role(self, role_name: str) -> dict[str, Any] | None:
        row = await self._active_pool.fetchrow(
            """
            SELECT role_name, allowed_services, allowed_methods
            FROM proxy_roles
            WHERE role_name = $1
            """,
            role_name,
        )
        return self._role_from_row(row) if row else None

    @staticmethod
    def _role_from_row(row: asyncpg.Record) -> dict[str, Any]:
        return {
            "role_name": row["role_name"],
            "allowed_services": _json_list(row["allowed_services"]),
            "allowed_methods": _json_list(row["allowed_methods"]),
        }

    async def upsert_role(self, role: dict[str, Any]) -> None:
        await self._active_pool.execute(
            """
            INSERT INTO proxy_roles (role_name, allowed_services, allowed_methods)
            VALUES ($1, $2::jsonb, $3::jsonb)
            ON CONFLICT (role_name) DO UPDATE SET
                allowed_services = EXCLUDED.allowed_services,
                allowed_methods = EXCLUDED.allowed_methods,
                updated_at = NOW()
            """,
            role["role_name"],
            json.dumps(role["allowed_services"]),
            json.dumps(role["allowed_methods"]),
        )
