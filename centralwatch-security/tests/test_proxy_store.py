"""Security-focused tests for encrypted proxy secret storage."""

import base64
import secrets

import pytest

from centralwatch_security.proxy_store import ProxyStoreError, _SecretCipher


def _key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def test_secret_cipher_encrypts_and_authenticates_service_name():
    cipher = _SecretCipher(_key())

    encrypted = cipher.encrypt("billing_api", "upstream-secret-value")

    assert b"upstream-secret-value" not in encrypted
    assert cipher.decrypt("billing_api", encrypted) == "upstream-secret-value"
    with pytest.raises(ProxyStoreError, match="Could not decrypt"):
        cipher.decrypt("different_service", encrypted)


@pytest.mark.parametrize("value", ["", "not-base64", base64.urlsafe_b64encode(b"short").decode()])
def test_secret_cipher_rejects_missing_or_invalid_keys(value):
    with pytest.raises(ProxyStoreError):
        _SecretCipher(value)
