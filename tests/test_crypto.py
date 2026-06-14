from __future__ import annotations

import unittest

from vaultlog.crypto import decrypt_json, derive_key, encrypt_json


class CryptoTests(unittest.TestCase):
    def test_encrypt_roundtrip(self) -> None:
        key = derive_key("secret", b"0123456789abcdef", 100_000)
        payload = {"hello": "world", "count": 2}
        encrypted = encrypt_json(key, payload)
        self.assertEqual(decrypt_json(key, encrypted), payload)


if __name__ == "__main__":
    unittest.main()
