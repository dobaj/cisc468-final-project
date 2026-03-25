import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto.identity import Identity
from crypto.key_exchange import KeyExchange
from crypto.session_cipher import SessionCipher
from sharing.file_manager import FileManager
from storage.encrypted_store import EncryptedStore
from trust.key_migration import create_migration_message, verify_migration
from trust.trust_store import TrustStore


class SecurityCoreTests(unittest.TestCase):
    def test_identity_persists_across_reloads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Identity("Alice", "correct horse", base_dir=temp_dir).load_or_create()
            second = Identity("Alice", "correct horse", base_dir=temp_dir).load_or_create()

            self.assertEqual(first.public_key_hex(), second.public_key_hex())
            self.assertEqual(first.fingerprint(), second.fingerprint())

    def test_key_exchange_produces_shared_secret_and_fresh_ephemeral_keys(self):
        alice_first = KeyExchange()
        bob_first = KeyExchange()
        alice_second = KeyExchange()

        secret_one = alice_first.compute_shared_secret(bob_first.get_public_bytes())
        secret_two = bob_first.compute_shared_secret(alice_first.get_public_bytes())

        self.assertEqual(secret_one, secret_two)
        self.assertNotEqual(
            alice_first.get_public_bytes(),
            alice_second.get_public_bytes(),
        )

    def test_session_cipher_detects_tampering(self):
        cipher = SessionCipher(b"\x01" * 32)
        nonce, ciphertext = cipher.encrypt(b"secret payload")

        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01

        with self.assertRaises(Exception):
            cipher.decrypt(nonce, bytes(tampered))

    def test_encrypted_store_encrypts_at_rest_and_rejects_wrong_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EncryptedStore(temp_dir, "hunter2")
            store.save_bytes("vault.bin", b"classified")

            raw = Path(temp_dir, "vault.bin").read_bytes()
            self.assertNotIn(b"classified", raw)
            self.assertEqual(store.load_bytes("vault.bin"), b"classified")

            wrong_store = EncryptedStore(temp_dir, "wrong-password")
            with self.assertRaises(InvalidTag):
                wrong_store.load_bytes("vault.bin")

    def test_signed_file_record_allows_cached_copy_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            owner = Identity("Alice", "pw", base_dir=temp_dir).load_or_create()
            owner_dir = Path(temp_dir, "shared_owner")
            relay_dir = Path(temp_dir, "relay_cache")

            owner_manager = FileManager(str(owner_dir))
            relay_manager = FileManager(str(relay_dir))

            owner_manager.save_file("notes.txt", b"hello peer")
            data, record = owner_manager.get_shared_file("notes.txt", owner)
            relay_manager.save_verified_file("notes.txt", data, record)

            cached_data, cached_record = relay_manager.get_shared_file("notes.txt", owner)
            self.assertEqual(cached_data, b"hello peer")
            self.assertEqual(cached_record["owner"], "Alice")

    def test_relayed_file_list_preserves_original_owner_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            owner = Identity("Alice", "pw", base_dir=temp_dir).load_or_create()
            relay = Identity("Carol", "pw", base_dir=temp_dir).load_or_create()
            owner_dir = Path(temp_dir, "shared_owner")
            relay_dir = Path(temp_dir, "relay_cache")

            owner_manager = FileManager(str(owner_dir))
            relay_manager = FileManager(str(relay_dir))

            owner_manager.save_file("notes.txt", b"hello peer")
            data, original_record = owner_manager.get_shared_file("notes.txt", owner)
            relay_manager.save_verified_file("notes.txt", data, original_record)

            listed_records = relay_manager.list_file_records(relay)

            self.assertEqual(len(listed_records), 1)
            self.assertEqual(listed_records[0], original_record)
            self.assertEqual(listed_records[0]["owner"], "Alice")
            self.assertEqual(listed_records[0]["owner_pub"], owner.public_key_hex())
            self.assertNotEqual(listed_records[0]["owner_pub"], relay.public_key_hex())

    def test_signed_file_record_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            owner = Identity("Alice", "pw", base_dir=temp_dir).load_or_create()
            manager = FileManager(str(Path(temp_dir, "shared")))

            manager.save_file("notes.txt", b"hello peer")
            _, record = manager.get_shared_file("notes.txt", owner)

            with self.assertRaises(ValueError):
                manager.save_verified_file("notes.txt", b"tampered", record)

    def test_trust_store_rotates_contact_keys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = TrustStore(str(Path(temp_dir, "trust.json")))
            store.add_contact("Bob", "old-fingerprint")
            store.rotate_contact_key("Bob", "new-fingerprint")

            self.assertTrue(store.is_trusted("Bob", "new-fingerprint"))
            self.assertIn("old-fingerprint", store.trusted["Bob"]["previous_fingerprints"])

    def test_key_migration_message_verifies(self):
        old_private = Ed25519PrivateKey.generate()
        new_private = Ed25519PrivateKey.generate()
        new_public_hex = new_private.public_key().public_bytes_raw().hex()

        message = create_migration_message(old_private, new_private, new_public_hex)
        verified = verify_migration(
            old_private.public_key(),
            new_private.public_key(),
            bytes.fromhex(message["old_sig"]),
            bytes.fromhex(message["new_sig"]),
        )

        self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
