"""Unit Test Otomatis untuk Modul Inti Kriptografi (crypto_engine.py)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi
Memenuhi Ketentuan Umum Bagian 4: "Sertakan minimal lima unit test untuk fungsi inti"
"""

import os
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from crypto_engine import (
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    hash_bytes,
    hash_file,
    sign_data,
    verify_signature,
    sign_hash,
    verify_hash,
)


class TestCryptoEngine(unittest.TestCase):
    """Kumpulan pengujian unit untuk fungsi-fungsi kriptografi ECDSA P-256 dan SHA-256."""

    def setUp(self):
        """Inisialisasi pasangan kunci untuk setiap pengujian."""
        self.priv_key, self.pub_key = generate_keypair()
        self.sample_data = b"Dokumen Resmi Fakultas Teknik Universitas Siliwangi - UTS KI 20261"

    def test_01_keypair_generation(self):
        """Uji 1: Memastikan pembangkitan kunci menghasilkan kurva NIST P-256 (secp256r1)."""
        self.assertIsInstance(self.priv_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(self.pub_key, ec.EllipticCurvePublicKey)
        self.assertEqual(self.priv_key.curve.name, "secp256r1")
        self.assertEqual(self.pub_key.curve.name, "secp256r1")

    def test_02_private_key_encryption_passphrase(self):
        """Uji 2: Memastikan Private Key dapat dienkripsi dengan passphrase dan didekripsi dengan benar."""
        passphrase = "PasswordKuatMahasiswaUNSIL2026!"
        encrypted_pem = export_private_key_pem(self.priv_key, passphrase=passphrase)
        
        # Header PEM terenkripsi harus menunjukkan format PKCS8 terenkripsi
        self.assertIn(b"ENCRYPTED PRIVATE KEY", encrypted_pem)
        
        # Dekripsi dengan password yang benar harus berhasil
        restored_priv = load_private_key_pem(encrypted_pem, passphrase=passphrase)
        self.assertIsInstance(restored_priv, ec.EllipticCurvePrivateKey)
        
        # Dekripsi dengan password salah wajib menimbulkan ValueError / exception
        with self.assertRaises(ValueError):
            load_private_key_pem(encrypted_pem, passphrase="PasswordSalahTotal")

    def test_03_public_key_export_import(self):
        """Uji 3: Memastikan Public Key dapat diekspor ke PEM dan dimuat ulang secara konsisten."""
        pub_pem = export_public_key_pem(self.pub_key)
        self.assertIn(b"PUBLIC KEY", pub_pem)
        restored_pub = load_public_key_pem(pub_pem)
        self.assertEqual(export_public_key_pem(restored_pub), pub_pem)

    def test_04_sha256_hashing(self):
        """Uji 4: Memastikan fungsi hash SHA-256 menghasilkan digest heksadesimal 64 karakter."""
        digest_hex = hash_bytes(self.sample_data)
        self.assertEqual(len(digest_hex), 64)
        
        # Uji hashing file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(self.sample_data)
            tmp_path = tmp.name
        
        try:
            file_hex, file_bytes = hash_file(tmp_path)
            self.assertEqual(file_hex, digest_hex)
            self.assertEqual(len(file_bytes), 32)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_05_sign_and_verify_valid(self):
        """Uji 5: Memastikan dokumen asli berhasil ditandatangani dan diverifikasi (Status: VALID)."""
        signature_b64 = sign_data(self.priv_key, self.sample_data)
        self.assertIsInstance(signature_b64, str)
        self.assertTrue(len(signature_b64) > 0)
        
        is_valid = verify_signature(self.pub_key, signature_b64, self.sample_data)
        self.assertTrue(is_valid, "Signature pada dokumen asli harus valid!")

    def test_06_tamper_detection(self):
        """Uji 6: Memastikan sistem menolak dokumen bila terdapat manipulasi meski hanya 1 byte (Status: INVALID)."""
        signature_b64 = sign_data(self.priv_key, self.sample_data)
        
        # Manipulasi 1 byte terakhir
        tampered_data = bytearray(self.sample_data)
        tampered_data[-1] ^= 0x01  # Flip 1 bit pada byte terakhir
        
        is_valid = verify_signature(self.pub_key, signature_b64, bytes(tampered_data))
        self.assertFalse(is_valid, "Dokumen yang di-tamper 1 byte wajib ditolak oleh verifier!")

    def test_07_invalid_public_key_rejection(self):
        """Uji 7: Memastikan verifikasi gagal jika menggunakan Public Key penandatangan yang salah."""
        signature_b64 = sign_data(self.priv_key, self.sample_data)
        
        # Buat keypair lain milik orang lain
        _, another_pub_key = generate_keypair()
        
        is_valid = verify_signature(another_pub_key, signature_b64, self.sample_data)
        self.assertFalse(is_valid, "Verifikasi dengan public key orang lain harus gagal!")

    def test_08_prehashed_signing_and_verification(self):
        """Uji 8: Memastikan penandatanganan eksplisit atas nilai digest hash SHA-256 bekerja dengan tepat."""
        _, digest_bytes = hash_file_bytes = (None, bytes.fromhex(hash_bytes(self.sample_data)))
        sig_hash_b64 = sign_hash(self.priv_key, digest_bytes)
        
        is_valid = verify_hash(self.pub_key, sig_hash_b64, digest_bytes)
        self.assertTrue(is_valid, "Verifikasi signature berbasis digest SHA-256 harus valid!")


if __name__ == "__main__":
    unittest.main()
