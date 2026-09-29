"""Unit Test Otomatis untuk Modul Penandatanganan Berkas Gambar (generic_signer.py)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi

Menguji skema *Embedded Signature* untuk berkas gambar (PNG, JPG, WEBP, dsb.),
melengkapi ketentuan pedoman: "tanda tangan atas nilai hash SHA-256 dari berkas
PDF atau berkas lain".
"""

import unittest

from crypto_engine import generate_keypair, export_public_key_pem
from generic_signer import (
    sign_generic_file,
    verify_generic_file,
    extract_signature_block,
    GENERIC_MARKER_START,
    GENERIC_MARKER_END,
    MARKER_PREFIX,
)


class TestGenericSigner(unittest.TestCase):
    """Kumpulan pengujian unit untuk penandatanganan berkas gambar (embedded signature)."""

    def setUp(self):
        """Inisialisasi pasangan kunci dan berkas gambar contoh."""
        self.priv_key, self.pub_key = generate_keypair()
        self.pub_pem = export_public_key_pem(self.pub_key)
        # Simulasi berkas PNG (header + data + penanda akhir IEND)
        self.png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200 + b"IEND\xaeB`\x82"
        self.png_name = "foto_ujian.png"

    def _sign(self, data=None):
        return sign_generic_file(
            file_bytes=data if data is not None else self.png_bytes,
            original_filename=self.png_name,
            private_key=self.priv_key,
            public_key_pem=self.pub_pem,
            signer_name="Fachri Ridhwan Imani",
            signer_id="247006111140",
        )

    def test_01_sign_embeds_block_into_file(self):
        """Uji 1: Blok integritas harus benar-benar tersemat ke dalam berkas gambar."""
        signed_bytes, payload = self._sign()
        self.assertGreater(len(signed_bytes), len(self.png_bytes))
        self.assertIn(GENERIC_MARKER_START, signed_bytes)
        self.assertIn(GENERIC_MARKER_END, signed_bytes)
        self.assertEqual(payload["type"], "embedded-signature")

    def test_02_sign_and_verify_valid(self):
        """Uji 2: Berkas gambar bertanda tangan harus menghasilkan status VALID."""
        signed_bytes, _ = self._sign()
        result = verify_generic_file(signed_bytes)
        self.assertEqual(result["status"], "VALID")
        self.assertTrue(result["valid"])

    def test_03_tamper_one_byte_detection(self):
        """Uji 3: Manipulasi 1 byte pada berkas gambar wajib terdeteksi (TAMPERED)."""
        signed_bytes, _ = self._sign()
        tampered = bytearray(signed_bytes)
        tampered[10] ^= 0xFF  # ubah 1 byte pada area konten gambar
        result = verify_generic_file(bytes(tampered))
        self.assertEqual(result["status"], "TAMPERED")
        self.assertFalse(result["valid"])

    def test_04_wrong_public_key_rejection(self):
        """Uji 4: Verifikasi memakai Public Key orang lain wajib gagal (KEY_MISMATCH)."""
        signed_bytes, _ = self._sign()
        _, another_pub = generate_keypair()
        another_pub_pem = export_public_key_pem(another_pub)
        result = verify_generic_file(signed_bytes, custom_public_key_pem=another_pub_pem)
        self.assertEqual(result["status"], "KEY_MISMATCH")
        self.assertFalse(result["valid"])

    def test_05_unsigned_file_detection(self):
        """Uji 5: Berkas gambar tanpa blok tanda tangan harus terdeteksi sebagai UNSIGNED."""
        result = verify_generic_file(self.png_bytes)
        self.assertEqual(result["status"], "UNSIGNED")
        self.assertFalse(result["valid"])

    def test_06_signature_block_removal_keeps_image(self):
        """Uji 6: Setelah blok dipisahkan, konten gambar (dengan marker) harus tetap valid."""
        signed_bytes, _ = self._sign()
        clean_bytes, payload = extract_signature_block(signed_bytes)
        # Konten gambar harus diawali signature PNG dan tidak memuat blok tanda tangan
        self.assertTrue(clean_bytes.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertNotIn(GENERIC_MARKER_START, clean_bytes)
        self.assertIsNotNone(payload)

    def test_07_multiple_signers_chained(self):
        """Uji 7: Penandatanganan berjenjang pada berkas gambar harus tetap valid seluruhnya."""
        signed_1, _ = self._sign()
        priv_2, pub_2 = generate_keypair()
        signed_2, payload_2 = sign_generic_file(
            file_bytes=signed_1,
            original_filename=self.png_name,
            private_key=priv_2,
            public_key_pem=export_public_key_pem(pub_2),
            signer_name="Wardah Nurwaffiq",
            signer_id="247006111150",
        )
        self.assertEqual(payload_2["total_signers"], 2)
        result = verify_generic_file(signed_2)
        self.assertEqual(result["status"], "VALID")
        self.assertEqual(len(result["signers"]), 2)

    def test_08_sentinel_marker_embedded(self):
        """Uji 8: Sentinel marker harus tersemat ke metadata internal gambar."""
        signed_bytes, _ = self._sign()
        self.assertIn(MARKER_PREFIX, signed_bytes)

    def test_09_rewritten_file_detected_as_tampered(self):
        """Uji 9: Berkas yang pernah ditandatangani tetapi bloknya hilang → TAMPERED."""
        signed_bytes, _ = self._sign()
        # Simulasi: berkas ditulis ulang aplikasi lain → blok hilang, marker tersisa
        rewritten = signed_bytes.split(GENERIC_MARKER_START)[0]
        self.assertIn(MARKER_PREFIX, rewritten)
        result = verify_generic_file(rewritten)
        self.assertEqual(result["status"], "TAMPERED")
        self.assertIsNotNone(result.get("marker_info"))
        self.assertEqual(result["marker_info"]["signer"], "Fachri Ridhwan Imani")

    def test_10_never_signed_still_unsigned(self):
        """Uji 10: Berkas tanpa blok DAN tanpa marker tetap terdeteksi UNSIGNED."""
        plain = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50 + b"IEND\xaeB`\x82"
        result = verify_generic_file(plain)
        self.assertEqual(result["status"], "UNSIGNED")
        self.assertIsNone(result.get("marker_info"))


if __name__ == "__main__":
    unittest.main()
