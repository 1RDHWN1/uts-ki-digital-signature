"""Uji Verifikasi QR-Code Mandiri (Fitur B2)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi

Menguji alur: QR-Code berisi URL verifikasi + payload -> pindai -> verifikasi
tanda tangan ECDSA secara mandiri (tanpa mengunggah berkas), termasuk penolakan
QR yang dipalsukan (nama, NPM, institusi, tanggal, hash, dan kunci publik).
"""

import unittest
import io
import hashlib

from pypdf import PdfWriter

from crypto_engine import (
    generate_keypair,
    export_public_key_pem,
    load_public_key_pem,
    export_public_key_compressed_b64,
    sign_hash,
)
from pdf_stamper import (
    sign_and_stamp_pdf,
    build_qr_verification_payload,
    parse_qr_verification_payload,
    qr_signed_digest,
)
from verifier import verify_qr_payload, verify_pdf_document


def _make_signed_context(signer="Fachri Ridhwan Imani", sid="247006111140"):
    """Membuat konteks: PDF bertanda tangan + URL QR + payload terurai."""
    priv, pub = generate_keypair()
    pem = export_public_key_pem(pub)

    w = PdfWriter()
    w.add_blank_page(width=595, height=842)
    b = io.BytesIO(); w.write(b)
    base = b.getvalue()

    signed, meta = sign_and_stamp_pdf(base, priv, pem, signer, sid)
    base_hash = hashlib.sha256(base).hexdigest()
    pub_compact = export_public_key_compressed_b64(load_public_key_pem(pem))
    date_str = meta["signatures"][0]["date"]

    qr_sig = sign_hash(
        priv,
        qr_signed_digest(signer, sid, "Universitas Siliwangi", date_str, base_hash),
    )
    url = build_qr_verification_payload(
        "https://signacerta.udincloud.me", signer, sid,
        "Universitas Siliwangi", date_str, base_hash, qr_sig, pub_compact,
    )
    token = url.split("p=")[1]
    payload = parse_qr_verification_payload(token)
    return {
        "signed": signed, "meta": meta, "url": url, "token": token,
        "payload": payload, "base_hash": base_hash, "priv": priv, "pem": pem,
    }


class TestQrVerification(unittest.TestCase):

    def setUp(self):
        self.ctx = _make_signed_context()

    def test_01_url_memuat_parameter_verifikasi(self):
        """Uji 1: URL QR memuat verify=auto dan parameter payload p."""
        url = self.ctx["url"]
        self.assertIn("verify=auto", url)
        self.assertIn("&p=", url)

    def test_02_payload_dapat_diurai(self):
        """Uji 2: Payload QR dapat diurai kembali menjadi dict identitas."""
        p = self.ctx["payload"]
        self.assertIsInstance(p, dict)
        self.assertEqual(p["signer"], "Fachri Ridhwan Imani")
        self.assertEqual(p["id"], "247006111140")

    def test_03_qr_asli_valid(self):
        """Uji 3: QR asli menghasilkan status VALID_QR."""
        res = verify_qr_payload(self.ctx["payload"])
        self.assertEqual(res["status"], "VALID_QR")
        self.assertTrue(res["valid"])
        self.assertTrue(res.get("public_key_fingerprint"))

    def test_04_tolak_pemalsuan_identitas(self):
        """Uji 4: Mengubah nama/NPM/institusi/tanggal -> SIGNATURE_INVALID."""
        for field, val in [("signer", "Rektor Palsu"), ("id", "000000"),
                           ("inst", "ITB"), ("date", "1999-01-01")]:
            tampered = dict(self.ctx["payload"]); tampered[field] = val
            res = verify_qr_payload(tampered)
            self.assertEqual(res["status"], "SIGNATURE_INVALID",
                             f"Pemalsuan {field} harus ditolak")

    def test_05_tolak_pemalsuan_hash(self):
        """Uji 5: Mengubah hash dokumen -> SIGNATURE_INVALID."""
        tampered = dict(self.ctx["payload"]); tampered["hash"] = "00" * 32
        self.assertEqual(verify_qr_payload(tampered)["status"], "SIGNATURE_INVALID")

    def test_06_tolak_kunci_publik_penyerang(self):
        """Uji 6: Mengganti kunci publik dengan milik penyerang -> SIGNATURE_INVALID."""
        _, attacker_pub = generate_keypair()
        tampered = dict(self.ctx["payload"])
        tampered["pub"] = export_public_key_compressed_b64(attacker_pub)
        self.assertEqual(verify_qr_payload(tampered)["status"], "SIGNATURE_INVALID")

    def test_07_payload_tidak_lengkap(self):
        """Uji 7: Payload kosong/rusak -> INVALID_QR (bukan crash)."""
        self.assertEqual(verify_qr_payload({})["status"], "INVALID_QR")
        self.assertEqual(verify_qr_payload({"signer": "x"})["status"], "INVALID_QR")
        self.assertEqual(verify_qr_payload(None)["status"], "INVALID_QR")

    def test_08_fingerprint_stabil(self):
        """Uji 8: Fingerprint kunci publik konsisten antar verifikasi."""
        r1 = verify_qr_payload(self.ctx["payload"])
        r2 = verify_qr_payload(self.ctx["payload"])
        self.assertEqual(r1["public_key_fingerprint"], r2["public_key_fingerprint"])

    def test_09_pdf_tetap_valid_setelah_refactor(self):
        """Uji 9: Blok integritas PDF tetap VALID setelah penambahan fitur QR."""
        self.assertEqual(verify_pdf_document(self.ctx["signed"])["status"], "VALID")

    def test_10_hash_qr_cocok_dengan_dokumen(self):
        """Uji 10: Hash dokumen di QR identik dengan hash dokumen asli."""
        self.assertEqual(self.ctx["payload"]["hash"], self.ctx["base_hash"])

    def test_11_pdf_multi_signer_custom_public_key(self):
        """Uji 11: PDF multi-signer diuji dengan public key salah satu pihak harus VALID."""
        # Tambah tanda tangan pihak kedua di atas dokumen yang sudah ada
        priv_2, pub_2 = generate_keypair()
        pub_2_pem = export_public_key_pem(pub_2)
        signed_2, _ = sign_and_stamp_pdf(
            input_pdf_bytes=self.ctx["signed"],
            private_key=priv_2,
            public_key_pem=pub_2_pem,
            signer_name="Wardah Nurwaffiq",
            signer_id="247006111150",
            position="bottom-left",
        )

        # Uji dengan kunci Pihak 1 (milik self.ctx)
        res_key1 = verify_pdf_document(signed_2, custom_public_key_pem=self.ctx["pem"])
        self.assertEqual(res_key1["status"], "VALID")
        self.assertTrue(res_key1["valid"])
        self.assertTrue(res_key1["signers"][0]["matched_custom_key"])
        self.assertFalse(res_key1["signers"][1]["matched_custom_key"])

        # Uji dengan kunci Pihak 2 (Wardah)
        res_key2 = verify_pdf_document(signed_2, custom_public_key_pem=pub_2_pem)
        self.assertEqual(res_key2["status"], "VALID")
        self.assertTrue(res_key2["valid"])
        self.assertFalse(res_key2["signers"][0]["matched_custom_key"])
        self.assertTrue(res_key2["signers"][1]["matched_custom_key"])

        # Uji dengan kunci penyerang asing
        _, alien_pub = generate_keypair()
        res_alien = verify_pdf_document(signed_2, custom_public_key_pem=export_public_key_pem(alien_pub))
        self.assertEqual(res_alien["status"], "KEY_MISMATCH")
        self.assertFalse(res_alien["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
