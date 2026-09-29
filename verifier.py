"""Modul Verifikasi Dokumen & Integritas Kriptografi (Verifier Engine)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi
Bagian: Mahardika Rajbi Firdaus & Fachri Ridhwan Imani

Fitur:
- Ekstraksi blok integritas tanda tangan digital dari berkas PDF.
- Validasi integritas berkas (deteksi manipulasi bahkan 1 byte).
- Validasi kriptografis tanda tangan digital dengan Public Key ECDSA NIST P-256.
- Validasi terhadap Kunci Publik eksternal / penandatangan lain (deteksi pemalsuan).
- Mendukung verifikasi multiple signatures (tanda tangan berjenjang).
"""

import io
import json
import hashlib
from typing import Dict, Any, Optional, Tuple

from pypdf import PdfReader

from crypto_engine import (
    load_public_key_pem,
    verify_hash,
)
from pdf_stamper import SIG_MARKER_START, SIG_MARKER_END


def extract_signature_block(pdf_bytes: bytes) -> Tuple[bytes, Optional[Dict[str, Any]]]:
    """Mengekstrak berkas visual PDF dan metadata blok integritas kriptografi."""
    if SIG_MARKER_START not in pdf_bytes or SIG_MARKER_END not in pdf_bytes:
        return pdf_bytes, None

    parts = pdf_bytes.split(SIG_MARKER_START)
    clean_bytes = parts[0]
    
    sub = parts[1].split(SIG_MARKER_END)
    meta_json_str = sub[0].decode("utf-8", errors="replace")
    
    try:
        metadata = json.loads(meta_json_str)
        return clean_bytes, metadata
    except Exception:
        return clean_bytes, None


def _read_pdf_marker(pdf_bytes: bytes) -> Optional[Dict[str, str]]:
    """Membaca sentinel marker SignaCerta dari dokumen PDF (bila ada).

    Marker dicari pada dua tempat:
    1. Content stream halaman (bertahan walau dokumen ditulis ulang / dikompres).
    2. Metadata DocInfo (sebagai cadangan).

    Marker ini adalah jejak non-kriptografis yang ditulis saat penandatanganan,
    sehingga dokumen yang pernah ditandatangani lalu ditulis ulang (mis. dikompres)
    masih dapat dikenali walaupun blok integritasnya sudah hilang.
    """
    def _parse(raw: str) -> Optional[Dict[str, str]]:
        idx = raw.find("SignaCerta-Sig:")
        if idx == -1:
            return None
        payload = raw[idx + len("SignaCerta-Sig:"):]
        # Ambil hanya sampai karakter yang jelas akhir penanda (baris baru / kutip / kurung).
        for stop in ("\n", "\r", ")", "]", "'", '"', "\\"):
            p = payload.find(stop)
            if p != -1:
                payload = payload[:p]
        parts = payload.split("|")
        return {
            "signer": parts[0].strip() if len(parts) > 0 and parts[0].strip() else "-",
            "id": parts[1].strip() if len(parts) > 1 else "-",
            "date": parts[2].strip() if len(parts) > 2 else "-",
        }

    # --- 1. Cari pada content stream halaman ---
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        for page in reader.pages:
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            if "SignaCerta-Sig:" in text:
                parsed = _parse(text)
                if parsed:
                    return parsed
    except Exception:
        pass

    # --- 2. Cari pada metadata DocInfo ---
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata or {}
        for k, v in meta.items():
            sv = str(v)
            if "SignaCerta-Sig:" in sv:
                parsed = _parse(sv)
                if parsed:
                    return parsed
    except Exception:
        pass

    return None


def verify_pdf_document(
    pdf_bytes: bytes,
    custom_public_key_pem: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Memverifikasi keaslian dan integritas dokumen PDF secara menyeluruh.
    
    Status Kembalian:
    - VALID: Dokumen 100% asli, hash cocok, dan tanda tangan digital terverifikasi.
    - TAMPERED: Isi dokumen telah diubah setelah penandatanganan (integritas rusak),
      ATAU dokumen pernah ditandatangani tetapi blok integritasnya hilang.
    - KEY_MISMATCH: Tanda tangan gagal diverifikasi dengan Public Key yang diberikan.
    - UNSIGNED: Dokumen belum dibubuhi blok tanda tangan digital.
    - CORRUPTED_METADATA: Blok tanda tangan rusak atau tidak dapat dibaca.
    """
    clean_bytes, metadata = extract_signature_block(pdf_bytes)

    if metadata is None:
        # Blok integritas tidak ada. Periksa sentinel marker pada metadata PDF
        # untuk membedakan dokumen yang belum pernah ditandatangani vs yang
        # pernah ditandatangani lalu ditulis ulang (mis. dikompres).
        marker = _read_pdf_marker(pdf_bytes)
        if marker is not None:
            return {
                "valid": False,
                "status": "TAMPERED",
                "message": (
                    "PERINGATAN: Dokumen ini pernah ditandatangani, tetapi blok integritas "
                    "kriptografisnya tidak ditemukan. Kemungkinan dokumen telah diedit, "
                    "dikompres, atau ditulis ulang oleh aplikasi lain sehingga blok tanda "
                    "tangan terhapus."
                ),
                "marker_info": marker,
                "details": {
                    "detected_signer": marker.get("signer", "-"),
                    "detected_date": marker.get("date", "-"),
                },
            }
        return {
            "valid": False,
            "status": "UNSIGNED",
            "message": "Dokumen tidak memiliki blok tanda tangan digital resmi.",
            "details": {},
        }

    # 1. Uji Integritas Dokumen (Perhitungan Ulang SHA-256)
    computed_hash = hashlib.sha256(clean_bytes).hexdigest()
    expected_hash = metadata.get("doc_hash", "")

    if computed_hash != expected_hash:
        return {
            "valid": False,
            "status": "TAMPERED",
            "message": "PERINGATAN: Integritas dokumen rusak! Berkas telah dimanipulasi atau diubah setelah ditandatangani.",
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "details": metadata,
        }

    # 2. Uji Kriptografis Tanda Tangan (ECDSA P-256)
    signatures = metadata.get("signatures", [])
    if not signatures:
        return {
            "valid": False,
            "status": "CORRUPTED_METADATA",
            "message": "Metadata dokumen tidak memuat data penandatangan yang valid.",
            "details": metadata,
        }

    verification_results = []
    all_signatures_valid = True

    for idx, sig_record in enumerate(signatures):
        signer_name = sig_record.get("signer", "Tidak Dikenal")
        sig_b64 = sig_record.get("signature", "")
        signed_doc_hash_hex = sig_record.get("doc_hash", expected_hash)
        
        try:
            signed_digest = bytes.fromhex(signed_doc_hash_hex)
        except Exception:
            signed_digest = hashlib.sha256(clean_bytes).digest()

        # Tentukan Public Key yang akan digunakan
        if custom_public_key_pem:
            target_pub_pem = custom_public_key_pem
        else:
            target_pub_pem = sig_record.get("public_key_pem", "").encode("utf-8")

        try:
            pub_key = load_public_key_pem(target_pub_pem)
            is_valid = verify_hash(pub_key, sig_b64, signed_digest)
        except Exception:
            is_valid = False

        if not is_valid:
            all_signatures_valid = False

        verification_results.append({
            "signer_index": idx + 1,
            "signer_name": signer_name,
            "signer_id": sig_record.get("id", "-"),
            "institution": sig_record.get("institution", "-"),
            "date": sig_record.get("date", "-"),
            "valid": is_valid,
        })

    if not all_signatures_valid:
        return {
            "valid": False,
            "status": "KEY_MISMATCH",
            "message": "Verifikasi gagal: Tanda tangan digital tidak cocok dengan Kunci Publik penandatangan!",
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "signers": verification_results,
            "details": metadata,
        }

    return {
        "valid": True,
        "status": "VALID",
        "message": "Dokumen Asli dan Seluruh Tanda Tangan Digital VALID (100% Otentik).",
        "computed_hash": computed_hash,
        "expected_hash": expected_hash,
        "signers": verification_results,
        "details": metadata,
    }
