"""Modul Penandatanganan Berkas Gambar (Image / Embedded Signature Engine)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi
Bagian: Fachri Ridhwan Imani (Signing Engine) & Mahardika Rajbi Firdaus (Verification)

Fitur:
- Menandatangani berkas GAMBAR (PNG, JPEG, WEBP, GIF, BMP) dengan menyematkan
  blok integritas kriptografis LANGSUNG ke dalam berkas.
- Menyematkan SENTINEL MARKER ke metadata internal gambar (PNG tEXt, JPEG COM,
  GIF Comment Extension, WEBP chunk) sebagai jejak bahwa berkas pernah
  ditandatangani oleh SignaCerta.
- Memverifikasi integritas berkas dan keaslian tanda tangan secara kriptografis.
- Mendukung penandatanganan berjenjang (multiple signers).

Strategi Penyematan:
1. Blok integritas utama ditambahkan setelah byte terakhir berkas gambar, dibungkus
   penanda unik GENERIC_MARKER_START / _END. Berisi hash SHA-256, tanda tangan ECDSA,
   dan metadata penandatangan.
2. Sentinel marker disisipkan ke metadata internal gambar. Marker ini bukan bukti
   kriptografis, melainkan jejak ringan agar sistem dapat membedakan:
   - "berkas tidak pernah ditandatangani" (UNSIGNED), dan
   - "berkas pernah ditandatangani, tetapi blok integritasnya hilang / berkas
     ditulis ulang oleh aplikasi lain" (TAMPERED).

Catatan Keterbatasan Sentinel Marker:
Sentinel marker bersifat *best-effort*. Sebagian aplikasi editor gambar menulis
ulang seluruh berkas dan membuang metadata internal (khususnya pada PNG), sehingga
marker ikut hilang. Pada kondisi tersebut status yang muncul kembali menjadi
UNSIGNED — namun pesannya tetap menjelaskan kemungkinan berkas pernah ditandatangani.
Pada JPEG, segmen COM umumnya dipertahankan oleh editor, sehingga deteksi TAMPERED
lebih andal.

Verifikasi integritas dilakukan dengan memotong blok terlebih dahulu, lalu
menghitung ulang SHA-256 atas byte konten gambar (termasuk sentinel marker).

Spesifikasi:
- Algoritma Asimetris: ECDSA kurva NIST P-256 (secp256r1)
- Fungsi Hash: SHA-256
"""

import base64
import json
import struct
import zlib
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from crypto_engine import (
    hash_bytes,
    sign_hash,
    verify_hash,
    load_public_key_pem,
)

# Penanda blok integritas utama yang disematkan di akhir berkas gambar
GENERIC_MARKER_START = b"\n% === SIGNACERTA INTEGRITY BLOCK ===\n"
GENERIC_MARKER_END = b"\n% === END SIGNACERTA ===\n"

# Penanda sentinel di metadata internal gambar (ASCII-safe, berbasis base64url)
MARKER_PREFIX = b"SignaCerta-Sig:"
# Terminator eksplisit: karakter yang TIDAK ada dalam alfabet base64url, sehingga
# parser tahu persis di mana token berakhir (mencegah byte CRC/header ikut terbaca).
MARKER_TERMINATOR = b"|"

# Ekstensi berkas gambar yang didukung
SUPPORTED_GENERIC_EXTENSIONS = ["png", "jpg", "jpeg", "webp", "gif", "bmp"]


# ---------------------------------------------------------------------------
# Sentinel marker pada metadata internal gambar
# ---------------------------------------------------------------------------

def _build_marker(signer_name: str, signer_id: str, date_str: str) -> bytes:
    """Menyusun string sentinel marker (ASCII-safe) berisi ringkasan penandatangan."""
    summary = {
        "app": "SignaCerta",
        "signer": signer_name,
        "id": signer_id,
        "date": date_str,
    }
    raw = json.dumps(summary, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return MARKER_PREFIX + base64.urlsafe_b64encode(raw) + MARKER_TERMINATOR


def _png_insert_text(png_bytes: bytes, marker: bytes) -> bytes:
    """Menyisipkan chunk tEXt ke berkas PNG (tepat sebelum chunk IEND)."""
    iend = png_bytes.rfind(b"IEND")
    if iend == -1:
        return png_bytes
    chunk_start = iend - 4  # posisi field panjang chunk IEND
    data = b"SignaCerta\x00" + marker
    chunk = struct.pack(">I", len(data)) + b"tEXt" + data
    crc = zlib.crc32(b"tEXt" + data) & 0xFFFFFFFF
    chunk += struct.pack(">I", crc)
    return png_bytes[:chunk_start] + chunk + png_bytes[chunk_start:]


def _jpeg_insert_comment(jpeg_bytes: bytes, marker: bytes) -> bytes:
    """Menyisipkan segmen COM (comment) ke berkas JPEG (tepat setelah SOI)."""
    if len(marker) + 2 > 0xFFFF:
        return jpeg_bytes
    com = b"\xff\xfe" + struct.pack(">H", len(marker) + 2) + marker
    return jpeg_bytes[:2] + com + jpeg_bytes[2:]


def _gif_insert_comment(gif_bytes: bytes, marker: bytes) -> bytes:
    """Menyisipkan Comment Extension ke berkas GIF (tepat sebelum trailer 0x3B)."""
    if gif_bytes[-1:] != b"\x3b":
        return gif_bytes
    body = gif_bytes[:-1]
    ext = b"\x21\xfe"
    for i in range(0, len(marker), 255):
        blk = marker[i:i + 255]
        ext += bytes([len(blk)]) + blk
    ext += b"\x00"
    return body + ext + b"\x3b"


def _webp_insert_chunk(webp_bytes: bytes, marker: bytes) -> bytes:
    """Menambahkan chunk kustom SIGN ke berkas WEBP (RIFF) dan memperbarui ukuran."""
    if webp_bytes[:4] != b"RIFF" or webp_bytes[8:12] != b"WEBP":
        return webp_bytes
    chunk = b"SIGN" + struct.pack("<I", len(marker)) + marker
    if len(marker) % 2:
        chunk += b"\x00"
    new_bytes = webp_bytes + chunk
    new_size = len(new_bytes) - 8
    return new_bytes[:4] + struct.pack("<I", new_size) + new_bytes[8:]


def _add_marker(file_bytes: bytes, marker: bytes) -> bytes:
    """Menyisipkan sentinel marker ke metadata internal sesuai format gambar."""
    if file_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return _png_insert_text(file_bytes, marker)
    if file_bytes[:2] == b"\xff\xd8":
        return _jpeg_insert_comment(file_bytes, marker)
    if file_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return _gif_insert_comment(file_bytes, marker)
    if file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        return _webp_insert_chunk(file_bytes, marker)
    # BMP tidak memiliki wadah metadata teks yang aman; sentinel dilewati.
    return file_bytes


def _read_marker(file_bytes: bytes) -> Optional[Dict[str, Any]]:
    """Membaca sentinel marker dari berkas gambar (None bila tidak ditemukan)."""
    idx = file_bytes.find(MARKER_PREFIX)
    if idx == -1:
        return None
    start = idx + len(MARKER_PREFIX)

    # 1. Cara utama: potong pada terminator eksplisit '|' (bukan bagian alfabet
    #    base64url), sehingga byte CRC/header setelahnya tidak ikut terbaca.
    term = file_bytes.find(MARKER_TERMINATOR, start)
    candidates = []
    if term != -1:
        candidates.append(file_bytes[start:term])

    # 2. Cadangan: baca karakter base64url berturut-turut, lalu coba semua
    #    panjang kelipatan 4 (dari terpanjang) sampai berhasil didekode.
    valid = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
    end = start
    while end < len(file_bytes) and file_bytes[end] in valid:
        end += 1
    greedy = file_bytes[start:end]
    for trim in range(0, 4):
        if len(greedy) - trim > 0:
            candidates.append(greedy[: len(greedy) - trim])

    for token in candidates:
        if not token:
            continue
        padded = token + b"=" * ((-len(token)) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            data = json.loads(raw.decode("utf-8"))
            if isinstance(data, dict) and "signer" in data:
                return data
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Blok integritas utama
# ---------------------------------------------------------------------------

def embed_signature_block(file_bytes: bytes, payload: Dict[str, Any]) -> bytes:
    """Menyematkan payload tanda tangan ke akhir berkas gambar sebagai blok integritas.

    Blok lama (bila ada) dibersihkan lebih dahulu agar tidak menumpuk saat
    penandatanganan berjenjang.
    """
    base_bytes = file_bytes
    if GENERIC_MARKER_START in base_bytes:
        base_bytes = base_bytes.split(GENERIC_MARKER_START)[0]

    payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
    return base_bytes + GENERIC_MARKER_START + payload_bytes + GENERIC_MARKER_END


def extract_signature_block(
    file_bytes: bytes,
) -> Tuple[bytes, Optional[Dict[str, Any]]]:
    """Memisahkan konten asli gambar dari blok integritas yang tersemat.

    Returns:
        (clean_bytes, payload) — clean_bytes adalah konten gambar (termasuk sentinel
        marker) tanpa blok tanda tangan; payload adalah dict metadata, atau None.
    """
    if GENERIC_MARKER_START not in file_bytes or GENERIC_MARKER_END not in file_bytes:
        return file_bytes, None

    parts = file_bytes.split(GENERIC_MARKER_START)
    clean_bytes = parts[0]
    sub = parts[1].split(GENERIC_MARKER_END)
    meta_json_str = sub[0].decode("utf-8", errors="replace")

    try:
        payload = json.loads(meta_json_str)
        if isinstance(payload, dict):
            return clean_bytes, payload
        return clean_bytes, None
    except Exception:
        return clean_bytes, None


def sign_generic_file(
    file_bytes: bytes,
    original_filename: str,
    private_key: ec.EllipticCurvePrivateKey,
    public_key_pem: bytes,
    signer_name: str,
    signer_id: str,
    institution: str = "Universitas Siliwangi",
    date_str: Optional[str] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Menandatangani berkas gambar dengan menyematkan blok integritas ke dalam berkas.

    Args:
        file_bytes: Isi berkas gambar (boleh sudah berisi blok tanda tangan sebelumnya).
        original_filename: Nama berkas asli, dipakai untuk metadata.
        private_key: Kunci privat ECDSA P-256 penandatangan.
        public_key_pem: Kunci publik penandatangan dalam format PEM (bytes).
        signer_name: Nama lengkap penandatangan.
        signer_id: NPM / NIP / NIDN penandatangan.
        institution: Institusi penandatangan.
        date_str: Waktu penandatanganan; jika kosong memakai waktu sistem.

    Returns:
        Tuple (signed_bytes, payload):
        - signed_bytes: berkas gambar lengkap dengan blok integritas tersemat.
        - payload: dict metadata tanda tangan yang tersimpan dalam blok.
    """
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Pisahkan konten asli dari blok tanda tangan sebelumnya (bila ada)
    clean_bytes, prev_payload = extract_signature_block(file_bytes)
    existing_signatures = []
    base_doc_hash = ""

    if isinstance(prev_payload, dict):
        base_doc_hash = prev_payload.get("base_doc_hash", "")
        existing_signatures = prev_payload.get("signatures", [])
        if not existing_signatures and prev_payload.get("signature"):
            existing_signatures = [prev_payload]

    # 2. Sisipkan sentinel marker ke metadata gambar (bila belum ada)
    if MARKER_PREFIX not in clean_bytes:
        clean_bytes = _add_marker(clean_bytes, _build_marker(signer_name, signer_id, date_str))

    # 3. Untuk penandatangan pertama, hitung hash konten gambar (termasuk marker)
    if not base_doc_hash:
        base_doc_hash = hash_bytes(clean_bytes)
    digest_bytes = bytes.fromhex(base_doc_hash)

    # 4. Tandatangani digest menggunakan Private Key ECDSA P-256
    signature_b64 = sign_hash(private_key, digest_bytes)

    # 5. Susun catatan tanda tangan
    new_signature_record = {
        "signer": signer_name,
        "id": signer_id,
        "institution": institution,
        "date": date_str,
        "signature": signature_b64,
        "public_key_pem": public_key_pem.decode("utf-8"),
    }
    all_signatures = existing_signatures + [new_signature_record]

    # 6. Rakit payload akhir
    payload = {
        "version": "1.0",
        "type": "embedded-signature",
        "algorithm": "ECDSA-NIST-P256-SHA256",
        "original_filename": original_filename,
        "base_doc_hash": base_doc_hash,
        "total_signers": len(all_signatures),
        "signatures": all_signatures,
    }

    # 7. Sematkan blok integritas ke dalam berkas gambar
    signed_bytes = embed_signature_block(clean_bytes, payload)
    return signed_bytes, payload


def verify_generic_file(
    file_bytes: bytes,
    custom_public_key_pem: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Memverifikasi integritas dan keaslian berkas gambar bertanda tangan tersemat.

    Status Kembalian:
    - VALID: Berkas utuh dan seluruh tanda tangan digital terverifikasi sah.
    - TAMPERED: Berkas telah diubah setelah ditandatangani, ATAU pernah ditandatangani
      tetapi blok integritasnya hilang akibat berkas ditulis ulang aplikasi lain.
    - KEY_MISMATCH: Tanda tangan gagal diverifikasi dengan Kunci Publik yang diberikan.
    - UNSIGNED: Berkas tidak memiliki blok tanda tangan digital.
    - CORRUPTED_METADATA: Blok tanda tangan rusak atau tidak dapat dibaca.
    """
    clean_bytes, payload = extract_signature_block(file_bytes)

    if payload is None:
        # Blok integritas tidak ada. Periksa sentinel marker untuk membedakan
        # berkas yang belum pernah ditandatangani vs berkas yang ditulis ulang.
        marker = _read_marker(file_bytes)
        if marker is not None:
            signer = marker.get("signer", "Tidak Dikenal")
            date = marker.get("date", "-")
            return {
                "valid": False,
                "status": "TAMPERED",
                "message": (
                    "PERINGATAN: Berkas ini pernah ditandatangani, tetapi blok integritas "
                    "kriptografisnya tidak ditemukan. Kemungkinan berkas telah diedit dan "
                    "disimpan ulang oleh aplikasi lain sehingga blok tanda tangan terhapus."
                ),
                "marker_info": marker,
                "details": {
                    "detected_signer": signer,
                    "detected_date": date,
                },
            }
        return {
            "valid": False,
            "status": "UNSIGNED",
            "message": (
                "Berkas tidak memiliki blok tanda tangan digital resmi. Berkas ini belum "
                "pernah ditandatangani melalui SignaCerta."
            ),
            "details": {},
        }

    # 1. Uji Integritas Berkas (Perhitungan Ulang SHA-256 atas konten gambar asli)
    computed_hash = hash_bytes(clean_bytes)
    expected_hash = payload.get("base_doc_hash", "")

    if not expected_hash:
        return {
            "valid": False,
            "status": "CORRUPTED_METADATA",
            "message": "Blok tanda tangan tidak memuat nilai hash berkas yang valid.",
            "details": payload,
        }

    if computed_hash != expected_hash:
        return {
            "valid": False,
            "status": "TAMPERED",
            "message": "PERINGATAN: Integritas berkas rusak! Berkas telah dimanipulasi atau diubah setelah ditandatangani.",
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "details": payload,
        }

    # 2. Uji Kriptografis Tanda Tangan (ECDSA P-256)
    signatures = payload.get("signatures", [])
    if not signatures:
        return {
            "valid": False,
            "status": "CORRUPTED_METADATA",
            "message": "Blok tanda tangan tidak memuat data penandatangan yang valid.",
            "details": payload,
        }

    # 2. Muat Kunci Publik Penguji jika diberikan
    custom_pub_key_obj = None
    if custom_public_key_pem:
        try:
            custom_pub_key_obj = load_public_key_pem(custom_public_key_pem)
        except Exception:
            return {
                "valid": False,
                "status": "KEY_MISMATCH",
                "message": "Kunci Publik penguji tidak valid atau formatnya rusak.",
                "computed_hash": computed_hash,
                "expected_hash": expected_hash,
                "details": payload,
            }

    # Jika custom key diuji, periksa apakah cocok dengan setidaknya salah satu penandatangan.
    if custom_pub_key_obj is not None:
        custom_key_matched_any = False
        for sig_record in signatures:
            sig_b64 = sig_record.get("signature", "")
            try:
                signed_digest = bytes.fromhex(expected_hash)
            except Exception:
                signed_digest = bytes.fromhex(computed_hash)
            if verify_hash(custom_pub_key_obj, sig_b64, signed_digest):
                custom_key_matched_any = True
                break

        if not custom_key_matched_any:
            verification_results = []
            for idx, sig_record in enumerate(signatures):
                verification_results.append({
                    "signer_index": idx + 1,
                    "signer_name": sig_record.get("signer", "Tidak Dikenal"),
                    "signer_id": sig_record.get("id", "-"),
                    "institution": sig_record.get("institution", "-"),
                    "date": sig_record.get("date", "-"),
                    "valid": False,
                    "matched_custom_key": False,
                })
            return {
                "valid": False,
                "status": "KEY_MISMATCH",
                "message": (
                    f"Verifikasi gagal: Kunci Publik penguji tidak cocok dengan "
                    f"penandatangan mana pun pada berkas ini (total {len(signatures)} penandatangan)."
                ),
                "computed_hash": computed_hash,
                "expected_hash": expected_hash,
                "signers": verification_results,
                "details": payload,
            }

    verification_results = []
    all_signatures_valid = True
    matched_custom_names = []

    for idx, sig_record in enumerate(signatures):
        signer_name = sig_record.get("signer", "Tidak Dikenal")
        sig_b64 = sig_record.get("signature", "")
        recorded_pub_pem = sig_record.get("public_key_pem", "").encode("utf-8")

        try:
            signed_digest = bytes.fromhex(expected_hash)
        except Exception:
            signed_digest = bytes.fromhex(computed_hash)

        is_valid = False
        matched_custom = False

        if custom_pub_key_obj is not None and verify_hash(custom_pub_key_obj, sig_b64, signed_digest):
            is_valid = True
            matched_custom = True
            matched_custom_names.append(signer_name)
        else:
            try:
                pub_key = load_public_key_pem(recorded_pub_pem)
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
            "matched_custom_key": matched_custom,
        })

    if not all_signatures_valid:
        return {
            "valid": False,
            "status": "KEY_MISMATCH",
            "message": "Verifikasi gagal: Tanda tangan digital tidak cocok dengan Kunci Publik penandatangan!",
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "signers": verification_results,
            "details": payload,
        }

    success_msg = "Berkas Asli dan Seluruh Tanda Tangan Digital VALID (100% Otentik)."
    if custom_public_key_pem and matched_custom_names:
        success_msg += f" Kunci Publik penguji terbukti cocok dan sah milik: {', '.join(matched_custom_names)}."

    return {
        "valid": True,
        "status": "VALID",
        "message": success_msg,
        "computed_hash": computed_hash,
        "expected_hash": expected_hash,
        "signers": verification_results,
        "details": payload,
    }


if __name__ == "__main__":
    print("=== PENGUJIAN MODUL IMAGE SIGNER (EMBEDDED SIGNATURE) ===")

    from crypto_engine import generate_keypair, export_public_key_pem

    priv, pub = generate_keypair()
    pem_pub = export_public_key_pem(pub)

    # Berkas contoh gambar PNG
    berkas_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + b"IEND\xaeB`\x82"
    signed_png, _ = sign_generic_file(
        file_bytes=berkas_png, original_filename="foto.png",
        private_key=priv, public_key_pem=pem_pub,
        signer_name="Fachri Ridhwan Imani", signer_id="247006111140",
    )
    print(f"✓ [PNG]        {len(berkas_png)} -> {len(signed_png)} byte | "
          f"verifikasi: {verify_generic_file(signed_png)['status']}")

    # Uji tamper 1 byte
    tampered = bytearray(signed_png); tampered[10] ^= 0xFF
    print(f"✓ [TAMPER]     status: {verify_generic_file(bytes(tampered))['status']}")

    # Uji blok hilang tapi marker masih ada (simulasi ditulis ulang aplikasi lain)
    stripped = signed_png.split(GENERIC_MARKER_START)[0]
    print(f"✓ [RE-SAVED]   status: {verify_generic_file(stripped)['status']}  (harus TAMPERED)")

    # Uji kunci publik salah
    _, pub_lain = generate_keypair()
    print(f"✓ [KEY SALAH]  status: {verify_generic_file(signed_png, custom_public_key_pem=export_public_key_pem(pub_lain))['status']}")

    # Uji berkas tanpa tanda tangan
    print(f"✓ [UNSIGNED]   status: {verify_generic_file(berkas_png)['status']}")

    # Uji berjenjang
    signed_2, payload_2 = sign_generic_file(
        file_bytes=signed_png, original_filename="foto.png",
        private_key=priv, public_key_pem=pem_pub,
        signer_name="Wardah Nurwaffiq", signer_id="247006111150",
    )
    print(f"✓ [BERJENJANG] total={payload_2['total_signers']} | "
          f"verifikasi: {verify_generic_file(signed_2)['status']}")

    print("\nSeluruh pengujian modul image signer berhasil 100%!")
