"""Modul Integrasi PDF & Penempelan QR-Code (PDF Stamper)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi
Bagian: Wardah Nurwaffiq & Fachri Ridhwan Imani

Fitur:
- Pembuatan QR-Code dinamis berisi ringkasan metadata penandatanganan.
- Pembuatan lencana visual tanda tangan digital (badge) profesional dengan ReportLab.
- Penempelan (overlay) badge ke halaman dokumen PDF (halaman terakhir atau halaman tertentu) via pypdf.
- Penyematan blok integritas kriptografi digital signature (ECDSA P-256 + SHA-256).
- Mendukung fitur pengayaan: Multiple Signers (penandatanganan berjenjang).
"""

import io
import json
import base64
import hashlib
from datetime import datetime
from typing import Tuple, Dict, Any, Optional

import qrcode
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader

from crypto_engine import sign_hash, ec

SIG_MARKER_START = b"\n% === UNSIL DIGITAL SIGNATURE INTEGRITY BLOCK ===\n"
SIG_MARKER_END = b"\n% === END UNSIL DIGITAL SIGNATURE INTEGRITY BLOCK ===\n"


def create_qr_code_image(data_text: str, box_size: int = 4, border: int = 1) -> bytes:
    """Menghasilkan gambar QR-Code dalam format bytes PNG."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0B3C5D", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _compute_badge_position(
    page_width: float,
    page_height: float,
    position: str,
    badge_width: float,
    badge_height: float,
    slot_index: int = 0,
) -> Tuple[float, float]:
    """Menghitung koordinat lencana dengan tata letak anti-tumpuk (anti-collision).

    Strategi: lencana disusun berjenjang dari bawah ke atas pada sisi kanan
    halaman (dan bergeser ke kiri bila sudah penuh), sehingga lencana dari
    beberapa penandatangan tidak saling menimpa.

    Args:
        slot_index: urutan penandatangan (0 = pertama, 1 = kedua, dst.).

    Returns:
        Tuple (x, y) dalam satuan poin PDF.
    """
    margin_x = 35.0
    margin_y = 35.0
    gap_y = 10.0  # jarak vertikal antar lencana
    gap_x = 12.0  # jarak horizontal antar kolom lencana

    # Berapa lencana yang muat menumpuk ke atas pada satu kolom?
    usable_h = page_height - (2 * margin_y)
    per_column = max(1, int((usable_h + gap_y) // (badge_height + gap_y)))
    per_column = min(per_column, 4)  # batasi agar tetap rapi

    column = slot_index // per_column          # kolom ke-berapa (dari kanan)
    row = slot_index % per_column              # posisi ke-berapa dalam kolom

    # Titik awal kolom: dari kanan ke kiri
    base_right_x = page_width - badge_width - margin_x
    x = base_right_x - column * (badge_width + gap_x)

    # Bila kolom sudah melewati batas kiri halaman, pindahkan ke tengah/kiri
    min_x = margin_x
    if x < min_x:
        # Bungkus: mulai kolom baru dari kiri
        columns_fit = max(1, int((page_width - 2 * margin_x + gap_x) // (badge_width + gap_x)))
        col_from_left = (column - columns_fit) % max(1, columns_fit)
        x = min_x + col_from_left * (badge_width + gap_x)

    # Posisi vertikal: menumpuk dari bawah ke atas
    y = margin_y + row * (badge_height + gap_y)

    return x, y


def create_signature_badge_pdf(
    page_width: float,
    page_height: float,
    signer_name: str,
    signer_id: str,
    institution: str,
    date_str: str,
    qr_png_bytes: bytes,
    position: str = "bottom-right",
    badge_width: float = 205.0,
    badge_height: float = 76.0,
    slot_index: int = 0,
) -> bytes:
    """Membuat dokumen PDF satu halaman transparan berisi badge tanda tangan digital."""
    x, y = _compute_badge_position(
        page_width, page_height, position, badge_width, badge_height, slot_index
    )

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_width, page_height))

    # 0. Sentinel marker sebagai teks mikro di sudut halaman.
    #    Ditulis ke dalam CONTENT STREAM halaman (bukan metadata), sehingga tetap
    #    bertahan walaupun dokumen ditulis ulang / dikompres oleh aplikasi lain.
    #    Ukuran sangat kecil (0.4pt) dan hampir transparan agar tidak mengganggu tampilan.
    try:
        c.saveState()
        c.setFillColor(HexColor("#F8FAFC"))  # nyaris sama dengan warna kertas
        c.setFont("Helvetica", 0.4)
        c.drawString(2.0, 2.0, f"SignaCerta-Sig:{signer_name}|{signer_id}|{date_str}")
        c.restoreState()
    except Exception:
        pass

    # 1. Kotak Luar Lencana (Background & Border)
    c.setStrokeColor(HexColor("#0B3C5D"))
    c.setLineWidth(1.2)
    c.setFillColor(HexColor("#F8FAFC"))
    c.roundRect(x, y, badge_width, badge_height, 6, fill=1, stroke=1)

    # 2. Header Bar Warna Biru UNSIL
    header_height = 18.0
    c.setFillColor(HexColor("#0B3C5D"))
    c.roundRect(x, y + badge_height - header_height, badge_width, header_height, 4, fill=1, stroke=0)
    
    # 3. Teks Header
    c.setFillColor(HexColor("#FFFFFF"))
    c.setFont("Helvetica-Bold", 7.5)
    c.drawCentredString(x + (badge_width / 2.0), y + badge_height - 13.0, "DITANDATANGANI SECARA DIGITAL")

    # 4. Informasi Penandatangan
    text_x = x + 10.0
    c.setFillColor(HexColor("#0F172A"))
    c.setFont("Helvetica-Bold", 8.5)
    name_display = signer_name if len(signer_name) <= 24 else signer_name[:22] + ".."
    c.drawString(text_x, y + 49.0, name_display)

    c.setFont("Helvetica", 7.2)
    c.setFillColor(HexColor("#334155"))
    id_label = f"NPM/NIP: {signer_id}"
    c.drawString(text_x, y + 37.0, id_label)

    inst_display = institution if len(institution) <= 26 else institution[:24] + ".."
    c.drawString(text_x, y + 26.0, inst_display)

    c.setFillColor(HexColor("#166534"))  # Hijau status valid
    c.setFont("Helvetica-Bold", 6.8)
    c.drawString(text_x, y + 14.0, f"Terverifikasi: {date_str}")

    # 5. Penempelan Gambar QR-Code di sisi kanan badge.
    #    Ukuran & posisi diatur agar TIDAK menutupi header bar di bagian atas.
    qr_size = 50.0
    qr_x = x + badge_width - qr_size - 7.0
    qr_y = y + 6.0
    qr_reader = ImageReader(io.BytesIO(qr_png_bytes))
    c.drawImage(qr_reader, qr_x, qr_y, width=qr_size, height=qr_size)

    c.save()
    return buf.getvalue()


def sign_and_stamp_pdf(
    input_pdf_bytes: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    public_key_pem: bytes,
    signer_name: str,
    signer_id: str,
    institution: str = "Universitas Siliwangi",
    date_str: Optional[str] = None,
    position: str = "bottom-right",
    verification_url_base: str = "https://signacerta.udincloud.me",
) -> Tuple[bytes, Dict[str, Any]]:
    """Membubuhkan tanda tangan visual (QR-Code badge) dan menyematkan blok integritas digital."""
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Periksa apakah berkas sudah memiliki tanda tangan sebelumnya (Multiple Signers)
    existing_signatures = []
    base_doc_hash = ""
    base_bytes = input_pdf_bytes

    if SIG_MARKER_START in input_pdf_bytes and SIG_MARKER_END in input_pdf_bytes:
        parts = input_pdf_bytes.split(SIG_MARKER_START)
        base_bytes = parts[0]
        sub = parts[1].split(SIG_MARKER_END)[0]
        try:
            prev_meta = json.loads(sub.decode("utf-8"))
            if isinstance(prev_meta, dict):
                base_doc_hash = prev_meta.get("base_doc_hash", "")
                if "signatures" in prev_meta:
                    existing_signatures = prev_meta["signatures"]
                else:
                    existing_signatures = [prev_meta]
        except Exception:
            pass

    # Jika penandatangan pertama, hitung hash dokumen asli (sebelum ada stempel apapun)
    if not base_doc_hash:
        base_doc_hash = hashlib.sha256(base_bytes).hexdigest()
        digest_to_sign = hashlib.sha256(base_bytes).digest()
    else:
        digest_to_sign = bytes.fromhex(base_doc_hash)

    # 2. Baca halaman target menggunakan pypdf
    reader_base = PdfReader(io.BytesIO(base_bytes))
    num_pages = len(reader_base.pages)
    if num_pages == 0:
        raise ValueError("Dokumen PDF tidak memiliki halaman.")

    last_page = reader_base.pages[-1]
    page_w = float(last_page.mediabox.width)
    page_h = float(last_page.mediabox.height)

    # 3. Payload ringkas untuk QR-Code
    qr_payload = json.dumps({
        "app": "SignaCerta-UNSIL",
        "signer": signer_name,
        "id": signer_id,
        "inst": institution,
        "date": date_str,
        "hash": base_doc_hash[:16] + "...",
        "verify_url": f"{verification_url_base}?verify=auto"
    }, separators=(',', ':'))

    qr_bytes = create_qr_code_image(qr_payload)

    # 4. Buat badge overlay dan gabungkan ke halaman terakhir.
    #    slot_index otomatis = jumlah penandatangan sebelumnya, sehingga lencana
    #    tersusun berjenjang dan TIDAK saling menumpuk (anti-collision).
    slot_index = len(existing_signatures)
    badge_pdf_bytes = create_signature_badge_pdf(
        page_width=page_w,
        page_height=page_h,
        signer_name=signer_name,
        signer_id=signer_id,
        institution=institution,
        date_str=date_str,
        qr_png_bytes=qr_bytes,
        position=position,
        slot_index=slot_index,
    )
    overlay_reader = PdfReader(io.BytesIO(badge_pdf_bytes))
    last_page.merge_page(overlay_reader.pages[0])

    # 5. Tulis PDF bertanda tangan visual
    writer = PdfWriter()
    for page in reader_base.pages:
        writer.add_page(page)

    # 5b. Sentel marker pada metadata PDF: jejak non-kriptografis agar berkas yang
    #     pernah ditandatangani lalu ditulis ulang (mis. dikompres) masih dapat
    #     dikenali sebagai "pernah ditandatangani" saat blok integritasnya hilang.
    try:
        marker_text = f"SignaCerta-Sig:{signer_name}|{signer_id}|{date_str}"
        writer.add_metadata({
            "/Producer": "SignaCerta v2.0 (UNSIL)",
            "/Creator": "SignaCerta Digital Signature",
            "/SignaCertaMarker": marker_text,
        })
    except Exception:
        pass

    stamped_buf = io.BytesIO()
    writer.write(stamped_buf)
    stamped_clean_bytes = stamped_buf.getvalue()

    # 6. Hitung Hash SHA-256 dari seluruh isi PDF visual akhir
    final_file_hash_hex = hashlib.sha256(stamped_clean_bytes).hexdigest()

    # 7. Tandatangani Digest dokumen yang disetujui menggunakan Private Key ECDSA P-256
    sig_b64 = sign_hash(private_key, digest_to_sign)

    # 8. Susun metadata tanda tangan
    new_signature_record = {
        "signer": signer_name,
        "id": signer_id,
        "institution": institution,
        "date": date_str,
        "doc_hash": base_doc_hash,
        "signature": sig_b64,
        "public_key_pem": public_key_pem.decode("utf-8"),
    }

    all_signatures = existing_signatures + [new_signature_record]

    master_metadata = {
        "version": "1.0",
        "algorithm": "ECDSA-NIST-P256-SHA256",
        "base_doc_hash": base_doc_hash,
        "doc_hash": final_file_hash_hex,
        "total_signers": len(all_signatures),
        "signatures": all_signatures,
    }

    # 9. Sematkan blok integritas kriptografi ke akhir berkas PDF
    meta_json_bytes = json.dumps(master_metadata, indent=2).encode("utf-8")
    final_signed_pdf = stamped_clean_bytes + SIG_MARKER_START + meta_json_bytes + SIG_MARKER_END

    return final_signed_pdf, master_metadata
