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
import zlib
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Tuple, Dict, Any, Optional

WIB = timezone(timedelta(hours=7))

import qrcode
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader

from crypto_engine import (
    sign_hash,
    load_public_key_pem,
    export_public_key_compressed_b64,
    ec,
)

SIG_MARKER_START = b"\n% === UNSIL DIGITAL SIGNATURE INTEGRITY BLOCK ===\n"
SIG_MARKER_END = b"\n% === END UNSIL DIGITAL SIGNATURE INTEGRITY BLOCK ===\n"

# Parameter kueri yang dipakai QR-Code agar aplikasi otomatis membuka modul verifikasi.
QR_VERIFY_PARAM = "verify"


def qr_signed_digest(signer_name: str, signer_id: str, institution: str,
                     date_str: str, doc_hash: str) -> bytes:
    """Menghitung digest yang ditandatangani untuk payload QR-Code.

    Digest ini mengikat **identitas penandatangan + waktu + hash dokumen** menjadi
    satu kesatuan (mirip *signed attributes* pada CMS/PAdES). Akibatnya, mengubah
    nama/identitas mana pun di dalam payload akan membuat tanda tangan tidak lagi
    cocok — sehingga nama pada QR tidak dapat dipalsukan.
    """
    canonical = f"{signer_name}|{signer_id}|{institution}|{date_str}|{doc_hash}"
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def build_qr_verification_payload(
    verification_url_base: str,
    signer_name: str,
    signer_id: str,
    institution: str,
    date_str: str,
    base_doc_hash: str,
    signature_b64: str,
    public_key_b64: str,
) -> str:
    """Menyusun URL verifikasi yang disematkan ke dalam QR-Code.

    URL memuat parameter ``verify=auto`` (pemicu modul verifikasi) dan ``p``
    (payload Base64-URL) berisi identitas penandatangan, hash dokumen, tanda tangan
    ECDSA, serta kunci publik terkompresi. Dengan begitu, satu pindaian QR cukup
    untuk menampilkan hasil verifikasi tanda tangan tanpa perlu mengunggah berkas.

    Payload dikompresi dengan zlib sebelum di-encode Base64-URL agar QR-Code yang
    dihasilkan lebih renggang (versi lebih kecil) sehingga lebih mudah dipindai.
    """
    payload = {
        "v": 1,
        "signer": signer_name,
        "id": signer_id,
        "inst": institution,
        "date": date_str,
        "hash": base_doc_hash,
        "sig": signature_b64,
        "pub": public_key_b64,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    compressed = zlib.compress(raw, 9)
    token = base64.urlsafe_b64encode(compressed).decode("utf-8").rstrip("=")
    return f"{verification_url_base}/?{QR_VERIFY_PARAM}=auto&z=1&p={token}"


def parse_qr_verification_payload(token: str) -> Optional[Dict[str, Any]]:
    """Mengurai kembali payload QR-Code dari parameter ``p`` (Base64-URL).

    Mendukung payload terkompresi zlib (format saat ini). Bila dekompresi gagal,
    fungsi mencoba menafsirkan token sebagai JSON Base64 biasa (kompatibilitas).
    """
    try:
        padded = token + "=" * ((-len(token)) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
        try:
            raw = zlib.decompress(raw)
        except Exception:
            pass  # bukan payload terkompresi; coba tafsirkan langsung
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


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


def _draw_badge(
    c: canvas.Canvas,
    x: float,
    y: float,
    badge_width: float,
    badge_height: float,
    signer_name: str,
    signer_id: str,
    institution: str,
    date_str: str,
    qr_png_bytes: bytes,
):
    """Menggambar elemen visual lencana tanda tangan digital pada koordinat (x, y)."""
    # 1. Kotak Luar Lencana (Background & Border)
    c.setStrokeColor(HexColor("#0B3C5D"))
    c.setLineWidth(1.2)
    c.setFillColor(HexColor("#F8FAFC"))
    c.roundRect(x, y, badge_width, badge_height, 6, fill=1, stroke=1)

    # 2. Header Bar Warna Biru UNSIL
    header_height = 20.0
    c.setFillColor(HexColor("#0B3C5D"))
    c.roundRect(x, y + badge_height - header_height, badge_width, header_height, 4, fill=1, stroke=0)
    
    # 3. Teks Header
    c.setFillColor(HexColor("#FFFFFF"))
    c.setFont("Helvetica-Bold", 8.0)
    c.drawCentredString(x + (badge_width / 2.0), y + badge_height - 14.0, "DITANDATANGANI SECARA DIGITAL")

    # 4. Informasi Penandatangan
    text_x = x + 11.0
    c.setFillColor(HexColor("#0F172A"))
    c.setFont("Helvetica-Bold", 9.0)
    name_display = signer_name if len(signer_name) <= 24 else signer_name[:22] + ".."
    c.drawString(text_x, y + 60.0, name_display)

    c.setFont("Helvetica", 7.4)
    c.setFillColor(HexColor("#334155"))
    id_label = f"NPM/NIP: {signer_id}"
    c.drawString(text_x, y + 46.0, id_label)

    inst_display = institution if len(institution) <= 26 else institution[:24] + ".."
    c.drawString(text_x, y + 34.0, inst_display)

    c.setFillColor(HexColor("#166534"))  # Hijau status valid
    c.setFont("Helvetica-Bold", 6.7)
    c.drawString(text_x, y + 21.0, f"Terverifikasi: {date_str}")

    # 5. Penempelan Gambar QR-Code di sisi kanan badge.
    qr_size = 64.0
    qr_x = x + badge_width - qr_size - 8.0
    qr_y = y + 6.0
    qr_reader = ImageReader(io.BytesIO(qr_png_bytes))
    c.drawImage(qr_reader, qr_x, qr_y, width=qr_size, height=qr_size)


def _compute_legalization_badge_position(
    page_width: float,
    page_height: float,
    slot_index: int,
    badge_width: float = 240.0,
    badge_height: float = 90.0,
) -> Tuple[float, float]:
    """Menghitung koordinat lencana pada Lembar Pengesahan Khusus (Grid 2 Kolom).

    Grid tersusun simetris dari atas ke bawah:
    Slot 0: Kiri Atas (Penandatangan 1)
    Slot 1: Kanan Atas (Penandatangan 2)
    Slot 2: Kiri Baris 2 (Penandatangan 3)
    Slot 3: Kanan Baris 2 (Penandatangan 4)
    ...
    """
    col = slot_index % 2
    row = slot_index // 2

    margin_x = 45.0
    x = margin_x if col == 0 else (page_width - margin_x - badge_width)

    top_y = page_height - 256.0  # Tepat di bawah kotak ringkasan integritas
    y = max(115.0, top_y - (row * (badge_height + 18.0)))
    return x, y


def create_legalization_page_pdf(
    page_width: float,
    page_height: float,
    base_doc_hash: str,
    signer_name: str,
    signer_id: str,
    institution: str,
    date_str: str,
    qr_png_bytes: bytes,
    slot_index: int = 0,
    badge_width: float = 240.0,
    badge_height: float = 90.0,
    is_base_page: bool = True,
) -> bytes:
    """Membuat halaman Lembar Pengesahan Khusus atau lapisan overlay lencananya."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_width, page_height))

    # 0. Sentinel marker sebagai teks mikro 0.4pt
    try:
        c.saveState()
        c.setFillColor(HexColor("#F8FAFC"))
        c.setFont("Helvetica", 0.4)
        c.drawString(2.0, 2.0, f"SignaCerta-Sig:{signer_name}|{signer_id}|{date_str}")
        c.restoreState()
    except Exception:
        pass

    if is_base_page:
        # 1. Header / Kop Lembaga (Dinamis dari Identitas Metadata Penandatangan)
        inst_clean = (institution or "Universitas Siliwangi").strip()
        header_font_size = 12.0 if len(inst_clean) <= 35 else (10.0 if len(inst_clean) <= 55 else 8.5)
        c.setFillColor(HexColor("#0B3C5D"))
        c.setFont("Helvetica-Bold", header_font_size)
        c.drawString(45, page_height - 45.0, inst_clean.upper())

        c.setFillColor(HexColor("#475569"))
        c.setFont("Helvetica-Bold", 7.6)
        c.drawString(45, page_height - 58.0, "OTORITAS PENERBIT PENGESAHAN DOKUMEN ELEKTRONIK • SISTEM SIGNACERTA")

        # Garis Pembatas Kop Formal (Navy & Slate)
        c.setStrokeColor(HexColor("#0B3C5D"))
        c.setLineWidth(1.6)
        c.line(45, page_height - 67.0, page_width - 45, page_height - 67.0)
        c.setStrokeColor(HexColor("#0284C7"))
        c.setLineWidth(0.6)
        c.line(45, page_height - 70.0, page_width - 45, page_height - 70.0)

        # 2. Kotak Ringkasan Integritas Dokumen Asli
        box_y = page_height - 150.0
        c.setFillColor(HexColor("#F8FAFC"))
        c.setStrokeColor(HexColor("#CBD5E1"))
        c.setLineWidth(1.0)
        c.roundRect(45, box_y, page_width - 90, 68, 5, fill=1, stroke=1)

        c.setFillColor(HexColor("#0F172A"))
        c.setFont("Helvetica-Bold", 9.2)
        c.drawString(57, box_y + 49.0, "LEMBAR PENGESAHAN TANDA TANGAN DIGITAL ELEKTRONIK")

        c.setFont("Helvetica", 7.4)
        c.setFillColor(HexColor("#475569"))
        c.drawString(57, box_y + 35.0, "Disahkan secara resmi melalui SignaCerta Digital Signature Engine (FIPS 186-4 ECDSA P-256)")

        c.setFont("Helvetica", 7.0)
        c.setFillColor(HexColor("#475569"))
        c.drawString(57, box_y + 22.0, "Hash Integritas Dokumen Asli (SHA-256):")

        c.setFont("Courier-Bold", 6.8)
        c.setFillColor(HexColor("#0B3C5D"))
        c.drawString(57, box_y + 10.0, base_doc_hash.upper())

        # 3. Catatan Hukum Footer
        c.setStrokeColor(HexColor("#CBD5E1"))
        c.setLineWidth(0.8)
        c.line(45, 96.0, page_width - 45, 96.0)

        c.setFont("Helvetica-Bold", 7.0)
        c.setFillColor(HexColor("#334155"))
        c.drawString(45, 83.0, "DASAR HUKUM & KEABSAHAN DOKUMEN ELEKTRONIK:")
        c.setFont("Helvetica", 6.5)
        c.setFillColor(HexColor("#64748B"))
        c.drawString(45, 72.0, "• Dokumen elektronik ini telah ditandatangani dan disahkan secara digital melalui SignaCerta Digital Signature Engine.")
        c.drawString(45, 62.0, "• Memiliki kekuatan hukum dan akibat hukum yang sah sesuai ketentuan Pasal 5 & 11 UU ITE No. 11/2008 serta PP No. 71/2019 tentang PSTE.")
        c.drawString(45, 52.0, "• Keaslian berkas dan validitas sertifikat tanda tangan dapat diverifikasi mandiri secara publik via pemindaian kode QR resmi.")

    # 4. Gambar Lencana Penandatangan pada Slot
    x, y = _compute_legalization_badge_position(page_width, page_height, slot_index, badge_width, badge_height)
    _draw_badge(c, x, y, badge_width, badge_height, signer_name, signer_id, institution, date_str, qr_png_bytes)

    c.save()
    return buf.getvalue()


def create_signature_badge_pdf(
    page_width: float,
    page_height: float,
    signer_name: str,
    signer_id: str,
    institution: str,
    date_str: str,
    qr_png_bytes: bytes,
    position: str = "bottom-right",
    badge_width: float = 232.0,
    badge_height: float = 90.0,
    slot_index: int = 0,
) -> bytes:
    """Membuat dokumen PDF satu halaman transparan berisi badge tanda tangan digital."""
    x, y = _compute_badge_position(
        page_width, page_height, position, badge_width, badge_height, slot_index
    )

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_width, page_height))

    # 0. Sentinel marker sebagai teks mikro di sudut halaman.
    try:
        c.saveState()
        c.setFillColor(HexColor("#F8FAFC"))  # nyaris sama dengan warna kertas
        c.setFont("Helvetica", 0.4)
        c.drawString(2.0, 2.0, f"SignaCerta-Sig:{signer_name}|{signer_id}|{date_str}")
        c.restoreState()
    except Exception:
        pass

    _draw_badge(c, x, y, badge_width, badge_height, signer_name, signer_id, institution, date_str, qr_png_bytes)

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
    position: str = "new_page",
    verification_url_base: str = "https://signacerta.udincloud.me",
) -> Tuple[bytes, Dict[str, Any]]:
    """Membubuhkan tanda tangan visual (QR-Code badge) dan menyematkan blok integritas digital.

    Mendukung dua mode penempatan visual:
    1. 'new_page' (Default): Membuat Lembar Pengesahan Khusus di halaman paling belakang,
       sehingga 100% TIDAK PERNAH menimpa/menutupi teks atau diagram pada dokumen asli.
       Pada penandatanganan berjenjang (multi-signers), seluruh lencana disusun rapi
       dalam grid 2 kolom pada lembar pengesahan yang sama tanpa membuat lembar baru lagi.
    2. 'bottom-right' / 'bottom-left' / 'in_page': Menempelkan lencana langsung pada sudut
       halaman terakhir berkas asli (mode klasik).
    """
    if date_str is None:
        date_str = datetime.now(WIB).strftime("%Y-%m-%d %H:%M:%S WIB")

    # 1. Periksa apakah berkas sudah memiliki tanda tangan sebelumnya (Multiple Signers)
    existing_signatures = []
    base_doc_hash = ""
    base_bytes = input_pdf_bytes
    has_legalization_page = False

    if SIG_MARKER_START in input_pdf_bytes and SIG_MARKER_END in input_pdf_bytes:
        parts = input_pdf_bytes.split(SIG_MARKER_START)
        base_bytes = parts[0]
        sub = parts[1].split(SIG_MARKER_END)[0]
        try:
            prev_meta = json.loads(sub.decode("utf-8"))
            if isinstance(prev_meta, dict):
                base_doc_hash = prev_meta.get("base_doc_hash", "")
                has_legalization_page = prev_meta.get("has_legalization_page", False)
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

    # Deteksi tambahan: jika halaman terakhir memuat teks lembar pengesahan resmi
    if not has_legalization_page and num_pages > 0:
        try:
            last_text = reader_base.pages[-1].extract_text() or ""
            if "LEMBAR PENGESAHAN TANDA TANGAN DIGITAL" in last_text:
                has_legalization_page = True
        except Exception:
            pass

    # Tentukan mode penempatan
    use_legalization_page = (position in ("new_page", "legalization_page", "sheet")) or has_legalization_page

    last_page = reader_base.pages[-1]
    page_w = float(last_page.mediabox.width)
    page_h = float(last_page.mediabox.height)

    # 3. Hitung tanda tangan ECDSA atas digest dokumen SEBELUM QR dibuat.
    #    `sig_b64` menandatangani hash dokumen (dipakai blok integritas PDF),
    #    sedangkan `qr_sig_b64` menandatangani digest yang MENGIKAT identitas +
    #    hash dokumen, sehingga nama pada QR tidak dapat dipalsukan.
    sig_b64 = sign_hash(private_key, digest_to_sign)
    qr_sig_b64 = sign_hash(
        private_key,
        qr_signed_digest(signer_name, signer_id, institution, date_str, base_doc_hash),
    )

    # 3b. Siapkan kunci publik terkompresi (44 char) untuk payload QR.
    try:
        pub_key_obj = load_public_key_pem(public_key_pem)
        pub_b64_compact = export_public_key_compressed_b64(pub_key_obj)
    except Exception:
        pub_b64_compact = ""

    # 3c. Payload QR: URL verifikasi mandiri (scan -> auto buka modul verifikasi).
    qr_payload = build_qr_verification_payload(
        verification_url_base=verification_url_base,
        signer_name=signer_name,
        signer_id=signer_id,
        institution=institution,
        date_str=date_str,
        base_doc_hash=base_doc_hash,
        signature_b64=qr_sig_b64,
        public_key_b64=pub_b64_compact,
    )

    qr_bytes = create_qr_code_image(qr_payload)

    # 4. Buat stempel visual dan susun halaman dokumen
    slot_index = len(existing_signatures)
    writer = PdfWriter()

    if use_legalization_page:
        if not has_legalization_page:
            # Penandatangan pertama: dokumen asli tetap 100% utuh tanpa stempel,
            # lalu tambahkan 1 lembar halaman baru khusus Lembar Pengesahan di akhir.
            for page in reader_base.pages:
                writer.add_page(page)

            leg_page_bytes = create_legalization_page_pdf(
                page_width=page_w,
                page_height=page_h,
                base_doc_hash=base_doc_hash,
                signer_name=signer_name,
                signer_id=signer_id,
                institution=institution,
                date_str=date_str,
                qr_png_bytes=qr_bytes,
                slot_index=0,
                is_base_page=True,
            )
            leg_reader = PdfReader(io.BytesIO(leg_page_bytes))
            writer.add_page(leg_reader.pages[0])
        else:
            # Penandatangan berikutnya: dokumen sudah memiliki Lembar Pengesahan di halaman terakhir.
            # Jangan tambah halaman baru! Cukup tempelkan lencana baru di slot berikutnya.
            for page in reader_base.pages[:-1]:
                writer.add_page(page)

            target_leg_page = reader_base.pages[-1]
            leg_overlay_bytes = create_legalization_page_pdf(
                page_width=page_w,
                page_height=page_h,
                base_doc_hash=base_doc_hash,
                signer_name=signer_name,
                signer_id=signer_id,
                institution=institution,
                date_str=date_str,
                qr_png_bytes=qr_bytes,
                slot_index=slot_index,
                is_base_page=False,
            )
            overlay_reader = PdfReader(io.BytesIO(leg_overlay_bytes))
            target_leg_page.merge_page(overlay_reader.pages[0])
            writer.add_page(target_leg_page)
    else:
        # Mode klasik: lencana ditempel langsung di halaman terakhir dokumen asli
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
        for page in reader_base.pages:
            writer.add_page(page)

    # 5b. Sentinel marker pada metadata PDF
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

    # 7. Susun metadata tanda tangan
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
        "has_legalization_page": use_legalization_page,
    }

    # 9. Sematkan blok integritas kriptografi ke akhir berkas PDF
    meta_json_bytes = json.dumps(master_metadata, indent=2).encode("utf-8")
    final_signed_pdf = stamped_clean_bytes + SIG_MARKER_START + meta_json_bytes + SIG_MARKER_END

    return final_signed_pdf, master_metadata
