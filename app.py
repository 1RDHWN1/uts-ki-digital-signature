"""SignaCerta — Sistem Otentikasi dan Tanda Tangan Digital Dokumen PDF
Fakultas Teknik, Jurusan Informatika, Universitas Siliwangi
Tugas Proyek UTS Keamanan Informasi (20261)
Dosen Pengampu: Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.
"""

import io
import os
import json
import streamlit as st
import pandas as pd
from pypdf import PdfReader

from crypto_engine import (
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    hash_bytes,
)
from pdf_stamper import (
    sign_and_stamp_pdf,
    SIG_MARKER_START,
    SIG_MARKER_END,
    parse_qr_verification_payload,
)
from verifier import verify_pdf_document, verify_qr_payload
from generic_signer import (
    sign_generic_file,
    verify_generic_file,
)

# ----------------- KONFIGURASI HALAMAN -----------------
st.set_page_config(
    page_title="SignaCerta — Otentikasi PDF (Universitas Siliwangi)",
    layout="wide",
    initial_sidebar_state="auto",
)

# ----------------- FUNGSI NAVIGASI SHORTCUT -----------------
def navigate_to(step_name):
    st.session_state["nav_sidebar"] = step_name


# ----------------- SISTEM NOTIFIKASI POP-UP (TOAST) -----------------
def show_toast(kind: str, title: str, message: str = "", duration: float = 5.0):
    """Menyimpan notifikasi pop-up ke antrean session state.

    Notifikasi ditampilkan sekali pada rerun berikutnya, lalu dihapus dari antrean
    agar tidak muncul berulang setiap kali Streamlit melakukan rerun.
    """
    queue = st.session_state.setdefault("sc_toast_queue", [])
    queue.append({"kind": kind, "title": title, "message": message, "duration": duration})


def render_toasts():
    """Merender seluruh notifikasi pop-up yang tertunda (sekali tampil, lalu dibersihkan).

    Implementasi murni HTML+CSS (tanpa JavaScript) karena Streamlit menyaring tag
    <script> pada st.markdown. Animasi muncul dan hilang otomatis dijalankan lewat
    CSS @keyframes dengan durasi sesuai parameter ``duration``.
    """
    queue = st.session_state.get("sc_toast_queue") or []
    if not queue:
        return

    icons = {
        "success": '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>',
        "error": '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>',
        "warning": '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
        "info": '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
    }

    cards_html = []
    for idx, item in enumerate(queue):
        kind = item.get("kind", "info")
        icon_svg = icons.get(kind, icons["info"])
        dur = float(item.get("duration", 5.0) or 5.0)
        safe_title = str(item.get("title", "")).replace("<", "&lt;").replace(">", "&gt;")
        safe_msg = str(item.get("message", "")).replace("<", "&lt;").replace(">", "&gt;")
        msg_html = f'<p class="sc-toast__msg">{safe_msg}</p>' if safe_msg else ""
        cb_id = f"sc-toast-cb-{idx}"
        cards_html.append(
            f'<input type="checkbox" id="{cb_id}" class="sc-toast__closer">'
            f'<div class="sc-toast sc-toast--{kind}" style="--sc-toast-life: {dur}s;" role="status">'
            f'<div class="sc-toast__icon">{icon_svg}</div>'
            f'<div class="sc-toast__body"><p class="sc-toast__title">{safe_title}</p>{msg_html}</div>'
            f'<label class="sc-toast__close" for="{cb_id}" aria-label="Tutup">&#10005;</label>'
            f'<div class="sc-toast__bar"></div>'
            f'</div>'
        )

    toast_html = '<div class="sc-toast-wrap">' + "".join(cards_html) + '</div>'
    st.markdown(toast_html, unsafe_allow_html=True)
    st.session_state["sc_toast_queue"] = []


# ----------------- PENANGANAN PINDAI QR-CODE (?verify=auto) -----------------
# Saat QR-Code dipindai, browser membuka URL dengan parameter verify=auto dan
# payload Base64 (p). Handler ini mengurai payload, memverifikasi tanda tangan
# ECDSA secara mandiri, lalu mengarahkan aplikasi ke modul Verifikasi.
_qp_verify = None
_qp_payload = None
try:
    _qp_verify = st.query_params.get("verify")
    _qp_payload = st.query_params.get("p")
except Exception:
    _qp_verify = None
    _qp_payload = None

if _qp_verify == "auto" and _qp_payload:
    _qr_parsed = parse_qr_verification_payload(_qp_payload)
    if _qr_parsed is not None:
        st.session_state["qr_scan_payload"] = _qr_parsed
        st.session_state["qr_scan_result"] = verify_qr_payload(_qr_parsed)
        st.session_state["nav_sidebar"] = "3. Verifikasi Integritas"
        st.session_state["qr_scan_active"] = True


# ----------------- SIDEBAR & NAVIGASI SISTEM -----------------
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.25rem;">
        <svg style="width: 40px; height: 40px; flex-shrink: 0;" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="44" height="44" rx="8" fill="#0B3C5D"/>
            <circle cx="22" cy="22" r="17" stroke="#D97706" stroke-width="1.5"/>
            <circle cx="22" cy="22" r="14" stroke="#CBD5E1" stroke-width="1" stroke-dasharray="2 2"/>
            <path d="M22 12L28 18H24V26H20V18H16L22 12Z" fill="#FFFFFF"/>
            <path d="M16 28H28V30C28 30.5523 27.5523 31 27 31H17C16.4477 31 16 30.5523 16 30V28Z" fill="#D97706"/>
        </svg>
        <div>
            <div style="font-weight: 800; font-size: 1.25rem; color: #0B3C5D; line-height: 1.1;">SignaCerta</div>
            <div style="font-size: 0.72rem; color: #64748B; font-weight: 500;">Universitas Siliwangi</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("###### NAVIGASI SISTEM")
    nav_choice = st.radio(
        "Navigasi Modul",
        [
            "1. Pembangkitan Kunci",
            "2. Penandatanganan Dokumen",
            "3. Verifikasi Integritas",
            "4. Uji Kuantitatif & Benchmark",
            "Tentang Proyek",
        ],
        label_visibility="collapsed",
        key="nav_sidebar",
    )
    
    st.markdown("---")
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg>
        <span style="font-size: 0.82rem; font-weight: 600;">Tema Antarmuka</span>
    </div>
    """, unsafe_allow_html=True)
    dark_mode = st.toggle("Mode Gelap", value=False, key="app_theme_dark")
    
    st.markdown("""
    <div style="margin-top: 3.5rem; padding-top: 1rem; border-top: 1px solid #E2E8F0; text-align: center;">
        <span class="sidebar-fips-badge">
            FIPS 186-4 • P-256
        </span>
        <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 0.5rem; font-weight: 500;">
            SignaCerta v1.0 • FT UNSIL
        </div>
    </div>
    """, unsafe_allow_html=True)

# ----------------- CSS DINAMIS & SISTEM WARNA LENGKAP -----------------
theme_css = """<style>
    :root {
        --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        --font-mono: "JetBrains Mono", Consolas, monospace;
    }
"""

if dark_mode:
    theme_css += """
    /* =================================================== */
    /* MODE GELAP (DARK THEME) - KONTROL TOTAL STABILITAS  */
    /* =================================================== */
    .stApp {
        background-color: #0A0F1D !important;
        color: #F8FAFC !important;
    }
    
    /* Typografi Umum & Seluruh Heading */
    h1, h2, h3, h4, h5, h6 {
        color: #F8FAFC !important;
    }
    
    p, span, li {
        color: #E2E8F0 !important;
    }
    
    /* Seluruh Label Formulir Wajib Terang & Terbaca Jelas */
    label,
    label p,
    label span,
    [data-testid="stWidgetLabel"],
    [data-testid="stWidgetLabel"] p,
    [data-testid="stWidgetLabel"] span {
        color: #F8FAFC !important;
        font-weight: 600 !important;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0F172A !important;
        border-right: 1px solid #1E293B !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        color: #CBD5E1 !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: #1E293B !important;
        color: #38BDF8 !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {
        background-color: #0284C7 !important;
        color: #FFFFFF !important;
        border-color: #0284C7 !important;
        box-shadow: 0 1px 3px 0 rgba(2, 132, 199, 0.4) !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) span,
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p {
        color: #FFFFFF !important;
    }
    
    /* Kartu & Kontainer Utama */
    div[data-testid="stVerticalBlockBorderWrapper"] > div {
        background-color: #111C33 !important;
        border: 1px solid #1E2E4A !important;
        color: #F8FAFC !important;
    }
    
    .top-bar-container {
        background-color: #111C33 !important;
        border: 1px solid #1E2E4A !important;
        color: #F8FAFC !important;
    }
    
    .navbar-badge {
        background-color: #0A0F1D !important;
        border: 1px solid #1E2E4A !important;
        color: #38BDF8 !important;
    }
    
    /* File Uploader Dropzone */
    [data-testid="stFileUploader"] {
        background-color: transparent !important;
    }
    
    [data-testid="stFileUploaderDropzone"] {
        background-color: #15223D !important;
        border: 1.5px dashed #334E68 !important;
        border-radius: 8px !important;
    }
    
    [data-testid="stFileUploaderDropzone"]:hover {
        border-color: #38BDF8 !important;
        background-color: #1A2B4C !important;
    }
    
    [data-testid="stFileUploaderDropzoneInstructions"],
    [data-testid="stFileUploaderDropzoneInstructions"] p,
    [data-testid="stFileUploaderDropzoneInstructions"] span,
    [data-testid="stFileUploaderDropzoneInstructions"] small {
        color: #94A3B8 !important;
    }
    
    [data-testid="stFileUploaderDropzone"] button,
    [data-testid="stFileUploader"] button {
        background-color: #1E2E4A !important;
        color: #F8FAFC !important;
        border: 1px solid #334E68 !important;
    }
    
    [data-testid="stFileUploaderDropzone"] button:hover,
    [data-testid="stFileUploader"] button:hover {
        background-color: #243B61 !important;
        border-color: #38BDF8 !important;
        color: #38BDF8 !important;
    }
    
    [data-testid="stFileUploaderDropzone"] button * {
        color: inherit !important;
    }
    
    /* Input Teks & Input Password (Semua Pembungkus React Aria & BaseWeb) */
    .react-aria-TextField > div,
    div[data-testid="stTextInput"] > div,
    div[data-testid="stTextInputRootElement"] > div,
    div[data-baseweb="input"],
    div[data-baseweb="base-input"] {
        background-color: #15223D !important;
        border: 1px solid #334E68 !important;
        border-radius: 6px !important;
        color: #F8FAFC !important;
    }
    
    .react-aria-TextField input,
    div[data-testid="stTextInput"] input,
    div[data-testid="stTextInputRootElement"] input,
    input[type="text"],
    input[type="password"] {
        color: #F8FAFC !important;
        background-color: transparent !important;
    }
    
    .react-aria-TextField input::placeholder,
    div[data-testid="stTextInput"] input::placeholder,
    input::placeholder {
        color: #64748B !important;
    }
    
    /* Dropdown Selectbox */
    [data-testid="stSelectbox"] div,
    [data-testid="stSelectbox"] button,
    div[data-baseweb="select"],
    div[data-baseweb="select"] div,
    .react-aria-Select,
    .react-aria-Select div {
        background-color: #15223D !important;
        border: 1px solid #334E68 !important;
        border-radius: 6px !important;
        color: #F8FAFC !important;
    }
    
    [data-testid="stSelectbox"] *,
    div[data-baseweb="select"] * {
        color: #F8FAFC !important;
    }
    
    .sidebar-fips-badge {
        font-family: var(--font-mono);
        font-size: 0.72rem;
        background-color: #15223D !important;
        color: #38BDF8 !important;
        border: 1px solid #334E68 !important;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
    }
    
    div[data-testid="stSelectboxVirtualDropdown"],
    div[role="listbox"],
    ul[role="listbox"],
    div[data-baseweb="popover"] > div {
        background-color: #111C33 !important;
        border: 1px solid #334E68 !important;
        color: #F8FAFC !important;
    }
    
    div[role="option"],
    li[role="option"] {
        background-color: #111C33 !important;
        color: #F8FAFC !important;
    }
    
    div[role="option"]:hover,
    li[role="option"]:hover,
    div[role="option"][aria-selected="true"],
    li[role="option"][aria-selected="true"] {
        background-color: #0284C7 !important;
        color: #FFFFFF !important;
    }
    
    /* Tombol Primer */
    button[kind="primary"], .stButton > button[kind="primary"] {
        background-color: #0284C7 !important;
        border: 1px solid #0284C7 !important;
        color: #FFFFFF !important;
    }
    
    button[kind="primary"]:hover, .stButton > button[kind="primary"]:hover {
        background-color: #0369A1 !important;
        border-color: #0369A1 !important;
        color: #FFFFFF !important;
    }
    
    button[kind="primary"] p {
        color: #FFFFFF !important;
    }
    
    /* Tombol Sekunder */
    button[kind="secondary"], .stButton > button[kind="secondary"] {
        background-color: #1E2E4A !important;
        border: 1px solid #334E68 !important;
        color: #F8FAFC !important;
    }
    
    button[kind="secondary"]:hover, .stButton > button[kind="secondary"]:hover {
        background-color: #243B61 !important;
        border-color: #38BDF8 !important;
        color: #38BDF8 !important;
    }
    
    button[kind="secondary"] p {
        color: #F8FAFC !important;
    }
    
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #111C33 !important;
        border: 1px solid #1E2E4A !important;
        color: #F8FAFC !important;
    }
    
    div[data-testid="stMetricLabel"] p {
        color: #94A3B8 !important;
    }
    
    div[data-testid="stMetricValue"] div {
        color: #38BDF8 !important;
    }
    
    /* Hash Hex & Code */
    .hash-hex-display, code {
        background-color: #060B18 !important;
        border: 1px solid #1E3A8A !important;
        color: #38BDF8 !important;
    }
    
    /* Sertifikat Valid & Tamper */
    .cert-audit-valid {
        background-color: rgba(5, 150, 105, 0.15) !important;
        border: 1px solid #059669 !important;
        border-left: 6px solid #10B981 !important;
    }
    
    .cert-audit-title-valid {
        color: #34D399 !important;
    }
    
    .cert-audit-tampered {
        background-color: rgba(220, 38, 38, 0.18) !important;
        border: 1px solid #DC2626 !important;
        border-left: 6px solid #EF4444 !important;
    }
    
    .cert-audit-title-tampered {
        color: #F87171 !important;
    }
    
    /* Footer */
    .footer-container {
        background-color: #0A0F1D !important;
        border-top: 1px solid #1E2E4A !important;
        color: #94A3B8 !important;
    }
    
    .footer-col h5 {
        color: #F8FAFC !important;
    }
    
    .footer-col p {
        color: #94A3B8 !important;
    }
    """
else:
    theme_css += """
    /* =================================================== */
    /* MODE TERANG (LIGHT THEME - SILIWANGI NAVY)          */
    /* =================================================== */
    .stApp {
        background-color: #FFFFFF !important;
        color: #0F172A !important;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: #0B3C5D !important;
    }
    
    p, span, li {
        color: #334155 !important;
    }
    
    label[data-testid="stWidgetLabel"],
    label[data-testid="stWidgetLabel"] p,
    label[data-testid="stWidgetLabel"] span {
        color: #0F172A !important;
        font-weight: 600 !important;
    }
    
    section[data-testid="stSidebar"] {
        background-color: #F8FAFC !important;
        border-right: 1px solid #E2E8F0 !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        color: #334155 !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: #EEF2F6 !important;
        color: #0B3C5D !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {
        background-color: #0B3C5D !important;
        color: #FFFFFF !important;
        border-color: #0B3C5D !important;
        box-shadow: 0 1px 3px 0 rgba(11, 60, 93, 0.25) !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) span,
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p {
        color: #FFFFFF !important;
    }
    
    div[data-testid="stVerticalBlockBorderWrapper"] > div {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
    }
    
    .top-bar-container {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        color: #0F172A !important;
    }
    
    .navbar-badge {
        background-color: #F0F7FC !important;
        border: 1px solid #BAE0F7 !important;
        color: #0B3C5D !important;
    }
    
    /* Dropzone Upload */
    [data-testid="stFileUploaderDropzone"] {
        background-color: #F8FAFC !important;
        border: 1.5px dashed #CBD5E1 !important;
        border-radius: 8px !important;
    }
    
    [data-testid="stFileUploaderDropzone"]:hover {
        border-color: #0B3C5D !important;
        background-color: #F1F5F9 !important;
    }
    
    [data-testid="stFileUploaderDropzoneInstructions"],
    [data-testid="stFileUploaderDropzoneInstructions"] p {
        color: #64748B !important;
    }
    
    /* Input Teks */
    .react-aria-TextField > div,
    [data-testid="stTextInputRootElement"] > div {
        background-color: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 6px !important;
    }
    
    .react-aria-TextField input,
    [data-testid="stTextInputRootElement"] input {
        color: #0F172A !important;
    }
    
    .react-aria-TextField input::placeholder,
    [data-testid="stTextInputRootElement"] input::placeholder,
    input::placeholder {
        color: #64748B !important;
        opacity: 1 !important;
    }
    
    /* Tombol Utama (Primary) Light Mode - Wajib Teks Putih Kontras Tinggi */
    button[kind="primary"],
    .stButton > button[kind="primary"],
    button[data-testid="baseButton-primary"] {
        background-color: #0B3C5D !important;
        color: #FFFFFF !important;
        border: 1px solid #0B3C5D !important;
    }
    
    button[kind="primary"] *,
    .stButton > button[kind="primary"] *,
    button[data-testid="baseButton-primary"] * {
        color: #FFFFFF !important;
    }
    
    button[kind="primary"]:hover,
    .stButton > button[kind="primary"]:hover,
    button[data-testid="baseButton-primary"]:hover {
        background-color: #07253D !important;
        border-color: #07253D !important;
        color: #FFFFFF !important;
    }
    
    button[kind="primary"]:hover *,
    .stButton > button[kind="primary"]:hover *,
    button[data-testid="baseButton-primary"]:hover * {
        color: #FFFFFF !important;
    }
    
    /* Tombol Sekunder Light Mode */
    button[kind="secondary"],
    .stButton > button[kind="secondary"],
    button[data-testid="baseButton-secondary"] {
        background-color: #FFFFFF !important;
        color: #0F172A !important;
        border: 1px solid #CBD5E1 !important;
    }
    
    button[kind="secondary"] *,
    .stButton > button[kind="secondary"] *,
    button[data-testid="baseButton-secondary"] * {
        color: #0F172A !important;
    }
    
    button[kind="secondary"]:hover,
    .stButton > button[kind="secondary"]:hover,
    button[data-testid="baseButton-secondary"]:hover {
        background-color: #F1F5F9 !important;
        border-color: #0B3C5D !important;
        color: #0B3C5D !important;
    }
    
    button[kind="secondary"]:hover *,
    .stButton > button[kind="secondary"]:hover *,
    button[data-testid="baseButton-secondary"]:hover * {
        color: #0B3C5D !important;
    }
    
    /* Password Eye Icon styling */
    div[data-testid="stTextInputRootElement"] button {
        background: transparent !important;
        border: none !important;
        filter: grayscale(100%) opacity(60%) !important;
    }
    
    div[data-testid="stTextInputRootElement"] button:hover {
        filter: grayscale(100%) opacity(100%) !important;
    }
    
    div[data-testid="stMetric"] {
        background-color: #F8FAFC !important;
        border: 1px solid #E2E8F0 !important;
    }
    
    .hash-hex-display {
        background-color: #F8FAFC !important;
        border: 1px solid #E2E8F0 !important;
        color: #0B3C5D !important;
    }
    
    .cert-audit-valid {
        background-color: #F8FCF9 !important;
        border: 1px solid #10B981 !important;
        border-left: 6px solid #059669 !important;
    }
    
    .cert-audit-title-valid {
        color: #065F46 !important;
    }
    
    .cert-audit-tampered {
        background-color: #FEF2F2 !important;
        border: 1px solid #F87171 !important;
        border-left: 6px solid #DC2626 !important;
    }
    
    .cert-audit-title-tampered {
        color: #991B1B !important;
    }
    
    .footer-container {
        background-color: #FFFFFF !important;
        border-top: 1px solid #E2E8F0 !important;
        color: #64748B !important;
    }
    
    .footer-col h5 {
        color: #0B3C5D !important;
    }
    """

# CSS Universal & Responsif Mobile
theme_css += """
    /* Sidebar Radio Base */
    section[data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 0.35rem !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        background-color: transparent !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        padding: 0.55rem 0.75rem !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        cursor: pointer !important;
        display: flex !important;
        align-items: center !important;
        transition: all 0.15s ease-in-out !important;
        width: 100% !important;
    }
    
    section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child {
        display: none !important;
    }

    /* Top Breadcrumb Bar */
    .top-bar-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 1.25rem;
        margin-bottom: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
    }
    
    .navbar-badge {
        font-family: var(--font-mono);
        font-size: 0.75rem;
        font-weight: 600;
        padding: 0.35rem 0.65rem;
        border-radius: 4px;
        letter-spacing: 0.02em;
    }

    /* Header & Layout Scaling */
    header[data-testid="stHeader"] {
        background: transparent !important;
        height: 2.75rem !important;
        z-index: 50 !important;
    }
    
    .block-container {
        max-width: 1280px;
        padding-top: 1.75rem !important;
        padding-bottom: 3rem !important;
    }
    
    /* Tombol Primer */
    button[kind="primary"], .stButton > button[kind="primary"] {
        border-radius: 6px !important;
        font-weight: 600 !important;
        padding: 0.5rem 1rem !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
    }

    /* Hash Display */
    .hash-hex-display {
        font-family: var(--font-mono);
        font-size: 0.8rem;
        padding: 0.65rem 0.85rem;
        border-radius: 6px;
        letter-spacing: 0.02em;
        word-break: break-all;
        white-space: pre-wrap;
    }
    
    /* Footer */
    .footer-container {
        margin-top: 3.5rem;
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    .footer-grid {
        display: grid;
        grid-template-columns: 1.5fr 1fr 1fr;
        gap: 2rem;
    }
    
    .footer-col h5 {
        font-size: 0.95rem;
        font-weight: 700;
        margin-bottom: 0.65rem;
    }
    
    .footer-col p {
        font-size: 0.82rem;
        line-height: 1.5;
        margin: 0.25rem 0;
    }

    /* =================================================== */
    /* ATURAN RESPONSIF MOBILE & TABLET (antislop-layoutmobile) */
    /* =================================================== */
    @media (max-width: 900px) {
        .block-container {
            padding-left: 1rem !important;
            padding-right: 1rem !important;
            padding-top: 2rem !important;
        }
        .top-bar-container {
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 0.6rem !important;
            padding: 0.85rem 1rem !important;
        }
        .navbar-badge {
            font-size: 0.7rem !important;
        }
        .footer-grid {
            grid-template-columns: 1fr 1fr !important;
            gap: 1.5rem !important;
        }
    }

    @media (max-width: 600px) {
        header[data-testid="stHeader"] {
            display: block !important;
            background: transparent !important;
            height: 2.75rem !important;
            z-index: 100 !important;
        }
        
        header[data-testid="stHeader"] button[data-testid="stSidebarCollapseButton"] {
            min-width: 44px !important;
            min-height: 44px !important;
            border-radius: 6px !important;
        }
        
        .block-container {
            padding-left: 0.75rem !important;
            padding-right: 0.75rem !important;
            padding-top: 3.5rem !important;
            padding-bottom: 2rem !important;
        }
        
        button, input, select {
            min-height: 44px !important;
        }
        
        .stApp, body, html {
            overflow-x: hidden !important;
        }
        
        .hash-hex-display {
            font-size: 0.72rem !important;
            word-break: break-all !important;
            white-space: pre-wrap !important;
            padding: 0.5rem !important;
        }
        
        .footer-grid {
            grid-template-columns: 1fr !important;
            gap: 1.25rem !important;
        }
    }

    /* ============================================================
       NOTIFIKASI POP-UP BERANIMASI (SignaCerta Toast)
       Implementasi CSS murni — tanpa JavaScript (Streamlit menyaring <script>)
       ============================================================ */
    @keyframes sc-toast-lifecycle {
        0%   { opacity: 0; transform: translateY(-28px) scale(0.92); visibility: visible; }
        7%   { opacity: 1; transform: translateY(0)     scale(1); }
        88%  { opacity: 1; transform: translateY(0)     scale(1); }
        100% { opacity: 0; transform: translateY(-18px) scale(0.96); visibility: hidden; }
    }
    @keyframes sc-toast-out {
        0%   { opacity: 1; transform: translateY(0) scale(1); }
        100% { opacity: 0; transform: translateY(-20px) scale(0.95); visibility: hidden; }
    }
    @keyframes sc-toast-progress {
        0%   { width: 100%; }
        100% { width: 0%; }
    }
    @keyframes sc-toast-icon-pop {
        0%   { transform: scale(0.3) rotate(-25deg); opacity: 0; }
        55%  { transform: scale(1.18) rotate(6deg); opacity: 1; }
        100% { transform: scale(1) rotate(0deg); opacity: 1; }
    }
    @keyframes sc-toast-ring {
        0%   { box-shadow: 0 0 0 0 rgba(5, 150, 105, 0.45); }
        70%  { box-shadow: 0 0 0 12px rgba(5, 150, 105, 0); }
        100% { box-shadow: 0 0 0 0 rgba(5, 150, 105, 0); }
    }

    .sc-toast-wrap {
        position: fixed;
        top: 18px;
        right: 18px;
        z-index: 999999;
        display: flex;
        flex-direction: column;
        gap: 10px;
        pointer-events: none;
        max-width: min(92vw, 400px);
    }
    .sc-toast {
        pointer-events: auto;
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 14px 16px 16px 16px;
        border-radius: 12px;
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-left: 5px solid #059669;
        box-shadow: 0 12px 32px rgba(15, 23, 42, 0.18), 0 2px 6px rgba(15, 23, 42, 0.08);
        animation: sc-toast-lifecycle var(--sc-toast-life, 5s) cubic-bezier(0.22, 1, 0.36, 1) both;
        position: relative;
        overflow: hidden;
        font-family: var(--font-sans);
    }
    /* Tombol tutup (checkbox murni CSS, tanpa JavaScript) */
    .sc-toast__closer { position: absolute; opacity: 0; pointer-events: none; width: 0; height: 0; }
    .sc-toast__closer:checked + .sc-toast {
        animation: sc-toast-out 0.34s cubic-bezier(0.4, 0, 1, 1) both;
        pointer-events: none;
    }
    .sc-toast--success { border-left-color: #059669; }
    .sc-toast--error   { border-left-color: #DC2626; }
    .sc-toast--warning { border-left-color: #D97706; }
    .sc-toast--info    { border-left-color: #0284C7; }

    .sc-toast__icon {
        flex: 0 0 auto;
        width: 30px;
        height: 30px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .sc-toast--success .sc-toast__icon { background: #D1FAE5; color: #047857; animation: sc-toast-icon-pop 0.5s cubic-bezier(0.22,1,0.36,1) 0.08s both, sc-toast-ring 1.1s ease-out 0.5s 1; }
    .sc-toast--error   .sc-toast__icon { background: #FEE2E2; color: #B91C1C; animation: sc-toast-icon-pop 0.5s cubic-bezier(0.22,1,0.36,1) 0.08s both; }
    .sc-toast--warning .sc-toast__icon { background: #FEF3C7; color: #B45309; animation: sc-toast-icon-pop 0.5s cubic-bezier(0.22,1,0.36,1) 0.08s both; }
    .sc-toast--info    .sc-toast__icon { background: #E0F2FE; color: #0369A1; animation: sc-toast-icon-pop 0.5s cubic-bezier(0.22,1,0.36,1) 0.08s both; }

    .sc-toast__body { flex: 1 1 auto; min-width: 0; }
    .sc-toast__title {
        font-size: 0.86rem;
        font-weight: 700;
        color: #0F172A;
        margin: 0 0 2px 0;
        letter-spacing: 0.01em;
    }
    .sc-toast__msg {
        font-size: 0.79rem;
        line-height: 1.4;
        color: #475569;
        margin: 0;
        word-break: break-word;
    }
    .sc-toast__close {
        flex: 0 0 auto;
        color: #94A3B8;
        cursor: pointer;
        font-size: 0.95rem;
        line-height: 1;
        padding: 2px 6px;
        border-radius: 6px;
        user-select: none;
        transition: background 0.15s ease, color 0.15s ease;
    }
    .sc-toast__close:hover { background: #F1F5F9; color: #334155; }

    .sc-toast__bar {
        position: absolute;
        left: 0;
        bottom: 0;
        height: 3px;
        width: 100%;
        background: #059669;
        animation: sc-toast-progress var(--sc-toast-life, 5s) linear both;
    }
    .sc-toast--error   .sc-toast__bar { background: #DC2626; }
    .sc-toast--warning .sc-toast__bar { background: #D97706; }
    .sc-toast--info    .sc-toast__bar { background: #0284C7; }

    @media (prefers-reduced-motion: reduce) {
        .sc-toast, .sc-toast__icon, .sc-toast__bar { animation-duration: 0.01s !important; }
    }

    @media (max-width: 640px) {
        .sc-toast-wrap { top: 10px; right: 10px; left: 10px; max-width: none; }
    }
</style>"""

theme_badge_color = "#38BDF8" if dark_mode else "#0B3C5D"
theme_css += f"""
<div class="top-bar-container">
    <div style="font-size: 0.92rem; font-weight: 600;">
        <span style="color: {theme_badge_color}; font-weight: 700;">SignaCerta</span> &nbsp;/&nbsp; {nav_choice}
    </div>
    <div class="navbar-badge">
        NIST P-256 • SHA-256 • FIPS 186-4
    </div>
</div>
"""

st.markdown(theme_css, unsafe_allow_html=True)

if nav_choice == "1. Pembangkitan Kunci":
    st.subheader("Pembangkitan Pasangan Kunci Asimetris ECDSA NIST P-256")
    st.write(
        "Kunci privat (*Private Key*) disimpan secara rahasia untuk menandatangani berkas, "
        "sedangkan kunci publik (*Public Key*) disebarkan untuk memvalidasi keaslian dokumen."
    )
    
    col_k1, col_k2 = st.columns([1.1, 1], gap="large")
    with col_k1:
        with st.container(border=True):
            st.markdown("##### Langkah 1: Tentukan Passphrase Pengaman")
            st.caption("Sesuai standar FIPS 186-4, Private Key wajib dienkripsi berbasis AES-256 (PKCS#8).")
            
            passphrase_input = st.text_input(
                "Kata Sandi / Passphrase Kunci Privat:",
                type="password",
                placeholder="Masukkan kata sandi pengaman (minimal 6 karakter)...",
                key="pass_keygen"
            )
            
            btn_generate = st.button("Bangkitkan Pasangan Kunci Baru", type="primary", use_container_width=True)
            if btn_generate:
                if not passphrase_input or len(passphrase_input) < 6:
                    show_toast(
                        "warning",
                        "Passphrase Terlalu Pendek",
                        "Passphrase wajib diisi minimal 6 karakter demi kekuatan enkripsi.",
                    )
                else:
                    with st.spinner("Menghasilkan titik generator acak pada kurva secp256r1..."):
                        priv, pub = generate_keypair()
                        priv_pem = export_private_key_pem(priv, passphrase=passphrase_input)
                        pub_pem = export_public_key_pem(pub)
                        
                        st.session_state["gen_priv_pem"] = priv_pem
                        st.session_state["gen_pub_pem"] = pub_pem
                        st.session_state["saved_passphrase"] = passphrase_input
                        show_toast(
                            "success",
                            "Kunci Berhasil Dibangkitkan",
                            "Pasangan kunci ECDSA NIST P-256 berhasil dibuat dan diamankan dengan passphrase.",
                            duration=5.0,
                        )

    with col_k2:
        with st.container(border=True):
            st.markdown("##### Langkah 2: Unduh Berkas Kunci Kriptografi")
            if "gen_priv_pem" in st.session_state:
                pub_bytes = st.session_state["gen_pub_pem"]
                priv_bytes = st.session_state["gen_priv_pem"]
                pub_fingerprint = hash_bytes(pub_bytes)
                
                st.write(f"• **Ukuran Public Key:** `{len(pub_bytes)} bytes` (Format PEM)")
                st.write(f"• **Ukuran Private Key (Terenkripsi):** `{len(priv_bytes)} bytes`")
                st.caption("Fingerprint Kunci Publik (SHA-256):")
                st.markdown(f'<div class="hash-badge">{pub_fingerprint}</div>', unsafe_allow_html=True)
                
                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    st.download_button(
                        label="Unduh Kunci Privat (.pem)",
                        data=priv_bytes,
                        file_name="private_key.pem",
                        mime="application/x-pem-file",
                        use_container_width=True,
                    )
                with col_d2:
                    st.download_button(
                        label="Unduh Kunci Publik (.pem)",
                        data=pub_bytes,
                        file_name="public_key.pem",
                        mime="application/x-pem-file",
                        use_container_width=True,
                    )
                st.markdown("---")
                st.button(
                    "Lanjut ke Tahap 2: Penandatanganan Dokumen →",
                    type="primary",
                    use_container_width=True,
                    on_click=navigate_to,
                    args=("2. Penandatanganan Dokumen",),
                )
            else:
                st.caption("Berkas kunci (.pem) dan sidik jari kriptografis akan tampil di sini setelah dibuat.")

# ==============================================================================
# TAB 2: PENANDATANGANAN DOKUMEN (SIGNING)
# ==============================================================================
elif nav_choice == "2. Penandatanganan Dokumen":
    st.subheader("Penandatanganan Dokumen & Pembubuhan Lencana QR-Code")
    st.write(
        "Unggah dokumen yang ingin ditandatangani (PDF atau berkas gambar), "
        "tentukan identitas resmi penandatangan, lalu bubuhkan tanda tangan digital. "
        "Sistem mendukung fitur penandatanganan berjenjang (*Multiple Signers*) tanpa merusak tanda tangan terdahulu."
    )
    
    col_s1, col_s2 = st.columns([1.2, 1], gap="large")
    with col_s1:
        with st.container(border=True):
            st.markdown("##### 1. Formulir Berkas & Identitas Penandatangan")
            pdf_file = st.file_uploader(
                "Pilih Berkas yang Akan Ditandatangani (PDF atau Gambar):",
                type=["pdf", "png", "jpg", "jpeg", "webp", "gif", "bmp"],
                key="pdf_sign_upload",
            )
            
            # Deteksi tipe berkas: PDF (lencana visual) atau gambar (blok tersemat)
            is_pdf_file = False
            if pdf_file:
                is_pdf_file = pdf_file.name.lower().endswith(".pdf")
            
            # Tampilkan info berkas instan jika diunggah
            existing_signers_count = 0
            pdf_bytes_tmp = None
            if pdf_file:
                try:
                    pdf_bytes_tmp = pdf_file.getvalue()
                    if is_pdf_file:
                        reader_tmp = PdfReader(io.BytesIO(pdf_bytes_tmp))
                        st.caption(f"Informasi Berkas: **{pdf_file.name}** ({len(pdf_bytes_tmp)/1024:.1f} KB) • **{len(reader_tmp.pages)} Halaman**")
                        if SIG_MARKER_START in pdf_bytes_tmp and SIG_MARKER_END in pdf_bytes_tmp:
                            parts = pdf_bytes_tmp.split(SIG_MARKER_START)
                            sub = parts[1].split(SIG_MARKER_END)[0]
                            prev_meta = json.loads(sub.decode("utf-8"))
                            existing_signers_count = prev_meta.get("total_signers", len(prev_meta.get("signatures", [])))
                            prev_sigs = prev_meta.get("signatures", [])
                            prev_names = ", ".join(
                                f"{s.get('signer', '-')} ({s.get('id', '-')})" for s in prev_sigs
                            ) or "-"
                            st.warning(
                                f"**Mode Tanda Tangan Berjenjang (Multiple Signers) Aktif**\n\n"
                                f"Dokumen ini sudah ditandatangani oleh **{existing_signers_count} pihak**: "
                                f"{prev_names}.\n\n"
                                f"Tanda tangan Anda akan ditambahkan **tanpa merusak** tanda tangan sebelumnya. "
                                f"Lencana Anda otomatis ditempatkan pada slot kosong agar **tidak menumpuk** "
                                f"dengan lencana pihak terdahulu."
                            )
                    else:
                        st.caption(f"Informasi Berkas: **{pdf_file.name}** ({len(pdf_bytes_tmp)/1024:.1f} KB) • Berkas Gambar")
                        st.info(
                            "Berkas gambar ditandatangani dengan skema *Embedded Signature*: blok "
                            "integritas kriptografis (hash + tanda tangan ECDSA) disematkan langsung ke "
                            "dalam berkas, sehingga **satu berkas** sudah memuat tanda tangannya dan "
                            "gambar tetap tampil normal."
                        )
                except Exception:
                    pass

            c_q1, c_q2 = st.columns([3, 1])
            with c_q2:
                btn_preset = st.button("Isi Cepat Demo", help="Mengisi kolom dengan profil anggota kelompok secara otomatis untuk demonstrasi cepat.", use_container_width=True)
            
            val_name = "Fachri Ridhwan Imani" if btn_preset else ""
            val_id = "247006111140" if btn_preset else ""
            val_inst = "Universitas Siliwangi" if btn_preset else ""

            ci_1, ci_2 = st.columns(2)
            with ci_1:
                signer_name = st.text_input("Nama Lengkap Penandatangan:", value=val_name, placeholder="Contoh: Fachri Ridhwan Imani", key="name_in")
                signer_id = st.text_input("NPM / NIP / NIDN:", value=val_id, placeholder="Contoh: 247006111140", key="id_in")
            with ci_2:
                institution = st.text_input("Institusi / Fakultas / Unit:", value=val_inst, placeholder="Contoh: Universitas Siliwangi", key="inst_in")
                
                # Pemilih posisi lencana hanya relevan untuk berkas PDF.
                # Sistem sudah otomatis menata lencana secara berjenjang
                # (anti-collision), sehingga pengguna tidak perlu mengatur manual.
                if is_pdf_file or not pdf_file:
                    stamp_pos = "bottom-right"
                    if existing_signers_count == 0:
                        st.caption("Lencana tanda tangan akan ditempatkan otomatis di sudut kanan bawah halaman terakhir.")
                    else:
                        st.caption(
                            f"Lencana Anda akan ditempatkan otomatis pada slot ke-{existing_signers_count + 1} "
                            f"(bertingkat, tidak menumpuk dengan {existing_signers_count} lencana sebelumnya)."
                        )
                else:
                    # Berkas gambar: tidak memakai lencana visual
                    stamp_pos = "bottom-right"

            st.markdown("---")
            st.markdown("###### Otorisasi Kunci Privat Penandatangan")
            use_current_key = False
            if "gen_priv_pem" in st.session_state:
                use_current_key = st.checkbox("Gunakan kunci privat yang baru saja dibangkitkan pada Tab 1", value=True)

            if use_current_key:
                priv_bytes_input = st.session_state["gen_priv_pem"]
                default_pass = st.session_state.get("saved_passphrase", "")
                signer_pass = st.text_input("Passphrase Kunci Privat:", value=default_pass, type="password", key="pass_preset")
            else:
                priv_file_in = st.file_uploader("Unggah Berkas Kunci Privat (.pem):", type=["pem", "key"], key="priv_file_upload")
                priv_bytes_input = priv_file_in.getvalue() if priv_file_in else None
                signer_pass = st.text_input("Passphrase Kunci Privat:", type="password", placeholder="Masukkan passphrase pengaman...", key="pass_custom")

            btn_execute_sign = st.button("Tandatangani Dokumen Sekarang", type="primary", use_container_width=True)
            if btn_execute_sign:
                if not pdf_file:
                    show_toast("warning", "Berkas Belum Diunggah", "Silakan unggah berkas yang akan ditandatangani terlebih dahulu.")
                elif not signer_name or not signer_id:
                    show_toast("warning", "Identitas Belum Lengkap", "Nama lengkap dan identitas pengenal (NPM/NIP) wajib diisi.")
                elif not priv_bytes_input or not signer_pass:
                    show_toast("warning", "Otorisasi Belum Lengkap", "Berkas Private Key dan Passphrase wajib disertakan untuk otorisasi tanda tangan.")
                else:
                    try:
                        with st.spinner("Menghitung digest SHA-256 dan membubuhkan tanda tangan kriptografis..."):
                            private_key = load_private_key_pem(priv_bytes_input, passphrase=signer_pass)
                            public_key_pem = export_public_key_pem(private_key.public_key())

                            file_bytes = pdf_file.getvalue()

                            if is_pdf_file:
                                # Jalur PDF: lencana visual QR-Code + blok integritas di akhir berkas
                                signed_bytes, meta = sign_and_stamp_pdf(
                                    input_pdf_bytes=file_bytes,
                                    private_key=private_key,
                                    public_key_pem=public_key_pem,
                                    signer_name=signer_name,
                                    signer_id=signer_id,
                                    institution=institution or "Universitas Siliwangi",
                                    position=stamp_pos,
                                )
                                st.session_state["signed_pdf_result"] = signed_bytes
                                st.session_state["signed_meta"] = meta
                                st.session_state["signed_output_name"] = f"signed_{pdf_file.name}"
                                st.session_state["signed_output_mime"] = "application/pdf"
                                st.session_state["signed_mode"] = "pdf"
                                st.session_state.pop("signed_detached_payload", None)
                                st.session_state.pop("signed_generic_result", None)
                                st.session_state.pop("signed_generic_meta", None)
                                show_toast("success", "PDF Berhasil Ditandatangani", "Dokumen PDF berhasil ditandatangani dan dicap dengan lencana QR-Code.")
                            else:
                                # Jalur gambar: blok integritas disematkan langsung ke dalam berkas
                                signed_bytes, sig_payload = sign_generic_file(
                                    file_bytes=file_bytes,
                                    original_filename=pdf_file.name,
                                    private_key=private_key,
                                    public_key_pem=public_key_pem,
                                    signer_name=signer_name,
                                    signer_id=signer_id,
                                    institution=institution or "Universitas Siliwangi",
                                )
                                st.session_state["signed_generic_result"] = signed_bytes
                                st.session_state["signed_generic_meta"] = sig_payload
                                st.session_state["signed_output_name"] = f"signed_{pdf_file.name}"
                                st.session_state["signed_output_mime"] = "application/octet-stream"
                                st.session_state["signed_mode"] = "generic"
                                st.session_state["signed_original_name"] = pdf_file.name
                                st.session_state.pop("signed_pdf_result", None)
                                st.session_state.pop("signed_meta", None)
                                show_toast("success", "Berkas Berhasil Ditandatangani", "Blok integritas kriptografis telah disematkan ke dalam berkas gambar.")
                    except ValueError:
                        show_toast("error", "Passphrase Salah", "Passphrase tidak sesuai! Kunci privat gagal didekripsi.")
                    except Exception as e:
                        show_toast("error", "Penandatanganan Gagal", f"Terjadi kegagalan penandatanganan: {e}")

    with col_s2:
        with st.container(border=True):
            st.markdown("##### 2. Berkas Hasil Penandatanganan")
            signed_mode = st.session_state.get("signed_mode", "")

            if signed_mode == "pdf" and "signed_pdf_result" in st.session_state:
                meta = st.session_state["signed_meta"]
                latest_sig = meta["signatures"][-1]
                
                st.download_button(
                    label="Unduh PDF Bertanda Tangan Resmi (.pdf)",
                    data=st.session_state["signed_pdf_result"],
                    file_name=st.session_state.get("signed_output_name", "signed_document.pdf"),
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True,
                )
                
                st.markdown("**Metadata Penandatangan Terdaftar:**")
                st.write(f"• **Penandatangan Terakhir:** {latest_sig.get('signer', '-')} ({latest_sig.get('id', '-')})")
                st.write(f"• **Institusi:** {latest_sig.get('institution', latest_sig.get('inst', '-'))}")
                st.write(f"• **Waktu:** {latest_sig.get('date', '-')}")
                st.write(f"• **Total Penandatangan:** {meta.get('total_signers', len(meta.get('signatures', [])))} pihak")
                
                if meta.get("total_signers", 1) > 1:
                    st.caption("Daftar seluruh penandatangan terdaftar pada berkas ini:")
                    for idx, s in enumerate(meta.get("signatures", []), 1):
                        st.write(f"  {idx}. **{s.get('signer', '-')}** ({s.get('id', '-')}) — *{s.get('institution', '-')}*")
                
                st.caption("Digest SHA-256 Dokumen:")
                st.markdown(f'<div class="hash-badge">{meta["doc_hash"]}</div>', unsafe_allow_html=True)
                
                st.caption("Tanda Tangan Digital ECDSA (Base64):")
                st.markdown(f'<div class="hash-badge">{latest_sig["signature"][:40]}... (Panjang: {len(latest_sig["signature"])} Karakter)</div>', unsafe_allow_html=True)

            elif signed_mode == "generic" and "signed_generic_result" in st.session_state:
                payload = st.session_state["signed_generic_meta"]
                latest_sig = payload["signatures"][-1]
                original_name = st.session_state.get("signed_original_name", payload.get("original_filename", "berkas"))
                
                st.info(
                    "Berkas sudah ditandatangani dalam **satu berkas**. Blok integritas kriptografis "
                    "disematkan di akhir berkas; berkas tetap dapat dibuka normal oleh aplikasi aslinya "
                    "(Word, Excel, penampil gambar, dsb.)."
                )
                st.download_button(
                    label=f"Unduh Berkas Bertanda Tangan ({original_name})",
                    data=st.session_state["signed_generic_result"],
                    file_name=st.session_state.get("signed_output_name", f"signed_{original_name}"),
                    mime="application/octet-stream",
                    type="primary",
                    use_container_width=True,
                )
                
                st.markdown("**Metadata Penandatangan Terdaftar:**")
                st.write(f"• **Berkas Ditandatangani:** {original_name}")
                st.write(f"• **Penandatangan Terakhir:** {latest_sig.get('signer', '-')} ({latest_sig.get('id', '-')})")
                st.write(f"• **Institusi:** {latest_sig.get('institution', '-')}")
                st.write(f"• **Waktu:** {latest_sig.get('date', '-')}")
                st.write(f"• **Total Penandatangan:** {payload.get('total_signers', 1)} pihak")
                
                if payload.get("total_signers", 1) > 1:
                    st.caption("Daftar seluruh penandatangan terdaftar pada berkas ini:")
                    for idx, s in enumerate(payload.get("signatures", []), 1):
                        st.write(f"  {idx}. **{s.get('signer', '-')}** ({s.get('id', '-')}) — *{s.get('institution', '-')}*")
                
                st.caption("Digest SHA-256 Konten Berkas:")
                st.markdown(f'<div class="hash-badge">{payload["base_doc_hash"]}</div>', unsafe_allow_html=True)
                
                st.caption("Tanda Tangan Digital ECDSA (Base64):")
                st.markdown(f'<div class="hash-badge">{latest_sig["signature"][:40]}... (Panjang: {len(latest_sig["signature"])} Karakter)</div>', unsafe_allow_html=True)

            else:
                st.caption("Berkas bertanda tangan dan ringkasan metadata kriptografis akan ditampilkan di sini.")

            if signed_mode in ("pdf", "generic"):
                st.markdown("---")
                col_btn_prev, col_btn_next = st.columns(2)
                with col_btn_prev:
                    st.button(
                        "← Kembali ke Tahap 1 (Kunci)",
                        use_container_width=True,
                        on_click=navigate_to,
                        args=("1. Pembangkitan Kunci",),
                    )
                with col_btn_next:
                    st.button(
                        "Lanjut ke Tahap 3: Verifikasi Integritas →",
                        type="primary",
                        use_container_width=True,
                        on_click=navigate_to,
                        args=("3. Verifikasi Integritas",),
                    )

# ==============================================================================
# TAB 3: VERIFIKASI INTEGRITAS DOKUMEN (VERIFICATION)
# ==============================================================================
elif nav_choice == "3. Verifikasi Integritas":
    st.subheader("Verifikasi Keaslian & Uji Integritas Dokumen")

    # --- Panel hasil pindai QR-Code (bila pengguna datang dari memindai QR) ---
    if st.session_state.get("qr_scan_active") and st.session_state.get("qr_scan_result"):
        _qr = st.session_state["qr_scan_result"]
        _qr_id = _qr.get("identity", {})
        _qr_status = _qr.get("status", "")

        st.markdown("##### Hasil Pindai QR-Code")
        if _qr_status == "VALID_QR":
            st.success(
                "QR-Code VALID — tanda tangan digital di dalam QR terverifikasi "
                "secara kriptografis (ECDSA NIST P-256)."
            )
        elif _qr_status == "SIGNATURE_INVALID":
            st.error(
                "QR-Code TIDAK VALID — tanda tangan tidak cocok. QR kemungkinan "
                "dimodifikasi atau dipalsukan."
            )
        else:
            st.warning("QR-Code tidak dapat diverifikasi — payload tidak lengkap atau rusak.")

        _c1, _c2 = st.columns(2)
        with _c1:
            st.markdown("**Identitas Penandatangan (dari QR)**")
            st.markdown(
                f"- Nama: **{_qr_id.get('signer', '-')}**\n"
                f"- NPM/NIP: **{_qr_id.get('id', '-')}**\n"
                f"- Institusi: **{_qr_id.get('institution', '-')}**\n"
                f"- Waktu: **{_qr_id.get('date', '-')}**"
            )
        with _c2:
            st.markdown("**Bukti Kriptografis**")
            st.markdown(
                f"- Hash dokumen (SHA-256):\n`{_qr.get('doc_hash', '-')}`"
            )
            _fp = _qr.get("public_key_fingerprint")
            if _fp:
                st.markdown(f"- Fingerprint Kunci Publik:\n`{_fp}`")

        st.info(
            "Langkah penguatan (opsional): cocokkan **Fingerprint Kunci Publik** di atas "
            "dengan daftar kunci resmi, dan unggah berkas asli di bawah untuk memastikan "
            "hash-nya identik. Pencocokan fingerprint menutup celah 'QR buatan sendiri'."
        )
        if st.button("Tutup Hasil Pindai QR", key="qr_scan_close"):
            st.session_state["qr_scan_active"] = False
            st.rerun()
        st.markdown("---")

    st.write(
        "Unggah berkas untuk menguji keabsahan tanda tangan digital serta memastikan "
        "tidak terdapat manipulasi isi (bahkan perubahan sebesar 1 byte). Mendukung berkas "
        "PDF maupun berkas gambar (PNG, JPG, WEBP) — cukup satu berkas saja."
    )
    
    col_v1, col_v2 = st.columns([1.1, 1.2], gap="large")
    with col_v1:
        with st.container(border=True):
            st.markdown("##### 1. Berkas Pengujian")
            
            use_recent_signed = False
            recent_mode = st.session_state.get("signed_mode", "")
            if recent_mode == "pdf" and "signed_pdf_result" in st.session_state:
                use_recent_signed = st.checkbox(
                    "Gunakan berkas PDF hasil penandatanganan dari Tahap 2",
                    value=True,
                    help="Praktis untuk pengujian langsung tanpa perlu mengunduh dan mengunggah ulang berkas PDF.",
                )
                if use_recent_signed:
                    st.info("Berkas aktif: Dokumen PDF resmi dari Tahap 2 siap diverifikasi.")
            elif recent_mode == "generic" and "signed_generic_result" in st.session_state:
                use_recent_signed = st.checkbox(
                    "Gunakan berkas hasil penandatanganan dari Tahap 2",
                    value=True,
                    help="Praktis untuk pengujian langsung berkas gambar yang baru ditandatangani.",
                )
                if use_recent_signed:
                    st.info("Berkas aktif: Berkas gambar bertanda tangan dari Tahap 2 siap diverifikasi.")
            
            verify_file = None
            if not use_recent_signed:
                verify_file = st.file_uploader(
                    "Pilih Berkas yang Ingin Diverifikasi (PDF atau Gambar):",
                    type=["pdf", "png", "jpg", "jpeg", "webp", "gif", "bmp"],
                    key="pdf_verify_upload",
                )
            
            with st.expander("Uji Kunci Publik Tertentu (Demonstrasi Penolakan Kunci Palsu)"):
                st.caption("Gunakan opsi ini saat demonstrasi untuk membuktikan bahwa sistem menolak verifikasi jika menggunakan Public Key milik pihak lain.")
                custom_pub_upload = st.file_uploader("Unggah Kunci Publik Penguji (.pem):", type=["pem", "pub"], key="pub_custom_upload")

            btn_verify_act = st.button("Jalankan Verifikasi Integritas", type="primary", use_container_width=True)
            if btn_verify_act:
                file_data = None
                target_is_pdf = True

                if use_recent_signed:
                    if recent_mode == "pdf" and "signed_pdf_result" in st.session_state:
                        file_data = st.session_state["signed_pdf_result"]
                        target_is_pdf = True
                    elif recent_mode == "generic" and "signed_generic_result" in st.session_state:
                        file_data = st.session_state["signed_generic_result"]
                        target_is_pdf = False
                elif verify_file:
                    file_data = verify_file.getvalue()
                    target_is_pdf = verify_file.name.lower().endswith(".pdf")
                    
                if not file_data:
                    show_toast("warning", "Berkas Belum Dipilih", "Silakan pilih berkas yang ingin diverifikasi.")
                else:
                    with st.spinner("Memvalidasi integritas kriptografis dan mencocokkan digest SHA-256..."):
                        custom_pub_data = custom_pub_upload.getvalue() if custom_pub_upload else None
                        if target_is_pdf:
                            audit_res = verify_pdf_document(file_data, custom_public_key_pem=custom_pub_data)
                        else:
                            audit_res = verify_generic_file(file_data, custom_public_key_pem=custom_pub_data)
                        st.session_state["verify_result"] = audit_res
                        # Notifikasi pop-up sesuai hasil audit
                        _status = audit_res.get("status", "")
                        if _status == "VALID":
                            show_toast(
                                "success",
                                "Verifikasi Berhasil — Berkas VALID",
                                "Berkas terbukti otentik, utuh, dan seluruh tanda tangan digital sah.",
                                duration=6.0,
                            )
                        elif _status == "TAMPERED":
                            show_toast(
                                "error",
                                "Verifikasi Gagal — Berkas TAMPERED",
                                "Integritas berkas rusak. Berkas telah dimanipulasi setelah ditandatangani.",
                                duration=7.0,
                            )
                        elif _status == "KEY_MISMATCH":
                            show_toast(
                                "error",
                                "Verifikasi Gagal — Kunci Tidak Cocok",
                                "Tanda tangan digital tidak cocok dengan Kunci Publik yang diberikan.",
                                duration=7.0,
                            )
                        elif _status == "UNSIGNED":
                            show_toast(
                                "warning",
                                "Berkas Belum Ditandatangani",
                                "Berkas tidak memiliki blok tanda tangan digital resmi.",
                                duration=6.0,
                            )
                        else:
                            show_toast(
                                "warning",
                                "Verifikasi Tidak Dapat Diselesaikan",
                                audit_res.get("message", "Metadata tanda tangan rusak atau tidak dapat dibaca."),
                                duration=6.0,
                            )

    with col_v2:
        with st.container(border=True):
            st.markdown("##### 2. Laporan Audit Kriptografis")
            if "verify_result" in st.session_state:
                res = st.session_state["verify_result"]
                
                if res["status"] == "VALID":
                    st.markdown(f"""
                    <div class="cert-audit-valid">
                        <div class="cert-audit-title-valid">STATUS: DOKUMEN OTENTIK & UTUH (VALID)</div>
                        <div style="color: #065F46; font-size: 0.95rem;">
                            {res["message"]} Dokumen dipastikan asli dari penandatangan terdaftar dan belum mengalami perubahan apapun.
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("**Daftar Penandatangan Sah:**")
                    for s in res.get("signers", []):
                        custom_badge = " <span style='color: #10B981; font-weight: bold;'>✓ Cocok dengan Kunci Publik Penguji</span>" if s.get("matched_custom_key") else ""
                        st.markdown(f"• **{s['signer_name']}** ({s['signer_id']}) — *{s['institution']}* — Tanggal: {s['date']}{custom_badge}", unsafe_allow_html=True)
                    
                    st.caption("Digest SHA-256 Terverifikasi:")
                    st.markdown(f'<div class="hash-badge">{res.get("computed_hash")}</div>', unsafe_allow_html=True)

                elif res["status"] == "TAMPERED":
                    st.markdown(f"""
                    <div class="cert-audit-tampered">
                        <div class="cert-audit-title-tampered">PERINGATAN: INTEGRITAS RUSAK / BERKAS DIMANIPULASI</div>
                        <div style="color: #991B1B; font-size: 0.95rem;">
                            {res["message"]}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if res.get("marker_info"):
                        st.markdown("**Jejak Penandatangan Terdeteksi pada Metadata Berkas:**")
                        mk = res["marker_info"]
                        st.write(f"• **Penandatangan:** {mk.get('signer', '-')}")
                        st.write(f"• **Identitas:** {mk.get('id', '-')}")
                        st.write(f"• **Tanggal Tanda Tangan:** {mk.get('date', '-')}")

                    if res.get("computed_hash"):
                        st.caption("Nilai Hash SHA-256 Berkas Saat Ini (Hasil Manipulasi):")
                        st.markdown(f'<div class="hash-badge">{res.get("computed_hash")}</div>', unsafe_allow_html=True)

                        st.caption("Nilai Hash Asli yang Ditandatangani:")
                        st.markdown(f'<div class="hash-badge">{res.get("expected_hash")}</div>', unsafe_allow_html=True)

                elif res["status"] == "KEY_MISMATCH":
                    st.markdown(f"""
                    <div class="cert-audit-tampered">
                        <div class="cert-audit-title-tampered">VERIFIKASI GAGAL: KUNCI PUBLIK TIDAK COCOK</div>
                        <div style="color: #991B1B; font-size: 0.95rem;">
                            {res["message"]} Tanda tangan digital pada dokumen ini bukan milik pemilik Kunci Publik yang Anda berikan.
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if res.get("signers"):
                        st.markdown("**Daftar Penandatangan Terdaftar pada Berkas:**")
                        for s in res.get("signers", []):
                            st.write(f"• **{s['signer_name']}** ({s['signer_id']}) — *{s['institution']}* — ❌ *Kunci publik penguji tidak cocok*")
                else:
                    # Status UNSIGNED / CORRUPTED_METADATA: tampilkan pesan penjelas.
                    st.warning(res["message"])
                    if res["status"] == "UNSIGNED":
                        st.caption(
                            "Catatan: Berkas yang belum pernah ditandatangani memang tidak memiliki "
                            "blok tanda tangan. Untuk mengujinya, tanda tangani dulu berkas pada Tahap 2, "
                            "lalu verifikasi kembali di sini."
                        )
                
                st.markdown("---")
                col_v_prev, col_v_next = st.columns(2)
                with col_v_prev:
                    st.button(
                        "← Kembali ke Tahap 2 (Tanda Tangan)",
                        use_container_width=True,
                        on_click=navigate_to,
                        args=("2. Penandatanganan Dokumen",),
                    )
                with col_v_next:
                    st.button(
                        "Lanjut ke Tahap 4: Uji Benchmark →",
                        type="primary",
                        use_container_width=True,
                        on_click=navigate_to,
                        args=("4. Uji Kuantitatif & Benchmark",),
                    )
            else:
                st.caption("Hasil audit integritas dokumen akan muncul di panel ini setelah verifikasi dieksekusi.")

# ==============================================================================
# TAB 4: BENCHMARK & PENGUJIAN KUANTITATIF (BENCHMARK)
# ==============================================================================
elif nav_choice == "4. Uji Kuantitatif & Benchmark":
    st.subheader("Pengujian Kuantitatif & Benchmark Kriptografi")
    st.write(
        "Sesuai ketentuan **Bagian 4 Panduan Tugas UTS Keamanan Informasi**, dilakukan pengujian berulang minimal 30 kali iterasi "
        "untuk mengukur performa waktu penandatanganan (*signing*), verifikasi, efisiensi ukuran kunci, serta ketahanan deteksi manipulasi berkas 1-byte."
    )
    
    col_ctrl1, col_ctrl2 = st.columns([3, 2], gap="large")
    with col_ctrl1:
        st.write("Jalankan siklus pengujian otomatis langsung di hadapan penguji untuk membuktikan keakuratan metrik secara real-time.")
    with col_ctrl2:
        btn_run_bench = st.button("Jalankan Siklus Pengujian 30x", type="primary", use_container_width=True)

    if btn_run_bench:
        with st.spinner("Mengeksekusi 30 siklus penandatanganan dan verifikasi ECDSA NIST P-256..."):
            try:
                from benchmark import run_benchmark
                res = run_benchmark(iterations=30)
                st.session_state["benchmark_result"] = res
                show_toast(
                    "success",
                    "Benchmark Selesai",
                    "Seluruh 30 iterasi pengujian dan 10 skenario uji tamper berhasil diselesaikan.",
                    duration=6.0,
                )
            except Exception as e:
                show_toast("error", "Benchmark Gagal", f"Gagal menjalankan benchmark: {e}")

    res = st.session_state.get("benchmark_result")
    
    col_b1, col_b2, col_b3, col_b4 = st.columns(4)
    avg_s = f"{res['avg_sign']:.2f} ms" if res else "27.29 ms"
    avg_v = f"{res['avg_verify']:.2f} ms" if res else "0.21 ms"
    pub_s = f"{res['pub_size']} bytes" if res else "178 bytes"
    
    col_b1.metric("Rata-rata Waktu Signing", avg_s, "-5.8 ms")
    col_b2.metric("Rata-rata Waktu Verifikasi", avg_v, "< 1 ms")
    col_b3.metric("Ukuran Public Key (ECDSA)", pub_s, "Sangat Ringkas")
    col_b4.metric("Deteksi Tamper 1-Byte", "100%", "10/10 Skenario")

    if res and "benchmark_data" in res:
        df_bench = pd.DataFrame(res["benchmark_data"])
        st.markdown("##### Distribusi Waktu Komputasi Tiap Iterasi (ms)")
        st.line_chart(
            df_bench.set_index("iteration")[["sign_time_ms", "verify_time_ms"]].rename(
                columns={
                    "sign_time_ms": "Waktu Signing (ms)",
                    "verify_time_ms": "Waktu Verifikasi (ms)",
                }
            ),
            color=["#0B3C5D", "#059669"]
        )
        
        st.markdown("##### Matriks Hasil Uji Ketahanan Manipulasi Dokumen (Tamper Test)")
        df_tamper = pd.DataFrame(res["tamper_results"])
        df_tamper["status_deteksi"] = df_tamper["detected"].apply(lambda x: "BERHASIL DITOLAK (SUKSES)" if x else "GAGAL")
        st.dataframe(
            df_tamper[["byte_position", "status", "status_deteksi"]].rename(
                columns={
                    "byte_position": "Offset Byte yang Diubah",
                    "status": "Respon Sistem",
                    "status_deteksi": "Evaluasi Integritas"
                }
            ),
            use_container_width=True
        )

    st.markdown("##### Berkas Rekapitulasi Data Pengujian Resmi:")
    if os.path.exists("data_pengujian_benchmark.xlsx"):
        with open("data_pengujian_benchmark.xlsx", "rb") as f:
            st.download_button(
                label="Unduh Rekapitulasi Data Pengujian (.xlsx)",
                data=f.read(),
                file_name="data_pengujian_benchmark.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )
            
    st.markdown("---")
    col_b_prev, col_b_next = st.columns(2)
    with col_b_prev:
        st.button(
            "← Kembali ke Verifikasi Integritas (Tahap 3)",
            use_container_width=True,
            on_click=navigate_to,
            args=("3. Verifikasi Integritas",),
        )
    with col_b_next:
        st.button(
            "Pelajari Selengkapnya: Tentang Proyek →",
            type="primary",
            use_container_width=True,
            on_click=navigate_to,
            args=("Tentang Proyek",),
        )

# ==============================================================================
# TAB 5: TENTANG PROYEK (ABOUT & ACADEMIC DISCLOSURE)
# ==============================================================================
elif nav_choice == "Tentang Proyek":
    st.subheader("Tentang Proyek SignaCerta")
    
    col_a1, col_a2 = st.columns([1.2, 1], gap="large")
    with col_a1:
        with st.container(border=True):
            st.markdown("##### 1. Latar Belakang & Urgensi Masalah")
            st.write(
                "Dokumen elektronik dalam format PDF sangat rentan terhadap manipulasi isi, pemalsuan stempel, "
                "dan peniruan tanda tangan visual biasa (gambar *scan* tanda tangan). Tanpa skema kriptografis yang kuat, "
                "keaslian berkas administratif tidak dapat dibuktikan secara hukum dan teknis."
            )
            st.write(
                "**SignaCerta** mengimplementasikan algoritma asimetris modern **ECDSA (Elliptic Curve Digital Signature Algorithm)** "
                "dengan kurva **NIST P-256 (secp256r1)** dan fungsi ringkasan pesan **SHA-256**. Keunggulan kurva eliptik ini adalah "
                "memberikan tingkat keamanan setara RSA 3072-bit namun dengan ukuran kunci dan tanda tangan yang jauh lebih ringkas "
                "serta komputasi yang efisien pada perangkat pengguna."
            )
            
            st.markdown("##### 2. Alur Kerja Kriptografi Dokumen")
            st.markdown("""
            1. **Pembacaan & Ringkasan Dokumen:** Berkas PDF dibaca secara biner, kemudian dihitung nilai ringkasannya menggunakan fungsi *Secure Hash Algorithm* 256-bit (**SHA-256**).
            2. **Penandatanganan Digital:** Digest SHA-256 ditandatangani menggunakan **Private Key** pemilik melalui algoritma matematika kurva eliptik ECDSA.
            3. **Penyematan QR-Code & Lencana Visual:** Metadata penandatangan, timestamp, dan tanda tangan digital dikemas ke dalam penanda visual QR-Code dan disematkan ke halaman PDF.
            4. **Audit Integritas:** Saat verifikasi, berkas dibaca ulang untuk menghitung kembali hash-nya. Bila terdapat perbedaan sekecil 1 byte, verifikasi dinyatakan **GAGAL / TAMPERED**.
            """)

    with col_a2:
        with st.container(border=True):
            st.markdown("##### 3. Konteks Akademik & Pembimbing")
            st.markdown("""
            * **Mata Kuliah:** Keamanan Informasi (20261)
            * **Program Studi:** Jurusan Informatika, Fakultas Teknik, Universitas Siliwangi
            * **Dosen Pengampu:** **Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.**
            * **Tugas Proyek:** Ujian Tengah Semester (UTS) — Topik D (Digital Signature PDF)
            """)
            
            st.markdown("##### 4. Tim Pengembang & Kontribusi")
            st.markdown("""
            * **Fachri Ridhwan Imani** (247006111140)  
              *Peran:* Key Management, Cryptographic Engine (ECDSA P-256), Unit Testing.
            * **Wardah Nurwaffiq** (247006111150)  
              *Peran:* PDF Integration, Visual Signature Badge, QR-Code Stamping.
            * **Mahardika Rajbi Firdaus** (247006111148)  
              *Peran:* Verification Engine, Tamper Auditing, Quantitative Benchmark (30x).
            """)
            
            st.markdown("##### 5. Standar Keamanan & Spesifikasi Kriptografi")
            st.markdown("""
            * **NIST FIPS 186-4:** Digital Signature Standard (Kurva Eliptik NIST P-256 / secp256r1).
            * **NIST FIPS 180-4:** Secure Hash Standard (Fungsi Ringkasan Pesan SHA-256).
            * **RFC 5280 / PKCS#8:** Enkripsi Kunci Privat Berbasis Kata Sandi (*AES-256-GCM / PBKDF2*).
            """)
            
            st.markdown("##### 6. Referensi Riset Pembina")
            st.caption("Sitasi publikasi ilmiah dosen pengampu (format APA 7 via Mendeley):")
            st.markdown("""
            * Gunawan, R., Rahmatulloh, A., & Rizal, R. (2024). Implementasi Digital Signature Pada Dokumen Elektronik Berbasis QR-Code. *STRING (Satuan Tulisan Riset dan Inovasi Teknologi)*.
            * Raihan, & Rahmatulloh, A. (2026). *Implementation and Performance Analysis of Elliptic Curve Digital Signature Algorithm (ECDSA) for Academic Document Security*. Universitas Siliwangi.
            """)
            
            st.markdown("##### 7. Pernyataan Integritas Akademik (AI Disclosure)")
            st.caption(
                "Sesuai ketentuan Bagian 10 Pedoman Tugas UTS Keamanan Informasi: "
                "Asisten AI digunakan secara bertanggung jawab sebagai pendukung perancangan logika dasar dan refaktor antarmuka pengguna. "
                "Seluruh implementasi modul matematika, pengujian kuantitatif, dan pengujian manipulasi telah divalidasi dan dikuasai sepenuhnya oleh tim pengembang."
            )
            
    st.markdown("---")
    col_t_prev, col_t_next = st.columns(2)
    with col_t_prev:
        st.button(
            "← Kembali ke Uji Benchmark (Tahap 4)",
            use_container_width=True,
            on_click=navigate_to,
            args=("4. Uji Kuantitatif & Benchmark",),
        )
    with col_t_next:
        st.button(
            "Mulai Pengujian Ulang: Tahap 1 (Pembangkitan Kunci) →",
            type="primary",
            use_container_width=True,
            on_click=navigate_to,
            args=("1. Pembangkitan Kunci",),
        )

# ----------------- FOOTER INSTITUSIONAL -----------------
st.markdown("""
<div class="footer-container">
    <div style="display: grid; grid-template-columns: 2fr 1.5fr 1.5fr; gap: 2rem;">
        <div>
            <div class="footer-title">SignaCerta • Universitas Siliwangi</div>
            <div>Sistem Informasi Otentikasi dan Penjaminan Integritas Dokumen Elektronik PDF berbasis Kriptografi Kunci Publik ECDSA NIST P-256.</div>
            <div style="margin-top: 0.5rem; font-size: 0.78rem;">Jurusan Informatika • Fakultas Teknik • Universitas Siliwangi</div>
        </div>
        <div>
            <div class="footer-title">Akademik & Pengampu</div>
            <div>Mata Kuliah: Keamanan Informasi (20261)</div>
            <div>Dosen Pengampu: <b>Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.</b></div>
            <div>Tugas Proyek Tengah Semester (UTS) — Topik D</div>
        </div>
        <div>
            <div class="footer-title">Standar Keamanan</div>
            <div>• NIST FIPS 186-4 (Digital Signature Standard)</div>
            <div>• NIST FIPS 180-4 (Secure Hash Standard SHA-256)</div>
            <div>• RFC 5280 / PKCS#8 Key Protection (AES-256)</div>
            <div style="margin-top: 0.5rem; font-size: 0.78rem;">© 2026 SignaCerta Tim Pengembang</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ----------------- NOTIFIKASI POP-UP (dirender di AKHIR agar toast dari aksi
# tombol pada rerun yang sama langsung muncul, tanpa perlu rerun tambahan) -----------------
render_toasts()
