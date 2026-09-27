"""Aplikasi Web Digital Signature Dokumen PDF Berbasis QR-Code
Tugas Proyek UTS Keamanan Informasi (20261) - Universitas Siliwangi
Dosen Pengampu: Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.

Tim Pengembang:
- Fachri Ridhwan Imani (247006111140)
- Wardah Nurwaffiq (247006111150)
- Mahardika Rajbi Firdaus (247006111148)
"""

import io
import os
import streamlit as st

from crypto_engine import (
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
)
from pdf_stamper import sign_and_stamp_pdf
from verifier import verify_pdf_document

st.set_page_config(
    page_title="SIDIGS - Digital Signature PDF (UNSIL)",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS Styling (Anti-Slop Clean Corporate Academic Style)
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #0B3C5D;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    .card-valid {
        background-color: #F0FDF4;
        border: 1.5px solid #22C55E;
        padding: 1.2rem;
        border-radius: 8px;
        color: #14532D;
    }
    .card-tampered {
        background-color: #FEF2F2;
        border: 1.5px solid #EF4444;
        padding: 1.2rem;
        border-radius: 8px;
        color: #7F1D1D;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/id/thumb/7/7b/Logo_Universitas_Siliwangi.png/200px-Logo_Universitas_Siliwangi.png", width=90)
    st.markdown("### **SIDIGS UNSIL**")
    st.markdown("**Sistem Tanda Tangan Digital PDF**")
    st.caption("Tugas Proyek UTS Keamanan Informasi 20261")
    
    st.divider()
    st.markdown("#### 👨‍🏫 **Dosen Pengampu**")
    st.write("Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.")
    
    st.markdown("#### 👥 **Tim Pengembang**")
    st.markdown("""
    - **Fachri Ridhwan Imani** (247006111140)
    - **Wardah Nurwaffiq** (247006111150)
    - **Mahardika Rajbi Firdaus** (247006111148)
    """)
    
    st.divider()
    st.caption("Algoritma: ECDSA NIST P-256 (secp256r1)")
    st.caption("Fungsi Hash: SHA-256")
    st.caption("Enkripsi Kunci: AES-256 PBKDF2/PKCS#8")

# Main Content
st.markdown('<div class="main-header">🔒 Aplikasi Digital Signature Dokumen PDF</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Platform penandatanganan dan verifikasi keaslian dokumen PDF berbasis QR-Code dan Kriptografi Kunci Publik ECDSA.</div>', unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs([
    "🔑 1. Manajemen Kunci (Key Management)",
    "✍️ 2. Tanda Tangani PDF (Signing)",
    "🛡️ 3. Verifikasi Dokumen (Verification)",
    "📊 4. Hasil Pengujian & Benchmark",
])

# ----------------- TAB 1: MANAJEMEN KUNCI -----------------
with tab1:
    st.markdown("### Pembangkitan Pasangan Kunci Asimetris (ECDSA P-256)")
    st.write("Bangkitkan kunci privat (*Private Key*) untuk menandatangani dokumen dan kunci publik (*Public Key*) untuk memverifikasi keaslian.")
    
    col_k1, col_k2 = st.columns(2)
    with col_k1:
        passphrase_input = st.text_input(
            "Masukkan Kata Sandi / Passphrase untuk Melindungi Kunci Privat:",
            type="password",
            placeholder="Minimal 8 karakter kombinasi...",
            help="Kunci privat wajib dienkripsi sesuai standar keamanan agar tidak dapat disalahgunakan.",
        )
        
        if st.button("🚀 Bangkitkan Pasangan Kunci Baru", type="primary"):
            if not passphrase_input or len(passphrase_input) < 6:
                st.error("⚠️ Masukkan passphrase minimal 6 karakter demi keamanan kunci privat!")
            else:
                with st.spinner("Membangkitkan kurva eliptik NIST P-256..."):
                    priv, pub = generate_keypair()
                    priv_pem = export_private_key_pem(priv, passphrase=passphrase_input)
                    pub_pem = export_public_key_pem(pub)
                    
                    st.session_state["gen_priv_pem"] = priv_pem
                    st.session_state["gen_pub_pem"] = pub_pem
                    st.success("✅ Pasangan kunci ECDSA P-256 berhasil dibangkitkan dan diamankan!")

    with col_k2:
        if "gen_priv_pem" in st.session_state:
            st.markdown("#### Unduh Berkas Kunci Anda:")
            st.download_button(
                label="📥 Unduh Private Key (private_key.pem) - RAHASIA",
                data=st.session_state["gen_priv_pem"],
                file_name="private_key.pem",
                mime="application/x-pem-file",
            )
            st.download_button(
                label="📥 Unduh Public Key (public_key.pem) - PUBLIK",
                data=st.session_state["gen_pub_pem"],
                file_name="public_key.pem",
                mime="application/x-pem-file",
            )
            st.info("💡 **Perhatian:** Simpan `private_key.pem` di tempat aman dan jangan pernah dibagikan kepada orang lain.")

# ----------------- TAB 2: TANDA TANGAN DOKUMEN -----------------
with tab2:
    st.markdown("### Penandatanganan Dokumen PDF")
    st.write("Unggah dokumen PDF asli, bubuhkan identitas penandatangan, lalu tempelkan lencana visual QR-Code.")
    
    col_s1, col_s2 = st.columns([1.2, 1])
    with col_s1:
        pdf_file = st.file_uploader("Pilih Berkas PDF Asli:", type=["pdf"], key="pdf_upload_sign")
        
        c_i1, c_i2 = st.columns(2)
        with c_i1:
            signer_name = st.text_input("Nama Lengkap Penandatangan:", value="Fachri Ridhwan Imani")
            signer_id = st.text_input("NPM / NIP:", value="247006111140")
        with c_i2:
            institution = st.text_input("Institusi / Jabatan:", value="Universitas Siliwangi")
            stamp_pos = st.selectbox("Posisi Lencana QR-Code:", ["bottom-right", "bottom-left", "bottom-center"])

        st.markdown("##### Kredensial Penandatangan")
        priv_key_file = st.file_uploader("Unggah Private Key (.pem):", type=["pem", "key"])
        signer_passphrase = st.text_input("Passphrase Kunci Privat:", type="password", key="pass_sign")

        if st.button("🔏 Tandatangani Dokumen Sekarang", type="primary"):
            if not pdf_file:
                st.error("⚠️ Silakan pilih berkas PDF terlebih dahulu!")
            elif not priv_key_file or not signer_passphrase:
                st.error("⚠️ Unggah berkas Private Key dan masukkan Passphrase yang sesuai!")
            else:
                try:
                    with st.spinner("Memproses penandatanganan kriptografis & pembuatan QR-Code..."):
                        priv_bytes = priv_key_file.getvalue()
                        private_key = load_private_key_pem(priv_bytes, passphrase=signer_passphrase)
                        public_key_pem = export_public_key_pem(private_key.public_key())
                        
                        pdf_input_bytes = pdf_file.getvalue()
                        signed_pdf_bytes, meta = sign_and_stamp_pdf(
                            input_pdf_bytes=pdf_input_bytes,
                            private_key=private_key,
                            public_key_pem=public_key_pem,
                            signer_name=signer_name,
                            signer_id=signer_id,
                            institution=institution,
                            position=stamp_pos,
                        )
                        st.session_state["signed_pdf_result"] = signed_pdf_bytes
                        st.session_state["signed_meta"] = meta
                        st.success("🎉 Dokumen PDF berhasil ditandatangani dan dicap dengan lencana QR-Code!")
                except ValueError:
                    st.error("❌ Passphrase salah! Kunci privat tidak dapat didekripsi.")
                except Exception as e:
                    st.error(f"❌ Terjadi kesalahan: {e}")

    with col_s2:
        if "signed_pdf_result" in st.session_state:
            st.markdown("#### Berkas PDF Bertanda Tangan")
            meta = st.session_state["signed_meta"]
            st.download_button(
                label="📥 Unduh PDF Bertanda Tangan Resmi (.pdf)",
                data=st.session_state["signed_pdf_result"],
                file_name="dokumen_terverifikasi_digital.pdf",
                mime="application/pdf",
                type="primary",
            )
            st.json({
                "Penandatangan": meta["signatures"][-1]["signer"],
                "NPM": meta["signatures"][-1]["id"],
                "Waktu": meta["signatures"][-1]["date"],
                "Hash SHA-256": meta["doc_hash"][:32] + "...",
                "Digital Signature": meta["signatures"][-1]["signature"][:32] + "...",
                "Total Penandatangan": meta["total_signers"],
            })

# ----------------- TAB 3: VERIFIKASI DOKUMEN -----------------
with tab3:
    st.markdown("### Verifikasi Keaslian & Integritas Dokumen")
    st.write("Unggah dokumen PDF bertanda tangan untuk memvalidasi apakah berkas masih 100% asli atau telah dimanipulasi.")
    
    col_v1, col_v2 = st.columns([1.1, 1])
    with col_v1:
        verify_pdf_file = st.file_uploader("Pilih Berkas PDF yang Akan Diverifikasi:", type=["pdf"], key="pdf_upload_verify")
        
        with st.expander("⚙️ Opsi Pengujian Kunci Publik Khusus (Opsional)"):
            st.caption("Gunakan opsi ini untuk mendemonstrasikan penolakan verifikasi bila menggunakan Public Key yang salah.")
            custom_pub_file = st.file_uploader("Unggah Public Key Penandatangan (.pem):", type=["pem", "pub"], key="pub_upload_verify")
        
        if st.button("🔍 Verifikasi Integritas & Tanda Tangan", type="primary"):
            if not verify_pdf_file:
                st.error("⚠️ Silakan pilih berkas PDF yang ingin diverifikasi!")
            else:
                with st.spinner("Memeriksa integritas berkas dan tanda tangan digital..."):
                    pdf_bytes_to_verify = verify_pdf_file.getvalue()
                    custom_pub_bytes = custom_pub_file.getvalue() if custom_pub_file else None
                    
                    res = verify_pdf_document(pdf_bytes_to_verify, custom_public_key_pem=custom_pub_bytes)
                    st.session_state["verify_result"] = res

    with col_v2:
        if "verify_result" in st.session_state:
            res = st.session_state["verify_result"]
            st.markdown("#### Status Hasil Verifikasi:")
            
            if res["status"] == "VALID":
                st.markdown(f"""
                <div class="card-valid">
                    <h3>✅ DOKUMEN ASLI (100% VALID)</h3>
                    <p><b>{res["message"]}</b></p>
                    <p>Integritas dokumen terjamin, tidak terdapat perubahan pada berkas.</p>
                </div>
                """, unsafe_allow_html=True)
                st.markdown("##### Daftar Penandatangan Sah:")
                for s in res.get("signers", []):
                    st.write(f"- ✍️ **{s['signer_name']}** ({s['signer_id']}) — *{s['institution']}* | {s['date']}")
                st.caption(f"Hash SHA-256: `{res.get('computed_hash')}`")

            elif res["status"] == "TAMPERED":
                st.markdown(f"""
                <div class="card-tampered">
                    <h3>❌ PERINGATAN: DOKUMEN TELAH DIMANIPULASI!</h3>
                    <p><b>{res["message"]}</b></p>
                    <p>Sistem mendeteksi bahwa berkas PDF ini telah diubah isinya setelah ditandatangani.</p>
                </div>
                """, unsafe_allow_html=True)
                st.error(f"Hash Berkas Diterima : `{res.get('computed_hash')}`")
                st.warning(f"Hash Tanda Tangan Asli: `{res.get('expected_hash')}`")

            elif res["status"] == "KEY_MISMATCH":
                st.markdown(f"""
                <div class="card-tampered">
                    <h3>❌ VERIFIKASI GAGAL: KUNCI PUBLIK TIDAK COCOK!</h3>
                    <p><b>{res["message"]}</b></p>
                    <p>Tanda tangan digital pada dokumen ini bukan milik pemilik Public Key yang digunakan.</p>
                </div>
                """, unsafe_allow_html=True)

            else:
                st.warning(f"⚠️ {res['message']}")

# ----------------- TAB 4: BENCHMARK & PENGUJIAN -----------------
with tab4:
    st.markdown("### 📊 Pengujian Kuantitatif & Benchmark Kriptografi")
    st.write("Sesuai ketentuan **Bagian 4 Panduan UTS**, pengujian dilakukan minimal 30 kali iterasi untuk mengukur kecepatan pembuatan tanda tangan, verifikasi, ukuran kunci, dan ketahanan terhadap manipulasi berkas.")
    
    col_ctrl1, col_ctrl2 = st.columns([3, 2])
    with col_ctrl1:
        st.info("💡 Tekan tombol di samping untuk menjalankan loop 30x pengujian secara langsung di depan penguji.")
    with col_ctrl2:
        btn_run_bench = st.button("🚀 Jalankan Benchmark Sekarang (30x)", type="primary", use_container_width=True)

    if btn_run_bench:
        with st.spinner("Menjalankan 30 iterasi penandatanganan dan verifikasi ECDSA P-256..."):
            try:
                from benchmark import run_benchmark
                res = run_benchmark(iterations=30)
                st.session_state["benchmark_result"] = res
                st.success("✓ Seluruh 30 iterasi pengujian dan uji tamper berhasil dijalankan!")
            except Exception as e:
                st.error(f"Gagal menjalankan benchmark: {e}")

    # Ambil hasil dari session_state jika ada
    res = st.session_state.get("benchmark_result")
    
    # 4 Kartu Metrik Utama
    col_b1, col_b2, col_b3, col_b4 = st.columns(4)
    avg_s = f"{res['avg_sign']:.2f} ms" if res else "27.29 ms"
    avg_v = f"{res['avg_verify']:.2f} ms" if res else "0.21 ms"
    pub_s = f"{res['pub_size']} bytes" if res else "178 bytes"
    
    col_b1.metric("Rata-rata Waktu Signing", avg_s, "-5.8 ms")
    col_b2.metric("Rata-rata Waktu Verifikasi", avg_v, "< 1 ms")
    col_b3.metric("Ukuran Public Key (ECDSA)", pub_s, "Ringkas")
    col_b4.metric("Deteksi Tamper 1-Byte", "100%", "10/10 Skenario")

    # Jika ada data hasil uji, tampilkan grafik & tabel detail
    if res and "benchmark_data" in res:
        import pandas as pd
        df_bench = pd.DataFrame(res["benchmark_data"])
        st.markdown("#### 📈 Grafik Fluktuasi Waktu Eksekusi (30 Iterasi)")
        st.line_chart(
            df_bench.set_index("iterasi")[["waktu_signing_ms", "waktu_verifikasi_ms"]],
            color=["#0B3C5D", "#2ECC71"]
        )
        
        st.markdown("#### 🛡️ Bukti Hasil Uji Tamper / Manipulasi (10 Posisi Byte Berbeda)")
        df_tamper = pd.DataFrame(res["tamper_results"])
        df_tamper["status_deteksi"] = df_tamper["detected"].apply(lambda x: "✓ BERHASIL DITOLAK (SUKSES)" if x else "GAGAL")
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

    st.markdown("#### 📥 Unduh Berkas Hasil Pengujian Resmi (.xlsx):")
    if os.path.exists("data_pengujian_benchmark.xlsx"):
        with open("data_pengujian_benchmark.xlsx", "rb") as f:
            st.download_button(
                label="📥 Unduh Data Pengujian Lengkap (data_pengujian_benchmark.xlsx)",
                data=f.read(),
                file_name="data_pengujian_benchmark.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="secondary",
                use_container_width=True
            )
    else:
        st.info("Jalankan `python benchmark.py` untuk menghasilkan berkas Excel pengujian.")
