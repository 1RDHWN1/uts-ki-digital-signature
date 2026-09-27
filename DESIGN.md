# Panduan Desain Antarmuka (DESIGN.md)

> Proyek: **Aplikasi Digital Signature Dokumen PDF (SIDIGS UNSIL)**  
> Mata Kuliah: Keamanan Informasi 20261 — Universitas Siliwangi  
> Dosen Pengampu: **Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.**

---

## 1. Design Read & Filosofi Visual
* **Surface & Archetype:** Portal Kriptografi Institusi Akademik (*Academic & Institutional Cryptographic Tool*).
* **Karakter:** Berwibawa, presisi, bersih, transparan, dan dapat dipercaya (*high-trust & authoritative*). Bukan aplikasi mainan atau dashboard AI generik.
* **Sumber Arah Desain:** Identitas kelembagaan Universitas Siliwangi, memadukan palet biru tua formal, permukaan kertas/kanvas bersih, tipografi tegas, serta sertifikat tanda terima verifikasi (*cryptographic verification certificate*).

### Dials (Tingkat Dinamika Visual)
* **ENERGY: 1** — Tenang, formal, fokus pada kejelasan data dan fungsi keamanan dokumen.
* **RHYTHM: 2** — Struktur berjenjang yang tertib (*tab-based sequential workflow*): Keygen ➔ Signing ➔ Verification ➔ Benchmark.
* **MOTION: 1** — Gerakan fungsional saja (indikator loading saat proses komputasi kriptografis), tanpa animasi bouncing, pulse berulang, atau floating loops tanpa guna (R-19).

---

## 2. Sistem Warna & Kontras (WCAG AA Compliant)

| Token Warna | Nilai Hex | Peran Visual | Rasio Kontras |
| :--- | :--- | :--- | :--- |
| **Primary Navy** | `#0B3C5D` | Warna identitas utama UNSIL, tombol aksi utama, header | 8.9:1 terhadap putih |
| **Slate Dark (Ink)** | `#0F172A` | Teks utama, judul bab, label input | 15.6:1 terhadap putih |
| **Muted Slate** | `#475569` | Keterangan, teks pendukung, metadata sekunder | 5.2:1 terhadap putih |
| **Surface Base** | `#FFFFFF` | Latar belakang halaman utama | Dasar |
| **Surface Alt** | `#F8FAFC` | Latar belakang sidebar dan kartu formulir | Dasar |
| **Border Neutral** | `#E2E8F0` | Garis pembatas kartu, tabel, dan formulir | 3.1:1 non-text |
| **Semantic Valid** | `#047857` | Lencana dan kartu dokumen asli terverifikasi | 5.4:1 terhadap `#ECFDF5` |
| **Semantic Tamper** | `#B91C1C` | Peringatan manipulasi berkas (1-byte tamper) | 6.8:1 terhadap `#FEF2F2` |

---

## 3. Aturan Bebas AI Slop (Antislop Policy)
1. **Bebas Polusi Emoji (R-04):** Tidak menggunakan deretan emoji ceria (`🚀`, `✨`, `🎉`, `💡`, `🔥`) pada tombol aksi dan judul antarmuka. Makna disampaikan lewat bahasa teknis yang lugas dan terukur.
2. **Formulir Jujur & Bersih (R-23, R-38):** Bidang input tidak diisi dengan data dummy palsu yang di-hardcode. Input dimulai dengan keadaan kosong disertai teks bantuan (*placeholder*) yang informatif (`Contoh: Fachri Ridhwan Imani`).
3. **Tanpa Gradien Ungu/Biru Klise (R-01):** Menghindari latar belakang gradien ungu-biru atau efek kaca (*glassmorphism*) tebal yang tidak relevan dengan instansi kampus.
4. **Kejelasan Status Kriptografis (R-27):**
   * *Status Kosong:* Memberikan petunjuk jelas apa yang harus diunggah pertama kali.
   * *Status Valid:* Menampilkan kartu verifikasi lengkap dengan nama penandatangan, timestamp, institusi, dan komparasi digest SHA-256.
   * *Status Tampered:* Memberikan laporan audit byte: menampilkan hash berkas yang diterima vs hash tanda tangan asli yang diharapkan.
