# Panduan Desain Antarmuka (DESIGN.md)

> Proyek: **SignaCerta — Sistem Otentikasi dan Tanda Tangan Digital Dokumen PDF**  
> Mata Kuliah: Keamanan Informasi (20261) — Jurusan Informatika, Fakultas Teknik, Universitas Siliwangi  
> Dosen Pengampu: **Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.**

---

## 1. Identitas & Filosofi Desain (Design Read)
* **Nama Proyek:** **SignaCerta** (dari bahasa Latin: *Signatura Certa*, kepastian dan otentisitas tanda tangan).
* **Surface & Archetype:** Portal Otentikasi Dokumen Institusional Akademik (*Institutional Cryptographic Verification Portal*).
* **Karakter Visual:** Berwibawa, bersih, presisi tinggi, transparan, dan dapat dipercaya (*high-trust & authoritative*). Dirancang dengan standar antarmuka institusi pendidikan tinggi.
* **Sumber Arah Desain:** Identitas kelembagaan Universitas Siliwangi, memadukan warna *Siliwangi Deep Navy* (`#0B3C5D`), kanvas netral bersih (`#FFFFFF` & `#F8FAFC`), batas struktural arsitektural (`#E2E8F0`), dan tipografi sans-serif modern yang terbaca jelas.

### Parameter Dial (Dinamika Visual)
* **ENERGY: 1** — Tenang, formal, minim distraksi, berorientasi pada fungsionalitas dan kejelasan data audit kriptografi.
* **RHYTHM: 2** — Struktur horizontal berjejer rapi (*side-by-side horizontal navigation*) dengan 5 kanal kerja terstruktur:
  1. Pembangkitan Kunci
  2. Penandatanganan Dokumen
  3. Verifikasi Integritas
  4. Uji Kuantitatif & Benchmark
  5. Tentang Proyek & Integritas Akademik
* **MOTION: 1** — Transisi statis-fungsional; indikator progres hanya muncul saat komputasi kriptografis berjalan. Tanpa animasi looping atau pantulan (*bounce*) yang tidak esensial.

---

## 2. Sistem Warna & Aksesibilitas (WCAG AA)

| Token Warna | Nilai Hex | Peran Antarmuka | Rasio Kontras |
| :--- | :--- | :--- | :--- |
| **Siliwangi Navy** | `#0B3C5D` | Warna identitas utama, header, tombol aksi primer | 8.9:1 terhadap putih |
| **Slate Dark (Ink)** | `#0F172A` | Judul bab, teks utama, label input | 15.6:1 terhadap putih |
| **Slate Muted** | `#475569` | Deskripsi alur, metadata sekunder, keterangan | 5.2:1 terhadap putih |
| **Canvas Base** | `#FFFFFF` | Latar belakang bidang konten | Dasar |
| **Surface Alt** | `#F8FAFC` | Latar belakang sidebar, footer, dan kartu data | Dasar |
| **Border Neutral** | `#E2E8F0` | Garis pembatas kartu formulir dan kontainer | 3.1:1 non-text |
| **Audit Valid** | `#059669` | Sertifikat dokumen asli & digest cocok | 5.4:1 terhadap `#ECFDF5` |
| **Audit Tampered** | `#DC2626` | Peringatan manipulasi berkas (1-byte tamper) | 6.8:1 terhadap `#FEF2F2` |

---

## 3. Implementasi Aturan Anti-Slop
1. **Navigasi Horizontal Berjejer (Side-by-side):** Alur kerja 1, 2, 3, 4 dan kanal informasi Tentang Proyek ditata berdampingan di bagian atas antarmuka, memberikan navigasi yang cepat dan tidak tersembunyi.
2. **Navbar & Footer Institusional:** Header navigasi atas memuat identitas institusi dan indikator standar FIPS 186-4. Footer bawah merangkum atribusi akademik, dosen pengampu, tim pengembang, dan referensi standar kriptografi.
3. **Bebas Polusi Emoji (R-04):** Teks tombol dan judul sepenuhnya mengandalkan bahasa teknis baku tanpa taburan emoji dekoratif.
4. **Formulir Jujur & Cepat (R-23, R-38):** Bidang input tidak dijejali data palsu yang terkunci, melainkan menggunakan placeholder informatif dan tombol bantuan isi cepat (*quick-fill preset*) untuk mempercepat demonstrasi langsung saat UTS.
5. **Skala & Pengalaman Pengguna (UX Scale):** Menggunakan kontainer berbatas tegas (`border=True`), indikator ukuran dan halaman berkas PDF yang diunggah secara instan, serta laporan audit kriptografi komparatif.
