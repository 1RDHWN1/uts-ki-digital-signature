# Aplikasi Digital Signature pada Dokumen PDF Berbasis QR-Code

> Tugas Proyek UTS Mata Kuliah Keamanan Informasi (20261)  
> Jurusan Informatika, Fakultas Teknik, Universitas Siliwangi  
> Dosen Pengampu: **Ir. Alam Rahmatulloh, S.T., M.T., MCE., IPM.**

---

## 👥 Tim Pengembang
* **Fachri Ridhwan Imani** (247006111140) — [@1RDHWN1](https://github.com/1RDHWN1) — *Key Management, Cryptographic Engine & Signing*
* **Wardah Nurwaffiq** (247006111150) — [@wardahnr](https://github.com/wardahnr) — *PDF Integration, QR-Code Stamping & Technical Documentation*
* **Mahardika Rajbi Firdaus** (247006111148) — [@dikarajbi](https://github.com/dikarajbi) — *Verification Engine, Benchmarking & Quantitative Testing*

---

## 📌 Deskripsi Proyek
Proyek ini mengimplementasikan skema **Tanda Tangan Digital (Digital Signature)** pada dokumen PDF untuk menjamin:
1. **Keaslian (Authenticity):** Memastikan dokumen ditandatangani oleh entitas yang sah.
2. **Keutuhan (Integrity):** Mendeteksi perubahan bahkan 1 byte/karakter setelah dokumen ditandatangani.
3. **Nir-penyangkalan (Non-repudiation):** Penandatangan tidak dapat menyangkal berkas yang telah dibubuhi tanda tangannya.

### Spesifikasi Teknis
* **Algoritma Asimetris:** ECDSA (*Elliptic Curve Digital Signature Algorithm*) dengan kurva **NIST P-256 (secp256r1)**.
* **Fungsi Hash:** **SHA-256** (*Secure Hash Algorithm 256-bit*).
* **Proteksi Kunci Privat:** Enkripsi *Private Key* menggunakan **AES-256-GCM** berbasis kata sandi (*passphrase*).
* **Penanda Visual Dokumen:** **QR-Code** memuat metadata penandatanganan dan tanda tangan digital terenkode Base64.

---

## 📁 Struktur Repositori
```text
├── .gitignore
├── README.md
├── requirements.txt
├── crypto_engine.py       # Modul inti kriptografi (Keygen, Hash, Sign, Enkripsi Kunci)
├── pdf_stamper.py         # Modul integrasi PDF & overlay QR-Code
├── verifier.py            # Modul verifikasi dokumen & validasi tanda tangan
├── benchmark.py           # Script pengujian kuantitatif & ekspor Excel (.xlsx)
└── tests/                 # Unit test otomatis (minimal 5 skenario uji wajib)
    └── test_crypto.py     # Pengujian modul kriptografi
```

---

## 🚀 Cara Menjalankan

### 1. Instalasi Dependensi
```bash
pip install -r requirements.txt
```

### 2. Menjalankan Unit Test (Otomatis)
```bash
python -m unittest discover -s tests -v
```

### 3. Menjalankan Aplikasi Web (Streamlit)
```bash
streamlit run app.py
```
Aplikasi dapat diakses melalui peramban web di `http://localhost:8501`.

### 4. Menjalankan Pengujian Benchmark (30x Iterasi ke Excel)
```bash
python benchmark.py
```

### 5. Generate Kunci & Uji Coba Kriptografi CLI
```bash
python crypto_engine.py
```
