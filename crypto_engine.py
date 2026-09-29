"""Modul Inti Kriptografi (Crypto Engine)
Tugas Proyek UTS Keamanan Informasi - Universitas Siliwangi
Bagian: Fachri Ridhwan Imani (Key Management, Hashing & Signing)

Spesifikasi:
- Algoritma Asimetris: ECDSA kurva NIST P-256 (secp256r1)
- Fungsi Hash: SHA-256
- Proteksi Private Key: Enkripsi berbasis Passphrase (BestAvailableEncryption / AES-256)
"""

import base64
import hashlib
from typing import Tuple, Optional, cast
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Membangkitkan pasangan kunci asimetris ECDSA dengan kurva NIST P-256."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def export_private_key_pem(private_key: ec.EllipticCurvePrivateKey, passphrase: Optional[str] = None) -> bytes:
    """Mengekspor Private Key ke format PEM. Jika passphrase diberikan, kunci dienkripsi."""
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption_algorithm = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def export_public_key_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Mengekspor Public Key ke format PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(pem_bytes: bytes, passphrase: Optional[str] = None) -> ec.EllipticCurvePrivateKey:
    """Memuat Private Key dari data PEM dan mendekripsi dengan passphrase jika ada."""
    password_bytes = passphrase.encode("utf-8") if passphrase else None
    key = serialization.load_pem_private_key(pem_bytes, password=password_bytes)
    return cast(ec.EllipticCurvePrivateKey, key)


def load_public_key_pem(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Memuat Public Key dari data PEM."""
    key = serialization.load_pem_public_key(pem_bytes)
    return cast(ec.EllipticCurvePublicKey, key)


def export_public_key_compressed_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    """Mengekspor Public Key ke titik terkompresi (X9.62) lalu Base64-URL.

    Titik terkompresi P-256 hanya 33 byte (44 karakter Base64), jauh lebih ringkas
    daripada PEM (178 karakter), sehingga efisien untuk disematkan di dalam QR-Code.
    """
    point = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return base64.urlsafe_b64encode(point).decode("utf-8").rstrip("=")


def load_public_key_compressed_b64(b64_str: str) -> ec.EllipticCurvePublicKey:
    """Memuat kembali Public Key dari titik terkompresi Base64-URL."""
    padded = b64_str + "=" * ((-len(b64_str)) % 4)
    point = base64.urlsafe_b64decode(padded.encode("utf-8"))
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def public_key_fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """Menghitung fingerprint SHA-256 dari Public Key (format heksadesimal bergrup).

    Fingerprint ini adalah identitas ringkas kunci publik yang dapat dicocokkan
    secara manual terhadap daftar kunci resmi (trust anchor).
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def hash_bytes(data: bytes) -> str:
    """Menghitung nilai hash SHA-256 dari data bytes dan mengembalikan format heksadesimal."""
    digest = hashlib.sha256(data).hexdigest()
    return digest


def hash_file(file_path: str) -> Tuple[str, bytes]:
    """Menghitung nilai hash SHA-256 dari sebuah file secara efisien (chunk-based)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    digest_bytes = sha256.digest()
    digest_hex = sha256.hexdigest()
    return digest_hex, digest_bytes


def sign_data(private_key: ec.EllipticCurvePrivateKey, data_bytes: bytes) -> str:
    """Menandatangani data menggunakan Private Key dengan algoritma ECDSA (SHA-256).
    Mengembalikan signature dalam format string Base64.
    """
    raw_signature = private_key.sign(
        data_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(raw_signature).decode("utf-8")


def verify_signature(public_key: ec.EllipticCurvePublicKey, signature_b64: str, data_bytes: bytes) -> bool:
    """Memverifikasi signature Base64 terhadap data menggunakan Public Key.
    Mengembalikan True jika valid, False jika data atau signature tidak cocok.
    """
    try:
        raw_signature = base64.b64decode(signature_b64.encode("utf-8"))
        public_key.verify(
            raw_signature,
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_hash(private_key: ec.EllipticCurvePrivateKey, digest_bytes: bytes) -> str:
    """Menandatangani nilai digest hash SHA-256 (32 bytes) menggunakan Private Key ECDSA.
    Mengembalikan signature dalam format string Base64.
    """
    raw_signature = private_key.sign(
        digest_bytes,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    return base64.b64encode(raw_signature).decode("utf-8")


def verify_hash(public_key: ec.EllipticCurvePublicKey, signature_b64: str, digest_bytes: bytes) -> bool:
    """Memverifikasi signature Base64 terhadap nilai digest hash SHA-256 menggunakan Public Key.
    Mengembalikan True jika valid, False jika digest atau signature tidak cocok.
    """
    try:
        raw_signature = base64.b64decode(signature_b64.encode("utf-8"))
        public_key.verify(
            raw_signature,
            digest_bytes,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        return True
    except (InvalidSignature, ValueError):
        return False


if __name__ == "__main__":
    print("=== PENGUJIAN MODUL CRYPTO ENGINE ===")
    
    # 1. Pembangkitan Kunci
    passphrase = "kunci-rahasia-uts"
    priv, pub = generate_keypair()
    
    pem_priv = export_private_key_pem(priv, passphrase=passphrase)
    pem_pub = export_public_key_pem(pub)
    print(f"✓ Berhasil generate keypair ECDSA (P-256)")
    print(f"✓ Ukuran Public Key: {len(pem_pub)} bytes")
    print(f"✓ Ukuran Encrypted Private Key: {len(pem_priv)} bytes")
    
    # 2. Uji Signing
    dokumen_dummy = b"Dokumen Resmi Universitas Siliwangi - UTS Keamanan Informasi"
    doc_hash = hash_bytes(dokumen_dummy)
    print(f"✓ SHA-256 Dokumen: {doc_hash}")
    
    signature = sign_data(priv, dokumen_dummy)
    print(f"✓ Digital Signature (Base64): {signature[:32]}... ({len(signature)} chars)")
    
    # 3. Uji Verifikasi Valid
    is_valid = verify_signature(pub, signature, dokumen_dummy)
    print(f"✓ Hasil Verifikasi Dokumen Asli: {'VALID' if is_valid else 'GAGAL'}")
    assert is_valid, "Harus valid!"
    
    # 4. Uji Tamper (Modifikasi 1 Byte)
    dokumen_tampered = b"Dokumen Resmi Universitas Siliwangi - UTS Keamanan lnformasi"  # huruf I diganti l
    is_tampered_valid = verify_signature(pub, signature, dokumen_tampered)
    print(f"✓ Hasil Verifikasi Dokumen Tampered: {'VALID' if is_tampered_valid else 'BERHASIL DITOLAK (INVALID)'}")
    assert not is_tampered_valid, "Dokumen yang diubah harus ditolak!"
    
    print("\nSeluruh pengujian inti modul crypto_engine berhasil 100%!")
