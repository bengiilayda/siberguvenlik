import os
import time
import hashlib
from PIL import Image
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher

print("[02] GÖRÜNTÜ ŞİFRELEME ANALİZİ (AES-ECB vs AES-CTR)")
# 176x176 boyutunda iç içe geometrik desenli test görüntüsü oluşturalım
img = Image.new("RGB", (176, 176), color=(255, 255, 255))
for x in range(18, 158):
    for y in range(18, 158):
        img.putpixel((x, y), (22, 42, 74))

for x in range(44, 132):
    for y in range(44, 132):
        if (x - 88) ** 2 + (y - 88) ** 2 <= 44 ** 2:
            img.putpixel((x, y), (212, 58, 58))

for x in range(72, 104):
    for y in range(72, 104):
        img.putpixel((x, y), (255, 255, 255))

img.save("orijinal.png")
raw_bytes = img.tobytes()

# ECB için 16 baytlık blok padding
pad_len = (16 - (len(raw_bytes) % 16)) % 16
padded_bytes = raw_bytes + b"\x00" * pad_len

key = os.urandom(16)
nonce = os.urandom(16)

# ECB Şifreleme
cipher_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
encryptor_ecb = cipher_ecb.encryptor()
ecb_encrypted = encryptor_ecb.update(padded_bytes) + encryptor_ecb.finalize()
ecb_bytes = ecb_encrypted[:len(raw_bytes)]

# CTR Şifreleme
cipher_ctr = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
encryptor_ctr = cipher_ctr.encryptor()
ctr_bytes = encryptor_ctr.update(raw_bytes) + encryptor_ctr.finalize()

# Görselleri üret
img_ecb = Image.frombytes("RGB", img.size, ecb_bytes)
img_ctr = Image.frombytes("RGB", img.size, ctr_bytes)

# Görselleri yan yana göster ve kaydet
fig, axes = plt.subplots(1, 3, figsize=(12, 4))
axes[0].imshow(img)
axes[0].set_title("1. Orijinal Görüntü")
axes[1].imshow(img_ecb)
axes[1].set_title("2. AES-ECB (Desen Sızar)")
axes[2].imshow(img_ctr)
axes[2].set_title("3. AES-CTR (Rastgele Gürültü)")
for ax in axes:
    ax.axis("off")
plt.tight_layout()
plt.savefig("adim2_karsilastirma.png")
print("Durum: 'orijinal.png' iki modda şifrelendi -> ECB blok desenini korudu, CTR gizledi.")
plt.show()


print("\n[03] BÜTÜNLÜK TESTİ: CTR ANAHTARSIZ DEĞİŞTİRME vs AES-GCM")
plain_text = b"Tutar: 100 TL"

# 1. CTR Modunda Bit Değiştirme ("100" -> "450")
cipher_ctr2 = Cipher(algorithms.AES(key), modes.CTR(nonce))
encryptor2 = cipher_ctr2.encryptor()
ciphertext = bytearray(encryptor2.update(plain_text) + encryptor2.finalize())

target_idx = plain_text.index(b"1")
ciphertext[target_idx] ^= (ord('1') ^ ord('4'))
ciphertext[target_idx + 1] ^= (ord('0') ^ ord('5'))

decryptor2 = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
tampered_plain = decryptor2.update(bytes(ciphertext)) + decryptor2.finalize()
print(f"Orijinal Düz Metin    : {plain_text.decode()}")
print(f"CTR Değiştirilmiş     : {tampered_plain.decode(errors='ignore')}   <-- Anahtar bilinmeden bit-flipping ile değişti!")

# 2. AES-GCM Modunda Deneme
aesgcm = AESGCM(key)
nonce_gcm = os.urandom(12)
gcm_ciphertext = bytearray(aesgcm.encrypt(nonce_gcm, plain_text, None))
gcm_ciphertext[target_idx] ^= (ord('1') ^ ord('4'))
gcm_ciphertext[target_idx + 1] ^= (ord('0') ^ ord('5'))

try:
    aesgcm.decrypt(nonce_gcm, bytes(gcm_ciphertext), None)
    print("AES-GCM Doğrulama     : Doğrulama başarılı (beklenmeyen durum)")
except Exception as e:
    print(f"AES-GCM Doğrulama     : {type(e).__name__} İstisnası -> Bütünlük bozulduğu için çözüm reddedildi.")


print("\n[04] PERFORMANS ÖLÇÜMÜ: SHA-256 vs ARGON2ID")
data = b"BengisuAku2026#"

# SHA-256
t0 = time.perf_counter()
for _ in range(10000):
    hashlib.sha256(data).hexdigest()
sha256_single = ((time.perf_counter() - t0) / 10000) * 1000

# Argon2id
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)
t1 = time.perf_counter()
for _ in range(5):
    ph.hash("BengisuAku2026#")
argon_single = ((time.perf_counter() - t1) / 5) * 1000

print(f"SHA-256  (1 özet)     : {sha256_single:.6f} ms")
print(f"Argon2id (1 özet)     : {argon_single:.2f} ms")
print(f"Karşılaştırma         : Argon2id, SHA-256'dan yaklaşık {argon_single / sha256_single:,.0f} kat daha yavaş çalıştı.")
