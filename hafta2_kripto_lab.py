#!/bin/bash
# Siber Güvenlik Laboratuvarı — Parola Güvenliği ve Özet Kırma Analizi
# Öğrenci: Bengisu İlayda HARMANCI (232923040)

echo "=== 1. Hedef MD5 Özetleri ve Sözlük Dosyası Oluşturuluyor ==="
cat << 'EOF' > aku_sozluk.txt
guvenlik2026
afyon03
sibervatan
kocatepe23
parola123
admin2026
denizli20
bilgisayar
123456
qwerty
EOF

> hedef_md5.txt
while IFS= read -r parola; do
    [ -z "$parola" ] && continue
    printf "%s" "$parola" | md5sum | awk '{print $1}' >> hedef_md5.txt
done < aku_sozluk.txt

echo "Olusturulan hedef_md5.txt icerigi:"
cat hedef_md5.txt

echo -e "\n=== 2. Hashcat ile MD5 Sözlük Saldırısı ==="
hashcat -m 0 -a 0 hedef_md5.txt aku_sozluk.txt --force
hashcat -m 0 -a 0 hedef_md5.txt aku_sozluk.txt --show

echo -e "\n=== 3. John the Ripper Algoritma Hız Testi (Benchmark) ==="
john --test --format=raw-md5
john --test --format=raw-sha256
john --test --format=bcrypt
