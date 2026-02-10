# Python 3 Uyumluluk Güncellemeleri

## Yapılan Değişiklikler

Bu proje Python 2.7'den Python 3'e (3.13+) uyumlu hale getirilmiştir.

### Ana Değişiklikler

1. **print statement → print() fonksiyonu**
   - Tüm `print` kullanımları `print()` fonksiyonuna dönüştürüldü

2. **raw_input() → input()**
   - Python 2'deki `raw_input()` fonksiyonu Python 3'te `input()` olarak güncellendi

3. **Exception Handling**
   - `e.message` kullanımları `str(e)` ile değiştirildi
   - Python 3'te exception.message attribute'u kaldırıldı

4. **Dictionary değişiklikleri**
   - `dict.values()[0]` kullanımı `list(dict.values())[0]` olarak değiştirildi
   - Python 3'te dictionary.values() bir liste değil, view objesi döner

5. **String formatting**
   - Eski stil string formatting güncellemeler yapıldı
   - Format string'lerde gereksiz `%` operatörleri düzeltildi

6. **Platform uyumluluğu**
   - `os.system('clear')` komutları Windows uyumlu hale getirildi
   - `os.system('cls' if os.name == 'nt' else 'clear')` kullanıldı

7. **Escape sequences**
   - Banner fonksiyonunda raw string (r'...') kullanıldı
   - Invalid escape sequence uyarıları düzeltildi

### Güncellenen Dosyalar

#### Ana Dosyalar
- `sigploit.py` - Ana menü ve framework
- `ss7main.py` - SS7 saldırı menüleri
- `gtpmain.py` - GTP saldırı menüleri

#### SS7 Modülleri
- `ss7/tracking.py` - Lokasyon takip saldırıları
- `ss7/fraud.py` - Fraud ve bilgi toplama saldırıları
- `ss7/interception.py` - İnterception saldırıları
- `ss7/dos.py` - DoS saldırıları

#### GTP Modülleri
- `gtp/info.py` - Bilgi toplama saldırıları
- `gtp/fraud.py` - Fraud saldırıları

## Kullanım

### Gereksinimler
- Python 3.x (test edildi: Python 3.13)
- Java 1.7+ (SS7 saldırıları için)
- Windows/Linux/MacOS

### Kurulum

```bash
# Bağımlılıkları yükle
pip install -r requirements.txt

# Programı çalıştır
python sigploit.py
```

### Windows Notları
- Program Windows'ta test edildi ve çalışıyor
- `cls` komutu otomatik olarak kullanılıyor
- PowerShell ve CMD ile uyumlu

## Test Sonuçları

Tüm dosyalar Python syntax kontrolünden geçti:
- ✅ sigploit.py - Başarılı
- ✅ ss7main.py - Başarılı
- ✅ gtpmain.py - Başarılı
- ✅ SS7 modülleri - Başarılı
- ✅ GTP modülleri - Başarılı

## Notlar

- Orijinal Python 2.7 uyumluluğu korunmadı - sadece Python 3 desteği var
- Java bağımlılıkları (.jar dosyaları) değiştirilmedi
- Tüm fonksiyonellik korundu
- Menü sistemi ve kullanıcı etkileşimi aynı kaldı

## Sorun Giderme

Eğer "invalid escape sequence" uyarısı alırsanız:
- Raw string kullanın: `r'...'`
- Veya backslash'leri iki kez yazın: `\\`

Eğer import hatası alırsanız:
- `pip install -r requirements.txt` komutunu çalıştırın
- Python 3 kullandığınızdan emin olun: `python --version`

## Lisans

MIT License (Orijinal proje lisansı korundu)

