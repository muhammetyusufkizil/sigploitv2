# Windows Kurulum Rehberi

## Önemli Not

Bu araç orijinal olarak Linux için tasarlanmıştır. Windows'ta bazı sınırlamalar vardır:

### ✅ Windows'ta Çalışan Özellikler:
- **GTP Saldırıları** (3G/4G Data saldırıları)
  - GTP Nodes Discovery
  - TEID Allocation Discovery
  - Tunnel Hijacking
- **Menü Sistemi** - Tam çalışır
- **Kullanıcı Arayüzü** - Tam çalışır

### ❌ Windows'ta ÇALIŞMAYAN Özellikler:
- **SS7 Saldırıları** - `pysctp` paketi gerektirir
  - Location Tracking
  - Call and SMS Interception
  - Fraud & Info Gathering
  - DoS Attacks

**Neden?** Windows, SCTP (Stream Control Transmission Protocol) protokolünü native olarak desteklemez. SS7 saldırıları bu protokolü kullanır.

## Windows Kurulumu

### 1. Python Bağımlılıklarını Yükleyin

```bash
pip install -r requirements.txt
```

Bu komut sadece Windows uyumlu paketleri yükler (`pysctp` hariç).

### 2. Programı Çalıştırın

```bash
python sigploit.py
```

### 3. GTP Saldırılarını Kullanın

Programı başlattığınızda:
1. Ana menüden **"1) GTP"** seçeneğini seçin
2. **"1) GTPv2"** seçeneğini seçin
3. İstediğiniz saldırı türünü seçin

## SS7 Saldırıları İçin

Eğer SS7 saldırılarını kullanmak istiyorsanız, şu seçenekleriniz var:

### Seçenek 1: Linux Kullanın (Önerilen)
- Ubuntu, Debian, Kali Linux gibi bir Linux dağıtımı kullanın
- Linux'ta şu komutu çalıştırın:
  ```bash
  pip install -r requirements-linux.txt
  ```

### Seçenek 2: WSL (Windows Subsystem for Linux) Kullanın
1. Windows'ta WSL2 yükleyin:
   ```powershell
   wsl --install
   ```
2. Ubuntu yükleyin
3. Ubuntu içinde projeyi çalıştırın:
   ```bash
   cd /mnt/c/Users/ASUS/Desktop/SigPloit-master
   pip install -r requirements-linux.txt
   python sigploit.py
   ```

### Seçenek 3: Docker Kullanın
Linux tabanlı bir Docker container içinde çalıştırın.

## Sorun Giderme

### "pysctp" Hatası Alıyorsanız

```
ERROR: Failed building wheel for pysctp
```

**Çözüm:** Normal! Windows'ta pysctp çalışmaz. `requirements.txt` dosyası zaten güncellenmiştir ve bu paketi yüklemeye çalışmaz.

### Java Hatası Alıyorsanız

SS7 saldırıları için Java gereklidir. Java 1.7 veya üstü yükleyin:
- https://www.java.com/tr/download/

### Import Hatası Alıyorsanız

```bash
pip install colorama pyfiglet termcolor configobj IPy
```

## Test

Programın çalışıp çalışmadığını test edin:

```bash
python sigploit.py
```

**✅ Program şimdi tamamen çalışıyor!**

Menüyü görmelisiniz:
- **0) SS7** - ⚠️ Linux gereklidir (pysctp paketi)
- **1) GTP** - ✅ TAM ÇALIŞIR! (Windows ve Linux)
  - GTPv2 → Information Gathering → GTP Nodes Discovery
  - GTPv2 → Information Gathering → TEID Allocation Discovery  
  - GTPv2 → Fraud → Tunnel Hijacking

## Notlar

- Bu araç **eğitim ve yasal penetrasyon testi** amaçlıdır
- Sadece **izin verilen sistemlerde** kullanın
- Windows'ta **GTP modülü tam çalışır**
- **SS7 modülü için Linux gereklidir**

## Destek

Eğer sorun yaşıyorsanız:
1. Python 3.x kullandığınızdan emin olun: `python --version`
2. Tüm bağımlılıkları yükleyin: `pip install -r requirements.txt`
3. Java yüklü olduğundan emin olun: `java -version`

