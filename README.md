# SigPloit - SS7/Diameter/GTP Security Testing Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-2.0-red.svg" alt="Version">
</p>

**SigPloit** is a comprehensive telecom security testing framework for SS7, Diameter, and GTP protocols. Designed for security researchers and bug bounty hunters to identify vulnerabilities in mobile network infrastructure.

**SigPloit**, SS7, Diameter ve GTP protokolleri için kapsamlı bir telekom güvenlik test çerçevesidir. Güvenlik araştırmacıları ve bug bounty avcıları için mobil ağ altyapısındaki güvenlik açıklarını tespit etmek amacıyla tasarlanmıştır.

---

## 🌟 Features / Özellikler

### Multi-Protocol Support / Çoklu Protokol Desteği

| Protocol | Ports | Description |
|----------|-------|-------------|
| **SS7/SCTP** | 2904-2908 | SIGTRAN, M3UA, SCCP, TCAP, MAP |
| **Diameter** | 3868-3869 | 4G/LTE Signaling |
| **GTP** | 2123, 2152 | Mobile Data Tunneling |
| **SIP** | 5060-5061 | VoIP Signaling |

### Attack Modules / Saldırı Modülleri

#### 📍 Location Tracking / Konum Takibi
- **SendRoutingInfo (SRI)** - Call routing query
- **ProvideSubscriberInfo (PSI)** - VLR location query
- **SendRoutingInfoForSM (SRI-SM)** - SMS routing query
- **AnyTimeInterrogation (ATI)** - Direct HLR query
- **SendRoutingInfoForGPRS** - GPRS routing query

#### 📱 Interception / Dinleme
- **UpdateLocation (UL)** - SMS interception via MSC redirection

#### 💳 Fraud / Dolandırıcılık
- **SendIMSI** - IMSI retrieval from MSISDN
- **SendAuthenticationInfo (SAI)** - Get authentication vectors
- **InsertSubscriberData (ISD)** - Subscriber profile manipulation
- **CancelLocation (CL)** - Subscriber disconnection

#### 💥 DoS Attacks / Servis Dışı Bırakma
- **PurgeMS** - Mass subscriber disconnection

#### 🔍 Network Discovery / Ağ Keşfi
- **Random Auto-Scan** - Infinite bounty mode scanning
- **Targeted Scan** - Specific IP range scanning
- **Multi-Protocol Scan** - SS7 + Diameter + GTP + SIP

---

## 🚀 Installation / Kurulum

### Requirements / Gereksinimler

```bash
# Python 3.8+
python3 --version

# Linux
sudo apt install python3-pip git -y

# Windows (requires Npcap)
# Download from: https://npcap.com/
```

### Install / Kurulum

```bash
# Clone repository
git clone https://github.com/muhammetyusufkizil/sigploit.git
cd sigploit

# Install dependencies
pip3 install scapy IPy

# Run (requires root/admin)
sudo python3 sigploit.py
```

---

## 📖 Usage / Kullanım

### Main Menu / Ana Menü

```
######################## SigPloit ########################

1) SS7 (SIGTRAN)            # SS7 Attacks
2) GTP                      # Mobile Data Attacks
3) Diameter                 # 4G/LTE Attacks

(sigploit)> 1
```

### SS7 Attack Menu / SS7 Saldırı Menüsü

```
0) Location Tracking               # Konum Takibi
1) Call and SMS Interception       # Arama ve SMS Dinleme
2) Fraud & Info Gathering          # Dolandırıcılık
3) DoS                             # Servis Dışı Bırakma
4) Network Discovery (Leak Scanner) # Ağ Tarayıcı
5) Multi-Protocol Scanner 🚀        # Çoklu Protokol Tarayıcı

(attacks)> 5
```

### Multi-Protocol Scanner / Çoklu Protokol Tarayıcı

```
1) SS7 + Diameter + GTP + SIP (All Protocols)
2) SS7/SCTP Only (SIGTRAN)
3) Diameter Only (4G/LTE)
4) GTP Only (Mobile Data)
5) SIP Only (VoIP)

(scanner)> 1
```

---

## 📁 Output Files / Çıktı Dosyaları

| File | Content |
|------|---------|
| `leaks.txt` | SS7 SCTP open ports (vulnerabilities) |
| `leaks_ss7.txt` | SS7 leaks from multi-scanner |
| `leaks_diameter.txt` | Diameter open services |
| `leaks_gtp.txt` | GTP responses |
| `leaks_sip.txt` | SIP responses |
| `alive_hosts.txt` | All scan results with details |
| `tcp_open.txt` | TCP open ports for verification |

---

## 🔧 Architecture / Mimari

```
sigploit/
├── sigploit.py              # Main entry point
├── ss7main.py               # SS7 attack menu
├── ss7/
│   ├── scan.py              # SS7 network scanner
│   ├── multi_scan.py        # Multi-protocol scanner
│   ├── tracking.py          # Location tracking handler
│   ├── fraud.py             # Fraud attacks handler
│   ├── interception.py      # Interception handler
│   ├── dos.py               # DoS attacks handler
│   └── attacks/
│       ├── asn1_utils.py    # ASN.1 BER encoding
│       ├── tcap_layer.py    # TCAP protocol layer
│       ├── map_layer.py     # MAP protocol layer
│       ├── ss7_layers.py    # M3UA, SCCP layers
│       ├── tracking/        # Tracking attack modules
│       ├── fraud/           # Fraud attack modules
│       ├── interception/    # Interception modules
│       └── dos/             # DoS attack modules
├── gtp/                     # GTP protocol modules
└── diameter/                # Diameter protocol modules
```

---

## ⚠️ Legal Disclaimer / Yasal Uyarı

### English
This tool is intended for **authorized security testing only**. Unauthorized access to telecommunications networks is illegal. Use only with explicit permission from network owners or within authorized bug bounty programs.

### Türkçe
Bu araç **yalnızca yetkili güvenlik testleri** için tasarlanmıştır. Telekomünikasyon ağlarına yetkisiz erişim yasadışıdır. Yalnızca ağ sahiplerinin açık izniyle veya yetkili bug bounty programları kapsamında kullanın.

---

## 🏆 Bug Bounty Tips / Bug Bounty İpuçları

### Best Practices / En İyi Uygulamalar

1. **Use Cloud VPS** - Turkish ISPs block SCTP
   - AWS, Oracle Cloud, DigitalOcean recommended
   
2. **Target Known Telecom Ranges** - Focus on telecom IP blocks
   - Africa (41.x.x.x, 102.x.x.x) - Higher exposure
   - Asia (202.x.x.x, 203.x.x.x)
   - Middle East (212.x.x.x)

3. **Check Multiple Protocols** - Not just SS7
   - Diameter (3868) - 4G/LTE core
   - GTP (2123) - Mobile data
   - SIP (5060) - VoIP

4. **Document Everything** - For valid reports
   - Save all scan logs
   - Record packet captures
   - Note timestamps and IPs

---

## 🤝 Contributing / Katkıda Bulunma

Pull requests are welcome! For major changes, please open an issue first.

Katkılarınızı bekliyoruz! Büyük değişiklikler için önce bir issue açın.

---

## 📜 License / Lisans

MIT License - See [LICENSE](LICENSE) file for details.

---

## 👤 Author / Yazar

**Muhammed Yusuf Kızıl**

- GitHub: [@muhammetyusufkizil](https://github.com/muhammetyusufkizil)

---

## 🙏 Credits / Teşekkürler

- Original SigPloit by P1 Security
- Scapy Project
- SS7 Research Community

---

<p align="center">
  <b>🔒 Hack Responsibly | Sorumlu Şekilde Hackleyin 🔒</b>
</p>
