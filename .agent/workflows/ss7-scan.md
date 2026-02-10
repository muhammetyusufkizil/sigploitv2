---
description: SS7/Diameter Scanner - Hızlı Test Workflow
---

# SS7/Diameter Scanner Workflow

## 1. Tarama Başlat (AWS)
// turbo
```bash
cd ~/sigploit
screen -S scanner
sudo python3 -c "from ss7.multi_scan import *; run_multi_scan(['SS7','DIAMETER','GTP','SIP'])"
# Ctrl+A+D ile arka plana at
```

## 2. Sonuçları Kontrol Et
// turbo
```bash
# Leak dosyalarını gör
cat ~/sigploit/leaks_diameter.txt | wc -l
cat ~/sigploit/leaks_ss7.txt
cat ~/sigploit/leaks_sip.txt
cat ~/sigploit/leaks_gtp.txt
```

## 3. Unique IP'leri Listele
// turbo
```bash
cat ~/sigploit/leaks_diameter.txt | cut -d: -f1 | sort -u
```

## 4. IP Aralıklarını Göster
// turbo
```bash
cat ~/sigploit/leaks_diameter.txt | cut -d: -f1 | cut -d. -f1-3 | sort | uniq -c | sort -rn | head -20
```

## 5. Hızlı Diameter Test
```bash
python3 << 'EOF'
import socket
ip = "HEDEF_IP"
s = socket.socket(); s.settimeout(10)
try:
    s.connect((ip, 3868)); print('[+] Connected')
    s.send(b'\x01\x00\x00\x14\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    r = s.recv(1024)
    print(f'Response: {len(r)} bytes, first: {hex(r[0])}')
except Exception as e: print(f'[-] {e}')
EOF
```

## 6. Whois Sorgusu
// turbo
```bash
whois HEDEF_IP | grep -iE "org|country|netname|descr" | head -10
```

## 7. Nmap Detaylı Tarama
```bash
sudo nmap -sV -p 3868,3869,2905 HEDEF_IP -Pn
```
