---
description: Web Bug Bounty - Hızlı Test Workflow
---

# Web Bug Bounty Workflow

## 1. Hedef Belirle
```bash
cd ~/bugbounty
TARGET="hedef.com"
```

## 2. Subdomain Keşfi
// turbo
```bash
subfinder -d $TARGET -o subs.txt
cat subs.txt | wc -l
```

## 3. Aktif Hostları Bul
// turbo
```bash
cat subs.txt | httpx -o alive.txt
cat alive.txt
```

## 4. Admin Panel Ara
// turbo
```bash
for sub in $(cat alive.txt); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$sub/admin")
    echo "$sub/admin: $code"
done
```

## 5. Login Form Bul
// turbo
```bash
for sub in $(cat alive.txt | head -10); do
    echo "=== $sub ==="
    curl -sL "$sub" | grep -iE "form|input|login|password" | head -5
done
```

## 6. Güvenlik Header Kontrolü
// turbo
```bash
curl -sI "https://$TARGET" | grep -iE "x-frame|x-xss|x-content|strict|csp"
```

## 7. SQLMap Test
```bash
sqlmap -u "https://hedef.com/login" \
  --data="username=test&password=test" \
  --batch --level=2 --risk=2
```

## 8. Dizin Tarama
```bash
ffuf -u "https://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -fc 404
```

## 9. Nuclei Tarama (Hafif)
```bash
nuclei -u "https://$TARGET" -t cves/ -severity critical,high
```
