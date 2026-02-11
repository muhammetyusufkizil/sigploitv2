#!/usr/bin/env python
"""
Spoofing Guard (Defensive)
- SIP/SS7/Diameter cikti dosyalarinda supheli spoofing izlerini tespit eder.
- MAP opcode analizi, SS7 GT/IMSI tutarliligi, Diameter AVP kontrolu.
"""
import os
import re
import time
import struct


def _get_input(prompt, default=None):
    if default is not None:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else default
    return input(f"{prompt}: ").strip()


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines(), None
    except OSError as e:
        return [], str(e)


def _detect_sip_spoof(lines):
    findings = []
    from_re = re.compile(r"^From:\s*(.*)$", re.IGNORECASE)
    pai_re = re.compile(r"^P-Asserted-Identity:\s*(.*)$", re.IGNORECASE)
    via_re = re.compile(r"^Via:\s*(.*)$", re.IGNORECASE)

    from_headers = []
    pai_headers = []
    via_headers = []

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        m_from = from_re.match(line)
        if m_from:
            from_headers.append((idx, m_from.group(1)))
        m_pai = pai_re.match(line)
        if m_pai:
            pai_headers.append((idx, m_pai.group(1)))
        m_via = via_re.match(line)
        if m_via:
            via_headers.append((idx, m_via.group(1)))

    if from_headers and pai_headers:
        for (lf, fv), (lp, pv) in zip(from_headers, pai_headers):
            if fv != pv:
                findings.append(("YUKSEK", lf, f"From != P-Asserted-Identity | {fv} <> {pv}"))

    suspicious_tokens = ["anonymous", "invalid", "spoof", "fake", "test@", "noreply"]
    for idx, value in from_headers + pai_headers:
        low = value.lower()
        if any(tok in low for tok in suspicious_tokens):
            findings.append(("ORTA", idx, f"Supheli kimlik degeri: {value}"))

    private_ip = re.compile(r"\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")
    for idx, value in via_headers:
        if private_ip.search(value):
            findings.append(("ORTA", idx, f"Via private IP iceriyor: {value}"))

    return findings


def _detect_msisdn_spoof(lines):
    findings = []
    msisdn_re = re.compile(r"\b(\+?\d{8,15})\b")
    seen = {}
    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        nums = msisdn_re.findall(line)
        for n in nums:
            norm = n.lstrip('+')
            if not norm.isdigit():
                continue
            if norm in seen and seen[norm] != line:
                findings.append(("ORTA", idx, f"Ayni MSISDN farkli baglamlarda geciyor: {n}"))
            else:
                seen[norm] = line
        if "imsi=" in line.lower() and "msisdn=" in line.lower() and "?" in line:
            findings.append(("DUSUK", idx, "MSISDN/IMSI esleme belirsiz gorunuyor"))
    return findings


def _detect_tr_focus(lines):
    findings = []
    tr_num = re.compile(r"\+?90\d{10}")
    tr_keywords = ["turkcell", "vodafone", "turk telekom", "ttmobil", "kablonet"]

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip().lower()
        if tr_num.search(line) and ("anonymous" in line or "spoof" in line or "fake" in line):
            findings.append(("YUKSEK", idx, "TR numara + supheli kimlik ifadesi"))
        if any(k in line for k in tr_keywords) and ("from:" in line or "p-asserted-identity" in line):
            if "invalid" in line or "anonymous" in line:
                findings.append(("ORTA", idx, "TR operator baglaminda supheli header"))
    return findings


def _detect_ss7_spoof(lines):
    """SS7/MAP mesajlarinda spoofing belirtileri tespit et."""
    findings = []
    
    # Tehlikeli MAP opcode'lari
    dangerous_opcodes = {
        'updateLocation': 'Konum guncelleme (interception riski)',
        'cancelLocation': 'Konum iptali (DoS riski)',
        'insertSubscriberData': 'Profil manipulasyonu',
        'sendAuthenticationInfo': 'Auth vektor hirsizligi (SIM klonlama)',
        'provideSubscriberInfo': 'Konum takibi',
        'anyTimeInterrogation': 'Dogrudan konum sorgusu',
        'sendRoutingInfo': 'Routing bilgisi sorgulama',
        'registerSS': 'Servis kaydi (cagri yonlendirme)',
        'eraseSS': 'Servis silme',
        'activateSS': 'Servis aktivasyonu',
        'mtForwardSM': 'SMS gonderme (sahte SMS)',
        'sendIMSI': 'IMSI cekme',
        'purgeMS': 'Abone temizleme (DoS)',
    }
    
    # GT (Global Title) tutarsizliklari
    gt_re = re.compile(r'(?:GT|GlobalTitle|CalledParty|CallingParty)[:\s=]+(\+?\d{5,15})', re.IGNORECASE)
    imsi_re = re.compile(r'(?:IMSI)[:\s=]+(\d{14,15})', re.IGNORECASE)
    opc_re = re.compile(r'(?:OPC|OrigPC|OriginatingPC)[:\s=]+(\d+)', re.IGNORECASE)
    
    gt_values = []
    imsi_values = []
    opc_values = []
    
    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        low = line.lower()
        
        # Tehlikeli opcode tespiti
        for opcode, risk in dangerous_opcodes.items():
            if opcode.lower() in low:
                findings.append(("YUKSEK", idx, f"Tehlikeli MAP operasyonu: {opcode} ({risk})"))
        
        # GT toplama
        gt_match = gt_re.findall(line)
        for gt in gt_match:
            gt_values.append((idx, gt.lstrip('+')))
        
        # IMSI toplama
        imsi_match = imsi_re.findall(line)
        for imsi in imsi_match:
            imsi_values.append((idx, imsi))
        
        # OPC toplama
        opc_match = opc_re.findall(line)
        for opc in opc_match:
            opc_values.append((idx, opc))
        
        # SCTP/M3UA anomalileri
        if 'aspup' in low or 'asp_up' in low:
            findings.append(("ORTA", idx, "ASP Up mesaji tespit edildi (M3UA baglanti denemesi)"))
        
        # Fragmentation bypass denemesi
        if 'fragment' in low and ('bypass' in low or 'split' in low):
            findings.append(("YUKSEK", idx, "Fragmentasyon bypass denemesi"))
    
    # GT-IMSI tutarsizligi kontrolu (farkli ulke kodlari)
    if gt_values and imsi_values:
        gt_countries = set()
        imsi_countries = set()
        for _, gt in gt_values:
            if len(gt) >= 3:
                gt_countries.add(gt[:3])
        for _, imsi in imsi_values:
            if len(imsi) >= 3:
                imsi_countries.add(imsi[:3])
        if gt_countries and imsi_countries and not gt_countries.intersection(imsi_countries):
            findings.append(("YUKSEK", 0, f"GT ulke kodu ({gt_countries}) IMSI ulke kodu ({imsi_countries}) ile uyusmuyor - spoofing olabilir"))
    
    # Ayni OPC'den farkli operasyonlar (scanning belirtisi)
    if len(opc_values) > 5:
        findings.append(("ORTA", 0, f"Ayni OPC'den {len(opc_values)} istek - bulk scanning olabilir"))
    
    return findings


def _detect_diameter_spoof(lines):
    """Diameter mesajlarinda spoofing tespiti."""
    findings = []
    
    dangerous_cmds = {
        'AIR': 'Authentication-Information-Request (auth vektor cikarma)',
        'ULR': 'Update-Location-Request (konum guncelleme)',
        'CLR': 'Cancel-Location-Request (abone koparmak)',
        'IDR': 'Insert-Subscriber-Data-Request (profil manipulasyonu)',
        'PUR': 'Purge-UE-Request (abone temizleme)',
        'NOR': 'Notify-Request (bildirim)',
    }
    
    origin_hosts = set()
    origin_realms = set()
    
    origin_host_re = re.compile(r'(?:Origin-Host|OriginHost)[:\s=]+(\S+)', re.IGNORECASE)
    origin_realm_re = re.compile(r'(?:Origin-Realm|OriginRealm)[:\s=]+(\S+)', re.IGNORECASE)
    
    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        low = line.lower()
        
        # Tehlikeli Diameter komutlari
        for cmd, risk in dangerous_cmds.items():
            if cmd.lower() in low or risk.split('(')[0].strip().lower().replace('-', '') in low.replace('-', ''):
                findings.append(("YUKSEK", idx, f"Diameter komutu: {cmd} ({risk})"))
        
        # Origin-Host / Origin-Realm toplama
        oh_match = origin_host_re.findall(line)
        for oh in oh_match:
            origin_hosts.add(oh)
        or_match = origin_realm_re.findall(line)
        for orealm in or_match:
            origin_realms.add(orealm)
        
        # CER/CEA - baglanti kurma
        if 'capabilities-exchange' in low or 'cer' in low.split() or 'cea' in low.split():
            findings.append(("ORTA", idx, "Diameter CER/CEA baglanti denemesi"))
    
    # Birden fazla Origin-Host (impersonation olabilir)
    if len(origin_hosts) > 1:
        findings.append(("YUKSEK", 0, f"Birden fazla Origin-Host: {origin_hosts} - kimlik taklit olabilir"))
    
    if len(origin_realms) > 1:
        findings.append(("ORTA", 0, f"Birden fazla Origin-Realm: {origin_realms}"))
    
    return findings


def _detect_network_anomaly(lines):
    """Ag anomalileri tespit et (port scanning, brute force vb.)."""
    findings = []
    
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    port_re = re.compile(r':(\d{2,5})\b')
    
    ip_counts = {}
    port_counts = {}
    error_count = 0
    timeout_count = 0
    
    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        low = line.lower()
        
        # IP frekansi
        ips = ip_re.findall(line)
        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Port frekansi
        ports = port_re.findall(line)
        for port in ports:
            port_counts[port] = port_counts.get(port, 0) + 1
        
        # Hata sayaci
        if 'error' in low or 'failed' in low or 'refused' in low:
            error_count += 1
        if 'timeout' in low or 'timed out' in low:
            timeout_count += 1
        
        # Brute force belirtisi
        if 'denied' in low and 'auth' in low:
            findings.append(("ORTA", idx, "Kimlik dogrulama reddedildi"))
    
    # Cok sayida farkli port (scanning)
    if len(port_counts) > 10:
        findings.append(("YUKSEK", 0, f"{len(port_counts)} farkli port tespit edildi - port taramasi olabilir"))
    
    # Yuksek hata orani
    if error_count > 20:
        findings.append(("ORTA", 0, f"{error_count} hata satiri - brute force/fuzzing olabilir"))
    
    if timeout_count > 10:
        findings.append(("DUSUK", 0, f"{timeout_count} timeout - ag sorunlari/slow DoS olabilir"))
    
    # En cok gorülen IP'ler
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        if count > 50:
            findings.append(("ORTA", 0, f"IP {ip} - {count} kez gorunuyor (yuksek aktivite)"))
    
    return findings


def _summarize_findings(findings):
    summary = {"YUKSEK": 0, "ORTA": 0, "DUSUK": 0}
    for sev, _, _ in findings:
        summary[sev] = summary.get(sev, 0) + 1
    return summary


def _dedupe_findings(findings):
    seen = set()
    out = []
    for item in findings:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _save_findings(path, title, findings):
    out_name = f"spoofing_guard_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    with open(out_name, 'w', encoding='utf-8') as f:
        f.write(f"Report: {title}\n")
        f.write(f"Source: {path}\n")
        f.write(f"Generated: {time.ctime()}\n\n")
        for sev, line_no, detail in findings:
            f.write(f"[{sev}] line {line_no}: {detail}\n")
    return out_name


def run_guard_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 70)
        print(" Spoofing Guard (Defensive Security)")
        print(" SIP/SS7/Diameter ciktilarinda supheli aktivite tespiti")
        print("=" * 70)
        print("\n[SIP Analizleri]")
        print("  1) SIP log analizi (From/PAI/Via spoofing)")
        print("\n[SS7/MAP Analizleri]")
        print("  2) SS7/MAP mesaj analizi (tehlikeli opcode, GT/IMSI)")
        print("  3) MSISDN/IMSI tutarlilik analizi")
        print("\n[Diameter Analizleri]")
        print("  4) Diameter mesaj analizi (AIR/ULR/CLR/IDR)")
        print("\n[Genel Analizler]")
        print("  5) Ag anomali tespiti (scanning, brute force)")
        print("  6) TR odakli spoofing risk analizi")
        print("  7) TOPLU ANALIZ (tum testler)")
        print("\n  99) Geri")

        choice = _get_input("secim", "1").strip().lower()

        if choice == "99":
            return

        if choice not in {"1", "2", "3", "4", "5", "6", "7"}:
            print("[-] Gecersiz secim")
            time.sleep(1)
            continue

        path = _get_input("Analiz dosya yolu", "leaks_verified.txt")
        lines, err = _read_lines(path)
        if err:
            print(f"[-] Dosya okunamadi: {err}")
            input("\nDevam icin Enter...")
            continue

        if choice == "1":
            findings = _detect_sip_spoof(lines)
            title = "SIP Spoofing Analizi"
        elif choice == "2":
            findings = _detect_ss7_spoof(lines)
            title = "SS7/MAP Tehdit Analizi"
        elif choice == "3":
            findings = _detect_msisdn_spoof(lines)
            title = "Telecom Tutarlilik Analizi"
        elif choice == "4":
            findings = _detect_diameter_spoof(lines)
            title = "Diameter Tehdit Analizi"
        elif choice == "5":
            findings = _detect_network_anomaly(lines)
            title = "Ag Anomali Analizi"
        elif choice == "6":
            findings = _detect_tr_focus(lines)
            title = "TR Odakli Spoofing Risk Analizi"
        else:  # choice == "7"
            findings = []
            findings.extend(_detect_sip_spoof(lines))
            findings.extend(_detect_ss7_spoof(lines))
            findings.extend(_detect_msisdn_spoof(lines))
            findings.extend(_detect_diameter_spoof(lines))
            findings.extend(_detect_network_anomaly(lines))
            findings.extend(_detect_tr_focus(lines))
            title = "Toplu Guvenlik Analizi"

        print(f"\n[+] {title} | dosya: {path}")
        findings = _dedupe_findings(findings)
        if not findings:
            print("[+] Supheli bulgu bulunamadi.")
        else:
            summary = _summarize_findings(findings)
            print(f"[!] {len(findings)} supheli bulgu:")
            print(f"    YUKSEK: {summary.get('YUKSEK',0)} | ORTA: {summary.get('ORTA',0)} | DUSUK: {summary.get('DUSUK',0)}")
            for sev, line_no, detail in findings[:200]:
                print(f" - [{sev}] satir {line_no}: {detail}")
            if len(findings) > 200:
                print(f" ... {len(findings)-200} ek bulgu gizlendi")

            save_choice = _get_input("Bulgular dosyaya kaydedilsin mi? (e/h)", "e").strip().lower()
            if save_choice in ("e", "evet", "y", "yes"):
                try:
                    out_name = _save_findings(path, title, findings)
                    print(f"[+] Rapor kaydedildi: {out_name}")
                except OSError as e:
                    print(f"[-] Rapor kaydetme hatasi: {e}")

        input("\nDevam icin Enter...")


if __name__ == "__main__":
    run_guard_menu()
