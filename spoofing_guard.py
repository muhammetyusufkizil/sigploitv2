#!/usr/bin/env python
"""
Spoofing Guard (Defensive)
- SIP/telecom çıktı dosyalarında şüpheli spoofing izlerini tespit etmeye yardımcı olur.
"""
import os
import re
import time


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
        print("=" * 60)
        print(" Spoofing Guard (Defensive)")
        print(" SIP/SS7 ciktilarinda supheli spoofing izleri")
        print("=" * 60)
        print("1) SIP log dosyasi analizi (From/PAI/Via)")
        print("2) Genel telecom cikti analizi (MSISDN tutarliligi)")
        print("3) TR odakli spoofing risk analizi")
        print("99) Geri")

        choice = _get_input("secim", "1").strip().lower()

        if choice == "99":
            return

        if choice not in {"1", "2", "3"}:
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
            findings = _detect_msisdn_spoof(lines)
            title = "Telecom Tutarlilik Analizi"
        else:
            findings = _detect_tr_focus(lines)
            title = "TR Odakli Spoofing Risk Analizi"

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
