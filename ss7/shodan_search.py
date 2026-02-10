#!/usr/bin/env python
"""
Shodan/Censys Integration Module for SigPloit
Finds telecom infrastructure nodes using Shodan and Censys APIs.

Usage: Requires API keys in config.ini
"""
import sys
import os
import time
import json
import datetime
import socket

# Telecom search queries
TELECOM_QUERIES = {
    'SS7': {
        'shodan': [
            'port:2905',
            'port:2905 sctp',
            'port:2904',
            'port:2906',
            'port:2907',
            'port:2908',
        ],
        'censys': 'services.port:2905',
        'ports': [2904, 2905, 2906, 2907, 2908],
        'description': 'SS7/SIGTRAN (M3UA/M2PA/M2UA)',
    },
    'DIAMETER': {
        'shodan': [
            'port:3868',
            'port:3868 diameter',
            'port:3869',
        ],
        'censys': 'services.port:3868',
        'ports': [3868, 3869],
        'description': 'Diameter (4G/LTE S6a)',
    },
    'GTP': {
        'shodan': [
            'port:2123',
            'port:2152',
            'port:2123 gtp',
        ],
        'censys': 'services.port:2123',
        'ports': [2123, 2152],
        'description': 'GTP (GPRS Tunnelling Protocol)',
    },
    'SIP': {
        'shodan': [
            'port:5060 sip',
            'port:5060',
            'port:5061',
        ],
        'censys': 'services.port:5060',
        'ports': [5060, 5061],
        'description': 'SIP (VoIP/IMS)',
    },
}

# Country codes for targeted searches
COUNTRY_CODES = {
    'TR': 'Turkiye',
    'DE': 'Almanya',
    'FR': 'Fransa',
    'US': 'ABD',
    'GB': 'Ingiltere',
    'RU': 'Rusya',
    'CN': 'Cin',
    'IN': 'Hindistan',
    'BR': 'Brezilya',
    'KR': 'Guney Kore',
    'JP': 'Japonya',
    'SA': 'Suudi Arabistan',
    'AE': 'BAE',
    'EG': 'Misir',
    'NG': 'Nijerya',
}


def load_config():
    """Load API keys from config.ini."""
    config = {
        'shodan_api_key': '',
        'censys_api_id': '',
        'censys_api_secret': '',
    }

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, _, value = line.partition('=')
                        key = key.strip()
                        value = value.strip()
                        if key in config:
                            config[key] = value
        except Exception:
            pass

    return config


def save_config(config):
    """Save API keys to config.ini."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini')
    try:
        with open(config_path, 'w') as f:
            f.write("# SigPloit Configuration\n")
            f.write("# API Keys for Shodan/Censys integration\n\n")
            f.write(f"shodan_api_key = {config.get('shodan_api_key', '')}\n")
            f.write(f"censys_api_id = {config.get('censys_api_id', '')}\n")
            f.write(f"censys_api_secret = {config.get('censys_api_secret', '')}\n")
        print(f"[+] Yapilandirma kaydedildi: {config_path}")
    except Exception as e:
        print(f"[-] Kayit hatasi: {e}")


def get_input(prompt, default=None):
    """Get user input with optional default."""
    if default:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else default
    return input(f"{prompt}: ").strip()


def _prompt_int(prompt, default, min_value=None, max_value=None):
    while True:
        raw_value = get_input(prompt, str(default))
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


# ============================================
# SHODAN SEARCH
# ============================================

def search_shodan(api_key, query, country=None, max_results=100):
    """Search Shodan for telecom nodes."""
    results = []

    try:
        import shodan
    except ImportError:
        print("[-] 'shodan' modulu kurulu degil. Kurmak icin: pip install shodan")
        return results

    try:
        api = shodan.Shodan(api_key)

        if country:
            query += f" country:{country}"

        print(f"[+] Shodan sorgusu: {query}")

        result = api.search(query, limit=max_results)
        total = result.get('total', 0)
        print(f"[+] Toplam sonuc: {total}")

        for match in result.get('matches', []):
            ip = match.get('ip_str', '')
            port = match.get('port', 0)
            org = match.get('org', 'N/A')
            country_code = match.get('location', {}).get('country_code', 'N/A')
            isp = match.get('isp', 'N/A')

            results.append({
                'ip': ip,
                'port': port,
                'org': org,
                'country': country_code,
                'isp': isp,
                'source': 'shodan',
            })

    except Exception as e:
        error_msg = str(e)
        if 'Access denied' in error_msg or 'Invalid API key' in error_msg:
            print("[-] Gecersiz Shodan API anahtari!")
        elif 'limit' in error_msg.lower():
            print("[-] Shodan API limiti asildi. Lutfen bekleyin veya plan yukseltme yapin.")
        else:
            print(f"[-] Shodan hatasi: {e}")

    return results


def search_shodan_all(api_key, protocols=None, country=None, max_per_query=50):
    """Search Shodan for all telecom protocols."""
    all_results = {}

    if protocols is None:
        protocols = list(TELECOM_QUERIES.keys())

    for proto in protocols:
        if proto not in TELECOM_QUERIES:
            continue

        queries = TELECOM_QUERIES[proto]['shodan']
        proto_results = []

        for query in queries:
            print(f"\n[>] {proto}: {query}")
            results = search_shodan(api_key, query, country, max_per_query)
            proto_results.extend(results)
            time.sleep(1)  # Rate limiting

        # Deduplicate by IP:port
        seen = set()
        unique = []
        for r in proto_results:
            key = f"{r['ip']}:{r['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(r)

        all_results[proto] = unique
        print(f"[+] {proto}: {len(unique)} benzersiz sonuc")

    return all_results


# ============================================
# CENSYS SEARCH
# ============================================

def search_censys(api_id, api_secret, query, max_results=100):
    """Search Censys for telecom nodes."""
    results = []

    try:
        import requests
    except ImportError:
        print("[-] 'requests' modulu kurulu degil. Kurmak icin: pip install requests")
        return results

    try:
        url = "https://search.censys.io/api/v2/hosts/search"
        headers = {"Accept": "application/json"}
        params = {
            "q": query,
            "per_page": min(max_results, 100),
        }

        print(f"[+] Censys sorgusu: {query}")

        import requests
        resp = requests.get(url, params=params, headers=headers,
                           auth=(api_id, api_secret), timeout=30)

        if resp.status_code == 200:
            data = resp.json()
            hits = data.get('result', {}).get('hits', [])
            total = data.get('result', {}).get('total', 0)
            print(f"[+] Toplam sonuc: {total}")

            for hit in hits:
                ip = hit.get('ip', '')
                services = hit.get('services', [])
                location = hit.get('location', {})
                autonomous_system = hit.get('autonomous_system', {})

                for svc in services:
                    port = svc.get('port', 0)
                    results.append({
                        'ip': ip,
                        'port': port,
                        'org': autonomous_system.get('description', 'N/A'),
                        'country': location.get('country_code', 'N/A'),
                        'isp': autonomous_system.get('name', 'N/A'),
                        'source': 'censys',
                    })
        elif resp.status_code == 401:
            print("[-] Gecersiz Censys API kimlik bilgileri!")
        elif resp.status_code == 429:
            print("[-] Censys API limiti asildi.")
        else:
            print(f"[-] Censys hatasi: {resp.status_code} {resp.text[:200]}")

    except Exception as e:
        print(f"[-] Censys hatasi: {e}")

    return results


def search_censys_all(api_id, api_secret, protocols=None, max_per_query=100):
    """Search Censys for all telecom protocols."""
    all_results = {}

    if protocols is None:
        protocols = list(TELECOM_QUERIES.keys())

    for proto in protocols:
        if proto not in TELECOM_QUERIES:
            continue

        query = TELECOM_QUERIES[proto]['censys']
        print(f"\n[>] {proto}: {query}")
        results = search_censys(api_id, api_secret, query, max_per_query)

        # Deduplicate
        seen = set()
        unique = []
        for r in results:
            key = f"{r['ip']}:{r['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(r)

        all_results[proto] = unique
        print(f"[+] {proto}: {len(unique)} benzersiz sonuc")
        time.sleep(2)  # Rate limiting

    return all_results


# ============================================
# RESULT HANDLING
# ============================================

def save_results(all_results, prefix="shodan"):
    """Save search results to files."""
    total = 0
    files_created = []

    for proto, results in all_results.items():
        if not results:
            continue

        fname = f"leaks_{proto.lower()}_{prefix}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"# {proto} - {TELECOM_QUERIES.get(proto, {}).get('description', '')}\n")
            f.write(f"# Source: {prefix} | Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"# Total: {len(results)}\n\n")

            for r in results:
                f.write(f"{r['ip']}:{r['port']} | {r['org']} | {r['country']} | {r['isp']}\n")

        files_created.append(fname)
        total += len(results)
        print(f"[+] {fname}: {len(results)} sonuc kaydedildi")

    # Also save combined JSON
    json_fname = f"targets_{prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_fname, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False, default=str)
    files_created.append(json_fname)

    print(f"\n[+] Toplam: {total} hedef, {len(files_created)} dosya olusturuldu")
    return files_created


def quick_verify_results(results, protocol, max_verify=20):
    """Quick verification of discovered targets."""
    if not results:
        return []

    verified = []
    sample = results[:max_verify]
    print(f"\n[+] {len(sample)} hedef hizli dogrulama yapiliyor...")

    for r in sample:
        ip = r['ip']
        port = r['port']
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.close()
            verified.append(r)
            print(f"  \033[32m[+] {ip}:{port} - ACIK\033[0m")
        except Exception:
            print(f"  [-] {ip}:{port} - kapali/filtrelenmis")

    print(f"\n[+] Dogrulanan: {len(verified)}/{len(sample)}")
    return verified


# ============================================
# MENU
# ============================================

def shodan_search_menu():
    """Shodan/Censys search interactive menu."""
    os.system('cls' if os.name == 'nt' else 'clear')

    config = load_config()

    print("=" * 60)
    print(" Hedef Bulma (Shodan/Censys Entegrasyonu)")
    print("=" * 60)
    print()
    print("  Secenekler:")
    print("  0) API Anahtarlarini Ayarla")
    print("  1) Shodan ile Ara (Tum Protokoller)")
    print("  2) Shodan ile Ara (Ulke Bazli)")
    print("  3) Censys ile Ara")
    print("  4) Ozel Shodan Sorgusu")
    print("  5) Kayitli Sonuclari Dogrula")
    print("  6) Mevcut Hedef Dosyalarini Goster")
    print()

    has_shodan = bool(config.get('shodan_api_key'))
    has_censys = bool(config.get('censys_api_id') and config.get('censys_api_secret'))

    status_shodan = "\033[32mAKTIF\033[0m" if has_shodan else "\033[31mEKSIK\033[0m"
    status_censys = "\033[32mAKTIF\033[0m" if has_censys else "\033[31mEKSIK\033[0m"
    print(f"  Shodan API: {status_shodan}")
    print(f"  Censys API: {status_censys}")
    print()
    print("  Geri donmek icin 'back' yazin")
    print()

    choice = input("\033[37m(\033[0m\033[2;31mhedef\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        _setup_api_keys(config)
        shodan_search_menu()
    elif choice == "1":
        if not has_shodan:
            print("[-] Shodan API anahtari gerekli! Once 0 ile ayarlayin.")
            time.sleep(2)
        else:
            _shodan_search_all(config['shodan_api_key'])
        shodan_search_menu()
    elif choice == "2":
        if not has_shodan:
            print("[-] Shodan API anahtari gerekli!")
            time.sleep(2)
        else:
            _shodan_search_country(config['shodan_api_key'])
        shodan_search_menu()
    elif choice == "3":
        if not has_censys:
            print("[-] Censys API kimlik bilgileri gerekli!")
            time.sleep(2)
        else:
            _censys_search_all(config['censys_api_id'], config['censys_api_secret'])
        shodan_search_menu()
    elif choice == "4":
        if not has_shodan:
            print("[-] Shodan API anahtari gerekli!")
            time.sleep(2)
        else:
            _shodan_custom_query(config['shodan_api_key'])
        shodan_search_menu()
    elif choice == "5":
        _verify_saved_results()
        shodan_search_menu()
    elif choice == "6":
        _show_target_files()
        shodan_search_menu()
    elif choice == "back" or choice == "geri":
        return
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-6)')
        time.sleep(1.5)
        shodan_search_menu()


def _setup_api_keys(config):
    """Setup API keys."""
    print("\n" + "=" * 50)
    print(" API Anahtari Ayarlari")
    print("=" * 50)
    print()
    print("Shodan API Key: https://account.shodan.io")
    print("Censys API: https://search.censys.io/account/api")
    print()

    shodan_key = get_input("Shodan API Key", config.get('shodan_api_key', ''))
    censys_id = get_input("Censys API ID", config.get('censys_api_id', ''))
    censys_secret = get_input("Censys API Secret", config.get('censys_api_secret', ''))

    config['shodan_api_key'] = shodan_key
    config['censys_api_id'] = censys_id
    config['censys_api_secret'] = censys_secret

    save_config(config)


def _shodan_search_all(api_key):
    """Search all protocols on Shodan."""
    print("\n[+] Shodan uzerinden tum protokoller aranacak...")
    print("[+] Protokoller: SS7, Diameter, GTP, SIP\n")

    max_results = _prompt_int("Protokol basina maks sonuc", 100, min_value=1, max_value=1000)

    results = search_shodan_all(api_key, max_per_query=max_results)
    if results:
        save_results(results, "shodan")
    else:
        print("[-] Sonuc bulunamadi.")

    input("\nDevam etmek icin Enter'a basin...")


def _shodan_search_country(api_key):
    """Search by country on Shodan."""
    print("\n[+] Ulke bazli arama")
    print()
    for code, name in sorted(COUNTRY_CODES.items()):
        print(f"  {code}: {name}")
    print()

    country = get_input("Ulke kodu (orn: TR)", "TR").upper()
    if country not in COUNTRY_CODES:
        print(f"[-] Bilinmeyen ulke kodu: {country}")
        print("[*] Yine de aranacak...")

    print(f"\n[+] {COUNTRY_CODES.get(country, country)} icin arama yapiliyor...\n")

    max_results = _prompt_int("Protokol basina maks sonuc", 100, min_value=1, max_value=1000)
    results = search_shodan_all(api_key, country=country, max_per_query=max_results)

    if results:
        save_results(results, f"shodan_{country.lower()}")

        # Quick verify
        do_verify = get_input("Hizli dogrulama yapilsin mi? (e/h)", "e")
        if do_verify.lower() in ['e', 'y', 'evet', 'yes']:
            for proto, proto_results in results.items():
                if proto_results:
                    print(f"\n--- {proto} Dogrulamasi ---")
                    quick_verify_results(proto_results, proto)
    else:
        print("[-] Sonuc bulunamadi.")

    input("\nDevam etmek icin Enter'a basin...")


def _censys_search_all(api_id, api_secret):
    """Search all protocols on Censys."""
    print("\n[+] Censys uzerinden tum protokoller aranacak...")

    results = search_censys_all(api_id, api_secret)
    if results:
        save_results(results, "censys")
    else:
        print("[-] Sonuc bulunamadi.")

    input("\nDevam etmek icin Enter'a basin...")


def _shodan_custom_query(api_key):
    """Custom Shodan query."""
    print("\n[+] Ozel Shodan Sorgusu")
    print("[+] Ornek sorgular:")
    print("    port:2905 country:TR")
    print("    port:3868 org:\"Turkcell\"")
    print("    port:5060 sip country:DE")
    print()

    while True:
        query = get_input("Sorgu")
        if query:
            break
        print("[-] Sorgu bos olamaz.")
    max_results = _prompt_int("Maks sonuc", 100, min_value=1, max_value=1000)

    results = search_shodan(api_key, query, max_results=max_results)

    if results:
        print(f"\n[+] {len(results)} sonuc bulundu:")
        for r in results[:20]:
            print(f"  {r['ip']}:{r['port']} | {r['org']} | {r['country']}")
        if len(results) > 20:
            print(f"  ... ve {len(results) - 20} daha")

        # Save
        fname = f"shodan_custom_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"{r['ip']}:{r['port']} | {r['org']} | {r['country']}\n")
        print(f"[+] Sonuclar kaydedildi: {fname}")
    else:
        print("[-] Sonuc bulunamadi.")

    input("\nDevam etmek icin Enter'a basin...")


def _verify_saved_results():
    """Verify previously saved search results."""
    print("\n[+] Kayitli sonuclari dogrulama")

    # Find leak/target files
    files = []
    root = os.path.dirname(os.path.dirname(__file__))
    for f in os.listdir(root):
        if (f.startswith('leaks_') or f.startswith('shodan_') or f.startswith('targets_')) and f.endswith('.txt'):
            files.append(f)

    if not files:
        print("[-] Dogrulanacak dosya bulunamadi.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    print("\nDosyalar:")
    for i, f in enumerate(files):
        print(f"  {i}) {f}")

    idx = _prompt_int("Dosya numarasi", 0, min_value=0, max_value=len(files) - 1)
    if idx >= len(files):
        print("[-] Gecersiz secim.")
        return

    filepath = os.path.join(root, files[idx])
    targets = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Extract IP:port
            parts = line.split('|')[0].strip().split(':')
            if len(parts) >= 2:
                try:
                    ip = parts[0].strip()
                    port = int(parts[1].strip())
                    targets.append({'ip': ip, 'port': port})
                except ValueError:
                    continue

    if not targets:
        print("[-] Hedef bulunamadi.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    print(f"[+] {len(targets)} hedef bulundu. Dogrulama basliyor...")
    verified = quick_verify_results(targets, "MIXED", max_verify=min(50, len(targets)))

    if verified:
        fname = f"verified_{files[idx]}"
        with open(os.path.join(root, fname), "w", encoding="utf-8") as f:
            for v in verified:
                f.write(f"{v['ip']}:{v['port']}\n")
        print(f"[+] Dogrulanmis hedefler: {os.path.join(root, fname)}")

    input("\nDevam etmek icin Enter'a basin...")


def _show_target_files():
    """Show available target files."""
    print("\n[+] Mevcut hedef dosyalari:")
    root = os.path.dirname(os.path.dirname(__file__))

    files = []
    for f in sorted(os.listdir(root)):
        if any(f.startswith(p) for p in ['leaks_', 'shodan_', 'censys_', 'targets_', 'verified_',
                                          'turkey_', 'diameter_', 'sip_']):
            filepath = os.path.join(root, f)
            size = os.path.getsize(filepath)
            try:
                with open(filepath, 'r') as fh:
                    lines = sum(1 for _ in fh)
            except Exception:
                lines = 0
            files.append((f, size, lines))

    if files:
        print(f"\n  {'Dosya':<45} {'Boyut':>10} {'Satir':>8}")
        print("  " + "-" * 65)
        for name, size, lines in files:
            size_str = f"{size/1024:.1f} KB" if size > 1024 else f"{size} B"
            print(f"  {name:<45} {size_str:>10} {lines:>8}")
    else:
        print("  Henuz hedef dosyasi yok.")

    input("\nDevam etmek icin Enter'a basin...")


if __name__ == "__main__":
    shodan_search_menu()
