#!/usr/bin/env python
"""
5G Core Network Security Module for SigPloit
Basic reconnaissance and scanning for 5G infrastructure.

Focuses on:
- HTTP/2 SBI (Service Based Interface) endpoint discovery
- NRF (Network Repository Function) discovery
- PFCP (Packet Forwarding Control Protocol) scanning - N4 interface
- N32/SEPP roaming security checks

NOTE: This module is for reconnaissance/scanning only.
5G protocols are significantly more complex than SS7/Diameter.
"""
import sys
import os
import socket
import struct
import time
import json
import random
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_input(prompt, default=None):
    if default:
        data = input(f"{prompt} [{default}]: ")
        return data if data else default
    return input(f"{prompt}: ")


# ============================================
# 5G NF (Network Function) Types
# ============================================

NF_TYPES = {
    'NRF': {'description': 'Network Repository Function', 'default_port': 8443, 'path': '/nnrf-disc/v1/nf-instances'},
    'AMF': {'description': 'Access and Mobility Management', 'default_port': 8443, 'path': '/namf-comm/v1/'},
    'SMF': {'description': 'Session Management Function', 'default_port': 8443, 'path': '/nsmf-pdusession/v1/'},
    'UDM': {'description': 'Unified Data Management', 'default_port': 8443, 'path': '/nudm-sdm/v2/'},
    'AUSF': {'description': 'Authentication Server Function', 'default_port': 8443, 'path': '/nausf-auth/v1/'},
    'PCF': {'description': 'Policy Control Function', 'default_port': 8443, 'path': '/npcf-smpolicycontrol/v1/'},
    'UPF': {'description': 'User Plane Function', 'default_port': 8805, 'path': None},  # PFCP, not HTTP
    'NSSF': {'description': 'Network Slice Selection Function', 'default_port': 8443, 'path': '/nnssf-nsselection/v2/'},
    'NEF': {'description': 'Network Exposure Function', 'default_port': 8443, 'path': '/3gpp-monitoring-event/v1/'},
    'SEPP': {'description': 'Security Edge Protection Proxy', 'default_port': 443, 'path': '/n32f-handshake/v1/'},
}

# Known 5G SBI API paths for discovery
SBI_PATHS = [
    '/nnrf-disc/v1/nf-instances',
    '/nnrf-nfm/v1/nf-instances',
    '/namf-comm/v1/ue-contexts',
    '/nsmf-pdusession/v1/sm-contexts',
    '/nudm-sdm/v2/shared-data',
    '/nudm-uecm/v1/registrations',
    '/nausf-auth/v1/ue-authentications',
    '/npcf-smpolicycontrol/v1/sm-policies',
    '/nssf-nsselection/v2/network-slice-information',
    '/nnef-eventexposure/v1/subscriptions',
    '/n32f-handshake/v1/exchange-capability',
]


# ============================================
# HTTP/2 SBI SCANNING
# ============================================

def scan_sbi_endpoint(ip, port, path, timeout=5, use_https=True):
    """Scan a 5G SBI endpoint via HTTP/1.1 (fallback - no h2 dependency)."""
    result = {
        'ip': ip,
        'port': port,
        'path': path,
        'status': 0,
        'server': '',
        'response': '',
        'accessible': False,
    }

    try:
        import ssl

        scheme = "https" if use_https else "http"

        # Try with requests first (simpler)
        try:
            import requests
            url = f"{scheme}://{ip}:{port}{path}"
            resp = requests.get(url, timeout=timeout, verify=False,
                               headers={'Accept': 'application/json', 'User-Agent': 'SigPloit/5G-Scanner'})
            result['status'] = resp.status_code
            result['server'] = resp.headers.get('Server', '')
            result['response'] = resp.text[:500]
            result['accessible'] = resp.status_code < 500

            return result
        except ImportError:
            pass

        # Fallback: raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)

        sock.connect((ip, port))

        # HTTP/1.1 request
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Accept: application/json\r\n"
            f"User-Agent: SigPloit/5G-Scanner\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.send(request.encode())

        response = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        sock.close()

        resp_text = response.decode('utf-8', errors='ignore')
        if 'HTTP/' in resp_text:
            status_line = resp_text.split('\r\n')[0]
            parts = status_line.split(' ', 2)
            if len(parts) >= 2:
                try:
                    result['status'] = int(parts[1])
                except ValueError:
                    pass

            for line in resp_text.split('\r\n'):
                if line.lower().startswith('server:'):
                    result['server'] = line.split(':', 1)[1].strip()
                    break

            # Get body
            if '\r\n\r\n' in resp_text:
                result['response'] = resp_text.split('\r\n\r\n', 1)[1][:500]

            result['accessible'] = result['status'] < 500

    except ConnectionRefusedError:
        result['status'] = -1
    except socket.timeout:
        result['status'] = -2
    except Exception as e:
        result['status'] = -3
        result['response'] = str(e)[:200]

    return result


def discover_nrf(ip, port=8443, timeout=5):
    """Discover NRF (Network Repository Function) and list registered NFs."""
    print(f"\n[+] NRF Discovery: {ip}:{port}")

    # Try NRF Discovery API
    paths = [
        '/nnrf-disc/v1/nf-instances?target-nf-type=AMF',
        '/nnrf-disc/v1/nf-instances?target-nf-type=SMF',
        '/nnrf-disc/v1/nf-instances?target-nf-type=UDM',
        '/nnrf-nfm/v1/nf-instances',
    ]

    discovered_nfs = []

    for path in paths:
        result = scan_sbi_endpoint(ip, port, path, timeout)
        if result['accessible']:
            print(f"  \033[32m[+] {path}: {result['status']}\033[0m")
            if result['response']:
                try:
                    data = json.loads(result['response'])
                    # Parse NF instances
                    nf_instances = data.get('nfInstances', [])
                    if not nf_instances and isinstance(data, list):
                        nf_instances = data

                    for nf in nf_instances:
                        nf_type = nf.get('nfType', 'Unknown')
                        nf_id = nf.get('nfInstanceId', 'N/A')
                        nf_status = nf.get('nfStatus', 'N/A')
                        ipv4 = nf.get('ipv4Addresses', [])
                        fqdn = nf.get('fqdn', '')

                        discovered_nfs.append({
                            'type': nf_type,
                            'id': nf_id,
                            'status': nf_status,
                            'ipv4': ipv4,
                            'fqdn': fqdn,
                        })

                        print(f"    NF: {nf_type} | ID: {nf_id[:12]}... | Status: {nf_status}")
                        if ipv4:
                            print(f"        IP: {', '.join(ipv4)}")
                        if fqdn:
                            print(f"        FQDN: {fqdn}")

                except json.JSONDecodeError:
                    print(f"    Yanit (JSON degil): {result['response'][:100]}")
        else:
            status_text = {-1: 'Reddedildi', -2: 'Zaman asimi', -3: 'Hata'}.get(result['status'], str(result['status']))
            print(f"  [-] {path}: {status_text}")

    return discovered_nfs


# ============================================
# PFCP SCANNING (N4 Interface - UPF/SMF)
# ============================================

def build_pfcp_heartbeat():
    """Build a PFCP Heartbeat Request message."""
    # PFCP Header (Version=1, MP=0, S=0, Type=1 HeartbeatReq)
    seq = random.randint(1, 0xFFFFFF)

    # Recovery Time Stamp IE (Type=96, Length=4)
    ts = int(time.time()) - 2208988800  # NTP epoch
    recovery_ie = struct.pack('!HH', 96, 4) + struct.pack('!I', ts)

    msg_len = 4 + len(recovery_ie)  # 4 bytes for seq+spare

    header = struct.pack('!BBH',
                         0x20,     # Version=1, MP=0, S=0
                         1,        # Type: Heartbeat Request
                         msg_len)
    header += struct.pack('!I', (seq << 8))[:3] + b'\x00'  # Sequence + spare

    return header + recovery_ie


def build_pfcp_association_setup():
    """Build a PFCP Association Setup Request."""
    seq = random.randint(1, 0xFFFFFF)

    # Node ID IE (Type=60, Length=5, Type=0 IPv4)
    node_id = struct.pack('!HH', 60, 5)
    node_id += struct.pack('!B', 0)  # IPv4
    node_id += socket.inet_aton("1.2.3.4")

    # Recovery Time Stamp IE
    ts = int(time.time()) - 2208988800
    recovery_ie = struct.pack('!HH', 96, 4) + struct.pack('!I', ts)

    payload = node_id + recovery_ie
    msg_len = 4 + len(payload)

    header = struct.pack('!BBH',
                         0x20,     # Version=1, MP=0, S=0
                         5,        # Type: Association Setup Request
                         msg_len)
    header += struct.pack('!I', (seq << 8))[:3] + b'\x00'

    return header + payload


def scan_pfcp(ip, port=8805, timeout=5):
    """Scan for PFCP (N4) endpoint."""
    result = {
        'ip': ip,
        'port': port,
        'heartbeat': False,
        'association': False,
        'response_type': 0,
        'details': '',
    }

    # Try heartbeat
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        hb = build_pfcp_heartbeat()
        sock.sendto(hb, (ip, port))

        data, addr = sock.recvfrom(1024)
        sock.close()

        if data and len(data) >= 4:
            msg_type = data[1]
            if msg_type == 2:  # Heartbeat Response
                result['heartbeat'] = True
                result['details'] = "PFCP Heartbeat Response alindi"
                print(f"  \033[32m[+] {ip}:{port} PFCP Heartbeat yanit!\033[0m")
            else:
                result['details'] = f"PFCP yanit (type={msg_type})"
                result['response_type'] = msg_type

    except socket.timeout:
        result['details'] = 'Zaman asimi'
    except Exception as e:
        result['details'] = str(e)

    # Try association setup
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        assoc = build_pfcp_association_setup()
        sock.sendto(assoc, (ip, port))

        data, addr = sock.recvfrom(1024)
        sock.close()

        if data and len(data) >= 4:
            msg_type = data[1]
            if msg_type == 6:  # Association Setup Response
                result['association'] = True
                result['details'] += " | Association kabul edildi!"
                print(f"  \033[31m[!!!] {ip}:{port} PFCP Association kabul edildi!\033[0m")

    except Exception:
        pass

    return result


# ============================================
# N32/SEPP SCANNING
# ============================================

def scan_sepp(ip, port=443, timeout=5):
    """Scan for SEPP (Security Edge Protection Proxy) on N32 interface."""
    result = {
        'ip': ip,
        'port': port,
        'accessible': False,
        'details': '',
        'tls_info': '',
    }

    # Check TLS certificate for 5G-related info
    try:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((ip, port), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=ip)

        cert = ssock.getpeercert(binary_form=False)
        if cert:
            subject = dict(x[0] for x in cert.get('subject', ()))
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            cn = subject.get('commonName', '')
            org = subject.get('organizationName', '')
            result['tls_info'] = f"CN={cn}, Org={org}"
            result['accessible'] = True
            print(f"  [+] TLS: CN={cn}, Org={org}")

        ssock.close()
    except Exception as e:
        result['details'] = str(e)[:200]

    # Try N32 handshake endpoint
    n32_result = scan_sbi_endpoint(ip, port, '/n32f-handshake/v1/exchange-capability', timeout)
    if n32_result['accessible']:
        result['accessible'] = True
        result['details'] = f"N32 endpoint active (HTTP {n32_result['status']})"
        print(f"  \033[33m[!] N32/SEPP endpoint bulunan: {ip}:{port}\033[0m")

    return result


# ============================================
# COMPREHENSIVE SCANNER
# ============================================

def scan_5g_target(ip, ports=None, timeout=5):
    """Comprehensive 5G scan of a single target."""
    if ports is None:
        ports = [8443, 443, 8080, 8805, 29510, 29518, 29509, 29503, 29507]

    results = {
        'ip': ip,
        'sbi_endpoints': [],
        'pfcp': None,
        'sepp': None,
        'open_ports': [],
    }

    print(f"\n{'='*50}")
    print(f"[>] 5G Tarama: {ip}")
    print(f"{'='*50}")

    # Port scan
    print("\n[1/4] Port tarama...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                results['open_ports'].append(port)
                print(f"  [+] Port {port}: ACIK")
        except Exception:
            pass

    if not results['open_ports']:
        print("  [-] Acik port bulunamadi")
        return results

    # SBI endpoint discovery
    print("\n[2/4] SBI endpoint kesfetme...")
    for port in results['open_ports']:
        if port == 8805:
            continue  # PFCP is UDP

        for path in SBI_PATHS[:6]:  # Limit for speed
            sbi_result = scan_sbi_endpoint(ip, port, path, timeout)
            if sbi_result['accessible']:
                results['sbi_endpoints'].append(sbi_result)
                print(f"  \033[32m[+] {port}{path}: {sbi_result['status']}\033[0m")
                if sbi_result['server']:
                    print(f"      Server: {sbi_result['server']}")

    # PFCP scan
    print("\n[3/4] PFCP (N4) tarama...")
    results['pfcp'] = scan_pfcp(ip, 8805, timeout)

    # SEPP/N32 scan
    print("\n[4/4] SEPP/N32 tarama...")
    for port in [443, 8443]:
        if port in results['open_ports']:
            results['sepp'] = scan_sepp(ip, port, timeout)
            break

    return results


# ============================================
# MENU
# ============================================

def fiveg_menu():
    """5G security scanning menu."""
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print(" 5G Core Network Guvenlik Taramasi")
    print("=" * 60)
    print()
    print("  Secenekler:")
    print("  0) Kapsamli 5G Tarama (Tek Hedef)")
    print("  1) NRF Kesfetme (Network Repository)")
    print("  2) SBI Endpoint Tarama (HTTP/2)")
    print("  3) PFCP Tarama (N4 - UPF/SMF)")
    print("  4) SEPP/N32 Tarama (Roaming)")
    print("  5) Toplu 5G Tarama (Dosyadan)")
    print("  6) 5G NF Turleri Bilgi")
    print()
    print("  \033[33mNOT: Bu modul kesif/tarama icin.\033[0m")
    print("  \033[33m5G saldirilari henuz gelistirme asamasinda.\033[0m")
    print()
    print("  Geri donmek icin 'back' yazin")
    print()

    choice = input("\033[37m(\033[0m\033[2;31m5g\033[0m\033[37m)>\033[0m ")

    if choice == "0":
        _comprehensive_scan()
        fiveg_menu()
    elif choice == "1":
        _nrf_discovery()
        fiveg_menu()
    elif choice == "2":
        _sbi_scan()
        fiveg_menu()
    elif choice == "3":
        _pfcp_scan()
        fiveg_menu()
    elif choice == "4":
        _sepp_scan()
        fiveg_menu()
    elif choice == "5":
        _batch_scan()
        fiveg_menu()
    elif choice == "6":
        _show_nf_info()
        fiveg_menu()
    elif choice == "back" or choice == "geri":
        return
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-6)')
        time.sleep(1.5)
        fiveg_menu()


def _comprehensive_scan():
    """Full 5G scan of a single target."""
    ip = get_input("Hedef IP", "10.0.0.1")
    ports_str = get_input("Portlar (virgul ile)", "8443,443,8080,8805,29510,29518,29509")
    ports = [int(p.strip()) for p in ports_str.split(',')]
    timeout = int(get_input("Zaman asimi (sn)", "5"))

    results = scan_5g_target(ip, ports, timeout)

    # Summary
    print(f"\n{'='*50}")
    print(f" SONUC OZETI: {ip}")
    print(f"{'='*50}")
    print(f"  Acik Portlar: {results['open_ports']}")
    print(f"  SBI Endpointleri: {len(results['sbi_endpoints'])}")

    if results['pfcp'] and results['pfcp']['heartbeat']:
        print(f"  PFCP: \033[32mAKTIF\033[0m")
    else:
        print(f"  PFCP: Yanit yok")

    if results['sepp'] and results['sepp']['accessible']:
        print(f"  SEPP/N32: \033[33mBULUNDU\033[0m")
    else:
        print(f"  SEPP/N32: Bulunamadi")

    # Save results
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"5g_scan_{ip}_{ts}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n[+] Sonuclar kaydedildi: {fname}")

    input("\nDevam etmek icin Enter'a basin...")


def _nrf_discovery():
    """NRF Discovery."""
    ip = get_input("NRF IP adresi", "10.0.0.1")
    port = int(get_input("NRF Port", "8443"))

    nfs = discover_nrf(ip, port)

    if nfs:
        print(f"\n[+] {len(nfs)} NF bulundu:")
        for nf in nfs:
            print(f"  {nf['type']:10s} | {nf['id'][:20]} | {nf['status']} | {nf.get('fqdn', '')}")
    else:
        print("\n[-] NF bulunamadi veya NRF erisilemiyor.")

    input("\nDevam etmek icin Enter'a basin...")


def _sbi_scan():
    """SBI endpoint scanning."""
    ip = get_input("Hedef IP", "10.0.0.1")
    port = int(get_input("Hedef Port", "8443"))
    use_https = get_input("HTTPS kullan? (e/h)", "e").lower() in ['e', 'y']

    print(f"\n[+] {len(SBI_PATHS)} SBI endpoint taranacak...\n")

    found = []
    for path in SBI_PATHS:
        result = scan_sbi_endpoint(ip, port, path, use_https=use_https)
        if result['accessible']:
            found.append(result)
            print(f"  \033[32m[+] {path}: HTTP {result['status']}\033[0m")
            if result['server']:
                print(f"      Server: {result['server']}")
        else:
            status_text = {-1: 'Reddedildi', -2: 'Zaman asimi', -3: 'Hata'}.get(result['status'], str(result['status']))
            print(f"  [-] {path}: {status_text}")

    print(f"\n[+] Bulunan SBI endpoint: {len(found)}/{len(SBI_PATHS)}")
    input("\nDevam etmek icin Enter'a basin...")


def _pfcp_scan():
    """PFCP scan."""
    ip = get_input("Hedef IP (UPF/SMF)", "10.0.0.1")
    port = int(get_input("PFCP Port", "8805"))

    result = scan_pfcp(ip, port)

    print(f"\n[+] PFCP Sonuc:")
    print(f"  Heartbeat: {'Evet' if result['heartbeat'] else 'Hayir'}")
    print(f"  Association: {'Evet' if result['association'] else 'Hayir'}")
    print(f"  Detay: {result['details']}")

    if result['association']:
        print(f"\n  \033[31m[!!!] ZAFIYET: PFCP Association kimlik dogrulamasi yok!\033[0m")
        print(f"  [!!!] UPF oturumlari manipule edilebilir!")

    input("\nDevam etmek icin Enter'a basin...")


def _sepp_scan():
    """SEPP/N32 scan."""
    ip = get_input("Hedef SEPP IP", "10.0.0.1")
    port = int(get_input("Port", "443"))

    result = scan_sepp(ip, port)

    print(f"\n[+] SEPP/N32 Sonuc:")
    print(f"  Erisim: {'Evet' if result['accessible'] else 'Hayir'}")
    if result['tls_info']:
        print(f"  TLS: {result['tls_info']}")
    if result['details']:
        print(f"  Detay: {result['details']}")

    input("\nDevam etmek icin Enter'a basin...")


def _batch_scan():
    """Batch 5G scanning from file."""
    print("\nHedef dosyasi girin (her satirda bir IP):")
    filename = get_input("Dosya", "targets_5g.txt")

    if not os.path.exists(filename):
        # Manual input
        print("[-] Dosya bulunamadi. Manuel giriyor:")
        ips = []
        while True:
            ip = input("  IP (bos = bitir): ").strip()
            if not ip:
                break
            ips.append(ip)
    else:
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not ips:
        print("[-] Hedef yok.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    print(f"\n[+] {len(ips)} hedef taranacak...")

    all_results = []
    for ip in ips:
        result = scan_5g_target(ip)
        all_results.append(result)

    # Save all results
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"5g_batch_{ts}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False, default=str)

    # Summary
    print(f"\n{'='*50}")
    print(f" TOPLU 5G TARAMA SONUCLARI")
    print(f"{'='*50}")
    for r in all_results:
        sbi_count = len(r.get('sbi_endpoints', []))
        pfcp = 'Evet' if r.get('pfcp', {}).get('heartbeat') else 'Hayir'
        sepp = 'Evet' if r.get('sepp', {}).get('accessible') else 'Hayir'
        print(f"  {r['ip']:>15s} | Portlar: {r['open_ports']} | SBI: {sbi_count} | PFCP: {pfcp} | SEPP: {sepp}")

    print(f"\n[+] Sonuclar kaydedildi: {fname}")
    input("\nDevam etmek icin Enter'a basin...")


def _show_nf_info():
    """Show 5G NF type information."""
    print("\n" + "=" * 60)
    print(" 5G Network Function (NF) Turleri")
    print("=" * 60)
    print()

    for nf_type, info in NF_TYPES.items():
        path = info.get('path', 'N/A') or 'PFCP (UDP)'
        print(f"  {nf_type:6s} | Port: {info['default_port']:5d} | {info['description']}")
        print(f"         | Path: {path}")
        print()

    print("Tarama Portlari:")
    print("  8443     - Varsayilan SBI (HTTPS)")
    print("  443      - SEPP/N32")
    print("  8805     - PFCP (N4)")
    print("  29510    - NRF")
    print("  29518    - AMF")
    print("  29509    - NSSF")
    print("  29503    - UDM")
    print("  29507    - PCF")

    input("\nDevam etmek icin Enter'a basin...")


if __name__ == "__main__":
    fiveg_menu()
