#!/usr/bin/env python3
"""
Quick Multi-Protocol Scanner
Tests Diameter (3868), GTP (2123), and SIP (5060) targets.
Reads from leak files and tests with real protocol handshakes.
"""
import socket
import struct
import sys
import os
import re
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# DIAMETER FUNCTIONS
# ============================================================

def build_cer_quick():
    """Build minimal Diameter CER."""
    origin_host = b"scanner.test.com"
    origin_realm = b"test.com"

    # AVPs
    avps = b''
    # Origin-Host (264)
    oh_len = 8 + len(origin_host)
    oh_pad = (4 - (oh_len % 4)) % 4
    avps += struct.pack("!I", 264) + struct.pack("!B", 0x40) + struct.pack("!I", oh_len)[1:] + origin_host + b'\x00' * oh_pad
    # Origin-Realm (296)
    or_len = 8 + len(origin_realm)
    or_pad = (4 - (or_len % 4)) % 4
    avps += struct.pack("!I", 296) + struct.pack("!B", 0x40) + struct.pack("!I", or_len)[1:] + origin_realm + b'\x00' * or_pad

    msg_len = 20 + len(avps)
    header = struct.pack("!B", 1)  # version
    header += struct.pack("!I", msg_len)[1:]  # length (3 bytes)
    header += struct.pack("!B", 0xC0)  # flags: R+P
    header += struct.pack("!I", 257)[1:]  # CER command code (3 bytes)
    header += struct.pack("!I", 0)  # app-id
    header += struct.pack("!I", random.randint(1, 0xFFFFFFFF))  # hop-by-hop
    header += struct.pack("!I", random.randint(1, 0xFFFFFFFF))  # end-to-end

    return header + avps


def test_diameter(ip, port=3868, timeout=3):
    """Test Diameter CER/CEA handshake."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        cer = build_cer_quick()
        sock.send(cer)

        resp = sock.recv(4096)
        if resp and len(resp) >= 20:
            # Check Diameter version
            if resp[0] == 0x01:
                cmd_code = struct.unpack("!I", b'\x00' + resp[5:8])[0]
                if cmd_code == 257:  # CEA
                    return {'success': True, 'type': 'DIAMETER', 'ip': ip, 'port': port,
                            'detail': f'CEA received ({len(resp)} bytes)', 'raw': resp}
                return {'success': True, 'type': 'DIAMETER', 'ip': ip, 'port': port,
                        'detail': f'Response cmd={cmd_code} ({len(resp)} bytes)', 'raw': resp}
            return {'success': True, 'type': 'DIAMETER', 'ip': ip, 'port': port,
                    'detail': f'Non-Diameter response ({len(resp)} bytes)'}
        return {'success': False, 'ip': ip, 'port': port, 'error': 'No response'}
    except ConnectionRefusedError:
        return {'success': False, 'ip': ip, 'port': port, 'error': 'Refused'}
    except ConnectionResetError:
        return {'success': False, 'ip': ip, 'port': port, 'error': 'Reset'}
    except socket.timeout:
        return {'success': False, 'ip': ip, 'port': port, 'error': 'Timeout'}
    except OSError as e:
        return {'success': False, 'ip': ip, 'port': port, 'error': str(e)}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================
# GTP FUNCTIONS
# ============================================================

def build_gtp_echo():
    """Build GTPv2 Echo Request."""
    # GTPv2-C header: version=2, T=0, type=1 (Echo Request)
    # Length=4 (just IE), TEID not present, Seq=1
    header = bytes([
        0x40,   # version=2, P=0, T=0
        0x01,   # type=1 (Echo Request)
        0x00, 0x04,  # length=4
        0x00, 0x00, 0x01, 0x00,  # sequence + spare
    ])
    return header


def test_gtp(ip, port=2123, timeout=3):
    """Test GTP Echo Request/Response."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        echo = build_gtp_echo()
        sock.sendto(echo, (ip, port))

        resp, addr = sock.recvfrom(4096)
        if resp and len(resp) >= 4:
            version = (resp[0] >> 5) & 0x07
            msg_type = resp[1]
            if version == 2 and msg_type == 2:  # Echo Response
                return {'success': True, 'type': 'GTP', 'ip': ip, 'port': port,
                        'detail': f'GTPv2 Echo Response ({len(resp)} bytes)'}
            elif version == 1 and msg_type == 2:
                return {'success': True, 'type': 'GTP', 'ip': ip, 'port': port,
                        'detail': f'GTPv1 Echo Response ({len(resp)} bytes)'}
            return {'success': True, 'type': 'GTP', 'ip': ip, 'port': port,
                    'detail': f'GTP response v={version} t={msg_type} ({len(resp)} bytes)'}
        return {'success': False, 'ip': ip, 'port': port, 'error': 'No response'}
    except socket.timeout:
        return {'success': False, 'ip': ip, 'port': port, 'error': 'Timeout'}
    except OSError as e:
        return {'success': False, 'ip': ip, 'port': port, 'error': str(e)}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================
# SIP FUNCTIONS
# ============================================================

def test_sip(ip, port=5060, timeout=3):
    """Test SIP OPTIONS."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        branch = f"z9hG4bK{random.randint(100000, 999999)}"
        call_id = f"{random.randint(100000000, 999999999)}@scanner"
        tag = str(random.randint(10000, 99999))

        msg = (
            f"OPTIONS sip:{ip}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 1.2.3.4:5060;branch={branch}\r\n"
            f"From: <sip:scanner@test.com>;tag={tag}\r\n"
            f"To: <sip:{ip}:{port}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode()

        sock.sendto(msg, (ip, port))

        resp, addr = sock.recvfrom(4096)
        if resp:
            resp_str = resp.decode('utf-8', errors='ignore')
            # Extract status code
            first_line = resp_str.split('\r\n')[0] if '\r\n' in resp_str else resp_str[:50]
            status = 'Unknown'
            m = re.search(r'SIP/2\.0 (\d+)', first_line)
            if m:
                status = m.group(1)
            return {'success': True, 'type': 'SIP', 'ip': ip, 'port': port,
                    'detail': f'SIP {status} ({first_line.strip()})'}
        return {'success': False, 'ip': ip, 'port': port, 'error': 'No response'}
    except socket.timeout:
        return {'success': False, 'ip': ip, 'port': port, 'error': 'Timeout'}
    except OSError as e:
        return {'success': False, 'ip': ip, 'port': port, 'error': str(e)}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================
# MAIN
# ============================================================

def load_targets(filename, proto_filter=None):
    """Load targets from leak file."""
    targets = []
    if not os.path.exists(filename):
        return targets
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if m:
                ip = m.group(1)
                port = int(m.group(2))
                if (ip, port) not in targets:
                    targets.append((ip, port))
    return targets


def main():
    print("=" * 60)
    print(" Quick Multi-Protocol Scanner")
    print(" Diameter (CER/CEA) + GTP (Echo) + SIP (OPTIONS)")
    print("=" * 60)

    # Load Diameter targets
    diameter_targets = []
    for fname in ['leaks_diameter_new.txt', 'leaks_diameter.txt']:
        if os.path.exists(fname):
            diameter_targets = load_targets(fname)
            print(f"\n[+] Diameter: {len(diameter_targets)} hedef ({fname})")
            break

    if not diameter_targets:
        print("\n[-] Diameter hedef dosyasi bulunamadi")

    # GTP targets - use common ranges
    gtp_targets = []
    for fname in ['leaks_gtp.txt']:
        if os.path.exists(fname):
            gtp_targets = load_targets(fname)
            print(f"[+] GTP: {len(gtp_targets)} hedef ({fname})")
            break

    # SIP targets
    sip_targets = []
    for fname in ['leaks_sip.txt']:
        if os.path.exists(fname):
            sip_targets = load_targets(fname)
            print(f"[+] SIP: {len(sip_targets)} hedef ({fname})")
            break

    # Manual targets option
    print("\n[+] Manuel hedef ekle (bos birak atlama):")
    extra_d = input("  Diameter IP (virgul ayir): ").strip()
    extra_g = input("  GTP IP (virgul ayir): ").strip()
    extra_s = input("  SIP IP (virgul ayir): ").strip()

    if extra_d:
        for ip in extra_d.split(','):
            ip = ip.strip()
            if ip:
                diameter_targets.append((ip, 3868))
    if extra_g:
        for ip in extra_g.split(','):
            ip = ip.strip()
            if ip:
                gtp_targets.append((ip, 2123))
    if extra_s:
        for ip in extra_s.split(','):
            ip = ip.strip()
            if ip:
                sip_targets.append((ip, 5060))

    total = len(diameter_targets) + len(gtp_targets) + len(sip_targets)
    if total == 0:
        print("[-] Hedef yok.")
        return

    # Limit for speed
    MAX_DIAMETER = 100
    MAX_GTP = 50
    MAX_SIP = 50

    if len(diameter_targets) > MAX_DIAMETER:
        print(f"\n[!] Diameter: {len(diameter_targets)} hedeften ilk {MAX_DIAMETER} tanesi taranacak")
        # Sample diverse IPs
        seen_subnets = set()
        sampled = []
        for ip, port in diameter_targets:
            subnet = '.'.join(ip.split('.')[:3])
            if subnet not in seen_subnets:
                seen_subnets.add(subnet)
                sampled.append((ip, port))
            if len(sampled) >= MAX_DIAMETER:
                break
        # Fill rest
        for ip, port in diameter_targets:
            if (ip, port) not in sampled and len(sampled) < MAX_DIAMETER:
                sampled.append((ip, port))
        diameter_targets = sampled

    total = len(diameter_targets) + len(gtp_targets) + len(sip_targets)
    print(f"\n[+] Toplam: {total} hedef (D:{len(diameter_targets)} G:{len(gtp_targets)} S:{len(sip_targets)})")

    confirm = input("[?] Tarama baslatilsin mi? [E/h]: ").strip()
    if confirm.lower() in ('h', 'n', 'hayir'):
        return

    successes = []
    tested = 0

    # ---- DIAMETER ----
    if diameter_targets:
        print(f"\n{'='*60}")
        print(f" DIAMETER TARAMASI ({len(diameter_targets)} hedef)")
        print(f"{'='*60}")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_diameter, ip, port): (ip, port)
                       for ip, port in diameter_targets}
            for future in as_completed(futures):
                tested += 1
                result = future.result()
                ip, port = futures[future]
                if result.get('success'):
                    successes.append(result)
                    print(f"  \033[32m[+] {ip}:{port} -> {result['detail']}\033[0m")
                else:
                    if tested % 20 == 0:
                        print(f"  [{tested}/{len(diameter_targets)}] {result.get('error', '?')}...")

    # ---- GTP ----
    if gtp_targets:
        print(f"\n{'='*60}")
        print(f" GTP TARAMASI ({len(gtp_targets)} hedef)")
        print(f"{'='*60}")

        tested = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_gtp, ip, port): (ip, port)
                       for ip, port in gtp_targets}
            for future in as_completed(futures):
                tested += 1
                result = future.result()
                if result.get('success'):
                    successes.append(result)
                    ip, port = futures[future]
                    print(f"  \033[32m[+] {ip}:{port} -> {result['detail']}\033[0m")

    # ---- SIP ----
    if sip_targets:
        print(f"\n{'='*60}")
        print(f" SIP TARAMASI ({len(sip_targets)} hedef)")
        print(f"{'='*60}")

        tested = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_sip, ip, port): (ip, port)
                       for ip, port in sip_targets}
            for future in as_completed(futures):
                tested += 1
                result = future.result()
                if result.get('success'):
                    successes.append(result)
                    ip, port = futures[future]
                    print(f"  \033[32m[+] {ip}:{port} -> {result['detail']}\033[0m")

    # ---- SUMMARY ----
    print(f"\n{'='*60}")
    print(f" SONUC OZETI")
    print(f"{'='*60}")

    if successes:
        print(f"\n\033[32m[+] {len(successes)} hedef yanit verdi!\033[0m\n")

        d_ok = [s for s in successes if s['type'] == 'DIAMETER']
        g_ok = [s for s in successes if s['type'] == 'GTP']
        s_ok = [s for s in successes if s['type'] == 'SIP']

        if d_ok:
            print(f"\n  DIAMETER ({len(d_ok)} basarili):")
            for r in d_ok:
                print(f"    \033[32m{r['ip']}:{r['port']} - {r['detail']}\033[0m")

        if g_ok:
            print(f"\n  GTP ({len(g_ok)} basarili):")
            for r in g_ok:
                print(f"    \033[32m{r['ip']}:{r['port']} - {r['detail']}\033[0m")

        if s_ok:
            print(f"\n  SIP ({len(s_ok)} basarili):")
            for r in s_ok:
                print(f"    \033[32m{r['ip']}:{r['port']} - {r['detail']}\033[0m")

        # Save results
        with open('protocol_scan_results.txt', 'w', encoding='utf-8') as f:
            f.write(f"Multi-Protocol Scan Results\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in successes:
                f.write(f"[{r['type']}] {r['ip']}:{r['port']} - {r['detail']}\n")
        print(f"\n[+] Sonuclar protocol_scan_results.txt dosyasina kaydedildi.")
    else:
        print(f"\n\033[31m[-] Hicbir hedef yanit vermedi.\033[0m")

    input("\nDevam etmek icin Enter'a basin...")


if __name__ == "__main__":
    main()
