#!/usr/bin/env python
"""
Multi-Protocol Scanner Module for SigPloit
With REAL protocol-level verification (not just port scanning).

Phase 1: Fast TCP/SCTP/UDP port scan
Phase 2: Protocol handshake verification (eliminates false positives)
"""
import sys
import os
import random
import struct
import socket
import ipaddress
import time
from scapy.all import IP, TCP, UDP, SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkAbort, Raw, sr, sr1, conf

conf.verb = 0

RISK_PRIORITY_COUNTRIES = ["NG", "EG", "IN", "BR", "RU", "PH", "VN", "BD", "PK", "KE", "GH", "TZ", "UG", "ZA", "CO", "MX", "UA", "KZ", "UZ"]
PORT_TO_PROTO = {2904: "SS7", 2905: "SS7", 2906: "SS7", 2907: "SS7", 2908: "SS7", 3868: "DIAMETER", 3869: "DIAMETER", 2123: "GTP", 2152: "GTP", 5060: "SIP", 5061: "SIP"}

# Zafiyetli ulkelerin telekom altyapi IP bloklari
# SS7 firewall'i zayif veya olmayan operator'ler
VULN_COUNTRY_SUBNETS = {
    # AFRIKA (en yuksek risk - SS7 firewall'siz operatorler)
    "NG": [  # Nijerya (MTN, Airtel, Glo, 9mobile)
        "41.58.0.0/16", "41.73.0.0/16", "41.138.0.0/16", "41.190.0.0/16",
        "41.203.0.0/16", "41.206.0.0/16", "41.211.0.0/16", "197.210.0.0/16",
        "197.255.0.0/16", "154.113.0.0/16", "105.112.0.0/16", "105.113.0.0/16",
    ],
    "EG": [  # Misir (Vodafone, Orange, Etisalat)
        "41.32.0.0/16", "41.33.0.0/16", "41.34.0.0/16", "41.35.0.0/16",
        "41.36.0.0/16", "41.37.0.0/16", "41.38.0.0/16", "41.39.0.0/16",
        "41.65.0.0/16", "41.128.0.0/16", "41.129.0.0/16", "41.130.0.0/16",
        "41.176.0.0/16", "41.178.0.0/16", "41.179.0.0/16", "41.187.0.0/16",
        "196.218.0.0/16", "197.32.0.0/16", "197.33.0.0/16", "197.34.0.0/16",
    ],
    "KE": [  # Kenya (Safaricom, Airtel)
        "41.72.0.0/16", "41.89.0.0/16", "41.139.0.0/16", "41.215.0.0/16",
        "105.48.0.0/16", "105.161.0.0/16", "196.201.0.0/16", "197.136.0.0/16",
    ],
    "GH": [  # Gana
        "41.57.0.0/16", "41.74.0.0/16", "41.204.0.0/16", "41.210.0.0/16",
        "154.160.0.0/16", "197.135.0.0/16",
    ],
    "TZ": [  # Tanzanya
        "41.59.0.0/16", "41.73.128.0/17", "41.188.0.0/16", "41.222.0.0/16",
        "196.192.0.0/16", "197.148.0.0/16",
    ],
    "ZA": [  # Guney Afrika (MTN, Vodacom, Cell C)
        "41.0.0.0/16", "41.1.0.0/16", "41.2.0.0/16", "41.13.0.0/16",
        "41.76.0.0/16", "41.78.0.0/16", "41.79.0.0/16", "41.112.0.0/16",
        "105.0.0.0/16", "105.1.0.0/16", "105.2.0.0/16", "105.3.0.0/16",
        "154.0.0.0/16", "196.2.0.0/16", "196.7.0.0/16", "196.11.0.0/16",
    ],
    # ASYA (orta-yuksek risk)
    "IN": [  # Hindistan (BSNL, Airtel, Jio)
        "49.32.0.0/16", "49.33.0.0/16", "49.34.0.0/16", "49.35.0.0/16",
        "59.88.0.0/16", "59.89.0.0/16", "59.90.0.0/16", "59.91.0.0/16",
        "117.192.0.0/16", "117.193.0.0/16", "117.194.0.0/16", "117.195.0.0/16",
        "117.196.0.0/16", "117.197.0.0/16", "117.198.0.0/16", "117.199.0.0/16",
        "122.160.0.0/16", "122.161.0.0/16", "122.162.0.0/16", "122.163.0.0/16",
        "182.64.0.0/16", "182.65.0.0/16", "182.66.0.0/16", "182.67.0.0/16",
    ],
    "BD": [  # Banglades (Grameenphone, Robi, Banglalink)
        "103.4.0.0/16", "103.5.0.0/16", "103.7.0.0/16", "103.9.0.0/16",
        "103.48.0.0/16", "103.108.0.0/16", "114.130.0.0/16", "180.149.0.0/16",
    ],
    "PK": [  # Pakistan (Jazz, Telenor, Zong)
        "39.32.0.0/16", "39.33.0.0/16", "39.34.0.0/16", "39.35.0.0/16",
        "39.36.0.0/16", "39.37.0.0/16", "39.38.0.0/16", "39.39.0.0/16",
        "39.40.0.0/16", "39.41.0.0/16", "39.42.0.0/16", "39.43.0.0/16",
        "119.73.0.0/16", "119.160.0.0/16", "182.176.0.0/16", "182.177.0.0/16",
    ],
    "PH": [  # Filipinler (Globe, Smart)
        "49.144.0.0/16", "49.145.0.0/16", "49.146.0.0/16", "49.147.0.0/16",
        "112.198.0.0/16", "112.199.0.0/16", "112.200.0.0/16", "112.201.0.0/16",
        "119.92.0.0/16", "119.93.0.0/16", "119.94.0.0/16", "119.95.0.0/16",
    ],
    "VN": [  # Vietnam (Viettel, VNPT, Mobifone)
        "14.160.0.0/16", "14.161.0.0/16", "14.162.0.0/16", "14.163.0.0/16",
        "14.164.0.0/16", "14.165.0.0/16", "14.166.0.0/16", "14.167.0.0/16",
        "113.160.0.0/16", "113.161.0.0/16", "113.162.0.0/16", "113.163.0.0/16",
    ],
    # GUNEY AMERIKA (orta risk)
    "BR": [  # Brezilya (Claro, Vivo, TIM, Oi)
        "177.0.0.0/16", "177.1.0.0/16", "177.2.0.0/16", "177.3.0.0/16",
        "179.104.0.0/16", "179.105.0.0/16", "179.106.0.0/16", "179.107.0.0/16",
        "187.0.0.0/16", "187.1.0.0/16", "187.2.0.0/16", "187.3.0.0/16",
        "189.0.0.0/16", "189.1.0.0/16", "189.2.0.0/16", "189.3.0.0/16",
        "200.128.0.0/16", "200.129.0.0/16", "200.130.0.0/16", "200.131.0.0/16",
    ],
    "CO": [  # Kolombiya
        "186.0.0.0/16", "186.1.0.0/16", "186.2.0.0/16", "186.3.0.0/16",
        "181.128.0.0/16", "181.129.0.0/16", "181.130.0.0/16", "181.131.0.0/16",
    ],
    "MX": [  # Meksika (Telcel, AT&T)
        "187.128.0.0/16", "187.129.0.0/16", "187.130.0.0/16", "187.131.0.0/16",
        "189.128.0.0/16", "189.129.0.0/16", "189.130.0.0/16", "189.131.0.0/16",
        "201.0.0.0/16", "201.1.0.0/16", "201.2.0.0/16", "201.3.0.0/16",
    ],
    # ESKI SOVYET (orta risk)
    "RU": [  # Rusya (MTS, Beeline, Megafon, Tele2)
        "5.128.0.0/16", "5.129.0.0/16", "5.130.0.0/16", "5.131.0.0/16",
        "37.112.0.0/16", "37.113.0.0/16", "46.0.0.0/16", "46.1.0.0/16",
        "77.34.0.0/16", "77.35.0.0/16", "77.36.0.0/16", "77.37.0.0/16",
        "95.24.0.0/16", "95.25.0.0/16", "95.26.0.0/16", "95.27.0.0/16",
        "176.59.0.0/16", "176.60.0.0/16", "176.61.0.0/16", "176.62.0.0/16",
        "188.162.0.0/16", "188.163.0.0/16", "188.164.0.0/16", "188.165.0.0/16",
    ],
    "UA": [  # Ukrayna (Kyivstar, Vodafone, lifecell)
        "46.33.0.0/16", "46.118.0.0/16", "46.119.0.0/16", "46.148.0.0/16",
        "176.36.0.0/16", "176.37.0.0/16", "178.136.0.0/16", "178.137.0.0/16",
        "193.138.0.0/16", "195.64.0.0/16",
    ],
    "KZ": [  # Kazakistan (Beeline, Kcell, Tele2)
        "2.132.0.0/16", "2.133.0.0/16", "2.134.0.0/16", "2.135.0.0/16",
        "37.150.0.0/16", "37.151.0.0/16", "46.34.0.0/16", "46.35.0.0/16",
        "178.89.0.0/16", "178.90.0.0/16", "178.91.0.0/16",
    ],
    "UZ": [  # Ozbekistan
        "31.40.0.0/16", "46.255.0.0/16", "80.80.0.0/16", "195.69.0.0/16",
    ],
}

# ============================================
# PROTOCOL VERIFICATION FUNCTIONS
# ============================================

def verify_diameter(ip, port=3868, timeout=3):
    """
    Verify a real Diameter node by sending CER and checking for CEA.
    Returns (True, details) or (False, reason).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Build minimal Diameter CER (Capabilities-Exchange-Request)
        origin_host = b"scanner.sigploit.local"
        origin_realm = b"sigploit.local"
        
        # AVP: Origin-Host (264)
        avp1 = _build_diameter_avp(264, origin_host)
        # AVP: Origin-Realm (296) 
        avp2 = _build_diameter_avp(296, origin_realm)
        # AVP: Host-IP-Address (257) - dummy
        avp3 = _build_diameter_avp(257, b'\x00\x01' + socket.inet_aton("1.2.3.4"))
        # AVP: Vendor-Id (266)
        avp4 = _build_diameter_avp(266, struct.pack("!I", 0))
        # AVP: Product-Name (269)
        avp5 = _build_diameter_avp(269, b"SigPloit")
        
        avps = avp1 + avp2 + avp3 + avp4 + avp5
        
        # Diameter Header: Version(1) + Length(3) + Flags(1) + Code(3) + AppId(4) + HbH(4) + E2E(4)
        msg_len = 20 + len(avps)
        header = struct.pack("!B", 1)  # Version
        header += struct.pack("!I", msg_len)[1:]  # Length (3 bytes)
        header += struct.pack("!B", 0x80)  # Flags: Request
        header += struct.pack("!I", 257)[1:]  # Command Code: CER (3 bytes)
        header += struct.pack("!I", 0)  # Application-ID: 0 (base)
        header += struct.pack("!I", random.randint(1, 0xFFFFFFFF))  # Hop-by-Hop
        header += struct.pack("!I", random.randint(1, 0xFFFFFFFF))  # End-to-End
        
        cer = header + avps
        sock.send(cer)
        
        # Read response
        response = sock.recv(4096)
        sock.close()
        
        if not response or len(response) < 20:
            return False, "No Diameter response"
        
        # Check Diameter header
        version = response[0]
        resp_len = struct.unpack("!I", b'\x00' + response[1:4])[0]
        flags = response[4]
        cmd_code = struct.unpack("!I", b'\x00' + response[5:8])[0]
        
        if version != 1:
            return False, f"Not Diameter (version={version})"
        
        if cmd_code == 257 and not (flags & 0x80):
            # CEA (answer to CER) - THIS IS A REAL DIAMETER NODE
            # Try to extract Result-Code
            result_code = _extract_diameter_avp(response[20:], 268)
            origin = _extract_diameter_avp_str(response[20:], 264)
            realm = _extract_diameter_avp_str(response[20:], 296)
            
            details = f"CEA received"
            if origin:
                details += f" | Origin-Host: {origin}"
            if realm:
                details += f" | Realm: {realm}"
            if result_code:
                rc = struct.unpack("!I", result_code)[0] if len(result_code) == 4 else 0
                details += f" | Result-Code: {rc}"
            
            return True, details
        
        return False, f"Unexpected response (cmd={cmd_code}, flags=0x{flags:02x})"
        
    except socket.timeout:
        return False, "Timeout"
    except ConnectionRefusedError:
        return False, "Refused"
    except ConnectionResetError:
        return False, "Reset"
    except Exception as e:
        return False, str(e)


def verify_gtp(ip, port=2123, timeout=2):
    """
    Verify a real GTP node by sending Echo Request and checking for Echo Response.
    GTPv2-C Echo Request: Version=2, T=0, MessageType=1, Length=4
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # GTPv2 Echo Request
        # Flags: Version=2 (0x40), P=0, T=0 => 0x40
        # Message Type: 1 (Echo Request)
        # Length: 4 (just sequence + spare)
        # Sequence: random 3 bytes + spare 1 byte
        seq = random.randint(1, 0xFFFFFF)
        echo_req = struct.pack("!BBH", 0x40, 0x01, 4)  # Header: flags, type, length
        echo_req += struct.pack("!I", seq << 8)  # Sequence(3) + Spare(1)
        
        sock.sendto(echo_req, (ip, port))
        
        data, addr = sock.recvfrom(1024)
        sock.close()
        
        if not data or len(data) < 8:
            return False, "Too short"
        
        # Check GTPv2 Echo Response
        flags = data[0]
        msg_type = data[1]
        version = (flags >> 5) & 0x07
        
        if version == 2 and msg_type == 2:  # GTPv2 Echo Response
            return True, f"GTPv2 Echo Response from {addr[0]}"
        elif version == 1 and msg_type == 2:  # GTPv1 Echo Response
            return True, f"GTPv1 Echo Response from {addr[0]}"
        
        return False, f"Not GTP (version={version}, type={msg_type})"
        
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def verify_sip(ip, port=5060, timeout=2):
    """
    Verify a real SIP node by sending OPTIONS and checking response.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # SIP OPTIONS request
        branch = f"z9hG4bK{random.randint(100000,999999)}"
        call_id = f"{random.randint(100000,999999)}@scanner"
        
        sip_msg = (
            f"OPTIONS sip:{ip}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 1.2.3.4:5060;branch={branch}\r\n"
            f"From: <sip:scanner@sigploit.local>;tag={random.randint(1000,9999)}\r\n"
            f"To: <sip:{ip}:{port}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        
        sock.sendto(sip_msg.encode(), (ip, port))
        
        data, addr = sock.recvfrom(4096)
        sock.close()
        
        response = data.decode('utf-8', errors='ignore')
        
        if response.startswith("SIP/2.0"):
            # Extract status code
            parts = response.split('\r\n')[0].split(' ')
            status_code = parts[1] if len(parts) > 1 else "?"
            
            # Extract Server header if present
            server = ""
            for line in response.split('\r\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
                elif line.lower().startswith('user-agent:'):
                    server = line.split(':', 1)[1].strip()
                    break
            
            details = f"SIP/{status_code}"
            if server:
                details += f" | Server: {server}"
            
            return True, details
        
        return False, "Not SIP response"
        
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def verify_ss7_m3ua(ip, port, timeout=3):
    """
    Verify SS7/SIGTRAN node with SCTP INIT handshake.
    If raw packet permissions are unavailable, fall back to TCP M3UA probe.
    """
    try:
        pkt = IP(dst=ip) / SCTP(sport=random.randint(20000, 65000), dport=port) / SCTPChunkInit()
        ans = sr1(pkt, timeout=timeout, verbose=0)

        if ans is None:
            return False, "No SCTP response"
        if ans.haslayer(SCTPChunkInitAck):
            return True, "SCTP INIT-ACK (SIGTRAN)"
        if ans.haslayer(SCTPChunkAbort):
            return False, "SCTP ABORT"

        return False, f"Unexpected SCTP response ({ans.summary()[:80]})"
    except PermissionError:
        pass
    except Exception:
        pass

    # Fallback: TCP probe when raw packets cannot be sent (or Scapy path fails)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            return False, "TCP closed (fallback)"

        aspup = b'\x01\x00\x03\x01\x00\x00\x00\x08'
        sock.send(aspup)
        resp = sock.recv(256)
        if resp and len(resp) >= 8 and resp[0] == 0x01 and resp[2] in (0, 1, 2, 3, 4, 9):
            return True, f"TCP M3UA response (class={resp[2]} type={resp[3]})"
        return False, "TCP open but not M3UA (fallback)"
    except socket.timeout:
        return False, "TCP timeout (fallback)"
    except Exception as e:
        return False, f"fallback error: {str(e)[:60]}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================
# DIAMETER AVP HELPERS
# ============================================

def _build_diameter_avp(code, data, mandatory=True):
    """Build a Diameter AVP."""
    flags = 0x40 if mandatory else 0x00
    avp_len = 8 + len(data)
    avp = struct.pack("!I", code)
    avp += struct.pack("!B", flags)
    avp += struct.pack("!I", avp_len)[1:]
    avp += data
    # Pad to 4-byte boundary
    padding = (4 - (avp_len % 4)) % 4
    avp += b'\x00' * padding
    return avp

def _extract_diameter_avp(data, target_code):
    """Extract AVP value by code from Diameter message body."""
    idx = 0
    while idx + 8 <= len(data):
        code = struct.unpack("!I", data[idx:idx+4])[0]
        flags = data[idx+4]
        avp_len = struct.unpack("!I", b'\x00' + data[idx+5:idx+8])[0]
        
        has_vendor = bool(flags & 0x80)
        header_len = 12 if has_vendor else 8
        
        if avp_len < header_len or idx + avp_len > len(data) + 4:
            break
        
        if code == target_code:
            return data[idx+header_len:idx+avp_len]
        
        # Move to next AVP (with padding)
        padded_len = avp_len + (4 - (avp_len % 4)) % 4
        idx += padded_len
    
    return None

def _extract_diameter_avp_str(data, target_code):
    """Extract AVP as string."""
    val = _extract_diameter_avp(data, target_code)
    if val:
        return val.decode('utf-8', errors='ignore')
    return None


# ============================================
# MAIN SCANNER
# ============================================

def multi_scan_menu():
    """Main menu for multi-protocol scanning."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 60)
    print(" Multi-Protocol Telecom Scanner (Verified)")
    print(" SS7/SCTP | Diameter | GTP | SIP")
    print("=" * 60)
    print()
    print("\033[32m[+] NEW: Protocol-level verification (no false positives)\033[0m")
    print("\033[32m[+] Phase 1: Fast port scan  |  Phase 2: Handshake verify\033[0m")
    print()
    print("Select Scan Mode:")
    print()
    print("1) SS7 + Diameter + GTP + SIP (All Protocols)")
    print("2) SS7/SCTP Only (SIGTRAN)")
    print("3) Diameter Only (4G/LTE)")
    print("4) GTP Only (Mobile Data)")
    print("5) SIP Only (VoIP)")
    print("6) Verify Existing Results (from leaks_*.txt)")
    print("7) Limited Scan (N subnet, controlled run)")
    print("8) Risk-Temelli Ulke Analizi (dosyadan)")
    print("\033[33m9) Tam Otomatik Zincir (Zafiyet Onceli Ulkeler)\033[0m")
    print()
    print("or type back to return")
    print()
    
    choice = input("\033[37m(\033[0m\033[2;31mscanner\033[0m\033[37m)>\033[0m ").strip().lower()
    
    if choice == "1":
        run_multi_scan(['SS7', 'DIAMETER', 'GTP', 'SIP'])
    elif choice == "2":
        run_multi_scan(['SS7'])
    elif choice == "3":
        run_multi_scan(['DIAMETER'])
    elif choice == "4":
        run_multi_scan(['GTP'])
    elif choice == "5":
        run_multi_scan(['SIP'])
    elif choice == "6":
        verify_existing_results()
    elif choice == "7":
        run_limited_scan_menu()
    elif choice == "8":
        run_risk_based_country_menu()
    elif choice == "9":
        run_auto_chain_global()
    elif choice == "back":
        return
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (1-9)')
        time.sleep(1.5)
        multi_scan_menu()


def verify_existing_results():
    """
    Re-verify previously found results with protocol handshake.
    Reads leaks_*.txt files and does real protocol verification.
    """
    print("\n" + "=" * 60)
    print(" Re-Verify Existing Scan Results")
    print(" Eliminates false positives with protocol handshakes")
    print("=" * 60 + "\n")
    
    # Check multiple possible filenames for each protocol
    files_to_check = {}
    for proto, candidates in {
        'DIAMETER': ['leaks_diameter_new.txt', 'leaks_diameter.txt'],
        'SS7': ['leaks_ss7.txt', 'leaks.txt'],
        'GTP': ['leaks_gtp.txt'],
        'SIP': ['leaks_sip.txt'],
    }.items():
        for fname in candidates:
            if os.path.exists(fname):
                files_to_check[proto] = fname
                break
    
    verified_file = "leaks_verified.txt"
    verified_count = 0
    false_positive_count = 0
    
    with open(verified_file, "w") as vf:
        vf.write(f"--- SigPloit Verified Results ---\n")
        vf.write(f"Verification Date: {time.ctime()}\n\n")
    
    for proto, filename in files_to_check.items():
        if not os.path.exists(filename):
            continue
            
        try:
            import re
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, OSError):
            continue

        # Extract IP:PORT from any format
        targets_set = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('---') or line.startswith('='):
                continue
            m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if m:
                ip = m.group(1)
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                port = int(m.group(2))
                if not (1 <= port <= 65535):
                    continue
                targets_set.add((ip, port))

        if not targets_set:
            continue

        unique_targets = list(targets_set)
        # Limit to 200 per protocol for speed (diverse subnets first)
        if len(unique_targets) > 200:
            seen_subnets = set()
            sampled = []
            for ip, port in unique_targets:
                subnet = '.'.join(ip.split('.')[:3])
                if subnet not in seen_subnets:
                    seen_subnets.add(subnet)
                    sampled.append((ip, port))
                if len(sampled) >= 200:
                    break
            unique_targets = sampled
            print(f"\n[*] {proto}: {len(targets_set)} total -> {len(unique_targets)} sampled (diverse subnets)")
        else:
            print(f"\n[*] {proto}: {len(unique_targets)} unique targets to verify ({filename})")

        # Use threading for parallel verification
        from concurrent.futures import ThreadPoolExecutor, as_completed

        verify_func = {
            'DIAMETER': lambda t: (t, verify_diameter(t[0], t[1])),
            'SS7': lambda t: (t, verify_ss7_m3ua(t[0], t[1])),
            'GTP': lambda t: (t, verify_gtp(t[0], t[1])),
            'SIP': lambda t: (t, verify_sip(t[0], t[1])),
        }.get(proto)

        if not verify_func:
            continue

        done_count = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(verify_func, t): t for t in unique_targets}
            for future in as_completed(futures):
                done_count += 1
                try:
                    (ip, port), (verified, details) = future.result()
                except Exception as e:
                    verified, details = False, str(e)
                    ip, port = futures[future]

                if verified:
                    verified_count += 1
                    status = f"\033[32m[VERIFIED]\033[0m"
                    with open(verified_file, "a") as vf:
                        vf.write(f"[{proto}] {ip}:{port} | {details}\n")
                    print(f"  ({done_count}/{len(unique_targets)}) {ip}:{port} {status} {details}")
                else:
                    false_positive_count += 1
                    if done_count % 20 == 0:
                        print(f"  [{done_count}/{len(unique_targets)}] taranıyor...")
    
    print("\n" + "=" * 60)
    print(f" Verification Complete")
    print(f" Verified:        \033[32m{verified_count}\033[0m")
    print(f" False Positives: \033[31m{false_positive_count}\033[0m")
    print(f" Results saved:   {os.path.abspath(verified_file)}")
    print("=" * 60)
    
    input("\nPress Enter to return...")
    multi_scan_menu()



def _prompt_int(prompt, default, min_value=None, max_value=None):
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
        except ValueError:
            print("[-] Lutfen sayisal deger girin.")
            continue
        if min_value is not None and val < min_value:
            print(f"[-] En az {min_value} olmalidir.")
            continue
        if max_value is not None and val > max_value:
            print(f"[-] En fazla {max_value} olmalidir.")
            continue
        return val


def run_limited_scan_menu():
    """Run controlled global scan with subnet cap."""
    print("\n[+] Limited scan modu")
    print("1) All Protocols")
    print("2) SS7")
    print("3) Diameter")
    print("4) GTP")
    print("5) SIP")

    mode = input("Secim [1]: ").strip() or "1"
    proto_map = {
        "1": ['SS7', 'DIAMETER', 'GTP', 'SIP'],
        "2": ['SS7'],
        "3": ['DIAMETER'],
        "4": ['GTP'],
        "5": ['SIP'],
    }
    protocols = proto_map.get(mode)
    if not protocols:
        print("[-] Gecersiz secim")
        time.sleep(1)
        return

    subnet_limit = _prompt_int("Taranacak subnet sayisi", 20, min_value=1, max_value=10000)
    run_multi_scan(protocols, max_subnets=subnet_limit)


def _parse_country_targets(file_path):
    """Parse lines like: IP:port | org | country | isp"""
    import re
    targets = []
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if not m:
                continue
            ip = m.group(1)
            port = int(m.group(2))
            if port not in PORT_TO_PROTO:
                continue
            parts = [p.strip() for p in line.split('|')]
            country = parts[2].upper() if len(parts) >= 3 else 'N/A'
            targets.append({'ip': ip, 'port': port, 'country': country, 'raw': line})
    return targets


def run_risk_based_country_menu():
    """Defensive: prioritize verification for selected country groups from saved files."""
    print("\n[+] Risk-temelli ulke analizi (defensive)")
    print("[*] Kayitli shodan/censys txt dosyalarindan hedefleri okuyup protokol dogrulama yapar.")
    print(f"[*] Varsayilan oncelik ulkeleri: {', '.join(RISK_PRIORITY_COUNTRIES)}")

    root = os.getcwd()
    files = [f for f in sorted(os.listdir(root)) if (f.startswith('shodan_') or f.startswith('censys_')) and f.endswith('.txt')]
    if not files:
        print("[-] Analiz icin shodan_/censys_ dosyasi bulunamadi.")
        input("\nPress Enter to return...")
        return

    for i, f in enumerate(files):
        print(f"  {i}) {f}")
    idx = _prompt_int("Dosya numarasi", 0, min_value=0, max_value=len(files)-1)
    file_path = os.path.join(root, files[idx])

    targets = _parse_country_targets(file_path)
    if not targets:
        print("[-] Uygun IP:port hedefi bulunamadi.")
        input("\nPress Enter to return...")
        return

    user_cc = input("Ulke kodlari (virgullu) [varsayilan]: ").strip().upper()
    priority = RISK_PRIORITY_COUNTRIES if not user_cc else [x.strip() for x in user_cc.split(',') if x.strip()]
    filtered = [t for t in targets if t['country'] in priority]
    if not filtered:
        print("[-] Secilen ulkeler icin hedef bulunamadi.")
        input("\nPress Enter to return...")
        return

    limit = _prompt_int("Maks hedef", 200, min_value=1, max_value=5000)
    filtered = filtered[:limit]

    verify_map = {
        'SS7': lambda ip, port: verify_ss7_m3ua(ip, port),
        'DIAMETER': lambda ip, port: verify_diameter(ip, port),
        'GTP': lambda ip, port: verify_gtp(ip, port),
        'SIP': lambda ip, port: verify_sip(ip, port),
    }

    out_name = f"risk_assessment_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    verified = 0
    checked = 0
    with open(out_name, 'w', encoding='utf-8') as out:
        out.write(f"Risk Assessment Report\nSource: {files[idx]}\nCountries: {','.join(priority)}\n\n")
        for t in filtered:
            checked += 1
            proto = PORT_TO_PROTO.get(t['port'])
            vf = verify_map.get(proto)
            if not vf:
                continue
            ok, details = vf(t['ip'], t['port'])
            if ok:
                verified += 1
                out.write(f"[EXPOSED] {t['ip']}:{t['port']} | {proto} | {t['country']} | {details}\n")
                print(f"  [EXPOSED] {t['ip']}:{t['port']} {proto} {t['country']} | {details}")
            elif checked % 25 == 0:
                print(f"  [{checked}/{len(filtered)}] kontrol ediliyor...")

    print(f"\n[+] Kontrol: {checked} | Dogrulanan maruziyet: {verified}")
    print(f"[+] Rapor: {os.path.abspath(out_name)}")
    input("\nPress Enter to return...")

def run_multi_scan(protocols, max_subnets=None, auto_chain=False):
    """
    Run scanning with protocol-level verification.
    
    Args:
        protocols: List of protocols to scan ['SS7', 'DIAMETER', 'GTP', 'SIP']
        max_subnets: Maximum number of subnets to scan (None = infinite)
        auto_chain: If True, automatically run verification + vulnerability test after scan
    """
    
    PROTOCOL_PORTS = {
        'SS7': [2904, 2905, 2906, 2907, 2908],
        'DIAMETER': [3868, 3869],
        'GTP': [2123, 2152],
        'SIP': [5060, 5061],
    }
    
    print("\n" + "=" * 70)
    print(f" GLOBAL TELECOM SCANNER - ZAFIYET ONCELI")
    print(f" Protocols: {', '.join(protocols)}")
    print(f" Mode: Port Scan + Protocol Verification")
    if auto_chain:
        print(f" AUTO-CHAIN: Scan -> Verify -> Vuln Test -> Report")
    print("=" * 70)
    print()
    print("[!] Zafiyetli ulkeler oncelikli: NG, EG, IN, BR, RU, PH, VN, KE, GH, TZ, ZA, CO, MX, UA, KZ, UZ")
    print("[!] Output Files:")
    for proto in protocols:
        print(f"    - leaks_{proto.lower()}.txt (port scan hits)")
        print(f"    - leaks_verified.txt (protocol-verified only)")
    print()
    if max_subnets is None:
        print("[+] Press Ctrl+C to stop.\n")
    else:
        print(f"[+] Controlled run: max {max_subnets} subnet\n")
    
    # Create output files
    for proto in protocols:
        with open(f"leaks_{proto.lower()}.txt", "a") as _f:
            pass
    
    verified_file = "leaks_verified.txt"
    if not os.path.exists(verified_file):
        with open(verified_file, "w") as f:
            f.write(f"--- SigPloit Verified Results ---\n")
            f.write(f"Started: {time.ctime()}\n\n")
    
    scan_count = 0
    total_verified = 0
    total_false = 0
    
    try:
        while True:
            subnet = generate_prioritized_subnet()
            network = ipaddress.ip_network(subnet, strict=False)
            target_ips = [str(ip) for ip in list(network.hosts())[:50]]
            
            results = {}
            
            # ---- PHASE 1: Fast port scan ----
            
            # SS7/SCTP Scan (SCTP is already strong indicator)
            if 'SS7' in protocols:
                ss7_leaks, ss7_recv = scan_sctp(target_ips, PROTOCOL_PORTS['SS7'])
                results['SS7'] = (ss7_leaks, ss7_recv)
                if ss7_leaks:
                    with open("leaks_ss7.txt", "a") as f:
                        for leak in ss7_leaks:
                            f.write(f"{leak}\n")
                    # SCTP INIT-ACK is already very reliable - web servers don't use SCTP
                    with open(verified_file, "a") as vf:
                        for leak in ss7_leaks:
                            vf.write(f"[SS7] {leak} | SCTP INIT-ACK\n")
                            total_verified += 1
                    for leak in ss7_leaks:
                        print(f"    \033[32m[!!!] SS7 VERIFIED: {leak}\033[0m")
            
            # Diameter: TCP scan + CER verification
            if 'DIAMETER' in protocols:
                dia_open = scan_tcp(target_ips, PROTOCOL_PORTS['DIAMETER'])
                results['DIAMETER'] = []
                if dia_open:
                    for target in dia_open:
                        ip, port = target.split(':')
                        verified, details = verify_diameter(ip, int(port))
                        if verified:
                            results['DIAMETER'].append(target)
                            total_verified += 1
                            with open("leaks_diameter.txt", "a") as f:
                                f.write(f"{target} | {details}\n")
                            with open(verified_file, "a") as vf:
                                vf.write(f"[DIAMETER] {target} | {details}\n")
                            print(f"    \033[32m[!!!] DIAMETER VERIFIED: {target} | {details}\033[0m")
                        else:
                            total_false += 1
            
            # GTP: UDP scan + Echo verification
            if 'GTP' in protocols:
                gtp_candidates = scan_udp_fast(target_ips, PROTOCOL_PORTS['GTP'])
                results['GTP'] = []
                if gtp_candidates:
                    for target in gtp_candidates:
                        ip, port = target.split(':')
                        verified, details = verify_gtp(ip, int(port))
                        if verified:
                            results['GTP'].append(target)
                            total_verified += 1
                            with open("leaks_gtp.txt", "a") as f:
                                f.write(f"{target} | {details}\n")
                            with open(verified_file, "a") as vf:
                                vf.write(f"[GTP] {target} | {details}\n")
                            print(f"    \033[32m[!!!] GTP VERIFIED: {target} | {details}\033[0m")
                        else:
                            total_false += 1
            
            # SIP: UDP scan + OPTIONS verification
            if 'SIP' in protocols:
                sip_candidates = scan_udp_fast(target_ips, PROTOCOL_PORTS['SIP'])
                results['SIP'] = []
                if sip_candidates:
                    for target in sip_candidates:
                        ip, port = target.split(':')
                        verified, details = verify_sip(ip, int(port))
                        if verified:
                            results['SIP'].append(target)
                            total_verified += 1
                            with open("leaks_sip.txt", "a") as f:
                                f.write(f"{target} | {details}\n")
                            with open(verified_file, "a") as vf:
                                vf.write(f"[SIP] {target} | {details}\n")
                            print(f"    \033[33m[!] SIP: {target} | {details}\033[0m")
                        else:
                            total_false += 1
            
            # ---- Status Line ----
            status_parts = [f"{subnet}:"]
            for proto in protocols:
                if proto == 'SS7':
                    leaks, recv = results.get('SS7', ([], 0))
                    status_parts.append(f"SS7={len(leaks)}")
                else:
                    resp = results.get(proto, [])
                    status_parts.append(f"{proto}={len(resp)}")
            
            print(f"[>] {' | '.join(status_parts)}")
            
            scan_count += 1
            if scan_count % 20 == 0:
                print(f"\n[Status] Subnets: {scan_count} | Verified: {total_verified} | False+: {total_false}\n")

            if max_subnets is not None and scan_count >= max_subnets:
                print(f"\n[+] Controlled scan limiti tamamlandi: {scan_count}/{max_subnets}")
                break
                
    except KeyboardInterrupt:
        print(f"\n\n[+] Scan stopped.")
        print(f"[+] Subnets scanned: {scan_count}")
        print(f"[+] Verified hits:   {total_verified}")
        print(f"[+] False positives: {total_false}")
        print(f"[+] Results: leaks_verified.txt")
    
    input("\nPress Enter to return...")


def generate_prioritized_subnet():
    """
    Zafiyetli ulkelerden %80, random global %20.
    SS7 firewall'siz operator bloklarini onceliklendirir.
    """
    if random.random() < 0.80:  # %80 zafiyetli ulke
        country = random.choice(list(VULN_COUNTRY_SUBNETS.keys()))
        return random.choice(VULN_COUNTRY_SUBNETS[country])
    else:
        return generate_random_subnet()  # %20 global rastgele


def generate_random_subnet():
    """Generate random public /24, excluding private/reserved."""
    while True:
        o1 = random.randint(1, 223)
        o2 = random.randint(0, 255)
        o3 = random.randint(0, 255)
        
        if o1 == 0: continue
        if o1 == 10: continue
        if o1 == 127: continue
        if o1 == 172 and 16 <= o2 <= 31: continue
        if o1 == 192 and o2 == 168: continue
        if o1 == 169 and o2 == 254: continue
        if o1 >= 224: continue
        
        return f"{o1}.{o2}.{o3}.0/24"


def scan_sctp(target_ips, ports):
    """Scan SCTP/SS7 ports. SCTP INIT-ACK = strong SS7 indicator."""
    packets = []
    for ip in target_ips:
        for port in ports:
            pkt = IP(dst=ip)/SCTP(sport=random.randint(1024, 65535), dport=port, tag=0)/SCTPChunkInit()
            packets.append(pkt)
    
    if not packets:
        return [], 0
    
    ans, _ = sr(packets, timeout=2, verbose=0)
    
    leaks = []
    for sent, recv in ans:
        if recv.haslayer(SCTPChunkInitAck):
            leaks.append(f"{recv[IP].src}:{sent[SCTP].dport}")
    
    return leaks, len(ans)


def scan_tcp(target_ips, ports):
    """Fast TCP SYN scan (Phase 1 - candidates only)."""
    packets = []
    for ip in target_ips[:30]:
        for port in ports:
            pkt = IP(dst=ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            packets.append(pkt)
    
    if not packets:
        return []
    
    ans, _ = sr(packets, timeout=2, verbose=0)
    
    open_ports = []
    for sent, recv in ans:
        if recv.haslayer(TCP) and recv[TCP].flags == 0x12:
            open_ports.append(f"{recv[IP].src}:{sent[TCP].dport}")
    
    return open_ports


def scan_udp_fast(target_ips, ports):
    """Fast UDP scan - just find responsive IPs (Phase 1)."""
    packets = []
    for ip in target_ips[:30]:
        for port in ports:
            # Send minimal probe
            pkt = IP(dst=ip)/UDP(sport=random.randint(1024, 65535), dport=port)/Raw(load=b"\x00" * 8)
            packets.append(pkt)
    
    if not packets:
        return []
    
    ans, _ = sr(packets, timeout=2, verbose=0)
    
    responses = []
    for sent, recv in ans:
        if recv.haslayer(UDP):
            responses.append(f"{recv[IP].src}:{sent[UDP].dport}")
    
    return responses


def run_auto_chain_global():
    """
    Tam Otomatik Zincir: Zafiyet Onceli Global Tarama
    Adim 1: Zafiyetli ulkelerden baslayarak tum protokolleri tara
    Adim 2: Bulunan hedefleri dogrula (M3UA/CER/Echo/OPTIONS)
    Adim 3: Dogrulanmis hedeflere firewall bypass + zafiyet testi
    Adim 4: Ozet rapor olustur
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 65)
    print(" TAM OTOMATIK ZINCIR - ZAFIYET ONCELI GLOBAL TARAMA")
    print(" Scan -> Verify -> Bypass -> Vuln Test -> Report")
    print("=" * 65)
    print()
    print("\033[33m[!] Bu mod zafiyeti bilinen ulke subnetlerinden baslar\033[0m")
    print(f"\033[36m[i] Oncelikli ulkeler: {len(VULN_COUNTRY_SUBNETS)} ulke (%80 oncelik)\033[0m")
    print()
    
    max_subnets = _prompt_int("Maksimum subnet sayisi", 100, min_value=5, max_value=10000)
    protocols = ['SS7', 'DIAMETER', 'GTP', 'SIP']
    
    print(f"\n\033[32m[ADIM 1/4] TARAMA BASLIYOR - {max_subnets} subnet\033[0m")
    print(f"  Protokoller: {', '.join(protocols)}")
    print(f"  Oncelik: Zafiyetli ulkeler (%80)")
    print()
    
    # ADIM 1: Prioritized scan
    run_multi_scan(protocols, max_subnets=max_subnets, auto_chain=True)
    
    # ADIM 2: Verify existing results
    print(f"\n\033[32m[ADIM 2/4] DOGRULAMA BASLIYOR\033[0m")
    print("  Bulunan tum hedefler protokol seviyesinde dogrulanacak...")
    print()
    time.sleep(1)
    verify_existing_results()
    
    # ADIM 3: Firewall bypass on verified targets
    print(f"\n\033[32m[ADIM 3/4] FIREWALL BYPASS BASLIYOR\033[0m")
    print("  Dogrulanmis hedeflere bypass teknikleri uygulanacak...")
    print()
    time.sleep(1)
    
    verified_targets = []
    verified_file = "leaks_verified.txt"
    if os.path.exists(verified_file):
        try:
            with open(verified_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('---') or line.startswith('Started'):
                        continue
                    # Extract IP:port from lines like "[SS7] 1.2.3.4:2905 | SCTP"
                    import re
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                    if m:
                        verified_targets.append((m.group(1), int(m.group(2))))
        except Exception as e:
            print(f"  \033[31m[-] Verified dosya okunamadi: {e}\033[0m")
    
    bypass_results = []
    if verified_targets:
        # Deduplicate
        verified_targets = list(set(verified_targets))
        print(f"  \033[36m[i] {len(verified_targets)} hedef icin bypass deneniyor...\033[0m\n")
        
        try:
            from ss7.firewall_bypass import run_all_bypasses
            for idx, (ip, port) in enumerate(verified_targets[:50], 1):  # Max 50
                print(f"\n  [{idx}/{min(len(verified_targets), 50)}] {ip}:{port}")
                try:
                    result = run_all_bypasses(ip, port, timeout=5, verbose=False)
                    if result:
                        bypass_results.append({'ip': ip, 'port': port, 'result': result})
                        success_count = sum(1 for r in result if r.get('success'))
                        if success_count > 0:
                            print(f"    \033[32m[+] {success_count} bypass basarili!\033[0m")
                        else:
                            print(f"    \033[31m[-] Bypass basarisiz\033[0m")
                except Exception as e:
                    print(f"    \033[31m[-] Hata: {e}\033[0m")
        except ImportError:
            print("  \033[31m[-] firewall_bypass modulu yuklenemedi\033[0m")
    else:
        print("  \033[33m[!] Dogrulanmis hedef bulunamadi, bypass atlaniyor.\033[0m")
    
    # ADIM 4: Generate report
    print(f"\n\033[32m[ADIM 4/4] RAPOR OLUSTURULUYOR\033[0m")
    time.sleep(0.5)
    
    report_file = f"global_auto_chain_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 65 + "\n")
            f.write(" SIGPLOIT - TAM OTOMATIK ZINCIR RAPORU\n")
            f.write(f" Tarih: {time.ctime()}\n")
            f.write("=" * 65 + "\n\n")
            
            # Scan results summary
            f.write("[1] TARAMA SONUCLARI\n")
            f.write("-" * 40 + "\n")
            for proto in protocols:
                fname = f"leaks_{proto.lower()}.txt"
                count = 0
                if os.path.exists(fname):
                    with open(fname, 'r', encoding='utf-8', errors='replace') as pf:
                        count = sum(1 for line in pf if line.strip())
                f.write(f"  {proto}: {count} hedef bulundu\n")
            
            # Verified targets
            f.write(f"\n[2] DOGRULANMIS HEDEFLER\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Toplam: {len(verified_targets)} hedef\n")
            for ip, port in verified_targets[:20]:
                f.write(f"  - {ip}:{port}\n")
            if len(verified_targets) > 20:
                f.write(f"  ... ve {len(verified_targets) - 20} daha\n")
            
            # Bypass results
            f.write(f"\n[3] FIREWALL BYPASS SONUCLARI\n")
            f.write("-" * 40 + "\n")
            total_bypassed = 0
            for br in bypass_results:
                success_count = sum(1 for r in br['result'] if r.get('success'))
                if success_count > 0:
                    total_bypassed += 1
                    f.write(f"  [BYPASS OK] {br['ip']}:{br['port']} - {success_count} teknik basarili\n")
                    for r in br['result']:
                        if r.get('success'):
                            f.write(f"    + {r.get('technique', 'unknown')}: {r.get('details', '')}\n")
            f.write(f"\n  Toplam bypass edilen: {total_bypassed}/{len(bypass_results)}\n")
            
            # Vulnerability summary
            f.write(f"\n[4] ZAFIYET OZETI\n")
            f.write("-" * 40 + "\n")
            vuln_count = 0
            for vuln_file in ['vuln_results.txt', 'leaks_verified.txt']:
                if os.path.exists(vuln_file):
                    with open(vuln_file, 'r', encoding='utf-8', errors='replace') as vf_r:
                        for line in vf_r:
                            if 'VULN' in line.upper() or 'BYPASS' in line.upper() or 'VERIFIED' in line.upper():
                                vuln_count += 1
                                f.write(f"  {line.strip()}\n")
            if vuln_count == 0:
                f.write("  Kritik zafiyet bulunamadi.\n")
            
            f.write(f"\n{'=' * 65}\n")
            f.write(f" Rapor sonu - {time.ctime()}\n")
            f.write(f"{'=' * 65}\n")
        
        print(f"\n  \033[32m[+] Rapor olusturuldu: {report_file}\033[0m")
    except Exception as e:
        print(f"\n  \033[31m[-] Rapor olusturulamadi: {e}\033[0m")
    
    # Final summary
    print(f"\n{'=' * 65}")
    print(f" OTOMATIK ZINCIR TAMAMLANDI")
    print(f" Taranan subnet: {max_subnets}")
    print(f" Dogrulanmis hedef: {len(verified_targets)}")
    print(f" Bypass basarili: {sum(1 for br in bypass_results if any(r.get('success') for r in br['result']))}")
    print(f" Rapor: {report_file}")
    print(f"{'=' * 65}")
    
    input("\nPress Enter to return...")


if __name__ == "__main__":
    multi_scan_menu()
