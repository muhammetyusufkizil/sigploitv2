#!/usr/bin/env python
import sys
import os
import ipaddress
import random
import time
from scapy.all import *

# Suppress Scapy warnings
conf.verb = 0

def get_input(prompt, default=None):
    if default:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else default
    else:
        return input(f"{prompt}: ").strip()


def _prompt_yes_no(prompt, default="e"):
    choice = get_input(prompt, default).lower()
    return choice in ["e", "evet", "y", "yes"]


def _validate_cidr(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

def generate_random_public_subnet():
    """Generates a random /24 subnet, excluding private/reserved ranges."""
    while True:
        # Generate all octets FIRST
        o1 = random.randint(1, 223)
        o2 = random.randint(0, 255)
        o3 = random.randint(0, 255)
        
        # Exclude Private/Reserved Ranges
        if o1 == 0: continue                     # 0.x.x.x (Reserved)
        if o1 == 10: continue                    # 10.x.x.x (Private)
        if o1 == 127: continue                   # 127.x.x.x (Loopback)
        if o1 == 172 and 16 <= o2 <= 31: continue # 172.16-31.x.x (Private)
        if o1 == 192 and o2 == 168: continue     # 192.168.x.x (Private)
        if o1 == 169 and o2 == 254: continue     # 169.254.x.x (Link-Local)
        if o1 >= 224: continue                   # 224+ (Multicast/Reserved)
        
        return f"{o1}.{o2}.{o3}.0/24"

def fast_scan_subnet(subnet_str):
    """
    Scans a subnet accurately using sr() with a short timeout.
    This sends packets in parallel (batch) which is much faster than loop.
    Now supports MULTI-PORT scanning (2904-2908) + TCP check.
    """
    SS7_PORTS = [2904, 2905, 2906, 2907, 2908]
    TCP_CHECK_PORTS = [80, 443]  # Common ports to verify network works
    
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        if network.num_addresses > 1024:
            print(f"[!] Uyari: {subnet_str} cok buyuk ({network.num_addresses} IP). /24 veya daha kucuk girin.")
            return []
        target_ips = [str(ip) for ip in network.hosts()]
        
        # Build SCTP packets
        sctp_packets = []
        for ip in target_ips:
            for port in SS7_PORTS:
                pkt = IP(dst=ip)/SCTP(sport=random.randint(1024, 65535), dport=port, tag=0)/SCTPChunkInit()
                sctp_packets.append(pkt)
        
        # Build TCP SYN packets (just first 10 IPs to check connectivity)
        tcp_packets = []
        for ip in target_ips[:10]:
            for port in TCP_CHECK_PORTS:
                pkt = IP(dst=ip)/TCP(sport=12345, dport=port, flags="S")
                tcp_packets.append(pkt)
            
        # Send SCTP packets
        answered, unanswered = sr(sctp_packets, timeout=2.0, retry=0, verbose=0)
        
        # Send TCP packets (quick check)
        tcp_answered, _ = sr(tcp_packets, timeout=1.0, retry=0, verbose=0)
        
        found_leaks = []
        closed_cnt = 0
        icmp_cnt = 0
        tcp_open_cnt = 0
        
        # Log TCP open ports
        for sent, received in tcp_answered:
            if received.haslayer(TCP) and received[TCP].flags == 0x12:  # SYN-ACK
                tcp_open_cnt += 1
                try:
                    with open("tcp_open.txt", "a") as tf:
                        tf.write(f"{received[IP].src}:{sent[TCP].dport} | TCP OPEN\n")
                except (IOError, OSError): pass
        
        # Process SCTP responses
        try:
            with open("alive_hosts.txt", "a") as f:
                for sent, received in answered:
                    target_port = sent[SCTP].dport
                    target_ip = received[IP].src
                    status = "UNKNOWN"
                    
                    if received.haslayer(SCTPChunkInitAck):
                        status = "OPEN (LEAK)"
                        result_str = f"{target_ip}:{target_port}"
                        found_leaks.append(result_str)
                        try:
                            with open("leaks.txt", "a") as lf:
                                lf.write(f"{result_str}\n")
                        except (IOError, OSError): pass
                        
                    elif received.haslayer(SCTPChunkAbort):
                        status = "CLOSED (ABORT)"
                        closed_cnt += 1
                        
                    elif received.haslayer(ICMP):
                        type_val = received[ICMP].type
                        code_val = received[ICMP].code
                        status = f"ICMP (Type={type_val}, Code={code_val})"
                        icmp_cnt += 1
                    
                    f.write(f"{target_ip}:{target_port} | {status}\n")
        except (IOError, OSError): pass
        
        # Show TCP status in output
        tcp_status = f"TCP:{tcp_open_cnt}" if tcp_open_cnt > 0 else "TCP:0"
        sys.stdout.write(f"\r[>] {subnet_str}: Sent {len(sctp_packets)} | Recv {len(answered)} (Open: {len(found_leaks)}, ICMP: {icmp_cnt}, {tcp_status})    \n")
        sys.stdout.flush()

        return found_leaks
            
    except Exception as e:
        return []

def scan_main():
    print("\n" + "#" * 60)
    print(" SigPloit TURBO Scanner - Automated SS7 Leak Hunter ")
    print("#" * 60 + "\n")
    
    # Initialize report generator
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from reporting.report_generator import ReportGenerator
        report = ReportGenerator("ss7_scan_report.html")
        has_report = True
    except ImportError:
        has_report = False
    
    # 1. Setup Leaks File
    leaks_file = os.path.join(os.getcwd(), "leaks.txt")
    if not os.path.exists(leaks_file):
        with open(leaks_file, "w") as f:
            f.write("--- SigPloit SS7 Leak Report ---\n")
            f.write(f"Started: {time.ctime()}\n\n")
            
    print(f"[!] LEAK FILE: {leaks_file}")
    print(f"[!] FULL LOG:  {os.path.join(os.getcwd(), 'alive_hosts.txt')}")
    if has_report:
        print(f"[!] HTML REPORT: {os.path.abspath('ss7_scan_report.html')}")
    print("[!] MODE: HIGH SPEED PARALLEL SCANNING")
    print("[!] Target Ports: 2904, 2905, 2906, 2907, 2908 (SIGTRAN Suite)")
    
    print("\nSelect Mode:")
    print("1) Single Public Network (Manual CIDR)")
    print("2) Mass Scan (From targets.txt)")
    print("3) RANDOM AUTO-SCAN (Infinite Bounty Mode)")
    
    if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[!] Uyari: Scapy icin root/administrator yetkisi gerekebilir.")
        if not _prompt_yes_no("Yine de devam edilsin mi? (e/h)", "h"):
            return

    mode = get_input("Choice", "3").lower()
    
    if mode == "1":
        target = get_input("Target CIDR", "")
        if not target:
            return
        network = _validate_cidr(target)
        if not network:
            print("[-] Gecersiz CIDR girildi.")
            return
        if network.num_addresses > 1024:
            if not _prompt_yes_no("[?] Aralik buyuk. Devam edilsin mi? (e/h)", "h"):
                return
        leaks = fast_scan_subnet(target)
        if has_report:
            for leak in leaks:
                report.add_result("SS7 Scanner", leak, "GATEWAY FOUND", f"SCTP Port Open - {target}")
            report.generate()
        print_results(leaks)
        input("\nPress Enter...")
        
    elif mode == "2":
        path = get_input("Path to targets.txt", "targets.txt")
        try:
            with open(path, 'r') as f:
                lines = [l.strip() for l in f if l.strip()]
            print(f"[+] Loaded {len(lines)} ranges.")
            for subnet in lines:
                network = _validate_cidr(subnet)
                if not network:
                    print(f"[-] Gecersiz CIDR atlandi: {subnet}")
                    continue
                if network.num_addresses > 1024:
                    print(f"[!] Aralik buyuk, atlandi: {subnet}")
                    continue
                leaks = fast_scan_subnet(subnet)
                if leaks:
                    print_leaks_found(leaks)
                    if has_report:
                        for leak in leaks:
                            report.add_result("SS7 Scanner", leak, "GATEWAY FOUND", f"SCTP Port Open - {subnet}")
        except Exception as e:
            print(f"Error: {e}")
        if has_report:
            report.generate()
        input("\nDone. Press Enter...")
        
    elif mode == "3":
        print("\n[+] STARTING INFINITE AUTO-SCAN...")
        print("[+] Press Ctrl+C to stop.\n")
        total_scanned = 0
        try:
            while True:
                subnet = generate_random_public_subnet()
                leaks = fast_scan_subnet(subnet)
                total_scanned += 254
                
                if leaks:
                    print_leaks_found(leaks)
                    if has_report:
                        for leak in leaks:
                            report.add_result("SS7 Scanner", leak, "GATEWAY FOUND", f"SCTP Port Open - {subnet}")
                
                if total_scanned % 5080 == 0: # approx every 20 subnets
                     print(f"[Status] Scanned {total_scanned} Unique IPs (x5 Ports)...")
                
                if total_scanned % 10000 == 0:
                     print(f"[Status] Total IPs Checked: {total_scanned}...")
                     if has_report:
                         report.generate()
                     
        except KeyboardInterrupt:
            print("\n\n[!] Auto-Scan Stopped by User.")
            if has_report:
                report.generate()
            input("Press Enter...")

def print_leaks_found(leaks):
    print("\n" + "!"*40)
    print(f" [!!!] LEAK CONFIRMED: {len(leaks)} NODES FOUND")
    print("!"*40)
    for ip in leaks:
         print(f" [+] VULNERABLE: {ip}")
    print("!"*40 + "\n")

def print_results(leaks):
    if leaks:
        print_leaks_found(leaks)
    else:
        print("\n[-] No leaks found in this range.")

if __name__ == "__main__":
    scan_main()
