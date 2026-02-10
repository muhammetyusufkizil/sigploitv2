#!/usr/bin/env python
"""
Multi-Protocol Scanner Module for SigPloit
With REAL protocol-level verification (not just port scanning).

Phase 1: Fast TCP/SCTP/UDP port scan
Phase 2: Protocol handshake verification (eliminates false positives)
"""
import sys
import os
import random
import struct
import socket
import ipaddress
import time
from scapy.all import IP, TCP, UDP, SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkAbort, Raw, sr, sr1, conf

conf.verb = 0

# ============================================
# PROTOCOL VERIFICATION FUNCTIONS
# ============================================

def verify_diameter(ip, port=3868, timeout=3):
    """
    Verify a real Diameter node by sending CER and checking for CEA.
    Returns (True, details) or (False, reason).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Build minimal Diameter CER (Capabilities-Exchange-Request)
        origin_host = b"scanner.sigploit.local"
        origin_realm = b"sigploit.local"
        
        # AVP: Origin-Host (264)
        avp1 = _build_diameter_avp(264, origin_host)
        # AVP: Origin-Realm (296) 
        avp2 = _build_diameter_avp(296, origin_realm)
        # AVP: Host-IP-Address (257) - dummy
        avp3 = _build_diameter_avp(257, b'\x00\x01' + socket.inet_aton("1.2.3.4"))
        # AVP: Vendor-Id (266)
        avp4 = _build_diameter_avp(266, struct.pack("!I", 0))
        # AVP: Product-Name (269)
        avp5 = _build_diameter_avp(269, b"SigPloit")
        
        avps = avp1 + avp2 + avp3 + avp4 + avp5
        
        # Diameter Header: Version(1) + Length(3) + Flags(1) + Code(3) + AppId(4) + HbH(4) + E2E(4)
        msg_len = 20 + len(avps)
        header = struct.pack("!B", 1)  # Version
        header += struct.pack("!I", msg_len)[1:]  # Length (3 bytes)
        header += struct.pack("!B", 0x80)  # Flags: Request
        header += struct.pack("!I", 257)[1:]  # Command Code: CER (3 bytes)
        header += struct.pack("!I", 0)  # Application-ID: 0 (base)
        header += struct.pack("!I", random.randint(1, 0xFFFFFFFF))  # Hop-by-Hop
        header += struct.pack("!I", random.randint(1, 0xFFFFFFFF))  # End-to-End
        
        cer = header + avps
        sock.send(cer)
        
        # Read response
        response = sock.recv(4096)
        sock.close()
        
        if not response or len(response) < 20:
            return False, "No Diameter response"
        
        # Check Diameter header
        version = response[0]
        resp_len = struct.unpack("!I", b'\x00' + response[1:4])[0]
        flags = response[4]
        cmd_code = struct.unpack("!I", b'\x00' + response[5:8])[0]
        
        if version != 1:
            return False, f"Not Diameter (version={version})"
        
        if cmd_code == 257 and not (flags & 0x80):
            # CEA (answer to CER) - THIS IS A REAL DIAMETER NODE
            # Try to extract Result-Code
            result_code = _extract_diameter_avp(response[20:], 268)
            origin = _extract_diameter_avp_str(response[20:], 264)
            realm = _extract_diameter_avp_str(response[20:], 296)
            
            details = f"CEA received"
            if origin:
                details += f" | Origin-Host: {origin}"
            if realm:
                details += f" | Realm: {realm}"
            if result_code:
                rc = struct.unpack("!I", result_code)[0] if len(result_code) == 4 else 0
                details += f" | Result-Code: {rc}"
            
            return True, details
        
        return False, f"Unexpected response (cmd={cmd_code}, flags=0x{flags:02x})"
        
    except socket.timeout:
        return False, "Timeout"
    except ConnectionRefusedError:
        return False, "Refused"
    except ConnectionResetError:
        return False, "Reset"
    except Exception as e:
        return False, str(e)


def verify_gtp(ip, port=2123, timeout=2):
    """
    Verify a real GTP node by sending Echo Request and checking for Echo Response.
    GTPv2-C Echo Request: Version=2, T=0, MessageType=1, Length=4
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # GTPv2 Echo Request
        # Flags: Version=2 (0x40), P=0, T=0 => 0x40
        # Message Type: 1 (Echo Request)
        # Length: 4 (just sequence + spare)
        # Sequence: random 3 bytes + spare 1 byte
        seq = random.randint(1, 0xFFFFFF)
        echo_req = struct.pack("!BBH", 0x40, 0x01, 4)  # Header: flags, type, length
        echo_req += struct.pack("!I", seq << 8)  # Sequence(3) + Spare(1)
        
        sock.sendto(echo_req, (ip, port))
        
        data, addr = sock.recvfrom(1024)
        sock.close()
        
        if not data or len(data) < 8:
            return False, "Too short"
        
        # Check GTPv2 Echo Response
        flags = data[0]
        msg_type = data[1]
        version = (flags >> 5) & 0x07
        
        if version == 2 and msg_type == 2:  # GTPv2 Echo Response
            return True, f"GTPv2 Echo Response from {addr[0]}"
        elif version == 1 and msg_type == 2:  # GTPv1 Echo Response
            return True, f"GTPv1 Echo Response from {addr[0]}"
        
        return False, f"Not GTP (version={version}, type={msg_type})"
        
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def verify_sip(ip, port=5060, timeout=2):
    """
    Verify a real SIP node by sending OPTIONS and checking response.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # SIP OPTIONS request
        branch = f"z9hG4bK{random.randint(100000,999999)}"
        call_id = f"{random.randint(100000,999999)}@scanner"
        
        sip_msg = (
            f"OPTIONS sip:{ip}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 1.2.3.4:5060;branch={branch}\r\n"
            f"From: <sip:scanner@sigploit.local>;tag={random.randint(1000,9999)}\r\n"
            f"To: <sip:{ip}:{port}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        
        sock.sendto(sip_msg.encode(), (ip, port))
        
        data, addr = sock.recvfrom(4096)
        sock.close()
        
        response = data.decode('utf-8', errors='ignore')
        
        if response.startswith("SIP/2.0"):
            # Extract status code
            parts = response.split('\r\n')[0].split(' ')
            status_code = parts[1] if len(parts) > 1 else "?"
            
            # Extract Server header if present
            server = ""
            for line in response.split('\r\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
                elif line.lower().startswith('user-agent:'):
                    server = line.split(':', 1)[1].strip()
                    break
            
            details = f"SIP/{status_code}"
            if server:
                details += f" | Server: {server}"
            
            return True, details
        
        return False, "Not SIP response"
        
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def verify_ss7_m3ua(ip, port, timeout=3):
    """
    Verify SS7/SIGTRAN node with SCTP INIT handshake.
    If raw packet permissions are unavailable, fall back to TCP M3UA probe.
    """
    try:
        pkt = IP(dst=ip) / SCTP(sport=random.randint(20000, 65000), dport=port) / SCTPChunkInit()
        ans = sr1(pkt, timeout=timeout, verbose=0)

        if ans is None:
            return False, "No SCTP response"
        if ans.haslayer(SCTPChunkInitAck):
            return True, "SCTP INIT-ACK (SIGTRAN)"
        if ans.haslayer(SCTPChunkAbort):
            return False, "SCTP ABORT"

        return False, f"Unexpected SCTP response ({ans.summary()[:80]})"
    except PermissionError:
        pass
    except Exception:
        pass

    # Fallback: TCP probe when raw packets cannot be sent (or Scapy path fails)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            return False, "TCP closed (fallback)"

        aspup = b'\x01\x00\x03\x01\x00\x00\x00\x08'
        sock.send(aspup)
        resp = sock.recv(256)
        if resp and len(resp) >= 8 and resp[0] == 0x01 and resp[2] in (0, 1, 2, 3, 4, 9):
            return True, f"TCP M3UA response (class={resp[2]} type={resp[3]})"
        return False, "TCP open but not M3UA (fallback)"
    except socket.timeout:
        return False, "TCP timeout (fallback)"
    except Exception as e:
        return False, f"fallback error: {str(e)[:60]}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================
# DIAMETER AVP HELPERS
# ============================================

def _build_diameter_avp(code, data, mandatory=True):
    """Build a Diameter AVP."""
    flags = 0x40 if mandatory else 0x00
    avp_len = 8 + len(data)
    avp = struct.pack("!I", code)
    avp += struct.pack("!B", flags)
    avp += struct.pack("!I", avp_len)[1:]
    avp += data
    # Pad to 4-byte boundary
    padding = (4 - (avp_len % 4)) % 4
    avp += b'\x00' * padding
    return avp

def _extract_diameter_avp(data, target_code):
    """Extract AVP value by code from Diameter message body."""
    idx = 0
    while idx + 8 <= len(data):
        code = struct.unpack("!I", data[idx:idx+4])[0]
        flags = data[idx+4]
        avp_len = struct.unpack("!I", b'\x00' + data[idx+5:idx+8])[0]
        
        has_vendor = bool(flags & 0x80)
        header_len = 12 if has_vendor else 8
        
        if avp_len < header_len or idx + avp_len > len(data) + 4:
            break
        
        if code == target_code:
            return data[idx+header_len:idx+avp_len]
        
        # Move to next AVP (with padding)
        padded_len = avp_len + (4 - (avp_len % 4)) % 4
        idx += padded_len
    
    return None

def _extract_diameter_avp_str(data, target_code):
    """Extract AVP as string."""
    val = _extract_diameter_avp(data, target_code)
    if val:
        return val.decode('utf-8', errors='ignore')
    return None


# ============================================
# MAIN SCANNER
# ============================================

def multi_scan_menu():
    """Main menu for multi-protocol scanning."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 60)
    print(" Multi-Protocol Telecom Scanner (Verified)")
    print(" SS7/SCTP | Diameter | GTP | SIP")
    print("=" * 60)
    print()
    print("\033[32m[+] NEW: Protocol-level verification (no false positives)\033[0m")
    print("\033[32m[+] Phase 1: Fast port scan  |  Phase 2: Handshake verify\033[0m")
    print()
    print("Select Scan Mode:")
    print()
    print("1) SS7 + Diameter + GTP + SIP (All Protocols)")
    print("2) SS7/SCTP Only (SIGTRAN)")
    print("3) Diameter Only (4G/LTE)")
    print("4) GTP Only (Mobile Data)")
    print("5) SIP Only (VoIP)")
    print("6) Verify Existing Results (from leaks_*.txt)")
    print()
    print("or type back to return")
    print()
    
    choice = input("\033[37m(\033[0m\033[2;31mscanner\033[0m\033[37m)>\033[0m ").strip().lower()
    
    if choice == "1":
        run_multi_scan(['SS7', 'DIAMETER', 'GTP', 'SIP'])
    elif choice == "2":
        run_multi_scan(['SS7'])
    elif choice == "3":
        run_multi_scan(['DIAMETER'])
    elif choice == "4":
        run_multi_scan(['GTP'])
    elif choice == "5":
        run_multi_scan(['SIP'])
    elif choice == "6":
        verify_existing_results()
    elif choice == "back":
        return
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (1-6)')
        time.sleep(1.5)
        multi_scan_menu()


def verify_existing_results():
    """
    Re-verify previously found results with protocol handshake.
    Reads leaks_*.txt files and does real protocol verification.
    """
    print("\n" + "=" * 60)
    print(" Re-Verify Existing Scan Results")
    print(" Eliminates false positives with protocol handshakes")
    print("=" * 60 + "\n")
    
    # Check multiple possible filenames for each protocol
    files_to_check = {}
    for proto, candidates in {
        'DIAMETER': ['leaks_diameter_new.txt', 'leaks_diameter.txt'],
        'SS7': ['leaks_ss7.txt', 'leaks.txt'],
        'GTP': ['leaks_gtp.txt'],
        'SIP': ['leaks_sip.txt'],
    }.items():
        for fname in candidates:
            if os.path.exists(fname):
                files_to_check[proto] = fname
                break
    
    verified_file = "leaks_verified.txt"
    verified_count = 0
    false_positive_count = 0
    
    with open(verified_file, "w") as vf:
        vf.write(f"--- SigPloit Verified Results ---\n")
        vf.write(f"Verification Date: {time.ctime()}\n\n")
    
    for proto, filename in files_to_check.items():
        if not os.path.exists(filename):
            continue
            
        try:
            import re
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (IOError, OSError):
            continue

        # Extract IP:PORT from any format
        targets_set = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('---') or line.startswith('='):
                continue
            m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if m:
                ip = m.group(1)
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                port = int(m.group(2))
                if not (1 <= port <= 65535):
                    continue
                targets_set.add((ip, port))

        if not targets_set:
            continue

        unique_targets = list(targets_set)
        # Limit to 200 per protocol for speed (diverse subnets first)
        if len(unique_targets) > 200:
            seen_subnets = set()
            sampled = []
            for ip, port in unique_targets:
                subnet = '.'.join(ip.split('.')[:3])
                if subnet not in seen_subnets:
                    seen_subnets.add(subnet)
                    sampled.append((ip, port))
                if len(sampled) >= 200:
                    break
            unique_targets = sampled
            print(f"\n[*] {proto}: {len(targets_set)} total -> {len(unique_targets)} sampled (diverse subnets)")
        else:
            print(f"\n[*] {proto}: {len(unique_targets)} unique targets to verify ({filename})")

        # Use threading for parallel verification
        from concurrent.futures import ThreadPoolExecutor, as_completed

        verify_func = {
            'DIAMETER': lambda t: (t, verify_diameter(t[0], t[1])),
            'SS7': lambda t: (t, verify_ss7_m3ua(t[0], t[1])),
            'GTP': lambda t: (t, verify_gtp(t[0], t[1])),
            'SIP': lambda t: (t, verify_sip(t[0], t[1])),
        }.get(proto)

        if not verify_func:
            continue

        done_count = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(verify_func, t): t for t in unique_targets}
            for future in as_completed(futures):
                done_count += 1
                try:
                    (ip, port), (verified, details) = future.result()
                except Exception as e:
                    verified, details = False, str(e)
                    ip, port = futures[future]

                if verified:
                    verified_count += 1
                    status = f"\033[32m[VERIFIED]\033[0m"
                    with open(verified_file, "a") as vf:
                        vf.write(f"[{proto}] {ip}:{port} | {details}\n")
                    print(f"  ({done_count}/{len(unique_targets)}) {ip}:{port} {status} {details}")
                else:
                    false_positive_count += 1
                    if done_count % 20 == 0:
                        print(f"  [{done_count}/{len(unique_targets)}] taranıyor...")
    
    print("\n" + "=" * 60)
    print(f" Verification Complete")
    print(f" Verified:        \033[32m{verified_count}\033[0m")
    print(f" False Positives: \033[31m{false_positive_count}\033[0m")
    print(f" Results saved:   {os.path.abspath(verified_file)}")
    print("=" * 60)
    
    input("\nPress Enter to return...")
    multi_scan_menu()


def run_multi_scan(protocols):
    """Run scanning with protocol-level verification."""
    
    PROTOCOL_PORTS = {
        'SS7': [2904, 2905, 2906, 2907, 2908],
        'DIAMETER': [3868, 3869],
        'GTP': [2123, 2152],
        'SIP': [5060, 5061],
    }
    
    print("\n" + "=" * 60)
    print(f" Scanning: {', '.join(protocols)}")
    print(f" Mode: Port Scan + Protocol Verification")
    print("=" * 60)
    print()
    print("[!] Output Files:")
    for proto in protocols:
        print(f"    - leaks_{proto.lower()}.txt (port scan hits)")
    print(f"    - leaks_verified.txt (protocol-verified only)")
    print()
    print("[+] Press Ctrl+C to stop.\n")
    
    # Create output files
    for proto in protocols:
        with open(f"leaks_{proto.lower()}.txt", "a") as _f:
            pass
    
    verified_file = "leaks_verified.txt"
    if not os.path.exists(verified_file):
        with open(verified_file, "w") as f:
            f.write(f"--- SigPloit Verified Results ---\n")
            f.write(f"Started: {time.ctime()}\n\n")
    
    scan_count = 0
    total_verified = 0
    total_false = 0
    
    try:
        while True:
            subnet = generate_random_subnet()
            network = ipaddress.ip_network(subnet, strict=False)
            target_ips = [str(ip) for ip in list(network.hosts())[:50]]
            
            results = {}
            
            # ---- PHASE 1: Fast port scan ----
            
            # SS7/SCTP Scan (SCTP is already strong indicator)
            if 'SS7' in protocols:
                ss7_leaks, ss7_recv = scan_sctp(target_ips, PROTOCOL_PORTS['SS7'])
                results['SS7'] = (ss7_leaks, ss7_recv)
                if ss7_leaks:
                    with open("leaks_ss7.txt", "a") as f:
                        for leak in ss7_leaks:
                            f.write(f"{leak}\n")
                    # SCTP INIT-ACK is already very reliable - web servers don't use SCTP
                    with open(verified_file, "a") as vf:
                        for leak in ss7_leaks:
                            vf.write(f"[SS7] {leak} | SCTP INIT-ACK\n")
                            total_verified += 1
                    for leak in ss7_leaks:
                        print(f"    \033[32m[!!!] SS7 VERIFIED: {leak}\033[0m")
            
            # Diameter: TCP scan + CER verification
            if 'DIAMETER' in protocols:
                dia_open = scan_tcp(target_ips, PROTOCOL_PORTS['DIAMETER'])
                results['DIAMETER'] = []
                if dia_open:
                    for target in dia_open:
                        ip, port = target.split(':')
                        verified, details = verify_diameter(ip, int(port))
                        if verified:
                            results['DIAMETER'].append(target)
                            total_verified += 1
                            with open("leaks_diameter.txt", "a") as f:
                                f.write(f"{target} | {details}\n")
                            with open(verified_file, "a") as vf:
                                vf.write(f"[DIAMETER] {target} | {details}\n")
                            print(f"    \033[32m[!!!] DIAMETER VERIFIED: {target} | {details}\033[0m")
                        else:
                            total_false += 1
            
            # GTP: UDP scan + Echo verification
            if 'GTP' in protocols:
                gtp_candidates = scan_udp_fast(target_ips, PROTOCOL_PORTS['GTP'])
                results['GTP'] = []
                if gtp_candidates:
                    for target in gtp_candidates:
                        ip, port = target.split(':')
                        verified, details = verify_gtp(ip, int(port))
                        if verified:
                            results['GTP'].append(target)
                            total_verified += 1
                            with open("leaks_gtp.txt", "a") as f:
                                f.write(f"{target} | {details}\n")
                            with open(verified_file, "a") as vf:
                                vf.write(f"[GTP] {target} | {details}\n")
                            print(f"    \033[32m[!!!] GTP VERIFIED: {target} | {details}\033[0m")
                        else:
                            total_false += 1
            
            # SIP: UDP scan + OPTIONS verification
            if 'SIP' in protocols:
                sip_candidates = scan_udp_fast(target_ips, PROTOCOL_PORTS['SIP'])
                results['SIP'] = []
                if sip_candidates:
                    for target in sip_candidates:
                        ip, port = target.split(':')
                        verified, details = verify_sip(ip, int(port))
                        if verified:
                            results['SIP'].append(target)
                            total_verified += 1
                            with open("leaks_sip.txt", "a") as f:
                                f.write(f"{target} | {details}\n")
                            with open(verified_file, "a") as vf:
                                vf.write(f"[SIP] {target} | {details}\n")
                            print(f"    \033[33m[!] SIP: {target} | {details}\033[0m")
                        else:
                            total_false += 1
            
            # ---- Status Line ----
            status_parts = [f"{subnet}:"]
            for proto in protocols:
                if proto == 'SS7':
                    leaks, recv = results.get('SS7', ([], 0))
                    status_parts.append(f"SS7={len(leaks)}")
                else:
                    resp = results.get(proto, [])
                    status_parts.append(f"{proto}={len(resp)}")
            
            print(f"[>] {' | '.join(status_parts)}")
            
            scan_count += 1
            if scan_count % 20 == 0:
                print(f"\n[Status] Subnets: {scan_count} | Verified: {total_verified} | False+: {total_false}\n")
                
    except KeyboardInterrupt:
        print(f"\n\n[+] Scan stopped.")
        print(f"[+] Subnets scanned: {scan_count}")
        print(f"[+] Verified hits:   {total_verified}")
        print(f"[+] False positives: {total_false}")
        print(f"[+] Results: leaks_verified.txt")
    
    input("\nPress Enter to return...")


def generate_random_subnet():
    """Generate random public /24, excluding private/reserved."""
    while True:
        o1 = random.randint(1, 223)
        o2 = random.randint(0, 255)
        o3 = random.randint(0, 255)
        
        if o1 == 0: continue
        if o1 == 10: continue
        if o1 == 127: continue
        if o1 == 172 and 16 <= o2 <= 31: continue
        if o1 == 192 and o2 == 168: continue
        if o1 == 169 and o2 == 254: continue
        if o1 >= 224: continue
        
        return f"{o1}.{o2}.{o3}.0/24"


def scan_sctp(target_ips, ports):
    """Scan SCTP/SS7 ports. SCTP INIT-ACK = strong SS7 indicator."""
    packets = []
    for ip in target_ips:
        for port in ports:
            pkt = IP(dst=ip)/SCTP(sport=random.randint(1024, 65535), dport=port, tag=0)/SCTPChunkInit()
            packets.append(pkt)
    
    if not packets:
        return [], 0
    
    ans, _ = sr(packets, timeout=2, verbose=0)
    
    leaks = []
    for sent, recv in ans:
        if recv.haslayer(SCTPChunkInitAck):
            leaks.append(f"{recv[IP].src}:{sent[SCTP].dport}")
    
    return leaks, len(ans)


def scan_tcp(target_ips, ports):
    """Fast TCP SYN scan (Phase 1 - candidates only)."""
    packets = []
    for ip in target_ips[:30]:
        for port in ports:
            pkt = IP(dst=ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            packets.append(pkt)
    
    if not packets:
        return []
    
    ans, _ = sr(packets, timeout=2, verbose=0)
    
    open_ports = []
    for sent, recv in ans:
        if recv.haslayer(TCP) and recv[TCP].flags == 0x12:
            open_ports.append(f"{recv[IP].src}:{sent[TCP].dport}")
    
    return open_ports


def scan_udp_fast(target_ips, ports):
    """Fast UDP scan - just find responsive IPs (Phase 1)."""
    packets = []
    for ip in target_ips[:30]:
        for port in ports:
            # Send minimal probe
            pkt = IP(dst=ip)/UDP(sport=random.randint(1024, 65535), dport=port)/Raw(load=b"\x00" * 8)
            packets.append(pkt)
    
    if not packets:
        return []
    
    ans, _ = sr(packets, timeout=2, verbose=0)
    
    responses = []
    for sent, recv in ans:
        if recv.haslayer(UDP):
            responses.append(f"{recv[IP].src}:{sent[UDP].dport}")
    
    return responses


if __name__ == "__main__":
    multi_scan_menu()
