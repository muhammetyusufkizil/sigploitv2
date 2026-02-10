#!/usr/bin/env python
"""
SigPloit PCAP Capture & Analysis Module
Captures telecom protocol traffic to PCAP files and analyzes them.

Supports: SS7/SIGTRAN, Diameter, GTP, SIP
Uses Scapy for capture and analysis.
"""
import sys
import os
import time
import struct
import datetime
import json

# ============================================
# PCAP FILE WRITER (Manual - no Scapy dependency for writing)
# ============================================

PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_RAW = 101      # Raw IP
PCAP_LINKTYPE_ETHERNET = 1   # Ethernet

class PcapWriter:
    """Write PCAP files manually for maximum compatibility."""

    def __init__(self, filename, linktype=PCAP_LINKTYPE_RAW):
        self.filename = filename
        self.linktype = linktype
        self.packet_count = 0
        self.file = None

        # Create captures directory
        cap_dir = os.path.dirname(filename) or '.'
        if cap_dir != '.' and not os.path.exists(cap_dir):
            os.makedirs(cap_dir, exist_ok=True)

        self._write_header()

    def _write_header(self):
        """Write PCAP global header."""
        self.file = open(self.filename, 'wb')
        # Global header: magic, version_major, version_minor, thiszone, sigfigs, snaplen, linktype
        header = struct.pack('<IHHiIII',
                             PCAP_MAGIC,
                             PCAP_VERSION_MAJOR,
                             PCAP_VERSION_MINOR,
                             0,       # thiszone (UTC)
                             0,       # sigfigs
                             65535,   # snaplen
                             self.linktype)
        self.file.write(header)

    def write_packet(self, data, timestamp=None):
        """Write a single packet to the PCAP file."""
        if self.file is None:
            return

        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        incl_len = len(data)
        orig_len = len(data)

        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
        self.file.write(pkt_header)
        self.file.write(data)
        self.packet_count += 1
        self.file.flush()

    def write_tcp_packet(self, src_ip, dst_ip, src_port, dst_port, payload, direction='out'):
        """Write a TCP packet with IP header."""
        # Build minimal IP + TCP header + payload
        tcp_header = struct.pack('!HHIIBBHHH',
                                 src_port,    # Source Port
                                 dst_port,    # Dest Port
                                 0,           # Seq Number
                                 0,           # Ack Number
                                 0x50,        # Data Offset (5 * 4 = 20 bytes)
                                 0x18,        # Flags (PSH+ACK)
                                 65535,       # Window
                                 0,           # Checksum
                                 0)           # Urgent Pointer

        total_len = 20 + 20 + len(payload)  # IP + TCP + payload

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                0x45,         # Version + IHL
                                0,            # DSCP
                                total_len,    # Total Length
                                0,            # Identification
                                0,            # Flags + Fragment Offset
                                64,           # TTL
                                6,            # Protocol (TCP)
                                0,            # Checksum (0 = let Wireshark handle)
                                _ip_to_bytes(src_ip),
                                _ip_to_bytes(dst_ip))

        packet = ip_header + tcp_header + payload
        self.write_packet(packet)

    def write_udp_packet(self, src_ip, dst_ip, src_port, dst_port, payload):
        """Write a UDP packet with IP header."""
        udp_len = 8 + len(payload)
        udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

        total_len = 20 + 8 + len(payload)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                0x45, 0, total_len, 0, 0, 64,
                                17,  # Protocol (UDP)
                                0,
                                _ip_to_bytes(src_ip),
                                _ip_to_bytes(dst_ip))

        packet = ip_header + udp_header + payload
        self.write_packet(packet)

    def close(self):
        """Close the PCAP file."""
        if self.file:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()


def _ip_to_bytes(ip_str):
    """Convert IP string to 4 bytes."""
    try:
        parts = ip_str.split('.')
        return bytes([int(p) for p in parts])
    except Exception:
        return b'\x00\x00\x00\x00'


# ============================================
# CAPTURE CONTEXT (for use in attack modules)
# ============================================

class CaptureContext:
    """Context manager for capturing traffic during attacks."""

    _active_capture = None

    def __init__(self, filename=None, protocol="unknown"):
        if filename is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            cap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'captures')
            os.makedirs(cap_dir, exist_ok=True)
            filename = os.path.join(cap_dir, f"{protocol}_{ts}.pcap")

        self.writer = PcapWriter(filename)
        self.filename = filename
        self.protocol = protocol
        self.start_time = time.time()

    def __enter__(self):
        CaptureContext._active_capture = self
        print(f"[+] Paket yakalama basladi: {self.filename}")
        return self

    def __exit__(self, *args):
        CaptureContext._active_capture = None
        self.writer.close()
        elapsed = time.time() - self.start_time
        print(f"[+] Yakalama tamamlandi: {self.writer.packet_count} paket, {elapsed:.1f}sn")
        print(f"[+] Dosya: {self.filename}")

    def log_tcp(self, src_ip, dst_ip, src_port, dst_port, data, direction='out'):
        """Log a TCP packet."""
        self.writer.write_tcp_packet(src_ip, dst_ip, src_port, dst_port, data, direction)

    def log_udp(self, src_ip, dst_ip, src_port, dst_port, data):
        """Log a UDP packet."""
        self.writer.write_udp_packet(src_ip, dst_ip, src_port, dst_port, data)

    def log_raw(self, data):
        """Log raw data."""
        self.writer.write_packet(data)

    @staticmethod
    def get_active():
        """Get the active capture context (if any)."""
        return CaptureContext._active_capture


# ============================================
# PCAP ANALYSIS
# ============================================

def analyze_pcap(filename):
    """Analyze a PCAP file and print statistics."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, SCTP
        use_scapy = True
    except ImportError:
        use_scapy = False

    if not os.path.exists(filename):
        print(f"[-] Dosya bulunamadi: {filename}")
        return None

    stats = {
        'total_packets': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'sctp_packets': 0,
        'other_packets': 0,
        'unique_ips': set(),
        'unique_ports': set(),
        'protocols_detected': set(),
        'conversations': {},
        'file_size': os.path.getsize(filename),
        'diameter_messages': 0,
        'sip_messages': 0,
        'gtp_messages': 0,
        'm3ua_messages': 0,
    }

    if use_scapy:
        return _analyze_with_scapy(filename, stats)
    else:
        return _analyze_manual(filename, stats)


def _analyze_with_scapy(filename, stats):
    """Analyze PCAP using Scapy."""
    from scapy.all import rdpcap, IP, TCP, UDP, SCTP

    try:
        packets = rdpcap(filename)
    except Exception as e:
        print(f"[-] PCAP okuma hatasi: {e}")
        return None

    stats['total_packets'] = len(packets)

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            stats['unique_ips'].add(src)
            stats['unique_ips'].add(dst)

            if TCP in pkt:
                stats['tcp_packets'] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                stats['unique_ports'].add(sport)
                stats['unique_ports'].add(dport)

                # Track conversations
                conv_key = f"{src}:{sport} <-> {dst}:{dport}"
                stats['conversations'][conv_key] = stats['conversations'].get(conv_key, 0) + 1

                # Protocol detection
                payload = bytes(pkt[TCP].payload)
                _detect_protocol(payload, dport, stats)

            elif UDP in pkt:
                stats['udp_packets'] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                stats['unique_ports'].add(sport)
                stats['unique_ports'].add(dport)

                payload = bytes(pkt[UDP].payload)
                _detect_protocol(payload, dport, stats)

            elif SCTP in pkt:
                stats['sctp_packets'] += 1
            else:
                stats['other_packets'] += 1

    stats['unique_ips'] = list(stats['unique_ips'])
    stats['unique_ports'] = sorted(list(stats['unique_ports']))
    stats['protocols_detected'] = list(stats['protocols_detected'])

    return stats


def _analyze_manual(filename, stats):
    """Analyze PCAP manually without Scapy."""
    try:
        with open(filename, 'rb') as f:
            # Read global header
            header = f.read(24)
            if len(header) < 24:
                print("[-] Gecersiz PCAP dosyasi")
                return None

            magic = struct.unpack('<I', header[:4])[0]
            if magic != PCAP_MAGIC:
                # Try big-endian
                magic = struct.unpack('>I', header[:4])[0]
                if magic != PCAP_MAGIC:
                    print("[-] Gecersiz PCAP magic number")
                    return None

            # Read packets
            while True:
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                stats['total_packets'] += 1

                # Try to parse IP header
                if len(pkt_data) >= 20:
                    version = (pkt_data[0] >> 4) & 0xF
                    if version == 4:
                        protocol = pkt_data[9]
                        src_ip = '.'.join(str(b) for b in pkt_data[12:16])
                        dst_ip = '.'.join(str(b) for b in pkt_data[16:20])
                        stats['unique_ips'].add(src_ip)
                        stats['unique_ips'].add(dst_ip)

                        ihl = (pkt_data[0] & 0xF) * 4

                        if protocol == 6:  # TCP
                            stats['tcp_packets'] += 1
                            if len(pkt_data) >= ihl + 4:
                                sport = struct.unpack('!H', pkt_data[ihl:ihl+2])[0]
                                dport = struct.unpack('!H', pkt_data[ihl+2:ihl+4])[0]
                                stats['unique_ports'].add(sport)
                                stats['unique_ports'].add(dport)

                                tcp_hdr_len = ((pkt_data[ihl+12] >> 4) & 0xF) * 4
                                payload = pkt_data[ihl + tcp_hdr_len:]
                                _detect_protocol(payload, dport, stats)

                        elif protocol == 17:  # UDP
                            stats['udp_packets'] += 1
                            if len(pkt_data) >= ihl + 4:
                                sport = struct.unpack('!H', pkt_data[ihl:ihl+2])[0]
                                dport = struct.unpack('!H', pkt_data[ihl+2:ihl+4])[0]
                                stats['unique_ports'].add(sport)
                                stats['unique_ports'].add(dport)

                                payload = pkt_data[ihl + 8:]
                                _detect_protocol(payload, dport, stats)

                        elif protocol == 132:  # SCTP
                            stats['sctp_packets'] += 1
                        else:
                            stats['other_packets'] += 1

    except Exception as e:
        print(f"[-] Analiz hatasi: {e}")
        return None

    stats['unique_ips'] = list(stats['unique_ips'])
    stats['unique_ports'] = sorted(list(stats['unique_ports']))
    stats['protocols_detected'] = list(stats['protocols_detected'])

    return stats


def _detect_protocol(payload, dport, stats):
    """Detect telecom protocol from payload."""
    if not payload or len(payload) < 4:
        return

    # Diameter detection (version=1, first byte)
    if dport in [3868, 3869] or (len(payload) >= 20 and payload[0] == 1):
        if len(payload) >= 20 and payload[0] == 1:
            stats['diameter_messages'] += 1
            stats['protocols_detected'].add('DIAMETER')
            return

    # M3UA detection (version=1, reserved=0)
    if dport in [2905, 2904, 2906, 2907, 2908]:
        if len(payload) >= 8 and payload[0] == 1 and payload[1] == 0:
            stats['m3ua_messages'] += 1
            stats['protocols_detected'].add('M3UA/SS7')
            return

    # SIP detection
    if dport in [5060, 5061]:
        try:
            text = payload[:20].decode('utf-8', errors='ignore').upper()
            if any(text.startswith(m) for m in ['SIP/', 'INVITE', 'REGISTER', 'OPTIONS', 'BYE', 'CANCEL', 'ACK', 'MESSAGE']):
                stats['sip_messages'] += 1
                stats['protocols_detected'].add('SIP')
                return
        except Exception:
            pass

    # GTP detection
    if dport in [2123, 2152]:
        if len(payload) >= 4:
            gtp_version = (payload[0] >> 5) & 0x7
            if gtp_version in [1, 2]:
                stats['gtp_messages'] += 1
                stats['protocols_detected'].add('GTP')
                return


def print_analysis(stats):
    """Print PCAP analysis results."""
    if not stats:
        return

    print("\n" + "=" * 60)
    print(" PCAP Analiz Sonuclari")
    print("=" * 60)

    print(f"\n  Dosya Boyutu:       {stats['file_size'] / 1024:.1f} KB")
    print(f"  Toplam Paket:       {stats['total_packets']}")
    print(f"  TCP Paketleri:      {stats['tcp_packets']}")
    print(f"  UDP Paketleri:      {stats['udp_packets']}")
    print(f"  SCTP Paketleri:     {stats['sctp_packets']}")
    print(f"  Diger:              {stats['other_packets']}")

    print(f"\n  Benzersiz IP:       {len(stats['unique_ips'])}")
    if stats['unique_ips']:
        for ip in stats['unique_ips'][:10]:
            print(f"    - {ip}")
        if len(stats['unique_ips']) > 10:
            print(f"    ... ve {len(stats['unique_ips']) - 10} daha")

    print(f"\n  Benzersiz Port:     {len(stats['unique_ports'])}")
    if stats['unique_ports']:
        known_ports = {
            2904: 'M2UA', 2905: 'M3UA', 2906: 'M2PA', 2907: 'M3UA-alt',
            3868: 'Diameter', 3869: 'Diameter-TLS',
            2123: 'GTPv2-C', 2152: 'GTP-U',
            5060: 'SIP', 5061: 'SIP-TLS',
        }
        for port in stats['unique_ports'][:15]:
            name = known_ports.get(port, '')
            extra = f" ({name})" if name else ""
            print(f"    - {port}{extra}")

    print(f"\n  Tespit Edilen Protokoller:")
    if stats['protocols_detected']:
        for proto in stats['protocols_detected']:
            print(f"    - {proto}")
    else:
        print("    (Taninan protokol yok)")

    # Protocol-specific counts
    if stats['diameter_messages']:
        print(f"\n  Diameter Mesajlari: {stats['diameter_messages']}")
    if stats['m3ua_messages']:
        print(f"  M3UA/SS7 Mesajlari: {stats['m3ua_messages']}")
    if stats['sip_messages']:
        print(f"  SIP Mesajlari:      {stats['sip_messages']}")
    if stats['gtp_messages']:
        print(f"  GTP Mesajlari:      {stats['gtp_messages']}")

    # Top conversations
    if stats.get('conversations'):
        print(f"\n  En Aktif Konusmalar:")
        sorted_convs = sorted(stats['conversations'].items(), key=lambda x: x[1], reverse=True)
        for conv, count in sorted_convs[:5]:
            print(f"    {count:5d} paket: {conv}")

    print("\n" + "=" * 60)


# ============================================
# INTERACTIVE MENU
# ============================================

def get_input(prompt, default=None):
    if default:
        data = input(f"{prompt} [{default}]: ")
        return data if data else default
    return input(f"{prompt}: ")


def pcap_menu():
    """PCAP analysis menu."""
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print(" Paket Yakalama ve Analiz")
    print("=" * 60)
    print()
    print("  0) PCAP Dosyasi Analiz Et")
    print("  1) Kayitli PCAP Dosyalarini Listele")
    print("  2) Canli Yakalama Baslat (Diameter)")
    print("  3) Canli Yakalama Baslat (SIP)")
    print("  4) Canli Yakalama Baslat (SS7)")
    print("  5) PCAP'den Istatistik Cikar (JSON)")
    print()
    print("  Geri donmek icin 'back' yazin")
    print()

    choice = input("\033[37m(\033[0m\033[2;31mpcap\033[0m\033[37m)>\033[0m ")

    if choice == "0":
        _analyze_file()
        pcap_menu()
    elif choice == "1":
        _list_captures()
        pcap_menu()
    elif choice == "2":
        _live_capture_diameter()
        pcap_menu()
    elif choice == "3":
        _live_capture_sip()
        pcap_menu()
    elif choice == "4":
        _live_capture_ss7()
        pcap_menu()
    elif choice == "5":
        _export_stats()
        pcap_menu()
    elif choice == "back" or choice == "geri":
        return
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-5)')
        time.sleep(1.5)
        pcap_menu()


def _analyze_file():
    """Analyze a PCAP file."""
    print("\n[+] PCAP dosyasi yolu girin:")
    filename = get_input("Dosya yolu", "captures/")

    if os.path.isdir(filename):
        # List files in directory
        files = [f for f in os.listdir(filename) if f.endswith('.pcap')]
        if not files:
            print("[-] PCAP dosyasi bulunamadi.")
            input("\nDevam etmek icin Enter'a basin...")
            return

        print("\nDosyalar:")
        for i, f in enumerate(files):
            size = os.path.getsize(os.path.join(filename, f))
            print(f"  {i}) {f} ({size/1024:.1f} KB)")

        idx = int(get_input("Dosya numarasi", "0"))
        if idx < len(files):
            filename = os.path.join(filename, files[idx])
        else:
            print("[-] Gecersiz secim.")
            return

    print(f"\n[+] {filename} analiz ediliyor...")
    stats = analyze_pcap(filename)
    if stats:
        print_analysis(stats)

    input("\nDevam etmek icin Enter'a basin...")


def _list_captures():
    """List captured PCAP files."""
    cap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'captures')

    if not os.path.exists(cap_dir):
        print("\n[-] captures/ dizini bulunamadi. Henuz yakalama yapilmamis.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    files = [f for f in os.listdir(cap_dir) if f.endswith('.pcap')]
    if not files:
        print("\n[-] PCAP dosyasi bulunamadi.")
        input("\nDevam etmek icin Enter'a basin...")
        return

    print(f"\n  {'Dosya':<45} {'Boyut':>10}")
    print("  " + "-" * 57)
    for f in sorted(files, reverse=True):
        filepath = os.path.join(cap_dir, f)
        size = os.path.getsize(filepath)
        size_str = f"{size/1024:.1f} KB" if size > 1024 else f"{size} B"
        print(f"  {f:<45} {size_str:>10}")

    input("\nDevam etmek icin Enter'a basin...")


def _live_capture_diameter():
    """Live capture Diameter traffic."""
    import socket as sock_module

    target_ip = get_input("Hedef IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "3868"))

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'captures')
    os.makedirs(cap_dir, exist_ok=True)
    pcap_file = os.path.join(cap_dir, f"diameter_{target_ip}_{ts}.pcap")

    with CaptureContext(pcap_file, "diameter") as cap:
        try:
            from ss7.attacks.diameter_module import build_cer, parse_diameter_response

            s = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target_ip, target_port))
            print(f"[+] TCP baglandi {target_ip}:{target_port}")

            # CER
            cer = build_cer("probe.sigploit.local", "sigploit.local")
            s.send(cer)
            cap.log_tcp("127.0.0.1", target_ip, 12345, target_port, cer, 'out')
            print("[+] CER gonderildi ve kaydedildi")

            cea = s.recv(4096)
            if cea:
                cap.log_tcp(target_ip, "127.0.0.1", target_port, 12345, cea, 'in')
                parsed = parse_diameter_response(cea)
                print(f"[+] CEA alindi ve kaydedildi ({len(cea)} byte)")
                print(f"    Origin: {parsed.get('origin_host', 'N/A')}")

            s.close()
        except Exception as e:
            print(f"[-] Hata: {e}")

    input("\nDevam etmek icin Enter'a basin...")


def _live_capture_sip():
    """Live capture SIP traffic."""
    import socket as sock_module

    target_ip = get_input("Hedef IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'captures')
    os.makedirs(cap_dir, exist_ok=True)
    pcap_file = os.path.join(cap_dir, f"sip_{target_ip}_{ts}.pcap")

    with CaptureContext(pcap_file, "sip") as cap:
        try:
            from ss7.attacks.sip_module import build_sip_options

            s = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_DGRAM)
            s.settimeout(5)

            options = build_sip_options(target_ip, target_port)
            s.sendto(options.encode(), (target_ip, target_port))
            cap.log_udp("127.0.0.1", target_ip, 5060, target_port, options.encode())
            print("[+] SIP OPTIONS gonderildi ve kaydedildi")

            try:
                data, addr = s.recvfrom(4096)
                cap.log_udp(target_ip, "127.0.0.1", target_port, 5060, data)
                print(f"[+] SIP yanit alindi ve kaydedildi ({len(data)} byte)")
            except sock_module.timeout:
                print("[-] Yanit zaman asimi")

            s.close()
        except Exception as e:
            print(f"[-] Hata: {e}")

    input("\nDevam etmek icin Enter'a basin...")


def _live_capture_ss7():
    """Live capture SS7/M3UA traffic."""
    import socket as sock_module

    target_ip = get_input("Hedef IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "2905"))

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'captures')
    os.makedirs(cap_dir, exist_ok=True)
    pcap_file = os.path.join(cap_dir, f"ss7_{target_ip}_{ts}.pcap")

    with CaptureContext(pcap_file, "ss7") as cap:
        try:
            s = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_STREAM)
            s.settimeout(8)
            s.connect((target_ip, target_port))
            print(f"[+] TCP baglandi {target_ip}:{target_port}")

            # M3UA ASP Up
            asp_up = b'\x01\x00\x03\x01\x00\x00\x00\x08'
            s.send(asp_up)
            cap.log_tcp("127.0.0.1", target_ip, 12345, target_port, asp_up, 'out')
            print("[+] M3UA ASP Up gonderildi ve kaydedildi")

            resp = s.recv(1024)
            if resp:
                cap.log_tcp(target_ip, "127.0.0.1", target_port, 12345, resp, 'in')
                print(f"[+] M3UA yanit alindi ve kaydedildi ({len(resp)} byte)")

            s.close()
        except Exception as e:
            print(f"[-] Hata: {e}")

    input("\nDevam etmek icin Enter'a basin...")


def _export_stats():
    """Export PCAP stats to JSON."""
    filename = get_input("PCAP dosya yolu")

    if not os.path.exists(filename):
        print(f"[-] Dosya bulunamadi: {filename}")
        input("\nDevam etmek icin Enter'a basin...")
        return

    stats = analyze_pcap(filename)
    if not stats:
        return

    print_analysis(stats)

    json_file = filename.replace('.pcap', '_stats.json')
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n[+] Istatistikler kaydedildi: {json_file}")

    input("\nDevam etmek icin Enter'a basin...")


if __name__ == "__main__":
    pcap_menu()
