#!/usr/bin/env python3
"""
SS7 Location Tracking Module
Konum takibi saldırıları: SRI, PSI, SRI-SM, ATI, SRI-GPRS

@author: myk
@license: MIT license
"""

import sys
import time


def _post_attack_nav(menu_name="Tracking"):
    """Saldırı sonrası navigasyon menüsü.
    
    Returns:
        str: 'sub' (alt menüye dön), 'attacks' (saldırı menüsüne dön),
             'main' (ana menüye dön), 'exit' (çık)
    """
    print()
    choice = input(f'\n{menu_name} menusune donmek ister misiniz? (e/h): ').strip().lower()
    if choice in ('e', 'evet', 'y', 'yes'):
        return 'sub'
    elif choice in ('h', 'hayir', 'n', 'no'):
        attack_menu = input('Baska bir saldiri kategorisi secmek ister misiniz? (e/h): ').strip().lower()
        if attack_menu in ('e', 'evet', 'y', 'yes'):
            return 'attacks'
        elif attack_menu in ('h', 'hayir', 'n', 'no'):
            main_menu = input('Ana menuye donmek ister misiniz? (e/cikis): ').strip().lower()
            if main_menu in ('e', 'evet', 'y', 'yes'):
                return 'main'
            elif main_menu in ('cikis', 'exit'):
                print('TCAP End...')
                sys.exit(0)
    return 'sub'  # Varsayılan: alt menüye dön


def sri():
    """SendRoutingInfo - Konum takibi, çağrı yönlendirme."""
    try:
        from ss7.attacks.tracking import sri_scapy
        sri_scapy.sri_main()
        return _post_attack_nav("Konum Takibi")
    except ImportError as e:
        print(f"\033[31m[-] SRI modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] SRI hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def psi():
    """ProvideSubscriberInfo - Güvenilir konum takibi."""
    try:
        from ss7.attacks.tracking import psi_scapy
        psi_scapy.psi_main()
        return _post_attack_nav("Konum Takibi")
    except ImportError as e:
        print(f"\033[31m[-] PSI modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] PSI hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def srism():
    """SendRoutingInfoForSM - SMS konum takibi."""
    try:
        from ss7.attacks.tracking import srism_scapy
        srism_scapy.srism_main()
        return _post_attack_nav("Konum Takibi")
    except ImportError as e:
        print(f"\033[31m[-] SRI-SM modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] SRI-SM hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def ati():
    """AnyTimeInterrogation - Konum takibi (çoğu operatör engeller)."""
    try:
        from ss7.attacks.tracking import ati_scapy
        ati_scapy.ati_main()
        return _post_attack_nav("Konum Takibi")
    except ImportError as e:
        print(f"\033[31m[-] ATI modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] ATI hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def srigprs():
    """SendRoutingInfoForGPRS - GPRS konum, SGSN GT alır."""
    try:
        from ss7.attacks.tracking import srigprs_scapy
        srigprs_scapy.srigprs_main()
        return _post_attack_nav("Konum Takibi")
    except ImportError as e:
        print(f"\033[31m[-] SRI-GPRS modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] SRI-GPRS hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
