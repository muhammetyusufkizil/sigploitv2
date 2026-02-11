#!/usr/bin/env python3
"""
SS7 Fraud & Information Gathering Module
Dolandırıcılık ve bilgi toplama saldırıları:
SendIMSI, MTForwardSMS, InsertSubscriberData, SendAuthenticationInfo, CancelLocation

@author: loay
@license: MIT license
"""

import sys
import time


def _post_attack_nav(menu_name="Dolandiricilik"):
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


def simsi():
    """SendIMSI - Abone IMSI numarasını alma."""
    try:
        from ss7.attacks.fraud import simsi_scapy
        simsi_scapy.simsi_main()
        return _post_attack_nav("Dolandiricilik")
    except ImportError as e:
        print(f"\033[31m[-] SendIMSI modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] SendIMSI hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def mtsms():
    """MTForwardSMS - SMS oltalama ve sahte SMS."""
    try:
        from ss7.attacks.fraud import mtsms_scapy
        mtsms_scapy.mtsms_main()
        return _post_attack_nav("Dolandiricilik")
    except ImportError as e:
        print(f"\033[31m[-] MTForwardSMS modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] MTForwardSMS hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def cl():
    """CancelLocation - Abone konumunu iptal et (bağlantı kes)."""
    try:
        from ss7.attacks.fraud import cl_scapy
        cl_scapy.cl_main()
        return _post_attack_nav("Dolandiricilik")
    except ImportError as e:
        print(f"\033[31m[-] CancelLocation modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] CancelLocation hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def isd():
    """InsertSubscriberData - Abone profili değiştirme."""
    try:
        from ss7.attacks.fraud import isd_scapy
        isd_scapy.isd_main()
        return _post_attack_nav("Dolandiricilik")
    except ImportError as e:
        print(f"\033[31m[-] ISD modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] ISD hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'


def sai():
    """SendAuthenticationInfo - Abone kimlik doğrulama vektörleri."""
    try:
        from ss7.attacks.fraud import sai_scapy
        sai_scapy.sai_main()
        return _post_attack_nav("Dolandiricilik")
    except ImportError as e:
        print(f"\033[31m[-] SAI modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] SAI hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
