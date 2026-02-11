#!/usr/bin/env python3
"""
SS7 DoS Module
DoS (Servis Engelleme) saldırıları: PurgeMS

@author: loay
@license: MIT license
"""

import sys
import time


def _post_attack_nav(menu_name="DoS"):
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


def purge():
    """PurgeMS DoS Attack - Toplu abone DoS saldırısı."""
    try:
        from ss7.attacks.dos import purge_scapy
        purge_scapy.purge_main()
        return _post_attack_nav("DoS")
    except ImportError as e:
        print(f"\033[31m[-] PurgeMS modulu yuklenemedi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        return 'sub'
    except Exception as e:
        print(f"\033[31m[-] PurgeMS hatasi: {e}\033[0m")
        time.sleep(2)
        return 'sub'
