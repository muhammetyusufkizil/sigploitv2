#!/usr/bin/env python
'''
SigPloit Main

Created on 1 Feb 2018

@author: loay

@license:    MIT license
'''

import sys
import os
import signal
import time
import ss7main
import gtpmain
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format


def banner(word):
    letterforms = r'''\
       |       |       |       |       |       |       | |
  XXX  |  XXX  |  XXX  |   X   |       |  XXX  |  XXX  |!|
  X  X |  X  X |  X  X |       |       |       |       |"|
  X X  |  X X  |XXXXXXX|  X X  |XXXXXXX|  X X  |  X X  |#|
 XXXXX |X  X  X|X  X   | XXXXX |   X  X|X  X  X| XXXXX |$|
XXX   X|X X  X |XXX X  |   X   |  X XXX| X  X X|X   XXX|%|
  XX   | X  X  |  XX   | XXX   |X   X X|X    X | XXX  X|&|
  XXX  |  XXX  |   X   |  X    |       |       |       |'|
   XX  |  X    | X     | X     | X     |  X    |   XX  |(|
  XX   |    X  |     X |     X |     X |    X  |  XX   |)|
       | X   X |  X X  |XXXXXXX|  X X  | X   X |       |*|
       |   X   |   X   | XXXXX |   X   |   X   |       |+|
       |       |       |  XXX  |  XXX  |   X   |  X    |,|
       |       |       | XXXXX |       |       |       |-|
       |       |       |       |  XXX  |  XXX  |  XXX  |.|
      X|     X |    X  |   X   |  X    | X     |X      |/|
  XXX  | X   X |X     X|X     X|X     X| X   X |  XXX  |0|
   X   |  XX   | X X   |   X   |   X   |   X   | XXXXX |1|
 XXXXX |X     X|      X| XXXXX |X      |X      |XXXXXXX|2|
 XXXXX |X     X|      X| XXXXX |      X|X     X| XXXXX |3|
X      |X    X |X    X |X    X |XXXXXXX|     X |     X |4|
XXXXXXX|X      |X      |XXXXXX |      X|X     X| XXXXX |5|
 XXXXX |X     X|X      |XXXXXX |X     X|X     X| XXXXX |6|
XXXXXX |X    X |    X  |   X   |  X    |  X    |  X    |7|
 XXXXX |X     X|X     X| XXXXX |X     X|X     X| XXXXX |8|
 XXXXX |X     X|X     X| XXXXXX|      X|X     X| XXXXX |9|
   X   |  XXX  |   X   |       |   X   |  XXX  |   X   |:|
  XXX  |  XXX  |       |  XXX  |  XXX  |   X   |  X    |;|
    X  |   X   |  X    | X     |  X    |   X   |    X  |<|
       |       |XXXXXXX|       |XXXXXXX|       |       |=|
  X    |   X   |    X  |     X |    X  |   X   |  X    |>|
 XXXXX |X     X|      X|   XXX |   X   |       |   X   |?|
 XXXXX |X     X|X XXX X|X XXX X|X XXXX |X      | XXXXX |@|
   X   |  X X  | X   X |X     X|XXXXXXX|X     X|X     X|A|
XXXXXX |X     X|X     X|XXXXXX |X     X|X     X|XXXXXX |B|
 XXXXX |X     X|X      |X      |X      |X     X| XXXXX |C|
XXXXXX |X     X|X     X|X     X|X     X|X     X|XXXXXX |D|
XXXXXXX|X      |X      |XXXXX  |X      |X      |XXXXXXX|E|
XXXXXXX|X      |X      |XXXXX  |X      |X      |X      |F|
 21.45 |6     8|7      |2   lat|x1    x5|9     4| 31.74 |G|
X     X|X     X|X     X|XXXXXXX|X     X|X     X|X     X|H|
  XXX  |   X   |   X   |   X   |   X   |   X   |  XXX  |I|
      X|      X|      X|      X|X     X|X     X| XXXXX |J|
X    X |X   X  |X  X   |XXX    |X  X   |X   X  |X    X |K|
X      |X      |X      |X      |X      |X      |XXXXXXX|L|
X     X|XX   XX|X X X X|X  X  X|X     X|X     X|X     X|M|
X     X|XX    X|X X   X|X  X  X|X   X X|X    XX|X     X|N|
XXXXXXX|X     X|X     X|X     X|X     X|X     X|XXXXXXX|O|
XXXXXX |X     X|X     X|XXXXXX |X      |X      |X      |P|
 XXXXX |X     X|X     X|X     X|X   X X|X    X | XXXX X|Q|
XXXXXX |X     X|X     X|XXXXXX |X   X  |X    X |X     X|R|
 _IMSI |0x1  GT|PC     | _IMEI |     CI|Kc  421| _HLR_ |S|
XXXXXXX|   X   |   X   |   X   |   X   |   X   |   X   |T|
X     X|X     X|X     X|X     X|X     X|X     X| XXXXX |U|
X     X|X     X|X     X|X     X| X   X |  X X  |   X   |V|
X     X|X  X  X|X  X  X|X  X  X|X  X  X|X  X  X| XX XX |W|
X     X| X   X |  X X  |   X   |  X X  | X   X |X     X|X|
X     X| X   X |  X X  |   X   |   X   |   X   |   X   |Y|
XXXXXXX|     X |    X  |   X   |  X    | X     |XXXXXXX|Z|
 XXXXX | X     | X     | X     | X     | X     | XXXXX |[|
X      | X     |  X    |   X   |    X  |     X |      X|\|
 XXXXX |     X |     X |     X |     X |     X | XXXXX |]|
   X   |  X X  | X   X |       |       |       |       |^|
       |       |       |       |       |       |XXXXXXX|_|
       |  XXX  |  XXX  |   X   |    X  |       |       |`|
       |   XX  |  X  X | X    X| XXXXXX| X    X| X    X|a|
       | XXXXX | X    X| XXXXX | X    X| X    X| XXXXX |b|
       |  XXXX | X    X| X     | X     | X    X|  XXXX |c|
       | XXXXX | X    X| X    X| X    X| X    X| XXXXX |d|
       | XXXXXX| X     | XXXXX | X     | X     | XXXXXX|e|
       | XXXXXX| X     | XXXXX | X     | X     | X     |f|
       |  XXXX | X    X| X     | X  gtp| X    X|  XXXX |g|
       | X    X| X    X| XXXXXX| X    X| X    X| X    X|h|
       |  E    |  n    |  C    |  r    |  P    |  T    |i|
       |      X|      X|      X|      X| X    X|  XXXX |j|
       | X    X| X   X | XXXX  | X  X  | X   X | X    X|k|
       | GT    | PC    | x7    | x6    | x8    | Fraud |l|
       | X    X| XX  XX| X XX X| X    X| X    X| X    X|m|
       | X    X| XX   X| X X  X| X  X X| X   XX| X    X|n|
       |  SGSN | X    X| X    X| X    X| X    X|  gGsN |o|
       | Track | 6    8| s    i|credit | Kc    | G     |p|
       |  XXXX | X    X| X    X| X  X X| X   X |  XXX X|q|
       | XXXXX | X    X| X    X| XXXXX | X   X | X    X|r|
       |  XXXX | X     |  XXXX |      X| X    X|  XXXX |s|
       |--USIM-- |   x0  |   x2  |   x3  |   x8  |   x6  |t|
       | X    X| X    X| X    X| X    X| X    X|  XXXX |u|
       | X    X| X    X| X    X| X    X|  X  X |   XX  |v|
       | X    X| X    X| X    X| X XX X| XX  XX| X    X|w|
       | X    X|  X  X |   XX  |   XX  |  X  X | X    X|x|
       |  X   X|   X X |    X  |    X  |    X  |    X  |y|
       | XXXXXX|     X |    X  |   X   |  X    | XXXXXX|z|
  XXX  | X     | X     |XX     | X     | X     |  XXX  |{|
   X   |   X   |   X   |       |   X   |   X   |   X   |||
  XXX  |     X |     X |     XX|     X |     X |  XXX  |}|
 XX    |X  X  X|    XX |       |       |       |       |~|
'''.splitlines()

    table = {}
    for form in letterforms:
        if '|' in form:
            table[form[-2]] = form[:-3].split('|')

    ROWS = len(list(table.values())[0])

    for row in range(ROWS):
        for c in word:
            print(table[c][row], end=' ')
        print()
    print()



def mainMenu():
    os.system('cls' if os.name == 'nt' else 'clear')

    banner('SigPloit')
    print("\033[33m[-][-]\033[0m\t\tSignaling Exploitation Framework\t\033[33m [-][-]\033[0m")
    print("\033[33m[-][-]\033[0m\t\t\tVersion:\033[31mBETA 1.1\033[0m\t\t\033[33m [-][-]\033[0m")
    print("\033[33m[-][-]\033[0m\t\tAuthor:\033[32mLoay MYK(@mykizil)\033[0m\t\033[33m [-][-]\033[0m\n")
    print()
    print("Contributors:")

    print("\t\033[31mRosalia D'Alessandro\033[0m")
    print("\t\033[31mIlario Dal Grande\033[0m")
    print()
    print()
    print()
    print()
    print()
    print("   Modul".rjust(10) + "\t\t\tAciklama")
    print("   --------                --------------------")
    print("0) SS7".rjust(8) + "\t\t2G/3G Ses ve SMS saldirilari")
    print("1) GTP".rjust(8) + "\t\t3G/4G Veri saldirilari")
    print("2) Diameter".rjust(13) + "\t\t4G/LTE saldirilari (TAM)")
    print("3) SIP".rjust(8) + "\t\t4G IMS/VoIP saldirilari (TAM)")
    print("4) Yerel Ag".rjust(13) + "\t\tWi-Fi cihaz tarama")
    print("5) Turkiye Tarayici".rjust(21) + "\tTR altyapi tarama + zafiyet testi")
    print("6) Dunya Tarayici".rjust(19) + "\tGlobal tarama (Diameter+GTP+SIP+SS7)")
    print("7) Sonuc Test".rjust(15) + "\t\tBulunan sonuclari dogrula + saldiri")
    print("8) Hedef Bul".rjust(14) + "\t\tShodan/Censys ile hedef bulma")
    print("9) Oto Zincir".rjust(15) + "\t\tScan->Verify->Exploit->Report")
    print("10) PCAP Analiz".rjust(17) + "\tPaket yakalama ve analiz")
    print("11) Web Dashboard".rjust(19) + "\tTarayicida sonuc gorme")
    print("12) 5G Tarama".rjust(15) + "\t\t5G Core Network kesif")
    print("13) FW Bypass".rjust(15) + "\t\tSS7 Firewall bypass teknikleri")
    print("14) Telefon Kesif".rjust(19) + "\tBaz istasyonu tarama (USB telefon)")
    print("15) Web Tarayici".rjust(18) + "\tWeb sitesi guvenlik tarama")
    print("16) Spoofing Guard".rjust(19) + "\tSIP/SS7 spoofing tespit analizi")

    print()
    print("Cikmak icin quit yazin\n".rjust(28))

    choice = input("\033[34msig\033[0m\033[37m>\033[0m ").strip().lower()

    if choice == "0":
        os.system('cls' if os.name == 'nt' else 'clear')
        ss7main.attacksMenu()

    elif choice == "1":
        os.system('cls' if os.name == 'nt' else 'clear')
        gtpmain.prep()
    elif choice == "2":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7.attacks import diameter_module
            diameter_module.diameter_menu()
        except ImportError:
            print("\033[33m[!] Diameter module loading...\033[0m")
            ss7main.attacksMenu()
    elif choice == "3":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7.attacks.sip_module import sip_menu
            sip_menu()
        except ImportError as e:
            print(f"\033[33m[!] SIP module error: {e}\033[0m")
            time.sleep(2)
        mainMenu()
    elif choice == "4":
        try:
            import lan.scanner
            lan.scanner.main()
        except ImportError as e:
            print(f"[-] Error importing LAN module: {e}")
            time.sleep(2)
        except Exception as e:
             print(f"[-] Error: {e}")
             time.sleep(2)
        mainMenu()
    elif choice == "5":
        try:
            from turkey import scanner as turkey_scanner
            turkey_scanner.main()
        except ImportError as e:
            print(f"[-] Error importing Turkey module: {e}")
            print("[!] Lutfen turkey/scanner.py ve bagimliliklari kontrol edin.")
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[!] Turkey tarayici kullanici tarafindan durduruldu.")
            time.sleep(1)
        except Exception as e:
             print(f"[-] Error: {e}")
             time.sleep(2)
        mainMenu()
    elif choice == "6":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7 import multi_scan
            multi_scan.multi_scan_menu()
        except ImportError as e:
            print(f"[-] Module error: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "7":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            import quick_scan
            quick_scan.main()
        except ImportError as e:
            print(f"[-] Module error: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "8":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7.shodan_search import shodan_search_menu
            shodan_search_menu()
        except ImportError as e:
            print(f"[-] Shodan modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "9":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            import auto_chain
            auto_chain.chain_menu()
        except ImportError as e:
            print(f"[-] Auto chain modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "10":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7.pcap_analyzer import pcap_menu
            pcap_menu()
        except ImportError as e:
            print(f"[-] PCAP modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "11":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from web.dashboard import run_dashboard
            print("\n[+] Web Dashboard baslatiliyor...")
            print("[+] Tarayicidan http://localhost:5000 adresine gidin")
            print("[+] Durdurmak icin Ctrl+C\n")
            run_dashboard()
        except ImportError as e:
            print(f"[-] Dashboard hatasi: {e}")
            print("[*] Flask kurmak icin: pip install flask")
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n[+] Dashboard durduruldu.")
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "12":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7.attacks.fiveg_module import fiveg_menu
            fiveg_menu()
        except ImportError as e:
            print(f"[-] 5G modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "13":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from ss7.firewall_bypass import bypass_menu
            bypass_menu()
        except ImportError as e:
            print(f"[-] Firewall bypass modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "14":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from phone_recon import phone_menu
            phone_menu()
        except ImportError as e:
            print(f"[-] Telefon modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "15":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            from web_scanner import web_scan_menu
            web_scan_menu()
        except ImportError as e:
            print(f"[-] Web scanner modulu hatasi: {e}")
            print("[*] Gerekli: pip install requests")
            time.sleep(3)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "16":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            import spoofing_guard
            spoofing_guard.run_guard_menu()
        except ImportError as e:
            print(f"[-] Spoofing guard modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "17":
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            import system_check
            system_check.run_system_check()
        except ImportError as e:
            print(f"[-] Sistem kontrol modulu hatasi: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(2)
        mainMenu()
    elif choice == "quit" or choice == "exit" or choice == "cikis":
        print('\nSigPloit kapatiliyor...')
        time.sleep(1)
        sys.exit(0)
    else:
        print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0 - 17)')
        time.sleep(2)
        mainMenu()


def signal_handler(signal, frame):
    print()
    print('\nYou are now exiting SigPloit...')
    time.sleep(1)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    mainMenu()
