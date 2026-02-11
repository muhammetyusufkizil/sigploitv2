#!/usr/bin/env python3
'''
GTP Main - GTP Protocol Attack Framework

Created on 18 June 2018

@author: loay
@license: MIT license
'''
import os
import time
import sys

try:
    import gtp.info
    import gtp.fraud
except ImportError as e:
    print(f"[!] GTP modulleri yuklenemedi: {e}")
    gtp = None

try:
    from gtp.gtp_v2_core.utilities.configuration_parser import parseConfigs
except ImportError:
    parseConfigs = None

config_file= ''
remote_net =''
listening = True
verbosity = 2
output_file ='results.csv'

def gtpinfo():
    """GTP Bilgi Toplama alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(" \033[31mBilgi Toplama (Information Gathering)\033[0m ".center(105, "#"))
        print(" \033[34mBir saldiri secin\033[0m ".center(105, "#"))
        print()
        print("   Saldiri".rjust(10) + "\t\t\t\tAciklama")
        print("   --------                             ------------")
        print("0) GTP Nodes Discovery".rjust(25) + "\t\tEchoRequest/CreateSession ile NE kesfi")
        print("1) TEID Allocation Discovery".rjust(31) + "\t\tCreateSession/ModifyBearer ile TEID kesfi")
        print("2) TEID Predictability Index".rjust(31) + "\t\tTEID dizileri tahmin edilebilirlik analizi")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input("\033[37m(\033[0m\033[2;31minfo\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return
        elif choice == "0":
            try:
                gtp.info.nediscover()
            except Exception as e:
                print(f"\033[31m[-] Hata: {e}\033[0m")
                time.sleep(2)
        elif choice == "1":
            try:
                gtp.info.teidiscover()
            except Exception as e:
                print(f"\033[31m[-] Hata: {e}\033[0m")
                time.sleep(2)
        elif choice == "2":
            try:
                gtp.info.teidpredict()
            except Exception as e:
                print(f"\033[31m[-] Hata: {e}\033[0m")
                time.sleep(2)
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-2)')
            time.sleep(1.5)


def gtpfraud():
    """GTP Dolandırıcılık alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(" \033[31mDolandiricilik (Fraud)\033[0m ".center(105, "#"))
        print(" \033[34mBir saldiri secin\033[0m ".center(105, "#"))
        print()
        print("   Saldiri".rjust(10) + "\t\t\t\tAciklama")
        print("   --------                             ------------")
        print("0) Tunnel Hijack".rjust(19) + "\t\tTEID Hijack - ModifyBearerRequest ile tunel ele gecirme")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input("\033[37m(\033[0m\033[2;31mfraud\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return
        elif choice == "0":
            try:
                gtp.fraud.thijack()
            except Exception as e:
                print(f"\033[31m[-] Hata: {e}\033[0m")
                time.sleep(2)
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0)')
            time.sleep(1.5)


def gtpdos():
    """GTP DoS alt menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(" \033[31mDoS (Servis Engelleme)\033[0m ".center(105, "#"))
        print(" \033[34mBir saldiri secin\033[0m ".center(105, "#"))
        print()
        print("   Saldiri".rjust(10) + "\t\t\t\tAciklama")
        print("   --------                             ------------")
        print("0) Massive DoS".rjust(17) + "\t\t\tDeleteSession/CreateSession ile toplu flood")
        print("1) User DoS".rjust(14) + "\t\t\t\tBelirli kullanicinin GTP tunelini hedefle")

        print()
        print("Geri donmek icin back yazin".rjust(30))

        choice = input("\033[37m(\033[0m\033[2;31mdos\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return
        elif choice == "0":
            try:
                from gtp.attacks.dos.massive_dos import main as massive_main
                massive_main()
            except Exception as e:
                print(f"\033[31m[-] Hata: {e}\033[0m")
                time.sleep(2)
        elif choice == "1":
            try:
                from gtp.attacks.dos.user_dos import main as user_main
                user_main()
            except Exception as e:
                print(f"\033[31m[-] Hata: {e}\033[0m")
                time.sleep(2)
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-1)')
            time.sleep(1.5)


def gtpattacksv2():
    """GTP v2 saldırı kategorisi menüsü."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        print(" \033[34mGTP Saldiri Kategorisi Secin\033[0m ".center(105, "#"))
        print()
        print("0) Bilgi Toplama (Information Gathering)".rjust(43))
        print("1) Dolandiricilik (Fraud)".rjust(27))
        print("2) DoS (Servis Engelleme)".rjust(28))
        print()
        print("Ana menuye donmek icin back yazin".rjust(36))
        print()

        choice = input(
            "\033[37m(\033[0m\033[2;31mattacks\033[0m\033[37m)>\033[0m ").strip().lower()

        if choice == "back":
            return  # mainMenu döngüsüne geri dön
        elif choice == "0":
            gtpinfo()
        elif choice == "1":
            gtpfraud()
        elif choice == "2":
            gtpdos()
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-2)')
            time.sleep(1.5)

def showOptions(config_file='', remote_net='', listening=True, verbosity=2, output_file='results.csv'):

    print('\n     Option                    \t\t\t\t\tValue')
    print('     --------                                                   ------')
    print('     \033[34mconfig\033[0m     {:<15s} \t\t\t\033[31m{}\033[0m'.format('path to configuration file', config_file))
    print('     \033[34mtarget\033[0m     {:<15s} \t\033[31m{}\033[0m'.format('example: 10.10.10.1/32 or 10.10.10.0/24', remote_net))
    print('     \033[34mlistening\033[0m  {:<15s} \t\033[31m{}\033[0m'.format('accepting replies from target, default: True', listening))
    print('     \033[34mverbosity\033[0m  {:<15s} \t\t\t\033[31m{}\033[0m '.format('verbosity level, default: 2', verbosity))
    print('     \033[34moutput\033[0m     {:<15s} \t\t\033[31m{}\033[0m\n '.format('output file, default: result.csv', output_file))
   

def helpmenu():

    print('\n     Command                      Description')
    print('     ---------                   ------------')
    print('     \033[34mshow options\033[0m                display required options to run attack')
    print('     \033[34mset\033[0m                         set a value for an option')
    print("     \033[34mrun\033[0m                         run the exploit")
    print("     \033[34mhelp\033[0m                        display this menu")
    print("     \033[34mback\033[0m                        back to GTP attacks")
    print("     \033[34mexit\033[0m                        exit SigPloit\n")
  

def prep():
    """GTP protokol sürümü seçim menüsü."""
    while True:
        print()
        print("   Modul".rjust(10) + "\t\tAciklama")
        print("   --------             ------------")
        print("0) GTPv1".rjust(8) + "\t\t3G Veri saldirilari")
        print("1) GTPv2".rjust(8) + "\t\t4G Veri saldirilari")
        print()
        print("Ana menuye donmek icin back yazin".rjust(36))

        choice = input("\033[34mgtp\033[0m\033[37m>\033[0m ").strip().lower()

        if choice == "back":
            return  # mainMenu döngüsüne geri dön
        elif choice == "0":
            print("\n\033[34m[*]\033[0m GTPv1 surum 2.1'de guncellenecektir...")
            print("\033[34m[*]\033[0m GTP menusune donuluyor")
            time.sleep(2)
            os.system('cls' if os.name == 'nt' else 'clear')
        elif choice == "1":
            gtpattacksv2()
        else:
            print('\n\033[31m[-]Hata:\033[0m Gecerli bir secim yapin (0-1)')
            time.sleep(1.5)
