#!/usr/bin/env python

"""
Created on 1 Feb 2018

@author: loay
"""

import os
import sys
import time

import sigploit
import ss7main

sri_path = os.path.join(os.getcwd(), 'ss7/attacks/tracking/sri')
srism_path = os.path.join(os.getcwd(), 'ss7/attacks/tracking/srism')
psi_path = os.path.join(os.getcwd(), 'ss7/attacks/tracking/psi')
ati_path = os.path.join(os.getcwd(), 'ss7/attacks/tracking/ati')
srigprs_path = os.path.join(os.getcwd(), 'ss7/attacks/tracking/srigprs')


def sri():
    try:
        # New Python/Scapy Implementation
        from ss7.attacks.tracking import sri_scapy
        sri_scapy.sri_main()
        
        # Navigation logic
        lt = input('\nWould you like to go back to LocationTracking Menu? (y/n): ')
        if lt == 'y' or lt == 'yes':
            ss7main.ss7tracking()
        elif lt == 'n' or lt == 'no':
            attack_menu = input('Would you like to choose another attacks category? (y/n): ')
            if attack_menu == 'y' or attack_menu == 'yes':
                ss7main.attacksMenu()
            elif attack_menu == 'n' or attack_menu == 'no':
                main_menu = input('Would you like to go back to the main menu? (y/exit): ')
                if main_menu == 'y' or main_menu == 'yes':
                    sigploit.mainMenu()
                elif main_menu == 'exit':
                    print('TCAP End...')
                    sys.exit(0)

    except ImportError as e:
        print("\033[31m[-]Error:\033[0m Scapy script not found or dependencies missing: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()
    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()



def psi():
    try:
        from ss7.attacks.tracking import psi_scapy
        psi_scapy.psi_main()

        lt = input('\nWould you like to go back to LocationTracking Menu? (y/n): ')
        if lt == 'y' or lt == 'yes':
            ss7main.ss7tracking()
        elif lt == 'n' or lt == 'no':
            attack_menu = input('Would you like to choose another attacks category? (y/n): ')
            if attack_menu == 'y' or attack_menu == 'yes':
                ss7main.attacksMenu()
            elif attack_menu == 'n' or attack_menu == 'no':
                main_menu = input('Would you like to go back to the main menu? (y/exit): ')
                if main_menu == 'y' or main_menu == 'yes':
                    sigploit.mainMenu()
                elif main_menu == 'exit':
                    print('TCAP End...')
                    sys.exit(0)

    except ImportError as e:
        print("\033[31m[-]Error:\033[0m Scapy script not found or dependencies missing: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()
    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()


def srism():
    try:
        from ss7.attacks.tracking import srism_scapy
        srism_scapy.srism_main()

        lt = input('\nWould you like to go back to LocationTracking Menu? (y/n): ')
        if lt == 'y' or lt == 'yes':
            ss7main.ss7tracking()
        elif lt == 'n' or lt == 'no':
            attack_menu = input('Would you like to choose another attacks category? (y/n): ')
            if attack_menu == 'y' or attack_menu == 'yes':
                ss7main.attacksMenu()
            elif attack_menu == 'n' or attack_menu == 'no':
                main_menu = input('Would you like to go back to the main menu? (y/exit): ')
                if main_menu == 'y' or main_menu == 'yes':
                    sigploit.mainMenu()
                elif main_menu == 'exit':
                    print('TCAP End...')
                    sys.exit(0)

    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()


def ati():
    try:
        from ss7.attacks.tracking import ati_scapy
        ati_scapy.ati_main()

        lt = input('\nWould you like to go back to LocationTracking Menu? (y/n): ')
        if lt == 'y' or lt == 'yes':
            ss7main.ss7tracking()
        elif lt == 'n' or lt == 'no':
            attack_menu = input('Would you like to choose another attacks category? (y/n): ')
            if attack_menu == 'y' or attack_menu == 'yes':
                ss7main.attacksMenu()
            elif attack_menu == 'n' or attack_menu == 'no':
                main_menu = input('Would you like to go back to the main menu? (y/exit): ')
                if main_menu == 'y' or main_menu == 'yes':
                    sigploit.mainMenu()
                elif main_menu == 'exit':
                    print('TCAP End...')
                    sys.exit(0)

    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()


def srigprs():
    try:
        from ss7.attacks.tracking import srigprs_scapy
        srigprs_scapy.srigprs_main()

        lt = input('\nWould you like to go back to LocationTracking Menu? (y/n): ')
        if lt == 'y' or lt == 'yes':
            ss7main.ss7tracking()
        elif lt == 'n' or lt == 'no':
            attack_menu = input('Would you like to choose another attacks category? (y/n): ')
            if attack_menu == 'y' or attack_menu == 'yes':
                ss7main.attacksMenu()
            elif attack_menu == 'n' or attack_menu == 'no':
                main_menu = input('Would you like to go back to the main menu? (y/exit): ')
                if main_menu == 'y' or main_menu == 'yes':
                    sigploit.mainMenu()
                elif main_menu == 'exit':
                    print('TCAP End...')
                    sys.exit(0)

    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7tracking()
