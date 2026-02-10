#!/usr/bin/env python
"""
SS7 DoS Module
Updated to use Python/Scapy implementation.
"""

import os
import sys
import time

import sigploit
import ss7main

def purge():
    """PurgeMS DoS Attack - Now uses Python/Scapy."""
    try:
        from ss7.attacks.dos import purge_scapy
        purge_scapy.purge_main()
        _dos_menu_return()
        
    except ImportError as e:
        print("\033[31m[-]Error:\033[0m Scapy script not found: %s" % str(e))
        time.sleep(2)
        ss7main.ss7dos()
    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7dos()

def _dos_menu_return():
    """Handle menu navigation after attack."""
    ds = input('\nWould you like to go back to DoS Menu? (y/n): ')
    if ds == 'y' or ds == 'yes':
        ss7main.ss7dos()
    elif ds == 'n' or ds == 'no':
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
