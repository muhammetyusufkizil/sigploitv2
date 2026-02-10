#!/usr/bin/env python

"""
Created on 1 Feb 2018

@author: loay
"""

import os
import sys
import time
from subprocess import *

import sigploit
import ss7main

ul_path = os.path.join(os.getcwd(), 'ss7/attacks/interception/ul')


def ul():
    try:
        from ss7.attacks.interception import ul_scapy
        ul_scapy.ul_main()

        interception_menu = input('\nWould you like to go back to Interception Menu? (y/n): ')
        if interception_menu == 'y' or interception_menu == 'yes':
            ss7main.ss7interception()
        elif interception_menu == 'n' or interception_menu == 'no':
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
        ss7main.ss7interception()
    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7interception()
