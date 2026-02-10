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

simsi_path = os.path.join(os.getcwd(), 'ss7/attacks/fraud/simsi')
mtsms_path = os.path.join(os.getcwd(), 'ss7/attacks/fraud/mtsms')
cl_path = os.path.join(os.getcwd(), 'ss7/attacks/fraud/cl')
isd_path = os.path.join(os.getcwd(),'ss7/attacks/fraud/isd')
sai_path = os.path.join(os.getcwd(),'ss7/attacks/fraud/sai')



def simsi():
    try:
        from ss7.attacks.fraud import simsi_scapy
        simsi_scapy.simsi_main()
        _fraud_menu_return()

    except ImportError as e:
        print("\033[31m[-]Error:\033[0m Scapy script not found: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()
    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()

def mtsms():
    try:
        from ss7.attacks.fraud import mtsms_scapy
        mtsms_scapy.mtsms_main()
        _fraud_menu_return()

    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()

def cl():
    try:
        from ss7.attacks.fraud import cl_scapy
        cl_scapy.cl_main()
        _fraud_menu_return()

    except ImportError as e:
        print("\033[31m[-]Error:\033[0m Scapy script not found: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()
    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()
        
def isd():
    try:
        from ss7.attacks.fraud import isd_scapy
        isd_scapy.isd_main()
        _fraud_menu_return()

    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()

def sai():
    try:
        from ss7.attacks.fraud import sai_scapy
        sai_scapy.sai_main()
        _fraud_menu_return()

    except Exception as e:
        print("\033[31m[-]Error:\033[0m An error occurred: %s" % str(e))
        time.sleep(2)
        ss7main.ss7fraud()

def _fraud_menu_return():
    fr = input('\nWould you like to go back to Fraud Menu? (y/n): ')
    if fr == 'y' or fr == 'yes':
        ss7main.ss7fraud()
    elif fr == 'n' or fr == 'no':
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