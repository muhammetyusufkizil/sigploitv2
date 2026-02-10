import socket
import os
import time
from scapy.all import ARP, Ether, srp, conf

# Suppress Scapy warnings
conf.verb = 0

def get_local_ip_range():
    try:
        # Detect local IP by connecting to a public DNS (doesn't send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume /24 subnet
        ip_parts = local_ip.split('.')
        base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24"
        
        print(f"[!] Detected Local IP: {local_ip}")
        print(f"[!] Suggested Range: {base_ip}")
        
        user_input = input(f"Enter Network Range or Enter for [{base_ip}]: ")
        return user_input or base_ip
    except Exception as e:
        print(f"[-] Could not detect IP: {e}")
        return input("Enter Network Range (e.g. 192.168.1.1/24): ") or "192.168.1.1/24"

def access_points_scan():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(" \033[31mLocal Network Scanner\033[0m ".center(105, "#"))
    print("\n[+] Identifying connected devices via ARP...")
    
    target_ip = get_local_ip_range()
    
    print(f"\n[+] Scanning {target_ip} ... Please wait.")
    print(f"[+] Using Interface: {conf.iface.name}")
    
    # Warning for Hotspot Users
    if target_ip.startswith("10.") or target_ip.startswith("172."):
        print("\n\033[33m[!] WARNING: You seem to be using a Hotspot/Tethering network.\033[0m")
        print("\033[33m    If connected via USB Cable, you might NOT see devices on Wi-Fi.\033[0m")
        print("\033[33m    To see Wi-Fi devices, connect your PC to the phone's Wi-Fi hotspot instead.\033[0m")
    
    try:
        # Create ARP packet
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send and wait for response
        result = srp(packet, timeout=3, verbose=0)[0]
        
        # Parse results
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        # Display
        print("\n" + "="*50)
        print("IP Address".ljust(20) + "MAC Address")
        print("="*50)
        
        if not devices:
            print("[-] No devices found. Check your network range or firewall.")
        
        for device in devices:
            print(f"{device['ip'].ljust(20)}{device['mac']}")
            
        print("="*50)
        print(f"[+] Total Devices Found: {len(devices)}")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        
    input("\nPress Enter to return...")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(" \033[31mLocal Network Tools\033[0m ".center(105, "#"))
        print("\n   Action".rjust(10) + "\t\tDescription")
        print("   --------                    ------------")
        print("0) ARP Scanner".rjust(18) + "\t\tList all devices on Wi-Fi/LAN")
        print("\n   or type back to return to Main Menu")
        
        choice = input("\n\033[34mlan\033[0m\033[37m>\033[0m ")
        
        if choice == "0":
            access_points_scan()
        elif choice == "back" or choice == "quit" or choice == "exit":
            return
        else:
            print("[-] Invalid Choice")
            time.sleep(1)

if __name__ == "__main__":
    main()
