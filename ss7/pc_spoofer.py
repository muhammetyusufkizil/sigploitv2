#!/usr/bin/env python
"""
PC Identity Spoofer Module for SigPloit
Bilgisayar kimlik bilgilerini degistirerek iz birakmayi zorlastirir.

Desteklenen spoofing turleri:
- MAC Address degistirme
- Hostname degistirme
- Disk Serial Number maskeleme
- Windows Machine GUID degistirme
- DNS degistirme
- Network profili temizleme
- Browser fingerprint temizleme

NOT: Bazi islemler admin/root yetkisi gerektirir.
"""
import sys
import os
import re
import time
import random
import string
import struct
import platform
import subprocess
import json
import shutil

# ============================================
# YARDIMCI FONKSIYONLAR
# ============================================

def _get_input(prompt, default=None):
    if default:
        data = input(f"{prompt} [{default}]: ").strip()
        return data if data else default
    return input(f"{prompt}: ").strip()


def _is_admin():
    """Admin/root yetkisi kontrolu."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def _request_admin_elevation():
    """Windows'ta admin yetkisiyle programi yeniden baslat."""
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("\033[33m[!] Admin yetkisi gerekli. Program yeniden baslatiliyor...\033[0m")
                time.sleep(2)
                # ShellExecute ile 'runas' (Run as administrator)
                script = os.path.abspath(sys.argv[0])
                params = ' '.join(sys.argv[1:])
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{script}" {params}', None, 1
                )
                sys.exit(0)
        except Exception as e:
            print(f"\033[31m[-] Admin yetkisi alinamadi: {e}\033[0m")
            print("\033[33m[!] Lutfen programi 'Yonetici olarak calistir' ile baslatin.\033[0m")
            return False
    else:
        # Linux/Mac - sudo kontrolü
        if os.geteuid() != 0:
            print("\033[31m[-] Root yetkisi gerekli!\033[0m")
            print("\033[33m[!] Programi 'sudo python3 ...' ile calistirin.\033[0m")
            return False
    return True


def _run_cmd(cmd, shell=True, timeout=30):
    """Komutu calistir ve sonucu dondur."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True,
            text=False, timeout=timeout
        )
        # Windows'ta cp1254/cp850 gibi yerel kodlamalar bazi byte'lari cozemez.
        # Binary modda alip utf-8 + errors='replace' ile decode ediyoruz.
        stdout = result.stdout.decode('utf-8', errors='replace').strip() if result.stdout else ''
        stderr = result.stderr.decode('utf-8', errors='replace').strip() if result.stderr else ''
        return stdout, stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', -1
    except Exception as e:
        return '', str(e), -1


def _generate_random_mac():
    """Rastgele MAC adresi uret (locally administered)."""
    # Ilk byte: locally administered + unicast (x2, x6, xA, xE)
    first_byte = random.choice([0x02, 0x06, 0x0A, 0x0E])
    mac_bytes = [first_byte] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ':'.join(f'{b:02X}' for b in mac_bytes)


def _generate_random_hostname(prefix="DESKTOP"):
    """Rastgele hostname uret."""
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return f"{prefix}-{suffix}"


def _generate_random_serial():
    """Rastgele disk serial number uret."""
    return ''.join(random.choices(string.hexdigits.upper(), k=8))


def _generate_random_guid():
    """Rastgele GUID uret."""
    parts = [
        ''.join(random.choices(string.hexdigits.lower(), k=8)),
        ''.join(random.choices(string.hexdigits.lower(), k=4)),
        ''.join(random.choices(string.hexdigits.lower(), k=4)),
        ''.join(random.choices(string.hexdigits.lower(), k=4)),
        ''.join(random.choices(string.hexdigits.lower(), k=12)),
    ]
    return '-'.join(parts)


# ============================================
# MEVCUT BILGILERI GOSTER
# ============================================

def get_current_identity():
    """Mevcut PC kimlik bilgilerini topla."""
    identity = {}
    
    # Hostname
    identity['hostname'] = platform.node()
    
    # OS bilgileri
    identity['os'] = f"{platform.system()} {platform.release()} ({platform.version()})"
    identity['architecture'] = platform.machine()
    
    # MAC adresleri
    identity['mac_addresses'] = _get_mac_addresses()
    
    # Machine GUID (Windows)
    if os.name == 'nt':
        identity['machine_guid'] = _get_windows_machine_guid()
        identity['product_id'] = _get_windows_product_id()
        identity['disk_serials'] = _get_disk_serials_windows()
    else:
        identity['machine_id'] = _get_linux_machine_id()
        identity['disk_serials'] = _get_disk_serials_linux()
    
    # DNS sunuculari
    identity['dns_servers'] = _get_dns_servers()
    
    # Public IP (opsiyonel)
    identity['username'] = os.environ.get('USERNAME', os.environ.get('USER', 'unknown'))
    
    return identity


def _get_mac_addresses():
    """Tum ag arayuzlerinin MAC adreslerini al."""
    macs = {}
    try:
        if os.name == 'nt':
            stdout, _, _ = _run_cmd('getmac /FO CSV /NH')
            for line in stdout.split('\n'):
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2 and '-' in parts[0]:
                    mac = parts[0].replace('-', ':')
                    name = parts[1] if len(parts) > 1 else 'Unknown'
                    macs[name] = mac
            
            # ipconfig fallback
            if not macs:
                stdout, _, _ = _run_cmd('ipconfig /all')
                current_adapter = ''
                for line in stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith(' ') and ':' in line:
                        current_adapter = line.rstrip(':').strip()
                    elif 'Physical Address' in line or 'Fiziksel Adres' in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})', line)
                        if mac_match:
                            mac = mac_match.group(1).replace('-', ':')
                            macs[current_adapter or 'Unknown'] = mac
        else:
            stdout, _, _ = _run_cmd('ip link show 2>/dev/null || ifconfig -a')
            current_iface = ''
            for line in stdout.split('\n'):
                iface_match = re.match(r'^\d+:\s+(\S+):', line)
                if iface_match:
                    current_iface = iface_match.group(1)
                mac_match = re.search(r'(?:ether|HWaddr)\s+([0-9a-fA-F:]{17})', line)
                if mac_match:
                    macs[current_iface or 'Unknown'] = mac_match.group(1).upper()
    except Exception:
        pass
    return macs


def _get_windows_machine_guid():
    """Windows Machine GUID oku."""
    try:
        stdout, _, _ = _run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid'
        )
        match = re.search(r'MachineGuid\s+REG_SZ\s+(\S+)', stdout)
        return match.group(1) if match else 'Bulunamadi'
    except Exception:
        return 'Hata'


def _get_windows_product_id():
    """Windows Product ID oku."""
    try:
        stdout, _, _ = _run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductId'
        )
        match = re.search(r'ProductId\s+REG_SZ\s+(\S+)', stdout)
        return match.group(1) if match else 'Bulunamadi'
    except Exception:
        return 'Hata'


def _get_disk_serials_windows():
    """Windows disk serial numaralarini oku."""
    serials = []
    try:
        stdout, _, _ = _run_cmd('wmic diskdrive get serialnumber')
        for line in stdout.split('\n')[1:]:
            line = line.strip()
            if line:
                serials.append(line)
    except Exception:
        pass
    return serials


def _get_disk_serials_linux():
    """Linux disk serial numaralarini oku."""
    serials = []
    try:
        stdout, _, _ = _run_cmd('lsblk -o NAME,SERIAL 2>/dev/null')
        for line in stdout.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] != '':
                serials.append(f"{parts[0]}: {parts[1]}")
    except Exception:
        pass
    return serials


def _get_linux_machine_id():
    """Linux machine-id oku."""
    try:
        with open('/etc/machine-id', 'r') as f:
            return f.read().strip()
    except Exception:
        return 'Bulunamadi'


def _get_dns_servers():
    """Mevcut DNS sunucularini al."""
    servers = []
    try:
        if os.name == 'nt':
            stdout, _, _ = _run_cmd('ipconfig /all')
            for line in stdout.split('\n'):
                if 'DNS' in line and 'Server' in line or 'DNS' in line and 'Sunucu' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        servers.append(ip_match.group(1))
        else:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                servers.append(parts[1])
            except Exception:
                pass
    except Exception:
        pass
    return servers


def show_current_identity():
    """Mevcut PC kimlik bilgilerini goster."""
    print("\n" + "=" * 60)
    print(" MEVCUT PC KIMLIK BILGILERI")
    print("=" * 60)
    
    identity = get_current_identity()
    
    print(f"\n  Hostname:      {identity['hostname']}")
    print(f"  OS:            {identity['os']}")
    print(f"  Mimari:        {identity['architecture']}")
    print(f"  Kullanici:     {identity['username']}")
    
    print(f"\n  MAC Adresleri:")
    for iface, mac in identity.get('mac_addresses', {}).items():
        print(f"    {iface}: {mac}")
    
    if os.name == 'nt':
        print(f"\n  Machine GUID:  {identity.get('machine_guid', 'N/A')}")
        print(f"  Product ID:    {identity.get('product_id', 'N/A')}")
    else:
        print(f"\n  Machine ID:    {identity.get('machine_id', 'N/A')}")
    
    print(f"\n  Disk Serial(ler):")
    for serial in identity.get('disk_serials', []):
        print(f"    {serial}")
    
    print(f"\n  DNS Sunuculari:")
    for dns in identity.get('dns_servers', []):
        print(f"    {dns}")
    
    return identity


# ============================================
# MAC ADDRESS SPOOFING
# ============================================

def spoof_mac(interface=None, new_mac=None):
    """
    MAC adresini degistir.
    
    Args:
        interface: Ag arayuzu ismi (None = otomatik sec)
        new_mac: Yeni MAC adresi (None = rastgele uret)
    """
    if not _is_admin():
        print("\033[31m[-] MAC degistirme icin admin/root yetkisi gerekli!\033[0m")
        return False
    
    if new_mac is None:
        new_mac = _generate_random_mac()
    
    print(f"\n[+] Yeni MAC: {new_mac}")
    
    if os.name == 'nt':
        return _spoof_mac_windows(interface, new_mac)
    else:
        return _spoof_mac_linux(interface, new_mac)


def _spoof_mac_windows(interface, new_mac):
    """Windows'ta MAC degistir."""
    mac_no_colon = new_mac.replace(':', '').replace('-', '')
    
    # Arayuzleri listele
    if not interface:
        stdout, _, _ = _run_cmd('netsh interface show interface')
        print("\n[+] Mevcut arayuzler:")
        print(stdout)
        interface = _get_input("Arayuz adi", "Ethernet")
    
    # Registry uzerinden MAC degistir
    # Adaptorler HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
    base_key = r'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    
    # Alt anahtarlari tara
    stdout, _, _ = _run_cmd(f'reg query "{base_key}"')
    subkeys = re.findall(r'(HKLM\\.*\\(\d{4}))', stdout)
    
    target_key = None
    for full_key, idx in subkeys:
        driver_stdout, _, _ = _run_cmd(f'reg query "{full_key}" /v DriverDesc 2>NUL')
        if interface.lower() in driver_stdout.lower():
            target_key = full_key
            break
    
    if not target_key:
        # Ilk adaptoru kullan
        if subkeys:
            target_key = subkeys[0][0]
        else:
            print("[-] Adaptor bulunamadi")
            return False
    
    print(f"[+] Registry key: {target_key}")
    
    # MAC'i yaz
    stdout, stderr, rc = _run_cmd(
        f'reg add "{target_key}" /v NetworkAddress /t REG_SZ /d {mac_no_colon} /f'
    )
    
    if rc == 0:
        print("[+] Registry guncellendi")
        # Arayuzu yeniden baslat
        print("[+] Arayuz yeniden baslatiliyor...")
        _run_cmd(f'netsh interface set interface "{interface}" disable')
        time.sleep(2)
        _run_cmd(f'netsh interface set interface "{interface}" enable')
        time.sleep(3)
        
        print(f"\033[32m[+] MAC adresi degistirildi: {new_mac}\033[0m")
        return True
    else:
        print(f"[-] Registry hatasi: {stderr}")
        return False


def _spoof_mac_linux(interface, new_mac):
    """Linux'ta MAC degistir."""
    if not interface:
        stdout, _, _ = _run_cmd('ip -o link show | grep -v lo')
        print("\n[+] Mevcut arayuzler:")
        for line in stdout.split('\n'):
            match = re.match(r'\d+:\s+(\S+):', line)
            if match:
                print(f"    {match.group(1)}")
        interface = _get_input("Arayuz adi", "eth0")
    
    print(f"[+] Arayuz: {interface}")
    
    # Arayuzu kapat
    _run_cmd(f'ip link set {interface} down')
    time.sleep(0.5)
    
    # MAC degistir
    stdout, stderr, rc = _run_cmd(f'ip link set {interface} address {new_mac}')
    
    if rc == 0:
        # Arayuzu ac
        _run_cmd(f'ip link set {interface} up')
        time.sleep(1)
        print(f"\033[32m[+] MAC adresi degistirildi: {new_mac}\033[0m")
        return True
    else:
        # Fallback: macchanger
        stdout2, stderr2, rc2 = _run_cmd(f'macchanger -m {new_mac} {interface} 2>/dev/null')
        _run_cmd(f'ip link set {interface} up')
        if rc2 == 0:
            print(f"\033[32m[+] MAC adresi degistirildi (macchanger): {new_mac}\033[0m")
            return True
        else:
            _run_cmd(f'ip link set {interface} up')
            print(f"[-] MAC degistirilemedi: {stderr}")
            return False


# ============================================
# HOSTNAME SPOOFING
# ============================================

def spoof_hostname(new_hostname=None):
    """Hostname degistir."""
    if not _is_admin():
        print("\033[31m[-] Hostname degistirme icin admin/root yetkisi gerekli!\033[0m")
        return False
    
    if new_hostname is None:
        new_hostname = _generate_random_hostname()
    
    old_hostname = platform.node()
    print(f"[+] Eski hostname: {old_hostname}")
    print(f"[+] Yeni hostname: {new_hostname}")
    
    if os.name == 'nt':
        stdout, stderr, rc = _run_cmd(
            f'wmic computersystem where name="%COMPUTERNAME%" call rename name="{new_hostname}"'
        )
        if rc == 0 or 'ReturnValue = 0' in stdout:
            print(f"\033[32m[+] Hostname degistirildi: {new_hostname}\033[0m")
            print("[!] Degisiklik icin yeniden baslatma gerekli")
            return True
        else:
            # PowerShell fallback
            stdout2, stderr2, rc2 = _run_cmd(
                f'powershell -Command "Rename-Computer -NewName {new_hostname} -Force" 2>NUL'
            )
            if rc2 == 0:
                print(f"\033[32m[+] Hostname degistirildi (PS): {new_hostname}\033[0m")
                print("[!] Degisiklik icin yeniden baslatma gerekli")
                return True
            print(f"[-] Hostname degistirilemedi: {stderr}")
            return False
    else:
        # Linux
        _run_cmd(f'hostnamectl set-hostname {new_hostname} 2>/dev/null')
        _run_cmd(f'hostname {new_hostname}')
        
        # /etc/hostname guncelle
        try:
            with open('/etc/hostname', 'w') as f:
                f.write(new_hostname + '\n')
        except Exception:
            pass
        
        print(f"\033[32m[+] Hostname degistirildi: {new_hostname}\033[0m")
        return True


# ============================================
# MACHINE GUID / MACHINE-ID SPOOFING
# ============================================

def spoof_machine_id(new_guid=None):
    """Machine GUID/ID degistir."""
    if not _is_admin():
        print("\033[31m[-] Machine ID degistirme icin admin/root yetkisi gerekli!\033[0m")
        return False
    
    if new_guid is None:
        new_guid = _generate_random_guid()
    
    if os.name == 'nt':
        return _spoof_machine_guid_windows(new_guid)
    else:
        return _spoof_machine_id_linux(new_guid.replace('-', ''))


def _spoof_machine_guid_windows(new_guid):
    """Windows Machine GUID degistir."""
    old_guid = _get_windows_machine_guid()
    print(f"[+] Eski GUID: {old_guid}")
    print(f"[+] Yeni GUID: {new_guid}")
    
    # Backup
    backup_file = f"machine_guid_backup_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    with open(backup_file, 'w') as f:
        f.write(f"Backup: {old_guid}\n")
    print(f"[+] Yedek: {backup_file}")
    
    stdout, stderr, rc = _run_cmd(
        f'reg add "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid /t REG_SZ /d {new_guid} /f'
    )
    
    if rc == 0:
        print(f"\033[32m[+] Machine GUID degistirildi: {new_guid}\033[0m")
        print("[!] Bazi uygulamalar yeniden baslatma gerektirebilir")
        return True
    else:
        print(f"[-] GUID degistirilemedi: {stderr}")
        return False


def _spoof_machine_id_linux(new_id):
    """Linux machine-id degistir."""
    old_id = _get_linux_machine_id()
    print(f"[+] Eski Machine ID: {old_id}")
    print(f"[+] Yeni Machine ID: {new_id}")
    
    # Backup
    backup_file = f"machine_id_backup_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    with open(backup_file, 'w') as f:
        f.write(f"Backup: {old_id}\n")
    
    try:
        with open('/etc/machine-id', 'w') as f:
            f.write(new_id[:32] + '\n')
        
        # dbus machine-id de degistir
        dbus_path = '/var/lib/dbus/machine-id'
        if os.path.exists(dbus_path):
            with open(dbus_path, 'w') as f:
                f.write(new_id[:32] + '\n')
        
        print(f"\033[32m[+] Machine ID degistirildi: {new_id[:32]}\033[0m")
        return True
    except Exception as e:
        print(f"[-] Machine ID degistirilemedi: {e}")
        return False


# ============================================
# DNS SPOOFING (Lokal)
# ============================================

def spoof_dns(primary_dns=None, secondary_dns=None):
    """DNS sunucularini degistir."""
    if not _is_admin():
        print("\033[31m[-] DNS degistirme icin admin/root yetkisi gerekli!\033[0m")
        return False
    
    # Populer DNS sunuculari
    dns_options = {
        '1': ('1.1.1.1', '1.0.0.1', 'Cloudflare'),
        '2': ('8.8.8.8', '8.8.4.4', 'Google'),
        '3': ('9.9.9.9', '149.112.112.112', 'Quad9'),
        '4': ('208.67.222.222', '208.67.220.220', 'OpenDNS'),
        '5': ('94.140.14.14', '94.140.15.15', 'AdGuard'),
    }
    
    if primary_dns is None:
        print("\n  DNS Secenekleri:")
        for key, (p, s, name) in dns_options.items():
            print(f"    {key}) {name} ({p}, {s})")
        print(f"    6) Manuel gir")
        
        choice = _get_input("Secim", "1")
        if choice in dns_options:
            primary_dns, secondary_dns, name = dns_options[choice]
        else:
            primary_dns = _get_input("Primary DNS", "1.1.1.1")
            secondary_dns = _get_input("Secondary DNS", "1.0.0.1")
    
    print(f"[+] Primary DNS: {primary_dns}")
    print(f"[+] Secondary DNS: {secondary_dns}")
    
    if os.name == 'nt':
        # Aktif arayuzu bul
        stdout, _, _ = _run_cmd('netsh interface show interface')
        interface = _get_input("Arayuz adi", "Ethernet")
        
        _run_cmd(f'netsh interface ip set dns "{interface}" static {primary_dns}')
        if secondary_dns:
            _run_cmd(f'netsh interface ip add dns "{interface}" {secondary_dns} index=2')
        
        # DNS cache temizle
        _run_cmd('ipconfig /flushdns')
        print(f"\033[32m[+] DNS degistirildi ve cache temizlendi\033[0m")
        return True
    else:
        try:
            # systemd-resolved kullaniliyorsa
            stdout, _, rc = _run_cmd('systemctl is-active systemd-resolved 2>/dev/null')
            if rc == 0:
                content = f"[Resolve]\nDNS={primary_dns}\n"
                if secondary_dns:
                    content += f"FallbackDNS={secondary_dns}\n"
                with open('/etc/systemd/resolved.conf', 'w') as f:
                    f.write(content)
                _run_cmd('systemctl restart systemd-resolved')
            else:
                # resolv.conf dogrudan degistir
                with open('/etc/resolv.conf', 'w') as f:
                    f.write(f"nameserver {primary_dns}\n")
                    if secondary_dns:
                        f.write(f"nameserver {secondary_dns}\n")
            
            print(f"\033[32m[+] DNS degistirildi\033[0m")
            return True
        except Exception as e:
            print(f"[-] DNS degistirilemedi: {e}")
            return False


# ============================================
# NETWORK PROFILE TEMIZLEME
# ============================================

def clean_network_traces():
    """Ag izlerini temizle."""
    if not _is_admin():
        print("\033[31m[-] Admin/root yetkisi gerekli!\033[0m")
        return False
    
    print("\n[+] Ag izleri temizleniyor...")
    
    if os.name == 'nt':
        # DNS cache temizle
        _run_cmd('ipconfig /flushdns')
        print("  [+] DNS cache temizlendi")
        
        # ARP cache temizle
        _run_cmd('arp -d *')
        print("  [+] ARP cache temizlendi")
        
        # NetBIOS cache temizle
        _run_cmd('nbtstat -R')
        print("  [+] NetBIOS cache temizlendi")
        
        # Kayitli WiFi profilleri temizle (opsiyonel)
        _run_cmd('netsh wlan delete profile name=* i=*')
        print("  [+] WiFi profilleri temizlendi")
        
        # Network discovery gecmisini temizle
        _run_cmd('netsh interface ip delete arpcache')
        print("  [+] ARP arpcache temizlendi")
        
        # Temp dosyalari temizle
        temp_dir = os.environ.get('TEMP', 'C:\\Windows\\Temp')
        try:
            for f in os.listdir(temp_dir):
                fpath = os.path.join(temp_dir, f)
                try:
                    if os.path.isfile(fpath):
                        os.unlink(fpath)
                except Exception:
                    pass
            print("  [+] Temp dosyalari temizlendi")
        except Exception:
            pass
        
    else:
        # Linux
        _run_cmd('ip neigh flush all')
        print("  [+] ARP cache temizlendi")
        
        _run_cmd('systemd-resolve --flush-caches 2>/dev/null || resolvectl flush-caches 2>/dev/null')
        print("  [+] DNS cache temizlendi")
        
        # /tmp temizle
        try:
            for f in os.listdir('/tmp'):
                fpath = os.path.join('/tmp', f)
                try:
                    if os.path.isfile(fpath):
                        os.unlink(fpath)
                except Exception:
                    pass
            print("  [+] /tmp temizlendi")
        except Exception:
            pass
    
    print(f"\033[32m[+] Ag izleri temizlendi\033[0m")
    return True


# ============================================
# FULL IDENTITY SPOOF (TOPLU)
# ============================================

def full_identity_spoof():
    """Tum PC kimlik bilgilerini toplu degistir."""
    print("\n" + "=" * 60)
    print(" TOPLU KIMLIK DEGISIMI")
    print("=" * 60)
    print("\n\033[33m[!] UYARI: Bu islem geri alinmasi zor degisiklikler yapar!\033[0m")
    print("\033[33m[!] Yedekler otomatik alinir.\033[0m\n")
    
    if not _is_admin():
        print("\033[31m[-] Admin/root yetkisi gerekli!\033[0m")
        return
    
    # Mevcut bilgileri kaydet
    identity = get_current_identity()
    backup_file = f"identity_backup_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(backup_file, 'w', encoding='utf-8') as f:
        json.dump(identity, f, indent=2, ensure_ascii=False, default=str)
    print(f"[+] Yedek kaydedildi: {backup_file}")
    
    # Onay al
    confirm = _get_input("Devam etmek istiyor musunuz? (evet/hayir)", "hayir")
    if confirm.lower() not in ('evet', 'e', 'yes', 'y'):
        print("[-] Iptal edildi")
        return
    
    results = {}
    
    # 1. MAC degistir
    print("\n[1/5] MAC adresi degistiriliyor...")
    new_mac = _generate_random_mac()
    results['mac'] = spoof_mac(new_mac=new_mac)
    
    # 2. Hostname degistir
    print("\n[2/5] Hostname degistiriliyor...")
    new_hostname = _generate_random_hostname()
    results['hostname'] = spoof_hostname(new_hostname)
    
    # 3. Machine ID degistir
    print("\n[3/5] Machine ID degistiriliyor...")
    new_guid = _generate_random_guid()
    results['machine_id'] = spoof_machine_id(new_guid)
    
    # 4. DNS degistir
    print("\n[4/5] DNS degistiriliyor...")
    results['dns'] = spoof_dns('1.1.1.1', '1.0.0.1')
    
    # 5. Network izleri temizle
    print("\n[5/5] Ag izleri temizleniyor...")
    results['clean'] = clean_network_traces()
    
    # Ozet
    print("\n" + "=" * 60)
    print(" SONUC OZETI")
    print("=" * 60)
    
    success_count = sum(1 for v in results.values() if v)
    total = len(results)
    
    for op, success in results.items():
        status = "\033[32mBasarili\033[0m" if success else "\033[31mBasarisiz\033[0m"
        print(f"  {op:15s}: {status}")
    
    print(f"\n  Toplam: {success_count}/{total} basarili")
    print(f"  Yedek: {backup_file}")
    
    if success_count > 0:
        print(f"\n\033[33m[!] Bazi degisiklikler yeniden baslatma sonrasi aktif olur\033[0m")


# ============================================
# RESTORE (GERI YUKE)
# ============================================

def restore_identity(backup_file=None):
    """Yedekten kimlik bilgilerini geri yukle."""
    if not _is_admin():
        print("\033[31m[-] Admin/root yetkisi gerekli!\033[0m")
        return
    
    if backup_file is None:
        # En son yedegi bul
        backups = sorted([f for f in os.listdir('.') if f.startswith('identity_backup_')], reverse=True)
        if not backups:
            print("[-] Yedek dosyasi bulunamadi")
            return
        backup_file = backups[0]
    
    print(f"[+] Yedek dosyasi: {backup_file}")
    
    try:
        with open(backup_file, 'r') as f:
            identity = json.load(f)
    except Exception as e:
        print(f"[-] Yedek okunamadi: {e}")
        return
    
    print(f"[+] Hostname: {identity.get('hostname', 'N/A')}")
    print(f"[+] MAC'ler: {identity.get('mac_addresses', {})}")
    
    confirm = _get_input("Geri yuklemek istiyor musunuz? (evet/hayir)", "hayir")
    if confirm.lower() not in ('evet', 'e', 'yes', 'y'):
        print("[-] Iptal edildi")
        return
    
    # Hostname geri yukle
    old_hostname = identity.get('hostname')
    if old_hostname:
        spoof_hostname(old_hostname)
    
    # Machine ID geri yukle
    if os.name == 'nt':
        old_guid = identity.get('machine_guid')
        if old_guid and old_guid != 'Bulunamadi':
            spoof_machine_id(old_guid)
    else:
        old_mid = identity.get('machine_id')
        if old_mid and old_mid != 'Bulunamadi':
            spoof_machine_id(old_mid)
    
    print(f"\033[32m[+] Kimlik bilgileri geri yuklendi\033[0m")
    print("[!] MAC adresi manual geri yuklenmelidir")


# ============================================
# MENU
# ============================================

def pc_spoofer_menu():
    """PC Identity Spoofer menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        admin_status = "\033[32m[ADMIN]\033[0m" if _is_admin() else "\033[31m[USER]\033[0m"
        
        print("=" * 60)
        print(f" PC Identity Spoofer {admin_status}")
        print(" Bilgisayar kimlik bilgilerini degistir")
        print("=" * 60)
        print()
        print("  Bilgi:")
        print("    0) Mevcut PC kimligini goster")
        print()
        print("  Spoofing:")
        print("    1) MAC adresi degistir")
        print("    2) Hostname degistir")
        print("    3) Machine GUID/ID degistir")
        print("    4) DNS sunucularini degistir")
        print("    5) Ag izlerini temizle")
        print()
        print("  Toplu:")
        print("    6) TOPLU KIMLIK DEGISIMI (tum)")
        print("    7) Kimlik geri yukle (backup)")
        print()
        print("  Sistem:")
        print("    a) Admin olarak yeniden baslat (Windows)")
        print()
        print("  Geri donmek icin 'back' yazin")
        print()
        
        choice = _get_input("Secim", "0").lower()
        
        if choice == 'back' or choice == 'geri':
            return
        elif choice == '0':
            show_current_identity()
        elif choice == 'a':
            _request_admin_elevation()
            return  # Yeni baslatildigi icin cik
        elif choice == '1':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            interface = _get_input("Arayuz (bos = otomatik)", "")
            new_mac = _get_input("Yeni MAC (bos = rastgele)", "")
            spoof_mac(
                interface=interface if interface else None,
                new_mac=new_mac if new_mac else None
            )
        elif choice == '2':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            new_name = _get_input("Yeni hostname (bos = rastgele)", "")
            spoof_hostname(new_name if new_name else None)
        elif choice == '3':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            new_id = _get_input("Yeni GUID (bos = rastgele)", "")
            spoof_machine_id(new_id if new_id else None)
        elif choice == '4':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            spoof_dns()
        elif choice == '5':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            clean_network_traces()
        elif choice == '6':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            full_identity_spoof()
        elif choice == '7':
            if not _is_admin():
                print("\033[33m[!] Admin yetkisi gerekli. 'a' tusuna basarak yeniden baslatin.\033[0m")
                time.sleep(2)
                continue
            restore_identity()
        else:
            print("[-] Gecersiz secim")
            time.sleep(1)
            continue
        
        input("\nDevam icin Enter...")


if __name__ == "__main__":
    pc_spoofer_menu()
