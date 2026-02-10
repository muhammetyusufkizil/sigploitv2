#!/usr/bin/env python3
"""
SigPloit Phone Recon Module
============================
Telefonu USB ile PC'ye bagla, baz istasyonu bilgilerini topla.

Desteklenen yontemler:
1. ADB (Android Debug Bridge) - Android telefonlar
2. AT Komutlari (USB Serial) - Modem modu
3. Hibrit - Her ikisi birden

Toplanan bilgiler:
- Bagli baz istasyonu (Cell ID, LAC, MCC, MNC, ARFCN)
- Cevreki baz istasyonlari (neighbor cells)
- Sinyal gucu (RSSI, RSRP, RSRQ, SINR)
- Operator bilgisi
- IMSI/IMEI (kendi telefonun)
- Konum tahmini (Cell ID -> koordinat)
"""

import subprocess
import sys
import os
import json
import time
import re
import struct
import socket
import datetime
import math

# ============================================
# ADB (Android Debug Bridge) Modulu
# ============================================

class ADBPhone:
    """Android telefon ile ADB uzerinden iletisim."""
    
    def __init__(self):
        self.connected = False
        self.device_id = None
        self.model = None
    
    def check_adb(self):
        """ADB kurulu mu kontrol et."""
        try:
            result = subprocess.run(['adb', 'version'], 
                                     capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def connect(self):
        """Telefona baglan."""
        if not self.check_adb():
            print("  [-] ADB bulunamadi!")
            print("  [?] Kurulum:")
            print("      Windows: choco install adb")
            print("      Linux: sudo apt install adb")
            print("      Mac: brew install android-platform-tools")
            return False
        
        # Bagli cihazlari listele
        result = subprocess.run(['adb', 'devices'], 
                                 capture_output=True, text=True, timeout=10)
        
        lines = result.stdout.strip().split('\n')
        devices = []
        for line in lines[1:]:  # Ilk satir baslik
            if '\tdevice' in line:
                dev_id = line.split('\t')[0]
                devices.append(dev_id)
        
        if not devices:
            print("  [-] Bagli Android cihaz bulunamadi!")
            print("  [?] Kontrol edin:")
            print("      1. USB Debugging acik mi? (Ayarlar -> Gelistirici Secenekleri)")
            print("      2. USB kablosu bagli mi?")
            print("      3. Telefonda 'USB Debugging izin ver' onaylandi mi?")
            return False
        
        self.device_id = devices[0]
        self.connected = True
        
        # Model bilgisi
        self.model = self._adb_shell("getprop ro.product.model").strip()
        brand = self._adb_shell("getprop ro.product.brand").strip()
        android_ver = self._adb_shell("getprop ro.build.version.release").strip()
        
        print(f"  \033[32m[+] Telefon baglandi: {brand} {self.model} (Android {android_ver})\033[0m")
        print(f"      Device ID: {self.device_id}")
        
        return True
    
    def _adb_shell(self, cmd, timeout=10):
        """ADB shell komutu calistir."""
        try:
            result = subprocess.run(
                ['adb', '-s', self.device_id, 'shell', cmd],
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except (subprocess.TimeoutExpired, Exception):
            return ""
    
    def get_cell_info(self):
        """Bagli baz istasyonu ve komsulari."""
        info = {
            'serving_cell': None,
            'neighbor_cells': [],
            'operator': None,
            'network_type': None,
            'signal': {}
        }
        
        # Yontem 1: dumpsys telephony.registry
        dump = self._adb_shell("dumpsys telephony.registry")
        
        # MCC/MNC ve operator
        op_match = re.search(r'mOperatorAlphaLong=(\S+)', dump)
        if op_match:
            info['operator'] = op_match.group(1)
        
        mccmnc_match = re.search(r'mNetworkCountryIso=(\w+)', dump)
        
        # Network type
        nw_match = re.search(r'mDataNetworkType=(\d+)', dump)
        if nw_match:
            nw_types = {
                '0': 'Unknown', '1': 'GPRS', '2': 'EDGE', '3': 'UMTS',
                '4': 'CDMA', '5': 'EVDO_0', '6': 'EVDO_A', '7': 'RTT',
                '8': 'HSDPA', '9': 'HSUPA', '10': 'HSPA', '11': 'iDEN',
                '12': 'EVDO_B', '13': 'LTE', '14': 'eHRPD', '15': 'HSPA+',
                '19': 'TD_SCDMA', '20': '5G NR',
            }
            info['network_type'] = nw_types.get(nw_match.group(1), f'type_{nw_match.group(1)}')
        
        # Signal strength
        sig_match = re.search(r'mSignalStrength=SignalStrength:\s*(.*)', dump)
        if sig_match:
            info['signal']['raw'] = sig_match.group(1)[:100]
        
        # Yontem 2: dumpsys phone (daha detayli)
        phone_dump = self._adb_shell("dumpsys phone")
        
        # Cell ID ayrıştır
        cell_patterns = [
            # LTE
            r'CellIdentityLte.*?mci=(\d+)\s+mnc=(\d+).*?tac=(\d+).*?ci=(\d+).*?pci=(\d+)',
            r'CellIdentityLte\{mcc=(\d+)\s+mnc=(\d+).*?tac=(\d+).*?ci=(\d+).*?pci=(\d+)',
            # WCDMA/UMTS
            r'CellIdentityWcdma.*?mcc=(\d+)\s+mnc=(\d+).*?lac=(\d+).*?cid=(\d+)',
            # GSM
            r'CellIdentityGsm.*?mcc=(\d+)\s+mnc=(\d+).*?lac=(\d+).*?cid=(\d+)',
            # NR (5G)
            r'CellIdentityNr.*?mcc=(\d+)\s+mnc=(\d+).*?tac=(\d+).*?nci=(\d+)',
        ]
        
        # Tum cell bilgilerini topla
        all_cells_dump = phone_dump + "\n" + dump
        
        for pattern in cell_patterns:
            matches = re.finditer(pattern, all_cells_dump, re.DOTALL)
            for m in matches:
                groups = m.groups()
                cell = {
                    'mcc': groups[0],
                    'mnc': groups[1],
                }
                if len(groups) >= 4:
                    cell['lac_tac'] = groups[2]
                    cell['cell_id'] = groups[3]
                if len(groups) >= 5:
                    cell['pci'] = groups[4]
                
                if info['serving_cell'] is None:
                    info['serving_cell'] = cell
                else:
                    # Duplicate kontrolu
                    if cell.get('cell_id') != info['serving_cell'].get('cell_id'):
                        info['neighbor_cells'].append(cell)
        
        # Yontem 3: service call (daha derin bilgi)
        try:
            # getAllCellInfo
            all_cell = self._adb_shell("dumpsys connectivity | grep -i cell")
            if all_cell:
                info['connectivity_info'] = all_cell[:500]
        except Exception:
            pass
        
        return info
    
    def get_imei(self):
        """IMEI numarasini al."""
        # Yontem 1
        result = self._adb_shell("service call iphonesubinfo 1")
        if result:
            # Parse service call result
            imei_parts = re.findall(r"'(.*?)'", result)
            imei = ''.join(imei_parts).replace('.', '').strip()
            if len(imei) >= 15:
                return imei[:15]
        
        # Yontem 2
        result = self._adb_shell("getprop persist.radio.imei")
        if result.strip():
            return result.strip()
        
        # Yontem 3
        result = self._adb_shell("dumpsys phone | grep mImei")
        match = re.search(r'mImei=(\d+)', result)
        if match:
            return match.group(1)
        
        return "Alinamadi (root gerekebilir)"
    
    def get_imsi(self):
        """IMSI numarasini al (root gerekebilir)."""
        result = self._adb_shell("service call iphonesubinfo 7")
        if result:
            imsi_parts = re.findall(r"'(.*?)'", result)
            imsi = ''.join(imsi_parts).replace('.', '').strip()
            if len(imsi) >= 15:
                return imsi[:15]
        
        return "Alinamadi (root gerekli)"
    
    def get_neighbor_cells(self):
        """Komsun baz istasyonlarini tara."""
        cells = []
        
        # dumpsys telephony.registry'den neighbor cells
        dump = self._adb_shell("dumpsys telephony.registry")
        
        # CellInfo objelerini bul
        cell_blocks = re.findall(r'CellInfo\w*\{(.*?)\}', dump, re.DOTALL)
        
        for block in cell_blocks:
            cell = {}
            
            # Registered (serving) vs not registered (neighbor)
            cell['registered'] = 'registered=true' in block.lower() or 'isregistered=true' in block.lower()
            
            # MCC/MNC
            mcc = re.search(r'mcc[=:]?\s*(\d+)', block, re.IGNORECASE)
            mnc = re.search(r'mnc[=:]?\s*(\d+)', block, re.IGNORECASE)
            if mcc: cell['mcc'] = mcc.group(1)
            if mnc: cell['mnc'] = mnc.group(1)
            
            # Cell ID / CI
            ci = re.search(r'(?:ci|cid|nci)[=:]?\s*(\d+)', block, re.IGNORECASE)
            if ci: cell['cell_id'] = ci.group(1)
            
            # LAC / TAC
            lac = re.search(r'(?:lac|tac)[=:]?\s*(\d+)', block, re.IGNORECASE)
            if lac: cell['lac_tac'] = lac.group(1)
            
            # PCI (Physical Cell ID)
            pci = re.search(r'pci[=:]?\s*(\d+)', block, re.IGNORECASE)
            if pci: cell['pci'] = pci.group(1)
            
            # ARFCN / EARFCN
            arfcn = re.search(r'(?:arfcn|earfcn|nrarfcn)[=:]?\s*(\d+)', block, re.IGNORECASE)
            if arfcn: cell['arfcn'] = arfcn.group(1)
            
            # Signal
            rsrp = re.search(r'rsrp[=:]?\s*(-?\d+)', block, re.IGNORECASE)
            rsrq = re.search(r'rsrq[=:]?\s*(-?\d+)', block, re.IGNORECASE)
            rssi = re.search(r'rssi[=:]?\s*(-?\d+)', block, re.IGNORECASE)
            if rsrp: cell['rsrp'] = rsrp.group(1)
            if rsrq: cell['rsrq'] = rsrq.group(1)
            if rssi: cell['rssi'] = rssi.group(1)
            
            # Technology
            if 'nr' in block.lower() or 'NR' in block:
                cell['tech'] = '5G NR'
            elif 'lte' in block.lower():
                cell['tech'] = '4G LTE'
            elif 'wcdma' in block.lower() or 'umts' in block.lower():
                cell['tech'] = '3G UMTS'
            elif 'gsm' in block.lower():
                cell['tech'] = '2G GSM'
            
            if cell.get('cell_id') or cell.get('pci'):
                cells.append(cell)
        
        return cells
    
    def send_ussd(self, code):
        """USSD kodu gonder (ornegin *#06#)."""
        # USSD ADB uzerinden direkt calismaz, 
        # ama activity baslatabiliriz
        cmd = f'am start -a android.intent.action.CALL -d "tel:{code}"'
        result = self._adb_shell(cmd)
        return result
    
    def get_sim_info(self):
        """SIM kart bilgileri."""
        info = {}
        
        info['operator'] = self._adb_shell("getprop gsm.sim.operator.alpha").strip()
        info['operator_numeric'] = self._adb_shell("getprop gsm.sim.operator.numeric").strip()
        info['sim_state'] = self._adb_shell("getprop gsm.sim.state").strip()
        info['network_type'] = self._adb_shell("getprop gsm.network.type").strip()
        info['phone_type'] = self._adb_shell("getprop gsm.current.phone-type").strip()
        
        return info


# ============================================
# AT KOMUT MODULU (USB Serial/Modem)
# ============================================

class ATPhone:
    """AT komutlari ile modem iletisimi."""
    
    def __init__(self):
        self.serial = None
        self.port = None
    
    def find_modem(self):
        """USB modem portunu bul."""
        ports = []
        
        if sys.platform == 'win32':
            # Windows COM portlari
            for i in range(1, 30):
                port = f'COM{i}'
                try:
                    import serial
                    s = serial.Serial(port, 115200, timeout=1)
                    s.write(b'AT\r\n')
                    time.sleep(0.5)
                    resp = s.read(100)
                    if b'OK' in resp:
                        ports.append(port)
                    s.close()
                except Exception:
                    pass
        else:
            # Linux /dev/ttyUSB* veya /dev/ttyACM*
            import glob
            for pattern in ['/dev/ttyUSB*', '/dev/ttyACM*', '/dev/ttyS*']:
                for port in glob.glob(pattern):
                    try:
                        import serial
                        s = serial.Serial(port, 115200, timeout=1)
                        s.write(b'AT\r\n')
                        time.sleep(0.5)
                        resp = s.read(100)
                        if b'OK' in resp:
                            ports.append(port)
                        s.close()
                    except Exception:
                        pass
        
        return ports
    
    def connect(self, port=None):
        """Modeme baglan."""
        try:
            import serial as pyserial
        except ImportError:
            print("  [-] pyserial kurulu degil!")
            print("  [+] Kurmak icin: pip install pyserial")
            return False
        
        if port is None:
            ports = self.find_modem()
            if not ports:
                print("  [-] USB modem bulunamadi!")
                print("  [?] Kontrol edin:")
                print("      1. Telefon USB ile bagli mi?")
                print("      2. USB Tethering veya modem modu acik mi?")
                return False
            port = ports[0]
        
        try:
            self.serial = pyserial.Serial(port, 115200, timeout=2)
            self.port = port
            
            # Test
            resp = self._at_cmd("AT")
            if 'OK' in resp:
                model = self._at_cmd("AT+CGMM")
                print(f"  \033[32m[+] Modem baglandi: {port}\033[0m")
                print(f"      Model: {model.strip()}")
                return True
        except Exception as e:
            print(f"  [-] Baglanti hatasi: {e}")
        
        return False
    
    def _at_cmd(self, cmd, timeout=3):
        """AT komutu gonder ve yanit al."""
        if not self.serial:
            return ""
        try:
            self.serial.write(f'{cmd}\r\n'.encode())
            time.sleep(0.5)
            resp = self.serial.read(4096).decode('utf-8', errors='ignore')
            return resp
        except Exception:
            return ""
    
    def get_cell_info(self):
        """Baz istasyonu bilgisi al."""
        info = {}
        
        # Operator
        resp = self._at_cmd("AT+COPS?")
        match = re.search(r'\+COPS:\s*\d+,\d+,"([^"]+)",(\d+)', resp)
        if match:
            info['operator'] = match.group(1)
            tech = match.group(2)
            tech_map = {'0': 'GSM', '2': 'UMTS', '3': 'LTE', '7': 'LTE', '11': '5G NR', '12': '5G NR'}
            info['technology'] = tech_map.get(tech, f'type_{tech}')
        
        # Sinyal gucu
        resp = self._at_cmd("AT+CSQ")
        match = re.search(r'\+CSQ:\s*(\d+),(\d+)', resp)
        if match:
            rssi_raw = int(match.group(1))
            if rssi_raw < 31:
                info['rssi_dbm'] = -113 + (rssi_raw * 2)
            info['rssi_raw'] = rssi_raw
            info['ber'] = match.group(2)
        
        # Kayit durumu + LAC + Cell ID
        resp = self._at_cmd("AT+CREG?")
        match = re.search(r'\+CREG:\s*\d+,(\d+)(?:,"([^"]*)")?(?:,"([^"]*)")?', resp)
        if match:
            reg_status = {'0': 'Kayitsiz', '1': 'Kayitli (ev)', '2': 'Aranıyor', '3': 'Reddedildi', '5': 'Kayitli (roaming)'}
            info['registration'] = reg_status.get(match.group(1), match.group(1))
            if match.group(2): info['lac'] = match.group(2)
            if match.group(3): info['cell_id'] = match.group(3)
        
        # LTE detay
        resp = self._at_cmd("AT+CEREG?")
        match = re.search(r'\+CEREG:\s*\d+,(\d+)(?:,"([^"]*)")?(?:,"([^"]*)")?', resp)
        if match:
            if match.group(2): info['tac'] = match.group(2)
            if match.group(3): info['eci'] = match.group(3)
        
        # Neighbor cells (varsa)
        resp = self._at_cmd("AT+QENG=\"neighbourcell\"")
        if '+QENG' in resp:
            info['neighbor_raw'] = resp
        
        # Serving cell detay (Quectel/Huawei modular)
        resp = self._at_cmd('AT+QENG="servingcell"')
        if '+QENG' in resp:
            info['serving_raw'] = resp
        
        return info
    
    def get_imei(self):
        """IMEI al."""
        resp = self._at_cmd("AT+CGSN")
        match = re.search(r'(\d{15})', resp)
        return match.group(1) if match else "Alinamadi"
    
    def get_imsi(self):
        """IMSI al."""
        resp = self._at_cmd("AT+CIMI")
        match = re.search(r'(\d{15})', resp)
        return match.group(1) if match else "Alinamadi"
    
    def get_iccid(self):
        """SIM ICCID al."""
        resp = self._at_cmd("AT+CCID")
        match = re.search(r'(\d{19,20})', resp)
        return match.group(1) if match else "Alinamadi"


# ============================================
# CELL ID -> KONUM DONUSTURUCU
# ============================================

def cell_to_location(mcc, mnc, lac, cell_id):
    """
    Cell ID'yi koordinata donustur.
    LAC/TAC bos olabilir - o zaman sadece Cell ID ile dener.
    """
    import requests
    
    # LAC varsa direkt dene
    lac_values = []
    if lac:
        lac_values.append(int(lac))
    else:
        # LAC bilinmiyorsa yaygin Turkiye TAC/LAC degerleri ile dene
        # Vodafone TR: 30000-35000, Turkcell: 20000-25000, TT: 40000-50000
        lac_values = [0]  # 0 = bilinmiyor
    
    for lac_val in lac_values:
        # Yontem 1: OpenCellID (ucretsiz)
        try:
            if lac_val > 0:
                url = f"https://opencellid.org/cell/get?key=pk.demo&mcc={mcc}&mnc={mnc}&lac={lac_val}&cellid={cell_id}&format=json"
            else:
                url = f"https://opencellid.org/cell/get?key=pk.demo&mcc={mcc}&mnc={mnc}&cellid={cell_id}&format=json"
            
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('lat') and data.get('lon'):
                    return {
                        'lat': data['lat'],
                        'lon': data['lon'],
                        'range': data.get('range', 0),
                        'source': 'OpenCellID',
                        'lac_found': data.get('lac', lac_val)
                    }
        except Exception:
            pass
        
        # Yontem 2: Mozilla Location Service
        try:
            url = "https://location.services.mozilla.com/v1/geolocate?key=test"
            cell_tower = {
                "mobileCountryCode": int(mcc),
                "mobileNetworkCode": int(mnc),
                "cellId": int(cell_id),
            }
            if lac_val > 0:
                cell_tower["locationAreaCode"] = lac_val
            
            payload = {"cellTowers": [cell_tower]}
            resp = requests.post(url, json=payload, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                loc = data.get('location', {})
                if loc.get('lat') and loc.get('lng'):
                    return {
                        'lat': loc['lat'],
                        'lon': loc['lng'],
                        'range': data.get('accuracy', 0),
                        'source': 'Mozilla'
                    }
        except Exception:
            pass
    
    # Yontem 3: cellinfo.io (LAC gerektirmez)
    try:
        url = f"https://api.cellinfo.io/cell?mcc={mcc}&mnc={mnc}&cid={cell_id}"
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('lat') and data.get('lon'):
                return {
                    'lat': data['lat'],
                    'lon': data['lon'],
                    'range': data.get('range', 0),
                    'source': 'CellInfo.io'
                }
    except Exception:
        pass
    
    return None


# ============================================
# KONUMA GORE BAZ ISTASYONU TARAMA
# ============================================

# Turkiye sehir koordinatlari
TR_CITIES = {
    'adiyaman':   (37.7648, 38.2786),
    'adana':      (37.0000, 35.3213),
    'ankara':     (39.9334, 32.8597),
    'antalya':    (36.8969, 30.7133),
    'bursa':      (40.1885, 29.0610),
    'diyarbakir': (37.9144, 40.2306),
    'elazig':     (38.6810, 39.2264),
    'erzurum':    (39.9055, 41.2658),
    'eskisehir':  (39.7767, 30.5206),
    'gaziantep':  (37.0662, 37.3833),
    'istanbul':   (41.0082, 28.9784),
    'izmir':      (38.4192, 27.1287),
    'kayseri':    (38.7312, 35.4787),
    'konya':      (37.8746, 32.4932),
    'malatya':    (38.3552, 38.3095),
    'mersin':     (36.8121, 34.6415),
    'samsun':     (41.2928, 36.3313),
    'sanliurfa':  (37.1674, 38.7955),
    'sivas':      (39.7477, 37.0179),
    'trabzon':    (41.0015, 39.7178),
    'van':        (38.5012, 43.3730),
}

TR_OPERATORS = {
    '1': 'Turkcell',
    '2': 'Vodafone',
    '3': 'Turk Telekom',
    '4': 'Bimcell',
    '01': 'Turkcell',
    '02': 'Vodafone',
    '03': 'Turk Telekom',
    '04': 'Bimcell',
}


OPENCELLID_DB_FILE = "opencellid_286.csv"
OPENCELLID_TOKEN_FILE = ".opencellid_token"


def _load_opencellid_token():
    """Kayitli OpenCellID token'i oku."""
    for path in [OPENCELLID_TOKEN_FILE, os.path.expanduser(f"~/{OPENCELLID_TOKEN_FILE}")]:
        try:
            with open(path, 'r') as f:
                token = f.read().strip()
                if token and len(token) > 5:
                    return token
        except FileNotFoundError:
            pass
    return None


def _save_opencellid_token(token):
    """OpenCellID token'i kaydet."""
    with open(OPENCELLID_TOKEN_FILE, 'w') as f:
        f.write(token)


def _download_opencellid_db(token):
    """Turkiye (MCC=286) hucre veritabanini indir - sadece 264KB."""
    import requests
    import gzip
    import io
    
    print("  \033[36m[~] Turkiye hucre veritabani indiriliyor (264KB)...\033[0m")
    
    url = f"https://opencellid.org/ocid/downloads?token={token}&type=mcc&file=286.csv.gz"
    
    try:
        resp = requests.get(url, timeout=30, headers={'User-Agent': 'SigPloit/1.0'})
        
        if resp.status_code == 200:
            # Gzip'i ac
            if resp.content[:2] == b'\x1f\x8b':  # gzip magic number
                decompressed = gzip.decompress(resp.content)
                csv_data = decompressed.decode('utf-8', errors='ignore')
            else:
                csv_data = resp.text
            
            # CSV olarak kaydet
            with open(OPENCELLID_DB_FILE, 'w', encoding='utf-8') as f:
                f.write(csv_data)
            
            lines = csv_data.strip().split('\n')
            print(f"  \033[32m[+] Veritabani indirildi: {len(lines)-1} hucre kaydi\033[0m")
            return True
        elif resp.status_code == 403:
            print("  \033[31m[-] API token gecersiz veya limiti dolmus\033[0m")
        elif resp.status_code == 401:
            print("  \033[31m[-] API token yetkisiz\033[0m")
        else:
            print(f"  \033[31m[-] Indirme hatasi: HTTP {resp.status_code}\033[0m")
            # Icerik text ise goster
            if resp.text and len(resp.text) < 200:
                print(f"      {resp.text[:150]}")
    except Exception as e:
        print(f"  \033[31m[-] Indirme hatasi: {e}\033[0m")
    
    return False


def _search_local_db(lat, lon, radius_km, mnc=None):
    """Lokal OpenCellID veritabaninda ara."""
    towers = []
    
    if not os.path.exists(OPENCELLID_DB_FILE):
        return towers
    
    dlat = radius_km / 111.0
    dlon = radius_km / (111.0 * abs(math.cos(math.radians(lat))))
    
    lat1, lat2 = lat - dlat, lat + dlat
    lon1, lon2 = lon - dlon, lon + dlon
    
    # OpenCellID CSV formati (header olmayabilir):
    # radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal
    # Index: 0     1    2   3    4    5   6   7    8       9
    
    IDX_RADIO = 0
    IDX_MCC = 1
    IDX_MNC = 2
    IDX_LAC = 3
    IDX_CELL = 4
    IDX_LON = 6
    IDX_LAT = 7
    IDX_RANGE = 8
    IDX_SAMPLES = 9
    
    try:
        with open(OPENCELLID_DB_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Header satiri varsa atla
                if line.startswith('radio,') or line.startswith('Radio,'):
                    continue
                
                parts = line.split(',')
                if len(parts) < 8:
                    continue
                
                try:
                    t_lat = float(parts[IDX_LAT])
                    t_lon = float(parts[IDX_LON])
                    
                    # Hizli BBOX filtre
                    if t_lat < lat1 or t_lat > lat2 or t_lon < lon1 or t_lon > lon2:
                        continue
                    
                    t_mnc = parts[IDX_MNC].strip()
                    if mnc and t_mnc != mnc:
                        continue
                    
                    t_radio = parts[IDX_RADIO].strip()
                    t_cell = parts[IDX_CELL].strip()
                    t_lac = parts[IDX_LAC].strip()
                    t_range = parts[IDX_RANGE].strip() if len(parts) > IDX_RANGE else '0'
                    t_samples = parts[IDX_SAMPLES].strip() if len(parts) > IDX_SAMPLES else '0'
                    
                    dist = math.sqrt((t_lat - lat)**2 + (t_lon - lon)**2) * 111
                    
                    if dist > radius_km:
                        continue
                    
                    towers.append({
                        'cell_id': t_cell,
                        'lac': t_lac,
                        'mcc': '286',
                        'mnc': t_mnc,
                        'lat': t_lat,
                        'lon': t_lon,
                        'range': int(t_range) if t_range.isdigit() else 0,
                        'radio': t_radio,
                        'samples': int(t_samples) if t_samples.isdigit() else 0,
                        'source': 'OpenCellID',
                        'operator': TR_OPERATORS.get(t_mnc, '?'),
                        'distance_km': round(dist, 2),
                    })
                except (ValueError, IndexError):
                    continue
    except Exception as e:
        print(f"  \033[31m[-] Veritabani okuma hatasi: {e}\033[0m")
    
    towers.sort(key=lambda x: x['distance_km'])
    return towers


def search_towers_by_location(lat, lon, radius_km=5, mcc='286', mnc=None, verbose=True):
    """
    Koordinata gore yakin baz istasyonlarini bul.
    Oncelik: Lokal veritabani > Online API'ler > OpenStreetMap
    """
    import requests
    
    all_towers = []
    
    # BBOX hesapla
    dlat = radius_km / 111.0
    dlon = radius_km / (111.0 * abs(math.cos(math.radians(lat))))
    lat1, lat2 = lat - dlat, lat + dlat
    lon1, lon2 = lon - dlon, lon + dlon
    
    # ---- KAYNAK 1: Lokal OpenCellID veritabani ----
    if verbose:
        print("    [1/3] Lokal veritabani...", end=" ", flush=True)
    
    local_towers = _search_local_db(lat, lon, radius_km, mnc)
    if local_towers:
        all_towers.extend(local_towers)
        if verbose:
            print(f"\033[32m{len(local_towers)} hucre bulundu!\033[0m")
    else:
        if os.path.exists(OPENCELLID_DB_FILE):
            if verbose:
                print(f"\033[33m0 (bu yaricapta hucre yok, yaricapi artirin)\033[0m")
        else:
            if verbose:
                print(f"\033[33mVeritabani yok - indirmek icin asagiya bakin\033[0m")
    
    # ---- KAYNAK 2: OpenCellID API (token varsa) ----
    if not all_towers:
        token = _load_opencellid_token()
        if token:
            if verbose:
                print("    [2/3] OpenCellID API...", end=" ", flush=True)
            try:
                url = (f"https://opencellid.org/cell/getInArea?"
                       f"key={token}&BBOX={lat1},{lon1},{lat2},{lon2}"
                       f"&mcc={mcc}&format=json&limit=1000")
                if mnc:
                    url += f"&mnc={mnc}"
                
                resp = requests.get(url, timeout=15, headers={'User-Agent': 'SigPloit/1.0'})
                if resp.status_code == 200:
                    data = resp.json()
                    cells = data.get('cells', [])
                    if isinstance(data, list):
                        cells = data
                    
                    for cell in cells:
                        t_lat = float(cell.get('lat', 0))
                        t_lon = float(cell.get('lon', 0))
                        dist = math.sqrt((t_lat - lat)**2 + (t_lon - lon)**2) * 111
                        
                        all_towers.append({
                            'cell_id': cell.get('cellid', cell.get('cid', '?')),
                            'lac': cell.get('lac', '?'),
                            'mcc': cell.get('mcc', mcc),
                            'mnc': str(cell.get('mnc', '?')),
                            'lat': t_lat,
                            'lon': t_lon,
                            'range': cell.get('range', 0),
                            'radio': cell.get('radio', '?'),
                            'samples': cell.get('samples', 0),
                            'source': 'OpenCellID',
                            'operator': TR_OPERATORS.get(str(cell.get('mnc', '')), '?'),
                            'distance_km': round(dist, 2),
                        })
                    
                    if verbose:
                        print(f"\033[32m{len(cells)} bulundu\033[0m" if cells else "\033[33m0\033[0m")
                else:
                    if verbose:
                        print(f"\033[31mHTTP {resp.status_code}\033[0m")
            except Exception as e:
                if verbose:
                    print(f"\033[31m{str(e)[:40]}\033[0m")
        else:
            if verbose:
                print("    [2/3] OpenCellID API... \033[33mtoken yok\033[0m")
    
    # ---- KAYNAK 3: OpenStreetMap (fiziksel kule konumlari) ----
    if verbose:
        print("    [3/3] OpenStreetMap kuleleri...", end=" ", flush=True)
    try:
        overpass_query = f"""[out:json][timeout:25];
(
  node["man_made"="mast"]({lat1},{lon1},{lat2},{lon2});
  node["man_made"="tower"]["tower:type"="communication"]({lat1},{lon1},{lat2},{lon2});
  node["telecom"~"antenna|mast"]({lat1},{lon1},{lat2},{lon2});
  way["man_made"="mast"]({lat1},{lon1},{lat2},{lon2});
  way["man_made"="tower"]["tower:type"="communication"]({lat1},{lon1},{lat2},{lon2});
);
out center body;"""
        
        resp = requests.post("https://overpass-api.de/api/interpreter",
                           data={'data': overpass_query}, timeout=25)
        osm_count = 0
        if resp.status_code == 200:
            data = resp.json()
            for elem in data.get('elements', []):
                tags = elem.get('tags', {})
                e_lat = elem.get('lat', 0) or elem.get('center', {}).get('lat', 0)
                e_lon = elem.get('lon', 0) or elem.get('center', {}).get('lon', 0)
                
                if not e_lat or not e_lon:
                    continue
                
                dist = math.sqrt((e_lat - lat)**2 + (e_lon - lon)**2) * 111
                operator = tags.get('operator', tags.get('operator:en', ''))
                
                all_towers.append({
                    'cell_id': tags.get('ref', tags.get('ref:BTK', '?')),
                    'lac': '?',
                    'mcc': mcc,
                    'mnc': '?',
                    'lat': e_lat,
                    'lon': e_lon,
                    'range': 0,
                    'radio': tags.get('communication:mobile_phone', 'tower'),
                    'samples': 0,
                    'source': 'OSM',
                    'operator': operator,
                    'name': tags.get('name', ''),
                    'height': tags.get('height', '?'),
                    'distance_km': round(dist, 2),
                })
                osm_count += 1
        
        if verbose:
            print(f"\033[32m{osm_count} kule\033[0m" if osm_count else "\033[33m0\033[0m")
    except Exception as e:
        if verbose:
            print(f"\033[31m{str(e)[:40]}\033[0m")
    
    all_towers.sort(key=lambda x: x.get('distance_km', 999))
    return all_towers


def tower_search_menu(phone=None):
    """Baz istasyonu arama menusu."""
    print("\n  \033[36m============================================================\033[0m")
    print("  \033[36m  BAZ ISTASYONU TARAMA (Ucretsiz)\033[0m")
    print("  \033[36m============================================================\033[0m")
    print()
    
    # Veritabani durumu kontrol
    has_db = os.path.exists(OPENCELLID_DB_FILE)
    token = _load_opencellid_token()
    
    if has_db:
        try:
            with open(OPENCELLID_DB_FILE, 'r') as f:
                line_count = sum(1 for _ in f) - 1
            print(f"  \033[32m[+] Lokal veritabani mevcut: {line_count} hucre kaydi\033[0m")
        except Exception:
            print(f"  \033[32m[+] Lokal veritabani mevcut\033[0m")
    else:
        print(f"  \033[33m[!] Hucre veritabani indirilmemis\033[0m")
        print(f"      Daha iyi sonuclar icin veritabanini indirin (264KB)")
        print()
        
        if not token:
            print("  \033[33m  Adim 1: https://opencellid.org/register adresine gidin\033[0m")
            print("  \033[33m  Adim 2: Ucretsiz kayit olun (email ile)\033[0m")
            print("  \033[33m  Adim 3: API Token'inizi kopyalayin\033[0m")
            print()
            
            inp_token = input("  API Token (bos=atla): ").strip()
            if inp_token and len(inp_token) > 10:
                _save_opencellid_token(inp_token)
                token = inp_token
                print(f"  \033[32m[+] Token kaydedildi\033[0m")
        
        if token:
            dl = input("  Turkiye veritabanini indir? [E/h]: ").strip().lower()
            if dl != 'h':
                _download_opencellid_db(token)
                has_db = os.path.exists(OPENCELLID_DB_FILE)
        
        if not has_db:
            print("\n  \033[33m[i] Veritabani olmadan sadece OSM (fiziksel kule) sonuclari gelir\033[0m")
    
    print()
    
    # Konum al
    print("  Konum secin:")
    print("    1) Sehir adi gir (Turkiye)")
    print("    2) Koordinat gir (enlem, boylam)")
    if phone and isinstance(phone, iPhoneDevice):
        print("    3) Son bilinen konum (cihazdan)")
    print()
    
    loc_choice = input("  Secim [1]: ").strip() or "1"
    
    lat, lon = 0, 0
    
    if loc_choice == "1":
        print(f"\n  Mevcut sehirler: {', '.join(sorted(TR_CITIES.keys()))}")
        city = input("\n  Sehir: ").strip().lower()
        
        # Yakin eslesme bul
        matched = None
        for name, coords in TR_CITIES.items():
            if city in name or name in city:
                matched = (name, coords)
                break
        
        if matched:
            lat, lon = matched[1]
            print(f"  \033[32m[+] {matched[0].title()}: {lat}, {lon}\033[0m")
        else:
            print(f"  \033[31m[-] Sehir bulunamadi. Koordinat girin.\033[0m")
            try:
                lat = float(input("  Enlem (lat): ").strip())
                lon = float(input("  Boylam (lon): ").strip())
            except ValueError:
                print("  [-] Gecersiz koordinat")
                return
    
    elif loc_choice == "2":
        try:
            lat = float(input("  Enlem (lat): ").strip())
            lon = float(input("  Boylam (lon): ").strip())
        except ValueError:
            print("  [-] Gecersiz koordinat")
            return
    
    elif loc_choice == "3" and phone and isinstance(phone, iPhoneDevice):
        # iPhone konum bilgisi
        print("  \033[33m[i] iOS konum bilgisi USB uzerinden alinamaz.\033[0m")
        print("  \033[33m    Google Maps'te konumunuza basin -> koordinatlari kopyalayin\033[0m")
        try:
            lat = float(input("  Enlem (lat): ").strip())
            lon = float(input("  Boylam (lon): ").strip())
        except ValueError:
            print("  [-] Gecersiz koordinat")
            return
    
    if lat == 0 and lon == 0:
        print("  [-] Konum belirtilmedi")
        return
    
    # Yaricap
    radius = input("  Yaricap km [5]: ").strip()
    try:
        radius = float(radius) if radius else 5.0
    except ValueError:
        radius = 5.0
    
    # Operator filtresi
    print("\n  Operator (ENTER=tum operatorler):")
    print("    1=Turkcell, 2=Vodafone, 3=Turk Telekom")
    mnc_input = input("  MNC [hepsi]: ").strip()
    # "hepsi", bos, veya gecersiz -> None (tum operatorler)
    mnc = None
    if mnc_input in ('1', '2', '3', '01', '02', '03', '04'):
        mnc = mnc_input.lstrip('0')  # 01->1, 02->2 vb
    
    print(f"\n  \033[36m[~] {lat:.4f}, {lon:.4f} etrafinda {radius}km icinde tarama yapiliyor...\033[0m")
    print(f"  \033[36m    Birden fazla ucretsiz kaynak deneniyor...\033[0m\n")
    
    towers = search_towers_by_location(lat, lon, radius, '286', mnc)
    
    if not towers:
        print("  \033[33m[!] Bu yaricapta sonuc yok. Daha genis aranıyor (100km)...\033[0m\n")
        towers = search_towers_by_location(lat, lon, 100, '286', mnc, verbose=False)
        
        if towers:
            print(f"  \033[32m[+] Genis aramada {len(towers)} hucre bulundu (en yakin {towers[0].get('distance_km',0):.1f}km)\033[0m\n")
        else:
            print("  \033[31m[-] Baz istasyonu bulunamadi.\033[0m")
            if not has_db:
                print()
                print("  \033[33m[!] OpenCellID veritabani indirilmemis!\033[0m")
                print("      Veritabani ile binlerce hucre bilgisi gelir.")
                print()
                print("  \033[32mNasil indirilir:\033[0m")
                print("    1. https://opencellid.org/register adresine git")
                print("    2. Ucretsiz kayit ol")
                print("    3. API Token'i kopyala")
                print("    4. Bu menuyu tekrar ac -> token'i yapistir")
            else:
                print("      Bu bolgede OpenCellID verisi yok")
                print("      Daha buyuk sehir deneyin: istanbul, ankara, izmir")
            return
    
    # Sonuclari goster
    print(f"  \033[32m[+] {len(towers)} baz istasyonu bulundu!\033[0m\n")
    
    # Tablo basliği
    print(f"  {'#':>3} {'Mesafe':>7} {'Radio':<6} {'Op':<12} {'Cell ID':<12} {'LAC/TAC':<8} {'Enlem':>10} {'Boylam':>10} {'Kaynak'}")
    print(f"  {'---':>3} {'------':>7} {'-----':<6} {'--':<12} {'-------':<12} {'-------':<8} {'-----':>10} {'------':>10} {'------'}")
    
    for i, t in enumerate(towers[:50]):  # Max 50 goster
        mnc_val = str(t.get('mnc', '?'))
        op_name = t.get('operator', TR_OPERATORS.get(mnc_val, mnc_val))
        
        dist_str = f"{t['distance_km']}km" if t.get('distance_km', 999) < 999 else "?"
        
        print(f"  {i+1:>3} {dist_str:>7} {str(t.get('radio','?')):<6} {str(op_name)[:11]:<12} "
              f"{str(t.get('cell_id','?')):<12} {str(t.get('lac','?')):<8} "
              f"{t.get('lat',0):>10.5f} {t.get('lon',0):>10.5f} {t.get('source','?')}")
    
    if len(towers) > 50:
        print(f"\n  ... ve {len(towers)-50} tane daha")
    
    # Kaydet
    print()
    save = input("  Sonuclari kaydet? [E/h]: ").strip().lower()
    if save != 'h':
        fname = f"towers_{lat:.4f}_{lon:.4f}_{int(time.time())}.json"
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump({
                'search': {'lat': lat, 'lon': lon, 'radius_km': radius, 'mcc': '286', 'mnc': mnc},
                'count': len(towers),
                'towers': towers,
            }, f, indent=2, ensure_ascii=False, default=str)
        print(f"  \033[32m[+] Kaydedildi: {fname}\033[0m")
    
    # Secilen kulenin konumunu goster
    print()
    pick = input("  Bir kuleyi sec (numara, 0=atla): ").strip()
    if pick and pick != "0":
        try:
            idx = int(pick) - 1
            if 0 <= idx < len(towers):
                t = towers[idx]
                print(f"\n  \033[32m[+] Secilen Baz Istasyonu:\033[0m")
                print(f"      Cell ID:  {t.get('cell_id', '?')}")
                print(f"      LAC/TAC:  {t.get('lac', '?')}")
                print(f"      MCC/MNC:  {t.get('mcc', '?')}/{t.get('mnc', '?')}")
                print(f"      Radio:    {t.get('radio', '?')}")
                op = TR_OPERATORS.get(str(t.get('mnc', '')), str(t.get('operator', '?')))
                print(f"      Operator: {op}")
                print(f"      Konum:    {t.get('lat', '?')}, {t.get('lon', '?')}")
                print(f"      Mesafe:   {t.get('distance_km', '?')} km")
                print(f"      Maps:     https://maps.google.com/?q={t.get('lat',0)},{t.get('lon',0)}")
        except (ValueError, IndexError):
            pass


# ============================================
# HLR LOOKUP VIA SMS
# ============================================

def hlr_via_sms_explain():
    """HLR lookup yontemi aciklama."""
    print("""
  \033[33m[*] HLR Lookup (Numara Sorgulama) Yontemleri:\033[0m
  
  1. \033[32mSMS Delivery Report\033[0m
     - Hedef numaraya SMS gonder
     - Delivery Report'tan IMSI, MSC, VLR bilgisi alinabilir
     - Calismasi icin: operator network'e erisim lazim
  
  2. \033[32mUSSD *#31#<numara>\033[0m  
     - Bazi operatorlerde numara bilgisi doner
     - Her operatorde calismaz
  
  3. \033[32mSS7/MAP SRI (SendRoutingInfo)\033[0m
     - Gercek HLR lookup - IMSI ve MSC adresi doner
     - SS7 network erisimi gerekli (bu tool'un ana amaci)
  
  4. \033[32mOnline HLR API\033[0m
     - hlrlookup.com, numberverify.com gibi servisler
     - API key ile ucretli sorgulama
  
  \033[31m[!] Telefon uzerinden direkt SS7 mesaji gonderilemez.\033[0m
  \033[31m    SS7 core network'te calisir, radyo arayuzunde degil.\033[0m
  \033[33m    Ama telefon ile baz istasyonu kesfi yapilabilir.\033[0m
""")


# ============================================
# TURKIYE OPERATOR TESPITI
# ============================================

TR_OPERATORS = {
    '28601': 'Turkcell',
    '28602': 'Vodafone TR',
    '28603': 'Turk Telekom Mobil',
    '28604': 'Turk Telekom Mobil',  # Eski Avea
}

def identify_operator(mcc, mnc):
    """MCC/MNC'den operator tespit et."""
    key = f'{mcc}{mnc:02d}' if isinstance(mnc, int) else f'{mcc}{mnc}'
    return TR_OPERATORS.get(key, f'Bilinmiyor ({key})')


# ============================================
# iPHONE MODULU (pymobiledevice3 / libimobiledevice)
# ============================================

class iPhoneDevice:
    """iPhone ile USB uzerinden iletisim."""
    
    def __init__(self):
        self.connected = False
        self.model = None
        self.udid = None
        self._lockdown = None
    
    def connect(self):
        """iPhone'a baglan."""
        
        # Yontem 1: pymobiledevice3 (en iyi yontem)
        try:
            from pymobiledevice3.lockdown import create_using_usbmux
            
            self._lockdown = create_using_usbmux()
            self.connected = True
            
            info = self._lockdown.all_values
            self.model = info.get('ProductType', '?')
            model_name = info.get('MarketingName', self.model)
            ios_ver = info.get('ProductVersion', '?')
            self.udid = info.get('UniqueDeviceID', '?')
            phone_num = info.get('PhoneNumber', '')
            
            # IMSI ve operator bilgisi
            carrier = info.get('CarrierBundleInfoArray', [{}])
            if carrier:
                c = carrier[0]
                self._mcc = c.get('MCC', '?')
                self._mnc = c.get('MNC', '?')
                self._imsi = c.get('InternationalMobileSubscriberIdentity', '?')
                self._carrier_name = c.get('CFBundleIdentifier', '?').replace('com.apple.', '')
            
            print(f"  \033[32m[+] iPhone baglandi: {model_name} (iOS {ios_ver})\033[0m")
            print(f"      Telefon: {phone_num}")
            print(f"      IMEI:    {info.get('InternationalMobileEquipmentIdentity', '?')}")
            print(f"      IMSI:    {self._imsi}")
            print(f"      MCC/MNC: {self._mcc}/{self._mnc}")
            print(f"      Carrier: {self._carrier_name}")
            return True
            
        except ImportError:
            pass
        except Exception as e:
            if 'No device' in str(e) or 'no running' in str(e):
                pass
            else:
                print(f"  [-] pymobiledevice3 hatasi: {e}")
        
        # Yontem 2: libimobiledevice (ideviceinfo)
        try:
            result = subprocess.run(['ideviceinfo'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout:
                self.connected = True
                for line in result.stdout.splitlines():
                    if 'ProductType' in line:
                        self.model = line.split(':')[-1].strip()
                    if 'ProductVersion' in line:
                        ios_ver = line.split(':')[-1].strip()
                
                print(f"  \033[32m[+] iPhone baglandi: {self.model} (iOS {ios_ver})\033[0m")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Baglanamadiysa
        print("  [-] iPhone bulunamadi!")
        print()
        print("  \033[33mYontem 1: pymobiledevice3 kur (onerilen)\033[0m")
        print("    pip install pymobiledevice3")
        print()
        print("  \033[33mYontem 2: libimobiledevice kur\033[0m")
        print("    Windows: choco install libimobiledevice")
        print("    Linux:   sudo apt install libimobiledevice-utils")
        print("    Mac:     brew install libimobiledevice")
        print()
        print("  \033[33mYontem 3: Manuel (Field Test Mode)\033[0m")
        print("    iPhone'da su numarayi ara: *3001#12345#*")
        print("    Bu gizli modu acar -> baz istasyonu bilgileri goruntulenir")
        
        return False
    
    def get_cell_info(self):
        """Cihaz, SIM ve mumkunse baz istasyonu bilgisi al."""
        info = {
            'serving_cell': None,
            'neighbor_cells': [],
            'operator': None,
            'network_type': None,
            'signal': {},
            'sim': {}
        }
        
        if self._lockdown:
            try:
                all_vals = self._lockdown.all_values
                
                # Carrier bilgisi
                carrier = all_vals.get('CarrierBundleInfoArray', [{}])
                if carrier:
                    c = carrier[0]
                    info['operator'] = c.get('CFBundleIdentifier', '?').replace('com.apple.', '')
                    info['sim']['mcc'] = c.get('MCC', '?')
                    info['sim']['mnc'] = c.get('MNC', '?')
                    info['sim']['carrier'] = info['operator']
                    info['mcc'] = c.get('MCC', '?')
                    info['mnc'] = c.get('MNC', '?')
                    info['imsi'] = c.get('InternationalMobileSubscriberIdentity', '?')
                
                info['sim']['phone'] = all_vals.get('PhoneNumber', '?')
                info['phone_number'] = all_vals.get('PhoneNumber', '?')
                info['imei'] = all_vals.get('InternationalMobileEquipmentIdentity', '?')
                info['imei2'] = all_vals.get('InternationalMobileEquipmentIdentity2', '?')
                info['iccid'] = all_vals.get('IntegratedCircuitCardIdentity', '?')
                info['meid'] = all_vals.get('MEID', '?')
                info['model'] = all_vals.get('MarketingName', all_vals.get('ProductType', '?'))
                info['ios_version'] = all_vals.get('ProductVersion', '?')
                info['baseband'] = all_vals.get('BasebandVersion', '?')
                info['serial'] = all_vals.get('SerialNumber', '?')
                
            except Exception as e:
                info['error'] = str(e)
            
            # Gelismis: diagnostics/mobilegestalt ile radio bilgisi dene
            self._try_advanced_cell_info(info)
        
        return info
    
    def _try_advanced_cell_info(self, info):
        """pymobiledevice3 gelismis servisleri ile baz istasyonu bilgisi almaya calis."""
        if not self._lockdown:
            return
        
        # Yontem 1: MobileGestalt - cihaz ozellikleri ve radio bilgisi
        try:
            from pymobiledevice3.services.mobile_gestalt import MobileGestaltService
            mg = MobileGestaltService(self._lockdown)
            
            gestalt_keys = [
                'CellularTelephonyCapability',
                'RegionalBehaviorNTSC',
                'BasebandFirmwareVersion',
                'BasebandChipId',
                'BasebandCertId',
                'BasebandKeyHashInformation',
                'BasebandRegionSKU',
                'kCTPostponementInfoPRIVersion',
                'kCTPostponementInfoPRLVersion',
            ]
            
            for key in gestalt_keys:
                try:
                    val = mg.get_single(key)
                    if val is not None:
                        info.setdefault('gestalt', {})[key] = val
                except Exception:
                    pass
        except ImportError:
            pass
        except Exception:
            pass
        
        # Yontem 2: Diagnostics service
        try:
            from pymobiledevice3.services.diagnostics import DiagnosticsService
            diag = DiagnosticsService(self._lockdown)
            
            try:
                ioreg = diag.ioregistry_search('BasebandTelephony')
                if ioreg:
                    info['radio_ioreg'] = {}
                    for key, val in ioreg.items() if isinstance(ioreg, dict) else []:
                        if isinstance(val, (str, int, float, bool)):
                            info['radio_ioreg'][key] = val
            except Exception:
                pass
            
            try:
                ioreg2 = diag.ioregistry_search('AppleARMPE')
                if ioreg2 and isinstance(ioreg2, dict):
                    for key in ['CellularTechnology', 'CarrierName', 'radio-type']:
                        if key in ioreg2:
                            info.setdefault('radio_ioreg', {})[key] = ioreg2[key]
            except Exception:
                pass
            
        except ImportError:
            pass
        except Exception:
            pass
        
        # Yontem 3: com.apple.coretelephony.CTCarrier benzeri bilgiler
        try:
            all_vals = self._lockdown.all_values
            
            # DataConnectionInfo, CurrentRadioTechnology gibi anahtarlar
            radio_keys = [
                'SupportedNetworkTypes', 'CurrentTelephonyInfo',
                'DataCapabilityString', 'DataServiceEnabled',
            ]
            
            for key in radio_keys:
                if key in all_vals and all_vals[key]:
                    info.setdefault('radio_extra', {})[key] = all_vals[key]
            
            # CTRegistration bilgisi (bazen carrier config icerir)
            if 'kCTRegistrationCurrentMaxAllowedSoC' in all_vals:
                info.setdefault('radio_extra', {})['MaxSoC'] = all_vals['kCTRegistrationCurrentMaxAllowedSoC']
                
        except Exception:
            pass
    
    def get_imei(self):
        """IMEI al."""
        if self._lockdown:
            try:
                vals = self._lockdown.all_values
                return vals.get('InternationalMobileEquipmentIdentity', 'Alinamadi')
            except Exception:
                pass
        
        try:
            result = subprocess.run(['ideviceinfo', '-k', 'InternationalMobileEquipmentIdentity'],
                                     capture_output=True, text=True, timeout=5)
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        return "Alinamadi"
    
    def get_imsi(self):
        """IMSI - iPhone'da direkt erisilemez."""
        return "Erisilemez (iOS kisitlamasi)"
    
    def get_sim_info(self):
        """SIM bilgileri."""
        info = {}
        if self._lockdown:
            try:
                vals = self._lockdown.all_values
                info['iccid'] = vals.get('IntegratedCircuitCardIdentity', '?')
                info['phone_number'] = vals.get('PhoneNumber', '?')
                info['operator'] = vals.get('CarrierBundleInfoArray', [{}])[0].get('CFBundleIdentifier', '?')
                info['imei'] = vals.get('InternationalMobileEquipmentIdentity', '?')
                info['imei2'] = vals.get('InternationalMobileEquipmentIdentity2', '?')
                info['meid'] = vals.get('MEID', '?')
                info['baseband'] = vals.get('BasebandVersion', '?')
                info['model'] = vals.get('MarketingName', '?')
                info['serial'] = vals.get('SerialNumber', '?')
            except Exception:
                pass
        return info
    
    def get_neighbor_cells(self):
        """Komsu baz istasyonlari - iOS kisitlamalari ve alternatifler."""
        print()
        print("  \033[33m============================================================\033[0m")
        print("  \033[33m  iPHONE BAZ ISTASYONU BILGISI ALMA YONTEMLERI\033[0m")
        print("  \033[33m============================================================\033[0m")
        print()
        print("  \033[31m[!] iOS baz istasyonu bilgisine programatik erisimi kisitlar.\033[0m")
        print("  \033[31m    Field Test (*3001#12345#*) yeni iOS surumlerinde\033[0m")
        print("  \033[31m    ve bazi operatorlerde calismayabilir.\033[0m")
        print()
        print("  \033[32m--- ALTERNATIF YONTEMLER ---\033[0m")
        print()
        print("  \033[36m1) App Store Uygulamalari (EN KOLAY):\033[0m")
        print("     - \033[1mCellMapper\033[0m      -> Baz istasyonu haritasi + Cell ID")
        print("     - \033[1mNetwork Cell Info\033[0m -> Cell ID, LAC, MCC, MNC, sinyal")
        print("     - \033[1mOpenSignal\033[0m       -> Sinyal olcum + hiz testi")
        print("     - \033[1mNetMonitor Pro\033[0m   -> Detayli hucre bilgisi")
        print()
        print("  \033[36m2) Ayarlar Uzerinden:\033[0m")
        print("     Ayarlar -> Genel -> Hakkinda ->")
        print("       Tasiyici   : Operatorunuz (Turk Telekom, Turkcell, vb)")
        print("       IMEI       : Cihaz kimlik numarasi")
        print("       ICCID      : SIM kart numarasi")
        print()
        print("  \033[36m3) Kisa Kod Alternatifleri:\033[0m")
        print("     \033[1m*#06#\033[0m            -> IMEI goster (tum telefonlarda calisir)")
        print("     \033[1m*3001#12345#*\033[0m    -> Field Test (iOS 15 ve alti)")
        print("     \033[1m*#67#\033[0m            -> Yonlendirme durumu")
        print("     \033[1m*#21#\033[0m            -> Cagri yonlendirme kontrol")
        print()
        print("  \033[36m4) CellMapper Kullanimi (Onerilen):\033[0m")
        print("     - App Store'dan 'CellMapper' indir")
        print("     - Uygulamayi ac -> Haritada konumunu gor")
        print("     - Bagli baz istasyonunu ve komsulari goster")
        print("     - Cell ID, TAC, PCI, EARFCN bilgileri mevcut")
        print()
        
        # pymobiledevice3 ile ne kadar radio bilgisi alabildik goster
        if self._lockdown:
            try:
                info = self.get_cell_info()
                has_extra = False
                
                if info.get('gestalt'):
                    has_extra = True
                    print("  \033[32m[+] Cihazdan alinan ek radio bilgileri:\033[0m")
                    for k, v in info['gestalt'].items():
                        print(f"      {k}: {v}")
                
                if info.get('radio_ioreg'):
                    has_extra = True
                    print("  \033[32m[+] IORegistry radio bilgileri:\033[0m")
                    for k, v in info['radio_ioreg'].items():
                        print(f"      {k}: {v}")
                
                if info.get('radio_extra'):
                    has_extra = True
                    print("  \033[32m[+] Ek telekom bilgileri:\033[0m")
                    for k, v in info['radio_extra'].items():
                        print(f"      {k}: {v}")
                
                if not has_extra:
                    print("  \033[90m[i] Ek radio bilgisi alinamadi (iOS kisitlamasi)\033[0m")
                    
            except Exception as e:
                print(f"  \033[90m[i] Gelismis sorgu hatasi: {e}\033[0m")
        
        return []


# ============================================
# ANA MENU
def _iphone_field_test_guide():
    """iPhone Field Test Mode ve alternatif yontemler rehberi."""
    print("""
  \033[33m============================================================
   iPHONE BAZ ISTASYONU BILGISI ALMA REHBERI
  ============================================================\033[0m

  \033[31m[!] UYARI: Field Test Mode (*3001#12345#*) iOS 16+ ve\033[0m
  \033[31m    bazi operatorlerde (Turk Telekom, AVEA) CALISMAZ.\033[0m
  \033[31m    "Istegi gerceklestiremedik" hatasi alabilirsiniz.\033[0m

  \033[32m========================================\033[0m
  \033[32m  YONTEM 1: APP STORE (EN KOLAY)\033[0m
  \033[32m========================================\033[0m

  \033[36mCellMapper (UCRETSIZ - EN ONERILEN):\033[0m
    1. App Store'dan "CellMapper" indir
    2. Uygulamayi ac, konum iznini ver
    3. Haritada bagli baz istasyonunu gorursun
    4. Gosterilen bilgiler:
       - Cell ID, TAC (Tracking Area Code)
       - PCI (Physical Cell ID)
       - EARFCN (frekans)
       - MCC/MNC (operator kodu)
       - Sinyal gucu (RSRP/RSRQ)
       - Komsu hucre bilgileri
    5. Bu degerleri secim 5'e girip konum bulabilirsin

  \033[36mDiger Uygulamalar:\033[0m
    - \033[1mNetwork Cell Info Lite\033[0m  -> Cell ID + harita
    - \033[1mNetMonitor Pro\033[0m          -> Detayli radio bilgisi
    - \033[1mOpenSignal\033[0m              -> Sinyal + hiz testi
    - \033[1mSignal Finder\033[0m           -> Baz istasyonu yonlendirme

  \033[32m========================================\033[0m
  \033[32m  YONTEM 2: KISA KODLAR\033[0m
  \033[32m========================================\033[0m

  \033[36mCalisan Kodlar (tum iOS):\033[0m
    \033[1m*#06#\033[0m         -> IMEI numarasi (her zaman calisir)
    \033[1m*#21#\033[0m         -> Cagri yonlendirme durumu
    \033[1m*#67#\033[0m         -> Mesgulde yonlendirme
    \033[1m*#62#\033[0m         -> Ulasilamadiginda yonlendirme
    \033[1m*#61#\033[0m         -> Cevaplanmadiginda yonlendirme
    \033[1m##002#\033[0m        -> Tum yonlendirmeleri iptal et

  \033[36mField Test (iOS 15 ve alti):\033[0m
    \033[1m*3001#12345#*\033[0m -> Field Test Mode (eski iOS)

  \033[32m========================================\033[0m
  \033[32m  YONTEM 3: AYARLAR\033[0m
  \033[32m========================================\033[0m

    Ayarlar -> Genel -> Hakkinda:
      - Tasiyici     : Operator adi
      - Ag           : Bagli ag tipi
      - IMEI         : Cihaz kimligi
      - ICCID        : SIM numarasi
      - Modem Firmware : Baseband surumu

  \033[32m========================================\033[0m
  \033[32m  CELL ID'DEN KONUM BULMA\033[0m
  \033[32m========================================\033[0m

    CellMapper'dan veya baska uygulamadan Cell ID alinca:
      -> Bu menuye don -> Secim 5 (Cell ID -> Konum)
      -> MCC: 286 (Turkiye)
      -> MNC: 01 (Turkcell) / 02 (Vodafone) / 03 (Turk Telekom)
      -> TAC ve Cell ID gir
      -> Google Maps linki alirsin

  \033[33mTurk Operator MNC Kodlari:\033[0m
    286/01 = Turkcell
    286/02 = Vodafone
    286/03 = Turk Telekom (AVEA/TTNET Mobil)
    286/04 = Bimcell (Turkcell MVNO)
""")


# ============================================

def phone_menu():
    """Telefon kesfif menusu."""
    import signal
    # Ctrl+C'yi bu modülde yakala (sigploit.py'daki global handler sys.exit yapiyor - engelle)
    original_handler = signal.getsignal(signal.SIGINT)
    def _phone_sigint(sig, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _phone_sigint)
    
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 60)
    print(" SigPloit Telefon Kesif Modulu")
    print(" Baz istasyonu tarama ve bilgi toplama")
    print("=" * 60)
    print()
    print("Baglanti Yontemi:")
    print("  1) ADB (Android - USB Debugging)")
    print("  2) iPhone (USB - pymobiledevice3)")
    print("  3) AT Komutlari (USB Modem)")
    print("  4) HLR Lookup bilgi")
    print("  5) iPhone Field Test Mode rehberi")
    print()
    
    choice = input("Secim [2]: ").strip() or "2"
    
    if choice == "4":
        hlr_via_sms_explain()
        input("\nDevam etmek icin Enter'a basin...")
        return
    
    if choice == "5":
        _iphone_field_test_guide()
        input("\nDevam etmek icin Enter'a basin...")
        return
    
    phone = None
    
    if choice == "1":
        phone = ADBPhone()
        if not phone.connect():
            input("\nDevam etmek icin Enter'a basin...")
            return
    elif choice == "2":
        phone = iPhoneDevice()
        if not phone.connect():
            input("\nDevam etmek icin Enter'a basin...")
            return
    elif choice == "3":
        phone = ATPhone()
        if not phone.connect():
            input("\nDevam etmek icin Enter'a basin...")
            return
    
    # Ana dongu
    while True:
      try:
        print(f"\n{'='*60}")
        print(" Telefon Kesif Islemleri")
        print(f"{'='*60}")
        print("  1) Cihaz + SIM + Operator bilgisi")
        print("  2) Cevredeki baz istasyonlari tara")
        print("  3) SIM / IMEI / IMSI detay")
        print("  4) Sinyal gucu olc")
        print("  5) Cell ID -> Konum donustur")
        print("  \033[32m  6) Yakinlardaki baz istasyonlarini bul (UCRETSIZ)\033[0m")
        print("  7) Surekli izleme (her 5sn)")
        print("  8) Tum bilgileri kaydet (JSON)")
        print("  9) Alternatif yontemler rehberi")
        print("  0) Geri don")
        
        op = input("\nSecim: ").strip()
        
        if op == "0":
            break
        
        elif op == "1":
            print("\n  \033[36m[~] Baz istasyonu bilgisi aliniyor...\033[0m")
            info = phone.get_cell_info()
            
            if isinstance(phone, ADBPhone):
                if info.get('serving_cell'):
                    sc = info['serving_cell']
                    print(f"\n  \033[32m[+] Bagli Baz Istasyonu:\033[0m")
                    print(f"      MCC:     {sc.get('mcc', '?')}")
                    print(f"      MNC:     {sc.get('mnc', '?')}")
                    print(f"      LAC/TAC: {sc.get('lac_tac', '?')}")
                    print(f"      Cell ID: {sc.get('cell_id', '?')}")
                    if sc.get('pci'):
                        print(f"      PCI:     {sc['pci']}")
                    
                    mcc = sc.get('mcc', '')
                    mnc = sc.get('mnc', '')
                    if mcc and mnc:
                        op_name = identify_operator(mcc, mnc)
                        print(f"      Operator: \033[33m{op_name}\033[0m")
                else:
                    print("  [-] Baz istasyonu bilgisi alinamadi")
                
                if info.get('operator'):
                    print(f"      Network:  {info['operator']}")
                if info.get('network_type'):
                    print(f"      Teknoloji: {info['network_type']}")
            
            elif isinstance(phone, iPhoneDevice):
                print(f"\n  \033[32m[+] iPhone Bilgileri:\033[0m")
                print(f"      Model:      {info.get('model', '?')}")
                print(f"      iOS:        {info.get('ios_version', '?')}")
                print(f"      Baseband:   {info.get('baseband', '?')}")
                print(f"      Seri No:    {info.get('serial', '?')}")
                print()
                print(f"  \033[32m[+] SIM / Operator:\033[0m")
                print(f"      Telefon No: {info.get('phone_number', '?')}")
                print(f"      IMEI:       {info.get('imei', '?')}")
                print(f"      IMEI 2:     {info.get('imei2', '?')}")
                print(f"      IMSI:       {info.get('imsi', '?')}")
                print(f"      ICCID:      {info.get('iccid', '?')}")
                print(f"      MCC/MNC:    {info.get('mcc', '?')}/{info.get('mnc', '?')}")
                print(f"      Operator:   {info.get('operator', '?')}")
                
                mcc = info.get('mcc', '')
                mnc = info.get('mnc', '')
                if mcc and mnc:
                    op_name = identify_operator(mcc, mnc)
                    print(f"      Operator:   \033[33m{op_name}\033[0m")
                
                print(f"\n  \033[33m[!] iOS baz istasyonu (Cell ID) bilgisini kisitlar.\033[0m")
                print(f"      Cell ID icin Tower Locator / CellMapper uygulamasini kullanin")
                print(f"      Veya menu 8'i secin (rehber)")
            
            else:
                # AT modem
                for key, val in info.items():
                    if not key.endswith('_raw'):
                        print(f"      {key}: {val}")
        
        elif op == "2":
            print("\n  \033[36m[~] Cevredeki baz istasyonlari taraniyor...\033[0m")
            
            if isinstance(phone, iPhoneDevice):
                phone.get_neighbor_cells()  # Rehber gosterir
            elif isinstance(phone, ADBPhone):
                cells = phone.get_neighbor_cells()
                if cells:
                    print(f"\n  \033[32m[+] {len(cells)} baz istasyonu bulundu:\033[0m\n")
                    print(f"  {'#':>3} {'Tech':<8} {'MCC':<5} {'MNC':<5} {'LAC/TAC':<8} {'Cell ID':<12} {'PCI':<6} {'RSRP':<8} {'Durum'}")
                    print(f"  {'---':>3} {'----':<8} {'---':<5} {'---':<5} {'-------':<8} {'-------':<12} {'---':<6} {'----':<8} {'-----'}")
                    
                    for i, cell in enumerate(cells):
                        status = '\033[32mBAGLI\033[0m' if cell.get('registered') else '\033[90mkomsu\033[0m'
                        print(f"  {i+1:>3} {cell.get('tech','?'):<8} {cell.get('mcc','?'):<5} {cell.get('mnc','?'):<5} "
                              f"{cell.get('lac_tac','?'):<8} {cell.get('cell_id','?'):<12} {cell.get('pci','?'):<6} "
                              f"{cell.get('rsrp','?'):<8} {status}")
                else:
                    print("  [-] Komsu baz istasyonu bulunamadi")
            else:
                info = phone.get_cell_info()
                if info.get('neighbor_raw'):
                    print(f"  {info['neighbor_raw']}")
                else:
                    print("  [-] Bu modem neighbor cell desteklemiyor")
        
        elif op == "3":
            print("\n  \033[36m[~] Cihaz bilgileri aliniyor...\033[0m")
            imei = phone.get_imei()
            imsi = phone.get_imsi()
            
            print(f"\n  IMEI:  {imei}")
            print(f"  IMSI:  {imsi}")
            
            if isinstance(phone, ADBPhone):
                sim = phone.get_sim_info()
                print(f"  Operator: {sim.get('operator', '?')}")
                print(f"  MCC/MNC:  {sim.get('operator_numeric', '?')}")
                print(f"  SIM:      {sim.get('sim_state', '?')}")
                print(f"  Network:  {sim.get('network_type', '?')}")
            elif isinstance(phone, iPhoneDevice):
                sim = phone.get_sim_info()
                print(f"  ICCID:      {sim.get('iccid', '?')}")
                print(f"  Telefon No: {sim.get('phone_number', '?')}")
                print(f"  Operator:   {sim.get('operator', '?')}")
                print(f"  IMEI 2:     {sim.get('imei2', '?')}")
                print(f"  MEID:       {sim.get('meid', '?')}")
                print(f"  Baseband:   {sim.get('baseband', '?')}")
                print(f"  Model:      {sim.get('model', '?')}")
                print(f"  Seri No:    {sim.get('serial', '?')}")
            elif isinstance(phone, ATPhone):
                iccid = phone.get_iccid()
                print(f"  ICCID: {iccid}")
        
        elif op == "4":
            print("\n  \033[36m[~] Sinyal olculuyor...\033[0m")
            if isinstance(phone, iPhoneDevice):
                print("  \033[33m[!] iPhone sinyal gucunu programatik olarak vermez.\033[0m")
                print("  \033[33m    CellMapper veya Network Cell Info uygulamasini kullanin.\033[0m")
                print()
                print("  \033[36mSinyal Yorumu (RSRP degeri icin):\033[0m")
                print("    -80  ile -50  dBm  = \033[32mMukemmel\033[0m")
                print("    -90  ile -80  dBm  = \033[32mIyi\033[0m")
                print("    -100 ile -90  dBm  = \033[33mOrta\033[0m")
                print("    -110 ile -100 dBm  = \033[31mZayif\033[0m")
                print("    -120 ile -110 dBm  = \033[31mCok zayif\033[0m")
            else:
                for i in range(5):
                    info = phone.get_cell_info()
                    if isinstance(phone, ATPhone) and info.get('rssi_dbm'):
                        bars = min(5, max(0, (info['rssi_dbm'] + 113) // 20))
                        bar_str = '█' * bars + '░' * (5 - bars)
                        print(f"  [{i+1}/5] RSSI: {info['rssi_dbm']} dBm [{bar_str}]")
                    elif isinstance(phone, ADBPhone) and info.get('signal'):
                        print(f"  [{i+1}/5] {info['signal'].get('raw', '?')[:60]}")
                    time.sleep(2)
        
        elif op == "5":
            # iPhone'dan MCC/MNC otomatik al
            auto_mcc = "286"
            auto_mnc = ""
            if isinstance(phone, iPhoneDevice) and hasattr(phone, '_mcc'):
                auto_mcc = getattr(phone, '_mcc', '286')
                auto_mnc = getattr(phone, '_mnc', '')
            
            print(f"\n  \033[33m[*] Cell ID'yi Tower Locator uygulamasindan alin:\033[0m")
            print(f"      Baz istasyonuna tiklayin -> Cell ID degerini girin")
            print(f"      LAC/TAC yoksa bos birakin, sadece Cell ID ile arar\n")
            
            mcc = input(f"  MCC [{auto_mcc}]: ").strip() or auto_mcc
            mnc = input(f"  MNC [{auto_mnc}]: ").strip() or auto_mnc
            lac = input("  LAC/TAC (yoksa bos birakin): ").strip()
            cid = input("  Cell ID: ").strip()
            
            if mnc and cid:
                print("\n  \033[36m[~] Konum araniyor...\033[0m")
                if not lac:
                    print("  \033[33m[i] LAC/TAC girilmedi, Cell ID ile aranacak\033[0m")
                loc = cell_to_location(mcc, mnc, lac, cid)
                if loc:
                    print(f"\n  \033[32m[+] Konum bulundu!\033[0m")
                    print(f"      Enlem:    {loc['lat']}")
                    print(f"      Boylam:   {loc['lon']}")
                    print(f"      Yaricap:  {loc['range']}m")
                    print(f"      Kaynak:   {loc['source']}")
                    if loc.get('lac_found'):
                        print(f"      LAC/TAC:  {loc['lac_found']}")
                    print(f"      Maps:     https://maps.google.com/?q={loc['lat']},{loc['lon']}")
                else:
                    print("  [-] Konum bulunamadi")
                    print("      Olasi sebepler:")
                    print("        - Cell ID veritabaninda kayitli degil")
                    print("        - Cell ID hex ise decimal'e cevirin")
                    print("        - LAC/TAC girilirse sonuc iyilesebilir")
            else:
                print("  [-] MNC ve Cell ID gerekli")
                print("      Tower Locator uygulamasindan Cell ID'yi alin")
        
        elif op == "6":
            tower_search_menu(phone)
        
        elif op == "7":
            if isinstance(phone, iPhoneDevice):
                print("\n  \033[33m[!] iPhone icin CellMapper uygulamasini kullanin.\033[0m")
                print("  Cihaz bilgileri her 10 saniyede yenilenecek (Ctrl+C ile dur)...")
                try:
                    while True:
                        info = phone.get_cell_info()
                        ts = datetime.datetime.now().strftime('%H:%M:%S')
                        sim = info.get('sim', {})
                        print(f"  [{ts}] MCC:{sim.get('mcc','?')} MNC:{sim.get('mnc','?')} "
                              f"Op:{sim.get('carrier','?')} Tel:{sim.get('phone','?')}")
                        time.sleep(10)
                except KeyboardInterrupt:
                    print("\n  [+] Izleme durduruldu.")
            else:
                print("\n  \033[36m[~] Surekli izleme baslatildi (Ctrl+C ile dur)...\033[0m\n")
                try:
                    while True:
                        info = phone.get_cell_info()
                        ts = datetime.datetime.now().strftime('%H:%M:%S')
                        
                        if isinstance(phone, ADBPhone) and info.get('serving_cell'):
                            sc = info['serving_cell']
                            print(f"  [{ts}] Cell:{sc.get('cell_id','?')} LAC:{sc.get('lac_tac','?')} "
                                  f"MCC:{sc.get('mcc','?')} MNC:{sc.get('mnc','?')} "
                                  f"Net:{info.get('network_type','?')}")
                        elif isinstance(phone, ATPhone):
                            cid = info.get('cell_id', info.get('eci', '?'))
                            lac = info.get('lac', info.get('tac', '?'))
                            rssi = info.get('rssi_dbm', '?')
                            print(f"  [{ts}] Cell:{cid} LAC:{lac} RSSI:{rssi}dBm "
                                  f"Op:{info.get('operator','?')} Tech:{info.get('technology','?')}")
                        
                        time.sleep(5)
                except KeyboardInterrupt:
                    print("\n  [+] Izleme durduruldu.")
        
        elif op == "8":
            print("\n  \033[36m[~] Tum bilgiler toplaniyor...\033[0m")
            
            report = {
                'timestamp': datetime.datetime.now().isoformat(),
                'device': {},
                'cell_info': phone.get_cell_info(),
                'imei': phone.get_imei(),
            }
            
            if isinstance(phone, ADBPhone):
                report['device'] = {
                    'model': phone.model,
                    'device_id': phone.device_id,
                }
                report['sim'] = phone.get_sim_info()
                report['neighbor_cells'] = phone.get_neighbor_cells()
            elif isinstance(phone, iPhoneDevice):
                report['device'] = {
                    'model': phone.model,
                    'udid': str(phone.udid),
                }
                report['sim'] = phone.get_sim_info()
            
            fname = f"phone_recon_{int(time.time())}.json"
            with open(fname, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"\n  \033[32m[+] Kaydedildi: {fname}\033[0m")
        
        elif op == "9":
            _iphone_field_test_guide()
      
      except KeyboardInterrupt:
        print("\n\n  [!] Ctrl+C - Ana menuye donuluyor...")
        signal.signal(signal.SIGINT, original_handler)
        return
      except Exception as e:
        print(f"\n  \033[31m[-] Hata: {e}\033[0m")
        input("  Devam etmek icin Enter'a basin...")
    
    signal.signal(signal.SIGINT, original_handler)
    print("\n[+] Telefon kesif modulu kapatildi.")


if __name__ == '__main__':
    phone_menu()
