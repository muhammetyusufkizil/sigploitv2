#!/usr/bin/env python3
"""
SigPloit Web Security Scanner Module
======================================
Web sitesi guvenlik tarayici.

Asamalar:
1. DNS/WHOIS bilgi toplama
2. Subdomain kesfi (subfinder + crt.sh + brute force)
3. HTTP durum kontrolu
4. Port taramasi (nmap)
5. Guvenlik analizi (header, SSL, WAF, hassas dosya)
6. Zafiyet taramasi (nuclei)
7. Rapor olusturma (TXT + JSON)
"""

import subprocess
import sys
import os
import json
import time
import re
import socket
import ssl
import datetime
import random
import string
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ============================================
# YAPILANDIRMA
# ============================================

COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'owa',
    'admin', 'panel', 'cpanel', 'whm', 'portal', 'login', 'sso',
    'api', 'app', 'mobile', 'dev', 'test', 'staging', 'uat', 'qa',
    'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
    'mx', 'mx1', 'mx2', 'relay', 'mailgw',
    'vpn', 'remote', 'gateway', 'proxy', 'fw', 'firewall',
    'cdn', 'static', 'assets', 'img', 'images', 'media', 'files',
    'db', 'database', 'mysql', 'postgres', 'mssql', 'mongo', 'redis',
    'git', 'gitlab', 'github', 'svn', 'jenkins', 'ci', 'build',
    'monitor', 'nagios', 'zabbix', 'grafana', 'kibana', 'elk',
    'cms', 'blog', 'wordpress', 'wp', 'joomla', 'drupal',
    'intranet', 'extranet', 'internal', 'corp', 'office',
    'backup', 'bak', 'old', 'new', 'v2', 'beta', 'alpha',
    'shop', 'store', 'ecommerce', 'pay', 'payment',
    'docs', 'wiki', 'help', 'support', 'faq', 'forum',
    'cloud', 'aws', 'azure', 'gcp', 's3',
    'crm', 'erp', 'hr', 'finance',
    'autodiscover', 'exchange', 'lync', 'sip',
    'secure', 'ssl', 'waf',
    'web', 'www2', 'www3', 'web1', 'web2',
    'host', 'server', 'node1', 'node2',
    'status', 'health', 'ping',
    'video', 'stream', 'live', 'tv',
    'mx10', 'mx20', 'mail2', 'smtp2',
    'ns', 'ns4', 'dns3',
    'ebys', 'ebelediye', 'mecliskarari', 'encumenkarari',
    'bilgiislem', 'otomasyon', 'gis', 'harita',
]

SENSITIVE_PATHS = [
    '/.env',
    '/.git/config',
    '/.git/HEAD',
    '/.gitignore',
    '/wp-config.php.bak',
    '/wp-config.php.old',
    '/wp-config.php.save',
    '/backup/',
    '/admin/',
    '/administrator/',
    '/.htaccess',
    '/.htpasswd',
    '/robots.txt',
    '/sitemap.xml',
    '/server-status',
    '/server-info',
    '/phpinfo.php',
    '/info.php',
    '/web.config',
    '/.DS_Store',
    '/config.php.bak',
    '/database.sql',
    '/dump.sql',
    '/backup.zip',
    '/backup.tar.gz',
    '/.svn/entries',
    '/crossdomain.xml',
    '/elmah.axd',
    '/trace.axd',
    '/api/swagger',
    '/api/docs',
    '/debug/',
    '/test/',
    '/temp/',
    '/tmp/',
    '/log/',
    '/logs/',
]

SECURITY_HEADERS = [
    ('X-Frame-Options', 'Clickjacking korumasi'),
    ('Content-Security-Policy', 'CSP - icerik guvenligi'),
    ('X-Content-Type-Options', 'MIME sniffing engelleme'),
    ('Strict-Transport-Security', 'HSTS - zorunlu HTTPS'),
    ('X-XSS-Protection', 'XSS korumasi'),
    ('Permissions-Policy', 'Tarayici izin politikasi'),
    ('Referrer-Policy', 'Referrer bilgi kontrolu'),
]

INFO_LEAK_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

COMMON_PORTS = '21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,8888,9090,27017'
HTTP_PROBE_PATHS = ['/', '/.env', '/.git/config', '/admin/', '/login', '/robots.txt']
# Optimized: Top 1000 ports (nmap-like) instead of full 65535 for Python fallback
TOP_PORTS = [
    21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 113, 119, 135, 139, 143, 161, 179,
    389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636, 646, 873, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1434, 1521, 1720, 1723, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4000, 4443, 4899,
    5000, 5001, 5003, 5009, 5050, 5060, 5101, 5190, 5357, 5432, 5631, 5666,
    5800, 5900, 5901, 6000, 6001, 6379, 6646, 7000, 7001, 7002, 7070, 7080,
    8000, 8008, 8009, 8080, 8081, 8083, 8088, 8090, 8443, 8800, 8880, 8888,
    9000, 9001, 9043, 9060, 9080, 9090, 9100, 9200, 9300, 9443, 9999, 10000,
    10443, 11211, 12345, 27017, 27018, 28017, 50000, 50030, 50070,
]

# Technology fingerprint patterns
TECH_FINGERPRINTS = {
    'WordPress': {
        'paths': ['/wp-login.php', '/wp-admin/', '/wp-content/'],
        'headers': {},
        'body': ['wp-content', 'wp-includes', 'WordPress'],
    },
    'Joomla': {
        'paths': ['/administrator/', '/components/'],
        'headers': {},
        'body': ['Joomla!', '/media/jui/', 'joomla'],
    },
    'Drupal': {
        'paths': ['/core/misc/drupal.js', '/sites/default/'],
        'headers': {'X-Generator': 'Drupal'},
        'body': ['Drupal', 'drupal.js'],
    },
    'Laravel': {
        'paths': [],
        'headers': {},
        'body': ['Laravel', 'laravel_session'],
        'cookies': ['laravel_session', 'XSRF-TOKEN'],
    },
    'Django': {
        'paths': ['/admin/'],
        'headers': {},
        'body': ['csrfmiddlewaretoken', 'Django'],
        'cookies': ['csrftoken', 'sessionid'],
    },
    'React': {
        'paths': [],
        'headers': {},
        'body': ['react-root', '__NEXT_DATA__', 'data-reactroot', '_next/static'],
    },
    'Vue.js': {
        'paths': [],
        'headers': {},
        'body': ['Vue.js', 'data-v-', '__vue__'],
    },
    'Angular': {
        'paths': [],
        'headers': {},
        'body': ['ng-version', 'ng-app', 'angular.js', 'angular.min.js'],
    },
    'ASP.NET': {
        'paths': [],
        'headers': {'X-AspNet-Version': '', 'X-Powered-By': 'ASP.NET'},
        'body': ['__VIEWSTATE', '__EVENTVALIDATION', 'aspnet'],
    },
    'PHP': {
        'paths': [],
        'headers': {'X-Powered-By': 'PHP'},
        'body': [],
    },
    'nginx': {
        'paths': [],
        'headers': {'Server': 'nginx'},
        'body': [],
    },
    'Apache': {
        'paths': [],
        'headers': {'Server': 'Apache'},
        'body': [],
    },
    'IIS': {
        'paths': [],
        'headers': {'Server': 'Microsoft-IIS'},
        'body': [],
    },
    'Tomcat': {
        'paths': ['/manager/html'],
        'headers': {},
        'body': ['Apache Tomcat'],
    },
    'Spring Boot': {
        'paths': ['/actuator', '/actuator/health', '/actuator/info'],
        'headers': {},
        'body': ['Whitelabel Error Page', 'spring'],
    },
    'Express.js': {
        'paths': [],
        'headers': {'X-Powered-By': 'Express'},
        'body': [],
    },
}

# XSS test payloads (safe - won't actually exploit)
XSS_PROBES = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '{{7*7}}',  # Template injection
]

# SQL injection test payloads (safe - detection only)
SQLI_PROBES = [
    "' OR '1'='1",
    "1' AND '1'='1",
    "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:0'--",
]


def _ensure_tool(tool_name, install_cmd):
    if _check_tool(tool_name):
        return True
    if not _check_tool('go'):
        print(f"  \033[31m[-]\033[0m go bulunamadi, {tool_name} otomatik kurulamiyor.")
        return False
    print(f"  \033[33m[!]\033[0m {tool_name} kurulu degil, kurulmaya calisiliyor...")
    _run_cmd(install_cmd, timeout=300)
    if _check_tool(tool_name):
        print(f"  \033[32m[+]\033[0m {tool_name} kuruldu.")
        return True
    print(f"  \033[31m[-]\033[0m {tool_name} kurulumu basarisiz.")
    return False


# ============================================
# YARDIMCI FONKSIYONLAR
# ============================================

def _run_cmd(cmd, timeout=30):
    """Komutu calistir, stdout dondur."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='ignore'
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ''
    except Exception:
        return ''


def _check_tool(name):
    """Harici arac kurulu mu kontrol et."""
    try:
        result = subprocess.run(
            ['which', name] if os.name != 'nt' else ['where', name],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_ip(domain):
    """Domain'i IP'ye coz."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _get_title(html):
    """HTML'den title cek."""
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:60]
    return ''


# ============================================
# ASAMA 1: DNS/WHOIS BILGI TOPLAMA
# ============================================

def stage_dns_whois(domain, results):
    """DNS kayitlari ve WHOIS bilgisi topla."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 1: DNS/WHOIS Bilgi Toplama\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    info = {'domain': domain, 'ip': None, 'ns': [], 'mx': [], 'txt': [],
            'whois': '', 'cdn': None, 'geo': None}

    # A Record
    ip = _resolve_ip(domain)
    info['ip'] = ip
    if ip:
        print(f"  \033[32m[+]\033[0m A Record:     {ip}")
    else:
        print(f"  \033[31m[-]\033[0m A Record:     Cozulemedi")

    # NS Records
    stderr_redir = '2>NUL' if os.name == 'nt' else '2>/dev/null'
    ns_out = _run_cmd(f'nslookup -type=NS {domain} {stderr_redir} || dig NS {domain} +short {stderr_redir}')
    ns_servers = re.findall(r'nameserver\s*=\s*(\S+)|^(\S+\.)\s*$', ns_out, re.MULTILINE)
    for ns in ns_servers:
        server = (ns[0] or ns[1]).rstrip('.')
        if server and server not in info['ns']:
            info['ns'].append(server)
    if info['ns']:
        print(f"  \033[32m[+]\033[0m NS Records:   {', '.join(info['ns'][:4])}")
    
    # CDN/Cloudflare tespiti
    cf_indicators = ['cloudflare', 'cloudfront', 'akamai', 'fastly', 'incapsula']
    for ns in info['ns']:
        for cdn in cf_indicators:
            if cdn in ns.lower():
                info['cdn'] = cdn.capitalize()
                break
    
    if info['cdn']:
        print(f"  \033[33m[!]\033[0m CDN/WAF:      {info['cdn']} tespit edildi")
    else:
        # Header'dan kontrol
        if HAS_REQUESTS and ip:
            try:
                resp = requests.get(f'https://{domain}', timeout=5, verify=False,
                                  allow_redirects=True,
                                  headers={'User-Agent': 'Mozilla/5.0'})
                if 'cf-ray' in resp.headers:
                    info['cdn'] = 'Cloudflare'
                    print(f"  \033[33m[!]\033[0m CDN/WAF:      Cloudflare (cf-ray header)")
                elif 'x-cdn' in resp.headers:
                    info['cdn'] = resp.headers.get('x-cdn', 'Unknown CDN')
                    print(f"  \033[33m[!]\033[0m CDN:          {info['cdn']}")
            except Exception:
                pass
    
    # MX Records
    mx_out = _run_cmd(f'nslookup -type=MX {domain} {stderr_redir} || dig MX {domain} +short {stderr_redir}')
    mx_records = re.findall(r'mail exchanger\s*=\s*\d+\s+(\S+)|^\d+\s+(\S+)\s*$', mx_out, re.MULTILINE)
    for mx in mx_records:
        server = (mx[0] or mx[1]).rstrip('.')
        if server and server not in info['mx']:
            info['mx'].append(server)
    if info['mx']:
        print(f"  \033[32m[+]\033[0m MX Records:   {', '.join(info['mx'][:3])}")

    # TXT Records (SPF, DMARC vb.)
    txt_out = _run_cmd(f'nslookup -type=TXT {domain} {stderr_redir} || dig TXT {domain} +short {stderr_redir}')
    txt_records = re.findall(r'"([^"]+)"', txt_out)
    info['txt'] = txt_records[:5]
    if info['txt']:
        for txt in info['txt']:
            label = 'SPF' if 'spf' in txt.lower() else 'DMARC' if 'dmarc' in txt.lower() else 'TXT'
            print(f"  \033[32m[+]\033[0m {label}:         {txt[:70]}...")

    # WHOIS
    whois_out = _run_cmd(f'whois {domain} {stderr_redir}', timeout=10)
    if whois_out:
        info['whois'] = whois_out[:2000]
        # Onemli bilgileri cek
        for pattern, label in [
            (r'Registrar:\s*(.+)', 'Registrar'),
            (r'Creation Date:\s*(.+)', 'Olusturma'),
            (r'Registry Expiry Date:\s*(.+)', 'Bitis'),
            (r'Registrant Organization:\s*(.+)', 'Kurum'),
        ]:
            match = re.search(pattern, whois_out, re.IGNORECASE)
            if match:
                print(f"  \033[32m[+]\033[0m {label:12s}  {match.group(1).strip()}")

    # GeoIP
    if ip and HAS_REQUESTS:
        try:
            resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if resp.status_code == 200:
                geo = resp.json()
                info['geo'] = geo
                print(f"  \033[32m[+]\033[0m Konum:        {geo.get('city','?')}, {geo.get('country','?')} ({geo.get('org','?')})")
        except Exception:
            pass

    results['dns_whois'] = info
    return info


# ============================================
# ASAMA 2: SUBDOMAIN KESFI
# ============================================

def stage_subdomain_enum(domain, results):
    """Subdomain kesfet: subfinder + crt.sh + brute force."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 2: Subdomain Kesfi\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    subdomains = set()
    httpx_200 = []

    # 1. subfinder
    if _ensure_tool('subfinder', 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'):
        print("  \033[36m[~]\033[0m subfinder ile taranıyor...", end=" ", flush=True)
        out = _run_cmd(f'subfinder -d {domain} -silent -timeout 30', timeout=60)
        if out:
            found = [line.strip() for line in out.splitlines() if line.strip()]
            subdomains.update(found)
            print(f"\033[32m{len(found)} bulundu\033[0m")
        else:
            print("\033[33m0\033[0m")
    else:
        print("  \033[33m[!]\033[0m subfinder kurulamadigi icin subdomain kesfi eksik kalabilir.")

    # 2. crt.sh
    if HAS_REQUESTS:
        print("  \033[36m[~]\033[0m crt.sh sertifika sorgusu...", end=" ", flush=True)
        try:
            resp = requests.get(
                f'https://crt.sh/?q=%.{domain}&output=json',
                timeout=15,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            if resp.status_code == 200:
                crt_data = resp.json()
                crt_subs = set()
                for entry in crt_data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f'.{domain}') or sub == domain:
                            if '*' not in sub:
                                crt_subs.add(sub)
                subdomains.update(crt_subs)
                print(f"\033[32m{len(crt_subs)} bulundu\033[0m")
            else:
                print(f"\033[33mHTTP {resp.status_code}\033[0m")
        except Exception as e:
            print(f"\033[31m{str(e)[:30]}\033[0m")

    # 3. DNS Brute Force
    print(f"  \033[36m[~]\033[0m DNS brute force ({len(COMMON_SUBDOMAINS)} kelime)...", end=" ", flush=True)
    brute_count = 0

    def check_sub(prefix):
        fqdn = f'{prefix}.{domain}'
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_sub, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)
                brute_count += 1

    print(f"\033[32m{brute_count} bulundu\033[0m")

    # Ana domain'i de ekle
    subdomains.add(domain)

    # Sirala
    sorted_subs = sorted(subdomains)
    print(f"\n  \033[32m[+] Toplam: {len(sorted_subs)} benzersiz subdomain\033[0m")
    if sorted_subs:
        all_subs_file = f'{domain}_subdomains_all.txt'
        try:
            with open(all_subs_file, 'w', encoding='utf-8') as f:
                for sub in sorted_subs:
                    f.write(f"{sub}\n")
            print(f"  \033[32m[+]\033[0m Tum subdomainler kaydedildi: {all_subs_file}")
        except OSError as e:
            print(f"  \033[31m[-]\033[0m Subdomain dosyasi yazilamadi: {e}")

    if _ensure_tool('httpx', 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest') and sorted_subs:
        targets_file = f'{domain}_subdomains.txt'
        httpx_out_file = f'{domain}_httpx_200.txt'
        try:
            with open(targets_file, 'w', encoding='utf-8') as f:
                for sub in sorted_subs:
                    f.write(f"{sub}\n")
            print("  \033[36m[~]\033[0m httpx ile 200 kontrolu yapiliyor...", end=" ", flush=True)
            httpx_cmd = f'httpx -l {targets_file} -status-code -silent -mc 200'
            httpx_out = _run_cmd(httpx_cmd, timeout=120)
            if httpx_out:
                for line in httpx_out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    url = parts[0]
                    status = parts[1].strip('[]') if len(parts) > 1 else '200'
                    if status == '200':
                        httpx_200.append(url)
                with open(httpx_out_file, 'w', encoding='utf-8') as f:
                    for url in httpx_200:
                        f.write(f"{url}\n")
                print(f"\033[32m{len(httpx_200)} bulundu\033[0m")
                print(f"  \033[32m[+]\033[0m 200 durum kodlu subdomainler: {httpx_out_file}")
            else:
                print("\033[33m0\033[0m")
        except Exception as e:
            print(f"\033[31m{str(e)[:30]}\033[0m")
        finally:
            try:
                os.remove(targets_file)
            except Exception:
                pass
    else:
        print("  \033[33m[!]\033[0m httpx kurulamadigi icin 200 kontrolu atlandi.")

    results['subdomains'] = sorted_subs
    results['httpx_200'] = httpx_200
    return sorted_subs


# ============================================
# ASAMA 3: HTTP DURUM KONTROLU
# ============================================

def stage_http_check(domain, subdomains, results):
    """Her subdomain icin HTTP/HTTPS durum kontrolu."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 3: HTTP Durum Kontrolu\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    if not HAS_REQUESTS:
        print("  \033[31m[-]\033[0m requests kutuphanesi gerekli: pip install requests")
        results['http_results'] = []
        return []

    active = []

    def check_http(sub):
        info = {'subdomain': sub, 'ip': None, 'status': None, 'title': '',
                'server': '', 'redirect': '', 'content_length': 0, 'scheme': 'https'}

        info['ip'] = _resolve_ip(sub)

        for scheme in ['https', 'http']:
            try:
                resp = requests.get(
                    f'{scheme}://{sub}',
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                info['status'] = resp.status_code
                info['scheme'] = scheme
                info['server'] = resp.headers.get('Server', '')
                info['content_length'] = len(resp.content)
                info['title'] = _get_title(resp.text)
                if resp.history:
                    info['redirect'] = resp.url
                info['headers'] = dict(resp.headers)
                return info
            except requests.exceptions.SSLError:
                if scheme == 'https':
                    continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        info['status'] = 0
        return info

    print(f"  \033[36m[~]\033[0m {len(subdomains)} subdomain kontrol ediliyor...\n")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_http, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            info = future.result()
            if info['status'] and info['status'] < 500:
                active.append(info)
                status_color = '\033[32m' if info['status'] == 200 else '\033[33m'
                print(f"  {status_color}[{info['status']}]\033[0m {info['subdomain']:40s} "
                      f"IP:{info['ip'] or '?':15s} {info['title'][:30]}")

    active.sort(key=lambda x: x['subdomain'])

    print(f"\n  \033[32m[+] {len(active)}/{len(subdomains)} subdomain aktif\033[0m")

    results['http_results'] = active
    return active


# ============================================
# ASAMA 4: PORT TARAMASI
# ============================================

def _probe_open_ports(domain, port_results, output_file):
    if not HAS_REQUESTS:
        print("  \033[33m[!]\033[0m requests olmadigi icin port istegi atlanıyor.")
        return []

    findings = []
    print("\n  \033[36m[~]\033[0m Acik portlara HTTP istekleri atiliyor...")

    def probe(subdomain, port):
        schemes = ['https', 'http']
        if port in [80, 8080, 8888, 9090]:
            schemes = ['http', 'https']
        elif port in [443, 8443]:
            schemes = ['https', 'http']

        for scheme in schemes:
            base_url = f"{scheme}://{subdomain}:{port}" if port not in [80, 443] else f"{scheme}://{subdomain}"
            try:
                resp = requests.get(
                    base_url,
                    timeout=5, verify=False, allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                status = resp.status_code
                title = _get_title(resp.text)
                if 200 <= status < 400:
                    findings.append({
                        'subdomain': subdomain,
                        'port': port,
                        'url': base_url,
                        'status': status,
                        'title': title,
                        'path': '/',
                    })
                for path in HTTP_PROBE_PATHS[1:]:
                    try:
                        resp_path = requests.get(
                            f"{base_url}{path}",
                            timeout=5, verify=False, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                        if resp_path.status_code in (200, 403):
                            findings.append({
                                'subdomain': subdomain,
                                'port': port,
                                'url': base_url,
                                'status': resp_path.status_code,
                                'title': _get_title(resp_path.text),
                                'path': path,
                            })
                    except Exception:
                        continue
                return
            except Exception:
                continue

    for sub, ports in port_results.items():
        for p in ports:
            probe(sub, p['port'])

    if findings:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for finding in findings:
                    f.write(
                        f"{finding['subdomain']}:{finding['port']} {finding['url']}"
                        f"{finding['path']} [{finding['status']}] {finding['title']}\n"
                    )
            print(f"  \033[32m[+]\033[0m Port HTTP bulgulari kaydedildi: {output_file}")
        except OSError as e:
            print(f"  \033[31m[-]\033[0m Dosya yazma hatasi: {e}")
    else:
        print("  \033[32m[+]\033[0m Port HTTP bulgusu bulunamadi.")

    return findings


def stage_port_scan(domain, active_subs, all_subdomains, results):
    """nmap ile port taramasi."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 4: Port Taramasi\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    port_results = {}

    def _build_targets():
        targets = []
        seen = set()
        for sub_info in active_subs:
            sub = sub_info['subdomain']
            ip = sub_info.get('ip') or _resolve_ip(sub)
            if ip and sub not in seen:
                targets.append({'subdomain': sub, 'ip': ip})
                seen.add(sub)
        for sub in all_subdomains:
            if sub in seen:
                continue
            ip = _resolve_ip(sub)
            if ip:
                targets.append({'subdomain': sub, 'ip': ip})
                seen.add(sub)
        if domain not in seen:
            ip = _resolve_ip(domain)
            if ip:
                targets.append({'subdomain': domain, 'ip': ip})
        return targets

    targets = _build_targets()
    if not targets:
        print("  \033[33m[!]\033[0m Port taramasi icin hedef bulunamadi.")
        results['port_scan'] = {}
        return {}

    if not _check_tool('nmap'):
        print("  \033[33m[!]\033[0m nmap kurulu degil, Python soket taramasi kullaniliyor...")
        # Fallback: Python socket scan
        for sub_info in targets:
            sub = sub_info['subdomain']
            ip = sub_info.get('ip')
            if not ip:
                continue

            print(f"  \033[36m[~]\033[0m {sub} ({ip})...", end=" ", flush=True)
            open_ports = []
            ports_to_scan = TOP_PORTS  # Optimized: Top ~100 ports instead of 65535

            def _scan_port(port):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    if s.connect_ex((ip, port)) == 0:
                        return port
                except Exception:
                    return None
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                return None

            chunk_size = 2000
            for i in range(0, len(ports_to_scan), chunk_size):
                chunk = ports_to_scan[i:i + chunk_size]
                with ThreadPoolExecutor(max_workers=200) as executor:
                    futures = {executor.submit(_scan_port, port): port for port in chunk}
                    for future in as_completed(futures):
                        port = future.result()
                        if port:
                            open_ports.append({'port': port, 'service': '', 'version': ''})

            if open_ports:
                port_results[sub] = open_ports
                ports_str = ', '.join([str(p['port']) for p in open_ports])
                print(f"\033[32m{len(open_ports)} acik port: {ports_str}\033[0m")
            else:
                print("\033[90macik port yok\033[0m")

    else:
        # nmap ile tarama
        # Benzersiz IP'leri topla (ayni IP'yi tekrar taramayalim)
        ip_to_subs = {}
        for sub_info in targets:
            ip = sub_info.get('ip')
            if ip:
                if ip not in ip_to_subs:
                    ip_to_subs[ip] = []
                ip_to_subs[ip].append(sub_info['subdomain'])

        for ip, subs in ip_to_subs.items():
            sub_label = subs[0] if len(subs) == 1 else f"{subs[0]} (+{len(subs)-1})"
            print(f"  \033[36m[~]\033[0m nmap {ip} ({sub_label})...", flush=True)

            stderr_redirect = '2>NUL' if os.name == 'nt' else '2>/dev/null'
            nmap_out = _run_cmd(
                f'nmap -sV -T4 -p- --open {ip} {stderr_redirect}',
                timeout=600
            )

            open_ports = []
            for line in nmap_out.splitlines():
                match = re.match(r'\s*(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', line)
                if match:
                    port_info = {
                        'port': int(match.group(1)),
                        'protocol': match.group(2),
                        'service': match.group(3),
                        'version': match.group(4).strip(),
                    }
                    open_ports.append(port_info)

            if open_ports:
                for sub in subs:
                    port_results[sub] = open_ports
                for p in open_ports:
                    svc = f"{p['service']} {p['version']}".strip()
                    print(f"      \033[32m{p['port']}/{p.get('protocol','tcp')}\033[0m\t{svc}")
            else:
                print(f"      \033[90macik port yok\033[0m")

    results['port_scan'] = port_results
    results['port_http_findings'] = _probe_open_ports(domain, port_results, f'{domain}_port_http_findings.txt')
    return port_results


# ============================================
# ASAMA 5: GUVENLIK ANALIZI
# ============================================

def stage_security_analysis(domain, active_subs, results):
    """Header, SSL, WAF, hassas dosya analizi."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 5: Guvenlik Analizi\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    if not HAS_REQUESTS:
        print("  \033[31m[-]\033[0m requests kutuphanesi gerekli")
        results['security'] = {}
        return {}

    security_results = {}

    for sub_info in active_subs:
        sub = sub_info['subdomain']
        scheme = sub_info.get('scheme', 'https')
        headers = sub_info.get('headers', {})
        url = f"{scheme}://{sub}"

        sec = {
            'missing_headers': [],
            'info_leak': [],
            'ssl': {},
            'waf': None,
            'sensitive_files': [],
            'tech': [],
            'findings': [],
        }

        print(f"\n  \033[36m[{sub}]\033[0m")

        # -- Guvenlik Header Kontrolu --
        for header_name, description in SECURITY_HEADERS:
            if header_name.lower() not in {k.lower(): v for k, v in headers.items()}:
                sec['missing_headers'].append(header_name)
                sec['findings'].append({
                    'severity': 'MEDIUM',
                    'type': 'missing_header',
                    'detail': f'{header_name} eksik ({description})',
                })

        if sec['missing_headers']:
            print(f"    \033[33m[-]\033[0m Eksik headerlar: {', '.join(sec['missing_headers'][:4])}")

        # -- Bilgi Sizdirma --
        for h in INFO_LEAK_HEADERS:
            val = headers.get(h) or headers.get(h.lower())
            if val:
                sec['info_leak'].append(f'{h}: {val}')
                sec['tech'].append(val)
                sec['findings'].append({
                    'severity': 'LOW',
                    'type': 'info_leak',
                    'detail': f'{h} header bilgi sizdiriyor: {val}',
                })

        if sec['info_leak']:
            print(f"    \033[33m[!]\033[0m Bilgi sizdirma: {'; '.join(sec['info_leak'][:3])}")

        # -- WAF Tespiti --
        waf_indicators = {
            'cf-ray': 'Cloudflare', 'cf-cache-status': 'Cloudflare',
            'x-sucuri-id': 'Sucuri', 'x-sucuri-cache': 'Sucuri',
            'server': None,  # checked separately
        }
        server_val = (headers.get('Server') or headers.get('server') or '').lower()
        if 'cloudflare' in server_val:
            sec['waf'] = 'Cloudflare'
        elif 'akamaighost' in server_val:
            sec['waf'] = 'Akamai'
        elif 'imperva' in server_val or 'incapsula' in server_val:
            sec['waf'] = 'Imperva'

        for h_key, waf_name in waf_indicators.items():
            if h_key in {k.lower() for k in headers} and waf_name:
                sec['waf'] = waf_name

        if sec['waf']:
            print(f"    \033[32m[+]\033[0m WAF: {sec['waf']}")

        # -- SSL/TLS Analizi --
        if scheme == 'https':
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(socket.socket(), server_hostname=sub) as s:
                    s.settimeout(5)
                    s.connect((sub, 443))
                    cert = s.getpeercert(True)
                    cert_decoded = ssl.DER_cert_to_PEM_cert(cert)

                    # Sertifika bilgisi
                    peer_cert = s.getpeercert()
                    if peer_cert:
                        not_after = peer_cert.get('notAfter', '')
                        issuer = dict(x[0] for x in peer_cert.get('issuer', []))
                        sec['ssl'] = {
                            'issuer': issuer.get('organizationName', '?'),
                            'expires': not_after,
                            'protocol': s.version(),
                        }
                        print(f"    \033[32m[+]\033[0m SSL: {s.version()} | Issuer: {sec['ssl']['issuer']} | Bitis: {not_after}")

                        # Eski protokol uyarisi
                        if 'TLSv1.0' in (s.version() or '') or 'TLSv1.1' in (s.version() or ''):
                            sec['findings'].append({
                                'severity': 'HIGH',
                                'type': 'weak_ssl',
                                'detail': f'Eski TLS surumu aktif: {s.version()}',
                            })
                            print(f"    \033[31m[!]\033[0m Eski TLS: {s.version()}")
            except Exception:
                pass

        # -- Hassas Dosya/Dizin Taramasi --
        print(f"    \033[36m[~]\033[0m Hassas dosya taramasi...", end=" ", flush=True)
        sensitive_found = 0

        # False positive tespiti: rastgele URL'ye istek atip baseline boyut olc
        # cPanel/WHM/Webmail gibi paneller her URL'ye login sayfasi dondurur
        baseline_size = None
        baseline_text = ''
        try:
            rand_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=12)) + '.html'
            baseline_resp = requests.get(
                f'{url}{rand_path}',
                timeout=5, verify=False, allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            if baseline_resp.status_code == 200:
                baseline_size = len(baseline_resp.content)
                baseline_text = baseline_resp.text[:500].lower()
        except Exception:
            pass

        # Login/panel sayfasi tespiti icin anahtar kelimeler
        panel_keywords = ['cpanel', 'whm', 'webmail', 'login', 'sign in', 'log in',
                         'password', 'username', 'authentication', 'roundcube',
                         'horde', 'squirrelmail']

        def check_path(path):
            try:
                resp = requests.get(
                    f'{url}{path}',
                    timeout=5, verify=False, allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                if resp.status_code == 200 and len(resp.content) > 0:
                    content_size = len(resp.content)
                    resp_text_lower = resp.text[:500].lower()

                    # Custom 404 tespiti
                    if '404' in resp_text_lower or 'not found' in resp_text_lower:
                        return None

                    # Baseline karsilastirma: ayni boyutta yanit = false positive
                    # (cPanel/WHM/Webmail login sayfasi her URL'ye ayni sayfa doner)
                    if baseline_size is not None and content_size > 1000:
                        size_diff = abs(content_size - baseline_size)
                        if size_diff < 200:  # 200 byte tolerans
                            return None

                    # Panel login sayfasi tespiti
                    if content_size > 5000:
                        panel_match = sum(1 for kw in panel_keywords if kw in resp_text_lower)
                        if panel_match >= 2:
                            return None

                    return {'path': path, 'status': resp.status_code, 'size': content_size}
                elif resp.status_code == 403:
                    return {'path': path, 'status': 403, 'size': 0}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_path, p): p for p in SENSITIVE_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    sec['sensitive_files'].append(result)
                    severity = 'CRITICAL' if result['path'] in ['/.env', '/.git/config', '/.git/HEAD'] else 'HIGH' if result['status'] == 200 else 'LOW'
                    sec['findings'].append({
                        'severity': severity,
                        'type': 'sensitive_file',
                        'detail': f"{result['path']} erisilebilir (HTTP {result['status']}, {result['size']} byte)",
                    })
                    sensitive_found += 1

        if sensitive_found:
            print(f"\033[31m{sensitive_found} hassas dosya bulundu!\033[0m")
            for sf in sec['sensitive_files']:
                severity_color = '\033[31m' if sf['status'] == 200 else '\033[33m'
                print(f"      {severity_color}[{sf['status']}]\033[0m {sf['path']} ({sf['size']} byte)")
        else:
            print("\033[32mtemiz\033[0m")

        security_results[sub] = sec

    results['security'] = security_results
    return security_results


# ============================================
# ASAMA 6: TEKNOLOJI PARMAK IZI (YENi)
# ============================================

def stage_tech_fingerprint(domain, active_subs, results):
    """Teknoloji tespiti: CMS, Framework, Server, CDN."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 6: Teknoloji Parmak Izi\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    if not HAS_REQUESTS:
        print("  \033[31m[-]\033[0m requests gerekli")
        results['tech_fingerprint'] = {}
        return {}

    tech_results = {}

    for sub_info in active_subs:
        sub = sub_info['subdomain']
        scheme = sub_info.get('scheme', 'https')
        headers = sub_info.get('headers', {})
        url = f"{scheme}://{sub}"

        detected = []

        # Fetch main page content
        body = ''
        cookies = {}
        try:
            resp = requests.get(
                url, timeout=8, verify=False, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            body = resp.text[:50000].lower()
            cookies = {k.lower(): v for k, v in resp.cookies.items()}
        except Exception:
            pass

        # Check each technology fingerprint
        for tech_name, fp in TECH_FINGERPRINTS.items():
            score = 0

            # Header match
            for hdr_key, hdr_val in fp.get('headers', {}).items():
                actual = headers.get(hdr_key, '') or headers.get(hdr_key.lower(), '')
                if actual:
                    if not hdr_val or hdr_val.lower() in actual.lower():
                        score += 3

            # Body match
            for pattern in fp.get('body', []):
                if pattern.lower() in body:
                    score += 2

            # Cookie match
            for cookie_name in fp.get('cookies', []):
                if cookie_name.lower() in cookies:
                    score += 3

            # Path probe (only if score > 0 or has specific paths)
            for path in fp.get('paths', [])[:2]:  # Max 2 paths per tech
                try:
                    resp = requests.get(
                        f'{url}{path}', timeout=5, verify=False, allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    if resp.status_code in [200, 301, 302, 403]:
                        score += 2
                except Exception:
                    pass

            if score >= 2:
                confidence = 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
                detected.append({'name': tech_name, 'confidence': confidence, 'score': score})

        # Sort by score
        detected.sort(key=lambda x: x['score'], reverse=True)

        if detected:
            tech_results[sub] = detected
            techs_str = ', '.join([f"{d['name']}({d['confidence']})" for d in detected[:5]])
            print(f"  \033[32m[+]\033[0m {sub}: {techs_str}")
        else:
            print(f"  \033[90m[-]\033[0m {sub}: Teknoloji tespit edilemedi")

    print(f"\n  \033[32m[+] {len(tech_results)}/{len(active_subs)} hedefte teknoloji tespit edildi\033[0m")
    results['tech_fingerprint'] = tech_results
    return tech_results


# ============================================
# ASAMA 7: JS ENDPOINT CIKARTMA (YENi)
# ============================================

def stage_js_endpoint_extraction(domain, active_subs, results):
    """JavaScript dosyalarindan API endpoint ve hassas bilgi cikartma."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 7: JS Endpoint Cikartma\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    if not HAS_REQUESTS:
        print("  \033[31m[-]\033[0m requests gerekli")
        results['js_endpoints'] = {}
        return {}

    js_results = {}

    # Regex patterns for endpoint extraction
    endpoint_patterns = [
        (r'["\']/(api|v[0-9]+|rest|graphql)/[a-zA-Z0-9/_\-]+["\']', 'API Endpoint'),
        (r'["\']https?://[a-zA-Z0-9._\-]+\.[a-z]{2,}[/a-zA-Z0-9._\-]*["\']', 'External URL'),
        (r'["\']/(admin|dashboard|config|settings|user|auth|login|upload)[/a-zA-Z0-9_\-]*["\']', 'Admin Path'),
    ]

    # Sensitive data patterns
    sensitive_patterns = [
        (r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{10,}["\']', 'API Key/Token'),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']', 'Hardcoded Password'),
        (r'(?i)aws[_-]?(access[_-]?key|secret)[_-]?id?\s*[=:]\s*["\'][A-Za-z0-9/+=]{10,}["\']', 'AWS Key'),
        (r'(?i)(firebase|mongo|mysql|postgres|redis)://[^\s"\']+', 'Database URI'),
        (r'(?i)Bearer\s+[a-zA-Z0-9._\-]{10,}', 'Bearer Token'),
        (r'(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})', 'GitHub Token'),
    ]

    for sub_info in active_subs[:10]:  # Limit to 10 subs
        sub = sub_info['subdomain']
        scheme = sub_info.get('scheme', 'https')
        url = f"{scheme}://{sub}"

        endpoints = set()
        secrets = []
        js_files = []

        # Find JS files from HTML
        try:
            resp = requests.get(
                url, timeout=8, verify=False, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            # Extract JS file URLs
            js_matches = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text, re.IGNORECASE)
            for js_url in js_matches[:20]:  # Max 20 JS files
                if js_url.startswith('//'):
                    js_url = f'{scheme}:{js_url}'
                elif js_url.startswith('/'):
                    js_url = f'{url}{js_url}'
                elif not js_url.startswith('http'):
                    js_url = f'{url}/{js_url}'
                js_files.append(js_url)

            # Also check inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL | re.IGNORECASE)
            for script in inline_scripts:
                if len(script) > 50:  # Skip empty/tiny scripts
                    for pattern, label in endpoint_patterns:
                        for match in re.findall(pattern, script):
                            if isinstance(match, tuple):
                                match = match[0]
                            endpoints.add(match.strip('"\''))
                    for pattern, label in sensitive_patterns:
                        for match in re.findall(pattern, script):
                            if isinstance(match, tuple):
                                match = match[0]
                            secrets.append({'type': label, 'value': match[:50]})

        except Exception:
            pass

        # Fetch and analyze JS files
        print(f"  \033[36m[~]\033[0m {sub}: {len(js_files)} JS dosyasi...", end=" ", flush=True)

        def analyze_js(js_url):
            local_eps = set()
            local_secrets = []
            try:
                resp = requests.get(
                    js_url, timeout=5, verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                if resp.status_code == 200 and len(resp.text) > 100:
                    content = resp.text[:200000]  # Max 200KB per file

                    for pattern, label in endpoint_patterns:
                        for match in re.findall(pattern, content):
                            if isinstance(match, tuple):
                                match = match[0]
                            local_eps.add(match.strip('"\''))

                    for pattern, label in sensitive_patterns:
                        for match in re.findall(pattern, content):
                            if isinstance(match, tuple):
                                match = match[0]
                            local_secrets.append({'type': label, 'value': match[:50], 'file': js_url})
            except Exception:
                pass
            return local_eps, local_secrets

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(analyze_js, url): url for url in js_files}
            for future in as_completed(futures):
                eps, secs = future.result()
                endpoints.update(eps)
                secrets.extend(secs)

        if endpoints or secrets:
            js_results[sub] = {
                'endpoints': sorted(endpoints),
                'secrets': secrets,
                'js_files': len(js_files),
            }
            print(f"\033[32m{len(endpoints)} endpoint, {len(secrets)} secret\033[0m")
            if secrets:
                for s in secrets[:3]:
                    print(f"    \033[31m[!!!] {s['type']}: {s['value'][:40]}...\033[0m")
        else:
            print(f"\033[90mtemiz\033[0m")

    total_eps = sum(len(r['endpoints']) for r in js_results.values())
    total_secs = sum(len(r['secrets']) for r in js_results.values())
    print(f"\n  \033[32m[+] Toplam: {total_eps} endpoint, {total_secs} hassas bilgi\033[0m")

    results['js_endpoints'] = js_results
    return js_results


# ============================================
# ASAMA 8: AKTIF ZAFIYET TESTI (YENi)
# ============================================

def stage_active_vuln_test(domain, active_subs, results):
    """Aktif zafiyet testleri: XSS, SQLi, SSRF, LFI."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 8: Aktif Zafiyet Testi\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    if not HAS_REQUESTS:
        print("  \033[31m[-]\033[0m requests gerekli")
        results['active_vulns'] = []
        return []

    vulns = []

    for sub_info in active_subs[:5]:  # Max 5 targets
        sub = sub_info['subdomain']
        scheme = sub_info.get('scheme', 'https')
        url = f"{scheme}://{sub}"

        print(f"\n  \033[36m[{sub}]\033[0m")

        # 1. Find input points (forms and URL params)
        input_points = []
        try:
            resp = requests.get(
                url, timeout=8, verify=False, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            # Find forms
            forms = re.findall(
                r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                resp.text, re.DOTALL | re.IGNORECASE
            )
            for action, method, body in forms:
                inputs = re.findall(r'name=["\']([^"\']+)["\']', body)
                if inputs:
                    if action.startswith('/'):
                        action = f'{url}{action}'
                    elif not action.startswith('http'):
                        action = f'{url}/{action}'
                    input_points.append({
                        'url': action,
                        'method': method.upper(),
                        'params': inputs,
                    })

            # Find URL parameters from links
            links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', resp.text)
            for link in links[:10]:
                params = re.findall(r'[?&]([^=]+)=', link)
                if params:
                    if link.startswith('/'):
                        link = f'{url}{link}'
                    elif not link.startswith('http'):
                        link = f'{url}/{link}'
                    input_points.append({
                        'url': link.split('?')[0],
                        'method': 'GET',
                        'params': params,
                    })

        except Exception:
            pass

        print(f"    Giris noktalari: {len(input_points)}")

        # 2. XSS Test
        print(f"    \033[36m[~]\033[0m XSS testi...", end=" ", flush=True)
        xss_found = 0
        for ip_item in input_points[:5]:
            for probe in XSS_PROBES[:2]:  # Only 2 probes per input
                try:
                    test_params = {p: probe for p in ip_item['params']}
                    if ip_item['method'] == 'GET':
                        resp = requests.get(
                            ip_item['url'], params=test_params,
                            timeout=5, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    else:
                        resp = requests.post(
                            ip_item['url'], data=test_params,
                            timeout=5, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )

                    # Check if probe is reflected in response
                    if probe in resp.text:
                        xss_found += 1
                        vulns.append({
                            'type': 'XSS',
                            'severity': 'HIGH',
                            'url': ip_item['url'],
                            'param': list(ip_item['params']),
                            'payload': probe[:30],
                            'subdomain': sub,
                        })
                        break  # One finding per input point
                except Exception:
                    pass

        if xss_found:
            print(f"\033[31m{xss_found} bulundu!\033[0m")
        else:
            print(f"\033[32mtemiz\033[0m")

        # 3. SQL Injection Test (time-based detection)
        print(f"    \033[36m[~]\033[0m SQLi testi...", end=" ", flush=True)
        sqli_found = 0
        for ip_item in input_points[:3]:
            for probe in SQLI_PROBES[:2]:
                try:
                    test_params = {p: probe for p in ip_item['params']}

                    # Measure baseline response time
                    start = time.time()
                    if ip_item['method'] == 'GET':
                        resp = requests.get(
                            ip_item['url'], params=test_params,
                            timeout=10, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    else:
                        resp = requests.post(
                            ip_item['url'], data=test_params,
                            timeout=10, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    elapsed = time.time() - start

                    # Check for SQL error patterns
                    error_patterns = [
                        'sql syntax', 'mysql', 'ORA-', 'postgresql',
                        'sqlite', 'unclosed quotation', 'quoted string',
                        'syntax error', 'ODBC', 'SQL Server',
                    ]
                    resp_lower = resp.text[:5000].lower()
                    for err in error_patterns:
                        if err.lower() in resp_lower:
                            sqli_found += 1
                            vulns.append({
                                'type': 'SQLi',
                                'severity': 'CRITICAL',
                                'url': ip_item['url'],
                                'param': list(ip_item['params']),
                                'payload': probe[:30],
                                'error': err,
                                'subdomain': sub,
                            })
                            break
                except Exception:
                    pass

        if sqli_found:
            print(f"\033[31m{sqli_found} bulundu!\033[0m")
        else:
            print(f"\033[32mtemiz\033[0m")

        # 4. SSRF Test
        print(f"    \033[36m[~]\033[0m SSRF testi...", end=" ", flush=True)
        ssrf_found = 0
        ssrf_payloads = [
            'http://127.0.0.1:80',
            'http://169.254.169.254/latest/meta-data/',
            'http://[::1]:80',
            'http://0x7f000001',
        ]
        for ip_item in input_points[:3]:
            for payload in ssrf_payloads[:2]:
                try:
                    test_params = {p: payload for p in ip_item['params']}
                    if ip_item['method'] == 'GET':
                        resp = requests.get(
                            ip_item['url'], params=test_params,
                            timeout=5, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    else:
                        resp = requests.post(
                            ip_item['url'], data=test_params,
                            timeout=5, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )

                    # Check for SSRF indicators
                    resp_lower = resp.text[:5000].lower()
                    if any(indicator in resp_lower for indicator in
                           ['ami-id', 'instance-id', 'hostname', 'local-ipv4',
                            'meta-data', '127.0.0.1', 'localhost']):
                        ssrf_found += 1
                        vulns.append({
                            'type': 'SSRF',
                            'severity': 'CRITICAL',
                            'url': ip_item['url'],
                            'param': list(ip_item['params']),
                            'payload': payload[:30],
                            'subdomain': sub,
                        })
                        break
                except Exception:
                    pass

        if ssrf_found:
            print(f"\033[31m{ssrf_found} bulundu!\033[0m")
        else:
            print(f"\033[32mtemiz\033[0m")

        # 5. LFI Test
        print(f"    \033[36m[~]\033[0m LFI testi...", end=" ", flush=True)
        lfi_found = 0
        lfi_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        ]
        for ip_item in input_points[:3]:
            for payload in lfi_payloads[:2]:
                try:
                    test_params = {p: payload for p in ip_item['params']}
                    if ip_item['method'] == 'GET':
                        resp = requests.get(
                            ip_item['url'], params=test_params,
                            timeout=5, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                    else:
                        resp = requests.post(
                            ip_item['url'], data=test_params,
                            timeout=5, verify=False, allow_redirects=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )

                    if 'root:' in resp.text and '/bin/' in resp.text:
                        lfi_found += 1
                        vulns.append({
                            'type': 'LFI',
                            'severity': 'CRITICAL',
                            'url': ip_item['url'],
                            'param': list(ip_item['params']),
                            'payload': payload[:30],
                            'subdomain': sub,
                        })
                        break
                except Exception:
                    pass

        if lfi_found:
            print(f"\033[31m{lfi_found} bulundu!\033[0m")
        else:
            print(f"\033[32mtemiz\033[0m")

    # Summary
    criticals = [v for v in vulns if v['severity'] == 'CRITICAL']
    highs = [v for v in vulns if v['severity'] == 'HIGH']

    print(f"\n  \033[32m[+] Toplam: {len(vulns)} zafiyet ({len(criticals)} kritik, {len(highs)} yuksek)\033[0m")

    if criticals:
        print(f"\n  \033[31m[!!!] KRITIK ZAFIYETLER:\033[0m")
        for v in criticals:
            print(f"    \033[31m[{v['type']}]\033[0m {v['subdomain']}: {v['url']} (param: {v.get('param', [])})")

    results['active_vulns'] = vulns
    return vulns


# ============================================
# ASAMA 9: ZAFIYET TARAMASI (NUCLEI)
# ============================================

def stage_vuln_scan(domain, active_subs, results):
    """nuclei veya temel Python zafiyet taramasi."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 9: Zafiyet Taramasi (Nuclei)\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    vuln_results = []

    if _check_tool('nuclei'):
        print("  \033[36m[~]\033[0m nuclei ile taranıyor...\n")

        # Subdomain listesini dosyaya yaz
        targets_file = f'{domain}_targets.txt'
        with open(targets_file, 'w') as f:
            for sub_info in active_subs:
                scheme = sub_info.get('scheme', 'https')
                f.write(f"{scheme}://{sub_info['subdomain']}\n")

        nuclei_output = f'{domain}_nuclei.txt'
        nuclei_cmd = f'nuclei -l {targets_file} -severity low,medium,high,critical -o {nuclei_output} -silent -timeout 10 -retries 1 -rate-limit 50'
        
        print(f"  Komut: {nuclei_cmd}")
        print(f"  Bekleniyor (bu biraz zaman alabilir)...\n")

        _run_cmd(nuclei_cmd, timeout=300)

        # Sonuclari oku
        try:
            with open(nuclei_output, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        vuln_results.append(line)
                        # Severity renklendirme
                        if 'critical' in line.lower():
                            print(f"  \033[31m[CRITICAL]\033[0m {line}")
                        elif 'high' in line.lower():
                            print(f"  \033[31m[HIGH]\033[0m {line}")
                        elif 'medium' in line.lower():
                            print(f"  \033[33m[MEDIUM]\033[0m {line}")
                        else:
                            print(f"  \033[36m[LOW]\033[0m {line}")
        except FileNotFoundError:
            print("  \033[33m[-]\033[0m nuclei cikti dosyasi olusturulamadi")

        # Temizlik
        try:
            os.remove(targets_file)
        except Exception:
            pass

    else:
        print("  \033[33m[!]\033[0m nuclei kurulu degil, temel Python taramasi yapiliyor...\n")

        if not HAS_REQUESTS:
            print("  \033[31m[-]\033[0m requests gerekli")
        else:
            for sub_info in active_subs[:10]:  # ilk 10 ile sinirla
                sub = sub_info['subdomain']
                scheme = sub_info.get('scheme', 'https')
                base_url = f"{scheme}://{sub}"

                # Open redirect kontrolu
                try:
                    resp = requests.get(
                        f'{base_url}/?redirect=https://evil.com&url=https://evil.com&next=https://evil.com',
                        timeout=5, verify=False, allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location:
                            finding = f'[MEDIUM] {sub}: Open Redirect -> {location}'
                            vuln_results.append(finding)
                            print(f"  \033[33m{finding}\033[0m")
                except Exception:
                    pass

                # CORS misconfiguration
                try:
                    resp = requests.get(
                        base_url,
                        timeout=5, verify=False,
                        headers={'User-Agent': 'Mozilla/5.0', 'Origin': 'https://evil.com'}
                    )
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    if acao == '*' or 'evil.com' in acao:
                        finding = f'[MEDIUM] {sub}: CORS misconfiguration (ACAO: {acao})'
                        vuln_results.append(finding)
                        print(f"  \033[33m{finding}\033[0m")
                except Exception:
                    pass

    if not vuln_results:
        print("  \033[32m[+]\033[0m Zafiyet bulunamadi (veya nuclei kurulu degil)")

    print(f"\n  \033[32m[+] Toplam: {len(vuln_results)} zafiyet\033[0m")
    results['vulnerabilities'] = vuln_results
    return vuln_results


# ============================================
# ASAMA 10: RAPOR OLUSTURMA
# ============================================

def stage_report(domain, results):
    """TXT ve JSON rapor olustur."""
    print(f"\n\033[36m{'='*60}\033[0m")
    print(f"\033[36m  ASAMA 10: Rapor Olusturma\033[0m")
    print(f"\033[36m{'='*60}\033[0m\n")

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    safe_domain = domain.replace('.', '_').replace('/', '_')

    # -- TXT Rapor --
    txt_file = f'{safe_domain}_scan.txt'
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write('=' * 70 + '\n')
        f.write(f' WEB GUVENLIK TARAMA RAPORU\n')
        f.write(f' Hedef: {domain}\n')
        f.write(f' Tarih: {timestamp}\n')
        f.write('=' * 70 + '\n\n')

        # DNS/WHOIS
        dns = results.get('dns_whois', {})
        f.write('[1] DOMAIN BILGILERI\n')
        f.write(f'    IP:           {dns.get("ip", "?")}\n')
        f.write(f'    NS:           {", ".join(dns.get("ns", []))}\n')
        f.write(f'    MX:           {", ".join(dns.get("mx", []))}\n')
        f.write(f'    CDN/WAF:      {dns.get("cdn", "Yok")}\n')
        geo = dns.get('geo', {})
        if geo:
            f.write(f'    Konum:        {geo.get("city","?")}, {geo.get("country","?")} ({geo.get("org","?")})\n')
        f.write('\n')

        # Subdomains
        subs = results.get('subdomains', [])
        http = results.get('http_results', [])
        f.write(f'[2] SUBDOMAIN KESFI ({len(subs)} bulundu, {len(http)} aktif)\n')
        f.write(f'    {"#":>3} {"Subdomain":<40} {"IP":<16} {"Durum":<6} {"Title"}\n')
        f.write(f'    {"---":>3} {"--------":<40} {"--":<16} {"-----":<6} {"-----"}\n')
        for i, h in enumerate(http):
            f.write(f'    {i+1:>3} {h["subdomain"]:<40} {h.get("ip","?"):<16} {h.get("status","?"):<6} {h.get("title","")[:30]}\n')
        f.write('\n')

        # Ports
        ports = results.get('port_scan', {})
        f.write(f'[3] PORT TARAMASI\n')
        if ports:
            for sub, port_list in ports.items():
                f.write(f'    {sub}:\n')
                for p in port_list:
                    svc = f"{p.get('service','')} {p.get('version','')}".strip()
                    f.write(f'      {p["port"]}/tcp\t{svc}\n')
        else:
            f.write('    Acik port bulunamadi veya taranmadi.\n')
        f.write('\n')

        # Security
        security = results.get('security', {})
        f.write(f'[4] GUVENLIK ANALIZI\n')
        all_findings = []
        for sub, sec in security.items():
            for finding in sec.get('findings', []):
                all_findings.append((sub, finding))
                f.write(f'    [{finding["severity"]}] {sub}: {finding["detail"]}\n')
        if not all_findings:
            f.write('    Guvenlik sorunu bulunamadi.\n')
        f.write('\n')

        # Technology Fingerprint
        tech = results.get('tech_fingerprint', {})
        f.write(f'[5] TEKNOLOJI PARMAK IZI\n')
        if tech:
            for sub, techs in tech.items():
                techs_str = ', '.join([f"{t['name']}({t['confidence']})" for t in techs])
                f.write(f'    {sub}: {techs_str}\n')
        else:
            f.write('    Teknoloji tespit edilemedi.\n')
        f.write('\n')

        # JS Endpoints
        js_eps = results.get('js_endpoints', {})
        f.write(f'[6] JS ENDPOINT ANALIZI\n')
        total_eps = 0
        total_secs = 0
        if js_eps:
            for sub, data in js_eps.items():
                eps = data.get('endpoints', [])
                secs = data.get('secrets', [])
                total_eps += len(eps)
                total_secs += len(secs)
                f.write(f'    {sub}: {len(eps)} endpoint, {len(secs)} hassas bilgi\n')
                for ep in eps[:10]:
                    f.write(f'      - {ep}\n')
                for s in secs:
                    f.write(f'      [!!!] {s["type"]}: {s["value"]}\n')
        else:
            f.write('    JS analizi yapilmadi.\n')
        f.write('\n')

        # Active Vulns
        active_vulns = results.get('active_vulns', [])
        f.write(f'[7] AKTIF ZAFIYET TESTLERI\n')
        if active_vulns:
            for v in active_vulns:
                f.write(f'    [{v["severity"]}] [{v["type"]}] {v["subdomain"]}: {v["url"]}\n')
                f.write(f'        Param: {v.get("param", [])}, Payload: {v.get("payload", "")}\n')
        else:
            f.write('    Aktif zafiyet bulunamadi.\n')
        f.write('\n')

        # Nuclei Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        f.write(f'[8] ZAFIYETLER (nuclei)\n')
        if vulns:
            for v in vulns:
                f.write(f'    {v}\n')
        else:
            f.write('    Zafiyet bulunamadi.\n')
        f.write('\n')

        # Summary
        critical = sum(1 for _, f_item in all_findings if f_item['severity'] == 'CRITICAL')
        high = sum(1 for _, f_item in all_findings if f_item['severity'] == 'HIGH')
        medium = sum(1 for _, f_item in all_findings if f_item['severity'] == 'MEDIUM')
        low = sum(1 for _, f_item in all_findings if f_item['severity'] == 'LOW')
        
        # Add active vuln counts
        av_critical = sum(1 for v in active_vulns if v['severity'] == 'CRITICAL')
        av_high = sum(1 for v in active_vulns if v['severity'] == 'HIGH')
        critical += av_critical
        high += av_high

        f.write('=' * 70 + '\n')
        f.write(f' OZET\n')
        f.write(f'   Toplam subdomain: {len(subs)}\n')
        f.write(f'   Aktif:            {len(http)}\n')
        f.write(f'   Acik port:        {sum(len(v) for v in ports.values())}\n')
        f.write(f'   Teknoloji:        {sum(len(v) for v in tech.values())} tespit\n')
        f.write(f'   JS Endpoint:      {total_eps} endpoint, {total_secs} hassas bilgi\n')
        f.write(f'   Aktif zafiyet:    {len(active_vulns)} ({av_critical} kritik, {av_high} yuksek)\n')
        f.write(f'   Bulgular:         {critical} kritik, {high} yuksek, {medium} orta, {low} dusuk\n')
        f.write(f'   Zafiyet (nuclei): {len(vulns)}\n')
        f.write('=' * 70 + '\n')

    print(f"  \033[32m[+]\033[0m TXT rapor: {txt_file}")

    # -- JSON Rapor --
    json_file = f'{safe_domain}_scan.json'
    
    # Calculate totals for new sections
    tech = results.get('tech_fingerprint', {})
    js_eps = results.get('js_endpoints', {})
    active_vulns = results.get('active_vulns', [])
    total_eps = sum(len(data.get('endpoints', [])) for data in js_eps.values())
    total_secs = sum(len(data.get('secrets', [])) for data in js_eps.values())
    av_critical = sum(1 for v in active_vulns if v['severity'] == 'CRITICAL')
    av_high = sum(1 for v in active_vulns if v['severity'] == 'HIGH')
    
    json_data = {
        'domain': domain,
        'timestamp': timestamp,
        'dns_whois': {k: v for k, v in results.get('dns_whois', {}).items() if k != 'whois'},
        'subdomains': results.get('subdomains', []),
        'active_count': len(results.get('http_results', [])),
        'http_results': [{k: v for k, v in h.items() if k != 'headers'} for h in results.get('http_results', [])],
        'port_scan': results.get('port_scan', {}),
        'security_findings': [],
        'tech_fingerprint': tech,
        'js_endpoints': js_eps,
        'active_vulns': active_vulns,
        'vulnerabilities': results.get('vulnerabilities', []),
        'summary': {
            'total_subdomains': len(subs),
            'active': len(http),
            'open_ports': sum(len(v) for v in ports.values()),
            'tech_detected': sum(len(v) for v in tech.values()),
            'js_endpoints': total_eps,
            'js_secrets': total_secs,
            'active_vulns': len(active_vulns),
            'av_critical': av_critical,
            'av_high': av_high,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'nuclei_vulns': len(vulns),
        }
    }

    for sub, sec in security.items():
        for finding in sec.get('findings', []):
            json_data['security_findings'].append({
                'subdomain': sub,
                **finding
            })

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)

    print(f"  \033[32m[+]\033[0m JSON rapor: {json_file}")

    # -- Ozet --
    total_techs = sum(len(r.get('tech_fingerprint', {}).get('technologies', [])) for r in results.values())
    total_js_eps = sum(len(r.get('js_endpoints', {}).get('endpoints', [])) for r in results.values())
    total_js_secrets = sum(len(r.get('js_endpoints', {}).get('secrets', [])) for r in results.values())
    total_active_vulns = sum(len(r.get('active_vulns', [])) for r in results.values())
    
    print(f"\n\033[32m{'='*60}\033[0m")
    print(f"\033[32m  TARAMA TAMAMLANDI\033[0m")
    print(f"\033[32m{'='*60}\033[0m")
    print(f"   Hedef:            {domain}")
    print(f"   Subdomain:        {len(subs)} bulundu, {len(http)} aktif")
    print(f"   Acik Port:        {sum(len(v) for v in ports.values())}")
    print(f"   Teknoloji:        {total_techs} tespit edildi")
    print(f"   JS Endpoint:      {total_js_eps} endpoint, {total_js_secrets} secret")
    print(f"   Guvenlik Bulgu:   \033[31m{critical}\033[0m kritik, \033[31m{high}\033[0m yuksek, \033[33m{medium}\033[0m orta, {low} dusuk")
    print(f"   Aktif Zafiyet:    {total_active_vulns} tespit edildi")
    print(f"   Zafiyet (nuclei): {len(vulns)}")
    print(f"   Rapor:            {txt_file}, {json_file}")
    print(f"\033[32m{'='*60}\033[0m")

    return txt_file, json_file


# ============================================
# ANA MENU
# ============================================

def web_scan_menu():
    """Web sitesi guvenlik tarayici ana menusu."""

    # SSL uyarilarini kapat
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"\033[36m{'='*60}\033[0m")
    print(f"\033[36m  Web Sitesi Guvenlik Tarayici\033[0m")
    print(f"\033[36m{'='*60}\033[0m")
    print()

    # Arac durumu
    tools = {
        'subfinder': _check_tool('subfinder'),
        'nmap': _check_tool('nmap'),
        'nuclei': _check_tool('nuclei'),
        'requests': HAS_REQUESTS,
    }

    print("  Arac Durumu:")
    for tool, status in tools.items():
        icon = '\033[32m[+]\033[0m' if status else '\033[31m[-]\033[0m'
        print(f"    {icon} {tool}")
    print()

    if not HAS_REQUESTS:
        print("  \033[31m[!] requests kutuphanesi gerekli: pip install requests\033[0m\n")

    def _is_valid_ip(value):
        try:
            socket.inet_aton(value)
            return True
        except OSError:
            return False

    def _normalize_domain(raw_value):
        value = raw_value.strip()
        if not value:
            return ''
        if '://' in value:
            parsed = urlparse(value)
            value = parsed.netloc or parsed.path
        value = value.split('/')[0]
        if ':' in value:
            value = value.split(':')[0]
        value = value.strip().lower()
        if _is_valid_ip(value):
            return value
        domain_regex = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$')
        if domain_regex.match(value):
            return value
        return ''

    # Domain al
    while True:
        raw_domain = input("  Hedef domain (örn: example.com): ").strip()
        domain = _normalize_domain(raw_domain)
        if domain:
            break
        print("  [-] Geçersiz domain formatı. Örnek: example.com")

    print()
    print("  Tarama modu:")
    print("    1) Tam tarama (10 asama - onerilen)")
    print("    2) Sadece subdomain kesif")
    print("    3) Sadece port tarama")
    print("    4) Sadece guvenlik header analizi")
    print("    5) Sadece zafiyet tarama (nuclei)")
    print("    6) Teknoloji parmak izi + JS endpoint analizi")
    print("    7) Aktif zafiyet testi (XSS/SQLi/SSRF/LFI)")
    print("    0) Geri")
    print()

    valid_modes = {'0', '1', '2', '3', '4', '5', '6', '7'}
    while True:
        mode = input("  Secim [1]: ").strip() or "1"
        if mode in valid_modes:
            break
        print("  [-] Geçersiz seçim. 0-7 arasında bir değer girin.")

    if mode == "0":
        return

    print(f"\n  \033[36m[*] Hedef: {domain}\033[0m")
    print(f"  \033[36m[*] Mod: {mode}\033[0m")

    if not HAS_REQUESTS and mode in {'1', '2', '4', '5'}:
        warn_confirm = input("\n  [!] requests yok. HTTP/guvenlik kontrolleri atlanabilir. Devam edilsin mi? [E/h]: ").strip().lower()
        if warn_confirm in {'h', 'n', 'hayir', 'no'}:
            return

    confirm = input(f"\n  Baslatilsin mi? [E/h]: ").strip().lower()
    if confirm == 'h':
        return

    results = {}
    start_time = time.time()

    try:
        if mode in ['1', '2', '3', '4', '5']:
            # Asama 1: DNS/WHOIS (her modda)
            stage_dns_whois(domain, results)

        if mode in ['1', '2']:
            # Asama 2: Subdomain kesfi
            subdomains = stage_subdomain_enum(domain, results)
        else:
            # Sadece ana domain
            subdomains = [domain]
            results['subdomains'] = subdomains

        if mode in ['1', '2', '3', '4', '5']:
            # Asama 3: HTTP kontrol
            active = stage_http_check(domain, subdomains, results)
        else:
            active = []

        if mode in ['1', '4', '5'] and not active:
            print("  \033[33m[!]\033[0m Aktif HTTP hedefi bulunamadı. HTTP tabanlı aşamalar atlanacak.")

        if mode in ['1', '3']:
            # Asama 4: Port tarama
            stage_port_scan(domain, active, subdomains, results)

        if mode in ['1', '4'] and active:
            # Asama 5: Guvenlik analizi
            stage_security_analysis(domain, active, results)

        if mode in ['1', '6'] and active:
            # Asama 6: Teknoloji parmak izi
            stage_tech_fingerprint(domain, active, results)

        if mode in ['1', '6'] and active:
            # Asama 7: JS Endpoint extraction
            stage_js_endpoint_extraction(domain, active, results)

        if mode in ['1', '7'] and active:
            # Asama 8: Aktif zafiyet testi
            stage_active_vuln_test(domain, active, results)

        if mode in ['1', '5'] and active:
            # Asama 9: Zafiyet tarama (nuclei)
            stage_vuln_scan(domain, active, results)

        # Asama 10: Rapor
        stage_report(domain, results)

    except KeyboardInterrupt:
        print("\n\n  \033[33m[!] Tarama iptal edildi (Ctrl+C)\033[0m")
        # Kısmi rapor olustur
        if results:
            stage_report(domain, results)
    except Exception as e:
        print(f"\n  \033[31m[-] Hata: {e}\033[0m")
        import traceback
        traceback.print_exc()

    elapsed = time.time() - start_time
    print(f"\n  Toplam sure: {elapsed:.1f} saniye")
    input("\n  Devam etmek icin Enter'a basin...")


if __name__ == '__main__':
    web_scan_menu()
