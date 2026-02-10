#!/usr/bin/env python
"""SigPloit runtime health checks (defensive/operational)."""
import importlib.util
import os
import socket
import shutil
import sys
import time


REQUIRED_MODULES = [
    "scapy",
    "requests",
    "colorama",
    "termcolor",
    "pyfiglet",
]

OPTIONAL_MODULES = [
    "shodan",
    "flask",
    "sctp",
    "crcmod",
]

TOOL_NAMES = ["nmap", "go", "subfinder", "httpx"]



def _check_import(name):
    return importlib.util.find_spec(name) is not None



def _check_writeable(path):
    try:
        test = os.path.join(path, f".sigploit_check_{int(time.time())}")
        with open(test, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(test)
        return True, "ok"
    except Exception as e:
        return False, str(e)



def _check_dns():
    try:
        socket.gethostbyname("search.censys.io")
        return True, "dns ok"
    except Exception as e:
        return False, str(e)



def _check_python_version(min_major=3, min_minor=8):
    current = sys.version_info
    ok = (current.major, current.minor) >= (min_major, min_minor)
    return ok, f"{current.major}.{current.minor}.{current.micro}"



def run_system_check(non_interactive=False):
    """Run checks and optionally wait for Enter.

    Returns a structured summary dict for automation/tests.
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 68)
    print(" SigPloit Sistem Kontrolu")
    print("=" * 68)

    summary = {
        'required_missing': [],
        'optional_missing': [],
        'tools_missing': [],
        'python_ok': True,
        'dns_ok': True,
        'write_ok': True,
    }

    print("\n[0] Python surumu")
    py_ok, py_ver = _check_python_version()
    summary['python_ok'] = py_ok
    print(f"  {'[+]' if py_ok else '[-]'} Python: {py_ver} (minimum 3.8)")

    print("\n[1] Python modulleri")
    for m in REQUIRED_MODULES:
        ok = _check_import(m)
        print(f"  {'[+]' if ok else '[-]'} {m}")
        if not ok:
            summary['required_missing'].append(m)

    print("\n[2] Opsiyonel moduller")
    for m in OPTIONAL_MODULES:
        ok = _check_import(m)
        print(f"  {'[+]' if ok else '[~]'} {m}")
        if not ok:
            summary['optional_missing'].append(m)

    print("\n[3] Harici araclar")
    for t in TOOL_NAMES:
        path = shutil.which(t)
        print(f"  {'[+]' if path else '[~]'} {t} {'-> ' + path if path else ''}")
        if not path:
            summary['tools_missing'].append(t)

    print("\n[4] Dosya yazma izinleri")
    cwd_ok, cwd_msg = _check_writeable(os.getcwd())
    summary['write_ok'] = cwd_ok
    print(f"  {'[+]' if cwd_ok else '[-]'} CWD yazma: {cwd_msg}")

    print("\n[5] Ag / DNS")
    dns_ok, dns_msg = _check_dns()
    summary['dns_ok'] = dns_ok
    print(f"  {'[+]' if dns_ok else '[~]'} DNS: {dns_msg}")

    print("\n[6] Ozet")
    if summary['required_missing']:
        print("  [-] Kritik eksik moduller: " + ", ".join(summary['required_missing']))
        print("  [*] Kurulum onerisi: pip install " + " ".join(summary['required_missing']))
    else:
        print("  [+] Kritik moduller mevcut. SigPloit temel fonksiyonlari calisabilir.")

    if summary['tools_missing']:
        print("  [~] Eksik araclar: " + ", ".join(summary['tools_missing']))

    if not non_interactive:
        input("\nDevam etmek icin Enter'a basin...")

    return summary


if __name__ == "__main__":
    run_system_check()
