#!/usr/bin/env python
"""
SigPloit Web Dashboard
Flask-based web interface for viewing scan results, attack logs, and reports.

Usage: python web/dashboard.py
Opens at: http://localhost:5000
"""
import sys
import os
import json
import glob
import datetime
import threading

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from flask import Flask, render_template, jsonify, send_file, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))

if HAS_FLASK:
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

    # ============================================
    # ROUTES
    # ============================================

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/summary')
    def api_summary():
        """Get overall summary statistics."""
        summary = {
            'total_targets': 0,
            'total_verified': 0,
            'total_vulnerabilities': 0,
            'protocols': {},
            'recent_scans': [],
            'files': [],
        }

        # Count targets from leak files
        leak_files = {
            'SS7': ['leaks_ss7.txt', 'leaks.txt'],
            'Diameter': ['leaks_diameter_new.txt', 'leaks_diameter.txt'],
            'GTP': ['leaks_gtp.txt'],
            'SIP': ['leaks_sip.txt'],
        }

        for proto, files in leak_files.items():
            count = 0
            for fname in files:
                fpath = os.path.join(ROOT_DIR, fname)
                if os.path.exists(fpath):
                    try:
                        with open(fpath, 'r') as f:
                            count = sum(1 for line in f if line.strip() and not line.startswith('#'))
                    except Exception:
                        pass
                    break
            summary['protocols'][proto] = count
            summary['total_targets'] += count

        # Count verified
        for fname in ['turkey_verified.txt', 'verified_results.txt']:
            fpath = os.path.join(ROOT_DIR, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath, 'r') as f:
                        summary['total_verified'] += sum(1 for line in f if line.strip())
                except Exception:
                    pass

        # Count vulnerabilities from result files
        for pattern in ['diameter_results.txt', 'sip_results.txt', 'chain_summary_*.txt']:
            for fpath in glob.glob(os.path.join(ROOT_DIR, pattern)):
                try:
                    with open(fpath, 'r') as f:
                        content = f.read()
                        summary['total_vulnerabilities'] += content.upper().count('VULNERABLE')
                        summary['total_vulnerabilities'] += content.upper().count('ZAFIYET')
                except Exception:
                    pass

        # List result files
        result_patterns = ['leaks_*.txt', 'turkey_*.txt', 'shodan_*.txt', 'censys_*.txt',
                           'diameter_*.txt', 'sip_*.txt', 'chain_*.txt', 'verified_*.txt',
                           '*.json']
        for pattern in result_patterns:
            for fpath in glob.glob(os.path.join(ROOT_DIR, pattern)):
                fname = os.path.basename(fpath)
                if fname == 'config.ini' or fname.endswith('.py'):
                    continue
                try:
                    stat = os.stat(fpath)
                    summary['files'].append({
                        'name': fname,
                        'size': stat.st_size,
                        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    })
                except Exception:
                    pass

        summary['files'].sort(key=lambda x: x['modified'], reverse=True)

        return jsonify(summary)

    @app.route('/api/targets')
    def api_targets():
        """Get all discovered targets."""
        targets = []

        for fname in os.listdir(ROOT_DIR):
            if not fname.startswith('leaks_') and not fname.startswith('shodan_'):
                continue
            if not fname.endswith('.txt'):
                continue

            fpath = os.path.join(ROOT_DIR, fname)
            proto = 'Unknown'
            if 'diameter' in fname.lower():
                proto = 'Diameter'
            elif 'ss7' in fname.lower():
                proto = 'SS7'
            elif 'gtp' in fname.lower():
                proto = 'GTP'
            elif 'sip' in fname.lower():
                proto = 'SIP'

            try:
                with open(fpath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split('|')
                        ip_port = parts[0].strip().split(':')
                        if len(ip_port) >= 2:
                            targets.append({
                                'ip': ip_port[0].strip(),
                                'port': ip_port[1].strip(),
                                'protocol': proto,
                                'org': parts[1].strip() if len(parts) > 1 else '',
                                'country': parts[2].strip() if len(parts) > 2 else '',
                                'source': fname,
                            })
            except Exception:
                pass

        return jsonify({'targets': targets, 'total': len(targets)})

    @app.route('/api/results')
    def api_results():
        """Get attack results."""
        results = []

        for fname in ['diameter_results.txt', 'sip_results.txt']:
            fpath = os.path.join(ROOT_DIR, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                results.append({
                                    'source': fname,
                                    'line': line,
                                })
                except Exception:
                    pass

        # Check chain summaries
        for fpath in glob.glob(os.path.join(ROOT_DIR, 'chain_summary_*.txt')):
            try:
                with open(fpath, 'r') as f:
                    results.append({
                        'source': os.path.basename(fpath),
                        'line': f.read()[:500],
                    })
            except Exception:
                pass

        return jsonify({'results': results, 'total': len(results)})

    @app.route('/api/geoip/<ip>')
    def api_geoip(ip):
        """Get GeoIP info for an IP address."""
        try:
            import requests
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,lat,lon,isp,org,as",
                               timeout=5)
            if resp.status_code == 200:
                return jsonify(resp.json())
        except Exception:
            pass
        return jsonify({'status': 'fail', 'message': 'GeoIP lookup failed'})

    @app.route('/api/map-data')
    def api_map_data():
        """Get GeoIP data for map visualization."""
        targets = []
        seen_ips = set()

        for fname in os.listdir(ROOT_DIR):
            if not (fname.startswith('leaks_') or fname.startswith('shodan_') or fname.startswith('verified_')):
                continue
            if not fname.endswith('.txt'):
                continue

            fpath = os.path.join(ROOT_DIR, fname)
            try:
                with open(fpath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        ip = line.split(':')[0].split('|')[0].strip()
                        if ip and ip[0].isdigit() and ip not in seen_ips:
                            seen_ips.add(ip)
                            if len(seen_ips) >= 100:  # Limit for performance
                                break
            except Exception:
                pass
            if len(seen_ips) >= 100:
                break

        # Batch GeoIP lookup (using ip-api batch)
        ip_list = list(seen_ips)[:100]
        geo_data = []

        try:
            import requests
            # ip-api supports batch queries
            batch_size = 100
            for i in range(0, len(ip_list), batch_size):
                batch = ip_list[i:i+batch_size]
                resp = requests.post("http://ip-api.com/batch",
                                    json=[{"query": ip} for ip in batch],
                                    timeout=10)
                if resp.status_code == 200:
                    for item in resp.json():
                        if item.get('status') == 'success':
                            geo_data.append({
                                'ip': item.get('query', ''),
                                'lat': item.get('lat', 0),
                                'lon': item.get('lon', 0),
                                'country': item.get('country', ''),
                                'city': item.get('city', ''),
                                'isp': item.get('isp', ''),
                                'org': item.get('org', ''),
                            })
        except Exception:
            pass

        return jsonify({'locations': geo_data, 'total_ips': len(seen_ips)})

    @app.route('/download/<filename>')
    def download_file(filename):
        """Download a result file."""
        fpath = os.path.join(ROOT_DIR, filename)
        if os.path.exists(fpath) and not '..' in filename:
            return send_file(fpath, as_attachment=True)
        return "File not found", 404


def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Start the web dashboard."""
    if not HAS_FLASK:
        print("[-] Flask kurulu degil! Kurmak icin: pip install flask")
        print("[-] Alternatif: pip install flask flask-cors")
        return

    print(f"\n[+] SigPloit Web Dashboard baslatiliyor...")
    print(f"[+] Adres: http://localhost:{port}")
    print(f"[+] Durdurmak icin Ctrl+C\n")

    app.run(host=host, port=port, debug=debug)


def run_dashboard_background(host='0.0.0.0', port=5000):
    """Start dashboard in background thread."""
    if not HAS_FLASK:
        print("[-] Flask kurulu degil!")
        return None

    thread = threading.Thread(target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
                              daemon=True)
    thread.start()
    print(f"[+] Dashboard arka planda calisiyor: http://localhost:{port}")
    return thread


if __name__ == '__main__':
    run_dashboard(debug=True)
