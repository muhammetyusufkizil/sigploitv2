#!/usr/bin/env python3
"""Quick check of OpenCellID CSV data for Adiyaman area."""

count = 0
matches = []
total = 0

with open('opencellid_286.csv', 'r') as f:
    for line in f:
        total += 1
        parts = line.strip().split(',')
        if len(parts) < 8:
            continue
        try:
            lon = float(parts[6])
            lat = float(parts[7])
            
            # Adiyaman: lat=37.76, lon=38.28
            if 37.5 < lat < 38.0 and 37.8 < lon < 38.8:
                count += 1
                if count <= 15:
                    matches.append(f"  lon={lon}, lat={lat} -> {line.strip()[:90]}")
        except:
            pass

print(f"Toplam satir: {total}")
print(f"Adiyaman bolgesi (lat 37.5-38.0, lon 37.8-38.8): {count} kayit")
print()

if matches:
    for m in matches:
        print(m)
else:
    print("HICBIR KAYIT YOK!")
    print()
    # Tum farkli lat/lon araligini goster
    lats = []
    lons = []
    with open('opencellid_286.csv', 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 8:
                continue
            try:
                lon = float(parts[6])
                lat = float(parts[7])
                lats.append(lat)
                lons.append(lon)
            except:
                pass
    
    print(f"Lat aralik: {min(lats):.2f} - {max(lats):.2f}")
    print(f"Lon aralik: {min(lons):.2f} - {max(lons):.2f}")
    print()
    
    # Adiyaman'a en yakin kayitlari bul
    import math
    target_lat, target_lon = 37.7648, 38.2786
    closest = []
    with open('opencellid_286.csv', 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 8:
                continue
            try:
                lon = float(parts[6])
                lat = float(parts[7])
                dist = math.sqrt((lat - target_lat)**2 + (lon - target_lon)**2) * 111
                closest.append((dist, line.strip()[:100]))
            except:
                pass
    
    closest.sort()
    print("En yakin 10 kayit (Adiyaman 37.7648, 38.2786):")
    for d, l in closest[:10]:
        print(f"  {d:.1f}km -> {l}")
