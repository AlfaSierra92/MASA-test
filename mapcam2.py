import folium
import json
import math
from scapy.all import rdpcap, UDP
from folium.plugins import MeasureControl


def parse_gprmc(sentence):
    parts = sentence.split(',')
    if len(parts) < 7 or parts[2] != 'A':
        return None  # Sentenza non valida o posizione non disponibile

    lat_deg = int(parts[3][:2])
    lat_min = float(parts[3][2:])
    lat = lat_deg + (lat_min / 60)
    if parts[4] == 'S':
        lat = -lat

    lon_deg = int(parts[5][:3])
    lon_min = float(parts[5][3:])
    lon = lon_deg + (lon_min / 60)
    if parts[6] == 'W':
        lon = -lon

    return lat, lon


def haversine(lat1, lon1, lat2, lon2):
    R = 6371000  # Raggio della Terra in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c  # Distanza in km


# Caricare il file PCAP
input_pcap = "test555.pcap"  # Modifica con il percorso corretto
packets = rdpcap(input_pcap)

# Liste di coordinate
udp_coords = []
cam_coords = []

# Estrarre coordinate dai pacchetti UDP
for pkt in packets:
    if pkt.haslayer(UDP) and hasattr(pkt[UDP], "payload"):
        raw_payload = bytes(pkt[UDP].payload)
        payload_str = raw_payload.decode(errors="ignore")
        for line in payload_str.splitlines():
            if "$GPRMC" in line:
                coords = parse_gprmc(line)
                if coords:
                    udp_coords.append(coords)

# Caricare coordinate dai pacchetti CAM in JSON
input_json = "cam_data.json"  # Modifica con il percorso corretto
with open(input_json, "r", encoding="utf-8") as f:
    cam_data = json.load(f)
    for packet in cam_data:
        try:
            lat = int(packet["Latitude"]) / 10000000.0
            lon = int(packet["Longitude"]) / 10000000.0
            cam_coords.append((lat, lon))
        except (KeyError, ValueError) as e:
            print(f"Errore nel parsing del JSON: {e}")

# Creare la mappa
m = folium.Map(location=udp_coords[0] if udp_coords else cam_coords[0] if cam_coords else [0, 0], zoom_start=18, max_zoom=20)
m.add_child(MeasureControl(primary_length_unit='meters'))

# Aggiungere tracce UDP
for lat, lon in udp_coords:
    folium.CircleMarker([lat, lon], radius=1, color='blue', fill=True, fill_color='blue', fill_opacity=0.6).add_to(m)

# Aggiungere tracce CAM
for lat, lon in cam_coords:
    folium.CircleMarker([lat, lon], radius=1, color='red', fill=True, fill_color='red', fill_opacity=0.6).add_to(m)

# Salvare la mappa
map_output = "map.html"
m.save(map_output)
print(f"Mappa salvata come {map_output}")
