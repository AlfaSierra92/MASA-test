import folium
import json
import math
import csv
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


# Caricare il file PCAP
input_pcap = "test2222.pcap"  # Modifica con il percorso corretto
packets = rdpcap(input_pcap)

# Liste di coordinate
udp_coords = []
cam_coords = []

# Estrarre coordinate dai pacchetti UDP
for i, pkt in enumerate(packets, start=1):
    if pkt.haslayer(UDP) and hasattr(pkt[UDP], "payload"):
        raw_payload = bytes(pkt[UDP].payload)
        payload_str = raw_payload.decode(errors="ignore")
        for line in payload_str.splitlines():
            if "$GPRMC" in line:
                coords = parse_gprmc(line)
                if coords:
                    udp_coords.append((i, coords[0], coords[1]))  # (ID, lat, lon)

# Salvare i dati UDP in un CSV
csv_output = "udp_ids.csv"
with open(csv_output, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["ID"])
    for packet_id in udp_coords:
        writer.writerow([packet_id[0]])
print(f"Dati UDP salvati in {csv_output}")

# Caricare coordinate dai pacchetti CAM in JSON
input_json = "test2222_parsed.json"  # Modifica con il percorso corretto
with open(input_json, "r", encoding="utf-8") as f:
    cam_data = json.load(f)
    for i, packet in enumerate(cam_data, start=1):
        try:
            lat = int(packet["Latitude"]) / 10000000.0
            lon = int(packet["Longitude"]) / 10000000.0
            cam_coords.append((i, lat, lon))  # (ID, lat, lon)
        except (KeyError, ValueError) as e:
            print(f"Errore nel parsing del JSON: {e}")

# Creare la mappa
m = folium.Map(location=udp_coords[0][1:] if udp_coords else cam_coords[0][1:] if cam_coords else [0, 0], zoom_start=18, max_zoom=25)
m.add_child(MeasureControl(primary_length_unit='meters'))

# Aggiungere tracce UDP con popup
for packet_id, lat, lon in udp_coords:
    folium.CircleMarker(
        [lat, lon],
        radius=3,  # Marker più piccolo
        color='blue',
        fill=True,
        fill_color='blue',
        fill_opacity=0.6,
        popup=f"UDP Packet ID: {packet_id}<br>Lat: {lat:.6f}, Lon: {lon:.6f}"
    ).add_to(m)

# Aggiungere tracce CAM con popup
for packet_id, lat, lon in cam_coords:
    folium.CircleMarker(
        [lat, lon],
        radius=3,  # Marker più piccolo
        color='red',
        fill=True,
        fill_color='red',
        fill_opacity=0.6,
        popup=f"CAM Packet ID: {packet_id}<br>Lat: {lat:.6f}, Lon: {lon:.6f}"
    ).add_to(m)

# Salvare la mappa
map_output = "map.html"
m.save(map_output)
print(f"Mappa salvata come {map_output}")
