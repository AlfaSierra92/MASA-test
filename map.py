import folium
from scapy.all import rdpcap, UDP

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

def extract_gps_from_cam(pkt):
    try:
        raw_payload = bytes(pkt.payload)
        payload_str = raw_payload.decode(errors="ignore")
        if "$GPRMC" in payload_str:
            return parse_gprmc(payload_str)
    except:
        pass
    return None

# Caricare il file PCAP
input_pcap = "test555.pcap"  # Modifica con il percorso corretto
packets = rdpcap(input_pcap)

# Liste di coordinate
udp_coords = []
cam_coords = []

for pkt in packets:
    if pkt.haslayer(UDP) and hasattr(pkt[UDP], "payload"):
        raw_payload = bytes(pkt[UDP].payload)
        payload_str = raw_payload.decode(errors="ignore")
        for line in payload_str.splitlines():
            if "$GPRMC" in line:
                coords = parse_gprmc(line)
                if coords:
                    udp_coords.append(coords)
    elif "CAM" in str(pkt):  # Identificare pacchetti CAM
        cam_coords = extract_gps_from_cam(pkt)
        if cam_coords:
            cam_coords.append(cam_coords)

# Creare la mappa
m = folium.Map(location=udp_coords[0] if udp_coords else [0, 0], zoom_start=14)

# Aggiungere tracce UDP
for lat, lon in udp_coords:
    folium.CircleMarker([lat, lon], radius=5, color='blue', fill=True, fill_color='blue', fill_opacity=0.6).add_to(m)

# Aggiungere tracce CAM
for lat, lon in cam_coords:
    folium.CircleMarker([lat, lon], radius=5, color='red', fill=True, fill_color='red', fill_opacity=0.6).add_to(m)

# Salvare la mappa
map_output = "map.html"
m.save(map_output)
print(f"Mappa salvata come {map_output}")

