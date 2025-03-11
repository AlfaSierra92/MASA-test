from scapy.all import rdpcap, wrpcap, UDP, IP, Raw
from geopy.distance import geodesic

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

# Caricare il file PCAP originale
input_pcap = "test555.pcap"  # Modifica con il percorso corretto
output_pcap = "filtered_udp.pcap"
packets = rdpcap(input_pcap)

# Nuovi pacchetti filtrati
filtered_packets = []
current_cam_packets = []
current_udp_coord = None

for pkt in packets:
    if pkt.haslayer(UDP) and hasattr(pkt[UDP], "payload"):
        raw_payload = bytes(pkt[UDP].payload)
        payload_str = raw_payload.decode(errors="ignore")
        for line in payload_str.splitlines():
            if "$GPRMC" in line:
                coords = parse_gprmc(line)
                if coords:
                    filtered_packets.append(pkt)
                    current_udp_coord = coords
                    
                    # Filtrare CAM basandosi sulla distanza
                    if current_cam_packets:
                        closest_cam = min(
                            current_cam_packets,
                            key=lambda cam_pkt: geodesic(current_udp_coord, extract_gps_from_cam(cam_pkt)).meters,
                            default=None
                        )
                        if closest_cam:
                            filtered_packets.append(closest_cam)
                    current_cam_packets = []

    elif "CAM" in str(pkt):  # Identificare pacchetti CAM
        cam_coords = extract_gps_from_cam(pkt)
        if cam_coords:
            current_cam_packets.append(pkt)

# Scrivere il nuovo PCAP
wrpcap(output_pcap, filtered_packets)
print(f"Creato {output_pcap} con CAM filtrati in base alla distanza rispetto agli UDP.")

