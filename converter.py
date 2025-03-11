from scapy.all import rdpcap, wrpcap, UDP, IP, Raw

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

# Caricare il file PCAP originale
input_pcap = "test555.pcap"  # Modifica con il percorso corretto
output_pcap = "filtered_udp.pcap"
packets = rdpcap(input_pcap)

# Nuovi pacchetti
new_packets = []

for pkt in packets:
    if pkt.haslayer(UDP) and hasattr(pkt[UDP], "payload"):
        raw_payload = bytes(pkt[UDP].payload)
        payload_str = raw_payload.decode(errors="ignore")
        modified = False
        for line in payload_str.splitlines():
            if "$GPRMC" in line:
                coords = parse_gprmc(line)
                if coords:
                    new_payload = f"Lat: {coords[0]:.6f}, Lon: {coords[1]:.6f}\n"
                    new_pkt = pkt.copy()
                    new_pkt[Raw].load = new_payload.encode()
                    new_packets.append(new_pkt)
                    modified = True
                    break
        if not modified:
            new_packets.append(pkt)
    else:
        new_packets.append(pkt)

# Scrivere il nuovo PCAP
wrpcap(output_pcap, new_packets)
print(f"Creato {output_pcap} con pacchetti originali e UDP GPRMC convertiti.")
