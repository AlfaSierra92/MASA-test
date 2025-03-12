import json
import sys
import csv
from scapy.all import rdpcap, UDP
from geopy.distance import geodesic


def parse_gprmc(sentence):
    parts = sentence.split(',')
    if len(parts) < 7 or parts[2] != 'A':
        return None

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


def load_udp_coordinates(pcap_file):
    packets = rdpcap(pcap_file)
    udp_coords = []
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer(UDP) and hasattr(pkt[UDP], "payload"):
            raw_payload = bytes(pkt[UDP].payload)
            payload_str = raw_payload.decode(errors="ignore")
            for line in payload_str.splitlines():
                if "$GPRMC" in line:
                    coords = parse_gprmc(line)
                    if coords:
                        udp_coords.append((i, coords[0], coords[1]))  # (ID, lat, lon)
    return udp_coords


def load_udp_ids(csv_file):
    udp_ids = set()
    with open(csv_file, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader, None)  # Salta l'intestazione se presente
        for row in reader:
            try:
                udp_id = int(row[0])  # Assumiamo che il CSV contenga una colonna con gli ID UDP
                udp_ids.add(udp_id)
            except ValueError:
                print(f"Errore nel parsing della riga CSV: {row}")
    return udp_ids


def calculate_distance_to_fixed_cam(udp_coords, cam_lat, cam_lon, udp_ids):
    cam_position = (cam_lat, cam_lon)
    for udp_id, lat, lon in udp_coords:
        if udp_id in udp_ids:
            distance = geodesic((lat, lon), cam_position).meters
            print(f"{udp_id},{distance:.5f}")


def main():
    if len(sys.argv) != 3:
        print("Uso: python script.py <file_pcap> <file_csv_udp_ids>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    csv_file = sys.argv[2]

    # Definisci qui le coordinate fisse della CAM
    cam_lat = 44.661164
    cam_lon = 10.934240

    # Caricare le coordinate UDP
    udp_coords = load_udp_coordinates(pcap_file)

    # Caricare gli ID UDP da considerare dal CSV
    udp_ids = load_udp_ids(csv_file)

    # Calcolare la distanza di ogni UDP rispetto alla CAM fissa (solo per gli ID presenti nel CSV)
    calculate_distance_to_fixed_cam(udp_coords, cam_lat, cam_lon, udp_ids)


if __name__ == "__main__":
    main()
