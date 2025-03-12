import json
import sys
from scapy.all import rdpcap, UDP
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


def load_cam_coordinates(json_file):
    cam_coords = []
    with open(json_file, "r", encoding="utf-8") as f:
        cam_data = json.load(f)
        for i, packet in enumerate(cam_data, start=1):
            try:
                lat = int(packet["Latitude"]) / 10000000.0
                lon = int(packet["Longitude"]) / 10000000.0
                cam_coords.append((i, lat, lon))  # (ID, lat, lon)
            except (KeyError, ValueError) as e:
                print(f"Errore nel parsing del JSON: {e}")
    return cam_coords


def find_coordinates_by_id(coords_list, packet_id):
    for cid, lat, lon in coords_list:
        if cid == packet_id:
            return lat, lon
    return None


def calculate_distance(udp_id, cam_id, udp_coords, cam_coords):
    udp_coords_found = find_coordinates_by_id(udp_coords, udp_id)
    cam_coords_found = find_coordinates_by_id(cam_coords, cam_id)

    if udp_coords_found and cam_coords_found:
        distance = geodesic(udp_coords_found, cam_coords_found).meters
        print(f"Distanza tra UDP ID {udp_id} e CAM ID {cam_id}: {distance:.2f} metri")
    else:
        print("Non sono state trovate le coordinate per gli ID dati.")


def main():
    #if len(sys.argv) != 4:
    #    print("Uso: python script.py <file_pcap> <file_json> <udp_id> <cam_id>")
    #    sys.exit(1)

    pcap_file = sys.argv[1]
    json_file = sys.argv[2]
    udp_id = int(sys.argv[3])
    cam_id = int(sys.argv[4])

    # Caricare le coordinate
    udp_coords = load_udp_coordinates(pcap_file)
    cam_coords = load_cam_coordinates(json_file)

    # Calcolare la distanza
    calculate_distance(udp_id, cam_id, udp_coords, cam_coords)


if __name__ == "__main__":
    main()
