import grp
import os
import sys
import pwd
import pyshark
import pandas as pd
from datetime import datetime
from collections import deque
import time

connections = deque(maxlen=1000)

def check_permissions():
    try:
        user_id = os.getuid()
        user_name = pwd.getpwuid(user_id).pw_name
        groups = [g.gr_name for g in grp.getgrall() if user_name in g.gr_mem]
        
        if 'wireshark' in groups:
            print("The user has the necessary permissions to capture packets.\n---")
        else:
            print("The user does not have the necessary permissions. Please add the user to the 'wireshark' group.")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error checking permissions: {e}")
        sys.exit(1)


def extract_features(packet):
    try:
        # Informations de base sur le paquet
        timestamp = packet.sniff_time
        protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'unknown'
        length = int(packet.length)
        src_ip = packet.ip.src if hasattr(packet, 'ip') else None
        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
        src_port = int(packet.tcp.srcport) if hasattr(packet, 'tcp') else (
            int(packet.udp.srcport) if hasattr(packet, 'udp') else 0
        )
        dst_port = int(packet.tcp.dstport) if hasattr(packet, 'tcp') else (
            int(packet.udp.dstport) if hasattr(packet, 'udp') else 0
        )
        tcp_flags = packet.tcp.flags if hasattr(packet, 'tcp') else None

        # Basic features
        features = {
            'duration': 0,  # Durée d'une seule capture = 0
            'protocol_type': protocol.lower() if protocol else 'unknown',
            'service': dst_port,  # Mapping du port au service (ex: 80 = HTTP)
            'flag': 'SF' if tcp_flags and int(tcp_flags, 16) & 0x12 else 'OTH',  # SYN-ACK ou autre
            'src_bytes': length if src_port else 0,
            'dst_bytes': length if dst_port else 0,
            'land': 1 if src_ip == dst_ip and src_port == dst_port else 0,
            'wrong_fragment': 0,  # Placeholder (à calculer si nécessaire)
            'urgent': 0,  # Placeholder (à extraire si le paquet a des flags urgents)
        }

        # Ajout des connexions à l'historique
        connections.append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'flag': features['flag']
        })

        # Analyse basée sur une fenêtre glissante
        current_time = time.time()
        window_size = 2  # Fenêtre de 2 secondes
        recent_connections = [
            conn for conn in connections if (current_time - conn['timestamp'].timestamp()) < window_size
        ]

        # Calcul des statistiques
        serror_count = len([conn for conn in recent_connections if conn['flag'] == 'S0'])
        srv_serror_count = len([conn for conn in recent_connections if conn['flag'] == 'S0' and conn['dst_ip'] == dst_ip])
        rerror_count = len([conn for conn in recent_connections if conn['flag'] in ['REJ', 'RSTO']])
        srv_rerror_count = len([conn for conn in recent_connections if conn['flag'] in ['REJ', 'RSTO'] and conn['dst_ip'] == dst_ip])

        features.update({
            'count': len(recent_connections),
            'srv_count': len([conn for conn in recent_connections if conn['dst_ip'] == dst_ip]),
            'serror_rate': serror_count / len(recent_connections) if recent_connections else 0,
            'srv_serror_rate': srv_serror_count / len(recent_connections) if recent_connections else 0,
            'rerror_rate': rerror_count / len(recent_connections) if recent_connections else 0,
            'srv_rerror_rate': srv_rerror_count / len(recent_connections) if recent_connections else 0,
            'same_srv_rate': len([conn for conn in recent_connections if conn['dst_ip'] == dst_ip]) / len(recent_connections) if recent_connections else 0,
            'diff_srv_rate': len([conn for conn in recent_connections if conn['dst_ip'] != dst_ip]) / len(recent_connections) if recent_connections else 0,
            'srv_diff_host_rate': len([conn for conn in recent_connections if conn['dst_ip'] != dst_ip]) / len(recent_connections) if recent_connections else 0,
            'dst_host_count': len([conn for conn in recent_connections if conn['dst_ip'] == dst_ip]),
            'dst_host_srv_count': len([conn for conn in recent_connections if conn['dst_port'] == dst_port]),
            'dst_host_same_srv_rate': len([conn for conn in recent_connections if conn['dst_port'] == dst_port]) / len(recent_connections) if recent_connections else 0,
            'dst_host_diff_srv_rate': len([conn for conn in recent_connections if conn['dst_ip'] != dst_ip]) / len(recent_connections) if recent_connections else 0,
            'dst_host_same_src_port_rate': len([conn for conn in recent_connections if conn['src_port'] == src_port]) / len(recent_connections) if recent_connections else 0,
            'dst_host_srv_diff_host_rate': len([conn for conn in recent_connections if conn['dst_ip'] != dst_ip and conn['dst_port'] == dst_port]) / len(recent_connections) if recent_connections else 0,
            'dst_host_serror_rate': serror_count / len(recent_connections) if recent_connections else 0,
            'dst_host_srv_serror_rate': srv_serror_count / len(recent_connections) if recent_connections else 0,
            'dst_host_rerror_rate': rerror_count / len(recent_connections) if recent_connections else 0,
            'dst_host_srv_rerror_rate': srv_rerror_count / len(recent_connections) if recent_connections else 0,
        })

        return features

    except AttributeError as e:
        print(f"Erreur lors de l'extraction des features : {e}")
        return None




def capture_traffic(interface, output_file, capture_duration):
    print(f"Capture network packets on interface {interface} for {capture_duration} seconds...")
    capture = pyshark.LiveCapture(interface=interface)
    
    traffic_data = []
    start_time = datetime.now()
    
    try:
        for packet in capture.sniff_continuously():
            elapsed_time = (datetime.now() - start_time).seconds
            if elapsed_time >= capture_duration:
                print("Capture time reached, stop capture.")
                break

            print(f"Packet captured: {packet}")
            
            features = extract_features(packet)
            if features:
                traffic_data.append(features)

    except Exception as e:
        print(f"Error during capture: {e}")
    
    finally:
        capture.close()

    df = pd.DataFrame(traffic_data)
    df.to_csv(output_file, index=False)
    print(f"Capture complete. Data saved in {output_file}")