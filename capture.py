import grp
import os
import sys
import pwd
import pyshark
import pandas as pd
from datetime import datetime
from collections import deque
import time
from sklearn.preprocessing import LabelEncoder
import numpy as np
import pickle

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

        features = {
            'duration': 0,
            'protocol_type': protocol.lower() if protocol else 'unknown',
            'service': dst_port,
            'flag': 'SF' if tcp_flags and int(tcp_flags, 16) & 0x12 else 'OTH',
            'src_bytes': length if src_port else 0,
            'dst_bytes': length if dst_port else 0,
            'land': 1 if src_ip == dst_ip and src_port == dst_port else 0,
            'wrong_fragment': 0, 
            'urgent': 0,
        }

        connections.append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'flag': features['flag']
        })

        current_time = time.time()
        window_size = 2
        recent_connections = [
            conn for conn in connections if (current_time - conn['timestamp'].timestamp()) < window_size
        ]

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


def live_capture_traffic(interface, model_file, encoders_file):
    with open(model_file, 'rb') as file:
        model = pickle.load(file)

    with open(encoders_file, 'rb') as f:
        encoders = pickle.load(f)

    categorical_columns = ['protocol_type', 'service', 'flag']
    
    capture = pyshark.LiveCapture(interface=interface)
    
    try:
        for packet in capture.sniff_continuously():
            features = extract_features(packet)
            if features:
                print("Packet received")
                for col in categorical_columns:
                    try:
                        features[col] = encoders[col].transform([features[col]])[0]

                    except:
                        new_label = features[col]
                        encoder = encoders[col]

                        if new_label not in encoder.classes_:
                            encoder.classes_ = np.append(encoder.classes_, new_label)

                        with open(encoders_file, 'wb') as f:
                            pickle.dump(encoders, f)

                        features[col] = encoder.transform([features[col]])[0]

                features = pd.DataFrame([features])
                prediction = model.predict(features)
                print("anomalie detected!" if prediction[0] == 'attack' else "Normal")

    except Exception as e:
        print(f"Error during capture: {e}")
    
    finally:
        capture.close()