import grp
import os
import sys
import pwd
import pyshark
import pandas as pd
from datetime import datetime


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
        protocol = packet.highest_layer
        length = int(packet.length)

        src_ip = packet.ip.src if hasattr(packet, 'ip') else None
        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
        src_port = packet.tcp.srcport if hasattr(packet, 'tcp') else None
        dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else None

        return {
            'timestamp': timestamp,
            'protocol': protocol,
            'length': length,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port
        }
    except Exception as e:
        print(f"Error during extraction: {e}")
        return None


def capture_traffic(interface='wlp1s0', output_file='network_traffic.csv', capture_duration=30):
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



check_permissions()
capture_traffic()