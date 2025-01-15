from streamlit import runtime
import grp
import os
import sys
import pwd
from collections import deque
import streamlit as st
import requests
from collections import defaultdict


connections = deque(maxlen=1000)

THRESHOLD_PACKETS = 100
THRESHOLD_PORTS = 50
MONITOR_INTERVAL = 5

ip_packet_count = defaultdict(int)
ip_target_count = defaultdict(set)
port_scan_count = defaultdict(lambda: defaultdict(set))


def detect_anomalies(elapsed_time):
    alerts = []
    detected_ips = set()

    for ip, count in ip_packet_count.items():
        for dst_ip, ports in port_scan_count[ip].items():
            if len(ports) > THRESHOLD_PORTS:
                alert = f"ALERT: Possible port scan detected from {ip} targeting {dst_ip} with {len(ports)} ports scanned in {elapsed_time} seconds."
                st.error(alert)
                alerts.append(alert)
                detected_ips.add(ip)
                return alerts 
            
        if count > THRESHOLD_PACKETS and ip not in detected_ips:
            alert = f"ALERT: Possible DDoS detected from {ip} with {count} packets in {elapsed_time} seconds."
            st.error(alert)
            alerts.append(alert)
            return alerts  

    return alerts


def is_streamlit():
    return runtime.exists()


def check_permissions():
    try:
        user_id = os.getuid()
        user_name = pwd.getpwuid(user_id).pw_name
        groups = [g.gr_name for g in grp.getgrall() if user_name in g.gr_mem]
        
        if 'wireshark' in groups:
            if is_streamlit():
                st.success("✅ The user has the necessary permissions to capture packets.")
            else:
                print("The user has the necessary permissions to capture packets.\n---")
        else:
            if is_streamlit():
                st.error("🚨 The user does not have the necessary permissions. Please add the user to the 'wireshark' group.")
            else:
                print("The user does not have the necessary permissions. Please add the user to the 'wireshark' group.")
            sys.exit(1)
    
    except Exception as e:
        if is_streamlit():
            st.error(f"Error checking permissions: {e}")
        else:
            print(f"Error checking permissions: {e}")
        sys.exit(1)


def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()