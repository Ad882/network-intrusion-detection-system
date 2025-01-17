from streamlit import runtime
import grp
import os
import sys
import pwd
from collections import deque
import streamlit as st
import requests
from collections import defaultdict
from typing import Optional


connections = deque(maxlen=1000)

# Abnormal traffic threshold:
THRESHOLD_PACKETS = 100
THRESHOLD_PORTS = 50
MONITOR_INTERVAL = 5

ip_packet_count = defaultdict(int)
ip_target_count = defaultdict(set)
port_scan_count = defaultdict(lambda: defaultdict(set))


def detect_anomalies(elapsed_time: float) -> list:
    """
    Fonction: detect_anomalies

    Input:
        - elapsed_time: float, Elapsed time between packets.
    
    Output:
        - alerts: list, Suspected alerts.

    Description:
        Detects potential port scan and DDoS (Distributed Denial of Service) attacks based on network packet analysis.
        The function checks whether any IP has scanned an excessive number of ports or has sent an unusually high
        number of packets in a given time period.
    """
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


def is_streamlit() -> bool:
    """
    Fonction: is_streamlit
    
    Input:
        - None

    Output:
        - boolean, Streamlit is running or not.

    Description:
        Detects if the streamlit application is running.
    """
    return runtime.exists()


def check_permissions():
    """
    Function: check_permissions

    Input:
        - None

    Output:
        - None

    Description:
        Checks if the current user has the necessary permissions to sniff packets using PyShark.
        It verifies if the user is part of the 'wireshark' group, which is typically required for packet capture operations.
        
        If the user has the correct permissions:
            - In Streamlit, a success message is displayed.
            - In a standard environment, a success message is printed to the console.
        
        If the user does not have the necessary permissions:
            - In Streamlit, an error message is displayed, instructing the user to add the user to the 'wireshark' group.
            - In a standard environment, an error message is printed, and the program exits with status code 1.

        If any error occurs while checking the permissions, the function:
            - In Streamlit, displays an error message with the exception details.
            - In a standard environment, prints the exception details and exits with status code 1.

    """
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


def load_lottieurl(url: str) -> Optional[dict]:
    """
    Function: load_lottieurl

    Input:
        - url: str, URL pointing to the Lottie animation JSON file.

    Output:
        - Optional[dict], Returns the JSON response as a dictionary if the request is successful (status code 200).
                          Returns None if the request fails (status code is not 200).

    Description:
        Loads and displays the lottie animation.
    """
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()