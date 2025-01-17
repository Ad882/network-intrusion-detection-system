import pandas as pd
import pickle
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from utils import is_streamlit
import dpkt
import socket
import pandas as pd
from collections import defaultdict
from typing import Tuple, Optional


PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}


def analyze_packet(packet: bytes) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Function: analyze_packet

    Input:
        - packet: bytes, binary data sequence representing the raw Ethernet packet.
    
    Output:
        - src_ip: Optional[str], Packet's source IP address (str) or None if the analysis fails.
        - dst_ip: Optional[str], Packet's destination IP address (str) or None if the analysis fails.
        - dst_port: Optional[int], Packet's destination port (int) or None if the analysis fails or if no port is found.

    Description:
        Extracts useful information from the packet, such as the source IP (src_ip), 
        destination IP (dst_ip), and destination port (dst_port). If the packet 
        cannot be analyzed or the necessary information is not found, it returns None 
        for the respective fields.
    """
    try:
        eth = dpkt.ethernet.Ethernet(packet)
        if not isinstance(eth.data, dpkt.ip.IP):
            return None, None, None
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            transport = ip.data
            dst_port = transport.dport
            return src_ip, dst_ip, dst_port
        return src_ip, dst_ip, None
    except Exception:
        return None, None, None


def process_pcap(file_path: str) -> pd.DataFrame:
    """
    Function: process_pcap

    Input:
        - file_path: str, Path to the PCAP file to be processed.

    Output:
        - pd.DataFrame, A DataFrame containing processed network features derived from the PCAP file.

    Description:
        Processes a given PCAP file, extracting various network-related features from the captured packets.
        The function analyzes the Ethernet, IP, and transport layers of the packets, and calculates several statistics 
        such as packet counts, error rates, and service rates.

        For each packet in the PCAP file:
            - It extracts the source and destination IP addresses, ports, and protocol information.
            - It calculates various features, including packet counts, error rates, and service-related rates.
            - It handles the following error rates:
                - SYN + RST errors (for TCP)
                - ICMP errors (for protocol 1)
            - The function also calculates the rate of services, errors, and other packet statistics.

        The features extracted from each packet are added to a list, which is then converted into a pandas DataFrame.
        The resulting DataFrame contains the following columns:
            - `duration`: Duration between the last two packets from the same source IP.
            - `protocol_type`: The protocol name (e.g., TCP, UDP, ICMP).
            - `service`: The destination port number.
            - `flag`: TCP flag type (e.g., SF, OTH).
            - `src_bytes`: The number of bytes from the source IP.
            - `dst_bytes`: The number of bytes to the destination IP.
            - `land`: A binary flag indicating if the packet is a land attack.
            - `count`: The total number of packets exchanged between the source and destination IP.
            - Additional features related to error rates, service rates, and other network characteristics.

        This function reads the PCAP file using `dpkt` and processes it packet by packet, storing relevant data 
        in a pandas DataFrame that can be used for further analysis or machine learning purposes.
    """
    data = []
    packet_counts = defaultdict(int)  
    srv_counts = defaultdict(int)     
    serror_counts = defaultdict(int)  
    rerror_counts = defaultdict(int) 

    previous_timestamp = None

    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                protocol = ip.p
                protocol_name = PROTOCOL_MAP.get(protocol, f"UNKNOWN ({protocol})")
                transport = ip.data

                src_port = getattr(transport, 'sport', None)
                dst_port = getattr(transport, 'dport', None)
                tcp_flags = getattr(transport, 'flags', None) if protocol == 6 else None

                packet_counts[(src_ip, dst_port)] += 1
                if dst_port:
                    srv_counts[dst_port] += 1

                if previous_timestamp is not None:
                    time_delta = timestamp - previous_timestamp
                else:
                    time_delta = 0
                previous_timestamp = timestamp

                src_bytes = len(buf) if hasattr(ip, 'data') else 0
                dst_bytes = src_bytes

                if protocol == 6 and tcp_flags & dpkt.tcp.TH_SYN and tcp_flags & dpkt.tcp.TH_RST:
                    serror_counts[(src_ip, dst_port)] += 1
                if protocol == 1:
                    rerror_counts[(src_ip, dst_port)] += 1

            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
            
            same_srv_rate = srv_counts[dst_port] / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            diff_srv_rate = (packet_counts[(src_ip, dst_ip)] - srv_counts[dst_port]) / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            serror_rate = serror_counts[(src_ip, dst_port)] / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            srv_serror_rate = serror_counts[(src_ip, dst_port)] / srv_counts[dst_port] if srv_counts[dst_port] > 0 else 0
            rerror_rate = rerror_counts[(src_ip, dst_port)] / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            srv_rerror_rate = rerror_counts[(src_ip, dst_port)] / srv_counts[dst_port] if srv_counts[dst_port] > 0 else 0

            data.append({
                'duration': time_delta,
                'protocol_type': protocol_name,
                'service': dst_port,
                'flag': 'SF' if tcp_flags and (tcp_flags & dpkt.tcp.TH_SYN and tcp_flags & dpkt.tcp.TH_ACK) else 'OTH',
                'src_bytes': src_bytes,
                'dst_bytes': dst_bytes,
                'land': 1 if src_ip == dst_ip and src_port == dst_port else 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'count': packet_counts[(src_ip, dst_ip)],
                'srv_count': srv_counts[dst_port],
                'serror_rate': serror_rate,
                'srv_serror_rate': srv_serror_rate,
                'rerror_rate': rerror_rate,
                'srv_rerror_rate': srv_rerror_rate,
                'same_srv_rate': same_srv_rate,
                'diff_srv_rate': diff_srv_rate,
                'srv_diff_host_rate': diff_srv_rate,
                'dst_host_count': len(set([dst_ip for src_ip, dst_ip in packet_counts.keys()])),
                'dst_host_srv_count': srv_counts[dst_port],
                'dst_host_same_srv_rate': srv_counts[dst_port] / len(set([dst_ip for src_ip, dst_ip in packet_counts.keys()])) if len(set([dst_ip for src_ip, dst_ip in packet_counts.keys()])) > 0 else 0,
                'dst_host_diff_srv_rate': 0,
                'dst_host_same_src_port_rate': 0,
                'dst_host_srv_diff_host_rate': 0,
                'dst_host_serror_rate': serror_rate,
                'dst_host_srv_serror_rate': srv_serror_rate,
                'dst_host_rerror_rate': rerror_rate,
                'dst_host_srv_rerror_rate': srv_rerror_rate,
                'src_ip': src_ip,
            })
    
    df = pd.DataFrame(data)
    return df



def preprocessing(capture_file: str, encoders_file: str) -> pd.DataFrame:
    """
    Function: preprocessing

    Input:
        - capture_file: str, Path to the CSV file containing the capture data (network traffic).
        - encoders_file: str, Path to the pickle file containing encoders for categorical columns.

    Output:
        - pd.DataFrame, A processed DataFrame where categorical columns are encoded, and the 'src_ip' column 
          is restored to its original state.

    Description:
        Performs preprocessing on the network traffic data contained in the provided CSV file.
        Specifically, it handles the encoding of categorical features using pre-existing encoders stored in a pickle 
        file. If a new category is encountered in any categorical column, the encoder is updated and saved back 
        to the pickle file.
    """
    with open(encoders_file, 'rb') as f:
        encoders = pickle.load(f)

    data = pd.read_csv(capture_file)
    temp_series = pd.Series(data['src_ip'])
    data.drop(columns=['src_ip'], inplace=True)

    categorical_columns = ['protocol_type', 'service', 'flag']
    for col in categorical_columns:
        try:
            data[col] = encoders[col].fit_transform(data[col])

        except:
            new_label = data[col]
            encoder = encoders[col]

            if new_label not in encoder.classes_:
                encoder.classes_ = np.append(encoder.classes_, new_label)

            with open(encoders_file, 'wb') as f:
                pickle.dump(encoders, f)

            data[col] = encoders[col].fit_transform(data[col])

    data['src_ip'] = temp_series
    return data




def plot_src_bytes_vs_dst_bytes(data: pd.DataFrame, anomalies: pd.DataFrame):
    """
    Function: plot_src_bytes_vs_dst_bytes

    Input:
        - data: pd.DataFrame, A DataFrame containing the normal data with columns for 'src_bytes' and 'dst_bytes'.
        - anomalies: pd.DataFrame, A DataFrame containing the anomalous data with columns for 'src_bytes' and 'dst_bytes'.

    Output:
        - None, The function visualizes the data in a scatter plot and displays it using Plotly.

    Description:
        Creates a scatter plot to visualize the relationship between 'src_bytes' and 'dst_bytes' in 
        network traffic data. It distinguishes normal data points from anomalies by plotting them in different colors 
        and styles.
    """
    x_data = 'src_bytes'
    y_data = 'dst_bytes'

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=data[x_data],
        y=data[y_data],
        mode='markers',
        marker=dict(color='blue', size=6, opacity=0.6),
        name='Normal'
    ))
    fig.add_trace(go.Scatter(
        x=anomalies[x_data],
        y=anomalies[y_data],
        mode='markers',
        marker=dict(color='red', size=8, line=dict(width=1, color='black')),
        name='anomalies'
    ))
    fig.update_layout(
        title=f'Visualization of Detected anomalies ({x_data} vs {y_data})',
        xaxis_title=f'{x_data}',
        yaxis_title=f'{y_data}',
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
        template='plotly_white'
    )

    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()


def plot_duration(data: pd.DataFrame, anomalies: pd.DataFrame):
    """
    Function: plot_duration

    Input:
        - data: pd.DataFrame, A DataFrame containing the normal data with columns for 'duration'.
        - anomalies: pd.DataFrame, A DataFrame containing the anomalous data with columns for 'duration'.

    Output:
        - None, The function visualizes the data in a scatter plot and displays it using Plotly.

    Description:
        Creates a scatter plot to visualize the packets duration in network traffic data. 
        It distinguishes normal data points from anomalies by plotting them in different colors 
        and styles.
    """
    y_data = 'duration'

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=data.index,
        y=data[y_data],
        mode='markers',
        marker=dict(color='blue', size=6, opacity=0.6),
        name='Normal'
    ))
    fig.add_trace(go.Scatter(
        x=anomalies.index,
        y=anomalies[y_data],
        mode='markers',
        marker=dict(color='red', size=8, line=dict(width=1, color='black')),
        name='anomalies'
    ))
    fig.update_layout(
        title=f'Visualization of Detected anomalies (packet duration)',
        xaxis_title='Index',
        yaxis_title='packet duration',
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
        template='plotly_white'
    )

    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()


def plot_count(data: pd.DataFrame):
    """
    Function: plot_count

    Input:
        - data: pd.DataFrame, A DataFrame containing the normal data with columns for 'protocol_type', 'src_ip'.
        - anomalies: pd.DataFrame, A DataFrame containing the anomalous data with columns for 'protocol_type', 'src_ip'.

    Output:
        - None, The function visualizes the data in an histogram plot and displays it using Plotly.

    Description:
        Creates an histogram plot to visualize the number of packets sent by ip in network traffic data. 
        It distinguishes normal data points from anomalies by plotting them in different colors 
        and styles.
    """
    count_by_src_ip = data.loc[:, ['protocol_type', 'src_ip']].groupby(["src_ip"]).count()
    fig = px.histogram(count_by_src_ip, x=count_by_src_ip.index, y="protocol_type")
    fig.update_layout(
        title="Histogram of packets sent by source ip",
        xaxis_title="source IP",
        yaxis_title="Number of packets sent")
    
    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()


def plot_dst_host_count(data: pd.DataFrame):
    """
    Function: plot_dst_host_count

    Input:
        - data: pd.DataFrame, A DataFrame containing the normal data with columns for 'dst_host_count'.
        - anomalies: pd.DataFrame, A DataFrame containing the anomalous data with columns for 'dst_host_count'.

    Output:
        - None, The function visualizes the data in an histogram plot and displays it using Plotly.

    Description:
        Creates an histogram plot to visualize the packets dst_host_count in network traffic data. 
        It distinguishes normal data points from anomalies by plotting them in different colors 
        and styles.
    """
    fig = px.histogram(data, x="dst_host_count", title="Histogram of dst_host_count")
    
    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()


def plot_src_ip_vs_dst_port(data: pd.DataFrame, anomalies: pd.DataFrame):
    """
    Function: plot_src_ip_vs_dst_port

    Input:
        - data: pd.DataFrame, A DataFrame containing the normal data with columns for 'src_ip' and 'service'.
        - anomalies: pd.DataFrame, A DataFrame containing the anomalous data with columns for 'src_ip' and 'service'.

    Output:
        - None, The function visualizes the data in a scatter plot and displays it using Plotly.

    Description:
        Creates a scatter plot to visualize the relationship between 'src_ip' and 'dst_port' in 
        network traffic data. It distinguishes normal data points from anomalies by plotting them in different colors 
        and styles.
    """
    x_data = 'src_ip'
    y_data = 'service'

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=data[x_data],
        y=data[y_data],
        mode='markers',
        marker=dict(color='blue', size=6, opacity=0.6),
        name='Normal'
    ))
    fig.add_trace(go.Scatter(
        x=anomalies[x_data],
        y=anomalies[y_data],
        mode='markers',
        marker=dict(color='red', size=8, line=dict(width=1, color='black')),
        name='anomalies'
    ))
    fig.update_layout(
        title=f'Visualization of Detected anomalies ({x_data} vs {y_data})',
        xaxis_title=f'{x_data}',
        yaxis_title=f'{y_data}',
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
        template='plotly_white'
    )

    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()


def plot_dst_host_count_vs_dst_host_srv_count(data: pd.DataFrame, anomalies: pd.DataFrame):
    """
    Function: plot_dst_host_count_vs_dst_host_srv_count

    Input:
        - data: pd.DataFrame, A DataFrame containing the normal data with columns for 'dst_host_count' and 'dst_host_srv_count'.
        - anomalies: pd.DataFrame, A DataFrame containing the anomalous data with columns for 'dst_host_count' and 'dst_host_srv_count'.

    Output:
        - None, The function visualizes the data in a scatter plot and displays it using Plotly.

    Description:
        Creates a scatter plot to visualize the relationship between 'dst_host_count' and 'dst_host_srv_count' in 
        network traffic data. It distinguishes normal data points from anomalies by plotting them in different colors 
        and styles.
    """
    x_data = 'dst_host_count'
    y_data = 'dst_host_srv_count'

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=data[x_data],
        y=data[y_data],
        mode='markers',
        marker=dict(color='blue', size=6, opacity=0.6),
        name='Normal'
    ))
    fig.add_trace(go.Scatter(
        x=anomalies[x_data],
        y=anomalies[y_data],
        mode='markers',
        marker=dict(color='red', size=8, line=dict(width=1, color='black')),
        name='anomalies'
    ))
    fig.update_layout(
        title=f'Visualization of Detected anomalies ({x_data} vs {y_data})',
        xaxis_title=f'{x_data}',
        yaxis_title=f'{y_data}',
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
        template='plotly_white'
    )

    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()



def find_anomalies(data: pd.DataFrame, model_file: str, feature: str):
    """
    Function: find_anomalies

    Input:
        - data: pd.DataFrame, A DataFrame containing the network traffic data to be analyzed for anomalies. 
                                    The DataFrame should include relevant features such as 'src_ip' and other network attributes.
        - model_file: str, Path to the pickle file containing the pre-trained model used for anomaly detection.
        - feature: str, A string specifying which feature to visualize the anomalies for. It controls the plot 
                          that will be generated based on detected anomalies.

    Output:
        - None, The function does not return any value but visualizes the detected anomalies and displays related 
                  statistics, such as the number of anomalies and non-anomalies.

    Description:
        Detects anomalies in network traffic data using a pre-trained model stored in the specified pickle 
        file. The function then visualizes the anomalies for a specific feature chosen by the user, and provides a count 
        of detected anomalies and non-anomalies.
    """
    with open(model_file, 'rb') as file:
        model = pickle.load(file)

    temp_series = pd.Series(data['src_ip'])
    data.drop(columns=['src_ip'], inplace=True)
    data['label'] = model.predict(data)
    data['src_ip'] = temp_series

    anomalies = data[data['label'] == 1]
    detected_anomalies = len(anomalies)
    non_anomalies = len(data) - len(anomalies)

    match feature:
        case "src_bytes vs. dst_bytes":
            plot_src_bytes_vs_dst_bytes(data, anomalies)

        case "duration":
            plot_duration(data, anomalies)

        case "count":
            plot_count(data)

        case "dst_host_count":
            plot_dst_host_count(data)

        case "src_ip vs. dst_port":
            plot_src_ip_vs_dst_port(data, anomalies)

        case "dst_host_count vs. dst_host_srv_count":
            plot_dst_host_count_vs_dst_host_srv_count(data, anomalies)

        case _:
            print(f"Unknown feature: {feature}")

    if is_streamlit():
        st.write(f"Number of detected anomalies: {detected_anomalies}")
        st.write(f"Number of detected non anomalies: {non_anomalies}")
    else:
        print(f"Number of detected anomalies: {detected_anomalies}")
        print(f"Number of detected non anomalies: {non_anomalies}")