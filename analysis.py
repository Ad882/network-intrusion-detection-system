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


def analyze_packet(packet):
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


def process_pcap(file_path):
    data = []
    packet_counts = defaultdict(int)  
    srv_counts = defaultdict(int)     
    serror_counts = defaultdict(int)  
    rerror_counts = defaultdict(int)  
    timestamps = defaultdict(list) 

    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            length = ip.len
            protocol = ip.p
            protocol_name = PROTOCOL_MAP.get(protocol, f"UNKNOWN ({protocol})")
            length = ip.len
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            transport = ip.data
            src_port = transport.sport if ((protocol == 6) | (protocol == 17)) else None
            dst_port = transport.dport if ((protocol == 6) | (protocol == 17)) else None
            tcp_flags = transport.flags if protocol == 6 else None

            packet_counts[(src_ip, dst_ip)] += 1
            srv_counts[dst_port] += 1
            timestamps[src_ip].append(timestamp)

            if protocol == 6 and tcp_flags & dpkt.tcp.TH_SYN and tcp_flags & dpkt.tcp.TH_RST:
                serror_counts[(src_ip, dst_port)] += 1

            if protocol == 1:
                rerror_counts[(src_ip, dst_port)] += 1

            same_srv_rate = srv_counts[dst_port] / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            diff_srv_rate = (packet_counts[(src_ip, dst_ip)] - srv_counts[dst_port]) / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            serror_rate = serror_counts[(src_ip, dst_port)] / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            srv_serror_rate = serror_counts[(src_ip, dst_port)] / srv_counts[dst_port] if srv_counts[dst_port] > 0 else 0
            rerror_rate = rerror_counts[(src_ip, dst_port)] / packet_counts[(src_ip, dst_ip)] if packet_counts[(src_ip, dst_ip)] > 0 else 0
            srv_rerror_rate = rerror_counts[(src_ip, dst_port)] / srv_counts[dst_port] if srv_counts[dst_port] > 0 else 0

            data.append({
                'duration': timestamps[src_ip][-1] - timestamps[src_ip][-2] if len(timestamps[src_ip]) > 2 else 0,
                'protocol_type': protocol_name,
                'service': dst_port,
                'flag': 'SF' if tcp_flags and (tcp_flags & dpkt.tcp.TH_SYN and tcp_flags & dpkt.tcp.TH_ACK) else 'OTH',
                'src_bytes': length if src_port else 0,
                'dst_bytes': length if dst_port else 0,
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



def preprocessing(capture_file, encoders_file):
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




def plot_src_bytes_vs_dst_bytes(data, anomalies):
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


def plot_duration(data, anomalies):
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


def plot_count(data):
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


def plot_dst_host_count(data):
    fig = px.histogram(data, x="dst_host_count", title="Histogram of dst_host_count")
    
    if is_streamlit():
        st.plotly_chart(fig)
    else:
        fig.show()


def plot_src_ip_vs_dst_port(data, anomalies):
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


def plot_dst_host_count_vs_dst_host_srv_count(data, anomalies):
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



def find_anomalies(data, model_file, feature):
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