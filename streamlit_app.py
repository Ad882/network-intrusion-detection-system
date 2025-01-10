import streamlit as st
from model import train_model, evaluate_model, save_model 
from capture import check_permissions, capture_traffic, extract_features
from analysis import preprocessing, find_anomalies
from streamlit_lottie import st_lottie
import requests
import time
import pyshark
import threading
import pickle
import pandas as pd
import numpy as np
import plotly.express as px

packet_count = 0
anomaly_count = 0
begin = 0
end = 0
lock = threading.Lock()
stop_event = threading.Event()
src_mac = ""
dst_mac = ""
src_ip = ""
dst_ip = ""
src_port = 0
dst_port = 0
payload = ""
highest_layer = ""
length = 0


def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


def live_capture(interface, model_file, encoders_file):
    global packet_count, anomaly_count, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload, highest_layer, length

    with open(model_file, 'rb') as file:
        model = pickle.load(file)

    with open(encoders_file, 'rb') as f:
        encoders = pickle.load(f)

    categorical_columns = ['protocol_type', 'service', 'flag']
    capture = pyshark.LiveCapture(interface=interface)

    try:
        for packet in capture:
            if stop_event.is_set():
                break
            with lock:
                packet_count += 1

            features = extract_features(packet)
            if features:
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


                if prediction[0] == 'attack':
                    with lock:
                        anomaly_count += 1

                        if 'eth' in packet:
                            src_mac = packet.eth.src
                            dst_mac = packet.eth.dst

                        if 'ip' in packet:
                            src_ip = packet.ip.src
                            dst_ip = packet.ip.dst

                        if 'tcp' in packet:
                            src_port = packet.tcp.srcport
                            dst_port = packet.tcp.dstport
                        elif 'udp' in packet:
                            src_port = packet.udp.srcport
                            dst_port = packet.udp.dstport

                        if 'data' in packet:
                            payload = packet.data.data

                        if hasattr(packet, 'highest_layer'):
                            highest_layer = packet.highest_layer

                        if hasattr(packet, 'length'):
                            length = packet.length

                    
    except Exception as e:
        print(f"Error in live capture: {e}")
    finally:
        capture.close()





def main():
    global packet_count, anomaly_count, begin, end, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload, highest_layer, length

    st.title("Network Anomaly Detection 🕵️")
    lottie_animation = load_lottieurl("https://lottie.host/6d367c3b-9b60-458a-9d93-bc96bb87baf4/kJ5r7yl4Ka.json")
    st_lottie(lottie_animation, height=300, key="loading")

    st.header("Model Training")


    if 'model' in st.session_state:
        model_training = "No, use the given one"
        st.write("Using the new trained model...")
        model_perf = ""
    else:
        url = "https://www.kaggle.com/datasets/hassan06/nslkdd"
        st.markdown("A model is already provided. It comes from the *nsl-kdd* dataset on [kaggle](%s)." % url)
        model_training = st.selectbox("Should the model be trained again?", ["", "Yes, make a new train", "No, use the given one"], index=0)
        model_perf = ""
    
    if model_training == "Yes, make a new train":
        with st.spinner('Training in progress...'):
            X_test, y_test, y_pred, model = train_model()
            save_model(model)
            st.session_state.model = model
            st.session_state.X_test = X_test
            st.session_state.y_test = y_test
            st.session_state.y_pred = y_pred
        st.success('Training completed!')

        model_perf = st.radio("Show the model performances?", ["No", "Yes"])
        if model_perf == "Yes":
            st.write("Here are the performances of the model:")
            evaluate_model(X_test, y_test, y_pred, model)

    elif model_training == "No, use the given one" and 'model' in st.session_state:
        model = st.session_state.model
        X_test = st.session_state.X_test
        y_test = st.session_state.y_test
        y_pred = st.session_state.y_pred

        model_perf = st.radio("Show the model performances?", ["No", "Yes"])
        if model_perf == "Yes":
            st.write("Evaluating the model performance...")
            evaluate_model(X_test, y_test, y_pred, model)




    if (model_training == "No, use the given one") | ((model_perf != "") & (model_training == "Yes, make a new train")):
        st.header("Network Traffic Capture")

        real_time_capture = st.selectbox("Should the application operate in real time?", ["", "Yes", "No"], index=0)

        capture_file = 'capture/network_traffic.csv'
        model_file = 'models/nsl-kdd_model.pkl'
        encoders_file = 'encoders/label_encoders.pkl'

        if real_time_capture == "Yes":
            st.header("Real-Time Packet analysis")

            interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "tun0", "custom"], index=0)
            with st.expander("To see all the interfaces available on a machine: (click to expand)"):
                st.markdown("""
                            
                    Use the following commands:
                    <h4 align='center'>On Linux: </h4>

                    ```bash
                    ip link show
                    ```
                    or
                    ```bash
                    ifconfig -a
                    ```

                    <h4 align='center'>On Windows: </h4>

                    ```cmd
                    ipconfig /all
                    ```

                    <h4 align='center'>On macOS: </h4>

                    ```bash
                    ifconfig
                    ```""", 
                    unsafe_allow_html=True
                )
            if interface == "custom": 
                interface = st.text_input("Enter the interface", "")

            st.write("Choose the stopping criterion:")
            max_capture_duration = st.slider("Choose the maximum listening duration", min_value=60, max_value=3600, value=600, step=60)
            max_capture_packets = st.slider("Choose the maximum number of packets ", min_value=100, max_value=50000, value=4000, step=100)
            start_button, _, _ = st.columns(3, vertical_alignment='center')
            packet_button = st.empty()
            anomaly_button = st.empty()

            capture_thread = threading.Thread(target=live_capture, args=(interface, model_file, encoders_file,))
            capture_thread.daemon = True
            anomalies_df = pd.DataFrame(columns=["src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port", "payload", "highest_layer", "length"])
            if "running" not in st.session_state:
                st.session_state.running = False
            if start_button.button("Start Sniffing", icon="🚥", use_container_width=True) and not st.session_state.running:
                with st.spinner('Capture in progress...'):
                    capture_thread.start()
                    begin = time.time()
                    st.session_state.running = True

                    nw_status_placeholder = st.empty()

                    if anomaly_count == 0:
                        nw_status_placeholder.success("Everything clear on the network!")

                    while st.session_state.running:
                        previous_count = packet_count
                        previous_anomaly_count = anomaly_count

                        time.sleep(0.01)
                        packet_button.metric(label="Packets Received", value=packet_count, delta=packet_count - previous_count, border=True)
                        anomaly_button.metric(label="Anomalies Detected", value=anomaly_count, delta=anomaly_count - previous_anomaly_count, border=True)
                        
                        if anomaly_count - previous_anomaly_count != 0:
                            nw_status_placeholder.error("Anomaly detected on the network!")
                            new_anomaly = {
                                "src_mac": src_mac,
                                "dst_mac": dst_mac,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "payload": payload,
                                "highest_layer": highest_layer,
                                "length": length
                            }
                            new_anomaly_df = pd.DataFrame([new_anomaly])
                            anomalies_df = pd.concat([anomalies_df, new_anomaly_df], ignore_index=True)

                        current_time = time.time()
                        elapsed_time = current_time - begin
                        if (packet_count > max_capture_packets) or (elapsed_time > max_capture_duration):
                            end = time.time()
                            stop_event.set()
                            st.session_state.running = False     

                    
            if stop_event.is_set():
                capture_thread.join()
                st.header("Sum up:")
                elapsed_time = int(end - begin)
                if elapsed_time < 60:
                    st.write(f"In {elapsed_time} seconds, {packet_count} packets were caught on the {interface} interface among which {anomaly_count} packets were classified as anomalies.")
                elif elapsed_time < 3600:
                    minutes = elapsed_time // 60
                    seconds = elapsed_time % 60
                    st.write(f"In {minutes} minutes and {seconds} seconds, {packet_count} packets were caught on the {interface} interface among which {anomaly_count} packets were classified as anomalies.")
                else:
                    hours = elapsed_time // 3600
                    minutes = (elapsed_time % 3600) // 60
                    seconds = elapsed_time % 60
                    st.write(f"In {hours} hours, {minutes} minutes, and {seconds} seconds, {packet_count} packets were caught on the {interface} interface among which {anomaly_count} packets were classified as anomalies.")
            
                if len(anomalies_df) != 0:
                    st.write("Here is a summary table of the abnormal packets detected in the network:")
                    st.dataframe(anomalies_df, width=700, height=300)

                    feature = st.radio("Select feature for anomaly detection:", ["src_mac", "src_ip"], index=0)
                    if feature:
                        frequencies = anomalies_df[feature].value_counts().reset_index()
                        frequencies.columns = [feature, 'frequency']

                        fig = px.bar(
                            frequencies, 
                            x=feature, 
                            y='frequency', 
                            title="Fréquences d'apparition des adresses IP source dans les anomalies",
                            labels={feature: f"Source {feature.split('_')[-1].upper()} address", 'frequency': 'Frequency'},
                            color='frequency',
                            color_continuous_scale='viridis'
                        )

                        fig.update_layout(
                            xaxis_title=f"Source {feature.split('_')[-1].upper()} address",
                            yaxis_title="Frequency",
                            xaxis=dict(tickangle=-45),
                            template="plotly_white"
                        )

                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.success("No anomalies detceted on the network! 🥳")



        elif real_time_capture == "No":
            perform_capture = st.selectbox("A network capture is already provided. Should a new network capture be made?", ["", "Yes, make a new capture", "No, use the given one"])
            if (perform_capture == "Yes, make a new capture") and ('capture_done' not in st.session_state):
                interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "tun0", "custom"], index=2)
                with st.expander("To see all the interfaces available on a machine: (click to expand)"):
                    st.markdown("""
                                
                        Use the following commands:
                        <h4 align='center'>On Linux: </h4>

                        ```bash
                        ip link show
                        ```
                        or
                        ```bash
                        ifconfig -a
                        ```

                        <h4 align='center'>On Windows: </h4>

                        ```cmd
                        ipconfig /all
                        ```

                        <h4 align='center'>On macOS: </h4>

                        ```bash
                        ifconfig
                        ```""", 
                        unsafe_allow_html=True
                    )
                if interface == "custom": 
                    interface = st.text_input("Enter the interface", "")

                capture_duration = st.slider("Choose a listening duration", min_value=0, max_value=120, value=0, step=5)

                
                if capture_duration > 0:
                    st.success(f"Capture duration set to {capture_duration} seconds with interface {interface}.")
                    with st.spinner('Capture in progress...'):
                        check_permissions()
                        capture_traffic(interface, capture_file, capture_duration)
                        st.session_state.capture_done = True
                    st.success(f"Capture complete!")
                else:
                    st.warning("Please set a valid capture duration (greater than 0).")
                

            elif (perform_capture == "No, use the given one") and ('capture_done' not in st.session_state):
                st.session_state.capture_done = True


            if 'capture_done' in st.session_state:
                data = preprocessing(capture_file, encoders_file)
                nb_packets = len(data)
                a, _, _ = st.columns(3)
                a.metric(label="Packets captured", value=nb_packets, border=True)
                st.header("Detecting network anomalies")
                
                feature = st.radio("Select feature for anomaly detection:", ["flag", "count", "src_bytes", "dst_bytes"], index=0)
                if feature:
                    find_anomalies(data, model_file, feature=feature)




if __name__ == "__main__":
    main()
