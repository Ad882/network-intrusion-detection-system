import streamlit as st
from model import train_model, evaluate_model, save_model 
from utils import MONITOR_INTERVAL, ip_packet_count, ip_target_count, port_scan_count, check_permissions, load_lottieurl, detect_anomalies
from analysis import analyze_packet, process_pcap, preprocessing, find_anomalies
from streamlit_lottie import st_lottie
import time
import pyshark
import threading
import subprocess
import os


lock = threading.Lock()
stop_event = threading.Event()


#                    #
##      MAIN        ##
###                ###

def main():

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

            interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "custom"], index=0)
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

            capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)
            start_time = time.time()
            count_time = time.time()
            nb_packets = 0
            previous_nb_packets = 0

            if "running" not in st.session_state:
                st.session_state.running = False
            if start_button.button("Start Sniffing", icon="🚥", use_container_width=True) and not st.session_state.running:
                with st.spinner('Capture in progress...'):
                    st.session_state.running = True

                    for packet in capture.sniff_continuously():
                        nb_packets += 1

                        elapsed_time = time.time() - count_time
                        if elapsed_time >= 0.5:
                            delta = nb_packets - previous_nb_packets

                            packet_button.metric(label="Packets Received", value=nb_packets, delta=delta, border=True)
                        
                            previous_nb_packets = nb_packets
                            count_time = time.time()

                        raw_packet = bytes(packet.get_raw_packet())
                        src_ip, dst_ip, dst_port = analyze_packet(raw_packet)
                        if src_ip and dst_ip:
                            ip_packet_count[src_ip] += 1
                            ip_target_count[src_ip].add(dst_ip)
                            if dst_port:
                                port_scan_count[src_ip][dst_ip].add(dst_port)

                        current_time = time.time()
                        elapsed_time = int(current_time - start_time)
                        if elapsed_time % MONITOR_INTERVAL == 0:
                            alerts = detect_anomalies(elapsed_time)
                            if alerts:
                                st.error("🚨 Attack detected! 🚨")
                                stop_event.set()
                                st.session_state.running = False   
                                break

                        if (nb_packets > max_capture_packets) or (elapsed_time > max_capture_duration):
                            stop_event.set()
                            st.session_state.running = False   

                    
                    
            if stop_event.is_set():
                capture.close()
                ip_packet_count.clear()
                ip_target_count.clear()
                port_scan_count.clear()
                st.header("Sum up:")
                end_time = time.time()
                elapsed_time = int(end_time - start_time)
                if elapsed_time < 60:
                    st.write(f"In {elapsed_time} seconds, {nb_packets} packets were caught on the {interface} interface.")
                elif elapsed_time < 3600:
                    minutes = elapsed_time // 60
                    seconds = elapsed_time % 60
                    st.write(f"In {minutes} minutes and {seconds} seconds, {nb_packets} packets were caught on the {interface} interface.")
                else:
                    hours = elapsed_time // 3600
                    minutes = (elapsed_time % 3600) // 60
                    seconds = elapsed_time % 60
                    st.write(f"In {hours} hours, {minutes} minutes, and {seconds} seconds, {nb_packets} packets were caught on the {interface} interface.")



        elif real_time_capture == "No":
            perform_capture = st.selectbox("A network capture is already provided. Should a new network capture be made?", ["", "Yes, make a new capture", "No, use the given one"])
            capture_file = 'capture/output.pcap'
            if (perform_capture == "Yes, make a new capture") and ('capture_done' not in st.session_state):
                interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "custom"], index=2)
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

                
                if (os.path.exists(capture_file)) & (perform_capture == "Yes, make a new capture"):
                    os.remove(capture_file)
                if capture_duration > 0:
                    st.success(f"Capture duration set to {capture_duration} seconds with interface {interface}.")
                    with st.spinner('Capture in progress...'):
                        check_permissions()
                        command = ["tcpdump", "-i", interface, "-w", capture_file]
                        start_time = time.time()
                        process = subprocess.Popen(command)
                        try:
                            while (time.time() - start_time) < capture_duration:
                                time.sleep(1)
                            process.terminate() 
                            process.wait()

                        except KeyboardInterrupt:
                            print("Capture interrupted by user. Stopping tcpdump...")
                            process.terminate()
                            process.wait()

                        st.session_state.capture_done = True
                    st.success(f"Capture complete!")
                else:
                    st.warning("Please set a valid capture duration (greater than 0).")
                

            elif (perform_capture == "No, use the given one") and ('capture_done' not in st.session_state):
                st.session_state.capture_done = True

            process_done = st.session_state.get('process_done', False)

            if not process_done:
                if 'capture_done' in st.session_state:
                    command = ["tshark", "-r", capture_file]
                    result = subprocess.run(command, stdout=subprocess.PIPE, text=True)
                    packet_count = len(result.stdout.splitlines())
                    _, a, _ = st.columns(3)
                    a.metric(label="Packets captured", value=packet_count, border=True)

                    st.header("Detecting network anomalies")
                    df = process_pcap(capture_file)
                    df.to_csv("capture/out.csv", index=None)
                    data = preprocessing('capture/out.csv', encoders_file)

                    st.session_state['process_done'] = True
                    st.session_state['data'] = data

            if 'data' in st.session_state:
                data = st.session_state['data'].copy()
                feature = st.radio("Select feature for anomaly detection:", ["src_bytes vs. dst_bytes", "duration", "count", "dst_host_count", "src_ip vs. dst_port", "dst_host_count vs. dst_host_srv_count"], index=0)
                if feature:
                    find_anomalies(data, model_file, feature=feature)





if __name__ == "__main__":
    main()


# TODO: clean stop:
# except KeyboardInterrupt:
#         print("\nCtrl+C detected. Exiting gracefully...")
#         cleanup()  
#         sys.exit(0)