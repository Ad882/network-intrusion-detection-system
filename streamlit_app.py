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

pcap_capture_file = 'capture/network_traffic.pcap'
csv_capture_file = 'capture/network_traffic.csv'
model_file = 'models/nsl-kdd_model.pkl'
encoders_file = 'encoders/label_encoders.pkl'


#                    #
##      MAIN        ##
###                ###


def main():

    #
    ## Header:
    st.title("Network Anomaly Detection 🕵️")
    lottie_animation = load_lottieurl("https://lottie.host/6d367c3b-9b60-458a-9d93-bc96bb87baf4/kJ5r7yl4Ka.json")
    st_lottie(lottie_animation, height=300, key="loading")


    #
    ## Model training section:
    st.header("Model Training")

    url = "https://www.kaggle.com/datasets/hassan06/nslkdd"
    st.markdown("A model is already provided. It comes from the *nsl-kdd* dataset on [kaggle](%s)." % url)
    model_training = st.selectbox("Should the model be trained again?", ["", "Yes, make a new train", "No, use the given one"], index=0)
    model_perf = "No"

    # Training the model and saving the results in the session_state (to avoid repeating the training each time you click on the page):
    if (model_training == "Yes, make a new train") and ("model" not in st.session_state):
        with st.spinner('Training in progress...'):
            X_test, y_test, y_pred, model = train_model()
            save_model(model)
            st.session_state.model = model
            st.session_state.X_test = X_test
            st.session_state.y_test = y_test
            st.session_state.y_pred = y_pred
        st.success('Training completed!')

    # User can choose whether or not to visualize the model's performances: 
    if "model" in st.session_state:
        model_perf = st.radio("Show the model performances?", ["No", "Yes"])
        
        # Printing accuracy_score and f1_score and plotting the ROC curve:  
        if (model_perf == "Yes"):
            st.write("Here are the performances of the model:")
            evaluate_model(st.session_state.X_test, st.session_state.y_test, st.session_state.y_pred, st.session_state.model)



    #
    ## Packets capture section:
    if (model_training == "No, use the given one") or ((model_training == "Yes, make a new train") and ("model" in st.session_state)):
        st.header("Network Traffic Capture")
        real_time_capture = st.selectbox("Should the application operate in real time?", ["", "Yes", "No"], index=0)

        #
        ## Live packets capture section:
        if real_time_capture == "Yes":
            st.header("Real-Time Packet analysis")

            # Network interface choice:
            interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "custom"], index=0)

            # User guide to determine which interface is available on their laptop:
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

            # Live capture stops naturally (if there is no intrusion) after a certain time / number of packets captured:
            st.write("Choose the stopping criterion:")
            max_capture_duration = st.slider("Choose the maximum listening duration", min_value=60, max_value=3600, value=600, step=60)
            max_capture_packets = st.slider("Choose the maximum number of packets ", min_value=100, max_value=50000, value=4000, step=100)


            start_button, _, _ = st.columns(3, vertical_alignment='center')
            capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

            start_time = time.time()
            count_time = time.time()
            nb_packets = 0
            previous_nb_packets = 0
            packet_button = st.empty()

            if "running" not in st.session_state:
                st.session_state.running = False

            # Triggering the live capture:
            if start_button.button("Start Sniffing", icon="🚥", use_container_width=True) and not st.session_state.running:
                # Checking if the user can use wireshark:
                check_permissions()

                with st.spinner('Capture in progress...'):
                    st.session_state.running = True

                    # Analyzing packets 
                    for packet in capture.sniff_continuously():
                        nb_packets += 1


                        elapsed_time = time.time() - count_time

                        # Live display of the number of packets captured (refreshed every 0.5s)
                        if elapsed_time >= 0.5:
                            delta = nb_packets - previous_nb_packets

                            packet_button.metric(label="Packets Received", value=nb_packets, delta=delta, border=True)
                        
                            previous_nb_packets = nb_packets
                            count_time = time.time()


                        # Retrieving usefull informations for each packet (src_ip, dst_ip, dst_port);
                        raw_packet = bytes(packet.get_raw_packet())
                        src_ip, dst_ip, dst_port = analyze_packet(raw_packet)
                        if src_ip and dst_ip:
                            ip_packet_count[src_ip] += 1
                            ip_target_count[src_ip].add(dst_ip)
                            if dst_port:
                                port_scan_count[src_ip][dst_ip].add(dst_port)

                        # Determine whether or not the packets received are suspicious:
                        current_time = time.time()
                        elapsed_time = int(current_time - start_time)
                        if elapsed_time % MONITOR_INTERVAL == 0:
                            alerts = detect_anomalies(elapsed_time)
                            if alerts:
                                st.error("🚨 Attack detected! 🚨")
                                stop_event.set()
                                st.session_state.running = False   
                                st.session_state.natural_stop = False  
                                break

                        # End the capture after a certain time / number of packets captured has been reached if no anomaly detected:
                        if (nb_packets > max_capture_packets) or (elapsed_time > max_capture_duration):
                            st.info("Ending the capture...")
                            stop_event.set()
                            st.session_state.running = False   
                            st.session_state.natural_stop = True 
                            break

                    
            # When live capture stops: 
            if stop_event.is_set():

                # Stop the PyShark capture:
                capture.close()
                
                # Reset all variables:
                ip_packet_count.clear()
                ip_target_count.clear()
                port_scan_count.clear()

                # Indicates to the user the reason of the capture stop:
                if st.session_state.natural_stop:
                    st.write(f"The capture stops because the maximum capture time / the maximum number of captured packets set by the user has been reached.")
                else:
                    st.write(f"The capture stops due to an abnormal activity detected!")

                # Summarise the number of packets received over the time interval, for the user:
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



        #
        ## Recorded packets capture section:
        elif real_time_capture == "No":
            perform_capture = st.selectbox("A network capture is already provided. Should a new network capture be made?", ["", "Yes, make a new capture", "No, use the given one"])
            
            # Record a new capture:
            if (perform_capture == "Yes, make a new capture") and ('capture_done' not in st.session_state):
                # Network interface choice:
                interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "custom"], index=2)

                # User guide to determine which interface is available on their laptop:
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

                # Setting the maximum capture duration:
                capture_duration = st.slider("Choose a listening duration", min_value=0, max_value=120, value=0, step=5)

                
                if (os.path.exists(pcap_capture_file)) & (perform_capture == "Yes, make a new capture"):
                    os.remove(pcap_capture_file)
                if capture_duration > 0:
                    st.success(f"Capture duration set to {capture_duration} seconds on interface {interface}.")
                    with st.spinner('Capture in progress...'):
                        # Triggering capture with tcpdump:
                        command = ["tcpdump", "-i", interface, "-w", pcap_capture_file]
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

                        # Ending capture:
                        st.session_state.capture_done = True
                    st.success(f"Capture complete!")
                else:
                    st.warning("Please set a valid capture duration (greater than 0).")
                

            elif (perform_capture == "No, use the given one") and ('capture_done' not in st.session_state):
                st.session_state.capture_done = True

            process_done = st.session_state.get('process_done', False)


            if not process_done:
                if 'capture_done' in st.session_state:
                    # Read the capture file (in pcap) with Tshark:
                    command = ["tshark", "-r", pcap_capture_file]
                    result = subprocess.run(command, stdout=subprocess.PIPE, text=True)

                    # Printing the number of packets caught:
                    packet_count = len(result.stdout.splitlines())
                    _, a, _ = st.columns(3)
                    a.metric(label="Packets captured", value=packet_count, border=True)

                    # Processing and storing the pcap file into a csv file:
                    df = process_pcap(pcap_capture_file)
                    df.to_csv(csv_capture_file, index=None)
                    data = preprocessing(csv_capture_file, encoders_file)

                    st.session_state['process_done'] = True
                    st.session_state['data'] = data

            if 'data' in st.session_state:
                # Detecting whether or not the record contains abnormal packets according to the ML model:
                st.header("Detecting network anomalies")
                data = st.session_state['data'].copy()
                feature = st.radio("Select feature for anomaly detection:", ["src_bytes vs. dst_bytes", "duration", "count", "dst_host_count", "src_ip vs. dst_port", "dst_host_count vs. dst_host_srv_count"], index=0)
                if feature:
                    find_anomalies(data, model_file, feature=feature)





if __name__ == "__main__":
    main()