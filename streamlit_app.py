import streamlit as st
from model import train_model, evaluate_model, save_model 
from capture import check_permissions, capture_traffic, live_capture_traffic
from analysis import preprocessing, find_anomalies
from streamlit_lottie import st_lottie
import requests
import time


def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


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
        model_training = st.selectbox("Should the model be trained again?", ["", "Yes, make a new train", "No, use the given one"])
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

        real_time_capture = st.selectbox("Should the application operate in real time?", ["", "Yes", "No"])

        capture_file = 'capture/network_traffic.csv'
        model_file = 'models/nsl-kdd_model.pkl'
        encoders_file = 'encoders/label_encoders.pkl'

        if real_time_capture == "Yes":
            st.write("Starting live capture...")
            interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "tun0", "docker0"], index=2)

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
            
            live_capture_traffic(interface, model_file, encoders_file)
        elif real_time_capture == "No":
            perform_capture = st.selectbox("A network capture is already provided. Should a new network capture be made?", ["", "Yes, make a new capture", "No, use the given one"])
            if (perform_capture == "Yes, make a new capture") and ('capture_done' not in st.session_state):
                capture_duration = st.slider("Choose a listening duration", min_value=0, max_value=120, value=0, step=5)
                interface = st.radio("Choose a network interface:", ["wlp1s0", "eth0", "lo", "tun0", "docker0"], index=2)
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

                
                if capture_duration > 0:
                    st.success(f"Capture duration set to {capture_duration} seconds with interface {interface}.")
                    with st.spinner('Capture in progress...'):
                        check_permissions()
                        capture_traffic(interface, capture_file, capture_duration)
                        st.session_state.capture_done = True

                else:
                    st.warning("Please set a valid capture duration (greater than 0).")
                

            elif (perform_capture == "No, use the given one") and ('capture_done' not in st.session_state):
                st.session_state.capture_done = True


            if 'capture_done' in st.session_state:
                st.header("Detecting network anomalies")
                data = preprocessing(capture_file, encoders_file)
                
                feature = st.radio("Select feature for anomalie detection:", ["flag", "count", "src_bytes", "dst_bytes"], index=0)
                if feature:
                    find_anomalies(data, model_file, feature=feature)




if __name__ == "__main__":
    main()
