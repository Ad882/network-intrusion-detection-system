<h1 align='center'> Network Intrusion Detection System (NIDS) 🔒🚨 </h1>

A project designed to monitor, detect, and analyze malicious activities within a network. The system uses machine learning models to classify network traffic.


<br>

## 🌟 Features 
This tool enables real-time traffic capture and analysis using **PyShark** 🦈, providing a robust foundation for monitoring network activity. It incorporates machine learning-based anomaly detection 🔬 to identify irregular patterns and potential threats. To test its capabilities, it offers a simulation of attacks through **Mininet** ⚔️. Additionally, the tool includes built-in visualization powered by **Streamlit** 📊, making data interpretation more intuitive and user-friendly.


<br>

## 🗂️ Project structure

Here's the current structure of the project:

```
phishing-simulator/
├── capture/                # Contains the captured network traffic
│   └── nw_traffic.csv      # Example of a intercepted network traffic
│
├── encoders/               # Contains the model encoders 
│   └── label_encoders.pkl  # Model encoders pickle file
│
├── models/                 # Contains the model 
│   └── nsl-kdd_model.pkl   # Model pickle file
│
├── nsl-kdd/                # NSL-KDD dataset
│   ├── ...                 # dataset files
│   └── ...                 # dataset files
│
├── analysis.py             # Anomaly analysis related file
├── capture.py              # PyShark capture related file
├── model.py                # ML model related file 
├── .gitignore              # Git ignore file
├── README.md               # Project documentation (this file)
├── requirements.txt        # Python dependencies
├── streamlit_app.py        # Streamlit application
├── topology.py             # Mininet network topologies
└── utils.py                # Utils functions
```


<br>

## **🕵️‍♂️ How to Use**

### **1. Capture Network Traffic**:
Run the live capture process to listen for incoming packets on a specific network interface. The NIDS system will process each packet to extract features and classify the traffic as normal or an attack.

### **2. Visualize Anomalies**:
The Streamlit app will present a user-friendly dashboard, displaying:
- Frequency of detected anomalies
- Packet statistics over time

### **3. Train the Model** (if needed):
Retrain the machine learning model by using the collected network traffic data. Ensure you have enough labeled data (normal and attack traffic) to retrain the model effectively.




<br>

## ⚙️ **Installation & Setup**  

### **System Requirements**  

- **Operating System**: Linux (Ubuntu recommended) 🐧  
- **Python Version**: 3.7 or later  
- **Mininet**: Required for network simulations  
- **Wireshark**: For traffic capture (via `PyShark`)  
- **Root Privileges**: Needed for network interface management  

---

### 🔗 **Dependencies**  

Install required Python libraries using:  
```bash
pip install -r requirements.txt
```  

Key dependencies:  
- `pyshark`  
- `pandas`  
- `scikit-learn`  
- `streamlit`  
- `mininet`  
- `numpy`  

---

### Installation steps 🛠️

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Ad882/network-intrusion-detection-system.git
   ```
<br>

2. **Install dependencies:**

   Once the virtual environment is active, install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```
<br>

3. **Install Mininet:**

   If Mininet is not installed, install it using:

   ```bash
   sudo apt-get update
   sudo apt-get install mininet
   ```

   Alternatively, follow the instructions in the [Mininet installation guide](http://mininet.org/download/).
<br>

4. **Install Tshark:**

   If Tshark is not installed, install it using:

   ```bash
   sudo apt-get update
   sudo apt-get install tshark
   ```

   If `Pyshark` lacks the necessary permissions, it will not be able to capture packets, even if everything seems correctly configured. Here’s how to check and fix this issue:  

   #### **Verify permissions**  
      Pyshark relies on `tshark` in the background. Check if `tshark` can capture packets on the interface:  
      ```bash
      sudo tshark -i wlp1s0
      ```  
      If this works, the issue likely lies with Pyshark-specific permissions.  

   ---

   #### **Add the $user to the `wireshark` group**  

   To run the script with `sudo`, grant the necessary permissions to the user:  

   a) **Add the $user to the `wireshark` group:**  
      ```bash
      sudo usermod -aG wireshark $USER
      ```  
   <br>

   b) **Restart session:**  
      Log out and log back in for the changes to take effect.  
   <br>

   c) **Grant the correct permissions to `tshark`:**  
      ```bash
      sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
      ```  
   <br>

   d) **Verify that `tshark` works without `sudo`:**  
      Test it:  
      ```bash
      tshark -i wlp1s0
      ```  

<br>





## **⚡ Quick Start**
To handle the project, just **start the streamlit application**:
   ```bash
   streamlit run streamlit_app.py
   ```

Then navigate between all the possible choices and enjoy!


<br>


### **😈 Simulate Attacks**
Once the application is understood, to test the classification model, you need to be in a situation where there is suspicious activity and therefore simulate attacks.

1. **Start Mininet** and choose the topology: **In another termial**, start mininet.
To choose the simple topology (2 hosts, 1 switch):

   ```bash
   sudo mn --custom topology.py --topo simple
   ```

   To choose a more complex topology (6 hosts, 1 switch):

      ```bash
      sudo mn --custom topology.py --topo ddos
      ```
   <br>

2. **Verify Network Nodes**: After starting Mininet, check the network topology:
      ```bash
      mininet> nodes
      ```
   <br>

3. **Ping test**: Test connectivity between hosts:
      ```bash
      mininet> pingall
      ```

      It should return `Results: 0% dropped`. If there is packet loss, it will require investigations on the Mininet setup or network interfaces.

4. **Identify network interfaces**:   
Mininet creates virtual interfaces on the host machine to simulate network connections. You can use the ip link show command to identify the veth interfaces that are created during simulation.  
      ```bash
      ip link show
      ```
      
`vethX` interfaces are those used for communication between Mininet hosts. 





---

There are several types of attacks:

#### Network scan
Run a network scan with **nmap**:
Nmap can be used to simulate network discovery attempts (port scans, service scans, etc.).
Example: From host 1, scan for all ports on address 10.0.0.2 (host 2).
  ```bash
  mininet> h1 nmap -p 1-65535 10.0.0.2
  ```


#### DDoS Attack Simulation

1. `iperf`  
Use `iperf` to flood traffic to the target. 
Example: From host 1 to host 2:
   ```bash
   mininet> h1 iperf -c h2 -t 60
   ```  
<br>

2. `ping`
Use `ping` to flood traffic to the target. 
Example: From host 1 to host 2:
   ```bash
   mininet> h1 ping -f h2
   ```  

   Using the flag `-s`, allows to set the length of the packets:
   ```bash
   mininet> h1 ping -s 1000 -f h2
   ```  
<br>

3. **Hping3**
Hping3 can simulate various types of DDoS attack:
- Flood TCP SYN (Simulates a Flood SYN attack):
  ```bash
  mininet> hping3 -S --flood -p 80 10.0.0.2 192.168.1.10
  ```
  Options:
  - `-S`: Sends TCP SYN packets.
  - `--flood`: Sends packets as fast as possible.
  - `-p 80`: Specifies the target port (80 for HTTP).

- Flood UDP:
  ```bash
  mininet> mininet> hping3 --udp --flood -p 53 10.0.0.2
  ```

- ICMP Echo Request (Simulates a Ping Flood)
  ```bash
  mininet> hping3 --icmp --flood 10.0.0.2
  ```

<br>

4. **LOIC/HOIC** 
Also tools such as **LOIC** or **HOIC** can generate massive traffic to a target. Use them with caution in isolated environments.


<br>

#### Custom attacks
1. **Scapy**
Scapy is a Python library for creating custom packages.
- Example: Generating a SYN Flood with Scapy
  ```python
  from scapy.all import *

  target_ip = ‘192.168.1.10’
  target_port = 80

  for i in range(1000): # Adjust the loop to intensify the attack
      ip = IP(src=RandIP(), dst=target_ip)
      tcp = TCP(sport=RandShort(), dport=target_port, flags=‘S’)
      packet = ip/tcp
      send(packet, verbose=0)
  ```
<br>

2. **Slowloris** (Slow HTTP attack)
Slowloris is a Python script to simulate a slow HTTP attack.
- Execution:
   ```bash
   python slowloris.py -p 80 -s 150 192.168.1.10
   ```

  Options:
  - `-p` : Specifies the port.
  - `-s`: Number of simultaneous connections.


<br>

---

### **Detection settings**
Make sure that your detection tool is configured to detect these patterns:
- Network tracking
  - Scanning activity on several ports from the same IP.
- DDoS
  - High volume of packets from different IP addresses.
  - Packets with specific flags (e.g. TCP SYN without ACK).


<br>

To prevent the script from asking for a password when executing `sudo`, it is better to use a secure configuration with `sudo` instead of directly including a password in the script or a `.env` file, which would be a dangerous practice in terms of security.

### Using `setcap` to Grant Permissions to `tcpdump`
If you prefer not to use `sudo`, you can grant the necessary permissions to `tcpdump` so it can operate without administrative rights:

1. **Check the Path to `tcpdump`:**  
   Run the following command to find the path to `tcpdump`:
   ```bash
   which tcpdump
   ```

2. **Grant Special Permissions to `tcpdump`:**  
   Execute the following command to allow `tcpdump` to capture packets without `sudo`:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
   ```
   *Replace `/usr/bin/tcpdump` with the path provided by the `which tcpdump` command.*

3. **Verify the Permissions:**  
   Check that the permissions have been correctly applied:
   ```bash
   getcap /usr/bin/tcpdump
   ```
   *Replace `/usr/bin/tcpdump` with the path provided by the `which tcpdump` command.*


**Warning**: permissions granted with setcap are not always permanent. 
Certain actions, such as updating or reinstalling tcpdump, can reset these permissions.

Check regularly whether the permissions are still active:
```bash
getcap /usr/bin/tcpdump
```
If the command returns nothing, this means that the permissions have been removed and need to be reapplied.


<br>




## 🚪 **Exiting**  
After testing, clean up the Mininet configuration:  
```bash
mininet> exit
sudo mn -c
``` 

The `mn -c` command cleans up network configurations.

<br>

Then, stop the streamlit application by typing the command `ctrl + c` in the terminal running the application.
