import joblib
import pandas as pd
import pyshark
import subprocess
from datetime import datetime
import json
import time
import os

# Load the trained model and scaler
script_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(script_dir, 'model_and_scaler.joblib')
data = joblib.load(model_path)
model = data['model']
scaler = data['scaler']

# Log file for Wazuh to monitor detected attacks
log_file_path = '/var/log/ai_nids/blocked_ips.log'

# Initialize dictionaries for session tracking
session_data = {
    'start_time': {}, 'spkts': {}, 'dpkts': {}, 'total_sbytes': {}, 'total_dbytes': {},
    'last_packet_time': {}, 'sinpkt': {}, 'dinpkt': {}, 'sjit': {}, 'djit': {}
}

# List of numerical features used in the model
numerical_features = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'sload', 'dload', 'sttl', 'dttl', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'tcprtt', 'synack', 'ackdat',
    'ct_srv_src', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_srv_dst'
]

# Block IP using iptables and log to file
def block_ip(ip_address):
    if ip_address == '192.168.45.129':
        print(f"Attempted to block server's own IP: {ip_address}. Skipping.")
        return
    # Check if the IP is already blocked
    existing_rules = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-v", "-n"], capture_output=True, text=True)
    if ip_address in existing_rules.stdout:
        print(f"IP {ip_address} is already blocked.")
        return

    # Add a new DROP rule for the IP if it's not already blocked
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
    print(f"Blocked IP: {ip_address}")

# Extract features from each packet
def extract_features(packet):
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        ttl = int(packet.ip.ttl)
        current_time = datetime.now().timestamp()

        # Initialize session start time if not already present
        if src_ip not in session_data['start_time']:
            session_data['start_time'][src_ip] = current_time

        # Calculate duration since the first packet from src_ip
        dur = current_time - session_data['start_time'].get(src_ip, current_time)

        # Update packet counts
        session_data['spkts'][src_ip] = session_data['spkts'].get(src_ip, 0) + 1
        session_data['dpkts'][dst_ip] = session_data['dpkts'].get(dst_ip, 0) + 1

        # Byte counts
        sbytes = len(src_ip)  # Example for single packet
        dbytes = len(dst_ip)
        session_data['total_sbytes'][src_ip] = session_data['total_sbytes'].get(src_ip, 0) + sbytes
        session_data['total_dbytes'][dst_ip] = session_data['total_dbytes'].get(dst_ip, 0) + dbytes

        # Calculate load rates
        sload = session_data['total_sbytes'][src_ip] / dur if dur > 0 else 0
        dload = session_data['total_dbytes'][dst_ip] / dur if dur > 0 else 0

        # Calculate inter-packet arrival time and jitter
        last_time = session_data['last_packet_time'].get(src_ip)
        sinpkt = current_time - last_time if last_time else 0.01
        session_data['sinpkt'][src_ip] = (session_data['sinpkt'].get(src_ip, 0) + sinpkt) / 2
        session_data['sjit'][src_ip] = abs(sinpkt - session_data['sinpkt'].get(src_ip, sinpkt))
        session_data['last_packet_time'][src_ip] = current_time

        # Handle missing values with defaults
        features = {
            'dur': dur,
            'spkts': session_data['spkts'].get(src_ip, 1),
            'dpkts': session_data['dpkts'].get(dst_ip, 1),
            'sbytes': sbytes,
            'dbytes': dbytes,
            'sload': sload,
            'dload': dload,
            'sttl': ttl,
            'dttl': ttl,
            'sinpkt': session_data['sinpkt'].get(src_ip, 0.01),
            'dinpkt': session_data['sinpkt'].get(dst_ip, 0.01),
            'sjit': session_data['sjit'].get(src_ip, 0),
            'djit': session_data['sjit'].get(dst_ip, 0),
            'tcprtt': 0.1,  # Placeholder; adjust as needed
            'synack': int(packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1') if 'tcp' in packet else 0,
            'ackdat': int(packet.tcp.flags_ack == '1') if 'tcp' in packet else 0
        }
        return pd.DataFrame([features])
    except AttributeError as e:
        print(f"Packet parsing error: {e}")
        return None

# Log results with inverse scaling
def log_detection_result(case, prediction):
    label = "Attack" if prediction == 1 else "Normal"
    original_values = scaler.inverse_transform(case[numerical_features])[0]
    event_data = dict(zip(numerical_features, original_values))

    event = {
        "timestamp": datetime.now().isoformat(),
        "event": label,
        "characteristics": event_data
    }
    print(f"Detected {label}: {event}")
    with open(log_file_path, 'a') as log_file:
        log_file.write(json.dumps(event) + "\n")
    time.sleep(0.2)

# Process each packet
def process_packet(packet):
    features = extract_features(packet)
    if features is not None:
        # Ensure all expected features are present with default values if missing
        for col in numerical_features:
            if col not in features.columns:
                features[col] = 0

        scaled_features = features.copy()
        scaled_features[numerical_features] = scaler.transform(features[numerical_features])
        prediction = model.predict(scaled_features)[0]
        log_detection_result(features, prediction)
        if prediction == 1:
            block_ip(packet.ip.src)

# Start capturing packets with Pyshark
capture = pyshark.LiveCapture(interface='any', bpf_filter="ip and not host 127.0.0.1")
for packet in capture.sniff_continuously():
    process_packet(packet)

