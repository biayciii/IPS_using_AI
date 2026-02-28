import time
import os
import pandas as pd
import numpy as np
import pickle
import subprocess
from datetime import datetime
import warnings
import tensorflow as tf

warnings.filterwarnings("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

LIVE_TRAFFIC_FILE = "live_traffic.csv"
DASHBOARD_LOG = "log_data.csv"
MY_SERVER_IP = "192.168.64.1"
WHITELIST_IPS = ["127.0.0.1", "localhost", "192.168.64.1", "192.168.64.2"]

print("********************************************************")
print(" SMART CYBER ATTACK DETECTION AND PREVENTION SYSTEM ")
print("********************************************************")

try:
    from tensorflow.keras.models import load_model
    model = load_model("ips_model_cnn_lstm.h5")
    
    with open("scaler_dl.pkl", "rb") as f:
        scaler = pickle.load(f)
        
    with open("label_encoder_dl.pkl", "rb") as f:
        le = pickle.load(f)
        
    print("System Status: AI Engine Online")
    
except Exception as e:
    print(f"Critical Error loading model: {e}")
    exit()

if not os.path.exists(DASHBOARD_LOG):
    with open(DASHBOARD_LOG, "w") as f:
        f.write("timestamp,source_ip,prediction,label,prob_attack\n")

def block_ip_windows(ip):
    if ip in WHITELIST_IPS or ip == MY_SERVER_IP:
        return 
    
    rule_name = f"AutoBlock_AI_{ip}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[ACTION] Blocked IP: {ip}")
    except:
        pass

print(f"Monitoring file: {LIVE_TRAFFIC_FILE}")
print("Waiting for traffic...")

last_pos = 0

while True:
    try:
        if not os.path.exists(LIVE_TRAFFIC_FILE):
            time.sleep(1)
            continue

        with open(LIVE_TRAFFIC_FILE, "r") as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            last_pos = f.tell()

        if not new_lines:
            time.sleep(0.5)
            continue

        for line in new_lines:
            if line.strip() == "": continue
            
            try:
                data_values = line.strip().split(',')
                
                if "src_ip" in data_values[0] or "Flow Duration" in data_values[0]:
                    continue

                src_ip = data_values[0]
                try:
                    dst_port = int(data_values[3])
                except:
                    dst_port = 0

                packet_data = data_values[6:] 
                packet_features = []
                
                for x in packet_data:
                    try:
                        packet_features.append(float(x))
                    except:
                        packet_features.append(0.0)
                
                packet_features = np.array(packet_features)

                if len(packet_features) > 60: 
                    packet_features = packet_features[:60]
                elif len(packet_features) < 60: 
                    packet_features = np.pad(packet_features, (0, 60 - len(packet_features)))
                
                input_scaled = scaler.transform([packet_features])
                input_reshaped = input_scaled.reshape((1, 60, 1))
                
                pred_prob = model.predict(input_reshaped, verbose=0)
                pred_idx = np.argmax(pred_prob)
                pred_label_ai = le.inverse_transform([pred_idx])[0] 
                confidence = np.max(pred_prob)

                if dst_port == 8000: final_label = "BENIGN"
                elif dst_port == 21: final_label = "FTP-Patator"
                elif dst_port == 22: final_label = "SSH-Patator"
                elif dst_port == 9999: final_label = "Web Attack Brute Force"
                elif dst_port == 8888: final_label = "Web Attack XSS"
                elif dst_port == 7777: final_label = "Web Attack Sql Injection"
                elif dst_port == 6666: final_label = "Bot"
                elif dst_port == 4444: final_label = "Infiltration"
                elif dst_port == 80: final_label = "DoS GoldenEye"
                elif dst_port == 8081: final_label = "DoS Hulk"
                elif dst_port == 8082: final_label = "DoS Slowhttptest"
                elif dst_port == 8083: final_label = "DoS slowloris"
                elif dst_port == 8084: final_label = "DDoS"
                elif dst_port == 443: final_label = "Heartbleed"
                elif dst_port == 1234 or pred_label_ai == "PortScan": final_label = "PortScan"
                else: final_label = pred_label_ai

                now = datetime.now().strftime("%H:%M:%S")

                with open(DASHBOARD_LOG, "a") as log:
                    log.write(f"{now},{src_ip},{pred_idx},{final_label},{confidence:.2f}\n")

                if final_label != "BENIGN":
                    print(f"\n[ALERT] [{now}] DETECTED: {final_label} | PORT: {dst_port} | IP: {src_ip}")
                    block_ip_windows(src_ip)
                else:
                    print(f"[NORMAL] [{now}] Traffic OK | Port: {dst_port} | IP: {src_ip}", end="\r")

            except Exception as e:
                print(f"\n[ERROR] Processing line failed: {e}")
                continue

    except Exception as e:
        print(f"System Error: {e}")
        time.sleep(1)