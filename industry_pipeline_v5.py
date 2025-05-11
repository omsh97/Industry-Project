import subprocess
import time
import os
import pandas as pd
from datetime import datetime
import numpy as np
from openai import OpenAI
#from tqdm import tqdm
#import json

# Configuration
interface = "ens33"  # interface for different OS
capture_duration = 10
base_dir = "/home/IndustryProject"  # path to dir

# Directory setup
pcap_dir = os.path.join(base_dir, "pcaps")
zeek_dir = os.path.join(base_dir, "zeek_logs")
argus_dir = os.path.join(base_dir, "argus_logs")

for d in [pcap_dir, zeek_dir, argus_dir]:
    os.makedirs(d, exist_ok=True)

# API Configuration
ATTACK_DETECTION_URL = "https://vmz596vt3lazdqj8.us-east-1.aws.endpoints.huggingface.cloud/v1/"
ATTACK_TYPE_URL = "https://cssjwosu0r80pfaw.us-east-1.aws.endpoints.huggingface.cloud/v1/"  # Replace with actual endpoint
API_KEY = "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"  # Replace with your Hugging Face API key

template_columns = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'service', 'state', 'dur',
    'spkts', 'dpkts', 'sbytes', 'dbytes', 'sload', 'dload', 'sttl', 'dttl',
    'smean', 'dmean', 'smeansz', 'dmeansz', 'ct_srv_src', 'ct_src_ltm', 'ct_dst_ltm'
]

# Network Capture Functions
def run_tshark(pcap_path, tshark_out_path):
    fields = [
        '-e', 'ip.src', '-e', 'tcp.srcport', '-e', 'ip.dst', '-e', 'tcp.dstport',
        '-e', 'ip.ttl', '-e', 'frame.len'
    ]
    command = ["tshark", "-r", pcap_path, "-T", "fields", *fields, "-E", "separator=,"]
    with open(tshark_out_path, 'w') as f:
        subprocess.run(command, stdout=f)

def run_capture(pcap_path):
    command = ["tshark", "-i", interface, "-a", f"duration:{capture_duration}", "-w", pcap_path]
    subprocess.run(command)

def run_zeek(pcap_path, zeek_out_dir):
    os.makedirs(zeek_out_dir, exist_ok=True)
    zeek_path = "/usr/local/zeek/bin/zeek"
    command = [zeek_path, "-C", "-r", pcap_path]
    subprocess.run(command, cwd=zeek_out_dir, capture_output=True)

def run_argus(pcap_path, argus_out_path):
    command = ["argus", "-r", pcap_path, "-w", argus_out_path]
    subprocess.run(command)

def read_argus_summary(argus_out_path):
    command = ["rasort", "-r", argus_out_path, "-m", "saddr sport daddr dport proto"]
    result = subprocess.run(command, capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")
    records = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 5:
            try:
                records.append({
                    "srcip": parts[0],
                    "sport": int(parts[1]),
                    "dstip": parts[2],
                    "dsport": int(parts[3]),
                    "proto": parts[4].lower()
                })
            except Exception:
                continue
    return pd.DataFrame(records)

def read_tshark_summary(tshark_out_path):
    cols = ['srcip', 'sport', 'dstip', 'dsport', 'ttl', 'length']
    try:
        df = pd.read_csv(
            tshark_out_path,
            names=cols,
            on_bad_lines='skip',
            engine='python'
        )
    except Exception as e:
        print(f"Error reading tshark output: {e}")
        return pd.DataFrame()

    df = df.dropna(subset=['srcip', 'dstip'])

    df['sport'] = pd.to_numeric(df['sport'], errors='coerce').fillna(0).astype(int)
    df['dsport'] = pd.to_numeric(df['dsport'], errors='coerce').fillna(0).astype(int)
    df['ttl'] = pd.to_numeric(df['ttl'], errors='coerce').fillna(0)
    df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)

    agg = df.groupby(['srcip', 'sport', 'dstip', 'dsport']).agg(
        sttl=('ttl', 'mean'),
        dttl=('ttl', 'mean'),
        smean=('length', 'mean'),
        dmean=('length', 'mean')
    ).reset_index()

    return agg

def safe_get(df, col):
    return df[col] if col in df.columns else pd.Series([np.nan] * len(df))

def read_zeek_conn_log(log_path):
    with open(log_path, 'r') as f:
        for line in f:
            if line.startswith('#fields'):
                columns = line.strip().split('\t')[1:]
                break
    df = pd.read_csv(log_path, sep='\t', comment='#', header=None, engine='python')
    df.columns = columns
    return df

def format_network_data(row):
    """Format network data into a structured input format"""
    return f"""Network Traffic Analysis Request:

Protocol: {row['proto']}
Service: {row['service']}
State: {row['state']}
Duration: {row['dur']} seconds

Traffic Statistics:
Source packets: {row['spkts']}
Destination packets: {row['dpkts']}
Source bytes: {row['sbytes']}
Destination bytes: {row['dbytes']}
Source load: {row['sload']} bits/sec
Destination load: {row['dload']} bits/sec
Source TTL: {row['sttl']}
Destination TTL: {row['dttl']}

Connection Statistics:
TCP round-trip time: {row.get('smean', 0)}
SYN-ACK time: {row.get('dmean', 0)}
ACK data time: {row.get('smeansz', 0)}
Mean packet size (source): {row.get('dmeansz', 0)}
Mean packet size (destination): {row.get('ct_srv_src', 0)}"""

# Inference Functions
def format_prompt(instruction, input_text):
    return f"{instruction}\n\n{input_text}"

def generate_response(prompt, endpoint_url):
    try:
        client = OpenAI(
            base_url=endpoint_url,
            api_key=API_KEY
        )
        
        # Print the request data for debugging
        print("\nSending request to Hugging Face with data:")
        print(f"Prompt: {prompt}")
        
        chat_completion = client.chat.completions.create(
            model="tgi",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            top_p=None,
            temperature=None,
            max_tokens=150,
            stream=True,
            seed=None,
            stop=None,
            frequency_penalty=None,
            presence_penalty=None
        )
        
        # Collect the streamed response
        full_response = ""
        for message in chat_completion:
            if message.choices[0].delta.content:
                content = message.choices[0].delta.content
                full_response += content
                print(content, end="", flush=True)
        
        print("\n")  # New line after response
        return full_response.strip()
        
    except Exception as e:
        print(f"Error generating response: {e}")
        return None

def process_network_flow(flow_data):
    """Process a single network flow through the inference pipeline"""
    # Step 1: Detect if there's an attack
    attack_prompt = format_prompt(flow_data["instruction"], flow_data["input"])
    attack_response = generate_response(attack_prompt, ATTACK_DETECTION_URL)
    
    if attack_response:
        # Check if an attack was detected
        if any(keyword in attack_response.lower() for keyword in ['shows characteristics', 'investigation', 'suspicious']):
            # Step 2: Determine the attack type
            type_instruction = "Analyze the following network traffic data and determine the specific type of attack being performed."
            type_prompt = format_prompt(type_instruction, flow_data["input"])
            type_response = generate_response(type_prompt, ATTACK_TYPE_URL)
            
            if type_response:
                final_response = type_response
            else:
                final_response = attack_response
            
            # Print attack detection
            print("\n" + "="*80)
            print(f"ATTACK DETECTED!")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Source IP: {flow_data.get('srcip', 'N/A')}")
            print(f"Destination IP: {flow_data.get('dstip', 'N/A')}")
            print(f"Analysis: {final_response}")
            print("="*80 + "\n")
            
            return True
    return False

def process_captured_data(zeek_out_dir, argus_df, tshark_df):
    """Process captured network data and perform inference"""
    log_path = os.path.join(zeek_out_dir, "conn.log")
    if not os.path.exists(log_path):
        return
    
    df = read_zeek_conn_log(log_path)
    if df.empty:
        return

    # Process network data
    out = pd.DataFrame()
    out["srcip"] = safe_get(df, "id.orig_h")
    out["sport"] = safe_get(df, "id.orig_p")
    out["dstip"] = safe_get(df, "id.resp_h")
    out["dsport"] = safe_get(df, "id.resp_p")
    out["proto"] = safe_get(df, "proto").str.lower()
    out["service"] = safe_get(df, "service")
    out["state"] = safe_get(df, "conn_state")
    out["dur"] = pd.to_numeric(safe_get(df, "duration"), errors='coerce')
    out["spkts"] = pd.to_numeric(safe_get(df, "orig_pkts"), errors='coerce')
    out["dpkts"] = pd.to_numeric(safe_get(df, "resp_pkts"), errors='coerce')
    out["sbytes"] = pd.to_numeric(safe_get(df, "orig_bytes"), errors='coerce')
    out["dbytes"] = pd.to_numeric(safe_get(df, "resp_bytes"), errors='coerce')

    out = out[out["dur"] > 0]

    out["sload"] = (out["sbytes"] * 8 / out["dur"]).replace([np.inf, -np.inf], 0)
    out["dload"] = (out["dbytes"] * 8 / out["dur"]).replace([np.inf, -np.inf], 0)

    if not tshark_df.empty:
        out = out.merge(tshark_df, on=["srcip", "sport", "dstip", "dsport"], how="left")

    if not argus_df.empty:
        out = out.merge(argus_df, on=["srcip", "sport", "dstip", "dsport", "proto"], how="left")

    out["smeansz"] = pd.Series(np.where(
        safe_get(df, "orig_pkts").astype(float) > 0,
        safe_get(df, "orig_ip_bytes").astype(float) / safe_get(df, "orig_pkts").astype(float),
        0)).replace([np.inf, -np.inf], 0).fillna(0)

    out["dmeansz"] = pd.Series(np.where(
        safe_get(df, "resp_pkts").astype(float) > 0,
        safe_get(df, "resp_ip_bytes").astype(float) / safe_get(df, "resp_pkts").astype(float),
        0)).replace([np.inf, -np.inf], 0).fillna(0)

    for col in ["sttl", "dttl", "smean", "dmean", "smeansz", "dmeansz"]:
        if col not in out.columns:
            out[col] = 0
        else:
            out[col] = out[col].fillna(0)

    out["ct_srv_src"] = out.groupby(['srcip', 'sport', 'proto'])['dstip'].transform('nunique').fillna(0)
    out["ct_src_ltm"] = out.groupby(['srcip'])['dstip'].transform('nunique').fillna(0)
    out["ct_dst_ltm"] = out.groupby(['dstip'])['srcip'].transform('nunique').fillna(0)

    # Process each network flow through inference pipeline
    attack_detected = False
    for _, row in out.iterrows():
        flow_data = {
            "instruction": "Analyze the following network traffic data for signs of malicious activity.",
            "input": format_network_data(row),
            "srcip": row["srcip"],
            "dstip": row["dstip"]
        }
        if process_network_flow(flow_data):
            attack_detected = True
    
    if not attack_detected:
        print(".", end="", flush=True)  # Show activity indicator for normal traffic

def main():
    print("Starting network traffic monitoring...")
    print("Press Ctrl+C to stop")
    print("Normal traffic will be shown as dots (.), attacks will be displayed in detail")
    
    try:
        while True:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Capture and process network data
            pcap_file = os.path.join(pcap_dir, f"capture_{ts}.pcap")
            tshark_file = os.path.join(pcap_dir, f"tshark_{ts}.csv")
            zeek_out = os.path.join(zeek_dir, f"zeek_{ts}")
            argus_out = os.path.join(argus_dir, f"argus_{ts}.argus")

            run_capture(pcap_file)
            run_zeek(pcap_file, zeek_out)
            run_tshark(pcap_file, tshark_file)
            run_argus(pcap_file, argus_out)

            tshark_df = read_tshark_summary(tshark_file)
            argus_df = read_argus_summary(argus_out)
            
            process_captured_data(zeek_out, argus_df, tshark_df)

            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping network traffic monitoring...")

if __name__ == "__main__":
    main() 