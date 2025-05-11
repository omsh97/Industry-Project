import pandas as pd
import json
import random

def generate_instruction(row):
    """Generate a clear instruction for the network traffic analysis task."""
    return "Analyze the following network traffic data and determine if it shows signs of malicious activity."

def generate_input(row):
    """Generate a structured input from the network traffic data."""
    input_text = f"Network Traffic Analysis Request:\n\n"
    input_text += f"Protocol: {row['proto']}\n"
    input_text += f"Service: {row['service']}\n"
    input_text += f"State: {row['state']}\n"
    input_text += f"Duration: {row['dur']} seconds\n\n"
    
    input_text += "Traffic Statistics:\n"
    input_text += f"Source packets: {row['spkts']}\n"
    input_text += f"Destination packets: {row['dpkts']}\n"
    input_text += f"Source bytes: {row['sbytes']}\n"
    input_text += f"Destination bytes: {row['dbytes']}\n"
    input_text += f"Source load: {row['sload']} bits/sec\n"
    input_text += f"Destination load: {row['dload']} bits/sec\n"
    input_text += f"Source TTL: {row['sttl']}\n"
    input_text += f"Destination TTL: {row['dttl']}\n\n"
    
    input_text += "Connection Statistics:\n"
    input_text += f"TCP round-trip time: {row['smean']}\n"
    input_text += f"SYN-ACK time: {row['dmean']}\n"
    input_text += f"ACK data time: {row['ct_srv_src']}\n"
    input_text += f"Mean packet size (source): {row['ct_src_ltm']}\n"
    input_text += f"Mean packet size (destination): {row['ct_dst_ltm']}\n"
    
    return input_text

def generate_output(row):
    """Generate an appropriate response based on the attack type."""
    attack_type = row['attack_cat']
    if attack_type == 'Normal':
        return "This network traffic appears to be normal and legitimate. No signs of malicious activity detected."
    else:
        #return f"This network traffic shows characteristics of a {attack_type} attack. The traffic pattern is suspicious and requires further investigation."
        return f"This network traffic shows characteristics of an attack. The traffic pattern is suspicious and requires further investigation."

def main():
    # Read the training set
    df = pd.read_csv('CSV Files/Training and Testing Sets/UNSW_NB15_training-set.csv')
    
    # Convert to Alpaca format
    training_data = []
    for _, row in df.iterrows():
        entry = {
            "instruction": generate_instruction(row),
            "input": generate_input(row),
            "output": generate_output(row)
        }
        training_data.append(entry)
    
    # Save to JSON file
    with open('training_prompts_alpaca2.json', 'w') as f:
        json.dump(training_data, f, indent=2)
    
    print(f"Converted {len(training_data)} examples to Alpaca format")

if __name__ == "__main__":
    main() 