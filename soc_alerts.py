import tkinter as tk
from tkinter import filedialog
import pyshark
import os
from collections import defaultdict

# Function to open file dialog and select a file
def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("All Files", "*.*")]
    )
    return file

# Function to analyze PCAP files using PyShark
def analyze_pcap(pcap_file):
    print("\nAnalyzing PCAP file...")
    try:
        cap = pyshark.FileCapture(pcap_file)
        ip_count = defaultdict(int)  # To count the number of packets per IP
        suspicious_ips = set()  # Set to keep track of suspicious IPs

        for packet in cap:
            if hasattr(packet, 'ip'):  # Check if the packet has an IP layer
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
                protocol = packet.transport_layer
                print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")

                # Count packets per source IP
                ip_count[ip_src] += 1

                # Check if the number of packets exceeds a threshold (e.g., 100 packets)
                if ip_count[ip_src] > 100:  # Threshold for suspicious activity
                    suspicious_ips.add(ip_src)

        # Alerts for suspicious IPs
        if suspicious_ips:
            print("\nSuspicious IPs detected (more than 100 packets):")
            for ip in suspicious_ips:
                print(f"ALERT! Suspicious activity from IP: {ip}")
        else:
            print("\nNo suspicious IPs detected.")
    
    except Exception as e:
        print(f"Error while analyzing PCAP file: {e}")

# Function to analyze regular text log files
def analyze_log(log_file):
    print("\nAnalyzing Log file...")
    event_count = defaultdict(int)
    suspicious_ips = set()

    with open(log_file, "r") as file:
        for line in file:
            # Example log format: 2025-04-19 14:35:45 - IP: 192.168.1.10 - Event: Failed login attempt
            parts = line.strip().split(" - ")
            if len(parts) == 3:
                timestamp, ip, event = parts
                ip = ip.replace("IP: ", "")
                event = event.replace("Event: ", "")
                
                # Print the log line (for traceability)
                print(f"Processing log: {line.strip()}")

                # Count events per IP
                event_count[ip] += 1

                # Flag suspicious IPs based on specific event criteria (e.g., multiple failed login attempts)
                if event == "Failed login attempt" and event_count[ip] >= 3:
                    suspicious_ips.add(ip)

    # Alerts for suspicious IPs based on specific events
    if suspicious_ips:
        print("\nSuspicious IPs detected (multiple failed login attempts):")
        for ip in suspicious_ips:
            print(f"ALERT! Suspicious activity from IP: {ip}")
    else:
        print("\nNo suspicious activity detected.")

# Main function to choose file type and process it
def main():
    # Ask user to select a file using GUI
    file = select_file()

    if file:
        # Automatically determine the file type based on the file extension
        _, file_extension = os.path.splitext(file)

        if file_extension.lower() in [".pcap", ".pcapng", ".cap"]:
            analyze_pcap(file)
        elif file_extension.lower() == ".log":
            analyze_log(file)
        else:
            print(f"Unsupported file type: {file_extension}. Please select a .pcap, .pcapng, .cap, or .log file.")
    else:
        print("No file selected. Exiting.")

# Run the script
if __name__ == "__main__":
    main()
