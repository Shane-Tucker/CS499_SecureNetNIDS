from scapy.all import *
from network_functions import *
import time
import threading

# List to store captured packets
packets = []

# Callback function to process each packet
def packet_callback(pkt):
    packets.append(pkt)

# Function to start sniffing in the background
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, iface=None)
    
def save_to_database(): 
    while True:   
        time.sleep(1)
        # WIP, will save packet information to DB when done
        print("Packet information saved")

# Start the sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Start the saving function in the background
save_thread = threading.Thread(target=save_to_database)
save_thread.daemon = True
save_thread.start()

# Keep the program running
try:
    while True:
        pass  # Infinite loop to keep the program running
except KeyboardInterrupt:
    print("Sniffing stopped.")