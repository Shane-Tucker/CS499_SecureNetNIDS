from scapy.all import *
from network_functions import *
import threading
from queue import Queue

# List to store captured packets
packet_queue = Queue()

# Callback function to process each packet
def packet_callback(pkt):
    packet_queue.put(pkt)

# Function to start sniffing in the background
def start_sniffing():
    print("Sniffing Started")
    sniff(prn=packet_callback, iface=None)
    
def save_to_database(): 
    while True:
        pass
        # WIP, will save packet information to DB when done

# Start the sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Start the saving function in the background
save_thread = threading.Thread(target=save_to_database)
save_thread.daemon = True
save_thread.start()

try:
    alerts = Queue()
    while True: 
        while not packet_queue.empty():
            alerts = all_detection(packet_queue, alerts)
            while not alerts.empty(): 
                alert = alerts.get()
                print(alert)
            
        time.sleep(5)
        
except KeyboardInterrupt:
    print("Sniffing stopped.")