from scapy.all import *
from network_functions import *
from dataset_util import *
import threading
from queue import Queue
import time
from os import path, makedirs

# List to store captured packets
packet_queue = Queue()

# Record time that program session started at to use when generating output file for this session
outputFileTime = time.strftime('%Y-%m-%d')
#outputFileTime = time.strftime('%Y-%m-%d_%H.%M.%S')

# Callback function to process each packet
def packet_callback(pkt):

    print(pkt)
    packet_queue.put(pkt)


# Function to start sniffing in the background
def start_sniffing():
    print("Sniffing Started")
    sniff(prn=packet_callback, iface=None)


def save_to_database(pq):

    fileName = 'dataset_raw'
    filePath = './dataset/raw'
    fileFormat = '.csv'

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(filePath):
        makedirs(filePath)

    outputFileName = filePath + '/' + fileName + '_' + outputFileTime + fileFormat
    outputFile = open(outputFileName, 'a')

    while not pq.empty():
        pkt = pq.get()

        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            dataset_packet =  dataset_entry(pkt[IP].src, pkt[IP].dst, pkt[IP].sport, pkt[IP].dport, pkt[IP].len)
            new_line = write_dataset_entry(dataset_packet)
            outputFile.write(new_line)

    outputFile.close()


#aysnc_sniff = AsyncSniffer(prn=packet_callback, iface=None, count=1000) # Collect N packets
aysnc_sniff = AsyncSniffer(prn=packet_callback, iface=None, timeout=300) # Collect packets for N seconds
aysnc_sniff.start()
aysnc_sniff.join()

save_to_database(packet_queue)


# Start the sniffing in a separate thread
#sniff_thread = threading.Thread(target=start_sniffing)
#sniff_thread.daemon = True
#sniff_thread.start()

# Start the saving function in the background
#save_thread = threading.Thread(target=save_to_database)
#save_thread.daemon = True
#save_thread.start()

#try:
#    while True: 
#        while not packet_queue.empty():
#            alerts = all_detection(packet_queue)
#            if not alerts.empty(): 
#                print(list(alerts.queue))
#            
#        time.sleep(5)
        
#except KeyboardInterrupt:
#    print("Sniffing stopped.")
#    save_to_database(packet_queue)
