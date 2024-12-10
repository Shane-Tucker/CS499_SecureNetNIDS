from scapy.all import *
from network_functions import *
from dataset_util import *
from machine_learning_functions import *
import threading
from queue import Queue
import time
from os import path, makedirs

# List to store captured packets
packet_queue = Queue()

# Record time that program session started at to use when generating output file for this session
output_file_time = time.strftime('%Y-%m-%d')

# Callback function to process each packet
def packet_callback(pkt):

    print(pkt)
    packet_queue.put(pkt)


# Function to start sniffing in the background
def start_sniffing():
    print("Sniffing Started")
    sniff(prn=packet_callback, iface=None)


# Read in queue of packets, grab all dataset-viable packets from the queue, and save them to both today's dataset file and a dataframe
# Dataset file is used to produce training data for future program runs
# Dataframe is used as testing data for the machine learning algorithms in the current program run
# Function returns the dataframe so that it can be passed to the machine learning algorithms
def save_to_database(pq):

    file_name = 'dataset'
    file_path = './dataset/raw'
    file_format = '.csv'
    new_dataframe_entries = []

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(file_path):
        makedirs(file_path)

    output_file_name = file_path + '/' + file_name + '_' + output_file_time + file_format
    output_file = open(output_file_name, 'a')

    while not pq.empty():
        pkt = pq.get()

        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            dataset_packet =  dataset_entry(pkt[IP].src, pkt[IP].dst, pkt[IP].sport, pkt[IP].dport, pkt[IP].len)

            # Write packet to dataset file
            new_line = write_dataset_entry(dataset_packet)
            output_file.write(new_line)

            # Preprocess packet and add to dataframe
            dataset_packet.src_ip = ipv4_string_to_float(dataset_packet.src_ip)
            dataset_packet.dst_ip = ipv4_string_to_float(dataset_packet.dst_ip)
            new_dataframe_entries.append(dataset_packet)

    output_file.close()

    new_dataframe = pd.DataFrame(data=new_dataframe_entries, columns=['src_ip','dst_ip','src_port','dst_port','frame_length'])

    return new_dataframe



# -----------------------------------------------------------------------
# Example integration of machine learning systems with packet collection
# -----------------------------------------------------------------------

# Initialize machine learning algorithms
column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length','label']
print('"blank": skip machine learning algorithms\n"today": load dataset for today\'s collected data')
user_input = input("Enter dataset file name (or blank to skip machine learning algorithms): ")
ml_active = False

if (user_input == 'today'): user_input = './dataset/preprocessed/dataset_' + output_file_time + '_preprocessed.csv'

if path.exists(user_input):
    print('Training machine learning algorithms')
    data_train = pd.read_csv(user_input, header=0, names=column_names)
    knn_model = knn_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)
    kmeans_model = kmeans_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 2)
    ml_active = True
else:
    print('unable to locate file: ', user_input)
    print('Running program without machine learning functionality.')

aysnc_sniff = AsyncSniffer(prn=packet_callback, iface=None, count=1000) # Collect N packets
#aysnc_sniff = AsyncSniffer(prn=packet_callback, iface=None, timeout=600) # Collect packets for N seconds
aysnc_sniff.start()
aysnc_sniff.join()

data_test = save_to_database(packet_queue)

if(ml_active == True):
    print('Machine learning algorithms started')
    knn_results = knn_test(knn_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'])
    kmeans_results = kmeans_test(kmeans_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'])

    knn_visualize(data_test, knn_results, 5)
    kmeans_visualize(data_test, kmeans_results, 2)

# -----------------------------------------------------------------------
# Example code end
# -----------------------------------------------------------------------



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
