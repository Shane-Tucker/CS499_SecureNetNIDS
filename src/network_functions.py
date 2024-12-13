# Internal classes
from dataset_util import *
from machine_learning_functions import *
# Python Standard Libraries
import socket
from queue import Queue
import datetime
import threading
from os import path, makedirs
# External Libraries
import geocoder
from scapy.all import *
import numpy
import psutil
import ipaddress

# Callback function to process each packet
def create_packet_callback(packet_queue, dataset_queue, stop_event): 
    def packet_callback(pkt):
        if not stop_event.is_set():
            packet_queue.put(pkt)
            dataset_queue.put(pkt)
    return packet_callback

# Function to start sniffing in the background
def start_sniffing(packet_queue, dataset_queue, stop_event):
    sniff(prn=create_packet_callback(packet_queue, dataset_queue, stop_event), iface=None, stop_filter=lambda x: stop_event.is_set())

# Read in queue of packets, grab all dataset-viable packets from the queue, and save them to both today's dataset file and a dataframe
# Dataset file is used to produce training data for future program runs
# Dataframe is used as testing data for the machine learning algorithms in the current program run
# Function returns the dataframe so that it can be passed to the machine learning algorithms
def save_to_dataset(pq):

    # Record time that program session started at to use when generating output file for this session
    output_file_time = time.strftime('%Y-%m-%d')
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

# Function to run machine learning algorithms on collected packet data
def start_machine_learning(dataset_queue: Queue, stop_event, dataset_file_name, classification_results, clustering_results):

    # Initialize machine learning algorithms
    ml_active = False
    column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length','label']

    # Load dataset from file and use it to train machine learning algorithms
    if (dataset_file_name != ''):
        print('Training machine learning algorithms')
        data_train = pd.read_csv(dataset_file_name, header=0, names=column_names)
        knn_model = knn_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)
        kmeans_model = kmeans_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)
        ml_active = True
    else:
        print('No dataset file loaded. Running program without machine learning functionality.')

    # Loop until network monitoring is stopped
    while not stop_event.is_set():
        # Write collected packet data to dataset for future use
        data_test = save_to_dataset(dataset_queue)

        if((ml_active == True) and (len(data_test) > 0)):
            # Run machine learning algorithms using collected packets as test data
            knn_results = knn_test(knn_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'])
            kmeans_results = kmeans_test(kmeans_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'])

            # Generate the visuals for the results of the algorithms
            knn_visuals = knn_visualize(data_test, knn_results, 5)
            kmeans_visuals = kmeans_visualize(data_test, kmeans_results, 5)

            # Pass the visuals to the GUI
            classification_results.put(knn_visuals)
            clustering_results.put(kmeans_visuals)

        # Sleep for 5 seconds to let new packets come in
        time.sleep(5)

# Start the sniffing in a separate thread
def start_sniff_thread(packet_queue, dataset_queue, stop_event):
    sniff_thread = threading.Thread(target=start_sniffing, args=(packet_queue, dataset_queue, stop_event, ))
    sniff_thread.daemon = True
    sniff_thread.start()

# Start the saving function in the background
def start_ml_thread(dataset_queue, stop_event, dataset_file_name, classification_results, clustering_results): 
    save_thread = threading.Thread(target=start_machine_learning, args=(dataset_queue, stop_event, dataset_file_name, classification_results, clustering_results))
    save_thread.daemon = True
    save_thread.start() 

# Function to start network monitoring and machine learning systems
def start_network_monitoring(alerts, stop_event, dataset_file_name, classification_results, clustering_results):
    packet_queue = Queue()
    dataset_queue = Queue()
    arp_dict = {} #Initiate dictionary used for ARP Poisoning
    avg_net_rate = Queue(maxsize=120) #Initiate average network rate for ddos detection
    ddos_anom = [0] #Python is pass-by-object-reference, so make this an object so it passes properly
    
    start_sniff_thread(packet_queue, dataset_queue, stop_event)
    start_ml_thread(dataset_queue, stop_event, dataset_file_name, classification_results, clustering_results)
    
    try: 
        while not stop_event.is_set(): 
            while not packet_queue.empty():
                alerts = all_detection(packet_queue, alerts, arp_dict, avg_net_rate, ddos_anom)
                time.sleep(5)
            time.sleep(5)
    except KeyboardInterrupt: 
        pass

# Function to start all detection alert systems
def all_detection(packets, alerts, arp_dict, avg_net_rate, ddos_anom):  
    threads = [] #Keep track of threads
    ps_packets = Queue()
    arp_pois_packets = Queue()
    num_packets = packets.qsize()
    
    #Queues elements are removed when they are looked at, so a copy of the queue is made for each different detection type
    #This ensures that each detection type gets every packet, and that thread A does not pop a packet that thread B needed
    while not packets.empty(): 
        p = packets.get()
        ps_packets.put(p)
        arp_pois_packets.put(p)
        
    #Start port scan detection
    det_port_scan_thread = threading.Thread(target=det_port_scan, args=(ps_packets, alerts,))
    det_port_scan_thread.daemon = True
    threads.append(det_port_scan_thread)
    det_port_scan_thread.start()
    
    #Start arp poisoning detection
    det_arp_pois_thread = threading.Thread(target=arp_poisoning_detection, args=(arp_pois_packets, alerts, arp_dict,))
    det_arp_pois_thread.daemon = True
    threads.append(det_arp_pois_thread)
    det_arp_pois_thread.start()
    
    #Start ddos detection
    det_ddos_thread = threading.Thread(target=ddos_detection, args=(num_packets, alerts, avg_net_rate, ddos_anom,))
    det_ddos_thread.daemon = True
    threads.append(det_ddos_thread)
    det_ddos_thread.start()
    
    for thread in threads: 
        thread.join()
        
    return alerts

#Finds source location of packet. If it cannot find location (eg. originates on private network), returns None
def geolocate(ip):
    location = geocoder.ip(ip)
    if location.ok: 
        return location.country, location.city
    else: 
        return None
    
#Detects if a port scan occurs
#Works by testing if a computer attempts to connect to multiple different ports on a different computer within a short timespan
#While this does catch large scale port scans, it cannot detect targeted port scans that attempt to see if just one port is open
#Additionally, it is prone to false positives if a host requires a connection to multiple ports
def det_port_scan(packets, alerts): 
    counts = {} #Dict to keep track of all src to dst packets
    min_att_ports = 10 #Sets a minimum of the amount of ports that an host needs to try to connect to to be considered a scan
                      #If set to 10, for example, if host A tries to attempt to 10+ ports on host B, considered an attempted scan
    while not packets.empty():
        p = packets.get()
        if p.haslayer('IP') and p.haslayer('TCP'):  # Ensure packet has IP and TCP layers
            ack_flag = p['TCP'].flags & 0x10
            full_ip = f"{p['IP'].src}_{p['IP'].dst}"
            if full_ip in counts and not ack_flag: #Checks if ip is unique and ACK is not set
                if p.dport not in counts[full_ip]: 
                    counts[full_ip].append(p.dport)
            elif not ack_flag: 
                counts.update({full_ip:[p.dport]})
                    
    for i in counts: 
        if len(counts[i]) >= min_att_ports: #Compares the list of unique ports to the set minimum
            divide = i.find("_") #Splits the string into source and dest ip
            current_time = datetime.datetime.now()
            #ip_src = i[0:divide]
            #ip_dst = i[divide + 1:]
            alert = ["port scan", i[0:divide], i[divide + 1:], "low", current_time.strftime("%H:%M")] 
            alerts.put(alert)
            
#Works by creating a table of IPs and associated MAC addresses. If one is changed, potential ARP poisoning and alert is issued. 
def arp_poisoning_detection(packets, alerts, arp_dict):
    while not packets.empty(): 
        p = packets.get()
        if p.haslayer('ARP') and p['ARP'].op == 2: #Checks if ARP and if response
            ip_src = p['ARP'].psrc
            mac_src = p['ARP'].hwsrc
            if ip_src in arp_dict and arp_dict[ip_src] != mac_src: #Checks if ip is in dictionary already and if it matches or not
                alert = ["arp poisoning", arp_dict[ip_src], mac_src, "medium", datetime.datetime.now().strftime("%H:%M"), ip_src] #Creates alert if IP and MAC do not match
                alerts.put(alert)
            else: #Add if no entry in dict
                arp_dict[ip_src] = mac_src
      
#Keeps a queue of last 120 entries of the # of packets collected. If newest is abnormally large, sends alert for potential ddos
def ddos_detection(num_packets, alerts, avg_net_rate, ddos_anom): 
    if avg_net_rate.full(): 
        avg_net_rate.get() #Make room for next input if queue is full
    elif avg_net_rate.qsize() < 12:
        avg_net_rate.put(num_packets)
        
    if avg_net_rate.qsize() >= 12: #Only run after 12+ iterations of data has been collected (~1 minute)
        avg_net_rate_list = list(avg_net_rate.queue)
        high_threshold = numpy.percentile(avg_net_rate_list, 99.7) #Finds the 99.7th percentile based on the current queue (based on 68-95-99.7 rule)
        #If num_packets is abnormally large, send alert
        if num_packets > high_threshold: 
            if ddos_anom[0] == 5:
                alert = ["ddos", "N/A", "N/A", "high", datetime.datetime.now().strftime("%H:%M")]
                alerts.put(alert)
            elif ddos_anom[0] == 2: #If traffic spike lasts than more than a couple seconds, send alert for high traffic
                alert = ["high traffic", "N/A", "N/A", "low", datetime.datetime.now().strftime("%H:%M")]
                alerts.put(alert)
            elif ddos_anom[0] > 6: 
                avg_net_rate.put(num_packets) # If high traffic is persistent, start including it in threshold calculation
            ddos_anom[0] = ddos_anom[0] + 1
        else: 
            avg_net_rate.put(num_packets) # Only includes num_packets if no high traffic is detected
            ddos_anom[0] = 0 #Reset counter
        
#Built in port scanner to find vulnerabilities on network
#scan_port is what actually detects if the port is open or not
def scan_port(ip, port, open_ports, lock): 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    connection = s.connect_ex((ip, port))
    
    if connection == 0:
        with lock: 
            open_ports.append(port)
    s.close()

#port_scanner uses multithreading to increase the speed of the scanner
def port_scanner(ip): 
    open_ports = []
    lock = threading.Lock() #Thread lock to ensure only one thread can change open_ports at a time
    threads = [] #List to keep track of threads
    
    for i in range(1, 1023): #Checks this first 1023 ports (saves resources/time)
        thread = threading.Thread(target=scan_port, args=(ip, i, open_ports, lock))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join() #Join all threads to prevent premature ending

    return open_ports

def network_scanner(devices): #Finds all hosts on network
    def get_subnet(): #Gets subnet
        interfaces = psutil.net_if_addrs()
        all_ips = []
        for interfaces, addrs in interfaces.items(): 
            for addr in addrs: 
                if addr.family == socket.AF_INET: 
                    ip = addr.address
                    netmask = addr.netmask
                    if ip and netmask: 
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        if str(network) not in all_ips and str(network) != "127.0.0.0/8" and str(network) != "169.254.0.0/16": #Removes possible duplicates, loopback, and APIPA
                            all_ips.append(str(network))       
        return all_ips
    
    def arp_scan(ip): #Sends out ARP scan and finds devices
        arp_request = ARP(pdst=ip)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_packet = ether_frame / arp_request
        answered_list = srp(arp_request_packet, timeout = 1, verbose = False)[0] #Help from: https://stackoverflow.com/questions/56411258/what-is-the-proper-way-to-scan-local-network-by-sending-arp-request-with-scapy-a
        clients_list = []

        for eachelement in answered_list:
            clients_list.append(eachelement[1].psrc)
        return clients_list
    
    target = get_subnet()
    for ip in target: 
        found_devices = arp_scan(ip)
        for i in found_devices: 
            devices.append(i)

def vulnerability_assessment(): 
    def vuln_scan(results): 
        results[host] = port_scanner(host)
        
    devices = []
    threads = []
    vuln_results = {}
    network_scanner(devices)
    
    for host in devices: #Does each device as thread to save time
        thread = threading.Thread(target=vuln_scan, args=(vuln_results, ))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join() #Join all threads to prevent premature ending
        
    return vuln_results
