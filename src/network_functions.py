import geocoder
from socket import *
from scapy.all import *
from queue import Queue
import datetime
import numpy

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
    elif avg_net_rate.qsize() <= 12:
        avg_net_rate.put(num_packets) #Add until greater than 12 so that the rest can take over
        
    if avg_net_rate.qsize() >= 12: #Only run after 12+ iterations of data has been collected (~1 minute)
        avg_net_rate_list = list(avg_net_rate.queue)
        high_threshold = numpy.percentile(avg_net_rate_list, 99.7) #Finds the 99.7th percentile based on the current queue (based on 68-95-99.7 rule)
        #If num_packets is abnormally large, send alert
        if num_packets > high_threshold: 
            if ddos_anom[0] >= 5:
                alert = ["ddos", "N/A", "N/A", "high", datetime.datetime.now().strftime("%H:%M")]
                alerts.put(alert)
            elif ddos_anom[0] == 2: #If traffic spike lasts than more than a couple seconds, send alert for high traffic
                alert = ["high traffic", "N/A", "N/A", "low", datetime.datetime.now().strftime("%H:%M")]
                alerts.put(alert)
            ddos_anom[0] = ddos_anom[0] + 1
        else: 
            avg_net_rate.put(num_packets) #Add num_packets to the counter
                                          #Purposefully does not put if high traffic so that threshold is not skewed
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
    
    for i in range(1, 65536): #Checks every port
        thread = threading.Thread(target=scan_port, args=(ip, i, open_ports, lock))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join() #Join all threads to prevent premature ending

    return open_ports
