import geocoder
import socket
from scapy.all import *

#Finds source location of packet. If it cannot find location (eg. originates on private network), returns None
def geolocate(ip):
    location = geocoder.ip(ip)
    if location.ok: 
        return location.country, location.city
    else: 
        return None
    
#Detects if a port scan occurs
#Works by testing if a computer attempts to connect to multiple different ports on a different computer within a short timespan
#May create false positives if host is running program that purposefully uses multiple ports
def det_port_scan(): 
    pass
    
#Built in port scanner to find vulnerabilities on network
def find_open_ports():
    open_ports = {}
    
