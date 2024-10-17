#imports
from scapy.all import *

#main
def packet_callback(packet):
    print(packet.show())

sniff(prn=packet_callback, count=10)
