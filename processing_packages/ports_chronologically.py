from scapy.all import *
from helpers import *
import sys

if len(sys.argv) >= 2:
    pcap_file = sys.argv[1]
else:
    pcap_file = "mpc.pcap"

packets = rdpcap(pcap_file)

show_ports_chronologically(packets)
