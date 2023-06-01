from scapy.all import *
from helpers import *
from graph import *
import sys


if len(sys.argv) >= 2:
    pcap_file = sys.argv[1]
else:
    pcap_file = "mpc.pcap"

if len(sys.argv) >= 4:
    ports_alice = read_ports_from_file(sys.argv[2])
    ports_bob = read_ports_from_file(sys.argv[3])
else:
    ports_alice = []
    ports_bob = []

packets = rdpcap(pcap_file)

ports_details = communicating_ports_details(packets)
filtered_ports = filter_communication(ports_details)

graph_name = pcap_file.split(".")[0]

show_communication_graph(filtered_ports, ports_alice, ports_bob, graph_name)

