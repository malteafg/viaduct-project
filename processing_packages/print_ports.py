from scapy.all import *
from helpers import *
import sys
import random
import sys

if len(sys.argv) >= 2:
    pcap_file = sys.argv[1]
else:
    pcap_file = "mpc.pcap"

packets = rdpcap(pcap_file)

ports = set()

for packet in packets:
    if packet.haslayer(TCP):
        source = packet[TCP].sport
        destination = packet[TCP].dport

        ports.add(source)
        ports.add(destination)

ports_details = communicating_ports_details(packets)
filtered = filter_communication(ports_details)

filtered_ports = set()

for (src, dst) in filtered.keys():
    filtered_ports.add(src)
    filtered_ports.add(dst)

filter_sum = sum([size for (_, size) in filtered.values()])
# for (_, size) in filtered.values:
#     filter_sum += size

print(str(len(ports)) + "\t\t" + str(len(filtered_ports)) + "\t\t" + str(filter_sum))
