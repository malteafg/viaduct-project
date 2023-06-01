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

for packet in packets:
    pretty_print(packet)
    print(f"Time: {get_time(packet)}")
    print(f"Packet size: {len(packet.payload)}")
    print(f"Payload size: {len(packet)}")

    if has_data(packet):
        print(f"Data size: {len(packet.load)}")
    else:
        print("This packet carries no data")

print("---------------------------")
print(f"Number of packets:       {len(packets)}")
print(f"Number of local packets: {len(filter_to_local(packets))}")

print(f"Communicating ports:     {find_communicating_ports(packets)}")

print("Communicating ports details:")
ports_details = communicating_ports_details(packets)
filtered_ports = filter_communication(ports_details)

pretty_print_details(filtered_ports)

show_ports_chronologically(packets)

show_communication_graph(filtered_ports, ports_alice, ports_bob, pcap_file)

