from scapy.all import *
from helpers import *
from graph import *
import sys


def communicating_ports_with_timestamps(packets):
    ports_details = {}

    for packet in packets:
        if packet.haslayer(TCP):
            source = packet[TCP].sport
            destination = packet[TCP].dport

            if (source, destination) in ports_details:
                packets_num, packets_size, timestamp = ports_details[(source, destination)]
                ports_details[(source, destination)] = (packets_num + 1, packets_size + get_data_size(packet), timestamp)
            else:
                timestamp = get_time(packet)
                ports_details[(source, destination)] = (1, get_data_size(packet), timestamp)
    
    return ports_details


def filter_communication_with_timestamps(ports_details, min_packets=2, min_size=1):
    return {(src, dst): (packets_num, packets_size, timestamp) 
     for (src, dst), (packets_num, packets_size, timestamp) in ports_details.items() 
     if packets_num >= min_packets or packets_size >= min_size}

def get_communication_for_specific_port(ports_details, port): 
    details = {}

    for (port_1, port_2), (packets_num, packets_size, timestamp) in ports_details.items():
        if port_1 == port or port_2 == port:
            details[(port_1, port_2)] = (packets_num, packets_size, timestamp) 
    return details

def make_undirected(ports_details):
    details = {}

    for (src, dst), (curr_packets_num, curr_packets_size, curr_timestamp) in ports_details.items():
        ports = (min(src, dst), max(src, dst))
        if ports in details:
            packets_num, packets_size, timestamp = details[ports]
            details[ports] = (curr_packets_num + packets_num, curr_packets_size + packets_size, min(curr_timestamp, timestamp))
        else:
            details[ports] = (curr_packets_num, curr_packets_size, curr_timestamp)

    return details


def get_communication_per_port(undirected_details):
    communication = {}

    for (port_1, port_2), (packets_num, packets_size, timestamp) in undirected_details.items():
        if port_1 in communication:
            communication[port_1].append((port_2, packets_num, packets_size, timestamp))
        else:
            communication[port_1] = [(port_2, packets_num, packets_size, timestamp)]

        if port_2 in communication:
            communication[port_2].append((port_1, packets_num, packets_size, timestamp))
        else:
            communication[port_2] = [(port_1, packets_num, packets_size, timestamp)]

    return communication


def has_mpc(ports_details):
    undirected_details = make_undirected(ports_details)
    communication_per_port = get_communication_per_port(undirected_details)

    for _, communication in communication_per_port.items():
        if len(communication) >= 2:
            for i in range(len(communication)):
                for j in range(i+1, len(communication)):
                    comm_1_time = communication[i][3].timestamp()
                    comm_2_time = communication[j][3].timestamp()

                    comm_1_size = communication[i][2]
                    comm_2_size = communication[j][2]

                    if abs(comm_1_time - comm_2_time) < 0.25 and comm_1_size > 3000 and comm_2_size > 3000:
                        return True
    
    return False

def is_multiple_of_conversation_size_ish(packets_size, conversation_size):
    if packets_size is None or packets_size < 3:
        return (False, 0)
    if ((packets_size-1) % conversation_size == 0):
        print()
        return (True, int((packets_size-1)/conversation_size))
    if ((packets_size-2) % conversation_size == 0):
        return (True, int((packets_size-2)/conversation_size))
    return (False, 0)

def get_packets_sent_to_port(ports_details, port):
    undirected_details = make_undirected(ports_details)
    single_port_details = get_communication_for_specific_port(ports_details, port)

    if len(single_port_details) == 2:
        for (port_1, port_2), (packets_num, packets_size, timestamp) in single_port_details.items():
            if port_2 == port:
                return packets_size
                break

def classify(packets):
    ports_details = filter_communication_with_timestamps(communicating_ports_with_timestamps(packets))
    assumed_alice_port = 5000
    usual_commitment_conversation_size = 39
    usual_zkp_conversation_size = 78
    total_port_packet_size = get_packets_sent_to_port(ports_details, assumed_alice_port)
    might_have_commitment = is_multiple_of_conversation_size_ish(total_port_packet_size, usual_commitment_conversation_size)
    might_have_zkp = is_multiple_of_conversation_size_ish(total_port_packet_size, usual_zkp_conversation_size)

    protocols = {}
    protocols["mpc"] = has_mpc(ports_details)
    protocols["zkp"] = str(might_have_zkp[0]) + ", detected " + str(might_have_zkp[1]) + " times"
    protocols["commitment"] = str(might_have_commitment[0]) + ", detected " + str(might_have_commitment[1]) + " times"
    if might_have_commitment[0] and might_have_zkp[0]:
        protocols["eitherZkpOrCommitment"] = "Could be either: ZKP: (" + protocols["zkp"] + ") or COMMITMENT: (" + protocols["commitment"] + ")"
    
    return protocols


if len(sys.argv) >= 2:
    pcap_file = sys.argv[1]
else:
    pcap_file = "mpc.pcap"

if len(sys.argv) >= 3:
    path_to_save_graph = sys.argv[2]
else:
    path_to_save_graph = None

if len(sys.argv) >= 4:
    path_to_save_classification = sys.argv[3]
else:
    path_to_save_classification = None

ports_alice = []
ports_bob = []


packets = rdpcap(pcap_file)

filtered_ports = filter_communication(communicating_ports_details(packets))

classification = classify(packets)

show_communication_graph(filtered_ports, ports_alice, ports_bob, pcap_file, path_to_save_graph, classification)

save_classification(path_to_save_classification, classification)
