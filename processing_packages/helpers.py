from scapy.all import *
import datetime


LOCAL_ADDRESS = "127.0.0.1"

def read_ports_from_file(file):
    ports = []

    with open(file, "r") as f:
        for line in f:
            if len(line) >= 1:
                ports.append(int(line))

    return ports


def to_flag_names(packet):
    flags = packet[TCP].flags

    found_flags = []

    if flags.A:
        found_flags.append("ACK")

    if flags.P:
        found_flags.append("PSH")

    if flags.S:
        found_flags.append("SYN")

    if flags.F:
        found_flags.append("FIN")

    return ", ".join(found_flags)


def pretty_print(packet):
    print("---------------------------")

    if (packet.haslayer(TCP)):
        print(f"Source:           {packet[IP].src}")
        print(f"Source port:      {packet[TCP].sport}")
        print(f"Destination:      {packet[IP].dst}")
        print(f"Destination port: {packet[TCP].dport}")
        print(f"Flags:            {to_flag_names(packet)}")
    else:
        print("No TCP")


def has_data(packet):
    return hasattr(packet, "load")


def get_data_size(packet):
    if has_data(packet):
        return len(packet.load)
    else:
        return 0


def get_time(packet):
    return datetime.datetime.fromtimestamp(float(packet.time))


def filter_to_local(packets):
    local_packets = []
    
    for packet in packets:
        if packet[IP].src == LOCAL_ADDRESS and packet[IP].dst == LOCAL_ADDRESS:
            local_packets.append(packet)

    return local_packets


def find_communicating_ports(packets):
    communicating_ports = set()

    for packet in packets:
        if packet.haslayer(TCP):
            source = packet[TCP].sport
            destination = packet[TCP].dport

            communicating_ports.add((source, destination))
    
    return communicating_ports


def communicating_ports_details(packets):
    ports_details = {}

    for packet in packets:
        if packet.haslayer(TCP):
            source = packet[TCP].sport
            destination = packet[TCP].dport

            if (source, destination) in ports_details:
                packets_num, packets_size = ports_details[(source, destination)]
                ports_details[(source, destination)] = (packets_num + 1, packets_size + get_data_size(packet))
            else:
                ports_details[(source, destination)] = (1, get_data_size(packet))
    
    return ports_details


def filter_communication(ports_details, min_packets=2, min_size=1):
    return {(src, dst): (packets_num, packets_size) 
     for (src, dst), (packets_num, packets_size) in ports_details.items() 
     if packets_num >= min_packets or packets_size >= min_size}
        

def pretty_print_details(ports_details):
    for (src, dst), (packets_num, packets_size) in ports_details.items():
        print("~~~~~~~~~~~~~~~~~~~~~~~~")
        print(f"Source:            {src}")
        print(f"Destination:       {dst}")
        print(f"Number of packets: {packets_num}")
        print(f"Sum of data sent:  {packets_size}")


def show_ports_chronologically(packets):
    ports_times = dict()

    for packet in packets:
        if (packet.haslayer(TCP)):
            source_port = packet[TCP].sport

            if source_port in ports_times:
                ports_times[source_port].append(get_time(packet))
            else:
                ports_times[source_port] = [get_time(packet)]

            destination_port = packet[TCP].sport

            if destination_port in ports_times:
                ports_times[destination_port].append(get_time(packet))
            else:
                ports_times[destination_port] = [get_time(packet)]
    
    ports_min_times = [(port, min(times)) for port, times in ports_times.items()]
    sorted_ports_min_times = sorted(ports_min_times, key=lambda x: x[1])

    for port, _ in sorted_ports_min_times:
        print(port)


def save_classification(path, classification):
    if path is not None:
        with open(path, "a+") as f:
            f.write(f'MPC: {classification["mpc"]}\n')
            if 'eitherZkpOrCommitment' in classification:
                f.write(f'{classification["eitherZkpOrCommitment"]}\n')
            if not ('eitherZkpOrCommitment' in classification):
                f.write(f'ZKP: {classification["zkp"]}\n')
                f.write(f'COMMITMENT: {classification["commitment"]}\n')

