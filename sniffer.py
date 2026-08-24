from scapy.all import sniff, IP, TCP, UDP, ICMP
import signal
import sys


# Packet counters
total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0


def packet_callback(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global icmp_packets

    if IP in packet:

        total_packets += 1

        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            tcp_packets += 1

        elif UDP in packet:
            protocol = "UDP"
            udp_packets += 1

        elif ICMP in packet:
            protocol = "ICMP"
            icmp_packets += 1

        else:
            protocol = "Other"

        print(
            f"[PACKET] {source} -> {destination} | Protocol: {protocol}"
        )


def show_statistics():

    print()
    print("==================================")
    print("       PACKET STATISTICS")
    print("==================================")
    print(f"Total packets captured : {total_packets}")
    print(f"TCP packets            : {tcp_packets}")
    print(f"UDP packets            : {udp_packets}")
    print(f"ICMP packets           : {icmp_packets}")
    print("==================================")


def stop_sniffer(signum, frame):

    print("\n[+] Packet sniffing stopped.")
    show_statistics()

    sys.exit(0)


# Handle CTRL+C
signal.signal(signal.SIGINT, stop_sniffer)


print("Starting packet sniffer...")
print("Press CTRL+C to stop.")


sniff(
    iface="eth0",
    filter="ip",
    prn=packet_callback,
    store=False
)
