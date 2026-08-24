from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime


# ==============================
# Global Variables
# ==============================

total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0

arp_table = {}


# ==============================
# Packet Sniffer
# ==============================

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


# ==============================
# ARP Spoofing Detector
# ==============================

def arp_callback(packet):

    if ARP in packet and packet[ARP].op == 2:

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table:

            old_mac = arp_table[ip]

            if old_mac != mac:

                print("\n================================")
                print("[WARNING] Possible ARP Spoofing!")
                print("================================")
                print(f"IP Address : {ip}")
                print(f"Old MAC    : {old_mac}")
                print(f"New MAC    : {mac}")

                log_alert(ip, old_mac, mac)

        else:

            arp_table[ip] = mac

            print(f"[ARP] {ip} -> {mac}")


# ==============================
# Log ARP Alert
# ==============================

def log_alert(ip, old_mac, new_mac):

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open("arp_alerts.log", "a") as file:

        file.write(
            f"{current_time}\n"
            f"Possible ARP Spoofing\n"
            f"IP: {ip}\n"
            f"Old MAC: {old_mac}\n"
            f"New MAC: {new_mac}\n"
            f"-----------------------------\n"
        )

    print("[+] Alert saved to arp_alerts.log")


# ==============================
# Start Packet Sniffer
# ==============================

def start_sniffer():

    print("\n==================================")
    print("       PACKET SNIFFER")
    print("==================================")

    print("Interface: eth0")
    print("Press CTRL+C to stop.\n")

    try:

        sniff(
            iface="eth0",
            filter="ip",
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:

        print("\n[+] Packet sniffing stopped.")

        show_statistics()


# ==============================
# Start ARP Detector
# ==============================

def start_arp_detector():

    print("\n==================================")
    print("       ARP SPOOF DETECTOR")
    print("==================================")

    print("Interface: eth0")
    print("Press CTRL+C to stop.\n")

    try:

        sniff(
            iface="eth0",
            filter="arp",
            prn=arp_callback,
            store=False
        )

    except KeyboardInterrupt:

        print("\n[+] ARP monitoring stopped.")


# ==============================
# Show Statistics
# ==============================

def show_statistics():

    print("\n==================================")
    print("       PACKET STATISTICS")
    print("==================================")

    print(f"Total packets captured : {total_packets}")
    print(f"TCP packets            : {tcp_packets}")
    print(f"UDP packets            : {udp_packets}")
    print(f"ICMP packets           : {icmp_packets}")


# ==============================
# Show ARP Table
# ==============================

def show_arp_table():

    print("\n==================================")
    print("           ARP TABLE")
    print("==================================")

    if not arp_table:

        print("ARP table is empty.")

    else:

        print("IP Address\tMAC Address")
        print("------------------------------------------")

        for ip, mac in arp_table.items():

            print(f"{ip}\t{mac}")


# ==============================
# View Alerts
# ==============================

def view_alerts():

    print("\n==================================")
    print("          ARP ALERTS")
    print("==================================")

    try:

        with open("arp_alerts.log", "r") as file:

            content = file.read()

            if content:

                print(content)

            else:

                print("No alerts found.")

    except FileNotFoundError:

        print("No alert log exists yet.")


# ==============================
# Main Menu
# ==============================

def main():

    while True:

        print("\n")
        print("==================================")
        print("      NETWORK SECURITY TOOL")
        print("==================================")

        print("1. Start Packet Sniffer")
        print("2. Start ARP Detector")
        print("3. Show ARP Table")
        print("4. Show Packet Statistics")
        print("5. View Alerts")
        print("6. Exit")

        choice = input("\nEnter choice: ")

        if choice == "1":

            start_sniffer()

        elif choice == "2":

            start_arp_detector()

        elif choice == "3":

            show_arp_table()

        elif choice == "4":

            show_statistics()

        elif choice == "5":

            view_alerts()

        elif choice == "6":

            print("\nExiting Network Security Tool...")
            break

        else:

            print("\n[!] Invalid choice.")


if __name__ == "__main__":

    main()
