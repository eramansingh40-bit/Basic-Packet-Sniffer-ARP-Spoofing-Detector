from scapy.all import ARP, Ether, srp
from datetime import datetime
import time


# Store known IP -> MAC mappings
arp_table = {}


# Log file
LOG_FILE = "arp_alerts.log"


def get_arp_table():

    print("\n========== ARP TABLE ==========\n")
    print("IP Address          MAC Address")
    print("-------------------------------------------")

    # Create ARP request
    arp_request = ARP(pdst="192.168.81.0/24")

    # Ethernet broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast / arp_request

    # Send request
    answered = srp(
        packet,
        timeout=2,
        verbose=False,
        iface="eth0"
    )[0]

    current_table = {}

    for sent, received in answered:

        ip = received.psrc
        mac = received.hwsrc

        current_table[ip] = mac

        print(f"{ip:<20} {mac}")

    return current_table


def log_alert(ip, old_mac, new_mac):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as file:

        file.write("\n")
        file.write(f"{timestamp}\n")
        file.write("Possible ARP Spoofing\n")
        file.write(f"IP: {ip}\n")
        file.write(f"Old MAC: {old_mac}\n")
        file.write(f"New MAC: {new_mac}\n")
        file.write("-----------------------------------\n")

    print("\n[!] POSSIBLE ARP SPOOFING DETECTED!")
    print(f"IP: {ip}")
    print(f"Old MAC: {old_mac}")
    print(f"New MAC: {new_mac}")


def check_for_spoofing(current_table):

    for ip, mac in current_table.items():

        if ip in arp_table:

            old_mac = arp_table[ip]

            if old_mac != mac:

                log_alert(
                    ip,
                    old_mac,
                    mac
                )

        else:

            arp_table[ip] = mac


print("======================================")
print("       ARP SPOOFING DETECTOR")
print("======================================")

print("\n[*] Creating initial ARP table...")

arp_table = get_arp_table()

print("\n[+] ARP table created.")
print("[+] Monitoring for ARP changes...")
print("[+] Press CTRL+C to stop.")


try:

    while True:

        time.sleep(5)

        current_table = get_arp_table()

        check_for_spoofing(current_table)

        # Update known table
        arp_table.update(current_table)


except KeyboardInterrupt:

    print("\n\n[+] ARP detector stopped.")
    print(f"[+] Alerts are stored in {LOG_FILE}")
