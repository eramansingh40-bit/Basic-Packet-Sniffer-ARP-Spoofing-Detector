# Basic Packet Sniffer + ARP Spoofing Detector

## 1. Project Overview

This project is a simple Python-based network security tool built using
Scapy.

The project performs two main tasks:

1. Captures and analyzes network packets.
2. Monitors ARP IP-to-MAC mappings to identify possible ARP spoofing.

The project is designed for a controlled Kali Linux VMware lab environment.

---

# 2. System Architecture

```text
                    BASIC PACKET SNIFFER
                 + ARP SPOOFING DETECTOR
                            |
                            |
                     Kali Linux VM
                            |
                       eth0 Interface
                            |
              +-------------+-------------+
              |                           |
              v                           v
       Packet Capture                ARP Monitoring
          (Scapy)                       (Scapy)
              |                           |
              v                           v
        IP Packets                  ARP Requests
              |                           |
       +------+------+             +------+------+
       |      |      |             |             |
       v      v      v             v             v
      TCP    UDP    ICMP       IP Address     MAC Address
       |      |      |             |             |
       +------+------+             +------+------+
              |                           |
              v                           v
       Packet Statistics            ARP Table
                                          |
                                          v
                                  IP -> MAC Mapping
                                          |
                                          v
                                    MAC Changed?
                                      /       \
                                    /           \
                                  NO             YES
                                  |               |
                                  v               v
                               Normal       Possible ARP
                                            Spoofing
                                                |
                                                v
                                         Alert Generated
                                                |
                                                v
                                         arp_alerts.log
