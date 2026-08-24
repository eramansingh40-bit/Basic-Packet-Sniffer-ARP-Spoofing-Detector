# Basic Packet Sniffer + ARP Spoofing Detector

A simple Python-based network security project that captures network packets
and monitors ARP IP-to-MAC mappings to identify possible ARP spoofing.

This project was developed and tested in a controlled Kali Linux VMware lab.

---

## Project Overview

The project has two main security functions:

### 1. Basic Packet Sniffer

The packet sniffer captures IP packets from the network interface and displays:

- Source IP
- Destination IP
- Protocol
- TCP packets
- UDP packets
- ICMP packets
- Total packet count

### 2. ARP Spoofing Detector

The ARP detector monitors the local ARP table and maintains:

```text
IP Address -> MAC Address

## 3.Test
Use wireshark to test the results in kali vm to match.
