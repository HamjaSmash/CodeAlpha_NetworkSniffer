# CodeAlpha Network Sniffer

A basic network packet sniffer developed in Python using Scapy as part of the CodeAlpha Cyber Security Internship.

## Project Overview

This project captures and analyzes network packets to understand basic network communication and packet structure.

The program displays:

- Source IP address
- Destination IP address
- Network protocol
- Source port
- Destination port
- Packet timestamp
- Payload size
- Payload in hexadecimal format
- Payload in ASCII format

## Technologies Used

- Python
- Scapy
- Npcap
- GitHub

## Features

- Captures network packets using Scapy
- Detects TCP, UDP and ICMP protocols
- Displays source and destination IP addresses
- Displays source and destination ports
- Shows payload information
- Provides timestamps for captured packets
- Captures up to 20 IP packets
- Excludes loopback traffic

## How It Works

The program uses Scapy to capture network packets. Each IP packet is analyzed to identify its source address, destination address, protocol, ports and payload information.

For Windows packet capture, Npcap is used together with Scapy.

## Example Output

```text
Packet #1
Timestamp        : 2026-XX-XX XX:XX:XX
Source IP        : 172.17.0.27
Destination IP   : 142.251.223.14
Protocol         : UDP
Source Port      : 56548
Destination Port : 443
Payload Size     : 1243 bytes
Payload (hex)    : ...
Payload (ASCII)  : ...
