from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
from datetime import datetime


MAX_PACKETS = 20
packet_count = 0


def get_payload_preview(payload):
    """
    Create a clean hexadecimal and ASCII preview
    of the captured payload.
    """

    # Limit payload size for clean terminal output
    preview_bytes = payload[:32]

    # Convert bytes to hexadecimal
    hex_data = " ".join(f"{byte:02x}" for byte in preview_bytes)

    # Convert printable bytes to ASCII
    ascii_data = "".join(
        chr(byte) if 32 <= byte <= 126 else "."
        for byte in preview_bytes
    )

    return hex_data, ascii_data


def packet_callback(packet):
    global packet_count

    # Ignore packets that do not contain an IP layer
    if not packet.haslayer(IP):
        return

    # Stop after the requested number of IP packets
    if packet_count >= MAX_PACKETS:
        return

    packet_count += 1

    print("\n" + "=" * 70)
    print(f"Packet #{packet_count}")
    print("=" * 70)

    # Timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Timestamp        : {timestamp}")

    # IP information
    ip_layer = packet[IP]

    print(f"Source IP        : {ip_layer.src}")
    print(f"Destination IP   : {ip_layer.dst}")

    # Protocol detection
    if packet.haslayer(TCP):
        protocol = "TCP"

    elif packet.haslayer(UDP):
        protocol = "UDP"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    else:
        protocol = f"IP Protocol ({ip_layer.proto})"

    print(f"Protocol         : {protocol}")

    # TCP information
    if packet.haslayer(TCP):

        print(f"Source Port      : {packet[TCP].sport}")
        print(f"Destination Port : {packet[TCP].dport}")

    # UDP information
    elif packet.haslayer(UDP):

        print(f"Source Port      : {packet[UDP].sport}")
        print(f"Destination Port : {packet[UDP].dport}")

    # Payload information
    if packet.haslayer(Raw):

        payload = bytes(packet[Raw].load)

        hex_data, ascii_data = get_payload_preview(payload)

        print(f"Payload Size     : {len(payload)} bytes")
        print(f"Payload (hex)    : {hex_data}")
        print(f"Payload (ASCII)  : {ascii_data}")

    else:

        print("Payload          : No application payload")


print("=" * 70)
print("                 CodeAlpha - Network Sniffer")
print("=" * 70)
print("[+] Starting packet capture...")
print(f"[+] Maximum packets: {MAX_PACKETS}")
print("[+] Loopback traffic excluded")
print("[+] Press Ctrl+C to stop")
print()


# Capture from all Scapy interfaces except Loopback.
# This allows the sniffer to capture the PPP/PPPoE
# Internet traffic on the current Windows setup.
interfaces = [
    interface
    for interface in conf.ifaces
    if "Loopback" not in str(interface)
]


sniff(
    iface=interfaces,
    prn=packet_callback,
    stop_filter=lambda packet: packet_count >= MAX_PACKETS
)


print("\n" + "=" * 70)
print("Packet capture completed.")
print(f"Total IP packets captured: {packet_count}")
print("=" * 70)