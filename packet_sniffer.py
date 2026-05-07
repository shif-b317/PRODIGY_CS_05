from scapy.all import sniff
from datetime import datetime

# Function to process packets
def packet_callback(packet):

    # Check if packet has IP layer
    if packet.haslayer("IP"):

        time = datetime.now().strftime("%H:%M:%S")

        # Hide real IP addresses for privacy
        src_ip = "xxx.xxx.x.x"
        dst_ip = "xxx.xxx.x.x"

        # Detect protocol type
        proto_num = packet["IP"].proto

        if proto_num == 6:
            protocol = "TCP"
        elif proto_num == 17:
            protocol = "UDP"
        elif proto_num == 1:
            protocol = "ICMP"
        else:
            protocol = str(proto_num)

        length = len(packet)

        # Packet information
        info = (
            f"[{time}] "
            f"Source: {src_ip} | "
            f"Destination: {dst_ip} | "
            f"Protocol: {protocol} | "
            f"Length: {length}"
        )

        # Display output
        print(info)

        # Save to log file
        with open("packets_log.txt", "a") as file:
            file.write(info + "\n")


# Starting message
print("Starting Packet Analyzer...")
print("Capturing 20 IP packets...\n")

# Start sniffing
sniff(
    filter="ip",
    prn=packet_callback,
    store=False,
    count=20
)

print("\nPacket capture completed.")