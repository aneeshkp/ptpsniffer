import psutil
from scapy.all import sniff, Ether, UDP, Raw

# Constants
PTP_ETHERTYPE = 0x88F7
PTP_UDP_PORT = 320
PTP_ANNOUNCE_TYPE = 0x0B

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    return [iface for iface in interfaces if not iface.startswith('lo')]

def is_ptp_announce(packet):
    try:
        if Raw in packet:
            raw_data = bytes(packet[Raw])
            msg_type = raw_data[0] & 0x0F
            print(f"Raw packet msg_type = {msg_type}")
        if Ethernet in packet:
            eth = packet[Ethernet]
            if eth.type == PTP_ETHERTYPE:
                print("[Ethernet PTP] Packet captured")
                ptp_payload = bytes(packet.payload.payload)

                msg_type = ptp_payload[0] & 0x0F
                print(f"Message Type: {msg_type}")
                return msg_type == PTP_ANNOUNCE_TYPE

        if UDP in packet and packet[UDP].dport == PTP_UDP_PORT and Raw in packet:
            print("[UDP PTP] Packet captured")
            ptp_payload = bytes(packet[Raw].load)

            msg_type = ptp_payload[0] & 0x0F
            print(f"Message Type: {msg_type}")
            return msg_type == PTP_ANNOUNCE_TYPE

    except Exception as e:
        print(f"Error parsing packet: {e}")

    return False

def detect_packets_on_interface(interface, timeout=5):
    try:
        print(f"Sniffing on {interface}...")
        packets = sniff(
            iface=interface,
            timeout=timeout,
            store=False,
            prn=lambda pkt:pkt.show()
        )
        return 0  # or parse count separately
    except Exception as e:
        print(f"⚠️ Could not sniff on {interface}: {e}")
        return 0

def detect_ptp_announce_on_interface(interface, timeout=5):
    try:
        packets = sniff(
            iface=interface,
            timeout=timeout,
            filter="ether proto 0x88f7", # or udp port 320",
            store=False,
            prn=lambda pkt:pkt.show()
        )
        count = sum(1 for pkt in packets if is_ptp_announce(pkt))
        return count
    except Exception as e:
        print(f"⚠️ Could not sniff on {interface}: {e}")
        return 0

def main():
    print("🔍 Checking PTP Announce message activity per NIC...\n")
    interfaces = list_interfaces()

    for iface in interfaces:
        count = detect_ptp_announce_on_interface(iface)
       # count=detect_packets_on_interface(iface)
        print(f"Interface: {iface:15} | PTP Announce Message: {count}")

if __name__ == "__main__":
    main()

