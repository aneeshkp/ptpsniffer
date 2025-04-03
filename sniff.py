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
        if Ether in packet and packet[Ether].type == PTP_ETHERTYPE:
            raw_layer = packet.getlayer(Raw)
            if not raw_layer or len(raw_layer.load) < 1:
                return False

            raw_bytes = raw_layer.load
            msg_type = raw_bytes[0] & 0x0F

            return msg_type == PTP_ANNOUNCE_TYPE

        # Optional UDP fallback if needed
        if UDP in packet and packet[UDP].dport == PTP_UDP_PORT and Raw in packet:
            raw_bytes = packet[Raw].load
            if raw_bytes and len(raw_bytes) >= 1:
                msg_type = raw_bytes[0] & 0x0F
                return msg_type == PTP_ANNOUNCE_TYPE

    except Exception:
        return False

    return False


def detect_packets_on_interface(interface, timeout=20):
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
            filter="ether proto 0x88f7 or udp port 320",
            store=True  # store packets for processing
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

