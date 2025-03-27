import psutil
from scapy.all import sniff, IP, UDP

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    return [iface for iface in interfaces if not iface.startswith('lo')]

def detect_ptp_on_interface(interface, timeout=5):
    try:
        packets = sniff(iface=interface, timeout=timeout, filter="udp port 319", store=False)
        return len(packets)
    except Exception as e:
        print(f"⚠️ Could not sniff on {interface}: {e}")
        return 0

def main():
    print("🔍 Checking PTP message activity per NIC...\n")
    interfaces = list_interfaces()

    for iface in interfaces:
        count = detect_ptp_on_interface(iface)
        print(f"Interface: {iface:15} | PTP Messages: {count}")

if __name__ == "__main__":
    main()

