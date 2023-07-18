import netfilterqueue
import scapy.all as scapy


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            print(scapy.packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

# service apache2 start
# echo 1 > /proc/sys/net/ipv4/ip_forward
# iptables -I FORWARD -j NFQUEUE --queue-num 0                 target
# iptables -I OUTPUT -j NFQUEUE --queue-num 0                  local
# iptables -I INPUT -j NFQUEUE --queue-num 0                   local
# iptables --flush