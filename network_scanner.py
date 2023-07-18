import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ipaddress", dest="user_ip", help="controls ip, /24 lists entire subnet")
    options = parser.parse_args()
    if not options.user_ip:
        parser.error("Please specify an ip address, use -i or --help for more info.")
    return options
def scan(ip):
    arp_request = scapy.ARP(pdst=str(ip))
    broadcast = scapy.Ether(dst=str("ff:ff:ff:ff:ff:ff"))
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
# ignores unanswered_list

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(str(options.user_ip))

print_result(scan_result)
