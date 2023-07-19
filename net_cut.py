# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --flush
# script just drops all packets the machine sends.

import netfilterqueue


def process_packet(packet):
    print(packet)
    packet.drop()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()



