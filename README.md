# Hacking-Course
Scripts written during hacking intro course by zSecurity
Will update as new commands are needed.

# Commands required for scripts:

# Enable IP Forwarding on Kali
echo 1 > /proc/sys/net/ipv4/ip_forward

# Local WebServer service on Kali
service apache2 start

# NetFilterQueue scripts to capture packets: 
iptables --flush
iptables -I FORWARD -j NFQUEUE --queue-num 0                 target
iptables -I OUTPUT -j NFQUEUE --queue-num 0                  local
iptables -I INPUT -j NFQUEUE --queue-num 0                   local

# Enable Bettercap for SSL strip:
bettercap -iface eth0 -caplet hstshijack/hstshijack

Running custom Kali Linux with this additional software:
Terminator
Leafpad
Firefox
Arpspoof
Mdk3
Mdk4
Pip
Pip3
BeEF Framework
Zaproxy
Zenmap
Latest working version of bettercap
Linux Wifi Hotspot
Mana toolkit
Evilgrade
Bdfproxy
Knock
