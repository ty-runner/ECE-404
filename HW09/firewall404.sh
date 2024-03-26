#!/bin/bash

# Flush and delete all previously defined rules and chains
sudo iptables -F
sudo iptables -X

# Rule 1: Accept packets originating from f1.com
f1="67.199.248.12"
sudo iptables -A INPUT -s $f1 -j ACCEPT

# Rule 2: Change outgoing packets' source IP address to your own machine's IP address (MASQUERADE)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Rule 3: Protect against indiscriminate and nonstop scanning of ports
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Rule 4: Protect against SYN-flood Attack
sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 500 -j ACCEPT

# Rule 5: Allow full loopback access
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Rule 6: Port forwarding from port 8888 to port 25565
sudo iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565

# Rule 7: Allow outgoing SSH connections to engineering.purdue.edu
engpurdue="128.46.104.20"
sudo iptables -A OUTPUT -p tcp -d $engpurdue --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Rule 8: Drop any other packets
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
