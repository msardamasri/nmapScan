#!/usr/bin/python3

import nmap
nm = nmap.PortScanner()

print("===================================")
print("|          NmapScan - MarcSM      | ")
print("===================================")

ip = input("[+] Enter IP adress -> ")

nm.scan(hosts=ip, arguments='-p- --open -n -sS --min-rate 5000 -Pn')
print('----------')
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
    print('----------')
    print("Protocol : %s" % proto)
    lport = list(nm[ip][proto].keys())
    lport.sort()
    for port in lport:
        print("port : %s\tstate : %s\tprotocol: %s" % (port, nm[ip][proto][port]["state"], proto))
print('----------')