#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    options, arguments = parser.parse_args()
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    ans_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]


    clients_list = []
    for element in ans_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
        # print("-----------------------------------------")
    return clients_list

def result(results_list):
    print("IP\t\t\t MAC address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
result(scan_result)
