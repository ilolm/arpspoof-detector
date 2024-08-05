#!/usr/bin/env python3

import optparse
import scapy.all as scapy


def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Specify an interface.", default="eth0")
    options = parser.parse_args()[0]

    if not options.interface:
        parser.error("\033[91m[-] Please specify an interface. --help for more info.")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, iface=options.interface, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def sniff():
    scapy.sniff(iface=options.interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            response_ip = packet[scapy.ARP].psrc
            real_mac = get_mac(response_ip)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("\033[1;33;40m[+] You are under ARP Poisoning attack!!!")
                print(f"\t\033[1;32;40m{response_ip} tells that has {response_mac} but actually has {real_mac}\n")

        except IndexError:
            pass


options = get_options()
sniff()
