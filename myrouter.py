#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {}  # Create cache ARP table
        self.arp_pending = {}  # Buffer for packets pending ARP resolution
        self.intf_ipaddrs = []
        self.forwarding_table = self.build_forwarding_table()  # Build the forwarding table

        for interface in self.net.interfaces():
            self.intf_ipaddrs.append(interface.ipaddr)

    def build_forwarding_table(self):
        # Read the forwarding table from the file
        forwarding_table = []
        try:
            with open('forwarding_table.txt', 'r') as file:
                for line in file:
                    parts = line.split()
                    network, netmask, nexthop, interface_name = parts
                    forwarding_table.append({
                        'network': IPv4Network(network + '/' + netmask).network_address,
                        'netmask': netmask,
                        'nexthop': IPv4Address(nexthop),
                        'interface': interface_name
                    })
        except FileNotFoundError:
            log_error("Forwarding table file not found.")
        return forwarding_table

    def longest_prefix_match(self, dest_ip):
        # Find the longest prefix match in the forwarding table
        max_prefixlen = -1
        best_match = None
        for entry in self.forwarding_table:
            if dest_ip in IPv4Network(f"{entry['network']}/{entry['netmask']}"):
                prefixlen = entry['network'].max_prefixlen
                if prefixlen > max_prefixlen:
                    max_prefixlen = prefixlen
                    best_match = entry
        return best_match

    def send_arp_request(self, interface, dest_ip):
        # Send an ARP request for the destination IP
        if dest_ip not in self.arp_pending:
            self.arp_pending[dest_ip] = []  # Initialize buffer for pending packets
        arp_request = Arp()
        arp_request.operation = ArpOperation.Request
        arp_request.targetprotoaddr = dest_ip
        arp_request.senderprotoaddr = interface.ipaddr
        arp_request.senderhwaddr = interface.ethaddr

        ether = Ethernet()
        ether.dst = "ff:ff:ff:ff:ff:ff"  # Broadcast address
        ether.src = interface.ethaddr
        ether.ethertype = EtherType.ARP

        packet = ether / arp_request
        log_info(f"Sending ARP request for {dest_ip} on {interface.name}")
        self.net.send_packet(interface.name, packet)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"Received packet {packet} from {ifaceName}")
        incoming_intf = self.net.interface_by_name(ifaceName)
        eth = packet.get_header(Ethernet)
        if eth.dst != "ff:ff:ff:ff:ff:ff" and eth.dst != incoming_intf.ethaddr:
            return  # Drop the packet

        pkt_type = eth.ethertype
        if pkt_type == EtherType.ARP:
            arp = packet.get_header(Arp)
            if arp.targetprotoaddr in self.intf_ipaddrs:
                if arp.operation == ArpOperation.Reply:
                    self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
                    log_info(f"Updated ARP table: {self.arp_table}")
                    # Forward any pending packets for this IP
                    if arp.senderprotoaddr in self.arp_pending:
                        for pending_packet in self.arp_pending[arp.senderprotoaddr]:
                            self.forward_packet(pending_packet, self.net.interface_by_name(self.arp_pending[arp.senderprotoaddr].interface), arp.senderprotoaddr)
                        del self.arp_pending[arp.senderprotoaddr]
                elif arp.operation == ArpOperation.Request:
                    target_intf = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                    if target_intf:
                        self.send_arp_reply(ethdst=eth.src, targethwaddr=arp.senderhwaddr,
                                             targetprotoaddr=arp.senderprotoaddr,
                                             senderprotoaddr=target_intf.ipaddr,
                                             senderhwaddr=target_intf.ethaddr, interface=incoming_intf)
        elif pkt_type == EtherType.IP:
            ip = packet.get_header(IPv4)
            dest_ip = ip.dstaddr
            forwarding_entry = self.longest_prefix_match(dest_ip)
            if forwarding_entry:
                if dest_ip in self.intf_ipaddrs:
                    # Packet is for the router itself, drop it
                    return
                elif forwarding_entry['interface'] == ifaceName:
                    # Directly connected network, no need to ARP
                    self.forward_packet(packet, incoming_intf, dest_ip)
                else:
                    # Need to ARP for the next hop
                    next_hop_intf = self.net.interface_by_name(forwarding_entry['interface'])
                    if next_hop_intf.ipaddr == forwarding_entry['nexthop']:
                        self.forward_packet(packet, next_hop_intf, dest_ip)
                    else:
                        if dest_ip not in self.arp_table:
                            self.send_arp_request(next_hop_intf, dest_ip)
                        else:
                            self.forward_packet(packet, next_hop_intf, dest_ip)

    def forward_packet(self, packet, interface, dest_ip):
        # Forward the packet to the next hop or directly to the destination
        eth = packet.get_header(Ethernet)
        ip = packet.get_header(IPv4)
        ip.ttl -= 1  # Decrement TTL
        if ip.ttl == 0:
            log_info("TTL expired, dropping packet")
            return
        if dest_ip in self.arp_table:
            eth.dst = self.arp_table[dest_ip]
            self.net.send_packet(interface.name, packet)
            log_info(f"Forwarded packet to {dest_ip} on {interface.name}")
        else:
            # ARP is needed
            if dest_ip not in self.arp_pending:
                self.arp_pending[dest_ip] = []  # Initialize buffer for pending packets
            self.arp_pending[dest_ip].append({'packet': packet, 'interface': interface.name})

    def start(self):
        '''A running daemon of the router. Receive packets until the end of time.'''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    '''
    Main entry point for router. Just create Router object and get it going.
    '''
    router = Router(net)
    router.start()
