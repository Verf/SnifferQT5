#!/usr/bin/env python3
# coding: utf-8
from struct import unpack

def b2a(ip_bytes):
    ip_hex = ip_bytes.hex()
    return ".".join([str(int(ip_hex[i:i+2], 16)) for i in range(0, len(ip_hex), 2)])

def b2m(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

def Praser(raw):
    res = prase_frame(raw)
    return res

def prase_frame(raw):
    ethernet = Ethernet()
    eth_header = unpack('!6s6s2s', raw[:14])
    ethernet.mac_src = b2m(eth_header[0])
    ethernet.mac_dst = b2m(eth_header[1])
    ethernet.type = "0x" + eth_header[2].hex()
    eth_data = raw[14:]
    ethernet.raw = raw[:]
    if ethernet.type == '0x0800':
        # ip
        ethernet.packet = prase_ip(eth_data)
    elif ethernet.type == '0x0806':
        # arp
        ethernet.packet = prase_arp(eth_data)
    else:
        ethernet.packet = "0x" + eth_data.hex()
    return ethernet


def prase_ip(packet):
    # default ip header lenght is 20 byte
    ip_header = unpack('!ss2s2s2sss2s4s4s', packet[:20])
    ip_packet = IP()
    ip_packet.ip_version = str(int(ip_header[0].hex()[0], 16))
    ip_packet.ip_hlen = str(int(ip_header[0].hex()[1])*4)
    ip_packet.ip_tos = '0x' + ip_header[1].hex()
    ip_packet.ip_tlen = str(int(ip_header[2].hex(), 16))
    ip_packet.ip_ident = '0x' + ip_header[3].hex()
    ip_packet.ip_flags = str(bin(int(ip_header[4].hex(), 16))[2:].zfill(16)[:3])
    ip_packet.ip_foffset = str(bin(int(ip_header[4].hex(), 16))[2:].zfill(16)[3:])
    ip_packet.ip_ttl = str(int(ip_header[5].hex(), 16))
    ip_packet.ip_protocol = str(int(ip_header[6].hex(), 16))
    ip_packet.ip_hchecksum = '0x' + ip_header[7].hex()
    ip_packet.ip_src = b2a(ip_header[8])
    ip_packet.ip_dst = b2a(ip_header[9])
    if ip_packet.ip_hlen != "20":
        ip_packet.ip_options = packet[20:int(ip_packet.ip_hlen)]
    ip_data = packet[int(ip_packet.ip_hlen):]
    if ip_packet.ip_protocol == "6":
        # tcp
        ip_packet.ip_packet = prase_tcp(ip_data)
    elif ip_packet.ip_protocol == "17":
        # udp
        ip_packet.ip_packet = prase_udp(ip_data)
    elif ip_packet.ip_protocol == "1":
        ip_packet.ip_packet = prase_icmp(ip_data)
    return ip_packet

def prase_tcp(packet):
    # default tcp header lenght is 20 byte
    tcp_header = unpack('!2s2s4s4s2s2s2s2s', packet[:20])
    tcp_packet = TCP()
    tcp_packet.tcp_sport = str(int(tcp_header[0].hex(), 16))
    tcp_packet.tcp_dport = str(int(tcp_header[1].hex(), 16))
    tcp_packet.tcp_seqnum = str(int(tcp_header[2].hex(), 16))
    tcp_packet.tcp_acknum = str(int(tcp_header[3].hex(), 16))
    tcp_feature = bin(int(tcp_header[4].hex(), 16))[2:].zfill(16)
    tcp_packet.tcp_hlen = str(int(tcp_feature[:4], 2)*4)
    tcp_packet.tcp_res = str(tcp_feature[4:10])
    tcp_packet.tcp_flags = str(tcp_feature[10:])
    tcp_packet.tcp_winsize = str(int(tcp_header[5].hex(), 16))
    tcp_packet.tcp_checksum = "0x" + tcp_header[6].hex()
    tcp_packet.tcp_urgpoint = str(int(tcp_header[7].hex(), 16))
    if tcp_packet.tcp_hlen != "20":
        tcp_packet.tcp_options = packet[20:int(tcp_packet.tcp_hlen)]
    tcp_packet.tcp_data = packet[int(tcp_packet.tcp_hlen):]
    return tcp_packet

def prase_udp(packet):
    # udp header lenght is 8 byte
    udp_header = unpack('!2s2s2s2s', packet[:8])
    udp_packet = UDP()
    udp_packet.udp_sport = str(int(udp_header[0].hex(), 16))
    udp_packet.udp_dport = str(int(udp_header[1].hex(), 16))
    udp_packet.udp_hlen = str(int(udp_header[2].hex(), 16))
    udp_packet.udp_checksum = "0x" + udp_header[3].hex()
    return udp_packet

def prase_icmp(packet):
    # default icmp header length is 3 byte
    icmp_header = unpack('!sss', packet[:3])
    icmp_packet = ICMP()
    icmp_packet.icmp_type = str(int(icmp_header[0].hex(), 16))
    icmp_packet.icmp_code = str(int(icmp_header[1].hex(), 16))
    icmp_packet.icmp_checksum = "0x" + icmp_header[2].hex()
    icmp_packet.icmp_data = packet[3:]
    return icmp_packet

def prase_arp(packet):
    # default arp header lenght is 28 byte
    arp_header = unpack('!2s2sss2s6s4s6s4s', packet[:28])
    arp_packet = ARP()
    arp_packet.arp_htype = str(int(arp_header[0].hex(), 16))
    arp_packet.arp_ptype = str(int(arp_header[1].hex(), 16))
    arp_packet.arp_hlen = str(int(arp_header[2].hex(), 16))
    arp_packet.arp_plen = str(int(arp_header[3].hex(), 16))
    arp_packet.arp_oper = str(int(arp_header[4].hex(), 16))
    arp_packet.arp_sha = b2m(arp_header[5])
    arp_packet.arp_spa = b2a(arp_header[6])
    arp_packet.arp_tha = b2m(arp_header[7])
    arp_packet.arp_tpa = b2a(arp_header[8])
    arp_packet.arp_data = packet[28:]
    return arp_packet

class Ethernet:
    def __init__(self):
        self.mac_src = None
        self.mac_dst = None
        self.type = None
        self.packet = None
        self.raw = None

class IP:
    def __init__(self):
        self.ip_versions = None
        self.ip_hlen = None
        self.ip_tos = None
        self.ip_tlen = None
        self.ip_ident = None
        self.ip_flags = None
        self.ip_foffset = None
        self.ip_ttl = None
        self.ip_protocol = None
        self.ip_hchecksum = None
        self.ip_src = None
        self.ip_dst = None
        self.ip_options = None
        self.ip_packet = None
        
class TCP:
    def __init__(self):
        self.tcp_sport = None
        self.tcp_dport = None
        self.tcp_seqnum = None
        self.tcp_acknum = None
        self.tcp_hlen = None
        self.tcp_res = None
        self.tcp_flags = None
        self.tcp_winsize = None
        self.tcp_checksum = None
        self.tcp_urgpoint = None
        self.tcp_options = None
        self.tcp_data = None

class UDP:
    def __init__(self):
        self.udp_sport = None
        self.udp_dport = None
        self.udp_hlen = None
        self.udp_checksum = None

class ICMP:
    def __init__(self):
        self.icmp_type = None
        self.icmp_code = None
        self.icmp_checksum = None
        self.icmp_data = None

class ARP:
    def __init__(self):
        self.arp_htype = None
        self.arp_ptype = None
        self.arp_hlen = None
        self.arp_plen = None
        self.arp_oper = None
        self.arp_sha = None
        self.arp_spa = None
        self.arp_tha = None
        self.arp_tpa = None
        self.arp_data = None
