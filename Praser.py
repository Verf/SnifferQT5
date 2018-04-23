#!/usr/bin/env python3
# coding: utf-8
from struct import unpack
from collections import OrderedDict
import Tools


class Praser:
    def __init__(self, raw):
        self.raw = raw
        self.packet = None

    def prase(self):
        # prsae ethernet
        packet = OrderedDict()
        eth_head = self.raw[:14]
        eth_data = self.raw[14:]
        packet["FP"] = ""
        packet["Info"] = ""
        packet["Raw"] = self.raw[:].hex()
        packet["Ethernet"] = self.prase_eth(eth_head)
        if packet["Ethernet"]["Type"] == "0x0800":
            packet["FP"] += '0'
            packet["Ethernet"]["Type"] += " (IPv4)"
            packet["IPv4"] = self.prase_ipv4(eth_data)
            ipv4_hlen = int(packet["IPv4"]["Header Length"])
            ipv4_data = eth_data[ipv4_hlen:]
            if packet["IPv4"]["Protocol"] == '1':
                packet["FP"] += '0'
                packet["IPv4"]["Protocol"] += " (ICMP)"
                packet["ICMP"] = self.prase_icmp(ipv4_data)
            elif packet["IPv4"]["Protocol"] == '6':
                packet["FP"] += '1'
                packet["IPv4"]["Protocol"] += " (TCP)"
                packet["TCP"] = self.prase_tcp(ipv4_data)
                packet["Info"] += "{0} -> {1} ".format(packet["TCP"]["Source Port"], packet["TCP"]["Destination Port"])
                packet["Info"] += "[{0}] ".format(','.join(Tools.tf2s(packet["TCP"]["Flags"])))
                packet["Info"] += "Seq={0} Ack={1}".format(packet["TCP"]["Sequence Number"], packet["TCP"]["Acknowledgment Number"])
            elif packet["IPv4"]["Protocol"] == '17':
                packet["FP"] += '2'
                packet["IPv4"]["Protocol"] += " (UDP)"
                packet["UDP"] = self.prase_udp(ipv4_data)
                packet["Info"] += "{0} -> {1} ".format(packet["UDP"]["Source Port"], packet["UDP"]["Destination Port"])
            else:
                packet["FP"] += '3'
                packet["Others"] = "Unknow Protocol"
        elif packet["Ethernet"]["Type"] == "0x0806":
            packet["FP"] += '1'
            packet["Ethernet"]["Type"] += " (ARP)"
            packet["ARP"] = self.prase_arp(eth_data)
            if packet["ARP"]["Opcode"][0] == '1':
                packet["Info"] += "Who has {0}? Tell {1}".format(packet["ARP"]["Target IP"], packet["ARP"]["Sender IP"])
            else:
                packet["Info"] += "I am {0} at {1}".format(packet["ARP"]["Sender IP"], packet["ARP"]["Sender MAC"])
        else:
            packet["FP"] += '2'
            packet["Others"] = "Unknow Protocol"
        self.packet = packet

    def prase_eth(self, raw):
        eth = OrderedDict()
        header = unpack('!6s6s2s', raw)
        eth["Source"] = Tools.b2m(header[0])
        eth["Destination"] = Tools.b2m(header[1])
        eth["Type"] = "0x" + header[2].hex()
        return eth

    def prase_ipv4(self, raw):
        ipv4 = OrderedDict()
        basic_header = unpack('!ss2s2s2sss2s4s4s', raw[:20])
        ipv4["Version"] = str(int(basic_header[0].hex()[:1], 16))
        ipv4["Header Length"] = str(int(basic_header[0].hex()[1])*4)
        ipv4["Type of Service"] = '0x' + basic_header[1].hex()
        ipv4["Total Length"] = str(int(basic_header[2].hex(), 16))
        ipv4["Indentification"] = '0x' + basic_header[3].hex()
        ipv4["Flags"] = str(bin(int(basic_header[4].hex(), 16))[2:].zfill(16)[:3])
        ipv4["Fragment Offset"] = str(bin(int(basic_header[4].hex(), 16))[2:].zfill(16)[3:])
        ipv4["Time to Live"] = str(int(basic_header[5].hex(), 16))
        ipv4["Protocol"] = str(int(basic_header[6].hex(), 16))
        ipv4["Header Checksum"] = '0x' + basic_header[7].hex()
        ipv4["Source"] = Tools.b2a(basic_header[8])
        ipv4["Destination"] = Tools.b2a(basic_header[9])
        return ipv4

    def prase_icmp(self, raw):
        icmp = OrderedDict()
        header = unpack('!sss', raw[:3])
        icmp["Type"] = str(int(header[0].hex(), 16))
        if icmp["Type"] == '8':
            icmp["Type"] += " (Echo ping request)"
        else:
            icmp["Type"] += " (Echo ping reply)"
        icmp["Code"] = str(int(header[1].hex(), 16))
        icmp["Checksum"] = "0x" + header[2].hex()
        return icmp

    def prase_arp(self, raw):
        arp = OrderedDict()
        header = unpack('!2s2sss2s6s4s6s4s', raw[:28])
        arp["Hardware Type"] = str(int(header[0].hex(), 16))
        arp["Protocol Type"] = str(int(header[1].hex(), 16))
        arp["Hardware Size"] = str(int(header[2].hex(), 16))
        arp["Protocol Size"] = str(int(header[3].hex(), 16))
        arp["Opcode"] = str(int(header[4].hex(), 16))
        if arp["Opcode"] == '1':
            arp["Opcode"] += " (request)"
        else:
            arp["Opcode"] += " (reply)"
        arp["Sender MAC"] = Tools.b2m(header[5])
        arp["Sender IP"] = Tools.b2a(header[6])
        arp["Target MAC"] = Tools.b2m(header[7])
        arp["Target IP"] = Tools.b2a(header[8])
        return arp

    def prase_tcp(self, raw):
        tcp = OrderedDict()
        header = unpack('!2s2s4s4s2s2s2s2s', raw[:20])
        tcp["Source Port"] = str(int(header[0].hex(), 16))
        tcp["Destination Port"] = str(int(header[1].hex(), 16))
        tcp["Sequence Number"] = str(int(header[2].hex(), 16))
        tcp["Acknowledgment Number"] = str(int(header[3].hex(), 16))
        tcp_feature = str(bin(int(header[4].hex(), 16)))[2:].zfill(16)
        tcp["Header Length"] = str(int(tcp_feature[:4], 2)*4) + "Byte"
        tcp["Reserved"] = tcp_feature[4:10]
        tcp["Flags"] = tcp_feature[10:]
        tcp["Window Size"] = str(int(header[5].hex(), 16))
        tcp["Checksum"] = "0x" + header[6].hex()
        tcp["Urgent Point"] = str(int(header[7].hex(), 16))
        hex_data = raw[int(tcp_feature[:4], 2)*4:].hex()
        tcp["Data"] = Tools.h2a(hex_data)
        return tcp

    def prase_udp(self, raw):
        udp = OrderedDict()
        header = unpack('!2s2s2s2s', raw[:8])
        udp["Source Port"] = str(int(header[0].hex(), 16))
        udp["Destination Port"] = str(int(header[1].hex(), 16))
        udp["Header Length"] = str(int(header[2].hex(), 16))
        udp["Checksum"] = "0x" + header[3].hex()
        hex_data = raw[8:].hex()
        udp["Data"] = Tools.h2a(hex_data)
        return udp
