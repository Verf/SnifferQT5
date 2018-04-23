#!/usr/bin/env python3
# coding: utf-8
def b2a(ip_bytes):
    ip_hex = ip_bytes.hex()
    return ".".join([str(int(ip_hex[i:i+2], 16)) for i in range(0, len(ip_hex), 2)])


def b2m(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)


def tf2s(flags):
    res = []
    fd = {1: "URG", 2: "ACK", 3: "PSH", 4: "RST", 5: "SYN", 6: "FIN"}
    for i in range(6):
        if flags[i] == '1':
            res.append(fd[i+1])
    return res


def h2a(raw):
    res = ""
    for i in range(0, len(raw), 2):
        h = raw[i:i+2]
        n = int(h, 16)
        if 31 < n < 127:
            res += chr(n)
        else:
            res += ' '
    return res


