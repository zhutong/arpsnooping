#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'zhutong'

"""
Create on 15/4/15
"""

import sys
import collections
import pexpect

child = pexpect.spawn('sudo tcpdump -nei ens160 arp')
arp_dict = collections.defaultdict(list)

while True:
    try:
        i = child.expect(['\n', pexpect.TIMEOUT], timeout=3600)
        if i == 0:
            line = child.before
            if ' ARP ' not in line:
                continue
            ss = line.split()
            s_mac = ss[1]
            d_mac = ss[3][:-1]
            if 'Request' in line:
                if d_mac == 'ff:ff:ff:ff:ff:ff':
                    ip = ss[-3][:-1]
                    mac = s_mac
                else:
                    ip = ss[11]
                    mac = d_mac
            elif 'Reply' in line:
                ip = ss[10]
                mac = s_mac
            else:
                continue
            # print line
            try:
                if mac != arp_dict[ip][-1]:
                    # ARP changed
                    arp_dict[ip].append(mac)
                    sys.stdout.write('!')
                else:
                    # ARP not changed
                    sys.stdout.write('.')
            except IndexError:
                # New IP
                sys.stdout.write('+')
                arp_dict[ip].append(mac)
            sys.stdout.flush()
    except KeyboardInterrupt:
        break

for ip, mac_list in arp_dict.items():
    print ip, mac_list
