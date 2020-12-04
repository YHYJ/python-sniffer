#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: list_nic.py
Author: YJ
Email: yj1516268@outlook.com
Created Time: 2020-12-04 09:07:56

Description: 列出所有NIC (Network Interface Card)信息
"""

import netifaces
import prettytable

substitute = '/'

ifaces = netifaces.interfaces()
table = prettytable.PrettyTable()
table.field_names = [
    'NIC', 'Address (IPv4)', 'Netmask (IPv4)', 'Broadcast (IPv4)',
    'Address (IPv6)', 'Netmask (IPv6)'
]

for iface in ifaces:
    iface_info = netifaces.ifaddresses(iface)
    table.add_row([
        iface,
        iface_info.get(netifaces.AF_INET, [dict()])[0].get('addr', substitute),
        iface_info.get(netifaces.AF_INET,
                       [dict()])[0].get('netmask', substitute),
        iface_info.get(netifaces.AF_INET,
                       [dict()])[0].get('broadcast', substitute),
        iface_info.get(netifaces.AF_INET6,
                       [dict()])[0].get('addr', substitute),
        iface_info.get(netifaces.AF_INET6,
                       [dict()])[0].get('netmask', substitute),
    ])

print(table)
