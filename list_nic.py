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
table.field_names = ['NIC', 'Address', 'Netmask', 'Broadcast']

for iface in ifaces:
    iface_info = netifaces.ifaddresses(iface)
    table.add_row([
        iface,
        iface_info.get(2, [dict()])[0].get('addr', substitute),
        iface_info.get(2, [dict()])[0].get('netmask', substitute),
        iface_info.get(2, [dict()])[0].get('broadcast', substitute)
    ])

print(table)
