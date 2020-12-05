#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: list_nic.py
Author: YJ
Email: yj1516268@outlook.com
Created Time: 2020-12-04 09:07:56

Description: 列出所有NIC (Network Interface Card)信息
"""

try:
    import winreg
except ModuleNotFoundError:
    pass
import platform

import netifaces
import prettytable

system = platform.system()
# Windows注册表中关于Network的一部分路径名，固定值
NETWORK_KEY = '{4D36E972-E325-11CE-BFC1-08002BE10318}'


def list_nic():
    """列出所有NIC的信息
    :returns: NIC信息，类型为：

        {
            'iface': {
                'v4': [{info}],
                'v6': [{info}],
                'rsp' {iface_name: iface_ID}
            }
        }

    """
    nics = dict()

    # 获取所有NIC名的列表 -- Linux获取的是正常的NIC名，Windows获取的是NIC的ID
    ifaces = netifaces.interfaces()
    if system == 'Linux':
        for iface in ifaces:
            iface_info = netifaces.ifaddresses(iface)  # 获取指定NIC的信息

            nic = dict()
            nic['v4'] = iface_info.get(netifaces.AF_INET, [dict()])
            nic['v6'] = iface_info.get(netifaces.AF_INET6, [dict()])
            nic['rsp'] = {iface: iface}
            nics[iface] = nic
    elif system == 'Windows':
        # 根据NIC ID从注册表获取NIC Name
        try:
            # 连接到注册表HKEY_LOCAL_MACHINE，None表示本地计算机
            registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            path = r'SYSTEM\CurrentControlSet\Control\Network\{}'.format(NETWORK_KEY)
            registry_network = winreg.OpenKey(registry, path)
        except Exception as e:
            raise e

        for iface_id in ifaces:
            iface_info = netifaces.ifaddresses(iface_id)  # 获取指定NIC的信息

            # NIC ID --> NIC Name
            sub_path = r'{}\{}'.format(iface_id, 'Connection')
            try:
                registry_nic = winreg.OpenKey(registry_network, sub_path)
                iface_name = winreg.QueryValueEx(registry_nic, 'Name')[0]
            except Exception:
                pass

            nic = dict()
            nic['v4'] = iface_info.get(netifaces.AF_INET, [dict()])
            nic['v6'] = iface_info.get(netifaces.AF_INET6, [dict()])
            nic['rsp'] = {iface_name: iface_id}
            nics[iface_name] = nic

    return nics


if __name__ == "__main__":
    substitute = '/'

    table = prettytable.PrettyTable()
    table.field_names = [
        'NIC', 'Address (IPv4)', 'Netmask (IPv4)', 'Broadcast (IPv4)',
        'Address (IPv6)', 'Netmask (IPv6)', 'Broadcast (IPv6)'
    ]

    nics = list_nic()
    for nic, info in nics.items():
        table.add_row([
            nic,
            info['v4'][0].get('addr', substitute),
            info['v4'][0].get('netmask', substitute),
            info['v4'][0].get('broadcast', substitute),
            info['v6'][0].get('addr', substitute),
            info['v6'][0].get('netmask', substitute),
            info['v6'][0].get('broadcast', substitute),
        ])

    print(table)
