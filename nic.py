#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: nic.py
Author: YJ
Email: yj1516268@outlook.com
Created Time: 2020-12-04 09:07:56

Description: 列出所有NIC (Network Interface Card)信息
1. Linux下直接得到正常的NIC Name
2. Windows下得到的是NIC ID，还需要根据NIC ID查询注册表得到NIC Name

# TODO: <05-12-20> #
1. 增加参数功能：主要是输出太长，增加可选只输出IPv4或IPv6或都可输出的选项
"""

try:
    # 导入注册表操作模块（Python for Windows内置模块）
    import winreg
except ModuleNotFoundError:
    pass
import platform

import netifaces
import prettytable

system = platform.system()


def nic_info():
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

    # Linux分支: 直出NIC信息
    if system == 'Linux':
        for iface in ifaces:
            iface_info = netifaces.ifaddresses(iface)  # 获取指定NIC的信息

            nic = dict()
            # IPv4信息
            nic['v4'] = iface_info.get(netifaces.AF_INET, [dict()])
            # IPv6信息
            nic['v6'] = iface_info.get(netifaces.AF_INET6, [dict()])
            # NIC Name和NIC ID的relationship
            nic['rsp'] = {iface: iface}
            nics[iface] = nic
    # Windows分支: 直出NIC ID，需要再以之得到NIC Name
    elif system == 'Windows':
        # Windows注册表中关于Network的一部分路径名，固定值
        NETWORK_KEY = '{4D36E972-E325-11CE-BFC1-08002BE10318}'
        path = r'SYSTEM\CurrentControlSet\Control\Network\{}'.format(
            NETWORK_KEY)
        # 根据NIC ID从注册表获取NIC Name
        try:
            # 连接到注册表HKEY_LOCAL_MACHINE，None表示本地计算机
            registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            registry_network = winreg.OpenKey(registry, path)
        except Exception as e:
            raise e

        for iface_id in ifaces:
            iface_info = netifaces.ifaddresses(iface_id)  # 获取指定NIC的信息

            # NIC ID --> NIC Name
            # 这里有一个问题：有一个iface_id在path + sub_path组成的注册表路径里找不到
            # 但不知道怎么iface_name匹配到了"蓝牙适配器"，奇怪的Windows
            sub_path = r'{}\{}'.format(iface_id, 'Connection')
            try:
                registry_nic = winreg.OpenKey(registry_network, sub_path)
                iface_name = winreg.QueryValueEx(registry_nic, 'Name')[0]
            except Exception:
                pass

            nic = dict()
            # IPv4信息
            nic['v4'] = iface_info.get(netifaces.AF_INET, [dict()])
            # IPv6信息
            nic['v6'] = iface_info.get(netifaces.AF_INET6, [dict()])
            # NIC Name和NIC ID的relationship
            nic['rsp'] = {iface_name: iface_id}
            nics[iface_name] = nic
    else:
        raise OSError('当前仅支持{}系统，该系统不受支持'.format('Linux/Windows'))

    return nics


if __name__ == "__main__":
    substitute = '/'  # 某一项信息获取不到时的替代品

    # 建立表格，表格形式输出以方便阅读
    table = prettytable.PrettyTable()
    # 表格的列名
    table.field_names = [
        'NIC', 'Address (IPv4)', 'Netmask (IPv4)', 'Broadcast (IPv4)',
        'Address (IPv6)', 'Netmask (IPv6)', 'Broadcast (IPv6)'
    ]

    nics = nic_info()
    for nic, info in nics.items():
        # 填充列表
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
