#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: sniffer.py
Author: YJ
Email: yj1516268@outlook.com
Created Time: 2020-12-01 09:22:43

Description: 嗅探指定网络接口的指定类型的报文

1. 需要以管理员权限运行
"""

import argparse
import fcntl
import json
import os
import socket
import struct
import threading
import time
from multiprocessing import Process, Queue

import scapy.all as scapy
import toml

_version = '0.1'


def get_address(iface: str):
    """获取指定网络接口的IP地址

    :iface: 网络接口名
    :returns: 指定网络接口的IP，类型为'str'

    宏'SIOCGIFADDR'在/usr/include/linux/sockios.h中定义
    宏'IFNAMSIZ'在/usr/include/net/if.h中定义

    """
    SIOCGIFADDR = 0x8915  # get PA address
    IFNAMSIZ = 16  # Length of interface name

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建socket对象
    fd = sock.fileno()  # 获取socket的文件描述符

    iface_bytes = iface.encode('UTF-8')
    ifreq = struct.pack('256s', iface_bytes[:IFNAMSIZ - 1])
    ip = socket.inet_ntoa(fcntl.ioctl(fd, SIOCGIFADDR, ifreq)[20:24])

    return ip


class Sniffer(object):
    """嗅探网络数据包并解析"""
    def __init__(self, conf: dict):
        """初始化

        :conf: 配置信息

        """
        # [interface]配置项
        conf_interface = conf.get('interface', dict())
        self.iface = conf_interface.get('iface', None)

        # [interface.sniffer]配置项
        conf_sniffer = conf_interface.get('sniffer', dict())
        self.filter_role = conf_sniffer.get('filter_role', None)
        self.filter_method = conf_sniffer.get('filter_method', None)
        self.filter_port = conf_sniffer.get('filter_port', None)
        self.count = conf_sniffer.get('count', 1)
        self.format = conf_sniffer.get('format', str())  # STDOUT输出格式

        # [parser]配置项
        conf_parser = conf.get('parser', dict())
        self.index = conf_parser.get('index', self.count)
        self.byte_order = conf_parser.get('byte_order', 4)
        self.command_length = conf_parser.get('command_length', 4)

        # [sender]配置项
        conf_sender = conf.get('sender', dict())
        self.protocol = conf_sender.get('protocol', 'UDP')
        self.ip = conf_sender.get('ip', '127.0.0.1')
        self.port = conf_sender.get('port', 8848)
        self.backlog = conf_sender.get('backlog', 5)
        self.coding = conf_sender.get('coding', 'UTF-8')

        # 获取iface的IP
        self.iface_ip = get_address(self.iface)

        # sniffer进程和forwarder进程通信队列
        self.queue = Queue()

    def _via_tcp(self, sock, data):
        """通过TCP发送数据

        :sock: TCP Server和TCP Client间的连接
        :data: 待发送的数据

        """
        while sock:
            try:
                sock.send(data)
            except Exception as e:
                print(e)

            time.sleep(1)

    def _tuple2dict(self, data):
        """将tuple(bytes(), bytes())类型的数据转换为dict()类型

        :data: tuple(bytes(), bytes())类型数据
        :returns: dict()类型数据

        """
        result = dict()
        if isinstance(data, (tuple)):
            result['{key}'.format(
                key=data[0].decode(self.coding))] = '{value}'.format(
                    value=data[1].decode(self.coding))

        return result

    def forwarder(self):
        """通过指定方式(TCP/UDP)将数据转发到指定地址"""
        addr = (self.ip, self.port)

        print('Send data to ({address}) via {proto}'.format(
            address=addr, proto=self.protocol))

        data = self.queue.get()
        data_jsonb = json.dumps(data).encode(self.coding)

        if self.protocol.upper() == 'TCP':
            # 创建TCP Server
            tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            tcp_server.bind(address=addr)
            tcp_server.listen(self.backlog)

            # TCP发送data
            while True:
                sock, client_addr = tcp_server.accept()
                thread = threading.Thread(target=self._via_tcp,
                                          args=(sock, data_jsonb))
                thread.start()
        elif self.protocol.upper() == 'UDP':
            # 创建UDP Client
            udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # UDP发送data
            while True:
                udp_client.sendto(data_jsonb, addr)
                time.sleep(1)
        else:
            print('不支持的协议')

    def sniffer(self):
        """嗅探数据包
        :returns: 嗅探到的数据包列表，类型为'scapy.plist.PacketList'

        """
        # 数据包嗅探规则（使用Berkeley Packet Filter (BPF) syntax）
        # Pre filter
        if self.filter_method and self.filter_port:
            pre_filter = '{method} port {port}'.format(
                method=self.filter_method, port=self.filter_port)
        elif self.filter_method and not self.filter_port:
            pre_filter = '{method}'.format(method=self.filter_method)
        elif not self.filter_method and self.filter_port:
            pre_filter = 'port {port}'.format(port=self.filter_port)
        else:
            pre_filter = ''
        # Post filter
        if self.filter_role:
            post_filter = 'ip {role} {iface_ip}'.format(role=self.filter_role,
                                                        iface_ip=self.iface_ip)
        else:
            post_filter = ''
        # Full filter
        bearing = ' && ' if post_filter else ''
        full_filter = '{pre}{bearing}{post}'.format(pre=pre_filter,
                                                    bearing=bearing,
                                                    post=post_filter)
        print('filter = {}'.format(full_filter))

        packets = scapy.sniff(iface=self.iface,
                              filter=full_filter.lower(),
                              count=self.count,
                              prn=lambda x: x.sprintf(self.format))

        return packets

    def parser(self, raw_load: bytes):
        """解析原始数据

        :raw_load: 原始数据，类型为'bytes'
        :returns: 原始数据解析结果，类型为'tuple'

        """
        raw_value_length = len(raw_load) - 10
        if raw_value_length > 0:
            fmt = '{byte_order}2x{command_length}s3x{value_length}sx'.format(
                byte_order=self.byte_order,
                command_length=self.command_length,
                value_length=raw_value_length)
        else:
            fmt = '{byte_order}2x{command_length}s3x'.format(
                byte_order=self.byte_order, command_length=self.command_length)

        payload = struct.unpack(fmt, raw_load)

        return payload

    def main(self):
        """主要流程函数"""
        while True:
            payloads = dict()

            packets = self.sniffer()
            indexs = self.index if isinstance(self.index,
                                              (list)) else range(self.index)
            for index in indexs:
                try:
                    raw_load = packets[index][scapy.Raw].load
                    print('Raw load = {}'.format(raw_load))
                    payload = self.parser(raw_load)
                    result = self._tuple2dict(payload)
                    payloads.update(result)
                except IndexError:
                    print('Layer [Raw] not found')

            self.queue.put(payloads)
            print('Payloads = {}\n'.format(payloads))

            time.sleep(1)


if __name__ == "__main__":
    # 构建默认配置文件路径
    name = os.path.basename(__file__).split('.')[0]  # 配置文件名
    ext = 'toml'  # 配置文件后缀
    filename = '{name}.{ext}'.format(name=name, ext=ext)  # 完整配置文件名

    # 定义参数范围 -- parser是正常参数，group是互斥参数
    parser = argparse.ArgumentParser(
        prog=name, description='Packet sniffing and forwarding tool.')
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-c',
                        '--config',
                        help=("specify configuration file, "
                              "default is '{}'").format(filename))
    group.add_argument('-s',
                       '--sniffer',
                       action='store_true',
                       help='start the sniffer (run as root)')
    group.add_argument('-f',
                       '--forwarder',
                       action='store_true',
                       help='start the forwarder (run as root)')
    group.add_argument('-v',
                       '--version',
                       action='version',
                       default=None,
                       version='%(prog)s {}'.format(_version))
    # 获取参数列表
    args = parser.parse_args()

    # 尝试获取配置信息
    confile = args.config if args.config else os.path.join('.', filename)
    conf = toml.load(confile)

    # 根据参数判断是否创建OPC2UDP对象
    if True in [args.sniffer, args.forwarder]:
        sniffer = Sniffer(conf)

    if args.sniffer:  # -s/--sniffer
        process = Process(target=sniffer.main)

        print('Starting {}\n'.format('sniffer'))
        process.start()

        payloads = sniffer.queue.get()
        print('Payloads = {}\n'.format(payloads))
    elif args.forwarder:  # -f/--forwarder
        process_sniffer = Process(target=sniffer.main)
        process_forwarder = Process(target=sniffer.forwarder)

        print('Starting {}\n'.format('sniffer'))
        print('Starting {}\n'.format('forwarder'))
        process_sniffer.start()
        process_forwarder.start()
